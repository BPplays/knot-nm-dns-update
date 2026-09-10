use anyhow::{Context, Result};
use resolv_conf::Config;
use serde_json::Value;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Copy NetworkManager's search domains into /etc/resolv.conf.
    #[arg(short = 's', long = "search")]
    search: bool,
}

const RESOLV_CONF: &str = "/etc/resolv.conf";
const KNOT_RESOLVER_LAST_STARTED: &str = "/run/knot-resolver/last_started";
const KNOT_RESOLVER_LAST_STARTED_KNOWN: &str =
    "/run/knot-nm-dns-update/knot-resolver.last_started.known";

const RESOLV_NM_CONF: &str = "/run/NetworkManager/resolv.conf";
const RESOLV_NM_LATEST: &str = "/run/knot-nm-dns-update/nm-resolv.conf.latest";
const RESOLV_ANTI_RFC6761: &str = "/etc/resolv.anti_rfc6761";

const RESOLV_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLV_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRule {
    subtree: Vec<String>,
    servers: Vec<IpAddr>,
    dnssec: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvData {
    nameservers: Vec<IpAddr>,
    search_domains: Vec<String>,
    bytes: Vec<u8>,
}

fn read_resolv_conf(
    path: impl AsRef<Path>,
) -> Result<ResolvData> {
    let path = path.as_ref();
    let deadline = Instant::now() + RESOLV_RETRY_TIMEOUT;

    let mut last_error;

    loop {
        match read_resolv_conf_once(path) {
            Ok(data) => {
                if !data.nameservers.is_empty() {
                    log::info!(
                        "using {} nameserver(s) from {}: {:?}",
                        data.nameservers.len(),
                        path.display(),
                        data.nameservers
                    );

                    return Ok(data);
                }

                last_error = Some(anyhow::anyhow!(
                    "{} contains no usable nameservers",
                    path.display()
                ));
            }

            Err(err) => {
                last_error = Some(err);
            }
        }

        let now = Instant::now();

        if now >= deadline {
            return Err(last_error.unwrap_or_else(|| {
                anyhow::anyhow!(
                    "timed out after {}s waiting for usable nameservers in {}",
                    RESOLV_RETRY_TIMEOUT.as_secs(),
                    path.display()
                )
            }));
        }

        let remaining = deadline - now;
        thread::sleep(RESOLV_RETRY_INTERVAL.min(remaining));
    }
}

fn read_resolv_conf_once(
    path: &Path,
) -> Result<ResolvData> {
    let data = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let config = Config::parse(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    // Preserve the order in resolv.conf while removing duplicate
    // nameservers after their first occurrence.
    let mut seen = HashSet::new();

    let nameservers = config
        .nameservers.clone()
        .into_iter()
        .filter(|addr| match addr {
            resolv_conf::ScopedIp::V6(_, scope) => scope.is_none(),
            resolv_conf::ScopedIp::V4(_) => true,
        })
        .map(Into::into)
        .filter(|addr: &IpAddr| seen.insert(*addr))
        .collect();

    let search_domains = config
        .get_search()
        .cloned()
        .unwrap_or_default();

    Ok(ResolvData {
        nameservers,
        search_domains,
        bytes: data,
    })
}

fn resolv_conf_changed(data: &[u8], latest_path: impl AsRef<Path>) -> Result<bool> {
    let latest_path = latest_path.as_ref();

    match fs::read(latest_path) {
        Ok(latest) => Ok(latest != data),

        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::debug!(
                "{} does not exist yet",
                latest_path.display()
            );
            Ok(true)
        }

        Err(err) => Err(err).with_context(|| {
            format!("failed to read {}", latest_path.display())
        }),
    }
}

fn atomic_write(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    let path = path.as_ref();

    let parent = path.parent().context("atomic write target has no parent")?;

    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let file_name = path
        .file_name()
        .context("atomic write target has no file name")?
        .to_string_lossy();

    let pid = std::process::id();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let tmp_path = parent.join(format!(
        ".{file_name}.tmp-{pid}-{timestamp}"
    ));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "failed to create temporary file {}",
                    tmp_path.display()
                )
            })?;

        file.write_all(data)
            .with_context(|| {
                format!(
                    "failed to write temporary file {}",
                    tmp_path.display()
                )
            })?;

        file.sync_all()
            .with_context(|| {
                format!(
                    "failed to sync temporary file {}",
                    tmp_path.display()
                )
            })?;

        fs::rename(&tmp_path, path)
            .with_context(|| {
                format!(
                    "failed to atomically replace {}",
                    path.display()
                )
            })?;

        Ok(())
    })();

    // If anything failed before rename, remove the temporary file.
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

fn read_anti_rfc6761(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let path = path.as_ref();

    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut domains = Vec::new();

    for line in data.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let domain = line
            .split_once('#')
            .map_or(line, |(domain, _)| domain)
            .trim();

        if domain.is_empty() {
            continue;
        }

        let domain = normalize_domain(domain);

        domains.push(domain);
    }

    domains.sort_unstable();
    domains.dedup();

    Ok(domains)
}

fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim();

    if domain == "." {
        return ".".to_string();
    }

    let domain = domain.trim_end_matches('.');

    if domain.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", domain.to_ascii_lowercase())
    }
}

fn build_forward_config(
    servers: &[IpAddr],
    anti_rfc6761: &[String],
) -> Value {
    let mut forwards = vec![
        serde_json::json!({
            "subtree": ".",
            "servers": servers,
        }),
    ];

    if !anti_rfc6761.is_empty() {
        forwards.push(serde_json::json!({
            "subtree": anti_rfc6761,
            "servers": servers,
            "options": {
                "dnssec": false,
            },
        }));
    }

    Value::Array(forwards)
}

fn get_knot_forward() -> Result<Value> {
    let output = Command::new("kresctl")
        .args([
            "config",
            "get",
            "--json",
            "-p",
            "/forward",
        ])
        .output()
        .context("failed to execute kresctl")?;

    if !output.status.success() {
        anyhow::bail!(
            "kresctl config get failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Array(Vec::new()));
    }

    serde_json::from_slice(&output.stdout)
        .context("invalid JSON from kresctl")
}

fn set_knot_forward(config: &Value) -> Result<()> {
    let json = serde_json::to_vec(config)
        .context("failed to serialize Knot forward configuration")?;

    let mut child = Command::new("kresctl")
        .args([
            "config",
            "set",
            "-p",
            "/forward",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to execute kresctl")?;

    child
        .stdin
        .take()
        .context("failed to open kresctl stdin")?
        .write_all(&json)
        .context("failed to write configuration to kresctl")?;

    let output = child
        .wait_with_output()
        .context("failed waiting for kresctl")?;

    if !output.status.success() {
        anyhow::bail!(
            "kresctl config set failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn canonicalize_forward(value: &Value) -> Result<Vec<ForwardRule>> {
    let rules = value
        .as_array()
        .context("Knot /forward is not an array")?;

    let mut result = Vec::with_capacity(rules.len());

    for (index, rule) in rules.iter().enumerate() {
        let object = rule
            .as_object()
            .with_context(|| {
                format!("Knot /forward rule {index} is not an object")
            })?;

        let subtree = match object.get("subtree") {
            Some(Value::String(value)) => {
                vec![normalize_domain(value)]
            }

            Some(Value::Array(values)) => values
                .iter()
                .enumerate()
                .map(|(subtree_index, value)| {
                    let value = value.as_str().with_context(|| {
                        format!(
                            "Knot /forward rule {index} subtree[{subtree_index}] \
                             is not a string"
                        )
                    })?;

                    Ok(normalize_domain(value))
                })
                .collect::<Result<Vec<_>>>()?,

            Some(other) => {
                anyhow::bail!(
                    "Knot /forward rule {index} has invalid subtree: {other}"
                );
            }

            None => Vec::new(),
        };

        let servers = object
            .get("servers")
            .and_then(Value::as_array)
            .with_context(|| {
                format!(
                    "Knot /forward rule {index} is missing servers array"
                )
            })?
            .iter()
            .enumerate()
            .map(|(server_index, value)| {
                let value = value.as_str().with_context(|| {
                    format!(
                        "Knot /forward rule {index} server[{server_index}] \
                         is not a string"
                    )
                })?;

                value.parse::<IpAddr>().with_context(|| {
                    format!(
                        "invalid IP address in Knot /forward rule {index}: \
                         {value:?}"
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let dnssec = object
            .get("options")
            .and_then(Value::as_object)
            .and_then(|options| options.get("dnssec"))
            .and_then(Value::as_bool);

        result.push(ForwardRule {
            subtree,
            servers,
            dnssec,
        });
    }

    Ok(result)
}


fn update_search_domains(
    path: impl AsRef<Path>,
    search_domains: &[String],
) -> Result<()> {
    let path = path.as_ref();

    let current = read_resolv_conf_once(path)?;

    // Nothing to change.
    if current.search_domains == search_domains {
        log::debug!(
            "{} search domains are already up to date: {:?}",
            path.display(),
            search_domains
        );

        return Ok(());
    }

    let text = String::from_utf8(current.bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;

    let replacement = if search_domains.is_empty() {
        None
    } else {
        Some(format!("search {}", search_domains.join(" ")))
    };

    let mut output = String::with_capacity(text.len() + 256);
    let mut replaced = false;

    for line in text.split_inclusive('\n') {
        let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
        let content = line_without_newline.strip_suffix('\r').unwrap_or(line_without_newline);

        let trimmed = content.trim_start();

        if trimmed == "search" || trimmed.starts_with("search ") {
            replaced = true;

            if let Some(replacement) = &replacement {
                output.push_str(replacement);

                // Preserve CRLF if the original line used it.
                if line_without_newline.ends_with('\r') {
                    output.push('\r');
                }

                if line.ends_with('\n') {
                    output.push('\n');
                }
            }

            continue;
        }

        output.push_str(line);
    }

    // No existing search directive: add one only when needed.
    if !replaced {
        if let Some(replacement) = &replacement {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }

            output.push_str(replacement);
            output.push('\n');
        }
    }

    if output.as_bytes() == text.as_bytes() {
        log::debug!(
            "{} search-domain update produced no changes",
            path.display()
        );

        return Ok(());
    }

    atomic_write(path, output.as_bytes())?;

    log::info!(
        "updated search domains in {}: {:?}",
        path.display(),
        search_domains
    );

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    log::info!("starting Knot Resolver NetworkManager DNS updater");

    // let (desired_nameservers, search_domains, resolv_conf_data) =
    let desired_resolv =
        read_resolv_conf(RESOLV_NM_CONF)?;

    if cli.search {
        update_search_domains(
            RESOLV_CONF,
            &desired_resolv.search_domains,
        )?;
    }


    let last_started_changed;
    let current_last_started = fs::read(KNOT_RESOLVER_LAST_STARTED);

    let known_last_started = fs::read(KNOT_RESOLVER_LAST_STARTED_KNOWN);
    match (&current_last_started, &known_last_started) {
        (Ok(current), Ok(known)) if current == known => {
            last_started_changed = false;
            log::debug!(
                "{} has the same content as {}",
                KNOT_RESOLVER_LAST_STARTED,
                KNOT_RESOLVER_LAST_STARTED_KNOWN,
            );
        }
        (Ok(_), Ok(_)) => {
            // Different contents
            last_started_changed = true;
        }
        _ => {
            // One or both reads failed
            last_started_changed = true;
        }
    }

    // Fast path: NetworkManager has not changed resolv.conf since our
    // previous successful run, so there is nothing for us to do.
    if !resolv_conf_changed(&desired_resolv.bytes, RESOLV_NM_LATEST)? &&
        !last_started_changed {
        log::info!(
            "{} is unchanged; exiting early",
            RESOLV_NM_CONF
        );

        return Ok(());
    }

    let anti_rfc6761 = read_anti_rfc6761(RESOLV_ANTI_RFC6761)
        .with_context(|| {
            format!(
                "failed to read anti-RFC6761 configuration from {}",
                RESOLV_ANTI_RFC6761
            )
        })?;

    log::info!(
        "anti-RFC6761 forwarding domains: {:?}",
        anti_rfc6761
    );

    let desired_forward =
        build_forward_config(&desired_resolv.nameservers, &anti_rfc6761);

    let current_forward = get_knot_forward()?;

    let desired_canonical = canonicalize_forward(&desired_forward)
        .context("failed to canonicalize desired forward configuration")?;

    let current_canonical = canonicalize_forward(&current_forward)
        .context("failed to canonicalize current Knot forward configuration")?;

    if current_canonical != desired_canonical {
        log::info!("Knot /forward differs from desired configuration");

        log::debug!(
            "current canonical /forward: {:#?}",
            current_canonical
        );

        log::debug!(
            "desired canonical /forward: {:#?}",
            desired_canonical
        );

        set_knot_forward(&desired_forward)?;
    } else {
        log::info!("Knot /forward is already up to date");
    }


    log::info!("Knot /forward updated successfully");

    atomic_write(RESOLV_NM_LATEST, &desired_resolv.bytes)?;

    log::debug!(
        "updated {} atomically",
        RESOLV_NM_LATEST
    );


    match &current_last_started {
        Ok(current) if last_started_changed => {
            atomic_write(
                KNOT_RESOLVER_LAST_STARTED_KNOWN,
                &current,
            )?;

            log::debug!(
                "updated {} atomically",
                KNOT_RESOLVER_LAST_STARTED_KNOWN,
            );
        }
        _ => {
            log::error!(
                "read failed for {}",
                KNOT_RESOLVER_LAST_STARTED,
            );
        }
    }

    Ok(())
}


