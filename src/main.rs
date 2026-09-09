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

const RESOLV_CONF: &str = "/run/NetworkManager/resolv.conf";
const RESOLV_LATEST: &str = "/run/knot-nm-dns-update/nm-resolv.conf.latest";
const RESOLV_ANTI_RFC6761: &str = "/etc/resolv.anti_rfc6761";

const RESOLV_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLV_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRule {
    subtree: Vec<String>,
    servers: Vec<IpAddr>,
    dnssec: Option<bool>,
}

fn read_resolv_conf(path: impl AsRef<Path>) -> Result<(Vec<IpAddr>, Vec<u8>)> {
    let path = path.as_ref();
    let deadline = Instant::now() + RESOLV_RETRY_TIMEOUT;

    let mut last_error;

    loop {
        match read_resolv_conf_once(path) {
            Ok((nameservers, data)) => {
                if !nameservers.is_empty() {
                    log::info!(
                        "using {} nameserver(s) from {}: {:?}",
                        nameservers.len(),
                        path.display(),
                        nameservers
                    );

                    return Ok((nameservers, data));
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

fn read_resolv_conf_once(path: &Path) -> Result<(Vec<IpAddr>, Vec<u8>)> {
    let data = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let config = Config::parse(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    // Preserve the order in resolv.conf while removing duplicate
    // nameservers after their first occurrence.
    let mut seen = HashSet::new();

    let nameservers = config
        .nameservers
        .into_iter()
        .filter(|addr| match addr {
            resolv_conf::ScopedIp::V6(_, scope) => scope.is_none(),
            resolv_conf::ScopedIp::V4(_) => true,
        })
        .map(Into::into)
        .filter(|addr: &IpAddr| seen.insert(*addr))
        .collect();

    Ok((nameservers, data))
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

fn main() -> Result<()> {
    env_logger::init();

    log::info!("starting Knot Resolver NetworkManager DNS updater");

    let (desired_nameservers, resolv_conf_data) =
        read_resolv_conf(RESOLV_CONF)?;

    // Fast path: NetworkManager has not changed resolv.conf since our
    // previous successful run, so there is nothing for us to do.
    if !resolv_conf_changed(&resolv_conf_data, RESOLV_LATEST)? {
        log::info!(
            "{} is unchanged; exiting early",
            RESOLV_CONF
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
        build_forward_config(&desired_nameservers, &anti_rfc6761);

    let current_forward = get_knot_forward()?;

    let desired_canonical = canonicalize_forward(&desired_forward)
        .context("failed to canonicalize desired forward configuration")?;

    let current_canonical = canonicalize_forward(&current_forward)
        .context("failed to canonicalize current Knot forward configuration")?;

    if current_canonical == desired_canonical {
        log::info!("Knot /forward is already up to date");

        atomic_write(RESOLV_LATEST, &resolv_conf_data)?;

        log::debug!(
            "updated {} atomically",
            RESOLV_LATEST
        );

        return Ok(());
    }

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

    log::info!("Knot /forward updated successfully");

    atomic_write(RESOLV_LATEST, &resolv_conf_data)?;

    log::debug!(
        "updated {} atomically",
        RESOLV_LATEST
    );

    Ok(())
}


