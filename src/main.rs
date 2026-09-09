use anyhow::{Context, Result};
use resolv_conf::Config;
use serde_json::Value;
use log;
use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const RESOLV_CONF: &str = "/run/NetworkManager/resolv.conf";
const RESOLV_ANTI_RFC6761: &str = "/etc/resolv.anti_rfc6761";

const RESOLV_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLV_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRule {
    subtree: Vec<String>,
    servers: Vec<IpAddr>,
    dnssec: Option<bool>,
}

fn read_nameservers(path: impl AsRef<Path>) -> Result<Vec<IpAddr>> {
    let path = path.as_ref();
    let deadline = Instant::now() + RESOLV_RETRY_TIMEOUT;

    let mut last_error;

    loop {
        match read_nameservers_once(path) {
            Ok(mut nameservers) => {
                if !nameservers.is_empty() {
                    nameservers.sort_unstable();
                    nameservers.dedup();

                    log::info!(
                        "using {} nameserver(s) from {}: {:?}",
                        nameservers.len(),
                        path.display(),
                        nameservers
                    );

                    return Ok(nameservers);
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

fn read_nameservers_once(path: &Path) -> Result<Vec<IpAddr>> {
    let data = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let config = Config::parse(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    Ok(config
        .nameservers
        .into_iter()
        .filter(|addr| match addr {
            resolv_conf::ScopedIp::V6(_, scope) => scope.is_none(),
            resolv_conf::ScopedIp::V4(_) => true,
        })
        .map(Into::into)
        .collect())
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

    let desired_nameservers = read_nameservers(RESOLV_CONF)?;

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

    Ok(())
}
