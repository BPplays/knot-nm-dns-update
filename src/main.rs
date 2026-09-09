use anyhow::{Context, Result};
use resolv_conf::Config;
use serde_json::Value;
use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
};

const RESOLV_CONF: &str = "/run/NetworkManager/resolv.conf";
const RESOLV_ANTI_RFC6761: &str = "/etc/resolv.anti_rfc6761";

fn read_nameservers(path: impl AsRef<Path>) -> Result<Vec<IpAddr>> {
    let data = fs::read(path.as_ref())
        .with_context(|| format!("failed to read {}", path.as_ref().display()))?;

    let config = Config::parse(&data)
        .with_context(|| format!("failed to parse {}", path.as_ref().display()))?;

    Ok(config
        .nameservers
        .into_iter()
        .filter(|addr| match addr {
            resolv_conf::ScopedIp::V4(_) => true,
            resolv_conf::ScopedIp::V6(_, scope) => scope.is_none(),
        })
        .map(Into::into)
        .collect())
}

fn read_anti_rfc6761(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let data = fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read {}", path.as_ref().display()))?;

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

        let domain = if domain == "." || domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        };

        domains.push(domain);
    }

    domains.sort_unstable();
    domains.dedup();

    Ok(domains)
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
            "kresctl failed: {}",
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
    let json = serde_json::to_vec(config)?;

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
            "kresctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    let desired = read_nameservers(RESOLV_CONF)?;

    // Keep the last known-good configuration if NetworkManager
    // temporarily has no upstream DNS servers.
    if desired.is_empty() {
        return Ok(());
    }

    let anti_rfc6761 = read_anti_rfc6761(RESOLV_ANTI_RFC6761)?;

    let desired_forward = build_forward_config(&desired, &anti_rfc6761);
    let current_forward = get_knot_forward()?;

    if current_forward == desired_forward {
        return Ok(());
    }

    set_knot_forward(&desired_forward)?;

    Ok(())
}
