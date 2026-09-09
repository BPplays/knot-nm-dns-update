use anyhow::{Context, Result};
use resolv_conf::Config;
use serde_json::Value;
use std::{
    fs,
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
};

const RESOLV_CONF: &str = "/run/NetworkManager/resolv.conf";

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

fn get_knot_servers() -> Result<Vec<IpAddr>> {
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

    // No /forward configuration means there are no forwarders.
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }

    let value: Value =
        serde_json::from_slice(&output.stdout).context("invalid JSON from kresctl")?;

    let servers = value
        .get("0")
        .and_then(|v| v.get("servers"))
        .and_then(Value::as_array);

    servers
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .as_str()
                .context("Knot forwarder is not a string")
                .and_then(|s| {
                    s.parse()
                        .with_context(|| format!("invalid Knot forwarder: {s}"))
                })
        })
        .collect()
}

fn set_knot_servers(servers: &[IpAddr]) -> Result<()> {
    let value = serde_json::json!([
        {
            "subtree": ".",
            "servers": servers,
        }
    ]);

    let json = serde_json::to_string(&value)?;

    let output = Command::new("kresctl")
        .args([
            "config",
            "set",
            "-p",
            "/forward",
        ])
        .arg(json)
        .output()
        .context("failed to execute kresctl")?;

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

    let current = get_knot_servers()?;

    if current == desired {
        return Ok(());
    }

    set_knot_servers(&desired)?;

    Ok(())
}
