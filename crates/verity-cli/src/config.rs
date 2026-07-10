//! ~/.verity/config.toml — the CLI's only state. Written by `verity-cli dev`,
//! read by everything else; every field can be overridden per-invocation
//! (--url, --config, --handle). The file may hold an admin token, so it is
//! written 0600.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Base URL of the verity server, e.g. "http://127.0.0.1:7717".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Tenant every command operates in (uuid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Bearer token for admin surfaces (tenants, webhooks, quarantine).
    /// Absent = the server is expected to run in dev mode (no VERITY_ADMIN_TOKEN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_token: Option<String>,
    /// The broad dev scope handle minted by `verity-cli dev`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_handle: Option<String>,
    /// Principal tokens behind that handle — kept so an expired handle can be
    /// re-minted without re-running `dev`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<i32>>,
    /// Source credentials written by the `connect` wizards (BYOT, SPEC §5e.2).
    /// Last field on purpose: TOML wants tables after scalar values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connectors: Option<Connectors>,
}

/// `[connectors.*]` — one optional table per BYOT source wizard.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Connectors {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack: Option<SlackConnector>,
}

/// `[connectors.slack]` — the two tokens `verity-cli connect slack` collects.
/// They live in this 0600 file only; the CLI never sends them anywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConnector {
    /// App-level token (`xapp-…`): opens the Socket Mode WebSocket.
    pub app_token: String,
    /// Bot token (`xoxb-…`): Web API reads under the app's bot user.
    pub bot_token: String,
}

pub fn default_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .context("cannot locate your home directory ($HOME is unset) — pass --config <path>")?;
    Ok(PathBuf::from(home).join(".verity").join("config.toml"))
}

pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    toml::from_str(&raw).with_context(|| {
        format!(
            "config file {} is not valid TOML — fix it or delete it and re-run `verity-cli dev`",
            path.display()
        )
    })
}

pub fn save(path: &Path, config: &Config) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create config directory {}", dir.display()))?;
    }
    let body = toml::to_string_pretty(config).context("config serializes")?;
    std::fs::write(path, body)
        .with_context(|| format!("cannot write config file {}", path.display()))?;
    // The file may carry an admin token: owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
