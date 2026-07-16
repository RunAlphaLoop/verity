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
        create_private_dir(dir)
            .with_context(|| format!("cannot create config directory {}", dir.display()))?;
    }
    let body = toml::to_string_pretty(config).context("config serializes")?;
    // The file may carry an admin token. Create it owner-only FROM THE START
    // (mode at creation, not a chmod-after race that leaves a world-readable
    // window) and via a temp file + atomic rename, so a concurrent reader never
    // catches a partial or briefly-permissive file. A permission failure is
    // propagated, never swallowed — a token must never be left world-readable
    // silently.
    write_private(path, body.as_bytes())
        .with_context(|| format!("cannot write config file {}", path.display()))?;
    Ok(())
}

/// Create a directory (recursively) that may hold a secret, owner-only. On
/// unix the 0700 mode is applied to directories THIS call creates; a
/// pre-existing directory is left as the operator set it.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `bytes` to `path` owner-only and atomically: a temp file created at
/// mode 0600 (so the token is never world-readable, even for an instant),
/// fsync'd, then renamed over the target (rename preserves the 0600 mode). Any
/// permission error propagates rather than leaving the secret exposed.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config");
        let tmp = parent.join(format!(".{stem}.{}.tmp", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // Rename is atomic within a filesystem and keeps the 0600 temp mode.
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn save_writes_owner_only_file_and_dir() {
        let base =
            std::env::temp_dir().join(format!("verity-cfg-{}-{}", std::process::id(), "save"));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join(".verity");
        let path = dir.join("config.toml");

        let cfg = Config {
            admin_token: Some("super-secret-admin-token".into()),
            ..Config::default()
        };
        save(&path, &cfg).unwrap();

        // The token file is owner-only — never the 0644 the old write-then-chmod
        // left in the race window (or permanently on a swallowed chmod error).
        assert_eq!(mode_of(&path), 0o600, "config with a token must be 0600");
        // The directory we created is owner-only too.
        assert_eq!(mode_of(&dir), 0o700, "a secret-bearing dir must be 0700");
        // Round-trips.
        assert_eq!(
            load(&path).unwrap().admin_token.as_deref(),
            Some("super-secret-admin-token")
        );
        // No temp file left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic write must leave no .tmp file");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn save_overwrites_existing_config_keeping_owner_only() {
        let base =
            std::env::temp_dir().join(format!("verity-cfg-{}-{}", std::process::id(), "over"));
        let _ = std::fs::remove_dir_all(&base);
        let path = base.join(".verity").join("config.toml");
        save(&path, &Config::default()).unwrap();
        save(
            &path,
            &Config {
                url: Some("http://127.0.0.1:7717".into()),
                ..Config::default()
            },
        )
        .unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(
            load(&path).unwrap().url.as_deref(),
            Some("http://127.0.0.1:7717")
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
