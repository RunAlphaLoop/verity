//! Console/CLI-owned Google directory-sync worker lifecycle (Identity Plane §6a).
//!
//! The directory worker is an external Python process
//! (`verity_ingest.connectors.gdirectory`) that reconciles Google Workspace
//! users + groups (nested membership preserved) into SpiceDB via the admin
//! principal/group endpoints, on a fixed interval. That interval IS the
//! group-membership freshness bound in the ACL-sync SLO (§6a), so — like the
//! knowledge worker (SPEC §2 L2) — it deserves a supervised, single-owner,
//! crash-resilient owner rather than a bare CLI loop. This module lets a RUNNING
//! server own that child: spawn it, track its pid, report authoritative status,
//! and kill+reap it.
//!
//! Mirrors `knowledge_worker.rs` one-for-one. The difference: identity, not an
//! Anthropic key. The child needs a service-account key PATH
//! (`GOOGLE_APPLICATION_CREDENTIALS`) and a domain-wide-delegation SUBJECT — the
//! server passes the key *path* through as an env var and NEVER reads the key
//! contents (the connector opens it itself), so nothing secret is logged or
//! returned. ONE owner per server: the CLI `--directory` flag routes through the
//! server start endpoint so a console Start and a CLI start can never stack two
//! workers racing the same snapshot / the same tenant's ReBAC tuples.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A live directory-sync worker THIS server spawned and owns. Presence in
/// `AppState.directory_worker` means authoritative status (pid, "started from
/// the console") and a real Stop; absence means the planes endpoint falls back
/// to the `connector_status` heartbeat proxy.
pub(crate) struct DirectoryWorker {
    pub(crate) child: Child,
    pub(crate) pid: u32,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) tenant_id: Uuid,
}

/// Why a spawn attempt could not proceed — each maps to a clean HTTP status
/// (NEVER a 500) with the exact fix in the message. `Os` is the runtime spawn
/// failure; the rest are checked preconditions.
pub(crate) enum SpawnError {
    /// The server was not started with `--repo`/`VERITY_REPO`, so it can't find
    /// `ingest/.venv`. → 422.
    NoRepo,
    /// No `<repo>/ingest/.venv/bin/python`. → 422. Carries the exact fix.
    NoVenv(String),
    /// Missing directory-sync config — the SA key path
    /// (`GOOGLE_APPLICATION_CREDENTIALS`) or the DWD subject
    /// (`VERITY_GDIRECTORY_SUBJECT`). → 503. Carries the exact fix. Fail-closed:
    /// we never spawn a worker that would run with no / the wrong identity.
    NoConfig(String),
    /// OS-level failure opening the log or spawning the process. → 503.
    Os(String),
}

/// The interpreter the worker runs under, given the server's repo root.
fn worker_python(repo: &Path) -> PathBuf {
    repo.join("ingest/.venv/bin/python")
}

/// Spawn + track the directory-sync worker. `repo_root` is the server's
/// `--repo`/`VERITY_REPO`; `base_url` is derived from `--listen`; `admin_token`
/// (if the server requires one) is passed through so the worker can reach the
/// admin-gated principal/group endpoints. `sa_key_path` is the service-account
/// key file (its PATH only — the server never reads the key); `subject` is the
/// DWD admin to impersonate (required); `domain` maps `type=CUSTOMER` members
/// (optional); `interval_secs` is the reconcile cadence (the §6a SLO bound).
///
/// Runs `verity_ingest.connectors.gdirectory` with NO `--once` and NO
/// `--dry-run` (continuous, live reconcile), cwd `<repo>/ingest`, detached
/// stdio → `gdirectory.log`, `GOOGLE_APPLICATION_CREDENTIALS` set to the key
/// path. Returns a typed `SpawnError` (mapped to 422/503, never 500) on any
/// checked precondition or OS failure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    repo_root: Option<&Path>,
    base_url: &str,
    tenant_id: Uuid,
    admin_token: Option<&str>,
    sa_key_path: Option<&Path>,
    subject: Option<&str>,
    domain: Option<&str>,
    interval_secs: u64,
) -> Result<DirectoryWorker, SpawnError> {
    let repo = repo_root.ok_or(SpawnError::NoRepo)?;
    let py = worker_python(repo);
    if !py.exists() {
        return Err(SpawnError::NoVenv(format!(
            "no ingest virtualenv at {} — create it (cd ingest && python -m venv .venv && \
             .venv/bin/pip install -e '.[gdrive]') then try again",
            py.display()
        )));
    }
    let sa_key = sa_key_path.filter(|p| p.exists()).ok_or_else(|| {
        SpawnError::NoConfig(
            "directory sync needs the service-account key — set GOOGLE_APPLICATION_CREDENTIALS \
             on the server to your Workspace SA JSON (domain-wide delegation, scopes \
             admin.directory.user.readonly + admin.directory.group.readonly), then try again"
                .to_string(),
        )
    })?;
    let subject = subject.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        SpawnError::NoConfig(
            "directory sync needs a domain-wide-delegation subject — set \
             VERITY_GDIRECTORY_SUBJECT to a Workspace admin to impersonate, then try again"
                .to_string(),
        )
    })?;

    // The snapshot checkpoint lives under the ingest dir; ensure its parent
    // exists so the connector's first write can't fail on a missing dir.
    let state_dir = repo.join("ingest").join(".verity");
    let _ = std::fs::create_dir_all(&state_dir);

    // Log next to the ingest dir so it sits with the worker's own artifacts;
    // the child's stdout/stderr are detached into it (never inherited).
    let log_path = repo.join("ingest").join("gdirectory.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| {
            SpawnError::Os(format!(
                "cannot open worker log {}: {e}",
                log_path.display()
            ))
        })?;
    let log2 = log
        .try_clone()
        .map_err(|e| SpawnError::Os(format!("log handle clone: {e}")))?;

    let tenant = tenant_id.to_string();
    let interval = interval_secs.to_string();
    let mut cmd = Command::new(&py);
    cmd.args(["-m", "verity_ingest.connectors.gdirectory", "--verity-url"])
        .arg(base_url)
        .args(["--tenant-id"])
        .arg(&tenant)
        .args(["--subject"])
        .arg(subject)
        .args(["--interval"])
        .arg(&interval);
    if let Some(domain) = domain.filter(|d| !d.trim().is_empty()) {
        cmd.args(["--domain"]).arg(domain);
    }
    cmd.current_dir(repo.join("ingest"))
        // The connector opens this path itself; the server never reads it.
        .env("GOOGLE_APPLICATION_CREDENTIALS", sa_key)
        .stdin(Stdio::null())
        .stdout(log2)
        .stderr(log);
    if let Some(token) = admin_token {
        cmd.env("VERITY_ADMIN_TOKEN", token);
    }
    let child = cmd.spawn().map_err(|e| {
        SpawnError::Os(format!(
            "cannot start the directory worker ({}): {e}",
            py.display()
        ))
    })?;
    let pid = child.id();
    Ok(DirectoryWorker {
        child,
        pid,
        started_at: Utc::now(),
        tenant_id,
    })
}

/// Whether the ingest venv Python exists for this repo root — used by the
/// planes read to decide `startable` without attempting a spawn.
pub(crate) fn venv_exists(repo_root: Option<&Path>) -> bool {
    repo_root
        .map(|r| worker_python(r).exists())
        .unwrap_or(false)
}

/// Whether the directory-sync config (SA key path present on disk + a non-empty
/// DWD subject) is in place — used by the planes read to decide `startable`.
/// Never reads the key itself.
pub(crate) fn config_ready(sa_key_path: Option<&Path>, subject: Option<&str>) -> bool {
    sa_key_path.is_some_and(|p| p.exists()) && subject.is_some_and(|s| !s.trim().is_empty())
}

/// The server-held directory-sync plane: the owned child (if any) plus the
/// config needed to spawn it. Bundled so `AppState` carries ONE field. Lives
/// inside `Arc<AppState>`, so the inner `Mutex` is shared without its own `Arc`.
pub(crate) struct DirectoryPlane {
    /// `Some` = this server spawned + owns a live child (authoritative status +
    /// a real Stop); `None` = fall back to the connector-status heartbeat proxy.
    pub(crate) worker: tokio::sync::Mutex<Option<DirectoryWorker>>,
    /// Service-account key PATH (`GOOGLE_APPLICATION_CREDENTIALS`). Passed to the
    /// child; the server never reads the key contents.
    pub(crate) sa_key: Option<PathBuf>,
    /// DWD subject (`VERITY_GDIRECTORY_SUBJECT`) — required to start.
    pub(crate) subject: Option<String>,
    /// Optional workspace domain (`VERITY_GDIRECTORY_DOMAIN`) for `type=CUSTOMER`.
    pub(crate) domain: Option<String>,
    /// Reconcile interval seconds (`VERITY_GDIRECTORY_INTERVAL`, default 300) —
    /// the §6a group-membership ACL-freshness bound.
    pub(crate) interval_secs: u64,
}

impl DirectoryPlane {
    /// From server env (`GOOGLE_APPLICATION_CREDENTIALS` + `VERITY_GDIRECTORY_*`).
    pub(crate) fn from_env() -> Self {
        Self {
            worker: tokio::sync::Mutex::new(None),
            sa_key: std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from),
            subject: std::env::var("VERITY_GDIRECTORY_SUBJECT")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            domain: std::env::var("VERITY_GDIRECTORY_DOMAIN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            interval_secs: std::env::var("VERITY_GDIRECTORY_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }

    /// A disabled plane (no config) — used by the test AppState builders.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            worker: tokio::sync::Mutex::new(None),
            sa_key: None,
            subject: None,
            domain: None,
            interval_secs: 300,
        }
    }

    /// SA key present on disk + a non-empty subject — decides `startable`.
    pub(crate) fn config_ready(&self) -> bool {
        config_ready(self.sa_key.as_deref(), self.subject.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fail-closed preconditions: spawn never runs a worker with missing repo /
    // venv / config, and each maps to a distinct typed error (→ 422/503, never
    // 500). No process is spawned in any of these paths.
    #[test]
    fn spawn_without_repo_is_no_repo() {
        let err = spawn(None, "http://x", Uuid::nil(), None, None, None, None, 300)
            .err()
            .expect("must fail");
        assert!(matches!(err, SpawnError::NoRepo));
    }

    #[test]
    fn spawn_without_venv_is_no_venv() {
        let repo = std::path::Path::new("/definitely/not/a/verity/repo");
        let err = spawn(
            Some(repo),
            "http://x",
            Uuid::nil(),
            None,
            None,
            None,
            None,
            300,
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoVenv(_)));
    }

    #[test]
    fn config_ready_needs_both_key_and_subject() {
        assert!(!config_ready(None, Some("admin@corp.example")));
        assert!(!config_ready(
            Some(Path::new("/no/such/key.json")),
            Some("admin@corp.example")
        ));
        // Present key path + subject would be ready; we don't touch the FS here
        // beyond the missing-path case (which is the fail-closed one).
        assert!(!DirectoryPlane::disabled().config_ready());
    }
}
