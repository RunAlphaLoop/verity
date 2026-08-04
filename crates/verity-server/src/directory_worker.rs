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

/// Which directory source a spawn targets. Both run the SAME supervised child
/// contract (NO `--once`, NO `--dry-run`, interval loop, detached stdio → a
/// per-source log, the `connector_status` heartbeat as their liveness proxy) —
/// only the Python module, the log file name, and the credential-env shape
/// differ. Keeping ONE spawn path (parameterized by this) means the two sources
/// can never drift on the supervised-child discipline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectoryKind {
    /// `verity_ingest.connectors.gdirectory` — Google Workspace (SA key +
    /// domain-wide-delegation subject). Heartbeat source `gdirectory`.
    Gdirectory,
    /// `verity_ingest.connectors.entra_directory` — Microsoft Entra ID
    /// (app-registration client credentials). Heartbeat source `entra`.
    Entra,
}

impl DirectoryKind {
    /// The Python module the worker runs (`python -m <module>`).
    fn module(self) -> &'static str {
        match self {
            DirectoryKind::Gdirectory => "verity_ingest.connectors.gdirectory",
            DirectoryKind::Entra => "verity_ingest.connectors.entra_directory",
        }
    }

    /// The detached-stdio log file (under `<repo>/ingest`), one per source so the
    /// two workers never interleave into the same file.
    fn log_name(self) -> &'static str {
        match self {
            DirectoryKind::Gdirectory => "gdirectory.log",
            DirectoryKind::Entra => "entra_directory.log",
        }
    }
}

/// The interpreter the worker runs under, given the server's repo root.
fn worker_python(repo: &Path) -> PathBuf {
    repo.join("ingest/.venv/bin/python")
}

/// The Entra app-registration credential set the server passes to the child as
/// env vars — PATHS/values ONLY, never the secret contents (the connector opens
/// the secret/cert file itself; the server never reads or logs it). The Microsoft
/// analog of gdirectory's `GOOGLE_APPLICATION_CREDENTIALS` + `--subject`.
#[derive(Clone)]
pub(crate) struct EntraCredentials {
    /// `ENTRA_TENANT_ID` — the Entra tenant GUID/domain in the token endpoint.
    pub(crate) graph_tenant: String,
    /// `ENTRA_CLIENT_ID` — the app registration's client id.
    pub(crate) client_id: String,
    /// `ENTRA_CLIENT_SECRET_FILE` — path to a file holding the client secret. The
    /// connector reads it; the server never does. Exactly one of secret/cert.
    pub(crate) client_secret_file: Option<PathBuf>,
    /// `ENTRA_CLIENT_CERT_FILE` — path to a PEM cert for cert-based app auth.
    pub(crate) client_cert_file: Option<PathBuf>,
    /// `ENTRA_ALIAS_FIELD` — the admin-declared SSO NameID field; unset = no SSO
    /// welding (fail-closed, never guessed).
    pub(crate) alias_field: Option<String>,
}

impl EntraCredentials {
    /// Whether the app-registration config is present enough to spawn: a
    /// non-empty tenant + client id AND a secret/cert file that exists on disk
    /// (path check only — contents never read, so present never claims valid).
    /// The exact `SpawnError::NoConfig` precondition, probed without spawning.
    pub(crate) fn ready(&self) -> bool {
        !self.graph_tenant.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && self.secret_or_cert_on_disk()
    }

    /// A secret OR cert file is configured and exists on disk.
    fn secret_or_cert_on_disk(&self) -> bool {
        self.client_secret_file
            .as_deref()
            .is_some_and(|p| p.exists())
            || self.client_cert_file.as_deref().is_some_and(|p| p.exists())
    }
}

/// The shared supervised-child scaffold for BOTH directory sources: check the
/// venv, ensure the state dir, open the per-source detached log, and build the
/// `Command` with the common CLI (`-m <module> --verity-url --tenant-id
/// --interval`) plus the admin token env — NO `--once`, NO `--dry-run` (a
/// continuous, live reconcile). The caller layers on the source-specific args /
/// credential env, then `finish_spawn`. Keeping this ONE function means the two
/// sources can never drift on the supervised-child discipline.
fn build_worker_command(
    kind: DirectoryKind,
    repo: &Path,
    base_url: &str,
    tenant_id: Uuid,
    admin_token: Option<&str>,
    interval_secs: u64,
) -> Result<Command, SpawnError> {
    let py = worker_python(repo);
    if !py.exists() {
        return Err(SpawnError::NoVenv(format!(
            "no ingest virtualenv at {} — create it (cd ingest && python -m venv .venv && \
             .venv/bin/pip install -e '.[gdrive]') then try again",
            py.display()
        )));
    }

    // The snapshot checkpoint lives under the ingest dir; ensure its parent
    // exists so the connector's first write can't fail on a missing dir.
    let state_dir = repo.join("ingest").join(".verity");
    let _ = std::fs::create_dir_all(&state_dir);

    // Log next to the ingest dir so it sits with the worker's own artifacts;
    // the child's stdout/stderr are detached into it (never inherited). One log
    // per source so the two workers never interleave.
    let log_path = repo.join("ingest").join(kind.log_name());
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
    cmd.args(["-m", kind.module(), "--verity-url"])
        .arg(base_url)
        .args(["--tenant-id"])
        .arg(&tenant)
        .args(["--interval"])
        .arg(&interval)
        .current_dir(repo.join("ingest"))
        .stdin(Stdio::null())
        .stdout(log2)
        .stderr(log);
    if let Some(token) = admin_token {
        cmd.env("VERITY_ADMIN_TOKEN", token);
    }
    Ok(cmd)
}

/// Spawn the built `Command` and wrap it in a tracked `DirectoryWorker`.
fn finish_spawn(mut cmd: Command, tenant_id: Uuid) -> Result<DirectoryWorker, SpawnError> {
    let child = cmd
        .spawn()
        .map_err(|e| SpawnError::Os(format!("cannot start the directory worker: {e}")))?;
    let pid = child.id();
    Ok(DirectoryWorker {
        child,
        pid,
        started_at: Utc::now(),
        tenant_id,
    })
}

/// Spawn + track the GOOGLE directory-sync worker. `repo_root` is the server's
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
    // Preserve the original precondition order (venv → config) so the resolution
    // sequence and error mapping the planes read / existing tests rely on stay
    // exact: build the command (which checks the venv) first.
    let mut cmd = build_worker_command(
        DirectoryKind::Gdirectory,
        repo,
        base_url,
        tenant_id,
        admin_token,
        interval_secs,
    )?;
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
    cmd.args(["--subject"]).arg(subject);
    if let Some(domain) = domain.filter(|d| !d.trim().is_empty()) {
        cmd.args(["--domain"]).arg(domain);
    }
    // The connector opens this path itself; the server never reads it.
    cmd.env("GOOGLE_APPLICATION_CREDENTIALS", sa_key);
    finish_spawn(cmd, tenant_id)
}

/// Spawn + track the MICROSOFT ENTRA directory-sync worker — the Microsoft analog
/// of `spawn`. Same supervised contract (NO `--once`/`--dry-run`, interval loop,
/// detached stdio → `entra_directory.log`), but the identity is an Entra app
/// registration instead of a Google SA: the credentials go to the child as env
/// vars (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET_FILE` or
/// `ENTRA_CLIENT_CERT_FILE`, `ENTRA_ALIAS_FIELD`) — PATHS/values ONLY; the server
/// NEVER reads or logs the secret/cert contents (the connector opens them).
///
/// Fail-closed preconditions (→ `SpawnError::NoConfig`, a 503, never a
/// mis-identified/half-started worker): a non-empty graph tenant + client id AND
/// a secret/cert file that exists on disk.
pub(crate) fn spawn_entra(
    repo_root: Option<&Path>,
    base_url: &str,
    tenant_id: Uuid,
    admin_token: Option<&str>,
    creds: &EntraCredentials,
    interval_secs: u64,
) -> Result<DirectoryWorker, SpawnError> {
    let repo = repo_root.ok_or(SpawnError::NoRepo)?;
    // Fail-closed config preconditions BEFORE touching the venv/log.
    if creds.graph_tenant.trim().is_empty() || creds.client_id.trim().is_empty() {
        return Err(SpawnError::NoConfig(
            "Entra directory sync needs the app registration — set ENTRA_TENANT_ID and \
             ENTRA_CLIENT_ID on the server (an admin-consented app with User.Read.All + \
             Group.Read.All + GroupMember.Read.All), then try again"
                .to_string(),
        ));
    }
    let secret = creds.client_secret_file.as_deref().filter(|p| p.exists());
    let cert = creds.client_cert_file.as_deref().filter(|p| p.exists());
    if secret.is_none() && cert.is_none() {
        return Err(SpawnError::NoConfig(
            "Entra directory sync needs an app credential — set ENTRA_CLIENT_SECRET_FILE (a file \
             holding the client secret) or ENTRA_CLIENT_CERT_FILE (a PEM cert) on the server to a \
             path that exists, then try again"
                .to_string(),
        ));
    }

    let mut cmd = build_worker_command(
        DirectoryKind::Entra,
        repo,
        base_url,
        tenant_id,
        admin_token,
        interval_secs,
    )?;
    // Credentials as env — PATHS/values only; the connector opens the secret/cert
    // file itself, so nothing secret is read or logged by the server.
    cmd.env("ENTRA_TENANT_ID", &creds.graph_tenant)
        .env("ENTRA_CLIENT_ID", &creds.client_id);
    if let Some(secret) = secret {
        cmd.env("ENTRA_CLIENT_SECRET_FILE", secret);
    }
    if let Some(cert) = cert {
        cmd.env("ENTRA_CLIENT_CERT_FILE", cert);
    }
    if let Some(field) = creds
        .alias_field
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        cmd.env("ENTRA_ALIAS_FIELD", field);
    }
    finish_spawn(cmd, tenant_id)
}

/// Whether the ingest venv Python exists for this repo root — used by the
/// planes read to decide `startable` without attempting a spawn.
pub(crate) fn venv_exists(repo_root: Option<&Path>) -> bool {
    repo_root
        .map(|r| worker_python(r).exists())
        .unwrap_or(false)
}

/// Whether the SA key path (`GOOGLE_APPLICATION_CREDENTIALS`) points at a file
/// that exists on disk — the exact `SpawnError::NoConfig` key precondition,
/// probed without spawning. Existence only; the key is never read, so present
/// never claims valid.
pub(crate) fn sa_key_ready(sa_key_path: Option<&Path>) -> bool {
    sa_key_path.is_some_and(|p| p.exists())
}

/// Whether a non-empty DWD subject (`VERITY_GDIRECTORY_SUBJECT`) is configured
/// — the exact `SpawnError::NoConfig` subject precondition.
pub(crate) fn subject_ready(subject: Option<&str>) -> bool {
    subject.is_some_and(|s| !s.trim().is_empty())
}

/// Whether the directory-sync config (SA key path present on disk + a non-empty
/// DWD subject) is in place — used by the planes read to decide `startable`.
/// Never reads the key itself.
pub(crate) fn config_ready(sa_key_path: Option<&Path>, subject: Option<&str>) -> bool {
    sa_key_ready(sa_key_path) && subject_ready(subject)
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

    /// Probe/reap the owned child under the lock: `Some` iff THIS server owns
    /// a live child RIGHT NOW, with the facts an authoritative status may
    /// claim (pid, start time, and the tenant it was spawned for). A dead
    /// child (`Some(exit)`) or an errored wait is reaped — the handle cleared
    /// — before returning `None`, never reported as a stale "on". Every admin
    /// read goes through here so the probe/reap discipline (and the worker's
    /// tenant) can never drift between them.
    pub(crate) async fn owned_live(&self) -> Option<OwnedWorker> {
        let mut guard = self.worker.lock().await;
        match guard.as_mut() {
            Some(worker) => match worker.child.try_wait() {
                Ok(None) => Some(OwnedWorker {
                    pid: worker.pid,
                    started_at: worker.started_at,
                    tenant_id: worker.tenant_id,
                }),
                _ => {
                    *guard = None;
                    None
                }
            },
            None => None,
        }
    }
}

/// The server-held MICROSOFT ENTRA directory-sync plane — the Microsoft analog
/// of `DirectoryPlane`. Same owned-child discipline (ONE owner, probe/reap via
/// `owned_live`), but the spawn config is an Entra app registration, not a
/// Google SA. Bundled so `AppState` carries ONE field.
pub(crate) struct EntraDirectoryPlane {
    /// `Some` = this server spawned + owns a live entra child (authoritative
    /// status + a real Stop); `None` = fall back to the `entra` connector-status
    /// heartbeat proxy.
    pub(crate) worker: tokio::sync::Mutex<Option<DirectoryWorker>>,
    /// The app-registration credentials passed to the child as env — PATHS/values
    /// only; the server never reads the secret/cert contents.
    pub(crate) creds: EntraCredentials,
    /// Reconcile interval seconds (`ENTRA_POLL_INTERVAL_SECS`, default 300) — the
    /// group-membership ACL-freshness bound (G3).
    pub(crate) interval_secs: u64,
}

impl EntraDirectoryPlane {
    /// From server env (`ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` /
    /// `ENTRA_CLIENT_SECRET_FILE` | `ENTRA_CLIENT_CERT_FILE` / `ENTRA_ALIAS_FIELD`
    /// / `ENTRA_POLL_INTERVAL_SECS`).
    pub(crate) fn from_env() -> Self {
        Self {
            worker: tokio::sync::Mutex::new(None),
            creds: EntraCredentials {
                graph_tenant: std::env::var("ENTRA_TENANT_ID").unwrap_or_default(),
                client_id: std::env::var("ENTRA_CLIENT_ID").unwrap_or_default(),
                client_secret_file: std::env::var_os("ENTRA_CLIENT_SECRET_FILE").map(PathBuf::from),
                client_cert_file: std::env::var_os("ENTRA_CLIENT_CERT_FILE").map(PathBuf::from),
                alias_field: std::env::var("ENTRA_ALIAS_FIELD")
                    .ok()
                    .filter(|s| !s.trim().is_empty()),
            },
            interval_secs: std::env::var("ENTRA_POLL_INTERVAL_SECS")
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
            creds: EntraCredentials {
                graph_tenant: String::new(),
                client_id: String::new(),
                client_secret_file: None,
                client_cert_file: None,
                alias_field: None,
            },
            interval_secs: 300,
        }
    }

    /// App registration present + a secret/cert on disk — decides `startable`.
    /// Never reads the secret itself.
    pub(crate) fn config_ready(&self) -> bool {
        self.creds.ready()
    }

    /// Probe/reap the owned child under the lock — same discipline as
    /// `DirectoryPlane::owned_live` (a dead child is reaped and cleared, never
    /// reported stale). `Some` iff THIS server owns a live entra child now.
    pub(crate) async fn owned_live(&self) -> Option<OwnedWorker> {
        let mut guard = self.worker.lock().await;
        match guard.as_mut() {
            Some(worker) => match worker.child.try_wait() {
                Ok(None) => Some(OwnedWorker {
                    pid: worker.pid,
                    started_at: worker.started_at,
                    tenant_id: worker.tenant_id,
                }),
                _ => {
                    *guard = None;
                    None
                }
            },
            None => None,
        }
    }
}

/// Snapshot of a live owned directory child, captured by `owned_live` while
/// holding the lock — the only facts a tier-1 authoritative status may state.
pub(crate) struct OwnedWorker {
    pub(crate) pid: u32,
    pub(crate) started_at: DateTime<Utc>,
    /// The tenant this child reconciles (fixed at spawn via `--tenant-id`) —
    /// a live child for a DIFFERENT tenant is no evidence about the queried one.
    pub(crate) tenant_id: Uuid,
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

    // ---- Entra directory worker: same fail-closed spawn discipline ---------

    fn entra_creds(secret: Option<PathBuf>) -> EntraCredentials {
        EntraCredentials {
            graph_tenant: "contoso.onmicrosoft.com".into(),
            client_id: "11111111-1111-1111-1111-111111111111".into(),
            client_secret_file: secret,
            client_cert_file: None,
            alias_field: None,
        }
    }

    #[test]
    fn spawn_entra_without_repo_is_no_repo() {
        let err = spawn_entra(
            None,
            "http://x",
            Uuid::nil(),
            None,
            &entra_creds(Some(PathBuf::from("/no/such/secret"))),
            300,
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoRepo));
    }

    #[test]
    fn spawn_entra_missing_config_is_no_config() {
        let repo = std::path::Path::new("/definitely/not/a/verity/repo");
        // Empty tenant/client → NoConfig, checked BEFORE the venv (fail-closed:
        // a misconfigured start never half-opens artifacts / mis-identifies).
        let mut creds = entra_creds(Some(PathBuf::from("/no/such/secret")));
        creds.graph_tenant = String::new();
        creds.client_id = String::new();
        let err = spawn_entra(Some(repo), "http://x", Uuid::nil(), None, &creds, 300)
            .err()
            .expect("must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));

        // App id present but NO secret/cert on disk → still NoConfig.
        let err2 = spawn_entra(
            Some(repo),
            "http://x",
            Uuid::nil(),
            None,
            &entra_creds(Some(PathBuf::from("/no/such/secret"))),
            300,
        )
        .err()
        .expect("must fail");
        assert!(matches!(err2, SpawnError::NoConfig(_)));
    }

    #[test]
    fn spawn_entra_without_venv_is_no_venv() {
        // Config satisfied (a real on-disk secret file) so the spawn reaches the
        // venv precondition, which fails for a non-repo path.
        let secret = std::env::temp_dir().join(format!("verity-entra-test-{}.txt", Uuid::new_v4()));
        std::fs::write(&secret, b"not-a-real-secret").expect("write temp secret");
        let repo = std::path::Path::new("/definitely/not/a/verity/repo");
        let err = spawn_entra(
            Some(repo),
            "http://x",
            Uuid::nil(),
            None,
            &entra_creds(Some(secret.clone())),
            300,
        )
        .err()
        .expect("must fail");
        let _ = std::fs::remove_file(&secret);
        assert!(matches!(err, SpawnError::NoVenv(_)));
    }

    #[test]
    fn entra_config_ready_needs_app_and_secret_on_disk() {
        // Missing everything → not ready.
        assert!(!EntraDirectoryPlane::disabled().config_ready());
        // Tenant + client set but the secret path does not exist → not ready.
        assert!(!entra_creds(Some(PathBuf::from("/no/such/secret"))).ready());
        // A real on-disk secret with tenant + client → ready.
        let secret =
            std::env::temp_dir().join(format!("verity-entra-ready-{}.txt", Uuid::new_v4()));
        std::fs::write(&secret, b"x").expect("write temp secret");
        assert!(entra_creds(Some(secret.clone())).ready());
        let _ = std::fs::remove_file(&secret);
    }
}
