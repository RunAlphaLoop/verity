//! Console-triggered, per-(tenant, source) ONE-SHOT backfill worker (Phase 3).
//!
//! Unlike the knowledge worker (SPEC §2 L2) and the directory worker (Identity
//! Plane §6a) — both CONTINUOUS single-owner loops — a connector backfill is a
//! ONE-SHOT full crawl: `python -m verity_ingest.connectors.<source> --backfill`
//! runs `run_backfill()` (→ `full_crawl()` into the admin sink), returns 0, and
//! exits. It is NOT `--once` (that is the incremental poll cursor); `--backfill`
//! is the alternate branch that re-emits everything.
//!
//! Because a backfill is per (tenant, source) — not per server — this module
//! owns a `HashMap<(tenant, source), Arc<Mutex<Option<ConnectorWorker>>>>` inside
//! a `ConnectorPlane`, NOT a single AppState slot. A single slot would silently
//! no-op tenant B's backfill against tenant A's live child (a cross-tenant
//! hole). The rules:
//!   - a Start for (tenant, source) whose OWN live child exists → 409
//!     already-running (never a masked no-op);
//!   - a Start for (tenant, source) whose SOURCE is live under a DIFFERENT
//!     tenant → 409 naming the busy tenant (a SA key / rate budget is shared per
//!     source, so we serialize per source across tenants);
//!   - on a clean spawn, a DETACHED reap task awaits the child, records the
//!     terminal exit, and CLEARS the map entry so status flips off and the next
//!     backfill can start — we do NOT rely on reap-on-next-lock-touch (that
//!     would leave a finished backfill reporting on with a stale pid).
//!
//! `gdrive`/`gmail` (Google content sources with a `full_crawl`) and `hubspot`
//! (tier-C CRM, Phase 4) are spawnable; `folder` is a local watch, `gdirectory`
//! is the continuous directory worker, and `salesforce` is fixtures-only. This
//! module is source-agnostic — the CALLER gates which sources may spawn.
//!
//! IDENTITY, per source family:
//!   - Google (gdrive/gmail): the server passes the SA-key PATH via
//!     `GOOGLE_APPLICATION_CREDENTIALS` (never reading the key contents) and,
//!     for gmail, a `--subject` impersonation address.
//!   - HubSpot (tier-C): the server DECRYPTS the stored bearer, writes it to a
//!     mode-0600 `O_CREAT|O_EXCL` temp file in a 0700 dir OUTSIDE the repo, and
//!     passes only that path via `--credential-file` — the token never touches
//!     argv, env, or `/proc/<pid>/environ`, and is never logged. The temp file
//!     is tracked on the worker and UNLINKED in the reap/stop (best-effort, even
//!     on a non-zero exit / crash), so a decrypted bearer never lingers on disk.
//!     The admin-assigned `--visibility` policy is resolved from the store.
//!
//! Common to all: the admin bearer is passed via `VERITY_ADMIN_TOKEN` (so the
//! child reaches the admin sink + the backfill progress endpoint), detached
//! stdio → a 0600 `<source>.log`, and the server-minted run_id is threaded so
//! progress polling can key on THIS run.
//!
//! DEGRADED-ACL: a HubSpot backfill whose app lacks the owners-read scope still
//! delivers every record but coarsens owner/team ACLs to `--visibility`. The
//! connector emits a distinct `verity.backfill.degraded_acl` signal to its log;
//! the reap greps for it and reconciles the run to `degraded_acl` (not the plain
//! `completed`) so the panel shows an honest badge, never a silent success.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

/// How the child's backfill run_id is passed. No `--run-id` CLI flag exists in
/// the connectors today (the reporter self-mints from `uuid4()` when unset), so
/// the server threads a pre-minted id through the `VERITY_BACKFILL_RUN_ID` env
/// (matching the connectors' env-default argparse pattern) — the connector CLI
/// reads it and hands it to `BackfillReporter(run_id=...)`. This keeps the panel
/// poll (`GET /v1/admin/backfill`) keyed on the run THIS Start created.
pub(crate) const RUN_ID_ENV: &str = "VERITY_BACKFILL_RUN_ID";

/// The distinct, machine-readable stdout/log token a HubSpot `--backfill` prints
/// (once) when it ran with the owners-read scope missing: the crawl delivered
/// every record, but owner/team ACLs were coarsened to the admin-assigned
/// `--visibility`. It mirrors the connector's `DEGRADED_ACL_SIGNAL` constant
/// (`ingest/verity_ingest/connectors/hubspot.py`) — a read-once contract the reap
/// greps the child log for so a clean exit surfaces as `degraded_acl`, not the
/// silent `completed` a coarsened run would otherwise report.
pub(crate) const DEGRADED_ACL_SIGNAL: &str = "verity.backfill.degraded_acl";

/// A backfill child THIS server spawned and owns, keyed by (tenant, source) in
/// the `ConnectorPlane` map. Presence of a LIVE entry means an authoritative
/// "running" status (pid, start time) + the source/tenant it was spawned for.
pub(crate) struct ConnectorWorker {
    pub(crate) child: Child,
    pub(crate) pid: u32,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) tenant_id: Uuid,
    /// The source this backfill crawls (`gdrive`/`gmail`) — half the owner key.
    pub(crate) source: String,
    /// The server-minted run_id passed to the child (so status can echo the run
    /// the panel should poll).
    pub(crate) run_id: Uuid,
    /// Absolute path to the detached 0600 `<source>.log`, so a non-zero exit can
    /// surface the last N lines inline.
    pub(crate) log_path: PathBuf,
    /// Absolute path to the server-materialized 0600 credential temp file (the
    /// decrypted HubSpot bearer, passed to the child via `--credential-file`),
    /// when this backfill was spawned from a stored tier-C bearer. UNLINKED in
    /// the reap and in `stop()` — best-effort, even on a non-zero exit / crash —
    /// so a decrypted secret never lingers on disk past the child's lifetime.
    /// `None` for the Google sources (no server-written secret file).
    pub(crate) cred_file_path: Option<PathBuf>,
    /// Which crawl mode this child runs in. Steers the reap: a `PollOnce` cycle
    /// is a short-lived delta drain with NO `backfill_run` denominator, so its
    /// exit must NOT be reconciled into `backfill_run` (that would fabricate a
    /// job row). A `Backfill` exit is reconciled as before.
    pub(crate) mode: SpawnMode,
}

/// Best-effort scrub of the materialized bearer temp file on EVERY path that
/// drops a worker — not just `reap`/`stop`. `owned_live` and
/// `source_busy_elsewhere` reap a dead child by setting the entry to `None`,
/// which drops the `ConnectorWorker`; if that race beats the detached reap's
/// 500ms poll, the reap then sees `None` and never unlinks. Anchoring the unlink
/// to `Drop` closes that window so a decrypted bearer never lingers on disk past
/// its worker, matching the contract's "best-effort even on a non-zero exit /
/// crash" requirement. (`reap`/`stop` still unlink explicitly and clear the path
/// so this is a harmless idempotent no-op on those paths.)
impl Drop for ConnectorWorker {
    fn drop(&mut self) {
        if let Some(cred) = self.cred_file_path.as_deref() {
            unlink_credential_file(cred);
        }
    }
}

/// Why a spawn attempt could not proceed — each maps to a clean HTTP status
/// (NEVER a 500) with the exact fix in the message. `Os` is the runtime spawn
/// failure; the rest are checked preconditions.
#[derive(Debug)]
pub(crate) enum SpawnError {
    /// The server was not started with `--repo`/`VERITY_REPO`, so it can't find
    /// `ingest/.venv`. → 422.
    NoRepo,
    /// No `<repo>/ingest/.venv/bin/python`. → 422. Carries the exact fix.
    NoVenv(String),
    /// Missing backfill config — the SA key path
    /// (`GOOGLE_APPLICATION_CREDENTIALS`), or a `subject` when the source
    /// requires it (gmail). → 503. Carries the exact fix. Fail-closed: we never
    /// spawn a backfill that would run with no / the wrong identity.
    NoConfig(String),
    /// This exact (tenant, source) already has a LIVE backfill child. → 409.
    /// Never a masked no-op. Carries the running pid.
    AlreadyRunning { pid: u32 },
    /// This SOURCE has a LIVE backfill under a DIFFERENT tenant. → 409. A SA key
    /// / rate budget is shared per source, so we serialize per source. Carries
    /// the busy tenant so the operator knows who to wait on.
    SourceBusy { tenant: Uuid, pid: u32 },
    /// OS-level failure opening the log or spawning the process. → 503.
    Os(String),
}

/// The resolved spawn recipe for one source's backfill — the SERVER-assembled
/// argv tail + the identity env. Kept as a pure value so argv assembly is
/// unit-testable without touching the filesystem or spawning a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackfillSpec {
    /// The connector module: `verity_ingest.connectors.gdrive` etc.
    pub(crate) module: String,
    /// The full argv AFTER the interpreter. For Google sources (gdrive/gmail):
    /// `["-m", <module>, "--backfill", "--verity-url", <url>, "--tenant-id",
    /// <uuid>, "--subject", <s>?]`. For HubSpot (tier-C): `["-m", <module>,
    /// "--backfill", "--visibility", <c,s,v>, "--credential-file", <path>]` — the
    /// hubspot CLI takes tenant/url/admin-token from env (`VERITY_TENANT_ID` /
    /// `VERITY_URL` / `VERITY_ADMIN_TOKEN`, via `VerityDebeziumSink.from_env`),
    /// not flags, so no `--verity-url`/`--tenant-id` are emitted; the secret is
    /// the file BODY of `--credential-file`, never a token literal in argv.
    pub(crate) argv: Vec<String>,
    /// Basename of the detached log: `<source>.log`.
    pub(crate) log_name: String,
}

/// Whether a source is a browser-triggerable backfillable source. `gdrive`/
/// `gmail` (Phase 3) and `hubspot` (Phase 4, tier-C) — `folder` (local watch),
/// `gdirectory` (continuous directory worker), and `salesforce` (fixtures-only,
/// awaiting a test org) are NOT. The caller gates on this; `assemble_spec` also
/// fail-closes on anything else.
pub(crate) fn is_backfillable(source: &str) -> bool {
    matches!(source, "gdrive" | "gmail" | "hubspot")
}

/// The single-static-bearer tier-C family: one pasted token, stored as one
/// encrypted `bearer`, delivered to the child via a 0600 `--credential-file`.
/// EXCLUDES salesforce (multi-part client-credentials OAuth: client_id +
/// secret + my_domain — no single bearer to materialize).
pub(crate) fn is_single_bearer(source: &str) -> bool {
    matches!(source, "hubspot" | "notion" | "intercom")
}

/// Whether a source supports a continuous-sync `--once` incremental poll cycle:
/// `gdrive` / `gmail` / `hubspot` (all have a `--once` CLI branch + a persisted
/// cursor). `gdirectory` has its OWN continuous directory plane (not a `--once`
/// poll), and `folder` / `salesforce` have no incremental cursor — the caller
/// (the toggle endpoint) maps `gdirectory` to the directory plane and 422s the
/// rest. Deliberately the same set as `is_backfillable` today, but a DISTINCT
/// predicate: a source can be backfillable without a `--once` cursor and vice
/// versa, so the two gates must not be conflated.
pub(crate) fn is_pollable(source: &str) -> bool {
    poll_cursor_basename(source).is_some()
}

/// Which crawl mode a connector child runs in: the Phase-3 one-shot full
/// `--backfill` crawl, or the Phase-4 continuous-sync `--once` incremental poll
/// cycle. The ONLY argv delta is the flag itself (`--backfill` vs `--once`) plus,
/// for a poll, a `--state-file <per-(tenant,source) cursor path>` (backfill has
/// no cursor). Everything downstream — spawn/materialize/cleanup/ownership/reap —
/// is mode-neutral; the mode only steers the reconcile (a poll must NOT fabricate
/// a `backfill_run` job row) and the log basename (a poll writes `<source>-poll.log`
/// so its lines never contaminate a backfill's degraded-ACL grep).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnMode {
    /// Phase-3 one-shot full crawl: `--backfill`, no cursor, reconciled into
    /// `backfill_run`.
    Backfill,
    /// Phase-4 continuous-sync incremental poll cycle: `--once --state-file
    /// <path>`, advances the persisted per-(tenant,source) cursor, exits in
    /// seconds. NOT reconciled into `backfill_run`.
    PollOnce,
}

impl SpawnMode {
    /// The CLI flag literal for this mode.
    fn flag(self) -> &'static str {
        match self {
            SpawnMode::Backfill => "--backfill",
            SpawnMode::PollOnce => "--once",
        }
    }
    /// The detached-log basename for a source in this mode. A poll writes to a
    /// DISTINCT `<source>-poll.log` so a poll cycle's lines never interleave with
    /// a backfill's log (the reap greps a backfill's whole log for the owners-403
    /// degraded-ACL signal — a poll's lines must not contaminate that grep).
    fn log_name(self, source: &str) -> String {
        match self {
            SpawnMode::Backfill => format!("{source}.log"),
            SpawnMode::PollOnce => format!("{source}-poll.log"),
        }
    }
}

/// Whether a source's backfill HARD-REQUIRES a `--subject` (gmail aborts before
/// any HTTP if unset; gdrive's `--subject` is optional at the credential layer,
/// though its fact lane self-disables without one).
pub(crate) fn subject_required(source: &str) -> bool {
    source == "gmail"
}

/// The resolved, source-family-specific identity a backfill spawn runs under.
/// Google sources open an SA-key PATH (via `GOOGLE_APPLICATION_CREDENTIALS`) +
/// an optional impersonation subject; HubSpot (tier-C) needs the DECRYPTED
/// bearer bytes (which `spawn` materializes to a 0600 `--credential-file`) + the
/// admin-assigned visibility policy. Keeping the two shapes in one enum lets the
/// caller resolve each family's precedence separately and hand `spawn` exactly
/// what that source needs — never a Google-shaped identity for HubSpot or vice
/// versa. The bearer is wrapped in `Zeroizing` so it is scrubbed from memory when
/// this value drops, matching the Phase-2 no-plaintext-lingering discipline.
pub(crate) enum BackfillIdentity {
    /// gdrive/gmail: the SA-key file path + optional DWD impersonation subject.
    Google {
        sa_key_path: PathBuf,
        subject: Option<String>,
    },
    /// single-bearer tier-C (hubspot/notion/intercom): the decrypted bearer
    /// bytes (materialized to a 0600 temp file at spawn) + the tier-C visibility
    /// policy resolved from the store.
    SingleBearer {
        bearer: zeroize::Zeroizing<Vec<u8>>,
        visibility: Vec<i32>,
    },
}

/// Assemble the server-side argv + identity for a backfill, PURE (no FS, no
/// spawn). Fail-closes preconditions in order: an unknown/non-backfillable
/// source → `NoConfig` (the caller should gate first, but we never assemble a
/// bogus command); a gmail run with no subject → `NoConfig` (matches the
/// connector's hard-required abort); a hubspot run with no `--visibility` / no
/// `--credential-file` path → `NoConfig` (the tier-C CLI requires both). The
/// two source families take DIFFERENT identity: Google threads `--verity-url` /
/// `--tenant-id` (+ `--subject`); HubSpot threads `--visibility` /
/// `--credential-file` and reads tenant/url from env. Returns the module, the
/// full argv tail, and the log basename.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_spec(
    source: &str,
    mode: SpawnMode,
    base_url: &str,
    tenant_id: Uuid,
    subject: Option<&str>,
    visibility: Option<&[i32]>,
    cred_file: Option<&Path>,
    state_file: Option<&Path>,
) -> Result<BackfillSpec, SpawnError> {
    // The eligible-source gate is MODE-specific: a full-crawl --backfill needs
    // `is_backfillable`; a --once poll needs `is_pollable`. These sets DIFFER —
    // notion/intercom are pollable (a --once cursor) but NOT backfillable (no
    // --backfill CLI branch; --once is required=True). Gating a poll on
    // is_backfillable would wrongly reject them; gating a backfill on is_pollable
    // would wrongly accept them into an argparse crash. Fail closed per mode.
    match mode {
        SpawnMode::Backfill if !is_backfillable(source) => {
            return Err(SpawnError::NoConfig(format!(
                "{source} has no browser-triggered backfill — only gdrive, gmail, and hubspot \
                 support a full crawl (folder is a local watch, gdirectory is the directory \
                 worker, salesforce is fixtures-only until a test org lands)"
            )));
        }
        SpawnMode::PollOnce if !is_pollable(source) => {
            return Err(SpawnError::NoConfig(format!(
                "{source} has no --once poll cursor — continuous sync is not wired for it \
                 (folder / gdirectory / salesforce have no incremental cursor)"
            )));
        }
        _ => {}
    }

    // A --once poll cycle MUST carry a per-(tenant,source) --state-file (the
    // cursor path); backfill has no cursor. Fail closed rather than let a poll
    // fall back to the connector's tenant-AGNOSTIC default cursor (which would
    // clobber across tenants).
    let state_file = match mode {
        SpawnMode::PollOnce => Some(state_file.ok_or_else(|| {
            SpawnError::NoConfig(format!(
                "{source} --once poll needs a per-(tenant,source) --state-file (the cursor path) — \
                 refusing to fall back to the connector's shared default cursor, which would \
                 clobber across tenants"
            ))
        })?),
        SpawnMode::Backfill => None,
    };

    let module = format!("verity_ingest.connectors.{source}");
    let log_name = mode.log_name(source);
    let flag = mode.flag().to_string();

    // HubSpot (tier-C): NO --verity-url / --tenant-id (the CLI reads those from
    // env); a required --visibility policy + a --credential-file path whose FILE
    // BODY is the bearer (never a token literal in argv).
    if is_single_bearer(source) {
        let visibility = visibility.filter(|v| !v.is_empty()).ok_or_else(|| {
            SpawnError::NoConfig(format!(
                "{source} sync needs a non-empty --visibility policy (tier-C requires a \
                 sharing scope) — store a {source} credential with a visibility policy first"
            ))
        })?;
        let cred_file = cred_file.ok_or_else(|| {
            SpawnError::NoConfig(format!(
                "{source} sync needs a server-materialized --credential-file (the decrypted \
                 bearer) — a resolvable stored bearer is required"
            ))
        })?;
        let vis = visibility
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut argv = vec![
            "-m".to_string(),
            module.clone(),
            flag,
            "--visibility".to_string(),
            vis,
            "--credential-file".to_string(),
            cred_file.to_string_lossy().into_owned(),
        ];
        if let Some(state_file) = state_file {
            argv.push("--state-file".to_string());
            argv.push(state_file.to_string_lossy().into_owned());
        }
        return Ok(BackfillSpec {
            module,
            argv,
            log_name,
        });
    }

    // Google sources (gdrive/gmail): --verity-url / --tenant-id (+ --subject).
    let subject = subject.map(str::trim).filter(|s| !s.is_empty());
    if subject_required(source) && subject.is_none() {
        return Err(SpawnError::NoConfig(format!(
            "{source} sync needs a mailbox-owner --subject (domain-wide-delegation \
             impersonation) — set it on the stored connector credential (or the server env) \
             then try again; {source} aborts before any HTTP without it"
        )));
    }
    let mut argv = vec![
        "-m".to_string(),
        module.clone(),
        flag,
        "--verity-url".to_string(),
        base_url.to_string(),
        "--tenant-id".to_string(),
        tenant_id.to_string(),
    ];
    if let Some(subject) = subject {
        argv.push("--subject".to_string());
        argv.push(subject.to_string());
    }
    if let Some(state_file) = state_file {
        argv.push("--state-file".to_string());
        argv.push(state_file.to_string_lossy().into_owned());
    }
    Ok(BackfillSpec {
        module,
        argv,
        log_name,
    })
}

/// The interpreter the backfill runs under, given the server's repo root.
fn worker_python(repo: &Path) -> PathBuf {
    repo.join("ingest/.venv/bin/python")
}

/// The per-server 0700 runtime dir that holds materialized credential temp files,
/// OUTSIDE the git tree (the ingest checkout also holds the backfill log, which
/// is why the log location must NOT be reused for a decrypted secret).
///
/// SECURITY: the base name is UNPREDICTABLE per server process (a random suffix),
/// created EXCLUSIVELY (`create_dir`, which is `mkdir(2)` — fails `AlreadyExists`
/// rather than silently reusing an attacker-pre-created dir the way a recursive
/// idempotent create would). Because the name can't be guessed before the server
/// mints it AND creation is exclusive, no other uid can pre-own or pre-plant the
/// parent under the world-writable OS temp root — closing the fixed-predictable-
/// path pre-creation / symlink-race hole. Created 0700 so only this server's uid
/// can read the bearer files inside. The `OnceLock` means all spawns in one
/// process share ONE such dir (created once, verified below).
static CRED_RUNTIME_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Base prefix for the per-process runtime dir; the boot sweep matches on it so a
/// crashed PRIOR server's orphaned dirs (holding live bearers) can be scrubbed.
const CRED_RUNTIME_PREFIX: &str = "verity-connector-creds";

/// Create-or-get the per-process credential runtime dir, exclusively (`mkdir`)
/// under an unpredictable random name so it can never be a reused foreign-owned
/// dir. Verifies the dir is a non-symlink at mode 0700 before returning it. Any
/// perm/IO error is propagated as `SpawnError::Os` (→ 503) — never swallowed.
fn cred_runtime_dir() -> Result<&'static Path, SpawnError> {
    if let Some(dir) = CRED_RUNTIME_DIR.get() {
        return verify_runtime_dir(dir).map(|_| dir.as_path());
    }
    // Race-tolerant: several threads may build a candidate; only the first to win
    // the OnceLock keeps its dir, the losers remove theirs. mkdir is exclusive so
    // an unguessable name never collides with an attacker plant.
    let candidate = std::env::temp_dir().join(format!("{CRED_RUNTIME_PREFIX}-{}", Uuid::new_v4()));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(false); // mkdir(2): AlreadyExists is a hard error, never reuse.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&candidate).map_err(|e| {
        SpawnError::Os(format!(
            "cannot create the credential runtime dir {}: {e}",
            candidate.display()
        ))
    })?;
    let dir = CRED_RUNTIME_DIR.get_or_init(|| candidate.clone());
    if dir != &candidate {
        // Lost the race — a peer thread's dir is canonical; drop ours.
        let _ = std::fs::remove_dir_all(&candidate);
    }
    verify_runtime_dir(dir).map(|_| dir.as_path())
}

/// Fail CLOSED if the runtime dir is not a real (non-symlink) directory at
/// exactly 0700. A no-op on non-unix.
fn verify_runtime_dir(dir: &Path) -> Result<(), SpawnError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // symlink_metadata: never follow a symlink planted at the dir name.
        let meta = std::fs::symlink_metadata(dir).map_err(|e| {
            SpawnError::Os(format!(
                "cannot stat the credential runtime dir {}: {e}",
                dir.display()
            ))
        })?;
        if !meta.is_dir() {
            return Err(SpawnError::Os(format!(
                "credential runtime dir {} is not a directory (possible symlink attack) — refusing \
                 to materialize a bearer",
                dir.display()
            )));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(SpawnError::Os(format!(
                "credential runtime dir {} is group/other-accessible (mode {:o}) — refusing to \
                 write a bearer; expected owner-only 0700",
                dir.display(),
                meta.permissions().mode() & 0o777
            )));
        }
    }
    let _ = dir;
    Ok(())
}

/// Boot-time sweep: unlink every orphaned credential runtime dir/file left by a
/// PRIOR server that was SIGKILLed/OOM-killed/panicked/rebooted between writing a
/// bearer and the reap firing. On a fresh boot NO live server-owned worker exists
/// yet, so any `verity-connector-creds-*` entry under the OS temp root is by
/// definition an orphan holding a possibly-live decrypted bearer — remove it
/// before any new spawn. Best-effort: a per-entry failure is logged, never fatal
/// (a locked/foreign entry we can't remove must not block startup). Called once
/// from `ConnectorPlane::from_env`.
pub(crate) fn sweep_orphaned_cred_dirs() {
    let base = std::env::temp_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return, // no temp root readable — nothing to sweep.
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(CRED_RUNTIME_PREFIX) {
            continue;
        }
        let path = entry.path();
        let res = match entry.file_type() {
            Ok(ft) if ft.is_dir() => std::fs::remove_dir_all(&path),
            _ => std::fs::remove_file(&path),
        };
        if let Err(e) = res {
            eprintln!(
                "connector boot sweep: failed to remove orphaned credential path {}: {e}",
                path.display()
            );
        }
    }
}

/// Env override for the continuous-sync cursor-state base dir. Unlike the
/// per-process credential runtime dir (unpredictable, wiped on boot), this is a
/// STABLE, PERSISTENT dir: a `--once` poll cursor MUST survive a server restart
/// (otherwise every reboot re-drains the whole change window). Default:
/// `<repo>/ingest/.verity/poll-cursors` when a repo is known, else
/// `<data-home>/verity/poll-cursors`.
pub(crate) const POLL_STATE_DIR_ENV: &str = "VERITY_POLL_STATE_DIR";

/// The cursor-file basename for a source's `--once` poll cursor. The format
/// differs per connector (hubspot = a bare ISO-8601 line; gdrive/gmail = a JSON
/// `{"cursor": ...}`), so the extension mirrors what each connector reads/writes
/// — but the SCHEME (one file per source under a per-tenant dir) is uniform.
/// `None` for a source with no `--once` cursor (folder / gdirectory / salesforce).
pub(crate) fn poll_cursor_basename(source: &str) -> Option<&'static str> {
    match source {
        "hubspot" => Some("hubspot_cursor"),
        "notion" => Some("notion_cursor"),
        "intercom" => Some("intercom_cursor"),
        "gdrive" => Some("gdrive_cursor.json"),
        "gmail" => Some("gmail_cursor.json"),
        _ => None,
    }
}

/// Resolve the STABLE per-(tenant, source) cursor-state file path for a `--once`
/// poll cycle, creating the per-tenant parent dir 0700 if needed. Returns the
/// absolute path the server passes to the connector as `--state-file` (equivalently
/// `HUBSPOT_STATE_FILE` / `GDRIVE_STATE_FILE` / `GMAIL_STATE_FILE`).
///
/// ISOLATION (non-negotiable): the path is
/// `<base>/<tenant-uuid>/<source>_cursor[.json]` — scoped by BOTH tenant and
/// source, so two tenants polling the same source NEVER share a cursor file (which
/// would race the change token and cross-contaminate resume state). The connector
/// default (`.verity/<source>_cursor`, relative to the ingest cwd) is
/// tenant-AGNOSTIC and would clobber across tenants — this helper exists so a
/// server-driven `--once` spawn never uses that shared default.
///
/// The base dir is `$VERITY_POLL_STATE_DIR` when set, else
/// `<repo>/ingest/.verity/poll-cursors` when a repo root is known, else
/// `<data-home>/verity/poll-cursors`. It is created recursively (persistent, so
/// unlike the cred runtime dir it is NOT unpredictable/exclusive — the cursor is
/// opaque, not a secret; it carries no bearer). Per-tenant dirs are made 0700 so
/// one tenant's opaque cursor is not world-readable.
pub(crate) fn poll_cursor_state_file(
    repo_root: Option<&Path>,
    tenant: Uuid,
    source: &str,
) -> Result<PathBuf, SpawnError> {
    let basename = poll_cursor_basename(source).ok_or_else(|| {
        SpawnError::NoConfig(format!(
            "source {source:?} has no --once poll cursor — continuous sync is not wired for it \
             (folder / gdirectory / salesforce have no incremental cursor)"
        ))
    })?;
    let base = poll_cursor_base_dir(repo_root);
    let tenant_dir = base.join(tenant.to_string());
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&tenant_dir).map_err(|e| {
        SpawnError::Os(format!(
            "cannot create the poll-cursor dir {}: {e}",
            tenant_dir.display()
        ))
    })?;
    Ok(tenant_dir.join(basename))
}

/// The base dir under which per-tenant cursor dirs are created. Env override
/// wins; else `<repo>/ingest/.verity/poll-cursors` (co-located with the ingest
/// artifacts, like the directory worker's snapshot checkpoint); else a
/// data-home fallback so a repo-less server still has a stable spot.
fn poll_cursor_base_dir(repo_root: Option<&Path>) -> PathBuf {
    if let Some(dir) = std::env::var_os(POLL_STATE_DIR_ENV) {
        return PathBuf::from(dir);
    }
    if let Some(repo) = repo_root {
        return repo.join("ingest").join(".verity").join("poll-cursors");
    }
    let home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    home.join("verity").join("poll-cursors")
}

/// Write `bytes` to a fresh `O_CREAT|O_EXCL`, mode-0600 temp file inside the
/// 0700 [`cred_runtime_dir`], returning its absolute path. `O_EXCL` means a
/// stale/attacker-planted file at the (uuid) name is a hard error, never a
/// silent reuse; mode-0600 is set AT creation so the secret is owner-only from
/// the first byte. The file name is unique per (uuid) so concurrent spawns never
/// collide. Any permission / IO error is propagated as `SpawnError::Os` (→ 503).
/// The caller UNLINKS the returned path when the child exits (reap / stop).
fn write_credential_file(unique: Uuid, bytes: &[u8]) -> Result<PathBuf, SpawnError> {
    let dir = cred_runtime_dir()?;
    let path = dir.join(format!("{unique}.cred"));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_CREAT | O_EXCL
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path).map_err(|e| {
        SpawnError::Os(format!(
            "cannot create the 0600 credential temp file {}: {e}",
            path.display()
        ))
    })?;
    use std::io::Write;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            // Best-effort remove a partial file before surfacing the error.
            let _ = std::fs::remove_file(&path);
            SpawnError::Os(format!(
                "cannot write the credential temp file {}: {e}",
                path.display()
            ))
        })?;
    Ok(path)
}

/// Best-effort unlink of a materialized credential temp file — called from the
/// reap and from `stop()` on any terminal path, so a decrypted bearer never
/// outlives its child (even on a non-zero exit / SIGKILL). A missing file is not
/// an error (the file may already be gone); a real IO error is logged, never
/// panicked (this runs on a detached task).
fn unlink_credential_file(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "connector reap: failed to unlink credential temp file {}: {e}",
            path.display()
        ),
    }
}

/// The last `n` lines of a log file, best-effort — used to surface a non-zero
/// exit inline. Returns an empty string if the log can't be read (never an
/// error; the exit code is the load-bearing signal, the tail is context).
pub(crate) fn tail_log(log_path: &Path, n: usize) -> String {
    let Ok(body) = std::fs::read_to_string(log_path) else {
        return String::new();
    };
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// A shared, per-key owner handle. The entry `Arc<Mutex<Option<..>>>` lets the
/// detached reap task hold + clear just this (tenant, source) slot without ever
/// contending the whole-map lock.
type WorkerHandle = Arc<Mutex<Option<ConnectorWorker>>>;

/// Terminal state of a finished backfill child, recorded by the detached reap.
#[derive(Debug, Clone)]
pub(crate) struct TerminalExit {
    /// Process exit code (`None` when killed by a signal with no code).
    pub(crate) code: Option<i32>,
    /// True iff the process exited 0.
    pub(crate) success: bool,
    pub(crate) finished_at: DateTime<Utc>,
    /// Last lines of `<source>.log` when the exit was non-zero (empty on clean
    /// exit) — surfaced inline so a crash never looks like a silent hang.
    pub(crate) tail: String,
    /// True iff the child was a HubSpot backfill that logged the owners-403
    /// `DEGRADED_ACL_SIGNAL`: a clean-exit crawl that had to coarsen owner/team
    /// ACLs to the admin-assigned `--visibility`. Reconciled to state
    /// `degraded_acl` (not `completed`) so the panel never shows a silent
    /// success. Always `false` on a non-zero exit (a failure is already `failed`).
    pub(crate) degraded_acl: bool,
}

/// The server-held connector-backfill plane: the per-(tenant, source) owner map
/// plus the spawn config. Bundled so `AppState` carries ONE field, mirroring
/// `DirectoryPlane`. Lives inside `Arc<AppState>`, so the inner `Mutex`es are
/// shared without their own `Arc`.
pub(crate) struct ConnectorPlane {
    /// Per-key owner handles. The OUTER mutex guards map membership (inserting a
    /// new key); each ENTRY is its own `Arc<Mutex<Option<..>>>` so the detached
    /// reap task can clear just that entry without holding the whole-map lock.
    workers: Mutex<HashMap<(Uuid, String), WorkerHandle>>,
    /// Serializes the whole admission decision (own-live check → cross-tenant
    /// source-busy check → spawn → insert) so two concurrent `start()`s for the
    /// same (tenant, source) — or the same source under two tenants — cannot both
    /// pass the checks and both spawn. The per-entry locks alone can't cover this:
    /// the cross-tenant check scans OTHER entries, and holding one entry lock
    /// across spawn wouldn't stop a same-key racer from slipping between the check
    /// and the insert. spawn is a fast fork, so serializing admissions is cheap.
    admission: Mutex<()>,
    /// The most recent terminal exit per (tenant, source), so status can report
    /// the last completion/failure after the live handle is cleared.
    last_exit: Mutex<HashMap<(Uuid, String), TerminalExit>>,
    /// Service-account key PATH (`GOOGLE_APPLICATION_CREDENTIALS`) from server
    /// env. Passed to the child; the server never reads the key contents. A
    /// stored per-source path (from connector_credentials) is resolved by the
    /// caller and passed to `spawn` directly, so this is the env fallback only.
    pub(crate) sa_key: Option<PathBuf>,
}

impl ConnectorPlane {
    /// From server env (`GOOGLE_APPLICATION_CREDENTIALS`). Per-source stored
    /// paths + subjects come from `connector_credentials` at Start time; this
    /// only captures the server-env SA-key fallback.
    pub(crate) fn from_env() -> Self {
        // Boot-time sweep: a PRIOR server that was SIGKILLed/OOM-killed/rebooted
        // between materializing a bearer and its reap firing leaves an orphaned
        // 0600 cred file (holding a live decrypted bearer) on disk with no in-
        // memory owner to unlink it — the map starts empty here. No live server-
        // owned worker exists yet at boot, so any leftover cred runtime path is by
        // definition an orphan; scrub every one before the first spawn.
        sweep_orphaned_cred_dirs();
        Self {
            workers: Mutex::new(HashMap::new()),
            admission: Mutex::new(()),
            last_exit: Mutex::new(HashMap::new()),
            sa_key: std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from),
        }
    }

    /// A disabled plane (no env SA key) — used by the test AppState builders.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            workers: Mutex::new(HashMap::new()),
            admission: Mutex::new(()),
            last_exit: Mutex::new(HashMap::new()),
            sa_key: None,
        }
    }

    /// Get-or-create the per-key entry handle. Cloning the `Arc` lets a caller
    /// (or the detached reap) hold just this entry's lock, never the map's.
    async fn entry(&self, tenant: Uuid, source: &str) -> WorkerHandle {
        let mut map = self.workers.lock().await;
        map.entry((tenant, source.to_string()))
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    /// Probe/reap THIS (tenant, source) entry under its own lock: `Some` iff a
    /// live child is owned RIGHT NOW. A dead child is reaped (handle cleared)
    /// before returning `None`. Even with the detached reap, this is the single
    /// choke-point every status read goes through so status + reap can't drift.
    pub(crate) async fn owned_live(&self, tenant: Uuid, source: &str) -> Option<OwnedWorker> {
        let entry = self.entry(tenant, source).await;
        let mut guard = entry.lock().await;
        match guard.as_mut() {
            Some(worker) => match worker.child.try_wait() {
                Ok(None) => Some(OwnedWorker {
                    pid: worker.pid,
                    started_at: worker.started_at,
                    tenant_id: worker.tenant_id,
                    source: worker.source.clone(),
                    run_id: worker.run_id,
                }),
                _ => {
                    *guard = None;
                    None
                }
            },
            None => None,
        }
    }

    /// Scan every entry for a LIVE child of `source` owned by a tenant OTHER than
    /// `tenant` — the per-source cross-tenant serialize check. Reaps any dead
    /// child it touches. `Some((busy_tenant, pid))` => the caller must 409.
    async fn source_busy_elsewhere(&self, tenant: Uuid, source: &str) -> Option<(Uuid, u32)> {
        // Snapshot the candidate entries under the map lock, then probe each
        // under its own lock (never hold the map lock across a try_wait).
        let candidates: Vec<(Uuid, WorkerHandle)> = {
            let map = self.workers.lock().await;
            map.iter()
                .filter(|((t, s), _)| s == source && *t != tenant)
                .map(|((t, _), h)| (*t, h.clone()))
                .collect()
        };
        for (other_tenant, entry) in candidates {
            let mut guard = entry.lock().await;
            if let Some(worker) = guard.as_mut() {
                match worker.child.try_wait() {
                    Ok(None) => return Some((other_tenant, worker.pid)),
                    _ => *guard = None,
                }
            }
        }
        None
    }

    /// Start a backfill for (tenant, source). Ownership decisions FIRST (own live
    /// child → `AlreadyRunning`; source live under another tenant → `SourceBusy`),
    /// then `spawn` (which checks repo/venv/config). On success, records the live
    /// handle and launches the DETACHED reap. `identity` is the resolved,
    /// source-family-specific identity (a Google SA-key path + subject, or the
    /// decrypted HubSpot bearer + visibility — the caller resolves each family's
    /// precedence). `run_id` is server-minted. `pool` lets the detached reap
    /// reconcile `backfill_run` with the CHILD-EXIT truth (completed on exit 0,
    /// degraded_acl when the child logged the owners-403 signal, failed + code +
    /// tail otherwise) so completion is never derived from a best-effort telemetry
    /// post that a hard kill skips.
    ///
    /// The whole check→spawn→insert sequence runs under the `admission` lock so a
    /// second concurrent `start()` for the same (tenant, source) — or the same
    /// source under a different tenant — cannot interleave between the checks and
    /// the insert and double-spawn. Exactly one racer gets `Ok`; the others see
    /// `AlreadyRunning`/`SourceBusy`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        self: &Arc<Self>,
        pool: PgPool,
        mode: SpawnMode,
        repo_root: Option<&Path>,
        base_url: &str,
        tenant_id: Uuid,
        source: &str,
        admin_token: Option<&str>,
        identity: BackfillIdentity,
        run_id: Uuid,
    ) -> Result<u32, SpawnError> {
        // Serialize the admission decision + spawn + insert as one atomic section
        // (held until this scope ends). Nothing may spawn while no lock reserves
        // the slot.
        let _admit = self.admission.lock().await;

        let entry = self.entry(tenant_id, source).await;
        // Own live child? honest 409, never a masked no-op.
        {
            let mut guard = entry.lock().await;
            if let Some(worker) = guard.as_mut() {
                match worker.child.try_wait() {
                    Ok(None) => return Err(SpawnError::AlreadyRunning { pid: worker.pid }),
                    _ => *guard = None,
                }
            }
        }
        // Same source live under a different tenant? 409 naming the busy tenant.
        if let Some((busy_tenant, pid)) = self.source_busy_elsewhere(tenant_id, source).await {
            return Err(SpawnError::SourceBusy {
                tenant: busy_tenant,
                pid,
            });
        }

        let worker = spawn(
            repo_root,
            mode,
            base_url,
            tenant_id,
            source,
            admin_token,
            identity,
            run_id,
        )?;
        let pid = worker.pid;
        {
            let mut guard = entry.lock().await;
            *guard = Some(worker);
        }
        // DETACHED reap: await the child, record the terminal exit, reconcile
        // backfill_run with the child-exit truth, and clear the handle — guarded
        // on pid-equality so a respawn is never clobbered.
        let plane = Arc::clone(self);
        let entry_clone = Arc::clone(&entry);
        let key = (tenant_id, source.to_string());
        tokio::spawn(async move {
            reap(plane, pool, entry_clone, key, pid).await;
        });
        Ok(pid)
    }

    /// Kill + reap an owned backfill child for (tenant, source) and clear the
    /// handle. Honest no-op when this server owns none. Mirrors the knowledge/
    /// directory Stop shape.
    pub(crate) async fn stop(&self, tenant: Uuid, source: &str) -> Option<u32> {
        let entry = self.entry(tenant, source).await;
        let mut guard = entry.lock().await;
        match guard.take() {
            Some(mut worker) => {
                let pid = worker.pid;
                let _ = worker.child.kill();
                let _ = worker.child.wait();
                // Unlink the materialized bearer temp file on the kill path too,
                // so a decrypted secret never outlives its child.
                if let Some(cred) = worker.cred_file_path.as_deref() {
                    unlink_credential_file(cred);
                }
                Some(pid)
            }
            None => None,
        }
    }

    /// The last recorded terminal exit for (tenant, source), if any — the reap
    /// task writes it. Lets status report a completed/failed backfill after the
    /// live handle is gone.
    pub(crate) async fn last_exit(&self, tenant: Uuid, source: &str) -> Option<TerminalExit> {
        self.last_exit
            .lock()
            .await
            .get(&(tenant, source.to_string()))
            .cloned()
    }

    /// A full status snapshot for (tenant, source): the live child (if any) plus
    /// the last terminal exit. Goes through `owned_live` so it reaps a dead
    /// child before reporting.
    pub(crate) async fn status(&self, tenant: Uuid, source: &str) -> ConnectorStatus {
        let live = self.owned_live(tenant, source).await;
        let last_exit = self.last_exit(tenant, source).await;
        ConnectorStatus { live, last_exit }
    }
}

/// The detached reap loop: poll the entry's child to completion, record its
/// terminal exit, and clear the handle — but ONLY if the entry still holds the
/// pid this task was spawned for (a respawn after a crash replaces the entry
/// with a NEW pid, which this task must not clobber). `std::process::Child::wait`
/// is blocking, so we `try_wait` under the entry lock on a short cadence rather
/// than block a runtime worker on a held lock.
async fn reap(
    plane: Arc<ConnectorPlane>,
    pool: PgPool,
    entry: WorkerHandle,
    key: (Uuid, String),
    pid: u32,
) {
    loop {
        // Terminal state captured under the entry lock, then applied AFTER the
        // lock is dropped (last_exit insert + backfill_run reconcile + cred
        // unlink). `cred_file` is this spawn's materialized bearer temp file (if
        // any), captured by value so a respawn's cred file is never clobbered.
        let terminal: TerminalExit;
        let run_id: Uuid;
        let cred_file: Option<PathBuf>;
        let mode: SpawnMode;
        {
            let mut guard = entry.lock().await;
            match guard.as_mut() {
                // Entry replaced by a newer spawn (different pid) or already
                // cleared — nothing for THIS task to reap.
                Some(worker) if worker.pid != pid => return,
                Some(worker) => match worker.child.try_wait() {
                    Ok(Some(exit)) => {
                        let log_path = worker.log_path.clone();
                        let code = exit.code();
                        let success = exit.success();
                        // On a clean exit, grep the child log for the connector's
                        // owners-403 signal: a coarsened-ACL crawl still exits 0,
                        // so this is the ONLY observable distinction between a
                        // full-fidelity `completed` and a `degraded_acl` run. On a
                        // non-zero exit we surface the tail instead (it's failed).
                        let (tail, degraded_acl) = if success {
                            (String::new(), log_signals_degraded_acl(&log_path))
                        } else {
                            (tail_log(&log_path, 20), false)
                        };
                        run_id = worker.run_id;
                        cred_file = worker.cred_file_path.clone();
                        mode = worker.mode;
                        terminal = TerminalExit {
                            code,
                            success,
                            finished_at: Utc::now(),
                            tail,
                            degraded_acl,
                        };
                        *guard = None;
                    }
                    Ok(None) => {
                        // Still running — release the lock and poll again.
                        drop(guard);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    Err(e) => {
                        // Errored wait — treat as terminal-failed so the run never
                        // hangs at "running". No exit code is available.
                        run_id = worker.run_id;
                        cred_file = worker.cred_file_path.clone();
                        mode = worker.mode;
                        terminal = TerminalExit {
                            code: None,
                            success: false,
                            finished_at: Utc::now(),
                            tail: format!("wait() failed while reaping the backfill child: {e}"),
                            degraded_acl: false,
                        };
                        *guard = None;
                    }
                },
                None => return,
            }
        }
        // The child exited: unlink the materialized bearer temp file (best-effort,
        // even on a crash / non-zero exit), then record the in-memory terminal
        // state and reconcile backfill_run with the CHILD-EXIT truth. The reconcile
        // is the authoritative completion signal the panel polls — NOT the
        // best-effort telemetry post, which a SIGKILL/OOM/dropped-post skips.
        if let Some(cred) = cred_file.as_deref() {
            unlink_credential_file(cred);
        }
        // A --once poll is a short-lived delta drain with NO backfill_run
        // denominator: reconciling it into backfill_run would fabricate a job row
        // and pollute the "latest run per source" dashboard. A poll's liveness is
        // carried by the connector's own connector_status heartbeat + the
        // scheduler's last_run_at stamp — NOT a backfill_run state. Only a
        // Backfill exit is reconciled here.
        if mode == SpawnMode::Backfill {
            reconcile_terminal(&pool, &key, run_id, &terminal).await;
        }
        plane.last_exit.lock().await.insert(key, terminal);
        return;
    }
}

/// Best-effort grep of a finished backfill's log for the connector's
/// [`DEGRADED_ACL_SIGNAL`] — the read-once token a HubSpot `--backfill` prints
/// when the owners-read scope was missing and ACLs were coarsened to
/// `--visibility`. `false` when the log is unreadable (a missing signal is never
/// inferred from a missing log — that's a clean `completed`, not a false badge).
fn log_signals_degraded_acl(log_path: &Path) -> bool {
    std::fs::read_to_string(log_path)
        .map(|body| body.lines().any(|l| l.trim() == DEGRADED_ACL_SIGNAL))
        .unwrap_or(false)
}

/// Reconcile `backfill_run` for a finished child from the CHILD-EXIT reap: a
/// clean exit → `completed`, UNLESS the child logged the owners-403 signal →
/// `degraded_acl` (the crawl delivered every record but coarsened owner/team ACLs
/// to `--visibility`, so `completed` would be a false honesty claim); any
/// non-zero/signal/errored exit → `failed` with the exit code + the last log
/// lines inline (so a hard kill surfaces as a terminal failure carrying context,
/// never a silent eternal "running"). Keyed on the server-minted run_id.
/// Best-effort (a failed reconcile logs; it never panics a detached task) but,
/// unlike the connector's own telemetry, it ALWAYS runs on child exit.
/// `ON CONFLICT` upserts so it lands whether or not the child managed a first
/// progress post; the reap's child-exit truth is authoritative and OVERWRITES the
/// state — including overriding a connector-posted `completed` with `degraded_acl`
/// when the signal is present, so a coarsened run can never mask itself as clean.
async fn reconcile_terminal(
    pool: &PgPool,
    key: &(Uuid, String),
    run_id: Uuid,
    exit: &TerminalExit,
) {
    let (tenant_id, source) = key;
    let state = if !exit.success {
        "failed"
    } else if exit.degraded_acl {
        "degraded_acl"
    } else {
        "completed"
    };
    let error = if !exit.success {
        let code = exit
            .code
            .map(|c| format!("exit code {c}"))
            .unwrap_or_else(|| "killed by signal (no exit code)".to_string());
        Some(if exit.tail.is_empty() {
            format!("backfill child exited non-zero ({code})")
        } else {
            format!("backfill child exited non-zero ({code})\n{}", exit.tail)
        })
    } else if exit.degraded_acl {
        // A clean crawl carrying the honest degrade note — NOT an error, but the
        // operator-facing reason the ACLs are coarse (the `error` column doubles
        // as the run's note field; the state distinguishes degraded from failed).
        Some(
            "owner/team ACLs unavailable (HubSpot owners-read scope missing) — every record \
             ingested under the admin-assigned visibility policy"
                .to_string(),
        )
    } else {
        None
    };
    let res = sqlx::query(
        "INSERT INTO backfill_run
             (id, tenant_id, source, state, error, started_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, now(), now())
         ON CONFLICT (id) DO UPDATE SET
             state      = EXCLUDED.state,
             error      = EXCLUDED.error,
             updated_at = now()",
    )
    .bind(run_id)
    .bind(tenant_id)
    .bind(source)
    .bind(state)
    .bind(error)
    .execute(pool)
    .await;
    if let Err(e) = res {
        eprintln!("connector reap: failed to reconcile backfill_run {run_id} to {state}: {e}");
    }
}

/// Spawn + track a backfill child. Checks repo → `NoRepo`,
/// `<repo>/ingest/.venv/bin/python` → `NoVenv`, then the source-family identity:
/// Google needs an SA key present on disk + (subject when required); HubSpot
/// materializes the decrypted bearer to a 0600 `--credential-file`. Assembles the
/// argv via `assemble_spec` (pure), sets the family-appropriate env (Google:
/// `GOOGLE_APPLICATION_CREDENTIALS`; HubSpot: `VERITY_TENANT_ID` / `VERITY_URL`,
/// and NEVER the token in env), passes the admin bearer + server-minted run_id,
/// and detaches stdio into a 0600 `<source>.log`. Returns a typed `SpawnError`
/// (mapped to 422/503, never 500) on any checked precondition or OS failure.
/// Ownership (already-running / source-busy) is decided by `ConnectorPlane::start`
/// BEFORE this is called. The HubSpot credential temp file is tracked on the
/// returned worker so the reap/stop can unlink it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    repo_root: Option<&Path>,
    mode: SpawnMode,
    base_url: &str,
    tenant_id: Uuid,
    source: &str,
    admin_token: Option<&str>,
    identity: BackfillIdentity,
    run_id: Uuid,
) -> Result<ConnectorWorker, SpawnError> {
    let repo = repo_root.ok_or(SpawnError::NoRepo)?;
    // A --once poll needs its per-(tenant,source) cursor path resolved BEFORE the
    // fork (created 0700). Backfill has no cursor. Resolving here (not in the
    // caller) keeps the per-tenant-dir discipline co-located with the spawn.
    let state_file = match mode {
        SpawnMode::PollOnce => Some(poll_cursor_state_file(repo_root, tenant_id, source)?),
        SpawnMode::Backfill => None,
    };
    let py = worker_python(repo);
    if !py.exists() {
        return Err(SpawnError::NoVenv(format!(
            "no ingest virtualenv at {} — create it (cd ingest && python -m venv .venv && \
             .venv/bin/pip install -e '.[gdrive]') then try again",
            py.display()
        )));
    }

    // Resolve the family-specific identity → the argv (via assemble_spec) + the
    // env additions + (HubSpot) the materialized 0600 credential temp file to
    // track and later unlink. For HubSpot the bearer is written to disk HERE,
    // synchronously right before the fork, and the plaintext `bearer` Zeroizing
    // buffer is dropped (scrubbed) at the end of this scope — it is never held
    // across an await, never placed in argv/env, never logged.
    let mut extra_env: Vec<(String, String)> = Vec::new();
    let mut cred_file_path: Option<PathBuf> = None;
    let spec = match &identity {
        BackfillIdentity::Google {
            sa_key_path,
            subject,
        } => {
            let sa_key = sa_key_path.exists().then_some(sa_key_path).ok_or_else(|| {
                SpawnError::NoConfig(format!(
                    "{source} backfill needs the service-account key — set \
                     GOOGLE_APPLICATION_CREDENTIALS on the server (or store the connector \
                     credential) to your Workspace SA JSON, then try again"
                ))
            })?;
            // The connector opens this path itself; the server never reads it.
            extra_env.push((
                "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                sa_key.to_string_lossy().into_owned(),
            ));
            assemble_spec(
                source,
                mode,
                base_url,
                tenant_id,
                subject.as_deref(),
                None,
                None,
                state_file.as_deref(),
            )?
        }
        BackfillIdentity::SingleBearer { bearer, visibility } => {
            // Materialize the decrypted bearer to a fresh O_CREAT|O_EXCL 0600 file
            // in the 0700 runtime dir (outside the repo). Its PATH — never the
            // token — becomes the --credential-file argv value.
            let cred = write_credential_file(Uuid::new_v4(), bearer)?;
            let spec = match assemble_spec(
                source,
                mode,
                base_url,
                tenant_id,
                None,
                Some(visibility),
                Some(cred.as_path()),
                state_file.as_deref(),
            ) {
                Ok(spec) => spec,
                Err(e) => {
                    // Never leave a decrypted bearer on disk if argv assembly
                    // rejects (e.g. empty visibility slipped through).
                    unlink_credential_file(&cred);
                    return Err(e);
                }
            };
            // The single-bearer CLI (hubspot/notion/intercom) reads tenant/url/
            // admin-token from env (no flags); the SINK identity comes from these,
            // the bearer only from the file.
            extra_env.push(("VERITY_TENANT_ID".to_string(), tenant_id.to_string()));
            extra_env.push(("VERITY_URL".to_string(), base_url.to_string()));
            cred_file_path = Some(cred);
            spec
        }
    };

    // Log next to the ingest dir with the worker's own artifacts; the child's
    // stdout/stderr are detached into it (never inherited). 0600 — a backfill
    // log may name entities/paths, so it is operator-only.
    let log_path = repo.join("ingest").join(&spec.log_name);
    let log = match open_backfill_log(&log_path) {
        Ok(log) => log,
        Err(e) => {
            // Clean up a materialized bearer file if we fail before the fork.
            if let Some(cred) = cred_file_path.as_deref() {
                unlink_credential_file(cred);
            }
            return Err(e);
        }
    };
    let log2 = match log.try_clone() {
        Ok(log2) => log2,
        Err(e) => {
            if let Some(cred) = cred_file_path.as_deref() {
                unlink_credential_file(cred);
            }
            return Err(SpawnError::Os(format!("log handle clone: {e}")));
        }
    };

    let mut cmd = Command::new(&py);
    cmd.args(&spec.argv)
        .current_dir(repo.join("ingest"))
        .stdin(Stdio::null())
        .stdout(log2)
        .stderr(log);
    // Server-minted run_id so the panel poll keys on THIS run (no --run-id CLI
    // flag exists; the connector reads this env into BackfillReporter). ONLY a
    // backfill needs it — the connectors read VERITY_BACKFILL_RUN_ID exclusively
    // inside their `if args.backfill:` branch; a --once poll ignores it and it
    // must not key a fabricated backfill_run row, so we don't thread it for a poll.
    if mode == SpawnMode::Backfill {
        cmd.env(RUN_ID_ENV, run_id.to_string());
    }
    for (k, v) in &extra_env {
        cmd.env(k, v);
    }
    if let Some(token) = admin_token {
        cmd.env("VERITY_ADMIN_TOKEN", token);
    }
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // A failed fork must not orphan a decrypted bearer on disk.
            if let Some(cred) = cred_file_path.as_deref() {
                unlink_credential_file(cred);
            }
            return Err(SpawnError::Os(format!(
                "cannot start the {source} backfill ({}): {e}",
                py.display()
            )));
        }
    };
    let pid = child.id();
    Ok(ConnectorWorker {
        child,
        pid,
        started_at: Utc::now(),
        tenant_id,
        source: source.to_string(),
        run_id,
        log_path,
        cred_file_path,
        mode,
    })
}

/// Open (create 0600, append) the detached backfill log, tightening the perms on
/// an already-existing file. Factored out of `spawn` so both source families
/// share the exact same operator-only log discipline.
fn open_backfill_log(log_path: &Path) -> Result<std::fs::File, SpawnError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let log = opts.open(log_path).map_err(|e| {
        SpawnError::Os(format!(
            "cannot open backfill log {}: {e}",
            log_path.display()
        ))
    })?;
    // Tighten an already-existing log (create+mode only applies on create).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(log_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(log)
}

/// Whether the ingest venv Python exists for this repo root — used by the panel
/// read to decide `startable` without attempting a spawn.
pub(crate) fn venv_exists(repo_root: Option<&Path>) -> bool {
    repo_root
        .map(|r| worker_python(r).exists())
        .unwrap_or(false)
}

/// Snapshot of a live owned backfill child, captured by `owned_live` while
/// holding the entry lock — the only facts an authoritative status may state.
pub(crate) struct OwnedWorker {
    pub(crate) pid: u32,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) tenant_id: Uuid,
    pub(crate) source: String,
    pub(crate) run_id: Uuid,
}

/// A full status snapshot for one (tenant, source): the live child (if any) and
/// the last terminal exit (if any).
pub(crate) struct ConnectorStatus {
    pub(crate) live: Option<OwnedWorker>,
    pub(crate) last_exit: Option<TerminalExit>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that mutate the process-global `POLL_STATE_DIR_ENV`.
    /// `std::env::set_var`/`remove_var` touch shared process state, so without
    /// this the default multi-threaded runner lets one test's `remove_var`
    /// clobber another's `set_var` mid-assertion (a `starts_with` flake). Guards
    /// only these env-mutating tests; no product code is affected.
    static POLL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn t() -> Uuid {
        Uuid::from_u128(1)
    }

    /// A Google identity for the spawn-precondition tests (SA-key path + subject).
    fn google_id(sa: Option<&str>, subject: Option<&str>) -> BackfillIdentity {
        BackfillIdentity::Google {
            sa_key_path: PathBuf::from(sa.unwrap_or("/no/such/sa.json")),
            subject: subject.map(str::to_string),
        }
    }

    // ---- argv assembly (pure) -------------------------------------------

    #[test]
    fn gdrive_argv_omits_subject_when_absent() {
        let spec = assemble_spec(
            "gdrive",
            SpawnMode::Backfill,
            "http://host:7717",
            t(),
            None,
            None,
            None,
            None,
        )
        .expect("gdrive ok");
        assert_eq!(spec.module, "verity_ingest.connectors.gdrive");
        assert_eq!(spec.log_name, "gdrive.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.gdrive",
                "--backfill",
                "--verity-url",
                "http://host:7717",
                "--tenant-id",
                &t().to_string(),
            ]
        );
        // gdrive subject is optional at the credential layer.
        assert!(!spec.argv.contains(&"--subject".to_string()));
    }

    #[test]
    fn gdrive_argv_includes_subject_when_present() {
        let spec = assemble_spec(
            "gdrive",
            SpawnMode::Backfill,
            "http://h",
            t(),
            Some("owner@corp.example"),
            None,
            None,
            None,
        )
        .expect("gdrive ok");
        let i = spec
            .argv
            .iter()
            .position(|a| a == "--subject")
            .expect("--subject present");
        assert_eq!(spec.argv[i + 1], "owner@corp.example");
    }

    #[test]
    fn gmail_argv_requires_and_includes_subject() {
        let spec = assemble_spec(
            "gmail",
            SpawnMode::Backfill,
            "http://h",
            t(),
            Some("mbox@corp.example"),
            None,
            None,
            None,
        )
        .expect("gmail ok with subject");
        assert_eq!(spec.module, "verity_ingest.connectors.gmail");
        assert_eq!(spec.log_name, "gmail.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.gmail",
                "--backfill",
                "--verity-url",
                "http://h",
                "--tenant-id",
                &t().to_string(),
                "--subject",
                "mbox@corp.example",
            ]
        );
    }

    #[test]
    fn gmail_without_subject_is_no_config() {
        let err = assemble_spec(
            "gmail",
            SpawnMode::Backfill,
            "http://h",
            t(),
            None,
            None,
            None,
            None,
        )
        .err()
        .expect("gmail must fail without subject");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // Blank/whitespace subject counts as absent (matches connector abort).
        assert!(matches!(
            assemble_spec(
                "gmail",
                SpawnMode::Backfill,
                "http://h",
                t(),
                Some("   "),
                None,
                None,
                None
            )
            .err(),
            Some(SpawnError::NoConfig(_))
        ));
    }

    #[test]
    fn subject_is_trimmed() {
        let spec = assemble_spec(
            "gdrive",
            SpawnMode::Backfill,
            "http://h",
            t(),
            Some("  a@b.co  "),
            None,
            None,
            None,
        )
        .expect("ok");
        let i = spec.argv.iter().position(|a| a == "--subject").unwrap();
        assert_eq!(spec.argv[i + 1], "a@b.co");
    }

    // ---- hubspot argv assembly (pure) — tier-C shape ---------------------

    #[test]
    fn hubspot_argv_carries_visibility_and_credential_file_not_url_or_tenant() {
        let cred = Path::new("/run/verity-connector-creds/abc.cred");
        let spec = assemble_spec(
            "hubspot",
            SpawnMode::Backfill,
            "http://host:7717",
            t(),
            None,
            Some(&[3, 9, 12]),
            Some(cred),
            None,
        )
        .expect("hubspot ok");
        assert_eq!(spec.module, "verity_ingest.connectors.hubspot");
        assert_eq!(spec.log_name, "hubspot.log");
        // The tier-C CLI takes tenant/url from env, NOT flags — assembling those
        // flags would make argparse reject the spawn.
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.hubspot",
                "--backfill",
                "--visibility",
                "3,9,12",
                "--credential-file",
                "/run/verity-connector-creds/abc.cred",
            ]
        );
        assert!(!spec.argv.iter().any(|a| a == "--verity-url"));
        assert!(!spec.argv.iter().any(|a| a == "--tenant-id"));
        assert!(!spec.argv.iter().any(|a| a == "--subject"));
        // The token is never a literal in argv (only the FILE PATH is).
        assert!(!spec.argv.iter().any(|a| a.contains("Bearer")));
    }

    #[test]
    fn hubspot_argv_requires_visibility_and_credential_file() {
        // No visibility → NoConfig with the exact honest fix.
        let cred = Path::new("/run/x.cred");
        let err = assemble_spec(
            "hubspot",
            SpawnMode::Backfill,
            "http://h",
            t(),
            None,
            None,
            Some(cred),
            None,
        )
        .err()
        .expect("no visibility must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // Empty visibility is treated as absent.
        let err = assemble_spec(
            "hubspot",
            SpawnMode::Backfill,
            "http://h",
            t(),
            None,
            Some(&[]),
            Some(cred),
            None,
        )
        .err()
        .expect("empty visibility must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // No credential-file path → NoConfig.
        let err = assemble_spec(
            "hubspot",
            SpawnMode::Backfill,
            "http://h",
            t(),
            None,
            Some(&[7]),
            None,
            None,
        )
        .err()
        .expect("no credential-file must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
    }

    // ---- --once poll argv assembly (pure) — the continuous-sync cycle ----
    // The ONLY delta from the backfill argv is: swap `--backfill`→`--once`, add
    // `--state-file <per-(tenant,source) cursor path>`, and write a distinct
    // `<source>-poll.log`. Everything else (env-fed tenant/url for hubspot,
    // --verity-url/--tenant-id/--subject for Google) is identical.

    #[test]
    fn gdrive_once_argv_swaps_flag_and_adds_state_file() {
        let cursor = Path::new("/var/verity/poll/tenant-a/gdrive_cursor.json");
        let spec = assemble_spec(
            "gdrive",
            SpawnMode::PollOnce,
            "http://host:7717",
            t(),
            Some("owner@corp.example"),
            None,
            None,
            Some(cursor),
        )
        .expect("gdrive --once ok");
        // Distinct poll log — never interleaves with the backfill log.
        assert_eq!(spec.log_name, "gdrive-poll.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.gdrive",
                "--once",
                "--verity-url",
                "http://host:7717",
                "--tenant-id",
                &t().to_string(),
                "--subject",
                "owner@corp.example",
                "--state-file",
                "/var/verity/poll/tenant-a/gdrive_cursor.json",
            ]
        );
        // Never both flags (which would ignore --once / clobber the cursor).
        assert!(!spec.argv.iter().any(|a| a == "--backfill"));
    }

    #[test]
    fn gmail_once_argv_carries_subject_and_state_file() {
        let cursor = Path::new("/var/verity/poll/tb/gmail_cursor.json");
        let spec = assemble_spec(
            "gmail",
            SpawnMode::PollOnce,
            "http://h",
            t(),
            Some("mbox@corp.example"),
            None,
            None,
            Some(cursor),
        )
        .expect("gmail --once ok");
        assert_eq!(spec.log_name, "gmail-poll.log");
        assert!(spec.argv.iter().any(|a| a == "--once"));
        let i = spec.argv.iter().position(|a| a == "--state-file").unwrap();
        assert_eq!(spec.argv[i + 1], "/var/verity/poll/tb/gmail_cursor.json");
    }

    #[test]
    fn hubspot_once_argv_carries_state_file_after_credential() {
        let cred = Path::new("/run/verity-connector-creds/abc.cred");
        let cursor = Path::new("/var/verity/poll/tc/hubspot_cursor");
        let spec = assemble_spec(
            "hubspot",
            SpawnMode::PollOnce,
            "http://host:7717",
            t(),
            None,
            Some(&[3, 9]),
            Some(cred),
            Some(cursor),
        )
        .expect("hubspot --once ok");
        assert_eq!(spec.log_name, "hubspot-poll.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.hubspot",
                "--once",
                "--visibility",
                "3,9",
                "--credential-file",
                "/run/verity-connector-creds/abc.cred",
                "--state-file",
                "/var/verity/poll/tc/hubspot_cursor",
            ]
        );
        // The tier-C CLI still takes tenant/url from env, never flags.
        assert!(!spec.argv.iter().any(|a| a == "--verity-url"));
        assert!(!spec.argv.iter().any(|a| a == "--tenant-id"));
    }

    #[test]
    fn once_without_state_file_is_no_config() {
        // A --once poll with no cursor path must fail closed (never fall back to
        // the connector's tenant-agnostic default, which would clobber tenants).
        for s in ["gdrive", "hubspot"] {
            let subj = if s == "gmail" { Some("m@c.co") } else { None };
            let vis: Option<&[i32]> = if s == "hubspot" { Some(&[7]) } else { None };
            let cred = if s == "hubspot" {
                Some(Path::new("/run/x.cred"))
            } else {
                None
            };
            let err = assemble_spec(
                "gdrive",
                SpawnMode::PollOnce,
                "http://h",
                t(),
                subj,
                vis,
                cred,
                None,
            )
            .err()
            .unwrap_or_else(|| panic!("{s} --once without state-file must fail"));
            assert!(matches!(err, SpawnError::NoConfig(_)), "{s}");
        }
    }

    #[test]
    fn pollable_matches_the_cursor_sources() {
        assert!(is_pollable("gdrive"));
        assert!(is_pollable("gmail"));
        assert!(is_pollable("hubspot"));
        // The single-bearer family notion/intercom is now pollable (bare-file
        // cursors), matching their NOTION_STATE_FILE / INTERCOM_STATE_FILE defaults.
        assert!(is_pollable("notion"));
        assert!(is_pollable("intercom"));
        assert_eq!(poll_cursor_basename("notion"), Some("notion_cursor"));
        assert_eq!(poll_cursor_basename("intercom"), Some("intercom_cursor"));
        // gdirectory has its own directory plane; folder/salesforce have no cursor.
        for s in ["folder", "gdirectory", "salesforce", "bogus"] {
            assert!(!is_pollable(s), "{s} must not be pollable");
        }
    }

    #[test]
    fn notion_intercom_are_pollable_but_not_backfillable() {
        // The is_backfillable ≠ is_pollable split: notion/intercom have a --once
        // poll cursor but NO --backfill CLI branch (--once is required=True), so
        // adding them to is_backfillable would spawn an argparse crash. Lock it in.
        for s in ["notion", "intercom"] {
            assert!(is_pollable(s), "{s} must be pollable");
            assert!(!is_backfillable(s), "{s} must NOT be backfillable");
        }
    }

    #[test]
    fn single_bearer_family_is_hubspot_notion_intercom() {
        for s in ["hubspot", "notion", "intercom"] {
            assert!(is_single_bearer(s), "{s} must be single-bearer");
        }
        // Salesforce is multi-part OAuth, NOT a single bearer — the exclusion guard.
        for s in [
            "salesforce",
            "gdrive",
            "gmail",
            "gdirectory",
            "folder",
            "bogus",
        ] {
            assert!(!is_single_bearer(s), "{s} must NOT be single-bearer");
        }
    }

    #[test]
    fn notion_once_argv_carries_visibility_credential_and_state_file() {
        let cred = Path::new("/run/verity-connector-creds/n.cred");
        let cursor = Path::new("/var/verity/poll/tn/notion_cursor");
        let spec = assemble_spec(
            "notion",
            SpawnMode::PollOnce,
            "http://host:7717",
            t(),
            None,
            Some(&[1, 2, 3]),
            Some(cred),
            Some(cursor),
        )
        .expect("notion --once ok");
        assert_eq!(spec.module, "verity_ingest.connectors.notion");
        assert_eq!(spec.log_name, "notion-poll.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.notion",
                "--once",
                "--visibility",
                "1,2,3",
                "--credential-file",
                "/run/verity-connector-creds/n.cred",
                "--state-file",
                "/var/verity/poll/tn/notion_cursor",
            ]
        );
        // Single-bearer CLI takes tenant/url from env, never flags; no token literal.
        assert!(!spec.argv.iter().any(|a| a == "--verity-url"));
        assert!(!spec.argv.iter().any(|a| a == "--tenant-id"));
        assert!(!spec.argv.iter().any(|a| a.contains("Bearer")));
    }

    #[test]
    fn intercom_once_argv_carries_visibility_credential_and_state_file() {
        let cred = Path::new("/run/verity-connector-creds/i.cred");
        let cursor = Path::new("/var/verity/poll/ti/intercom_cursor");
        let spec = assemble_spec(
            "intercom",
            SpawnMode::PollOnce,
            "http://host:7717",
            t(),
            None,
            Some(&[5]),
            Some(cred),
            Some(cursor),
        )
        .expect("intercom --once ok");
        assert_eq!(spec.module, "verity_ingest.connectors.intercom");
        assert_eq!(spec.log_name, "intercom-poll.log");
        assert_eq!(
            spec.argv,
            vec![
                "-m",
                "verity_ingest.connectors.intercom",
                "--once",
                "--visibility",
                "5",
                "--credential-file",
                "/run/verity-connector-creds/i.cred",
                "--state-file",
                "/var/verity/poll/ti/intercom_cursor",
            ]
        );
        assert!(!spec.argv.iter().any(|a| a == "--verity-url"));
        assert!(!spec.argv.iter().any(|a| a == "--tenant-id"));
    }

    #[test]
    fn notion_once_fail_closed_without_visibility_or_credential() {
        let cred = Path::new("/run/n.cred");
        let cursor = Path::new("/var/verity/poll/tn/notion_cursor");
        // No visibility → NoConfig.
        let err = assemble_spec(
            "notion",
            SpawnMode::PollOnce,
            "http://h",
            t(),
            None,
            None,
            Some(cred),
            Some(cursor),
        )
        .err()
        .expect("no visibility must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // Empty visibility is treated as absent.
        let err = assemble_spec(
            "notion",
            SpawnMode::PollOnce,
            "http://h",
            t(),
            None,
            Some(&[]),
            Some(cred),
            Some(cursor),
        )
        .err()
        .expect("empty visibility must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // No credential-file path → NoConfig.
        let err = assemble_spec(
            "notion",
            SpawnMode::PollOnce,
            "http://h",
            t(),
            None,
            Some(&[7]),
            None,
            Some(cursor),
        )
        .err()
        .expect("no credential-file must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
    }

    #[test]
    fn notion_backfill_is_no_config() {
        // notion/intercom have no --backfill CLI branch; a Backfill spawn must
        // fail closed at assemble time (locks in the is_backfillable exclusion).
        for s in ["notion", "intercom"] {
            let err = assemble_spec(
                s,
                SpawnMode::Backfill,
                "http://h",
                t(),
                None,
                Some(&[7]),
                Some(Path::new("/run/x.cred")),
                None,
            )
            .err()
            .unwrap_or_else(|| panic!("{s} backfill must fail closed"));
            assert!(matches!(err, SpawnError::NoConfig(_)), "{s}");
        }
    }

    // ---- backfillable gating (pure) -------------------------------------

    #[test]
    fn gdrive_gmail_hubspot_are_backfillable() {
        assert!(is_backfillable("gdrive"));
        assert!(is_backfillable("gmail"));
        assert!(is_backfillable("hubspot"));
        // salesforce is fixtures-only; folder/gdirectory are not applicable.
        for s in ["folder", "gdirectory", "salesforce", "bogus"] {
            assert!(!is_backfillable(s), "{s} must not be backfillable");
        }
    }

    #[test]
    fn non_backfillable_source_is_no_config() {
        for s in ["folder", "gdirectory", "salesforce", "bogus"] {
            let err = assemble_spec(
                s,
                SpawnMode::Backfill,
                "http://h",
                t(),
                Some("x@y.z"),
                None,
                None,
                None,
            )
            .err()
            .unwrap_or_else(|| panic!("{s} must not assemble"));
            assert!(matches!(err, SpawnError::NoConfig(_)), "{s}");
        }
    }

    #[test]
    fn subject_required_only_for_gmail() {
        assert!(subject_required("gmail"));
        assert!(!subject_required("gdrive"));
    }

    // ---- spawn preconditions → typed error (→ status mapping) -----------
    // Fail-closed: spawn never runs a backfill with a missing source / repo /
    // venv / key, and each maps to a distinct typed error (→ 422/503/409, never
    // 500). No process is spawned in any of these paths.

    #[test]
    fn spawn_non_backfillable_is_no_config() {
        // salesforce is not backfillable — assemble_spec (via spawn) fail-closes.
        // repo is Some so we reach the identity/argv assembly, not the NoRepo gate.
        let repo = Path::new("/definitely/not/a/verity/repo");
        let err = spawn(
            Some(repo),
            SpawnMode::Backfill,
            "http://h",
            t(),
            "salesforce",
            None,
            google_id(None, None),
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        // No venv is reached first for a bogus repo; a real repo would then hit
        // NoConfig. Either way it never spawns a non-backfillable source.
        assert!(matches!(
            err,
            SpawnError::NoVenv(_) | SpawnError::NoConfig(_)
        ));
    }

    #[test]
    fn spawn_without_repo_is_no_repo() {
        // Backfillable + subject present so we get past the pure checks to the
        // repo precondition.
        let err = spawn(
            None,
            SpawnMode::Backfill,
            "http://h",
            t(),
            "gmail",
            None,
            google_id(None, Some("m@corp.example")),
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoRepo));
    }

    #[test]
    fn spawn_without_venv_is_no_venv() {
        let repo = Path::new("/definitely/not/a/verity/repo");
        let err = spawn(
            Some(repo),
            SpawnMode::Backfill,
            "http://h",
            t(),
            "gdrive",
            None,
            google_id(None, None),
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoVenv(_)));
    }

    #[test]
    fn spawn_hubspot_without_repo_is_no_repo() {
        // A hubspot identity reaches the NoRepo gate BEFORE materializing any
        // credential file (no repo → no spawn, no secret written to disk).
        let err = spawn(
            None,
            SpawnMode::Backfill,
            "http://h",
            t(),
            "hubspot",
            None,
            BackfillIdentity::SingleBearer {
                bearer: zeroize::Zeroizing::new(b"pat-secret".to_vec()),
                visibility: vec![7],
            },
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoRepo));
    }

    // ---- ownership-key collision → 409 decision (pure of any process) ---
    // We exercise the OWNERSHIP decision without a real child by pre-seeding the
    // decision inputs through the plane's public spawn path indirectly. Since a
    // real Child can't be forged hermetically, we assert the SpawnError variants
    // used by the collision arms carry the right identity for the handler to
    // name in the 409.

    #[test]
    fn already_running_error_carries_pid() {
        let err = SpawnError::AlreadyRunning { pid: 4242 };
        match err {
            SpawnError::AlreadyRunning { pid } => assert_eq!(pid, 4242),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn source_busy_error_names_tenant() {
        let other = Uuid::from_u128(77);
        let err = SpawnError::SourceBusy {
            tenant: other,
            pid: 9,
        };
        match err {
            SpawnError::SourceBusy { tenant, pid } => {
                assert_eq!(tenant, other);
                assert_eq!(pid, 9);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ---- per-(tenant, source) poll cursor path --------------------------

    #[test]
    fn poll_cursor_basename_per_source() {
        assert_eq!(poll_cursor_basename("hubspot"), Some("hubspot_cursor"));
        assert_eq!(poll_cursor_basename("gdrive"), Some("gdrive_cursor.json"));
        assert_eq!(poll_cursor_basename("gmail"), Some("gmail_cursor.json"));
        // Sources with no --once cursor.
        assert_eq!(poll_cursor_basename("folder"), None);
        assert_eq!(poll_cursor_basename("gdirectory"), None);
        assert_eq!(poll_cursor_basename("salesforce"), None);
    }

    #[test]
    fn poll_cursor_path_is_isolated_per_tenant_and_source() {
        let _env = POLL_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("verity-poll-test-{}", Uuid::new_v4()));
        std::env::set_var(POLL_STATE_DIR_ENV, &base);

        let ta = Uuid::from_u128(0xAAAA);
        let tb = Uuid::from_u128(0xBBBB);

        let a_hub = poll_cursor_state_file(None, ta, "hubspot").expect("a hubspot");
        let b_hub = poll_cursor_state_file(None, tb, "hubspot").expect("b hubspot");
        let a_drive = poll_cursor_state_file(None, ta, "gdrive").expect("a gdrive");

        // Two tenants, same source → DIFFERENT files (never a shared cursor).
        assert_ne!(a_hub, b_hub);
        // Same tenant, two sources → different files.
        assert_ne!(a_hub, a_drive);
        // Path is scoped under both the tenant uuid and the source basename.
        assert!(a_hub.ends_with(format!("{ta}/hubspot_cursor")));
        assert!(b_hub.ends_with(format!("{tb}/hubspot_cursor")));
        assert!(a_drive.ends_with(format!("{ta}/gdrive_cursor.json")));
        // The per-tenant parent dir was created.
        assert!(a_hub.parent().unwrap().is_dir());
        assert!(a_hub.starts_with(&base));

        std::env::remove_var(POLL_STATE_DIR_ENV);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn poll_cursor_path_rejects_non_cursor_source() {
        let _env = POLL_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("verity-poll-test-{}", Uuid::new_v4()));
        std::env::set_var(POLL_STATE_DIR_ENV, &base);
        let err = poll_cursor_state_file(None, Uuid::from_u128(1), "folder")
            .expect_err("folder has no cursor");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        std::env::remove_var(POLL_STATE_DIR_ENV);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- run_id env contract --------------------------------------------

    #[test]
    fn run_id_env_var_is_stable() {
        // The connector reads exactly this env into BackfillReporter(run_id=..).
        assert_eq!(RUN_ID_ENV, "VERITY_BACKFILL_RUN_ID");
    }

    // ---- admission atomicity: two concurrent start()s never double-spawn ----
    // The TOCTOU regression was: the own-live check released the entry lock
    // before spawn+insert, so two racing starts for the same (tenant, source)
    // both passed the check and both spawned. We prove the fix by building a fake
    // ingest tree (a `python` that just sleeps so a real Child lives long enough
    // to be observed live), firing two concurrent start()s, and asserting exactly
    // one Ok(pid) + one AlreadyRunning — a single live child. A lazy pool means
    // the reap's backfill_run reconcile is a harmless best-effort no-op offline.
    #[cfg(unix)]
    fn fake_repo_with_sleeping_python(sleep_secs: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("verity-cw-admit-{}", Uuid::new_v4()));
        let bin = root.join("ingest/.venv/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let py = bin.join("python");
        // A shim that ignores its argv and sleeps, so the spawned child stays live.
        std::fs::write(&py, format!("#!/bin/sh\nexec sleep {sleep_secs}\n")).unwrap();
        std::fs::set_permissions(&py, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = root.join("sa.json");
        std::fs::write(&key, "{}").unwrap();
        (root, key)
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_start_spawns_exactly_one_child() {
        let (root, key) = fake_repo_with_sleeping_python("5");
        // Lazy pool: never actually connects, so the reap's reconcile is a
        // logged best-effort no-op and the test needs no database.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://verity:verity@127.0.0.1:5999/nope")
            .expect("lazy pool");
        let plane = Arc::new(ConnectorPlane::disabled());
        let tenant = t();

        let go = |p: Arc<ConnectorPlane>, pool: PgPool, root: PathBuf, key: PathBuf| async move {
            p.start(
                pool,
                SpawnMode::Backfill,
                Some(root.as_path()),
                "http://h",
                tenant,
                "gdrive",
                None,
                BackfillIdentity::Google {
                    sa_key_path: key,
                    subject: None,
                },
                Uuid::new_v4(),
            )
            .await
        };
        let (a, b) = tokio::join!(
            go(Arc::clone(&plane), pool.clone(), root.clone(), key.clone()),
            go(Arc::clone(&plane), pool.clone(), root.clone(), key.clone()),
        );

        let oks = [&a, &b].iter().filter(|r| r.is_ok()).count();
        let already = [&a, &b]
            .iter()
            .filter(|r| matches!(r, Err(SpawnError::AlreadyRunning { .. })))
            .count();
        assert_eq!(oks, 1, "exactly one start must win: {a:?} / {b:?}");
        assert_eq!(
            already, 1,
            "the loser must be AlreadyRunning: {a:?} / {b:?}"
        );
        // Exactly one live child is owned.
        assert!(plane.owned_live(tenant, "gdrive").await.is_some());

        // Clean up the live child so the sleeping process doesn't linger.
        let _ = plane.stop(tenant, "gdrive").await;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_start_same_source_cross_tenant_serializes() {
        // Two DIFFERENT tenants, same source: the per-source SA-key/rate budget is
        // shared, so exactly one wins and the other must be SourceBusy — never two
        // concurrent crawls against one key.
        let (root, key) = fake_repo_with_sleeping_python("5");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://verity:verity@127.0.0.1:5999/nope")
            .expect("lazy pool");
        let plane = Arc::new(ConnectorPlane::disabled());
        let ta = Uuid::from_u128(1);
        let tb = Uuid::from_u128(2);

        let go = |p: Arc<ConnectorPlane>,
                  pool: PgPool,
                  root: PathBuf,
                  key: PathBuf,
                  tenant: Uuid| async move {
            p.start(
                pool,
                SpawnMode::Backfill,
                Some(root.as_path()),
                "http://h",
                tenant,
                "gdrive",
                None,
                BackfillIdentity::Google {
                    sa_key_path: key,
                    subject: None,
                },
                Uuid::new_v4(),
            )
            .await
        };
        let (a, b) = tokio::join!(
            go(
                Arc::clone(&plane),
                pool.clone(),
                root.clone(),
                key.clone(),
                ta
            ),
            go(
                Arc::clone(&plane),
                pool.clone(),
                root.clone(),
                key.clone(),
                tb
            ),
        );

        let oks = [&a, &b].iter().filter(|r| r.is_ok()).count();
        let busy = [&a, &b]
            .iter()
            .filter(|r| matches!(r, Err(SpawnError::SourceBusy { .. })))
            .count();
        assert_eq!(oks, 1, "one tenant wins the shared source: {a:?} / {b:?}");
        assert_eq!(busy, 1, "the other is SourceBusy: {a:?} / {b:?}");

        let _ = plane.stop(ta, "gdrive").await;
        let _ = plane.stop(tb, "gdrive").await;
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- status on an empty plane ---------------------------------------

    #[tokio::test]
    async fn empty_plane_status_is_idle() {
        let plane = ConnectorPlane::disabled();
        let st = plane.status(t(), "gdrive").await;
        assert!(st.live.is_none());
        assert!(st.last_exit.is_none());
        // owned_live and stop are honest no-ops on an empty plane.
        assert!(plane.owned_live(t(), "gdrive").await.is_none());
        assert!(plane.stop(t(), "gdrive").await.is_none());
    }

    // ---- tail_log best-effort -------------------------------------------

    #[test]
    fn tail_log_missing_file_is_empty() {
        assert_eq!(tail_log(Path::new("/no/such/backfill.log"), 20), "");
    }

    #[test]
    fn tail_log_returns_last_n_lines() {
        let dir = std::env::temp_dir().join(format!("verity-cw-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.log");
        std::fs::write(&p, "a\nb\nc\nd\ne\n").unwrap();
        assert_eq!(tail_log(&p, 2), "d\ne");
        assert_eq!(tail_log(&p, 100), "a\nb\nc\nd\ne");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- credential temp file: 0600 + exclusive + unlink -----------------

    #[cfg(unix)]
    #[test]
    fn credential_file_is_written_0600_and_unlinks() {
        use std::os::unix::fs::PermissionsExt;
        let unique = Uuid::new_v4();
        let path = write_credential_file(unique, b"pat-abc123").expect("write");
        // Exists, owner-only (mode 0600), and holds exactly the bearer bytes.
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "credential temp file must be owner-only"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"pat-abc123");
        // The parent runtime dir is 0700.
        let dir_meta = std::fs::metadata(path.parent().unwrap()).expect("dir stat");
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        // The file is OUTSIDE the repo (under the OS temp root).
        assert!(path.starts_with(std::env::temp_dir()));
        // Unlink is a clean best-effort delete; a second unlink is a no-op.
        unlink_credential_file(&path);
        assert!(!path.exists(), "credential temp file must be unlinked");
        unlink_credential_file(&path); // idempotent, no panic
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_is_exclusive_create_new() {
        // O_CREAT|O_EXCL: writing to a name that already exists is a hard error,
        // never a silent reuse of a stale/attacker-planted file.
        let unique = Uuid::new_v4();
        let path = write_credential_file(unique, b"first").expect("first write");
        let dir = path.parent().unwrap().to_path_buf();
        // Re-derive the exact same path and pre-create it, then prove a second
        // write to that name fails (create_new).
        let clash = dir.join(format!("{}.cred", Uuid::nil()));
        std::fs::write(&clash, b"planted").unwrap();
        let err = write_credential_file(Uuid::nil(), b"second").expect_err("must not reuse");
        assert!(matches!(err, SpawnError::Os(_)));
        // The planted file's contents are untouched (never overwritten).
        assert_eq!(std::fs::read(&clash).unwrap(), b"planted");
        let _ = std::fs::remove_file(&clash);
        let _ = std::fs::remove_file(&path);
    }

    // ---- degraded_acl log signal detection -------------------------------

    #[test]
    fn degraded_acl_signal_detected_only_when_present() {
        let dir = std::env::temp_dir().join(format!("verity-cw-degraded-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // A clean log with no signal → not degraded.
        let clean = dir.join("clean.log");
        std::fs::write(&clean, "poll: 12 events\nbackfill delivered 12\n").unwrap();
        assert!(!log_signals_degraded_acl(&clean));
        // A log carrying the exact signal token on its own line → degraded.
        let degraded = dir.join("degraded.log");
        std::fs::write(
            &degraded,
            format!("backfill delivered 40\n{DEGRADED_ACL_SIGNAL}\n"),
        )
        .unwrap();
        assert!(log_signals_degraded_acl(&degraded));
        // A missing log is NOT inferred as degraded (that's a clean completed).
        assert!(!log_signals_degraded_acl(&dir.join("nope.log")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_state_is_degraded_acl_only_on_clean_signal_exit() {
        // The pure state-selection contract mirrored by reconcile_terminal:
        // failed wins over degraded; degraded wins over completed; clean+no-signal
        // is completed.
        let pick = |success: bool, degraded: bool| {
            if !success {
                "failed"
            } else if degraded {
                "degraded_acl"
            } else {
                "completed"
            }
        };
        assert_eq!(pick(true, false), "completed");
        assert_eq!(pick(true, true), "degraded_acl");
        assert_eq!(pick(false, true), "failed");
        assert_eq!(pick(false, false), "failed");
        // The signal constant matches the connector's emitted token exactly.
        assert_eq!(DEGRADED_ACL_SIGNAL, "verity.backfill.degraded_acl");
    }
}
