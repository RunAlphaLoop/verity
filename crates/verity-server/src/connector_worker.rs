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
//! Only `gdrive`/`gmail` are spawnable (content sources with a `full_crawl`);
//! `folder` is a local watch, `gdirectory` is the continuous directory worker,
//! and `hubspot`/`salesforce` are not wired in Phase 3. This module is
//! source-agnostic — the CALLER gates which sources may spawn.
//!
//! The server assembles the argv and passes the SA-key PATH via
//! `GOOGLE_APPLICATION_CREDENTIALS` (never reading the key contents) and the
//! admin bearer via `VERITY_ADMIN_TOKEN` (so the child reaches the admin sink +
//! the backfill progress endpoint). Detached stdio → a 0600 `<source>.log`. The
//! backfill run_id is server-minted and passed through so progress polling can
//! key on THIS run.

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
    /// The full argv AFTER the interpreter: `["-m", <module>, "--backfill",
    /// "--verity-url", <url>, "--tenant-id", <uuid>, "--subject", <s>?]`.
    pub(crate) argv: Vec<String>,
    /// Basename of the detached log: `<source>.log`.
    pub(crate) log_name: String,
}

/// Whether a source is a Phase-3 backfillable content source. `gdrive`/`gmail`
/// only — `folder` (local watch), `gdirectory` (continuous directory worker),
/// and `hubspot`/`salesforce` (not wired in Phase 3) are NOT. The caller gates
/// on this; `assemble_spec` also fail-closes on anything else.
pub(crate) fn is_backfillable(source: &str) -> bool {
    matches!(source, "gdrive" | "gmail")
}

/// Whether a source's backfill HARD-REQUIRES a `--subject` (gmail aborts before
/// any HTTP if unset; gdrive's `--subject` is optional at the credential layer,
/// though its fact lane self-disables without one).
pub(crate) fn subject_required(source: &str) -> bool {
    source == "gmail"
}

/// Assemble the server-side argv + identity for a backfill, PURE (no FS, no
/// spawn). Fail-closes preconditions in order: an unknown/non-backfillable
/// source → `NoConfig` (the caller should gate first, but we never assemble a
/// bogus command); a gmail run with no subject → `NoConfig` (matches the
/// connector's hard-required abort). Returns the module, the full argv tail, and
/// the log basename.
pub(crate) fn assemble_spec(
    source: &str,
    base_url: &str,
    tenant_id: Uuid,
    subject: Option<&str>,
) -> Result<BackfillSpec, SpawnError> {
    if !is_backfillable(source) {
        return Err(SpawnError::NoConfig(format!(
            "{source} has no Phase-3 backfill — only gdrive and gmail support a full crawl \
             (folder is a local watch, gdirectory is the directory worker, hubspot/salesforce \
             are not wired until Phase 4)"
        )));
    }
    let subject = subject.map(str::trim).filter(|s| !s.is_empty());
    if subject_required(source) && subject.is_none() {
        return Err(SpawnError::NoConfig(format!(
            "{source} backfill needs a mailbox-owner --subject (domain-wide-delegation \
             impersonation) — set it on the stored connector credential (or the server env) \
             then try again; {source} aborts before any HTTP without it"
        )));
    }

    let module = format!("verity_ingest.connectors.{source}");
    let mut argv = vec![
        "-m".to_string(),
        module.clone(),
        "--backfill".to_string(),
        "--verity-url".to_string(),
        base_url.to_string(),
        "--tenant-id".to_string(),
        tenant_id.to_string(),
    ];
    if let Some(subject) = subject {
        argv.push("--subject".to_string());
        argv.push(subject.to_string());
    }
    Ok(BackfillSpec {
        module,
        argv,
        log_name: format!("{source}.log"),
    })
}

/// The interpreter the backfill runs under, given the server's repo root.
fn worker_python(repo: &Path) -> PathBuf {
    repo.join("ingest/.venv/bin/python")
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
    /// handle and launches the DETACHED reap. `sa_key_path` is the resolved SA
    /// key (stored per-source path OR the env fallback — the caller resolves the
    /// precedence). `run_id` is server-minted. `pool` lets the detached reap
    /// reconcile `backfill_run` with the CHILD-EXIT truth (completed on exit 0,
    /// failed + code + tail otherwise) so completion is never derived from a
    /// best-effort telemetry post that a hard kill skips.
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
        repo_root: Option<&Path>,
        base_url: &str,
        tenant_id: Uuid,
        source: &str,
        admin_token: Option<&str>,
        sa_key_path: Option<&Path>,
        subject: Option<&str>,
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
            base_url,
            tenant_id,
            source,
            admin_token,
            sa_key_path,
            subject,
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
        // lock is dropped (last_exit insert + backfill_run reconcile).
        let terminal: TerminalExit;
        let run_id: Uuid;
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
                        let tail = if success {
                            String::new()
                        } else {
                            tail_log(&log_path, 20)
                        };
                        run_id = worker.run_id;
                        terminal = TerminalExit {
                            code,
                            success,
                            finished_at: Utc::now(),
                            tail,
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
                        terminal = TerminalExit {
                            code: None,
                            success: false,
                            finished_at: Utc::now(),
                            tail: format!("wait() failed while reaping the backfill child: {e}"),
                        };
                        *guard = None;
                    }
                },
                None => return,
            }
        }
        // The child exited: record the in-memory terminal state and reconcile
        // backfill_run with the CHILD-EXIT truth. This is the authoritative
        // completion signal the panel polls — NOT the best-effort telemetry post,
        // which a SIGKILL/OOM/dropped-post skips entirely.
        reconcile_terminal(&pool, &key, run_id, &terminal).await;
        plane.last_exit.lock().await.insert(key, terminal);
        return;
    }
}

/// Reconcile `backfill_run` for a finished child from the CHILD-EXIT reap: a
/// clean exit → `completed`; any non-zero/signal/errored exit → `failed` with the
/// exit code + the last log lines inline (so a hard kill surfaces as a terminal
/// failure carrying context, never a silent eternal "running"). Keyed on the
/// server-minted run_id. Best-effort (a failed reconcile logs; it never panics a
/// detached task) but, unlike the connector's own telemetry, it ALWAYS runs on
/// child exit. `ON CONFLICT` upserts so it lands whether or not the child managed
/// a first progress post; a terminal telemetry post that already landed is
/// idempotently re-affirmed to the same terminal state.
async fn reconcile_terminal(
    pool: &PgPool,
    key: &(Uuid, String),
    run_id: Uuid,
    exit: &TerminalExit,
) {
    let (tenant_id, source) = key;
    let state = if exit.success { "completed" } else { "failed" };
    let error = if exit.success {
        None
    } else {
        let code = exit
            .code
            .map(|c| format!("exit code {c}"))
            .unwrap_or_else(|| "killed by signal (no exit code)".to_string());
        Some(if exit.tail.is_empty() {
            format!("backfill child exited non-zero ({code})")
        } else {
            format!("backfill child exited non-zero ({code})\n{}", exit.tail)
        })
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
/// `<repo>/ingest/.venv/bin/python` → `NoVenv`, SA key path present on disk +
/// (subject when required) → `NoConfig`, before spawning. Assembles the argv via
/// `assemble_spec` (pure), sets `GOOGLE_APPLICATION_CREDENTIALS` to the key path,
/// passes the admin bearer + server-minted run_id through env, and detaches
/// stdio into a 0600 `<source>.log`. Returns a typed `SpawnError` (mapped to
/// 422/503, never 500) on any checked precondition or OS failure. Ownership
/// (already-running / source-busy) is decided by `ConnectorPlane::start` BEFORE
/// this is called.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    repo_root: Option<&Path>,
    base_url: &str,
    tenant_id: Uuid,
    source: &str,
    admin_token: Option<&str>,
    sa_key_path: Option<&Path>,
    subject: Option<&str>,
    run_id: Uuid,
) -> Result<ConnectorWorker, SpawnError> {
    // Pure precondition: backfillable source + required subject present.
    let spec = assemble_spec(source, base_url, tenant_id, subject)?;

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
        SpawnError::NoConfig(format!(
            "{source} backfill needs the service-account key — set \
             GOOGLE_APPLICATION_CREDENTIALS on the server (or store the connector credential) \
             to your Workspace SA JSON, then try again"
        ))
    })?;

    // Log next to the ingest dir with the worker's own artifacts; the child's
    // stdout/stderr are detached into it (never inherited). 0600 — a backfill
    // log may name entities/paths, so it is operator-only.
    let log_path = repo.join("ingest").join(&spec.log_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let log = opts.open(&log_path).map_err(|e| {
        SpawnError::Os(format!(
            "cannot open backfill log {}: {e}",
            log_path.display()
        ))
    })?;
    // Tighten an already-existing log (create+mode only applies on create).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
    }
    let log2 = log
        .try_clone()
        .map_err(|e| SpawnError::Os(format!("log handle clone: {e}")))?;

    let mut cmd = Command::new(&py);
    cmd.args(&spec.argv)
        .current_dir(repo.join("ingest"))
        // The connector opens this path itself; the server never reads it.
        .env("GOOGLE_APPLICATION_CREDENTIALS", sa_key)
        // Server-minted run_id so the panel poll keys on THIS run (no --run-id
        // CLI flag exists; the connector reads this env into BackfillReporter).
        .env(RUN_ID_ENV, run_id.to_string())
        .stdin(Stdio::null())
        .stdout(log2)
        .stderr(log);
    if let Some(token) = admin_token {
        cmd.env("VERITY_ADMIN_TOKEN", token);
    }
    let child = cmd.spawn().map_err(|e| {
        SpawnError::Os(format!(
            "cannot start the {source} backfill ({}): {e}",
            py.display()
        ))
    })?;
    let pid = child.id();
    Ok(ConnectorWorker {
        child,
        pid,
        started_at: Utc::now(),
        tenant_id,
        source: source.to_string(),
        run_id,
        log_path,
    })
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

    fn t() -> Uuid {
        Uuid::from_u128(1)
    }

    // ---- argv assembly (pure) -------------------------------------------

    #[test]
    fn gdrive_argv_omits_subject_when_absent() {
        let spec = assemble_spec("gdrive", "http://host:7717", t(), None).expect("gdrive ok");
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
        let spec = assemble_spec("gdrive", "http://h", t(), Some("owner@corp.example"))
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
        let spec = assemble_spec("gmail", "http://h", t(), Some("mbox@corp.example"))
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
        let err = assemble_spec("gmail", "http://h", t(), None)
            .err()
            .expect("gmail must fail without subject");
        assert!(matches!(err, SpawnError::NoConfig(_)));
        // Blank/whitespace subject counts as absent (matches connector abort).
        assert!(matches!(
            assemble_spec("gmail", "http://h", t(), Some("   ")).err(),
            Some(SpawnError::NoConfig(_))
        ));
    }

    #[test]
    fn subject_is_trimmed() {
        let spec = assemble_spec("gdrive", "http://h", t(), Some("  a@b.co  ")).expect("ok");
        let i = spec.argv.iter().position(|a| a == "--subject").unwrap();
        assert_eq!(spec.argv[i + 1], "a@b.co");
    }

    // ---- backfillable gating (pure) -------------------------------------

    #[test]
    fn only_gdrive_gmail_are_backfillable() {
        assert!(is_backfillable("gdrive"));
        assert!(is_backfillable("gmail"));
        for s in ["folder", "gdirectory", "hubspot", "salesforce", "bogus"] {
            assert!(!is_backfillable(s), "{s} must not be backfillable");
        }
    }

    #[test]
    fn non_backfillable_source_is_no_config() {
        for s in ["folder", "gdirectory", "hubspot", "salesforce", "bogus"] {
            let err = assemble_spec(s, "http://h", t(), Some("x@y.z"))
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
        let err = spawn(
            None,
            "http://h",
            t(),
            "hubspot",
            None,
            None,
            None,
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoConfig(_)));
    }

    #[test]
    fn spawn_without_repo_is_no_repo() {
        // Backfillable + subject present so we get past the pure checks to the
        // repo precondition.
        let err = spawn(
            None,
            "http://h",
            t(),
            "gmail",
            None,
            None,
            Some("m@corp.example"),
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
            "http://h",
            t(),
            "gdrive",
            None,
            None,
            None,
            Uuid::from_u128(9),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, SpawnError::NoVenv(_)));
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
                Some(root.as_path()),
                "http://h",
                tenant,
                "gdrive",
                None,
                Some(key.as_path()),
                None,
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
                Some(root.as_path()),
                "http://h",
                tenant,
                "gdrive",
                None,
                Some(key.as_path()),
                None,
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
}
