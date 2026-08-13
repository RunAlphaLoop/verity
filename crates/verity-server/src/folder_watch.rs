//! Server-side local-folder watching (ingest write-path).
//!
//! The dev server runs on the operator's own machine, so "point Verity at a
//! folder, drop files, query them" belongs SERVER-SIDE: the browser cannot
//! reach the filesystem, the local server can. The UI configures WHICH folders
//! to watch and WHO can see their files; the server watches them in-process and
//! turns dropped files into memory.
//!
//! Read-path purity (SPEC non-negotiable) is untouched: this is entirely
//! ingest/write-path. Every ingested file routes through the SAME choke point
//! as `POST /v1/ingest/documents` — [`crate::ingest_document`] — so extraction
//! (extract.rs, Tier-1), chunking, idempotency, the auto-resolve trigger, and
//! the freshness sample are never duplicated and the watcher never self-HTTPs.
//!
//! Fail-closed (SPEC §5e): a watch is created WITH an explicit visibility
//! policy (the principal tokens allowed to see its files). There is NO
//! permissive default — `visibility = []` is a deliberate "nobody can read
//! these", still a policy. acl_provenance is admin-assigned.
//!
//! Bounded ingestion, honest liveness:
//!   * files over [`MAX_FILE_BYTES`] are skipped with a logged reason;
//!   * hidden / temp / editor-swap files are skipped (`.*`, `*.tmp`, `*.swp`,
//!     `~$*`, `*~`);
//!   * a settle-debouncer coalesces editor write bursts and mid-write partials
//!     into a single event AFTER the file is quiescent, and a read that comes
//!     back empty is treated as a not-yet-flushed partial (retry-on-empty,
//!     never ingest an empty file as "the document");
//!   * each ingested file registers the watch as source `folder:<name>` in
//!     `connector_status` (items_synced++/last_event_at) so it shows up live in
//!     Sources & Freshness exactly like any other source, and records a
//!     `freshness_samples` row with an honest `event_at` (the file mtime).
//!
//! Deletes are a logged no-op: removing a file from a watched folder never
//! auto-forgets already-ingested memory (invalidate-don't-delete; the §8
//! hard-purge pipeline is the only physical-delete path).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use notify_debouncer_full::notify::{RecursiveMode, Watcher as _};
use notify_debouncer_full::{new_debouncer, DebounceEventResult};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use uuid::Uuid;

use verity_core::types::{AclProvenance, Confidentiality, PrincipalToken, TenantId};

use crate::backfill::{record_progress, BackfillProgressRequest};
use crate::{
    ingest_document, internal, storage_status, AppState, DeliveredContent, DocumentIngest,
    HandlerResult,
};

/// Per-file size cap. Mirrors the extract.rs 200 KB cap so a watched folder
/// can't stream an unbounded file into the ingest path; larger files are
/// skipped with a logged reason (fail-visible, never silently swallowed).
pub(crate) const MAX_FILE_BYTES: u64 = 200 * 1024;

/// Settle window: how long a file must be quiescent before we ingest it. Long
/// enough that an editor's multi-write save (and most mid-write partials)
/// coalesce into one event; short enough to feel live in the demo.
const DEBOUNCE: Duration = Duration::from_millis(800);

/// Pre-flight count entry cap: the bounded folder-preview walk visits at most
/// this many entries (files + dirs) before giving up and reporting `capped`.
/// The whole point is that the COUNT itself must never hang on a huge tree —
/// `capped = true` means "at least this many; the real tree is bigger", never
/// an exact total. It also bounds the DFS stack (and so any symlink cycle).
const MAX_PREVIEW_ENTRIES: u64 = 5_000;

/// Pre-flight count wall-clock budget: the preview walk aborts (and reports
/// `capped`) after this long even if the entry cap hasn't tripped, so counting
/// a slow/networked filesystem never itself hangs the request.
const PREVIEW_BUDGET: Duration = Duration::from_millis(1_500);

/// Big-folder guard thresholds — the SERVER-side copy of the UI's
/// `BIG_FOLDER_FILES` / `BIG_FOLDER_BYTES`. Above EITHER (or a capped count),
/// `add_folder_watch` refuses to start the scan unless the request carries an
/// explicit `acknowledge_large` ack. The client confirm is UX; this is the
/// authoritative gate (a raw `curl` can't bypass it), mirroring the fail-closed
/// posture everywhere else in the write path.
const BIG_FOLDER_FILES: u64 = 200;
const BIG_FOLDER_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

// ---------------------------------------------------------------------------
// Live watcher registry: OS-level handles kept alive for the process lifetime.
// ---------------------------------------------------------------------------

/// The concrete debouncer type. Held only to keep the OS watch alive (dropping
/// it stops the watch); we never call back into it.
type LiveDebouncer = notify_debouncer_full::Debouncer<
    notify_debouncer_full::notify::RecommendedWatcher,
    notify_debouncer_full::FileIdMap,
>;

/// Holds the live OS watch handles keyed by watch id. Arming inserts; stopping
/// removes (which drops the debouncer and releases the OS watch). Re-populated
/// from the `folder_watches` table on boot.
#[derive(Default)]
pub(crate) struct WatcherRegistry {
    live: Mutex<HashMap<Uuid, LiveDebouncer>>,
}

impl WatcherRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    async fn insert(&self, id: Uuid, deb: LiveDebouncer) {
        self.live.lock().await.insert(id, deb);
    }

    async fn remove(&self, id: &Uuid) -> bool {
        self.live.lock().await.remove(id).is_some()
    }

    /// Snapshot of the watch ids this process currently holds a live OS watch
    /// for. Lets sibling admin reads (connectors_admin) report the folder
    /// plane authoritatively without reaching into the private map.
    pub(crate) async fn armed_ids(&self) -> std::collections::HashSet<Uuid> {
        self.live.lock().await.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Initial-scan plane: supervised in-process background scans, keyed on
// (tenant, folder), each with a cooperative cancel flag + a JoinHandle.
// ---------------------------------------------------------------------------

/// A live initial-scan of a folder's EXISTING files. The scan runs in a
/// detached tokio task; this handle lets Stop cancel it cooperatively (the
/// task checks `cancel` between files and writes its own terminal row on the
/// way out) and lets a re-register supersede a predecessor cooperatively.
struct ScanHandle {
    run_id: Uuid,
    /// Cooperative cancel: the scan loop reads this between files and, if set,
    /// stops cleanly (already-ingested files stay) after writing a terminal
    /// `paused` row. The ONLY stop mechanism — we never abort(), so backfill_run
    /// never gets stuck at `running`.
    cancel: Arc<AtomicBool>,
    /// The scan's JoinHandle. Held so the task's lifecycle is tied to this entry
    /// and observable in tests (`is_finished`). Never abort()ed: dropping it just
    /// detaches, leaving the task to reach its cooperative terminal row.
    task: JoinHandle<()>,
}

/// Server-held initial-scan plane: one background scan per (tenant, folder id).
/// Mirrors `ConnectorPlane`'s admission discipline (a dedicated `admission`
/// mutex serializes check→spawn→insert) so two concurrent registers for the
/// same folder can't both spawn a scan and double-count into the same run.
/// Bundled as ONE `Arc` field on `AppState`.
#[derive(Default)]
pub(crate) struct FolderScanPlane {
    scans: Mutex<HashMap<(TenantId, Uuid), ScanHandle>>,
    admission: Mutex<()>,
}

impl FolderScanPlane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Cancel an in-flight initial scan for (tenant, folder). Sets the
    /// cooperative flag so the task writes its own terminal row and exits after
    /// the current file, then drops the handle. Returns the cancelled run_id, or
    /// `None` if no scan was live (honest no-op). The `task` is left to finish on
    /// its own so its terminal `paused` row lands.
    async fn cancel(&self, tenant: TenantId, folder_id: Uuid) -> Option<Uuid> {
        let mut map = self.scans.lock().await;
        let handle = map.remove(&(tenant, folder_id))?;
        // Cooperative: the task observes `cancel` between files and exits cleanly,
        // writing its own terminal `paused` row. We deliberately do NOT abort()
        // here — that would drop the task before it can write the terminal row and
        // leave backfill_run stuck at `running`. The handle is already removed, so
        // status is honest immediately; the task finishes on its own within one
        // per-file iteration. Re-register (spawn_initial_scan) supersedes the same
        // cooperative way.
        handle.cancel.store(true, Ordering::SeqCst);
        Some(handle.run_id)
    }

    /// True iff a scan is currently tracked for (tenant, folder). Used by tests.
    #[cfg(test)]
    async fn is_scanning(&self, tenant: TenantId, folder_id: Uuid) -> bool {
        self.scans.lock().await.contains_key(&(tenant, folder_id))
    }
}

// ---------------------------------------------------------------------------
// Skip rules (hidden / temp / editor-swap).
// ---------------------------------------------------------------------------

/// True for files the watcher must never ingest: hidden dotfiles and the
/// transient files editors write mid-save. Matched on the file name only.
fn is_skippable(name: &str) -> bool {
    name.starts_with('.')                       // .DS_Store, .git, dotfiles
        || name.ends_with(".tmp")
        || name.ends_with(".swp")
        || name.ends_with(".swx")
        || name.ends_with('~')                  // emacs/gedit backup
        || name.starts_with("~$") // office lock files
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|n| n.to_str())
}

// ---------------------------------------------------------------------------
// One folder watch config (a row of `folder_watches`).
// ---------------------------------------------------------------------------

struct WatchRow {
    id: Uuid,
    tenant_id: TenantId,
    name: String,
    path: String,
    visibility: Vec<PrincipalToken>,
    confidentiality: Confidentiality,
    last_seen: Option<DateTime<Utc>>,
}

fn source_name(watch_name: &str) -> String {
    format!("folder:{watch_name}")
}

/// Derive a stable, human-facing watch `name` from an absolute folder path: the
/// final path component (the folder's own name). The UI does not ask for a
/// separate label — the folder's name IS the label, and `folder:<name>` is the
/// source key it shows up under in Sources & Freshness. Falls back to a slug of
/// the whole path for pathological inputs (root, trailing slashes) so the source
/// key is never empty.
fn derive_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let slug: String = path
                .to_string_lossy()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect();
            let trimmed = slug.trim_matches('-');
            if trimmed.is_empty() {
                "root".to_string()
            } else {
                trimmed.to_string()
            }
        })
}

// ---------------------------------------------------------------------------
// Ingesting one file.
// ---------------------------------------------------------------------------

/// Read + ingest one path under a watch's configured visibility. Returns
/// `Ok(true)` if a document was ingested, `Ok(false)` if the path was skipped
/// (hidden/temp/too-big/empty/vanished), `Err` only on an ingest failure worth
/// surfacing. Never self-HTTPs — routes through [`ingest_document`].
async fn ingest_file(
    state: &AppState,
    watch: &WatchRow,
    path: &Path,
) -> Result<bool, (StatusCode, String)> {
    let Some(name) = file_name(path) else {
        return Ok(false);
    };
    if is_skippable(name) {
        return Ok(false);
    }
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() => m,
        // Directory, symlink loop, or vanished between event and read.
        _ => return Ok(false),
    };
    if meta.len() > MAX_FILE_BYTES {
        tracing::warn!(
            folder = %watch.name, file = %name, bytes = meta.len(), cap = MAX_FILE_BYTES,
            "folder watch: file over size cap, skipped"
        );
        return Ok(false);
    }
    // Honest event_at: the file's own modification time (falling back to now if
    // the platform can't report it) — the freshness sample measures the file's
    // clock → queryable, same convention as connector event times.
    let event_at: DateTime<Utc> = meta
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(Utc::now);

    let raw = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(folder = %watch.name, file = %name, "folder watch: read failed: {e}");
            return Ok(false);
        }
    };
    // Retry-on-empty: the debounce fires after quiescence, but a create event
    // can still race a not-yet-flushed write. An empty read is treated as a
    // partial — we decline rather than ingest an empty "document"; the next
    // write event re-fires the ingest.
    if raw.is_empty() {
        tracing::debug!(folder = %watch.name, file = %name, "folder watch: empty read, treating as partial write (will re-fire)");
        return Ok(false);
    }

    // Text-like files pass through as UTF-8; everything else is handed to
    // Tier-1 extraction (extract.rs decides via magic bytes, extension is a
    // hint). We never reimplement extraction here.
    let delivered = match String::from_utf8(raw.clone()) {
        // Valid UTF-8 AND not one of the binary formats extract.rs handles:
        // treat as text. (A UTF-8-decodable xlsx is impossible; pdf/pptx/xls
        // are binary and fail this decode, landing in the Bytes arm.)
        Ok(text) if !looks_binary(&raw) => DeliveredContent::Text(text),
        _ => DeliveredContent::Bytes {
            hash_over: blob_hash_input(path, event_at, raw.len()),
            raw,
        },
    };

    let outcome = ingest_document(
        state,
        DocumentIngest {
            tenant_id: watch.tenant_id,
            source: source_name(&watch.name),
            // Stable per-file document id: re-dropping the same filename
            // supersedes rather than forks (chunk idempotency keys on the
            // content hash; the doc id keys the L0 lineage).
            document_id: name.to_string(),
            filename: Some(name.to_string()),
            entities: Vec::new(),
            visibility: watch.visibility.clone(),
            confidentiality: watch.confidentiality,
            acl_provenance: AclProvenance::AdminAssigned,
            valid_from: Some(event_at),
            delivered,
        },
    )
    .await?;

    // Register/refresh the folder as a live source AND drop a freshness sample.
    // Best-effort telemetry: a failed heartbeat never fails the ingest.
    let src = source_name(&watch.name);
    if let Err(e) = bump_connector_status(state.pool(), watch.tenant_id, &src, event_at).await {
        tracing::warn!(folder = %watch.name, "folder watch: connector_status update failed: {e}");
    }
    crate::slo::record_sample(state.pool(), watch.tenant_id, &src, event_at).await;

    tracing::info!(
        folder = %watch.name, file = %name, chunks = outcome.chunks_indexed,
        "folder watch: ingested"
    );
    Ok(true)
}

/// A hash input for binary blobs that is stable per (path, mtime, len): the raw
/// bytes are the delivered payload for extraction, but the idempotency hash in
/// `ingest_document` is taken over `hash_over`. Feeding it path + mtime + len
/// means an unchanged binary re-drop is idempotent, and a changed file (new
/// mtime or len) re-ingests. Deterministic, tiny.
fn blob_hash_input(path: &Path, event_at: DateTime<Utc>, len: usize) -> String {
    format!("{}:{}:{}", path.display(), event_at.timestamp_millis(), len)
}

/// Heuristic: does this look like a binary format extract.rs should handle
/// (contains a NUL byte, or starts with a known office/pdf magic)? UTF-8-decodable
/// text with no NULs is treated as text; anything else goes to extraction.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
        || bytes.starts_with(b"%PDF-")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0])
}

/// Upsert the `folder:<name>` row in connector_status: +1 item, advance
/// last_event_at (never rewinds). Mirrors connectors::record_heartbeat's SQL.
async fn bump_connector_status(
    pool: &PgPool,
    tenant_id: TenantId,
    source: &str,
    event_at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO connector_status (tenant_id, source, items_synced, last_event_at, updated_at)
         VALUES ($1, $2, 1, $3, now())
         ON CONFLICT (tenant_id, source) DO UPDATE SET
             items_synced  = connector_status.items_synced + 1,
             last_event_at = GREATEST(EXCLUDED.last_event_at, connector_status.last_event_at),
             updated_at    = now()",
    )
    .bind(tenant_id)
    .bind(source)
    .bind(event_at)
    .execute(pool)
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Arming a live watch: OS watcher + async ingest consumer.
// ---------------------------------------------------------------------------

/// Arm a live debounced OS watch for `watch`, spawning a task that ingests
/// create/modify events. The returned debouncer is stored in the registry to
/// keep the watch alive; dropping it stops the watch.
async fn arm_watch(state: Arc<AppState>, watch: WatchRow) -> Result<(), String> {
    let path = PathBuf::from(&watch.path);
    if !path.is_dir() {
        return Err(format!("{} is not a directory", watch.path));
    }

    // The debouncer's handler is sync; it forwards settled event paths to an
    // async ingest task over an unbounded channel.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
    let mut debouncer = new_debouncer(DEBOUNCE, None, move |res: DebounceEventResult| match res {
        Ok(events) => {
            for ev in events {
                // Create/modify only; deletes are a no-op (invalidate-don't-
                // delete — a removed file never auto-forgets memory).
                use notify_debouncer_full::notify::EventKind;
                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for p in &ev.paths {
                        let _ = tx.send(p.clone());
                    }
                }
            }
        }
        Err(errors) => {
            for e in errors {
                tracing::warn!("folder watch: debouncer error: {e}");
            }
        }
    })
    .map_err(|e| format!("failed to create watcher: {e}"))?;

    debouncer
        .watcher()
        .watch(&path, RecursiveMode::Recursive)
        .map_err(|e| format!("failed to watch {}: {e}", watch.path))?;

    // Async ingest consumer. De-dupes bursts of the same path within a tick by
    // ingesting sequentially; ingest_document is idempotent on content hash so
    // a duplicate is cheap (Unchanged chunks).
    let ingest_watch = WatchRow {
        id: watch.id,
        tenant_id: watch.tenant_id,
        name: watch.name.clone(),
        path: watch.path.clone(),
        visibility: watch.visibility.clone(),
        confidentiality: watch.confidentiality,
        last_seen: watch.last_seen,
    };
    let ingest_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            match ingest_file(&ingest_state, &ingest_watch, &p).await {
                Ok(true) => {
                    // Advance last_seen so a later boot re-scan doesn't re-ingest
                    // this file. Best-effort.
                    let _ = touch_last_seen(ingest_state.pool(), ingest_watch.id).await;
                }
                Ok(false) => {}
                Err((status, msg)) => {
                    tracing::warn!(folder = %ingest_watch.name, %status, "folder watch: ingest failed: {msg}");
                }
            }
        }
        tracing::debug!(folder = %ingest_watch.name, "folder watch: ingest consumer stopped");
    });

    state.folder_watchers.insert(watch.id, debouncer).await;
    tracing::info!(folder = %watch.name, path = %watch.path, "folder watch armed");
    Ok(())
}

/// Set `last_seen = now()` for a watch (advances the boot re-scan high-water
/// mark). Best-effort.
async fn touch_last_seen(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE folder_watches SET last_seen = now(), updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Background initial scan: walk existing files, ingest each through the same
// choke point, report progress via backfill_run, cancellable + supervised.
// ---------------------------------------------------------------------------

/// Best-effort backfill_run reporter for one folder scan: holds the invariant
/// identity (pool, run_id, tenant, source) so each post is a short call. Writes
/// DIRECTLY (no self-HTTP) via the same SQL the POST /v1/admin/backfill handler
/// uses. `state` is self-validated by construction — the methods only ever pass
/// "running"/"completed"/"failed"/"paused" (all in the backfill VALID_STATES).
/// A failed post never fails the scan — it is telemetry, mirroring the connector
/// heartbeat's best-effort posture.
struct ScanReporter<'a> {
    pool: &'a PgPool,
    run_id: Uuid,
    tenant_id: TenantId,
    source: String,
}

impl ScanReporter<'_> {
    async fn post(
        &self,
        state: Option<&str>,
        total: Option<i64>,
        processed_delta: i64,
        skipped_delta: i64,
        error: Option<String>,
    ) {
        let req = BackfillProgressRequest {
            run_id: self.run_id,
            tenant_id: self.tenant_id,
            source: self.source.clone(),
            state: state.map(|s| s.to_string()),
            total,
            processed_delta,
            skipped_delta,
            cursor: None,
            error,
        };
        if let Err(e) = record_progress(self.pool, &req).await {
            tracing::warn!(run_id = %self.run_id, "folder scan: backfill_run progress write failed: {e}");
        }
    }

    /// Scan start: set the discovered total and mark running.
    async fn start(&self, total: i64) {
        self.post(Some("running"), Some(total), 0, 0, None).await;
    }

    /// One file ingested.
    async fn advance(&self) {
        self.post(None, None, 1, 0, None).await;
    }

    /// One file deliberately skipped (too large / hidden / temp / empty).
    async fn skip(&self) {
        self.post(None, None, 0, 1, None).await;
    }

    /// Clean finish.
    async fn complete(&self) {
        self.post(Some("completed"), None, 0, 0, None).await;
    }

    /// Operator-cancelled: honest terminal `paused` with the retained-files note.
    async fn cancelled(&self, note: String) {
        self.post(Some("paused"), None, 0, 0, Some(note)).await;
    }

    /// Abnormal terminal `failed`: the scan could not enumerate the folder, or
    /// the task panicked mid-scan. Writes an honest terminal row (with the error)
    /// so the strip flips off `running` instead of polling a wedged run forever.
    async fn failed(&self, note: String) {
        self.post(Some("failed"), None, 0, 0, Some(note)).await;
    }
}

/// Panic-safety guard for one in-flight initial scan. Created ARMED and threaded
/// into `run_initial_scan`, which calls [`ScanCleanup::finish`] on EVERY clean
/// terminal path (completed / paused / enumeration-failure) — that drops the
/// plane handle and disarms the guard. If the guard is dropped still armed, the
/// only remaining cause is a panic inside the scan (e.g. malformed-file
/// extraction unwinding through `ingest_document`): its Drop spawns a detached
/// task that writes a terminal `failed` backfill_run row AND drops the handle, so
/// a panicked scan never wedges the run at `running` nor leaves the folder
/// reading as live-scanning forever. Mirrors the fail-closed, self-reconciling
/// posture of the Phase-3 connector reap, kept in-process.
struct ScanCleanup {
    state: Arc<AppState>,
    tenant: TenantId,
    folder_id: Uuid,
    run_id: Uuid,
    source: String,
    armed: bool,
}

impl ScanCleanup {
    fn new(
        state: Arc<AppState>,
        tenant: TenantId,
        folder_id: Uuid,
        run_id: Uuid,
        source: String,
    ) -> Self {
        Self {
            state,
            tenant,
            folder_id,
            run_id,
            source,
            armed: true,
        }
    }

    /// Clean exit: the scan already wrote its own terminal row. Drop the plane
    /// handle (if still ours) and disarm so Drop does nothing.
    async fn finish(&mut self) {
        self.armed = false;
        drop_scan_handle(&self.state, self.tenant, self.folder_id, self.run_id).await;
    }
}

impl Drop for ScanCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Armed at drop ⇒ the scan panicked before its clean terminal write. Drop
        // can't await, so spawn a detached reconciler: write a terminal `failed`
        // row and drop the plane handle. Best-effort telemetry, same posture as
        // every other backfill progress write.
        let state = Arc::clone(&self.state);
        let (tenant, folder_id, run_id, source) = (
            self.tenant,
            self.folder_id,
            self.run_id,
            self.source.clone(),
        );
        tracing::error!(%run_id, %source, "folder scan: task panicked; reconciling terminal failed");
        tokio::spawn(async move {
            let reporter = ScanReporter {
                pool: state.pool(),
                run_id,
                tenant_id: tenant,
                source,
            };
            reporter
                .failed(
                    "initial scan aborted: an internal error occurred while reading a file".into(),
                )
                .await;
            drop_scan_handle(&state, tenant, folder_id, run_id).await;
        });
    }
}

/// The supervised background initial scan: walk the folder's EXISTING files and
/// ingest each through the SAME `ingest_file` choke point (extraction / dedup /
/// size-cap / skip logic unchanged), reporting processed/skipped/total to
/// `backfill_run` under the server-minted `run_id` (source `folder:<name>`).
///
/// Cooperative cancellation: `cancel` is checked before each file; when set the
/// scan stops cleanly (already-ingested files stay) and reconciles a terminal
/// `paused` row. On clean finish it reconciles `completed` and advances
/// `last_seen` (so a crash mid-scan re-scans on next boot — last_seen only moves
/// AFTER the walk). Double-ingest with the OS-watcher (armed before this runs) is
/// CHUNK-idempotent: `ingest_document` keys chunks on the content hash and the
/// doc id is the stable filename, so a file caught by both paths never
/// double-populates the search index. It is NOT idempotent at the L0/telemetry
/// layer — a doubly-caught file appends a second episode row and increments
/// items_synced/freshness once more — so overlap is cheap and non-corrupting,
/// but not literally a no-op. The overlap window is a single settle interval.
async fn run_initial_scan(
    state: Arc<AppState>,
    watch: WatchRow,
    run_id: Uuid,
    cancel: Arc<AtomicBool>,
    mut guard: ScanCleanup,
) {
    let pool = state.pool();
    let path = PathBuf::from(&watch.path);
    let reporter = ScanReporter {
        pool,
        run_id,
        tenant_id: watch.tenant_id,
        source: source_name(&watch.name),
    };

    // Count up front so the strip has a denominator (folder scans CAN count).
    // The enumeration is the UNBOUNDED, synchronous std::fs DFS — offload it to a
    // blocking thread (exactly as preview_folder does for its bounded count) so a
    // huge/deep/networked tree can never pin a tokio worker before the first
    // await. A JoinError (the blocking thread panicked) fails the scan cleanly.
    let files = match tokio::task::spawn_blocking(move || collect_files(&path)).await {
        Ok(files) => files,
        Err(e) => {
            tracing::warn!(folder = %watch.name, %run_id, "folder scan: enumeration failed: {e}");
            reporter
                .failed(format!("initial scan could not enumerate the folder: {e}"))
                .await;
            guard.finish().await;
            return;
        }
    };
    reporter.start(files.len() as i64).await;

    let mut processed = 0i64;
    let mut skipped = 0i64;
    let mut cancelled = false;
    for file in files {
        // Cooperative cancel: check BEFORE each file so a Stop takes effect
        // between files (already-ingested files stay).
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        match ingest_file(&state, &watch, &file).await {
            Ok(true) => {
                processed += 1;
                reporter.advance().await;
            }
            Ok(false) => {
                // Deliberately declined (too large / hidden / temp / empty) —
                // an honest skip, neither processed nor an error.
                skipped += 1;
                reporter.skip().await;
            }
            Err((status, msg)) => {
                tracing::warn!(folder = %watch.name, %status, "folder watch: initial ingest failed: {msg}");
            }
        }
    }

    // Terminal reconcile keyed on run_id — the scan owns its own terminal write
    // (no detached reap: this in-process task observes its own completion).
    if cancelled {
        reporter
            .cancelled(format!(
                "initial scan stopped by operator after {processed} ingested, {skipped} skipped — \
                 already-ingested files retained; new files still watched"
            ))
            .await;
        tracing::info!(folder = %watch.name, %run_id, processed, skipped, "folder scan: cancelled");
    } else {
        reporter.complete().await;
        // last_seen only advances after a clean, complete walk so a crash
        // mid-scan re-scans the folder on next boot.
        let _ = touch_last_seen(pool, watch.id).await;
        tracing::info!(folder = %watch.name, %run_id, processed, skipped, "folder scan: completed");
    }

    // Clean terminal path: the scan wrote its own terminal row above, so disarm
    // the guard (it drops the handle now, and will NOT spawn a `failed` write).
    // The only way the guard stays armed is a panic before this point — its Drop
    // then writes `failed` + drops the handle, so backfill_run never wedges at
    // `running` and the folder never reads as live-scanning forever.
    guard.finish().await;
}

/// Remove this scan's handle from the plane IF it is still the one registered for
/// this run (a Stop or a re-register may have already removed/replaced it). Runs
/// on every task exit — normal completion, cancellation, enumeration failure, or
/// a panic — so a wedged task never leaves the folder reading as live-scanning
/// forever.
async fn drop_scan_handle(state: &AppState, tenant: TenantId, folder_id: Uuid, run_id: Uuid) {
    let mut map = state.folder_scans.scans.lock().await;
    if map
        .get(&(tenant, folder_id))
        .is_some_and(|h| h.run_id == run_id)
    {
        map.remove(&(tenant, folder_id));
    }
}

/// Admit + spawn a supervised initial scan for `watch`, returning the minted
/// run_id. Serialized under the plane's `admission` lock so two concurrent
/// registers for the same folder can't both spawn (the second cooperatively
/// supersedes the predecessor and replaces its handle). The `watch` is cloned
/// into the task.
async fn spawn_initial_scan(state: &Arc<AppState>, watch: &WatchRow) -> Uuid {
    let _admit = state.folder_scans.admission.lock().await;
    let run_id = Uuid::now_v7();
    let cancel = Arc::new(AtomicBool::new(false));

    let task_state = Arc::clone(state);
    let task_watch = clone_watch(watch);
    let task_cancel = Arc::clone(&cancel);
    let task = tokio::spawn(async move {
        // Panic-safe supervision (finding: a panic mid-scan — e.g. a malformed
        // file blowing up extraction — must NOT skip the terminal backfill_run
        // write AND the handle cleanup, or the run wedges at `running` and the
        // folder reads as live-scanning forever). A ScanCleanup guard is created
        // ARMED; run_initial_scan disarms it on every clean terminal path
        // (completed / paused / enumeration-failure). If the guard is still armed
        // when dropped — the only remaining case is a panic — its Drop spawns the
        // terminal `failed` write + handle removal.
        let guard = ScanCleanup::new(
            Arc::clone(&task_state),
            task_watch.tenant_id,
            task_watch.id,
            run_id,
            source_name(&task_watch.name),
        );
        run_initial_scan(task_state, task_watch, run_id, task_cancel, guard).await;
    });

    let mut map = state.folder_scans.scans.lock().await;
    // A prior in-flight scan for this folder (a rapid re-register): supersede it
    // COOPERATIVELY — set its cancel flag and let it drain to its OWN terminal
    // `paused` row between files, exactly like the FolderScanPlane::cancel path.
    // We deliberately do NOT abort() it: an abort drops the predecessor's task at
    // its next await, and while its ScanCleanup guard would still reconcile a
    // terminal `failed` row on drop, a hard abort can also cut a half-written
    // ingest and races the flag it can't observe. The map entry is ALREADY
    // replaced by the new run above, so the predecessor's own cleanup keys on its
    // (now-superseded) run_id and can't disturb the new handle — status is honest
    // immediately, and the old run reaches a real terminal state on its own.
    if let Some(prev) = map.insert(
        (watch.tenant_id, watch.id),
        ScanHandle {
            run_id,
            cancel,
            task,
        },
    ) {
        prev.cancel.store(true, Ordering::SeqCst);
        // `prev.task` is dropped here (JoinHandle drop just detaches; it does NOT
        // abort), so the predecessor runs on to its cooperative `paused` terminal.
        drop(prev.task);
    }
    run_id
}

/// Clone a WatchRow (arm_watch consumes one, the scan task needs its own).
fn clone_watch(watch: &WatchRow) -> WatchRow {
    WatchRow {
        id: watch.id,
        tenant_id: watch.tenant_id,
        name: watch.name.clone(),
        path: watch.path.clone(),
        visibility: watch.visibility.clone(),
        confidentiality: watch.confidentiality,
        last_seen: watch.last_seen,
    }
}

// ---------------------------------------------------------------------------
// Boot re-establishment: re-scan for missed files, then re-arm.
// ---------------------------------------------------------------------------

/// On boot, for every active watch: re-scan the folder for files modified since
/// `last_seen` (dropped while the server was down) and ingest them, then re-arm
/// the live OS watch. Best-effort per watch — a vanished folder is logged and
/// skipped, never a boot failure.
pub(crate) async fn reestablish_on_boot(state: Arc<AppState>) {
    let rows = match load_active_watches(state.pool()).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("folder watch: could not load persisted watches on boot: {e}");
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    tracing::info!(
        count = rows.len(),
        "folder watch: re-establishing persisted watches"
    );
    for watch in rows {
        let path = PathBuf::from(&watch.path);
        if !path.is_dir() {
            tracing::warn!(folder = %watch.name, path = %watch.path, "folder watch: folder missing on boot, skipping re-arm");
            continue;
        }
        // Catch-up scan for files changed while we were down.
        let mut caught_up = 0usize;
        for file in collect_files(&path) {
            if !changed_since(&file, watch.last_seen) {
                continue;
            }
            match ingest_file(&state, &watch, &file).await {
                Ok(true) => caught_up += 1,
                Ok(false) => {}
                Err((status, msg)) => {
                    tracing::warn!(folder = %watch.name, %status, "folder watch: boot catch-up ingest failed: {msg}");
                }
            }
        }
        if caught_up > 0 {
            let _ = touch_last_seen(state.pool(), watch.id).await;
            tracing::info!(folder = %watch.name, files = caught_up, "folder watch: boot catch-up ingested");
        }
        if let Err(e) = arm_watch(Arc::clone(&state), watch).await {
            tracing::warn!("folder watch: re-arm failed: {e}");
        }
    }
}

/// True if the file's mtime is at/after `since` (or `since` is None — never
/// scanned before, so every file is "new").
fn changed_since(path: &Path, since: Option<DateTime<Utc>>) -> bool {
    let Some(since) = since else { return true };
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .map(|m| m >= since)
        .unwrap_or(true)
}

/// Depth-first, name-sorted walk collecting candidate files (skip rules
/// applied). Bounded implicitly by the per-file size cap at ingest time.
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let Some(name) = file_name(&path) else {
                continue;
            };
            if is_skippable(name) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The bounded pre-flight count of a folder: how many ingestable files and how
/// many bytes it holds, and whether the count hit a cap (`capped = true` means
/// "at least this many; the tree is bigger — we stopped counting"). Never an
/// exact total on a large tree; that is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FolderCount {
    files: u64,
    bytes: u64,
    capped: bool,
}

/// Bounded, fail-closed pre-flight count of a folder — the guard the UI uses to
/// decide whether to require an explicit "this is a big folder" confirm before
/// starting the scan. A clone of the `collect_files` DFS, but: it only
/// accumulates integers (never materializes the tree), it counts a file's bytes
/// from the DirEntry metadata (skip-rules applied, same as ingest), and it trips
/// `capped` + stops the moment either the entry cap ([`MAX_PREVIEW_ENTRIES`]) or
/// the wall-clock budget ([`PREVIEW_BUDGET`]) is hit — so counting a 16 GB tree
/// can never itself hang.
///
/// Fail-closed on the ROOT: unlike `collect_files` (which swallows every
/// read_dir error), an unreadable ROOT is an `Err` the handler turns into an
/// operator-facing refusal — a folder Verity can't enumerate must never register
/// as a silent 0-file count. Interior unreadable subdirs are still skipped (they
/// contribute nothing).
fn count_folder_bounded(root: &Path) -> std::io::Result<FolderCount> {
    let started = Instant::now();
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut visited = 0u64;
    let mut capped = false;

    // Fail closed on the root: it stat()s as a dir but must also be enumerable.
    let root_entries = std::fs::read_dir(root)?;
    let mut stack: Vec<Vec<PathBuf>> = vec![sorted_paths(root_entries)];

    'walk: while let Some(level) = stack.last_mut() {
        let Some(path) = level.pop() else {
            stack.pop();
            continue;
        };
        if visited >= MAX_PREVIEW_ENTRIES || started.elapsed() >= PREVIEW_BUDGET {
            capped = true;
            break 'walk;
        }
        visited += 1;
        let Some(name) = file_name(&path) else {
            continue;
        };
        if is_skippable(name) {
            continue;
        }
        // DirEntry-free re-stat: use symlink-following metadata once per entry
        // (same as ingest, which reads through symlinks). A missing/again-racing
        // entry contributes nothing.
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            // Interior unreadable subdirs are swallowed (they add nothing); only
            // the ROOT read failure fails closed.
            if let Ok(entries) = std::fs::read_dir(&path) {
                stack.push(sorted_paths(entries));
            }
        } else if meta.is_file() {
            files += 1;
            bytes += meta.len();
        }
    }

    Ok(FolderCount {
        files,
        bytes,
        capped,
    })
}

/// Collect + name-sort a read_dir into a reversed stack level so `pop()` yields
/// entries in ascending name order (deterministic, matches collect_files).
fn sorted_paths(entries: std::fs::ReadDir) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    paths.reverse();
    paths
}

async fn load_active_watches(pool: &PgPool) -> sqlx::Result<Vec<WatchRow>> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, name, path, visibility, confidentiality, last_seen
         FROM folder_watches WHERE active ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(row_to_watch).collect())
}

fn row_to_watch(row: &sqlx::postgres::PgRow) -> WatchRow {
    WatchRow {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        name: row.get("name"),
        path: row.get("path"),
        visibility: row.get::<Vec<i32>, _>("visibility"),
        confidentiality: Confidentiality::from_i16(row.get::<i16, _>("confidentiality")),
        last_seen: row.get("last_seen"),
    }
}

// ---------------------------------------------------------------------------
// HTTP: add / list / stop.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AddFolderWatchRequest {
    tenant_id: TenantId,
    /// Absolute server-local folder path to watch. The watch `name` (and the
    /// `folder:<name>` source key) is derived from this path's final component —
    /// the UI does not ask for a separate label.
    path: String,
    /// WHO can see files from this folder: materialized principal tokens (the
    /// ints the who-can-see-it picker already resolved). REQUIRED as a field
    /// (fail closed — a request that omits it is a 400 deserialize error, never
    /// a permissive default); `[]` is a deliberate "nobody can read these",
    /// still a policy (SPEC §5e), not refused.
    visibility: Vec<PrincipalToken>,
    #[serde(default = "default_confidentiality")]
    confidentiality: Confidentiality,
    /// Explicit "yes, read this big folder" ack. The server runs its OWN bounded
    /// pre-flight count and REFUSES a big folder (over [`BIG_FOLDER_FILES`] /
    /// [`BIG_FOLDER_BYTES`], or a capped count) unless this is `true` — so a raw
    /// `curl` at `~/Downloads` can't silently ingest 2,111 files. The UI sets it
    /// only after the operator confirms the big-folder dialog. Below threshold it
    /// is irrelevant (the scan starts regardless).
    #[serde(default)]
    acknowledge_large: bool,
}

fn default_confidentiality() -> Confidentiality {
    Confidentiality::Internal
}

/// POST /v1/admin/folders (admin): register a folder to watch under an explicit
/// who-can-see-it policy, ingest any files already in it, and arm the live
/// watch. Fail-closed: the `visibility` field is mandatory in the request shape
/// (there is no permissive default). The path must be an absolute server-local
/// directory; Verity creates it if it does not yet exist (the FTUE default
/// `./verity-inbox` case) rather than refusing a not-yet-populated inbox.
pub(crate) async fn add_folder_watch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddFolderWatchRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;

    let path = PathBuf::from(&req.path);
    if !path.is_absolute() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("path must be absolute (server-local): {}", req.path),
        ));
    }
    // The folder appearing in the list is a feature: an operator points Verity
    // at an inbox that does not exist yet, then drops files in. Create it (the
    // `created` flag tells the UI so its copy can say so), rather than 422 a
    // path that is simply not populated yet. A path that exists but is a FILE is
    // still a hard refusal — that is an operator mistake, not an empty inbox.
    let mut created = false;
    if !path.exists() {
        std::fs::create_dir_all(&path).map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("could not create {} on this machine: {e}", req.path),
            )
        })?;
        created = true;
    }
    if !path.is_dir() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "{} is not a directory the server can see — folder watching is server-side",
                req.path
            ),
        ));
    }

    // Big-folder guard (SERVER-side, authoritative): before recording anything,
    // run the SAME bounded pre-flight count the preview endpoint uses (offloaded
    // to a blocking thread so the async runtime never stalls). Above threshold —
    // or a capped count ("at least this many; the tree is bigger") — refuse
    // unless the request explicitly acknowledged the size. This is the gate a raw
    // `curl` at ~/Downloads hits: the client dialog is UX, this is the wall.
    if !req.acknowledge_large {
        let count_path = path.clone();
        let count = tokio::task::spawn_blocking(move || count_folder_bounded(&count_path))
            .await
            .map_err(internal)?
            .map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("refusing: folder is not readable by the server: {e}"),
                )
            })?;
        if count.capped || count.files > BIG_FOLDER_FILES || count.bytes > BIG_FOLDER_BYTES {
            let approx = if count.capped { "at least " } else { "~" };
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "this folder has {approx}{} files ({approx}{} bytes) — Verity would read and \
                     store their contents as memory; re-send with acknowledge_large=true to confirm",
                    count.files, count.bytes
                ),
            ));
        }
    }

    // Fail-closed (SPEC §5e): the visibility tokens are the who-can-see-it
    // policy, materialized at setup. `[]` is a deliberate "nobody"; the field
    // itself is mandatory in the request shape. No permissive default.
    let visibility: Vec<PrincipalToken> = req.visibility.clone();
    let name = derive_name(&path);

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO folder_watches
             (id, tenant_id, name, path, visibility, confidentiality, active)
         VALUES ($1, $2, $3, $4, $5, $6, true)
         ON CONFLICT (tenant_id, name) DO UPDATE SET
             path = EXCLUDED.path, visibility = EXCLUDED.visibility,
             confidentiality = EXCLUDED.confidentiality, active = true,
             updated_at = now()",
    )
    .bind(id)
    .bind(req.tenant_id)
    .bind(&name)
    .bind(&req.path)
    .bind(&visibility)
    .bind(req.confidentiality as i16)
    .execute(state.pool())
    .await
    .map_err(internal)?;

    // The row may have existed (ON CONFLICT) — read back the effective id so
    // the live registry and future stops target the right watch.
    let effective_id: Uuid =
        sqlx::query_scalar("SELECT id FROM folder_watches WHERE tenant_id = $1 AND name = $2")
            .bind(req.tenant_id)
            .bind(&name)
            .fetch_one(state.pool())
            .await
            .map_err(internal)?;

    let watch = WatchRow {
        id: effective_id,
        tenant_id: req.tenant_id,
        name: name.clone(),
        path: req.path.clone(),
        visibility: visibility.clone(),
        confidentiality: req.confidentiality,
        last_seen: None,
    };

    // REGISTER-FAST: arm the live OS watch for NEW files (fast — it only creates
    // the debouncer + spawns the consumer, never scans existing files), then hand
    // the walk-and-ingest of EXISTING files to a supervised background task and
    // RETURN IMMEDIATELY. The handler must not block on the initial scan (the bug
    // this fixes: a 2,111-file folder hung the request for minutes).
    //
    // If a watch with this name was already armed, drop it before re-arming so we
    // don't hold two OS watches for the same folder.
    state.folder_watchers.remove(&effective_id).await;
    if let Err(e) = arm_watch(Arc::clone(&state), clone_watch(&watch)).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("folder recorded but the live watch could not be armed: {e}"),
        ));
    }

    // Kick off the background initial scan (existing files). It reports
    // processed/total/skipped to backfill_run under `run_id` and reconciles a
    // terminal state on finish; the UI polls GET /v1/admin/backfill on `run_id`.
    // Double-ingest with the just-armed OS watcher is CHUNK-idempotent (content
    // hash + stable doc id ⇒ the search index is never double-populated); it is
    // not idempotent at the L0/telemetry layer (a second episode row, one extra
    // items_synced/freshness sample). Cheap and non-corrupting, not literally a
    // no-op — the overlap window is one settle interval.
    let run_id = spawn_initial_scan(&state, &watch).await;

    Ok(Json(serde_json::json!({
        "folder_id": effective_id,
        "source": source_name(&name),
        "path": req.path,
        "visibility": visibility,
        "confidentiality": req.confidentiality,
        "created": created,
        // The scan of existing files runs in the background; the client tracks it
        // via `run_id` against GET /v1/admin/backfill. No synchronous ingest count
        // is returned any more — it would have meant blocking on the whole scan.
        "run_id": run_id,
        "scan": "started",
        "watching": true,
    })))
}

#[derive(Deserialize)]
pub(crate) struct ListParams {
    tenant_id: TenantId,
}

/// GET /v1/admin/folders?tenant_id= (admin): every folder watch for the tenant
/// with its live status. `status` is "running" when the process currently holds
/// an OS watch (armed) AND the row is active, else "stopped". `files_ingested`
/// and `last_event_at` are read from the SAME `connector_status` row the folder
/// registers under (`folder:<name>`), so this table and Your Sources agree
/// exactly. Shape mirrors the console's folder contract: `{folders:[...]}`.
pub(crate) async fn list_folder_watches(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    // LEFT JOIN the folder's connector_status row on the derived source key so
    // the file count / last-event time come from the one place ingest updates.
    let rows = sqlx::query(
        "SELECT f.id, f.name, f.path, f.visibility, f.confidentiality, f.active,
                f.last_seen, f.created_at, f.updated_at,
                cs.items_synced, cs.last_event_at
         FROM folder_watches f
         LEFT JOIN connector_status cs
           ON cs.tenant_id = f.tenant_id AND cs.source = 'folder:' || f.name
         WHERE f.tenant_id = $1 ORDER BY f.name",
    )
    .bind(p.tenant_id)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;

    let live = state.folder_watchers.live.lock().await;
    let folders: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            let active: bool = row.get("active");
            let armed = live.contains_key(&id);
            // Plain-words status the console renders directly. "running" only
            // when the OS watch is actually held (armed) and the row active;
            // anything else is honestly "stopped" (never a fake-live green).
            let status = if active && armed {
                "running"
            } else {
                "stopped"
            };
            serde_json::json!({
                "folder_id": id,
                "name": row.get::<String, _>("name"),
                "source": source_name(&row.get::<String, _>("name")),
                "path": row.get::<String, _>("path"),
                "visibility": row.get::<Vec<i32>, _>("visibility"),
                // String form (PascalCase) — the console lowercases it for the
                // "ceiling: internal" note; matches every other confidentiality
                // surface on the wire.
                "confidentiality": Confidentiality::from_i16(row.get::<i16, _>("confidentiality")),
                "status": status,
                "active": active,
                // Live = the process currently holds an OS watch for this id.
                "armed": armed,
                "files_ingested": row.get::<Option<i64>, _>("items_synced"),
                "last_event_at": row.get::<Option<DateTime<Utc>>, _>("last_event_at"),
                "last_seen": row.get::<Option<DateTime<Utc>>, _>("last_seen"),
                "created_at": row.get::<DateTime<Utc>, _>("created_at"),
                "updated_at": row.get::<DateTime<Utc>, _>("updated_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "folders": folders })))
}

/// DELETE /v1/admin/folders/{id} (admin): stop watching a folder. The live OS
/// watch is dropped and the row marked inactive (kept for history). This is a
/// NO-OP on already-ingested memory — stopping a watch never forgets
/// (invalidate-don't-delete). An unknown id is an honest no-op (`stopped:false`)
/// rather than an error, so the console renders "nothing to stop", not a red
/// failure, when a folder was already stopped or never existed.
pub(crate) async fn stop_folder_watch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let updated =
        sqlx::query("UPDATE folder_watches SET active = false, updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(state.pool())
            .await
            .map_err(internal)?;
    let existed = updated.rows_affected() > 0;
    let was_armed = state.folder_watchers.remove(&id).await;
    Ok(Json(serde_json::json!({
        "folder_id": id,
        // True only when a live/active watch was actually turned off; an unknown
        // or already-stopped id is a truthful no-op the UI shows as such.
        "stopped": existed,
        "was_armed": was_armed,
        // Explicit so the UI copy can be honest: nothing was forgotten.
        "memory_retained": true,
    })))
}

// ---------------------------------------------------------------------------
// HTTP: pre-flight preview (bounded count) + stop an in-flight initial scan.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct PreviewParams {
    #[allow(dead_code)] // admitted for symmetry/audit; the count is path-only
    tenant_id: TenantId,
    path: String,
}

/// GET /v1/admin/folders/preview?tenant_id=&path= (admin): a BOUNDED pre-flight
/// count of a folder — {files, bytes, capped} — so the UI can decide whether to
/// require an explicit "this is a big folder" confirm before registering. The
/// count is bounded ([`MAX_PREVIEW_ENTRIES`] / [`PREVIEW_BUDGET`]) so it never
/// hangs on a huge tree; `capped = true` means "at least this many, bigger than
/// we counted". Read-only (never creates the folder, unlike register). Fails
/// closed on an unreadable path (a 422 refusal, never a false 0-file count).
pub(crate) async fn preview_folder(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<PreviewParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;

    let path = PathBuf::from(&p.path);
    if !path.is_absolute() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("path must be absolute (server-local): {}", p.path),
        ));
    }
    // Read-only: a non-existent path is "nothing to count" (NOT a mkdir side
    // effect — register creates the inbox, preview must not).
    if !path.exists() {
        return Ok(Json(serde_json::json!({
            "exists": false,
            "files": 0,
            "bytes": 0,
            "capped": false,
        })));
    }
    if !path.is_dir() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{} is not a directory", p.path),
        ));
    }

    // The bounded walk uses std::fs (blocking); offload it so the async runtime
    // never stalls for the (bounded) budget.
    let count = tokio::task::spawn_blocking(move || count_folder_bounded(&path))
        .await
        .map_err(internal)?
        .map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("refusing: folder is not readable by the server: {e}"),
            )
        })?;

    Ok(Json(serde_json::json!({
        "exists": true,
        "files": count.files,
        "bytes": count.bytes,
        "capped": count.capped,
    })))
}

/// Cap on subdirectories returned by one browse call — a directory with tens of
/// thousands of children never blows up the response or the picker.
const MAX_BROWSE_DIRS: usize = 1000;

#[derive(Deserialize)]
pub(crate) struct BrowseParams {
    /// Absolute server-local path to list. Empty/absent => the server's home
    /// directory (a sane starting point for the picker).
    #[serde(default)]
    path: String,
}

/// Immediate SUBDIRECTORIES of `dir` (dirs only, hidden dotdirs skipped), name
/// A→Z, capped at [`MAX_BROWSE_DIRS`]. Unreadable subdirs are skipped, never
/// fatal; only an unreadable ROOT is an `Err` the handler turns into a 422 (a
/// picker must never render an empty dir as "no folders here").
fn list_subdirs_bounded(dir: &Path) -> std::io::Result<(Vec<(String, PathBuf)>, bool)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut capped = false;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        // file_type() avoids a follow-symlink stat where possible; fall back to
        // is_dir() (which does follow) so a symlinked folder is still browsable.
        let is_dir = match entry.file_type() {
            Ok(ft) if ft.is_dir() => true,
            Ok(ft) if ft.is_symlink() => entry.path().is_dir(),
            _ => false,
        };
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // hidden dirs are noise for a folder-to-watch picker
        }
        if out.len() >= MAX_BROWSE_DIRS {
            capped = true;
            break;
        }
        out.push((name, entry.path()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((out, capped))
}

/// GET /v1/admin/folders/browse?path= (admin): a server-side directory picker.
/// Lists the immediate subdirectories of `path` so the console can navigate the
/// SERVER's filesystem (the watch runs on the server host; a browser cannot see
/// the server's real absolute paths). Admin-gated; this exposes no more than an
/// admin can already reach by typing any absolute path into the watch dialog.
///
/// Fail-closed exactly like `preview_folder`: the path is canonicalized (so `..`
/// and symlinks resolve and the returned path is a real absolute one), must be a
/// readable directory, and an unreadable root is a 422 refusal — never a false
/// "empty folder". Empty/absent `path` starts at the server's home directory.
pub(crate) async fn browse_folder(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<BrowseParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;

    // Default to the server's home directory when no path is given.
    let requested = if p.path.trim().is_empty() {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"))
    } else {
        PathBuf::from(p.path.trim())
    };

    if !requested.is_absolute() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "path must be absolute (server-local): {}",
                requested.display()
            ),
        ));
    }

    // canonicalize resolves `..`/symlinks and REQUIRES the path to exist — a
    // missing/unreadable path fails here, fail-closed (never a fabricated tree).
    let dir = std::fs::canonicalize(&requested).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("cannot open {}: {e}", requested.display()),
        )
    })?;
    if !dir.is_dir() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{} is not a directory", dir.display()),
        ));
    }

    let dir_for_list = dir.clone();
    let (entries, capped) =
        tokio::task::spawn_blocking(move || list_subdirs_bounded(&dir_for_list))
            .await
            .map_err(internal)?
            .map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("refusing: directory is not readable by the server: {e}"),
                )
            })?;

    let parent = dir.parent().map(|p| p.to_string_lossy().into_owned());
    let entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(name, path)| serde_json::json!({ "name": name, "path": path.to_string_lossy() }))
        .collect();

    Ok(Json(serde_json::json!({
        "path": dir.to_string_lossy(),
        // null at the filesystem root — the picker hides "up" there.
        "parent": parent,
        "entries": entries,
        "capped": capped,
    })))
}

#[derive(Deserialize)]
pub(crate) struct StopScanRequest {
    tenant_id: TenantId,
    folder_id: Uuid,
}

/// POST /v1/admin/folders/scan/stop (admin): cancel an IN-PROGRESS initial scan
/// cleanly. Cooperative — the task checks a cancel flag between files and exits
/// after the current file, writing its own terminal `paused` row (so the strip
/// flips to the honest stopped state). Already-ingested files STAY; the live
/// OS-watch for new files is UNAFFECTED (this is not the steady-state watch-off,
/// which is DELETE /v1/admin/folders/{id}). An unknown/finished scan is a
/// truthful no-op (`stopped: false`).
pub(crate) async fn stop_folder_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<StopScanRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let run_id = state
        .folder_scans
        .cancel(req.tenant_id, req.folder_id)
        .await;
    Ok(Json(serde_json::json!({
        "folder_id": req.folder_id,
        "stopped": run_id.is_some(),
        "run_id": run_id,
        // Explicit so the UI copy stays honest: nothing already ingested is lost.
        "memory_retained": true,
    })))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browse_lists_subdirs_only_sorted_skipping_hidden() {
        let base = std::env::temp_dir().join(format!("verity-browse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("zeta")).unwrap();
        std::fs::create_dir_all(base.join("alpha")).unwrap();
        std::fs::create_dir_all(base.join(".hidden")).unwrap();
        std::fs::write(base.join("a-file.txt"), b"x").unwrap();

        let (dirs, capped) = list_subdirs_bounded(&base).unwrap();
        let names: Vec<&str> = dirs.iter().map(|(n, _)| n.as_str()).collect();
        // Only real subdirs, hidden skipped, files excluded, sorted A→Z.
        assert_eq!(names, vec!["alpha", "zeta"]);
        assert!(!capped);
        // An unreadable/missing root is an Err (fail closed), never empty-ok.
        assert!(list_subdirs_bounded(&base.join("does-not-exist")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn skip_rules_cover_hidden_and_editor_temp_files() {
        assert!(is_skippable(".DS_Store"));
        assert!(is_skippable(".hidden"));
        assert!(is_skippable("notes.txt.tmp"));
        assert!(is_skippable("draft.swp"));
        assert!(is_skippable("~$deck.pptx"));
        assert!(is_skippable("backup~"));
        assert!(!is_skippable("renewal-risk.md"));
        assert!(!is_skippable("acme_pipeline.csv"));
    }

    #[test]
    fn text_vs_binary_routing() {
        assert!(!looks_binary(b"plain utf-8 text, no nulls"));
        assert!(looks_binary(b"%PDF-1.7 ..."));
        assert!(looks_binary(b"PK\x03\x04rest-of-zip"));
        assert!(looks_binary(&[0xD0, 0xCF, 0x11, 0xE0, 0x00]));
        assert!(looks_binary(b"has a \0 nul"));
    }

    #[test]
    fn source_name_is_folder_prefixed() {
        assert_eq!(source_name("acme-drop"), "folder:acme-drop");
    }

    // -----------------------------------------------------------------------
    // Hermetic (no DSN, no server): the pure pre-flight-count + scan-plane
    // primitives — bounded count caps, register-plane cancel flips state.
    // -----------------------------------------------------------------------

    #[test]
    fn bounded_count_sums_files_and_bytes_below_cap() {
        let dir = std::env::temp_dir().join(format!("verity-count-{}", Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
        std::fs::write(dir.join("a.txt"), b"12345").expect("write a"); // 5 bytes
        std::fs::write(dir.join("sub/b.txt"), b"678").expect("write b"); // 3 bytes
        std::fs::write(dir.join(".hidden"), b"skipme").expect("write hidden"); // skipped
        std::fs::write(dir.join("c.tmp"), b"tmp").expect("write tmp"); // skipped

        let count = count_folder_bounded(&dir).expect("count");
        assert_eq!(count.files, 2, "only the two non-skippable files count");
        assert_eq!(count.bytes, 8, "bytes sum the two counted files");
        assert!(!count.capped, "a tiny tree is not capped");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_count_trips_capped_past_entry_cap() {
        let dir = std::env::temp_dir().join(format!("verity-count-cap-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // MAX_PREVIEW_ENTRIES is 5000; write a few more than that so the walk
        // must trip capped (empty files keep the test cheap).
        for i in 0..(MAX_PREVIEW_ENTRIES + 50) {
            std::fs::write(dir.join(format!("f{i}.txt")), b"").expect("write");
        }
        let count = count_folder_bounded(&dir).expect("count");
        assert!(
            count.capped,
            "a tree bigger than the entry cap must report capped"
        );
        assert!(
            count.files <= MAX_PREVIEW_ENTRIES,
            "the count stops at the entry cap, never walks the whole tree"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_count_fails_closed_on_unreadable_root() {
        // A path that does not exist as a readable dir → Err (fail closed), not a
        // silent 0-file count. (read_dir on a missing path errors.)
        let missing = std::env::temp_dir().join(format!("verity-missing-{}", Uuid::now_v7()));
        assert!(
            count_folder_bounded(&missing).is_err(),
            "an unreadable/absent root must be an Err, never a false 0"
        );
    }

    #[tokio::test]
    async fn scan_plane_cancel_flips_scanning_state() {
        // Pure plane mechanics, no AppState: insert a live handle, prove cancel
        // sets the flag, removes the handle (status no longer claims live), and
        // returns the run_id; a second cancel is an honest no-op.
        let plane = FolderScanPlane::new();
        let tenant: TenantId = Uuid::now_v7();
        let folder_id = Uuid::now_v7();
        let run_id = Uuid::now_v7();
        let cancel = Arc::new(AtomicBool::new(false));

        // A trivial task that just waits on the flag, so it is genuinely live.
        let flag = Arc::clone(&cancel);
        let task = tokio::spawn(async move {
            while !flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        plane.scans.lock().await.insert(
            (tenant, folder_id),
            ScanHandle {
                run_id,
                cancel: Arc::clone(&cancel),
                task,
            },
        );

        assert!(
            plane.is_scanning(tenant, folder_id).await,
            "a registered scan reads as live"
        );
        let cancelled = plane.cancel(tenant, folder_id).await;
        assert_eq!(cancelled, Some(run_id), "cancel returns the run_id");
        assert!(
            cancel.load(Ordering::SeqCst),
            "cancel sets the cooperative flag the task checks"
        );
        assert!(
            !plane.is_scanning(tenant, folder_id).await,
            "after cancel the handle is gone — status no longer claims live"
        );
        // Second cancel: honest no-op.
        assert_eq!(plane.cancel(tenant, folder_id).await, None);
    }

    #[tokio::test]
    async fn tracking_returns_before_scan_task_completes() {
        // The register-fast contract: recording the scan handle returns while the
        // scan task is STILL RUNNING — the caller (the HTTP handler) never blocks
        // on the walk. Modeled on spawn_initial_scan's insert step: a task that
        // parks until released, a handle recorded for it, and an assertion that we
        // observe the live handle BEFORE the task has finished.
        let plane = Arc::new(FolderScanPlane::new());
        let tenant: TenantId = Uuid::now_v7();
        let folder_id = Uuid::now_v7();
        let run_id = Uuid::now_v7();

        let release = Arc::new(AtomicBool::new(false));
        let task_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            // Simulates the still-in-flight scan of existing files.
            while !task_release.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let handle = plane
            .scans
            .lock()
            .await
            .insert(
                (tenant, folder_id),
                ScanHandle {
                    run_id,
                    cancel: Arc::new(AtomicBool::new(false)),
                    task,
                },
            )
            .map(|_| ());
        assert!(handle.is_none(), "first scan for a folder replaces nothing");

        // We are HERE (analogous to the handler having returned its 200) while the
        // scan task is provably not yet finished.
        assert!(
            plane.is_scanning(tenant, folder_id).await,
            "the scan is tracked as live the instant registration returns"
        );
        {
            let map = plane.scans.lock().await;
            assert!(
                !map.get(&(tenant, folder_id)).unwrap().task.is_finished(),
                "register returned BEFORE the scan task ran to completion"
            );
        }

        // Now let the task finish and clean up.
        release.store(true, Ordering::SeqCst);
        let _ = plane.cancel(tenant, folder_id).await;
    }

    // -----------------------------------------------------------------------
    // DSN-gated integration: watch a temp dir, drop a file, prove it ingests
    // under the configured visibility and a WRONG-scope read cannot see it
    // (fail closed), plus boot re-establishment of a persisted watch.
    // -----------------------------------------------------------------------

    use crate::upsert_principal_tokens;
    use axum::extract::State as AxState;
    use axum::http::HeaderMap;
    use axum::Json;
    use verity_core::adapter::StorageAdapter;
    use verity_core::types::{RecallQuery, Scope};
    use verity_storage::{CachedAdapter, PostgresAdapter};

    async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
        let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
        let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
        pg.migrate().await.expect("migrate");
        let tenant = pg
            .create_tenant(&format!("folder-watch-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant");
        let state = Arc::new(AppState {
            storage: CachedAdapter::new(pg, 10_000),
            encoder: None, // BM25-only recall — no model download in tests
            minter: crate::scope::ScopeMinter::ephemeral(),
            purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
            admin: crate::AdminAuth {
                key: [0u8; 32],
                expected_tag: None, // dev mode: admin surfaces open
                allowed_origin: None,
            },
            rebac: None,
            revocations: crate::revocation::RevocationPlane::new(300),
            watch: Arc::new(crate::rebac_watch::WatchStatus::new()),
            watch_staleness_fence_secs: 900,
            folder_watchers: Arc::new(WatcherRegistry::new()),
            folder_scans: Arc::new(FolderScanPlane::new()),
            knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
            directory: crate::directory_worker::DirectoryPlane::disabled(),
            entra_directory: crate::directory_worker::EntraDirectoryPlane::disabled(),
            connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
            sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
            repo_root: None,
            listen: "127.0.0.1:0".to_string(),
            admin_token: None,
            source_freshness: crate::source_freshness::SourceFreshnessPlane::new(None),
            metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
            allow_restricted_without_rebac: false,
            remember_require_lineage: false,
            subscribers: crate::subscribe::Subscribers::new(64),
            auto_tag: false,
            knowledge_auto_merge: true,
            resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
            media_store: None,
        });
        Some((state, tenant))
    }

    /// BM25 recall over a scope carrying exactly `principals`.
    async fn recall_as(
        state: &AppState,
        tenant: TenantId,
        principals: Vec<PrincipalToken>,
        text: &str,
    ) -> Vec<String> {
        let hits = state
            .storage
            .recall(RecallQuery {
                scope: Scope {
                    tenant_id: tenant,
                    principals,
                    entity_scope: vec![],
                    max_confidentiality: Confidentiality::Internal,
                },
                embedding: None,
                text: Some(text.to_string()),
                k: 20,
            })
            .await
            .expect("recall");
        hits.into_iter().map(|h| h.content).collect()
    }

    /// Poll recall until a hit appears or the deadline passes (the live watch is
    /// async: debounce + FS event + ingest task).
    async fn recall_until(
        state: &AppState,
        tenant: TenantId,
        principals: Vec<PrincipalToken>,
        text: &str,
        needle: &str,
    ) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let hits = recall_as(state, tenant, principals.clone(), text).await;
            if hits.iter().any(|c| c.contains(needle)) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    async fn token_for(state: &AppState, tenant: TenantId, principal: &str) -> PrincipalToken {
        upsert_principal_tokens(state.pool(), tenant, &[principal.to_string()])
            .await
            .expect("token")[0]
            .1
    }

    #[tokio::test]
    async fn drop_file_ingests_under_visibility_and_wrong_scope_is_blind() {
        let Some((state, tenant)) = test_state().await else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let folder = format!("acme-drop-{}", Uuid::now_v7());
        let dir = std::env::temp_dir().join(&folder);
        std::fs::create_dir_all(&dir).expect("mkdir");

        // The who-can-see-it policy is materialized tokens (as the console's
        // picker sends them): resolve user:jordan's token first, pass it as
        // `visibility`. The watch `name`/source is derived from the folder name.
        let jordan = token_for(&state, tenant, "user:jordan").await;
        let stranger = token_for(&state, tenant, "user:stranger").await;

        let resp = add_folder_watch(
            AxState(Arc::clone(&state)),
            HeaderMap::new(),
            Json(
                serde_json::from_value(serde_json::json!({
                    "tenant_id": tenant,
                    "path": dir.to_string_lossy(),
                    "visibility": [jordan],
                    "confidentiality": "Internal",
                }))
                .unwrap(),
            ),
        )
        .await
        .expect("add watch");
        let Json(body) = resp;
        assert_eq!(body["watching"], true);
        assert_eq!(body["source"], format!("folder:{folder}"));
        assert!(body["folder_id"].is_string());

        // Drop a file INTO the watched folder — the live watch must ingest it.
        let needle = "renewal risk at Acme Freight is elevated";
        std::fs::write(dir.join("acme-renewal.md"), format!("# Acme\n\n{needle}\n"))
            .expect("write");

        assert!(
            recall_until(&state, tenant, vec![jordan], "renewal risk Acme", needle).await,
            "jordan (the configured principal) must see the dropped file"
        );
        // Fail closed: a scope WITHOUT jordan's token sees nothing.
        let stranger_hits = recall_as(&state, tenant, vec![stranger], "renewal risk Acme").await;
        assert!(
            !stranger_hits.iter().any(|c| c.contains(needle)),
            "a wrong-scope read must NOT see the file (fail closed)"
        );
        // And an empty-principal scope sees nothing (belt).
        let none_hits = recall_as(&state, tenant, vec![], "renewal risk Acme").await;
        assert!(none_hits.is_empty(), "empty scope reads nothing");

        // Source registered live in Sources & Freshness as folder:<name>.
        // The status row is bumped per-file inside the async ingest task, which
        // can lag chunk visibility, so poll for it (as the recall above does)
        // rather than assume it lands synchronously with the recalled chunk.
        let folder_src = format!("folder:{folder}");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let registered = loop {
            let sources = crate::connectors::list_status_rows(state.pool(), tenant)
                .await
                .expect("status");
            if sources.iter().any(|s| s["source"] == folder_src) {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        };
        assert!(registered, "the watch registers as a live source");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn boot_reestablish_catches_files_dropped_while_down() {
        let Some((state, tenant)) = test_state().await else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let dir = std::env::temp_dir().join(format!("verity-watch-boot-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("mkdir");

        // Simulate "configured earlier": a persisted row with no live watch, and
        // last_seen in the past so the on-boot re-scan treats the file as new.
        let jordan = token_for(&state, tenant, "user:jordan").await;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO folder_watches (id, tenant_id, name, path, visibility, confidentiality, active, last_seen)
             VALUES ($1, $2, 'boot-drop', $3, $4, 1, true, now() - interval '1 hour')",
        )
        .bind(id)
        .bind(tenant)
        .bind(dir.to_string_lossy())
        .bind(vec![jordan])
        .execute(state.pool())
        .await
        .expect("insert watch row");

        // File already present on disk (dropped while the server was "down").
        let needle = "Q3 forecast for Acme Freight closed at 125k";
        std::fs::write(dir.join("forecast.txt"), needle).expect("write");

        // Boot: re-scan + re-arm.
        reestablish_on_boot(Arc::clone(&state)).await;

        // The catch-up scan is synchronous inside reestablish_on_boot, so the
        // file is already queryable — under jordan, and blind to a stranger.
        let hits = recall_as(&state, tenant, vec![jordan], "Q3 forecast Acme").await;
        assert!(
            hits.iter().any(|c| c.contains("125k")),
            "boot catch-up must ingest the file dropped while down"
        );
        let stranger = token_for(&state, tenant, "user:stranger").await;
        let stranger_hits = recall_as(&state, tenant, vec![stranger], "Q3 forecast Acme").await;
        assert!(
            !stranger_hits.iter().any(|c| c.contains("125k")),
            "fail closed after boot re-establish too"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
