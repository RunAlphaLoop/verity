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
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use notify_debouncer_full::notify::{RecursiveMode, Watcher as _};
use notify_debouncer_full::{new_debouncer, DebounceEventResult};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;
use uuid::Uuid;

use verity_core::types::{AclProvenance, Confidentiality, PrincipalToken, TenantId};

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

    // Ingest files already present (the "drop first, then configure" and the
    // seed-a-folder flows both land here), then arm the live watch.
    let mut ingested = 0usize;
    for file in collect_files(&path) {
        match ingest_file(&state, &watch, &file).await {
            Ok(true) => ingested += 1,
            Ok(false) => {}
            Err((status, msg)) => {
                tracing::warn!(folder = %name, %status, "folder watch: initial ingest failed: {msg}");
            }
        }
    }
    let _ = touch_last_seen(state.pool(), effective_id).await;

    // If a watch with this name was already armed, drop it before re-arming so
    // we don't hold two OS watches for the same folder.
    state.folder_watchers.remove(&effective_id).await;
    if let Err(e) = arm_watch(Arc::clone(&state), watch).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("folder recorded but the live watch could not be armed: {e}"),
        ));
    }

    Ok(Json(serde_json::json!({
        "folder_id": effective_id,
        "source": source_name(&name),
        "path": req.path,
        "visibility": visibility,
        "confidentiality": req.confidentiality,
        "created": created,
        "initial_files_ingested": ingested,
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            folder_watchers: Arc::new(WatcherRegistry::new()),
            knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
            directory: crate::directory_worker::DirectoryPlane::disabled(),
            connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
            repo_root: None,
            listen: "127.0.0.1:0".to_string(),
            admin_token: None,
            allow_restricted_without_rebac: false,
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
        let sources = crate::connectors::list_status_rows(state.pool(), tenant)
            .await
            .expect("status");
        assert!(
            sources
                .iter()
                .any(|s| s["source"] == format!("folder:{folder}")),
            "the watch registers as a live source"
        );

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
