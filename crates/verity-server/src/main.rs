//! Verity server — API plane (Milestone A engine + Milestone B scope seam).
//!
//! Every read/write verb takes a MemoryScope handle (see scope.rs); scope
//! parameters cannot be widened by request arguments. Handle MINTING still
//! accepts caller-supplied principals until the identity/ReBAC planes land —
//! that seam is documented in scope.rs and POST /v1/scopes.

mod audit;
mod backfill;
mod compliance;
// Phase-3 backfill worker module. Its public surface (start/stop/status +
// argv assembly) is consumed by the connector backfill endpoint + panel, wired
// in a sibling task; allow dead_code until that lands so this module lands
// self-contained with its own hermetic tests.
#[allow(dead_code)]
mod connector_worker;
mod connectors;
mod connectors_admin;
#[cfg(test)]
mod console_later_tests;
mod consolidation;
#[cfg(test)]
mod consolidation_tests;
mod directory_worker;
#[cfg(test)]
mod entity_resolution_tests;
mod extract;
#[cfg(test)]
mod extract_tests;
mod folder_watch;
#[cfg(test)]
mod identity_tests;
mod ingest;
mod knowledge_worker;
#[cfg(test)]
mod manifest_tests;
mod manifests;
mod media;
#[cfg(test)]
mod media_tests;
mod metrics;
mod playground;
#[cfg(test)]
mod principals_tests;
mod purpose;
mod rebac;
mod rebac_watch;
mod resolver;
mod revocation;
mod scheduler;
mod scope;
mod slo;
#[cfg(test)]
mod sse_tests;
mod subscribe;
mod sync_scheduler;
#[cfg(test)]
mod sync_scheduler_tests;
#[cfg(test)]
mod system_tests;
#[cfg(test)]
mod tenants_tests;
mod ui;
mod webhooks;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use clap::Parser;
use serde::Deserialize;

use audit::spawn_audit;
use purpose::PurposePack;
use rebac::Rebac;
use revocation::RevocationPlane;
use scope::{ScopeMinter, ScopePayload};
use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

/// `verity_core::types::Result` shadows std's; handlers need the two-arg form.
pub(crate) type HandlerResult<T> = std::result::Result<T, (StatusCode, String)>;

#[derive(Parser)]
#[command(
    name = "verity",
    about = "Verity — permission-aware shared memory for agents"
)]
struct Cli {
    #[arg(long, default_value = "postgres://verity:verity@localhost:5433/verity")]
    dsn: String,
    #[arg(long, default_value = "127.0.0.1:7717")]
    listen: String,
    /// Repo root so the server can spawn the knowledge worker from
    /// `<repo>/ingest/.venv`. Falls back to `VERITY_REPO` when the flag is
    /// absent (see `Cli::repo_root`). Absent both → the knowledge plane reports
    /// `startable:false` with the fix in its `start_hint`; it is NEVER a hard
    /// boot failure (a server with no ingest checkout still runs every
    /// read/write path).
    #[arg(long)]
    repo: Option<std::path::PathBuf>,
}

impl Cli {
    /// Repo root from `--repo`, else `VERITY_REPO` (clap's `env` feature isn't
    /// enabled in this workspace, so the fallback is resolved by hand).
    fn repo_root(&self) -> Option<std::path::PathBuf> {
        self.repo
            .clone()
            .or_else(|| std::env::var_os("VERITY_REPO").map(std::path::PathBuf::from))
    }
}

/// Admin/ingest-plane bearer auth (roadmap task 3). When `VERITY_ADMIN_TOKEN`
/// is set, admin surfaces require `Authorization: Bearer <token>`; the check
/// is constant-time (HMAC tags under a per-process random key compared via
/// `Mac::verify_slice`). Unset = dev mode: warned once at startup, allowed.
pub(crate) struct AdminAuth {
    key: [u8; 32],
    expected_tag: Option<Vec<u8>>,
    // Read only by `SecretIntakeAuth::from_request_parts` via `check_origin`,
    // which gates the Phase-2 credential POST/DELETE/test handlers.
    /// `VERITY_ALLOWED_ORIGIN` — the one browser origin (scheme://host[:port])
    /// permitted to POST a secret to the secret-intake surface. Phase 2 CSRF
    /// defense: a cross-site form can set neither this `Origin` nor a bearer it
    /// cannot read, so a request whose `Origin` is present and ≠ this value is
    /// refused (`SecretIntakeAuth`). `None` = no browser origin is allowed; only
    /// server-to-server callers (no `Origin` header at all) may reach the
    /// surface, still under bearer auth. Never consulted by `check`/`require`;
    /// origin enforcement lives only on `SecretIntakeAuth`.
    allowed_origin: Option<String>,
}

impl AdminAuth {
    fn from_env() -> Self {
        let mut key = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut key);
        let expected_tag = match std::env::var("VERITY_ADMIN_TOKEN") {
            Ok(token) if !token.is_empty() => Some(Self::tag(&key, token.trim())),
            _ => {
                tracing::warn!("admin surfaces unauthenticated — dev mode (set VERITY_ADMIN_TOKEN to require bearer auth)");
                None
            }
        };
        let allowed_origin = std::env::var("VERITY_ALLOWED_ORIGIN")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Self {
            key,
            expected_tag,
            allowed_origin,
        }
    }

    /// Hermetic constructor for tests: build an `AdminAuth` with an explicit
    /// token (or `None` for the dev-open / no-token state) and an explicit
    /// allowed origin, without touching process env.
    #[cfg(test)]
    fn for_test(token: Option<&str>, allowed_origin: Option<&str>) -> Self {
        let mut key = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut key);
        let expected_tag = token.map(|t| Self::tag(&key, t.trim()));
        Self {
            key,
            expected_tag,
            allowed_origin: allowed_origin.map(|s| s.to_string()),
        }
    }

    fn tag(key: &[u8; 32], token: &str) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length works");
        mac.update(token.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    pub(crate) fn check(&self, headers: &HeaderMap) -> HandlerResult<()> {
        let Some(expected) = &self.expected_tag else {
            return Ok(()); // dev mode
        };
        self.verify_bearer(headers, expected)
    }

    /// Like `check`, but with NO dev-open branch: when `VERITY_ADMIN_TOKEN` is
    /// unset/empty (`expected_tag` is `None`) this returns 401 instead of
    /// `Ok(())`. Backs `SecretIntakeAuth` — the secret-intake surface must never
    /// be reachable unauthenticated, unlike every other admin surface which is
    /// dev-open via `check`. The constant-time HMAC path is shared with `check`
    /// (`verify_bearer`); only the missing-token disposition differs.
    // Consumed by `SecretIntakeAuth`, which gates the Phase-2 credential handlers.
    pub(crate) fn require(&self, headers: &HeaderMap) -> HandlerResult<()> {
        let Some(expected) = &self.expected_tag else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "secret intake requires VERITY_ADMIN_TOKEN (no dev-open path)".to_string(),
            ));
        };
        self.verify_bearer(headers, expected)
    }

    /// A short, non-reversible fingerprint of the presented bearer, for the
    /// Permission Graph audit `actor` column: an HMAC-tag prefix (never the raw
    /// token). Returns `"dev-open"` when no bearer is present (only possible on
    /// a `check`-gated surface — the Permission Graph uses `require`, which
    /// refuses a missing bearer, so this returns a real fingerprint there).
    pub(crate) fn actor_fingerprint(&self, headers: &HeaderMap) -> String {
        let Some(provided) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return "dev-open".to_string();
        };
        let tag = Self::tag(&self.key, provided.trim());
        let hex: String = tag.iter().take(6).map(|b| format!("{b:02x}")).collect();
        format!("bearer:{hex}")
    }

    /// Constant-time bearer verification shared by `check`/`require`. Reads the
    /// bearer ONLY from `Authorization: Bearer <token>`, never a cookie (a
    /// cookie would let a cross-site form ride the browser's ambient
    /// credential — the exact CSRF vector `SecretIntakeAuth` also guards).
    fn verify_bearer(&self, headers: &HeaderMap, expected: &[u8]) -> HandlerResult<()> {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "admin surface requires Authorization: Bearer <token>".to_string(),
            ))?;
        use hmac::{Hmac, Mac};
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(&self.key).expect("any key length works");
        mac.update(provided.trim().as_bytes());
        // Constant-time comparison via the Mac trait.
        mac.verify_slice(expected)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid admin token".to_string()))
    }

    /// CSRF/same-origin gate for `SecretIntakeAuth`. A browser attaches an
    /// `Origin` header it cannot forge cross-site; a server-to-server client
    /// sends none. Rules (fail-closed):
    ///   - `Origin` present and == `VERITY_ALLOWED_ORIGIN`  → allow.
    ///   - `Origin` present and no `VERITY_ALLOWED_ORIGIN` configured → 403
    ///     (a browser request with no allowlist is refused, never defaulted).
    ///   - `Origin` present and != the configured value → 403.
    ///   - `Origin` absent (non-browser caller) → allow; bearer already gates.
    ///
    /// A valid bearer alone is therefore insufficient for a cross-site browser
    /// POST — the `Origin` must also match.
    // Consumed by `SecretIntakeAuth`, which gates the Phase-2 credential handlers.
    fn check_origin(&self, headers: &HeaderMap) -> HandlerResult<()> {
        let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
            return Ok(()); // no Origin → server-to-server; bearer suffices.
        };
        match &self.allowed_origin {
            Some(allowed) if origin == allowed => Ok(()),
            _ => Err((
                StatusCode::FORBIDDEN,
                "cross-origin secret intake refused (set VERITY_ALLOWED_ORIGIN to the console origin)".to_string(),
            )),
        }
    }
}

/// A distinct axum extractor for the secret-intake surface (Phase-2 §AUTH +
/// §CSRF). Unlike `AdminAuth::check`, it has NO dev-open branch: an unset
/// `VERITY_ADMIN_TOKEN` yields 401, so the compiler-applied `SecretIntakeAuth`
/// argument can never reuse the dev-open admin path. It also enforces a
/// same-origin/`Origin` check so a valid bearer alone is insufficient against a
/// cross-site browser POST. Handlers opt in by taking a `_auth: SecretIntakeAuth`
/// argument; because `FromRequestParts` runs before any body extractor, place it
/// BEFORE any `Json<…>` argument.
// Wired to the Phase-2 credential POST/DELETE/test handlers
// (connectors_admin.rs) — the extractor argument makes the gate
// compiler-enforced and runs before any body extractor.
pub(crate) struct SecretIntakeAuth;

impl axum::extract::FromRequestParts<Arc<AppState>> for SecretIntakeAuth {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        // Order: origin first (cheap, no bearer oracle), then bearer with NO
        // dev-open branch. Both must pass.
        state.admin.check_origin(&parts.headers)?;
        state.admin.require(&parts.headers)?;
        Ok(SecretIntakeAuth)
    }
}

/// A redacting, zeroize-on-drop wrapper for a pasted secret in memory. `Debug`
/// and `Display` print `***` so a secret can never leak through a log line or a
/// formatted error; the inner bytes are wiped on drop so freed memory does not
/// retain key material. Use it for ANY pasted secret from the moment of intake
/// (contrast `SlackConnector`, which derived `Debug` over a bare `String`
/// token — the failure mode this type exists to prevent).
// Wraps the pasted bearer at the Phase-2 credential intake handler
// (connectors_admin.rs); deserialize + format-redaction + zeroize are proven by
// unit tests. `expose()` is handed to the encryptor / test-probe ONLY.
pub(crate) struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    pub(crate) fn new(raw: String) -> Self {
        Secret(zeroize::Zeroizing::new(raw))
    }

    /// The plaintext, for the single choke point that encrypts/probes it. Never
    /// log or format the return value — only `Secret` itself is safe to format.
    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into the Zeroizing<String> directly so the intermediate
        // never sits in a plain String that outlives this call unwiped.
        Ok(Secret(zeroize::Zeroizing::new(String::deserialize(de)?)))
    }
}

/// Bind-time gate decision (Phase-2 §TRANSPORT, D1). Given the parsed `--listen`
/// address and whether the two required env vars are set, decide whether the
/// server may bind. Loopback (127.0.0.0/8, ::1) binds unconditionally. A
/// non-loopback bind (including the unspecified `0.0.0.0`/`::`, which exposes
/// every interface and is NOT loopback) REFUSES unless BOTH `VERITY_ADMIN_TOKEN`
/// and `VERITY_KEK` are set. Pure + hermetic so it can be unit-tested without a
/// socket or process env.
fn bind_gate_decision(
    addr: std::net::SocketAddr,
    admin_set: bool,
    kek_set: bool,
) -> std::result::Result<(), String> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if admin_set && kek_set {
        return Ok(());
    }
    Err(format!(
        "refusing to bind non-loopback address {addr}: set VERITY_ADMIN_TOKEN and VERITY_KEK (or bind a loopback address)"
    ))
}

pub(crate) struct AppState {
    pub(crate) storage: CachedAdapter<PostgresAdapter>,
    /// Local query encoder (SPEC §4a). None = sparse-only recall; the server
    /// stays up if model download fails, it just loses the dense leg.
    encoder: Option<Arc<verity_encoder::QueryEncoder>>,
    pub(crate) minter: ScopeMinter,
    pub(crate) purposes: PurposePack,
    pub(crate) admin: AdminAuth,
    /// SpiceDB seam (task 10). None = ReBAC disabled: dev mode, caller-
    /// supplied principals at mint, restricted-class hits dropped.
    pub(crate) rebac: Option<Rebac>,
    pub(crate) revocations: RevocationPlane,
    /// `VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC=1` — explicit opt-out of the
    /// fail-closed restricted drop when no ReBAC engine is configured.
    pub(crate) allow_restricted_without_rebac: bool,
    /// Live SSE subscription gauge (task 21): capped, 429 beyond.
    pub(crate) subscribers: subscribe::Subscribers,
    /// `VERITY_AUTO_TAG=1` — consolidation tag suggestions at >= 0.9
    /// confidence are applied to chunks immediately. Default OFF: auto-tags
    /// widen retrieval scope for entity-bound scopes (SPEC §7d), so the
    /// default posture is suggest-only with human approval.
    pub(crate) auto_tag: bool,
    /// Media blob object-store seam (task 47, SPEC §10). `Some` when
    /// `VERITY_MEDIA_S3_ENDPOINT` + `VERITY_MEDIA_BUCKET` are configured:
    /// blobs live in S3-compatible storage with a `storage_ref` in the media
    /// row. `None` = the Postgres `bytea` dev-grade path, unchanged.
    pub(crate) media_store: Option<media::MediaStore>,
    /// `VERITY_KNOWLEDGE_AUTO_MERGE` kill switch (knowledge-merge-tuning.md §5).
    /// Default ON. When set to `0`, the server IGNORES worker-supplied
    /// `merge_into` entirely: only the deterministic canonical-exact fast path
    /// merges, so consolidation degrades to assisted/human-clustered — never a
    /// silent judged merge. A false merge fabricates cross-customer support
    /// (§1's governing asymmetry), so this is the emergency stop for the
    /// judged-merge leg.
    pub(crate) knowledge_auto_merge: bool,
    /// Server-side debounced auto-resolve (scheduler.rs). Every successful
    /// L1-mutating ingest marks its tenant dirty here; a background loop
    /// resolves dirty tenants past the `VERITY_RESOLVE_DEBOUNCE` window. This
    /// closes the gap where DIRECT ingest paths never auto-fired resolution
    /// (only the Temporal Python hook did). Because connector sinks also POST to
    /// `/v1/ingest/*`, this now covers the direct paths AND the connector sinks;
    /// it and the Temporal hook are belt-and-suspenders, deduped by the shared
    /// debounce + idempotent evidence.
    pub(crate) resolution: scheduler::ResolutionScheduler,
    /// SpiceDB Watch consumer health (rebac_watch.rs; SPEC §7b, opt-in via
    /// `VERITY_SPICEDB_WATCH=1`). Always present so the admin status endpoint
    /// can report `enabled: false`; the consumer only ADDS revocation
    /// tombstones — the read path never consults it.
    pub(crate) watch: Arc<rebac_watch::WatchStatus>,
    /// Live local-folder watchers (folder_watch.rs). Holds the OS-level watch
    /// handles keyed by watch id so add/stop can arm/disarm them at runtime;
    /// re-populated from the `folder_watches` table on boot. Ingest is
    /// write-path only — read-path purity is untouched.
    pub(crate) folder_watchers: Arc<folder_watch::WatcherRegistry>,
    /// Supervised in-process initial-scan plane (folder_watch.rs): one
    /// background scan per (tenant, folder) that walks a newly-registered
    /// folder's EXISTING files off the request path, reports progress via
    /// backfill_run, and is cancellable. Registering a folder no longer blocks
    /// the HTTP response on that walk. See folder_watch::FolderScanPlane.
    pub(crate) folder_scans: Arc<folder_watch::FolderScanPlane>,
    /// Console/CLI-started knowledge consolidation worker (SPEC §2 L2). `Some` =
    /// this server spawned + owns a live child → authoritative planes status
    /// (pid, "started from this console") + a real Stop. `None` = not owned
    /// here; the planes endpoint falls back to the `episode_processing`
    /// activity proxy. ONE owner only — the CLI `--knowledge` flag routes
    /// through `POST /v1/admin/planes/knowledge/start`, never a second child.
    /// `tokio::sync::Mutex` (not std): the start/stop handlers `.await` while
    /// holding the lock across the child `wait()`.
    pub(crate) knowledge_worker: Arc<tokio::sync::Mutex<Option<knowledge_worker::KnowledgeWorker>>>,
    /// Repo root (`--repo` / `VERITY_REPO`) so the server can find
    /// `ingest/.venv` to spawn the knowledge worker. `None` → knowledge is not
    /// startable here; the planes `start_hint` says to restart with `--repo`.
    pub(crate) repo_root: Option<std::path::PathBuf>,
    /// The `--listen` address, so a spawned knowledge worker can be pointed at
    /// this server's own `--base-url` (`http://<listen>`).
    pub(crate) listen: String,
    /// The raw admin bearer (`VERITY_ADMIN_TOKEN`) when the server requires
    /// one, passed to a spawned worker so it can reach the admin-gated
    /// consolidation endpoints. `None` in dev mode (admin surfaces open). NEVER
    /// logged or returned; distinct from `AdminAuth`'s one-way HMAC tag.
    pub(crate) admin_token: Option<String>,
    /// Console/CLI-started Google directory-sync plane (Identity Plane §6a): the
    /// server-owned child (if any) + the spawn config. ONE owner only — the CLI
    /// `--directory` flag routes through the server start endpoint, never a
    /// second child. See directory_worker::DirectoryPlane.
    pub(crate) directory: directory_worker::DirectoryPlane,
    /// Console-triggered per-(tenant, source) ONE-SHOT backfill plane (Phase 3):
    /// the owner map keyed on (tenant, source) + the env SA-key fallback. Only
    /// gdrive/gmail are spawnable; callers gate. Wrapped in `Arc` so the detached
    /// completion reap can clone the plane to clear its own entry on child exit.
    /// See connector_worker::ConnectorPlane.
    #[allow(dead_code)]
    pub(crate) connectors: Arc<connector_worker::ConnectorPlane>,
    /// Continuous-sync SCHEDULER plane (Phase 4, sync_scheduler.rs): per-(tenant,
    /// source) interval loops that fire a short-lived `--once` incremental poll
    /// cycle (NOT a persistent child). Each schedule is durable in `sync_schedules`
    /// (migration 0033) and re-armed on boot. The toggle endpoint arms/disarms;
    /// the loop reuses `ConnectorPlane::start(PollOnce, ..)` for spawn/cleanup/
    /// ownership, skipping a tick when the prior cycle is still in-flight.
    pub(crate) sync: Arc<sync_scheduler::SyncPlane>,
    /// M0 instrument panel (metrics.rs): hand-rolled atomic counters/gauges
    /// rendered by `/metrics`. The hot-path counters (recall, exact-scan,
    /// revocation subtract, audit drops) are cheap `Relaxed` adds; scrape-time
    /// DB gauges (quarantine depth, degraded ACL runs, watch-cursor lag) are
    /// read in the handler, never on the read path. Aggregate-only — no
    /// tenant labels, no secrets.
    pub(crate) metrics: Arc<metrics::Metrics>,
}

impl AppState {
    fn verify_scope(&self, handle: &str) -> HandlerResult<ScopePayload> {
        self.minter
            .verify(handle)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
    }

    /// Direct pool access for server-plane tables (audit, webhooks, media,
    /// principals) that live outside the StorageAdapter seam.
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.storage.inner().pool()
    }

    /// Build the enforcement Scope from a verified handle, subtracting tokens
    /// with an in-window revocation tombstone (SPEC §7b rule 3, v0.1
    /// contract — see revocation.rs). Every scoped read path goes through
    /// here so already-minted handles pick up revocations immediately.
    async fn scope_for(&self, payload: &ScopePayload) -> HandlerResult<Scope> {
        let mut scope = payload.to_scope();
        scope.principals = self
            .revocations
            .subtract(self.pool(), scope.tenant_id, &scope.principals)
            .await?;
        Ok(scope)
    }

    pub(crate) async fn encode(&self, text: &str) -> HandlerResult<Option<Vec<f32>>> {
        let Some(encoder) = &self.encoder else {
            return Ok(None);
        };
        let encoder = Arc::clone(encoder);
        let text = text.to_string();
        tokio::task::spawn_blocking(move || encoder.encode(&text))
            .await
            .map_err(internal)?
            .map(Some)
            .map_err(internal)
    }
}

/// Entity tags an agent writes must stay inside its scope (SPEC §7c): in an
/// entity-bound scope, requested ⊆ scope (empty = inherit the whole scope);
/// in an unbound scope, tags pass through as given.
pub(crate) fn resolve_entities(
    payload: &ScopePayload,
    requested: Vec<String>,
) -> HandlerResult<Vec<String>> {
    if payload.entity_scope.is_empty() {
        return Ok(requested);
    }
    if requested.is_empty() {
        return Ok(payload.entity_scope.clone());
    }
    if requested.iter().all(|e| payload.entity_scope.contains(e)) {
        Ok(requested)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "entities outside the scope's entity_scope".into(),
        ))
    }
}

/// One row in the `GET /v1/admin/planes` report.
///
/// `class` governs the panel's affordance (the no-dead-button rule):
/// - `"startable"` → a real Start/Stop button, but ONLY when `startable:true`;
/// - `"command-only"` → NEVER a button, a copyable `start_hint` command;
/// - `"config-only"` → NEVER a button, status + plain meaning, `start_hint:null`.
///
/// The UI keys off the machine-authoritative `startable`/`start_hint` fields
/// and never re-derives `class`. `knowledge_worker` alone may also carry
/// `authority`/`pid`/`started_at`/`stoppable` (merged in by the caller).
fn plane_row(
    name: &str,
    label: &str,
    class: &str,
    status: &str,
    detail: String,
    startable: bool,
    start_hint: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "label": label,
        "class": class,
        "status": status,
        "detail": detail,
        "startable": startable,
        "start_hint": start_hint,
    })
}

/// Command to bring the identity plane up (it is boot-time env, not
/// click-startable): start SpiceDB, then restart the server with the URL set.
const REBAC_START_HINT: &str = "docker compose -f deploy/docker-compose.yml up -d spicedb  \
     — then restart the server with VERITY_SPICEDB_URL set";
/// Command to bring the media object store up (Docker container, not
/// click-startable).
const MEDIA_START_HINT: &str = "docker compose -f deploy/docker-compose.yml up -d minio minio-init";

/// Coarse, plain-words duration ("15 min", "1 h") for the debounce window.
fn humanize_secs(s: u64) -> String {
    if s >= 3600 && s.is_multiple_of(3600) {
        format!("{} h", s / 3600)
    } else if s >= 60 {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

/// Coarse "how long ago" for an observed activity stamp — never fake-precise.
fn humanize_ago(t: DateTime<Utc>) -> String {
    let secs = (Utc::now() - t).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Query for the "what's running" read: `tenant_id` is REQUIRED — the
/// knowledge activity proxy and the start/stop symmetry are per-tenant.
#[derive(Deserialize)]
struct PlanesQuery {
    tenant_id: uuid::Uuid,
}

/// Body for the knowledge Start/Stop endpoints. Per-tenant so start and the
/// observed proxy line up on the same space.
#[derive(Deserialize)]
struct KnowledgeWorkerBody {
    tenant_id: uuid::Uuid,
}

/// GET /v1/admin/planes?tenant_id=<uuid> (admin): the "what's running"
/// infrastructure surface for the console. Reports each plane's OBSERVED state
/// from what the running server actually knows — the planes AppState holds
/// directly (permissions, media, encoder, auto-resolve, revocation watch) —
/// plus the knowledge worker in two strict tiers: AUTHORITATIVE when this
/// server owns a live child (pid, "started from this console", a real Stop),
/// else an OBSERVED activity proxy from `episode_processing` (labeled
/// "(observed)", no Stop). Every row carries `class`/`startable`/`start_hint`
/// so the panel never renders a dead button: only `knowledge_worker` is ever
/// startable, and only when the repo + venv + key all exist. Each plane probe
/// is independent — a failing probe yields that row `unknown`, never a 500.
async fn admin_planes(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<PlanesQuery>,
    headers: HeaderMap,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut planes: Vec<serde_json::Value> = Vec::new();

    // 1 · identity / ReBAC — files are permission-filtered live when on. Its
    // affordance is command-only: it is boot-time env, so when off the panel
    // teaches how to bring it up (never a dead button).
    if state.rebac.is_some() {
        planes.push(plane_row(
            "rebac",
            "Permissions engine",
            "command-only",
            "on",
            "on — files are permission-filtered live against the identity graph".to_string(),
            false,
            None,
        ));
    } else if state.allow_restricted_without_rebac {
        planes.push(plane_row(
            "rebac",
            "Permissions engine",
            "command-only",
            "degraded",
            "off, and the fail-closed guard is overridden — the most sensitive \
             (restricted) records index with no permissions engine to enforce them"
                .to_string(),
            false,
            Some(REBAC_START_HINT),
        ));
    } else {
        planes.push(plane_row(
            "rebac",
            "Permissions engine",
            "command-only",
            "off",
            "off — dev mode: reader keys are trusted exactly as given, and the most \
             sensitive (restricted) records are dropped rather than indexed unsafely"
                .to_string(),
            false,
            Some(REBAC_START_HINT),
        ));
    }

    // 2 · live access revocation (the SpiceDB Watch consumer). Config-only:
    // on/off is boot-time (VERITY_SPICEDB_WATCH), reported, never a button.
    let w = state.watch.snapshot();
    let enabled = w["enabled"].as_bool().unwrap_or(false);
    let connected = w["connected"].as_bool().unwrap_or(false);
    let degraded = w["degraded"].as_bool().unwrap_or(false);
    // A watch that is open but has never received a frame reports connected=false
    // BY DESIGN: SpiceDB sends nothing (not even headers) until the first access
    // change, so a quiet system pends here — healthy, not failing. Only real
    // churn (a prior reconnect or a recorded error) is genuinely reconnecting.
    let churning = w["reconnects"].as_u64().unwrap_or(0) > 0 || !w["last_error"].is_null();
    let (rev_status, rev_detail) = if !enabled {
        (
            "off",
            "off — when someone loses access it takes effect the next time a reader \
             mints a pass, not instantly (the live watch accelerates this)"
                .to_string(),
        )
    } else if degraded {
        (
            "degraded",
            "degraded — the live watch hit a gap; access removals still take effect, \
             just on the periodic baseline rather than the very next read"
                .to_string(),
        )
    } else if connected {
        (
            "on",
            "on — when someone loses access it takes effect on their next read".to_string(),
        )
    } else if churning {
        (
            "degraded",
            "reconnecting — the live watch dropped and is retrying; access removals still \
             apply on the periodic baseline until it's back"
                .to_string(),
        )
    } else {
        // Open, ready, nothing to stream yet on a quiet system — the healthy
        // idle state, not degraded.
        (
            "on",
            "on — connected and waiting; there's been no access change to stream yet, and a \
             live removal is applied on the reader's next read the instant one happens"
                .to_string(),
        )
    };
    planes.push(plane_row(
        "revocation_watch",
        "Live access revocation",
        "config-only",
        rev_status,
        rev_detail,
        false,
        None,
    ));

    // 3 · media / object store. Command-only: a Docker container, so when off
    // the panel offers the copyable `docker compose up` command, not a button.
    if state.media_store.is_some() {
        planes.push(plane_row(
            "media_store",
            "File & media storage",
            "command-only",
            "on",
            "on — uploaded files and media are kept in the object store".to_string(),
            false,
            None,
        ));
    } else {
        planes.push(plane_row(
            "media_store",
            "File & media storage",
            "command-only",
            "off",
            "off — files and media fall back to the database (fine for dev, not for \
             large files at scale)"
                .to_string(),
            false,
            Some(MEDIA_START_HINT),
        ));
    }

    // 4 · local query encoder — meaning-based recall when on. Config-only: the
    // model either loaded at boot or it didn't; off is `degraded` (server up).
    if state.encoder.is_some() {
        planes.push(plane_row(
            "encoder",
            "Meaning-based search",
            "config-only",
            "on",
            format!(
                "on — searches match on meaning, not just exact keywords (model {})",
                verity_encoder::MODEL_ID
            ),
            false,
            None,
        ));
    } else {
        planes.push(plane_row(
            "encoder",
            "Meaning-based search",
            "config-only",
            "off",
            "off — keyword-only search (the meaning model didn't load, so dense recall \
             is unavailable)"
                .to_string(),
            false,
            None,
        ));
    }

    // 5 · auto-resolve (entity resolution debounce). Config-only.
    if let Some(d) = state.resolution.debounce() {
        planes.push(plane_row(
            "auto_resolve",
            "Auto-merge of duplicate entities",
            "config-only",
            "on",
            format!(
                "on — records about the same thing are merged automatically about {} \
                 after they arrive",
                humanize_secs(d.as_secs())
            ),
            false,
            None,
        ));
    } else {
        planes.push(plane_row(
            "auto_resolve",
            "Auto-merge of duplicate entities",
            "config-only",
            "off",
            "off — duplicate records are merged only when someone runs resolution by hand"
                .to_string(),
            false,
            None,
        ));
    }

    // 6 · knowledge consolidation worker (L2) — the ONE startable plane, in two
    // strict tiers (§2). Tier 1 AUTHORITATIVE: this server owns a live child.
    // Tier 2 OBSERVED: no owned child → fall back to the episode_processing
    // activity proxy, tenant-scoped for start/stop symmetry.
    planes.push(knowledge_plane_row(&state, q.tenant_id).await);

    // 7 · directory-sync worker (Identity Plane §6a) — same two-tier treatment:
    // authoritative when this server owns a live child, else the connector-status
    // heartbeat proxy. The reconcile interval is the group-membership ACL SLO.
    planes.push(directory_plane_row(&state, q.tenant_id).await);

    // 8 · continuous-sync SCHEDULER (Phase 4) — the per-(tenant, source) interval
    // loops firing `--once` poll cycles. Server-authoritative from the in-memory
    // armed-loop count (a loop is armed iff this process owns it); the durable
    // enabled-flag lives in sync_schedules. `config-only`: there is no single
    // global Start — a schedule is toggled per source via
    // POST /v1/admin/connectors/{source}/sync, so no dead button and start_hint
    // is null. "on" iff at least one loop is armed.
    let armed = state.sync.armed_count().await;
    let sync_detail = if armed > 0 {
        format!(
            "{armed} continuous-sync schedule(s) armed — each fires a short-lived --once poll \
             cycle on its interval (toggle per source at POST /v1/admin/connectors/{{source}}/sync)"
        )
    } else {
        "no continuous-sync schedules armed — enable one per source at \
         POST /v1/admin/connectors/{source}/sync (gdrive/gmail/hubspot)"
            .to_string()
    };
    let mut sync_row = plane_row(
        "sync_scheduler",
        "Continuous sync (connector poll schedules)",
        "config-only",
        if armed > 0 { "on" } else { "off" },
        sync_detail,
        false,
        None,
    );
    sync_row
        .as_object_mut()
        .expect("plane_row is an object")
        .insert("armed_loops".into(), serde_json::json!(armed));
    planes.push(sync_row);

    let up = planes.iter().filter(|p| p["status"] == "on").count();
    Ok(Json(serde_json::json!({
        "planes": planes,
        "summary": { "up": up, "total": planes.len() },
        "checked_at": Utc::now().to_rfc3339(),
    })))
}

/// The `knowledge_worker` row: authoritative when this server owns a live
/// child, else the tenant-scoped observed activity proxy. A dead owned child is
/// reaped and the handle cleared before falling through — never a stale
/// "running, pid N".
/// The exact missing-prereq fix for a not-startable knowledge worker (repo /
/// venv / key, in that resolution order). `None` when all prereqs are present.
fn start_hint_for(repo: Option<&std::path::Path>, venv: bool, key: bool) -> Option<String> {
    let Some(repo) = repo else {
        return Some(
            "start the server with --repo <path> (or VERITY_REPO) so it can find ingest/.venv"
                .to_string(),
        );
    };
    if !venv {
        Some(format!(
            "no ingest virtualenv at {}/ingest/.venv/bin/python — create it (cd ingest && \
             python -m venv .venv && .venv/bin/pip install -e '.[gdrive]') then try again",
            repo.display()
        ))
    } else if !key {
        Some(
            "knowledge extraction needs an Anthropic key at ~/.verity-anthropic-key (0600) — \
             add it, then try again"
                .to_string(),
        )
    } else {
        None
    }
}

async fn knowledge_plane_row(state: &AppState, tenant_id: uuid::Uuid) -> serde_json::Value {
    const LABEL: &str = "Knowledge extraction worker";

    // Tier 1 — AUTHORITATIVE (server-owned). Hold the lock only long enough to
    // probe liveness / reap a dead child.
    {
        let mut guard = state.knowledge_worker.lock().await;
        if let Some(worker) = guard.as_mut() {
            match worker.child.try_wait() {
                Ok(None) => {
                    // Alive: the one authoritative "on" with pid + a real Stop.
                    let pid = worker.pid;
                    let started_at = worker.started_at;
                    let worker_tenant = worker.tenant_id;
                    let detail = format!(
                        "running · pid {pid} · started from this console {} — anthropic \
                         extractor + judge, leasing every 30s into the review queue. \
                         Auto-publish stays off.",
                        humanize_ago(started_at)
                    );
                    let mut row = plane_row(
                        "knowledge_worker",
                        LABEL,
                        "startable",
                        "on",
                        detail,
                        false,
                        None,
                    );
                    let obj = row.as_object_mut().expect("plane_row is an object");
                    obj.insert("authority".into(), serde_json::json!("server"));
                    obj.insert("stoppable".into(), serde_json::json!(true));
                    obj.insert("pid".into(), serde_json::json!(pid));
                    obj.insert(
                        "started_at".into(),
                        serde_json::json!(started_at.to_rfc3339()),
                    );
                    // The space this owned child leases against (it serves one
                    // tenant, fixed at spawn). Surfaced so the panel can note
                    // if the live worker belongs to a different tenant.
                    obj.insert(
                        "worker_tenant_id".into(),
                        serde_json::json!(worker_tenant.to_string()),
                    );
                    return row;
                }
                _ => {
                    // Child died (Some(exit)) OR the wait errored: reap (already
                    // waited) and clear the handle, then fall through to Tier 2.
                    *guard = None;
                }
            }
        }
    }

    // Tier 2 — OBSERVED PROXY. Same activity query as before, tenant-scoped.
    let last: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(GREATEST(leased_until - make_interval(mins => 5), \
                             COALESCE(processed_at, 'epoch'::timestamptz))) \
         FROM episode_processing WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(state.pool())
    .await
    .ok()
    .flatten();
    // Startability depends ONLY on the prereqs + not owning a live child (this
    // branch is reached only when the server owns none), NEVER on observed
    // activity — otherwise stopping a worker leaves recent activity that would
    // wrongly disable Start and dead-end the row (caught live 2026-07-13).
    let repo = state.repo_root.as_deref();
    let venv = knowledge_worker::venv_exists(repo);
    let key = knowledge_worker::key_exists();
    let startable = repo.is_some() && venv && key;

    let recent = last.is_some_and(|t| Utc::now() - t < chrono::Duration::minutes(2));
    if recent {
        let t = last.expect("recent implies Some");
        // Recent DB activity does NOT prove a worker is running now — it may
        // have just finished or been stopped. Honest status is "unknown", not a
        // false "on"; Start stays offered so a stopped worker isn't a dead-end.
        let detail = format!(
            "recently active — consolidation ran {}, but this console doesn't own a running \
             worker (it may have just finished, or be running elsewhere). Start one here to \
             own and stop it.",
            humanize_ago(t)
        );
        let hint = start_hint_for(repo, venv, key);
        let mut row = plane_row(
            "knowledge_worker",
            LABEL,
            "startable",
            "unknown",
            detail,
            startable,
            hint.as_deref(),
        );
        let obj = row.as_object_mut().expect("plane_row is an object");
        obj.insert("authority".into(), serde_json::json!("observed"));
        obj.insert("stoppable".into(), serde_json::json!(false));
        return row;
    }
    // `humanize_ago` already yields "…ago", so phrase around it (not "in the
    // last 2h ago"); a never-run worker reads "has never run".
    let recency = match last {
        Some(t) => format!("last ran {}", humanize_ago(t)),
        None => "has never run".to_string(),
    };
    let detail = format!("off — {recency}. New memories pile up unread until it runs.");
    // When not startable, start_hint carries the exact missing-prereq fix.
    let hint = start_hint_for(repo, venv, key);
    let mut row = plane_row(
        "knowledge_worker",
        LABEL,
        "startable",
        "off",
        detail,
        startable,
        hint.as_deref(),
    );
    let obj = row.as_object_mut().expect("plane_row is an object");
    obj.insert("authority".into(), serde_json::json!("observed"));
    obj.insert("stoppable".into(), serde_json::json!(false));
    row
}

/// The base-url the spawned worker should call back on, derived from `--listen`.
pub(crate) fn worker_base_url(listen: &str) -> String {
    format!("http://{listen}")
}

/// The exact missing-prereq fix for a not-startable directory worker (repo /
/// venv / config, in that resolution order). `None` when all prereqs exist.
fn directory_start_hint(
    repo: Option<&std::path::Path>,
    venv: bool,
    config: bool,
) -> Option<String> {
    let Some(repo) = repo else {
        return Some(
            "start the server with --repo <path> (or VERITY_REPO) so it can find ingest/.venv"
                .to_string(),
        );
    };
    if !venv {
        Some(format!(
            "no ingest virtualenv at {}/ingest/.venv/bin/python — create it (cd ingest && \
             python -m venv .venv && .venv/bin/pip install -e '.[gdrive]') then try again",
            repo.display()
        ))
    } else if !config {
        Some(
            "directory sync needs a service-account key (GOOGLE_APPLICATION_CREDENTIALS) and a \
             DWD subject (VERITY_GDIRECTORY_SUBJECT) — set both on the server, then try again"
                .to_string(),
        )
    } else {
        None
    }
}

/// The `directory_worker` row: authoritative when this server owns a live child,
/// else the tenant-scoped `connector_status` heartbeat proxy. A dead owned child
/// is reaped and the handle cleared before falling through — never a stale
/// "running, pid N".
async fn directory_plane_row(state: &AppState, tenant_id: uuid::Uuid) -> serde_json::Value {
    const LABEL: &str = "Directory sync worker";

    // Tier 1 — AUTHORITATIVE (server-owned). Shared probe/reap discipline
    // (`owned_live`) with the connectors read, so the two can never drift.
    if let Some(worker) = state.directory.owned_live().await {
        let detail = format!(
            "running · pid {} · started from this console {} — reconciling Google \
             users + groups (nested membership) into SpiceDB every {}s; that interval \
             is the ACL-freshness bound.",
            worker.pid,
            humanize_ago(worker.started_at),
            state.directory.interval_secs,
        );
        let mut row = plane_row(
            "directory_worker",
            LABEL,
            "startable",
            "on",
            detail,
            false,
            None,
        );
        let obj = row.as_object_mut().expect("plane_row is an object");
        obj.insert("authority".into(), serde_json::json!("server"));
        obj.insert("stoppable".into(), serde_json::json!(true));
        obj.insert("pid".into(), serde_json::json!(worker.pid));
        obj.insert(
            "started_at".into(),
            serde_json::json!(worker.started_at.to_rfc3339()),
        );
        obj.insert(
            "worker_tenant_id".into(),
            serde_json::json!(worker.tenant_id.to_string()),
        );
        return row;
    }

    // Tier 2 — OBSERVED PROXY: the gdirectory connector-status heartbeat.
    let last: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT updated_at FROM connector_status WHERE tenant_id = $1 AND source = 'gdirectory'",
    )
    .bind(tenant_id)
    .fetch_optional(state.pool())
    .await
    .ok()
    .flatten();

    // Startability depends ONLY on prereqs + not owning a live child, never on
    // observed activity (so a stopped worker isn't a dead-end).
    let repo = state.repo_root.as_deref();
    let venv = directory_worker::venv_exists(repo);
    let config = state.directory.config_ready();
    let startable = repo.is_some() && venv && config;
    let hint = directory_start_hint(repo, venv, config);

    let recent = last.is_some_and(|t| Utc::now() - t < chrono::Duration::minutes(2));
    let (status, detail) = if recent {
        let t = last.expect("recent implies Some");
        (
            "unknown",
            format!(
                "recently reconciled {}, but this console doesn't own a running worker (it may \
                 have just finished, or be running elsewhere). Start one here to own and stop it.",
                humanize_ago(t)
            ),
        )
    } else {
        let recency = match last {
            Some(t) => format!("last reconciled {}", humanize_ago(t)),
            None => "has never run".to_string(),
        };
        (
            "off",
            format!("off — {recency}. Group-membership ACLs go stale until it runs."),
        )
    };
    let mut row = plane_row(
        "directory_worker",
        LABEL,
        "startable",
        status,
        detail,
        startable,
        hint.as_deref(),
    );
    let obj = row.as_object_mut().expect("plane_row is an object");
    obj.insert("authority".into(), serde_json::json!("observed"));
    obj.insert("stoppable".into(), serde_json::json!(false));
    row
}

/// POST /v1/admin/planes/knowledge/start {tenant_id} (admin): spawn + track the
/// consolidation worker for this tenant. Idempotent (an already-owned live
/// child → 200 no-op). Missing repo/venv → 422, missing key / OS spawn failure
/// → 503 — each with the exact fix in `error`, NEVER a 500. The Anthropic key
/// is read from `~/.verity-anthropic-key` at spawn time, never embedded,
/// logged, or returned.
async fn admin_planes_knowledge_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<KnowledgeWorkerBody>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut guard = state.knowledge_worker.lock().await;

    // ONE owner per server: if we already hold a LIVE child (any tenant), it's
    // an idempotent no-op. A dead child is reaped and we proceed to respawn.
    if let Some(worker) = guard.as_mut() {
        match worker.child.try_wait() {
            Ok(None) => {
                return Ok(Json(serde_json::json!({
                    "started": false,
                    "pid": worker.pid,
                    "already_running": true,
                })));
            }
            _ => {
                *guard = None;
            }
        }
    }

    let base_url = worker_base_url(&state.listen);
    let admin_token = state.admin_token.as_deref();
    match knowledge_worker::spawn(
        state.repo_root.as_deref(),
        &base_url,
        body.tenant_id,
        admin_token,
    ) {
        Ok(worker) => {
            let pid = worker.pid;
            *guard = Some(worker);
            Ok(Json(serde_json::json!({ "started": true, "pid": pid })))
        }
        Err(knowledge_worker::SpawnError::NoRepo) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "the server doesn't know its repo path — start it with --repo <path> or VERITY_REPO \
             so it can find ingest/.venv"
                .to_string(),
        )),
        Err(knowledge_worker::SpawnError::NoVenv(msg)) => {
            Err((StatusCode::UNPROCESSABLE_ENTITY, msg))
        }
        Err(knowledge_worker::SpawnError::NoKey(msg)) => {
            Err((StatusCode::SERVICE_UNAVAILABLE, msg))
        }
        Err(knowledge_worker::SpawnError::Os(msg)) => Err((StatusCode::SERVICE_UNAVAILABLE, msg)),
    }
}

/// POST /v1/admin/planes/knowledge/stop {tenant_id} (admin): kill + reap the
/// tracked child and clear the handle. Honest no-op when this console owns no
/// worker (it may be running, started elsewhere — stop it there).
async fn admin_planes_knowledge_stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(_body): Json<KnowledgeWorkerBody>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut guard = state.knowledge_worker.lock().await;
    match guard.take() {
        Some(mut worker) => {
            let pid = worker.pid;
            // Kill then wait to reap — no zombie. Ignore a kill error on an
            // already-exited child; the wait still reaps it.
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            Ok(Json(serde_json::json!({ "stopped": true, "pid": pid })))
        }
        None => Ok(Json(serde_json::json!({
            "stopped": false,
            "note": "nothing to stop — this console doesn't own a worker. If one is running it \
                     was started outside this console (e.g. verity-cli dev --knowledge); stop it \
                     there.",
        }))),
    }
}

/// POST /v1/admin/planes/directory/start {tenant_id} (admin): spawn + track the
/// directory-sync worker for this tenant. Idempotent (an already-owned live
/// child → 200 no-op). Missing repo/venv → 422; missing SA key / subject / OS
/// spawn failure → 503 — each with the exact fix, NEVER a 500. The SA key path
/// is passed to the child; the server never reads the key contents.
async fn admin_planes_directory_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<KnowledgeWorkerBody>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut guard = state.directory.worker.lock().await;

    // ONE owner per server: a LIVE child (any tenant) → idempotent no-op; a dead
    // child is reaped and we respawn.
    if let Some(worker) = guard.as_mut() {
        match worker.child.try_wait() {
            Ok(None) => {
                return Ok(Json(serde_json::json!({
                    "started": false,
                    "pid": worker.pid,
                    "already_running": true,
                })));
            }
            _ => {
                *guard = None;
            }
        }
    }

    let base_url = worker_base_url(&state.listen);
    match directory_worker::spawn(
        state.repo_root.as_deref(),
        &base_url,
        body.tenant_id,
        state.admin_token.as_deref(),
        state.directory.sa_key.as_deref(),
        state.directory.subject.as_deref(),
        state.directory.domain.as_deref(),
        state.directory.interval_secs,
    ) {
        Ok(worker) => {
            let pid = worker.pid;
            *guard = Some(worker);
            Ok(Json(serde_json::json!({ "started": true, "pid": pid })))
        }
        Err(directory_worker::SpawnError::NoRepo) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "the server doesn't know its repo path — start it with --repo <path> or VERITY_REPO \
             so it can find ingest/.venv"
                .to_string(),
        )),
        Err(directory_worker::SpawnError::NoVenv(msg)) => {
            Err((StatusCode::UNPROCESSABLE_ENTITY, msg))
        }
        Err(directory_worker::SpawnError::NoConfig(msg)) => {
            Err((StatusCode::SERVICE_UNAVAILABLE, msg))
        }
        Err(directory_worker::SpawnError::Os(msg)) => Err((StatusCode::SERVICE_UNAVAILABLE, msg)),
    }
}

/// POST /v1/admin/planes/directory/stop {tenant_id} (admin): kill + reap the
/// tracked child. Honest no-op when this console owns no directory worker.
async fn admin_planes_directory_stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(_body): Json<KnowledgeWorkerBody>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut guard = state.directory.worker.lock().await;
    match guard.take() {
        Some(mut worker) => {
            let pid = worker.pid;
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            Ok(Json(serde_json::json!({ "stopped": true, "pid": pid })))
        }
        None => Ok(Json(serde_json::json!({
            "stopped": false,
            "note": "nothing to stop — this console doesn't own a directory worker. If one is \
                     running it was started outside this console (e.g. verity-cli dev --directory); \
                     stop it there.",
        }))),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // FTUE §2.3: when RUST_LOG is unset, default to `info` — a bare `./verity`
    // must never look like a hung terminal.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    // Bind-time gate (Phase-2 §TRANSPORT, D1): a non-loopback bind exposes the
    // whole surface, so it REFUSES TO START unless both VERITY_ADMIN_TOKEN and
    // VERITY_KEK are set. Loopback (the default 127.0.0.1:7717) is unaffected.
    // Fail-closed on a --listen that is not a literal host:port SocketAddr
    // (e.g. `localhost:7717`): treat it as non-loopback and require the secrets
    // rather than binding it unguarded. Reuses the anyhow::bail! "refusing to
    // start" idiom (crypto.rs / VERITY_SPICEDB_WATCH gate).
    {
        let admin_set = std::env::var("VERITY_ADMIN_TOKEN")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let kek_set = std::env::var("VERITY_KEK")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        match cli.listen.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                if let Err(msg) = bind_gate_decision(addr, admin_set, kek_set) {
                    anyhow::bail!("{msg}");
                }
            }
            Err(_) => {
                // Unparseable as a literal SocketAddr (hostname form). Fail
                // closed: require the secrets unless we can prove loopback.
                if !(admin_set && kek_set) {
                    anyhow::bail!(
                        "refusing to bind {:?}: not a literal loopback host:port and VERITY_ADMIN_TOKEN + VERITY_KEK are not both set (use 127.0.0.1:<port> for an unguarded dev bind)",
                        cli.listen
                    );
                }
            }
        }
    }

    // M0 instrument panel: build the shared metric block first so the storage
    // adapter and the revocation plane can be wired to its hot-path counters
    // before they are moved into AppState.
    let app_metrics = Arc::new(metrics::Metrics::new());
    let mut pg = PostgresAdapter::connect(&cli.dsn).await?;
    pg.set_exact_scan_counter(app_metrics.exact_scan_counter());
    let applied = pg.migrate().await?;
    if applied > 0 {
        println!("applied {applied} migrations");
    }
    let encoder = match tokio::task::spawn_blocking(verity_encoder::QueryEncoder::load).await? {
        Ok(enc) => Some(Arc::new(enc)),
        Err(e) => {
            tracing::warn!("query encoder unavailable, recall is sparse-only: {e:#}");
            None
        }
    };
    // ReBAC plane (task 10): configured => schema must be writable at startup
    // (a deployment that configured authz never runs without it); absent =>
    // dev mode with caller-supplied principals, warned.
    let rebac = Rebac::from_env();
    match &rebac {
        Some(r) => r
            .ensure_schema()
            .await
            .map_err(|e| anyhow::anyhow!("spicedb configured but unusable: {e}"))?,
        None => tracing::warn!(
            "ReBAC disabled (set VERITY_SPICEDB_URL to enable) — scope principals are caller-supplied; restricted-class hits will be dropped"
        ),
    }
    // L1 current-truth cache: the `get` hot path (SPEC §4b). 1M entries ≈ a
    // few hundred MB ceiling; invalidated on upsert, so never serves stale.
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 1_000_000),
        encoder,
        minter: ScopeMinter::from_env(),
        purposes: PurposePack::from_env()?,
        admin: AdminAuth::from_env(),
        rebac,
        revocations: {
            let mut r = RevocationPlane::from_env();
            r.set_subtraction_counter(app_metrics.revocation_subtractions_arc());
            r
        },
        allow_restricted_without_rebac: std::env::var("VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC")
            .is_ok_and(|v| v == "1"),
        subscribers: subscribe::Subscribers::from_env(),
        // Media blobs to object storage when configured; else the bytea path.
        // A configured-but-unbuildable store is a hard startup failure (a
        // deployment that pointed at S3 must not silently fall back to bytea).
        media_store: media::MediaStore::from_env()?,
        auto_tag: std::env::var("VERITY_AUTO_TAG").is_ok_and(|v| v == "1"),
        // Default ON: absent or anything but "0" leaves judged merges enabled.
        knowledge_auto_merge: std::env::var("VERITY_KNOWLEDGE_AUTO_MERGE")
            .map(|v| v != "0")
            .unwrap_or(true),
        // Reads VERITY_RESOLVE_DEBOUNCE (same env var as the Python hook,
        // default 900s, 0 disables). See scheduler.rs.
        resolution: scheduler::ResolutionScheduler::from_env(),
        watch: Arc::new(rebac_watch::WatchStatus::new()),
        folder_watchers: Arc::new(folder_watch::WatcherRegistry::new()),
        folder_scans: Arc::new(folder_watch::FolderScanPlane::new()),
        knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
        repo_root: cli.repo_root(),
        listen: cli.listen.clone(),
        admin_token: std::env::var("VERITY_ADMIN_TOKEN")
            .ok()
            .filter(|t| !t.is_empty()),
        directory: directory_worker::DirectoryPlane::from_env(),
        connectors: Arc::new(connector_worker::ConnectorPlane::from_env()),
        sync: Arc::new(sync_scheduler::SyncPlane::new()),
        metrics: app_metrics,
    });

    let app = Router::new()
        // M0 deliverable #4: real /healthz probes Postgres (+ SpiceDB when
        // configured) with a bounded timeout; stays UNAUTHENTICATED (load
        // balancers hit it). /metrics renders aggregate Prometheus text.
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics::metrics_handler))
        // Read-only scope-inspector UI (SPEC §11d) — embedded, zero-build.
        .route("/ui", get(ui::ui_page))
        .route("/v1/scopes", post(open_scope))
        .route("/v1/recall", post(recall))
        // Playground (docs/design/PLAYGROUND.md): the LLM sits ABOVE the read
        // path, calling recall/get as tools — recall/get themselves stay
        // LLM-free (read-path purity holds; see playground.rs module docs).
        .route("/v1/playground/status", get(playground::status))
        .route("/v1/playground/ask", post(playground::ask))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
        .route("/v1/entities/{canonical}", get(get_merged_entity))
        .route("/v1/admin/entities", get(admin_list_entities))
        .route("/v1/admin/entity-tags", get(admin_entity_tags))
        .route("/v1/admin/memories", get(admin_memories))
        .route("/v1/admin/entity-aliases", post(admin_entity_aliases))
        .route("/v1/admin/entity-precedence", post(admin_entity_precedence))
        .route("/v1/admin/entity-evidence", post(admin_evidence_insert))
        .route(
            "/v1/admin/entity-evidence/retract",
            post(admin_evidence_retract),
        )
        .route(
            "/v1/admin/entity-resolution-config",
            get(admin_resolution_config_get).put(admin_resolution_config_put),
        )
        .route(
            "/v1/admin/entity-resolution/decide",
            post(admin_entity_decide),
        )
        .route("/v1/admin/entity-resolution/fold", post(admin_trigger_fold))
        .route(
            "/v1/admin/entity-resolution/run",
            post(admin_run_resolution),
        )
        .route(
            "/v1/admin/entity-resolution/review-queue",
            get(admin_review_queue),
        )
        .route("/v1/episodes", post(remember))
        .route("/v1/actions", post(record_action))
        .route("/v1/activity", get(activity))
        .route("/v1/subscribe", get(subscribe::subscribe))
        .route("/v1/slo/freshness", get(slo::freshness))
        .route("/v1/forget", post(forget))
        .route("/v1/ingest/debezium", post(ingest_debezium))
        .route("/v1/ingest/documents", post(ingest_documents))
        .route("/v1/briefs/{entity}", get(brief))
        .route("/v1/admin/briefs/refresh", post(admin_refresh_briefs))
        .route("/v1/admin/reembed/batch", post(admin_reembed_batch))
        .route("/v1/admin/reembed/cutover", post(admin_reembed_cutover))
        .route("/v1/admin/tenants", post(create_tenant).get(list_tenants))
        .route("/v1/admin/tenants/{tenant_id}", get(get_tenant))
        .route(
            "/v1/admin/erasure/preview",
            post(compliance::admin_erasure_preview),
        )
        .route("/v1/admin/erasure", post(compliance::admin_erasure))
        .route("/v1/admin/dsar/export", get(compliance::dsar_export))
        .route("/v1/admin/audit", get(audit::admin_audit))
        .route("/v1/admin/quarantine", get(webhooks::admin_quarantine))
        .route(
            "/v1/admin/quarantine/{id}/reingest",
            post(admin_quarantine_reingest),
        )
        .route(
            "/v1/admin/quarantine/{id}/dismiss",
            post(admin_quarantine_dismiss),
        )
        .route("/v1/admin/debug/recall", post(admin_debug_recall))
        .route("/v1/admin/media", get(media::admin_list_media))
        .route(
            "/v1/admin/connector-status",
            post(connectors::post_status).get(connectors::get_status),
        )
        // Connect-a-source Phase 1 read plane (connectors_admin.rs): one
        // honest row per source family from what the server can truthfully
        // observe. Read-only — no secrets, no backfill trigger.
        .route(
            "/v1/admin/connectors",
            get(connectors_admin::list_connectors),
        )
        .route(
            "/v1/admin/connectors/{source}/prereqs",
            get(connectors_admin::source_prereqs),
        )
        // Connect-a-source Phase 2 secret-intake plane (connectors_admin.rs):
        // store / test / revoke a per-source credential. All three are gated by
        // `SecretIntakeAuth` (Origin/CSRF + bearer with NO dev-open branch), so
        // an unset VERITY_ADMIN_TOKEN hard-refuses (401) here even though the
        // Phase-1 GETs above are dev-open. The token is never logged, never
        // echoed — a successful store returns only { fingerprint, kind }.
        .route(
            "/v1/admin/connectors/{source}/credential",
            post(connectors_admin::store_credential).delete(connectors_admin::revoke_credential),
        )
        .route(
            "/v1/admin/connectors/{source}/credential/test",
            post(connectors_admin::test_credential),
        )
        // Connect-a-source Phase 3 backfill trigger (connectors_admin.rs): a
        // one-shot full-crawl for gdrive/gmail. admin.check-gated (NOT
        // SecretIntakeAuth — no secret in the request; the SA-key path + subject
        // are resolved server-side from the store or env). Every non-backfillable
        // source → 422 with the honest phase/applicability note.
        .route(
            "/v1/admin/connectors/{source}/backfill",
            post(connectors_admin::backfill_source),
        )
        // Connect-a-source Phase 4 continuous-sync toggle (connectors_admin.rs):
        // arm/disarm a per-(tenant, source) SCHEDULER that fires a short-lived
        // `--once` incremental poll cycle on an interval. admin.check-gated. The
        // schedule is durable (sync_schedules, migration 0033) + re-armed on boot.
        // gdirectory maps to the directory plane (422 pointing there); folder /
        // salesforce have no schedule (422).
        .route(
            "/v1/admin/connectors/{source}/sync",
            post(connectors_admin::sync_source),
        )
        .route(
            "/v1/admin/folders",
            post(folder_watch::add_folder_watch).get(folder_watch::list_folder_watches),
        )
        .route(
            "/v1/admin/folders/preview",
            axum::routing::get(folder_watch::preview_folder),
        )
        .route(
            "/v1/admin/folders/browse",
            axum::routing::get(folder_watch::browse_folder),
        )
        .route(
            "/v1/admin/folders/scan/stop",
            post(folder_watch::stop_folder_scan),
        )
        .route(
            "/v1/admin/folders/{id}",
            axum::routing::delete(folder_watch::stop_folder_watch),
        )
        .route(
            "/v1/admin/backfill",
            post(backfill::post_progress).get(backfill::get_runs),
        )
        .route("/v1/admin/consolidation/lease", post(consolidation::lease))
        .route(
            "/v1/admin/consolidation/complete",
            post(consolidation::complete),
        )
        .route(
            "/v1/admin/consolidation/merge-candidates",
            post(consolidation::merge_candidates),
        )
        .route(
            "/v1/admin/tag-suggestions",
            get(consolidation::list_tag_suggestions),
        )
        .route(
            "/v1/admin/tag-suggestions/{id}/approve",
            post(consolidation::approve_tag_suggestion),
        )
        .route(
            "/v1/admin/principals",
            post(admin_principals).get(admin_list_principals),
        )
        .route("/v1/admin/rebac-watch", get(rebac_watch::admin_status))
        // "What's running" — observed infrastructure-plane status for the
        // console System panel (admin-gated like every other /v1/admin read).
        .route("/v1/admin/planes", get(admin_planes))
        // The one real Start/Stop: spawn/kill the knowledge worker the server
        // owns (SPEC §2 L2). Idempotent start, honest-no-op stop; admin-gated.
        .route(
            "/v1/admin/planes/knowledge/start",
            post(admin_planes_knowledge_start),
        )
        .route(
            "/v1/admin/planes/knowledge/stop",
            post(admin_planes_knowledge_stop),
        )
        // The directory-sync worker's Start/Stop (Identity Plane §6a) — same
        // server-owned, single-owner, idempotent-start / honest-no-op-stop shape.
        .route(
            "/v1/admin/planes/directory/start",
            post(admin_planes_directory_start),
        )
        .route(
            "/v1/admin/planes/directory/stop",
            post(admin_planes_directory_stop),
        )
        .route(
            "/v1/admin/groups",
            post(admin_group_add).delete(admin_group_remove),
        )
        .route("/v1/admin/groups/members", get(admin_group_members))
        .route("/v1/admin/access/subject", get(admin_access_subject))
        .route("/v1/admin/access/object", get(admin_access_object))
        .route("/v1/knowledge", post(propose_learning).get(list_knowledge))
        .route("/v1/knowledge/{id}/publish", post(publish_knowledge))
        .route("/v1/admin/knowledge/{id}", get(admin_knowledge_detail))
        .route(
            "/v1/admin/knowledge/{id}/reject",
            post(admin_reject_knowledge),
        )
        .route(
            "/v1/manifests",
            post(manifests::upload_manifest).get(manifests::list_manifests),
        )
        .route("/v1/manifests/dry-run", post(manifests::dry_run_manifest))
        .route(
            "/v1/manifests/{id}/activate",
            post(manifests::activate_manifest),
        )
        .route("/v1/webhooks", post(webhooks::mint_webhook))
        .route("/v1/webhooks/{id}", delete(webhooks::revoke_webhook))
        .route("/wh/{token}", post(webhooks::webhook_post))
        .route("/v1/files", post(media::upload_file))
        .route("/v1/media/{id}", get(media::get_media))
        .route("/v1/media/{id}/sign", post(media::sign_media))
        // Media uploads need more than axum's 2MB default.
        .layer(DefaultBodyLimit::max(32 * 1024 * 1024))
        .with_state(Arc::clone(&state));

    // Server-side auto-resolve loop (scheduler.rs): resolve dirty tenants past
    // the debounce window. Skipped entirely when VERITY_RESOLVE_DEBOUNCE=0.
    if state.resolution.enabled() {
        let debounce = state.resolution.debounce().unwrap_or_default();
        tracing::info!(
            debounce_secs = debounce.as_secs(),
            "server-side auto-resolve loop enabled (covers direct ingest AND connector sinks; belt-and-suspenders with the Temporal hook, deduped by debounce + idempotent evidence)"
        );
        let sched_state = Arc::clone(&state);
        tokio::spawn(auto_resolve_loop(sched_state));
    } else {
        tracing::info!(
            "server-side auto-resolve DISABLED (VERITY_RESOLVE_DEBOUNCE=0) — resolution stays manual / Temporal-hook-only"
        );
    }

    // SpiceDB Watch-driven revocation materialization (rebac_watch.rs, SPEC
    // §7b). Opt-in: VERITY_SPICEDB_WATCH=1 AND ReBAC configured. The consumer
    // only ADDS tombstones — the windowed subtraction, mint-time resolution,
    // and restricted recheck keep enforcing regardless of watch health. A
    // configured watch whose stream can't be opened at startup is a hard
    // failure (same posture as ensure_schema — never silent).
    if std::env::var("VERITY_SPICEDB_WATCH").is_ok_and(|v| v == "1") {
        let Some(r) = &state.rebac else {
            anyhow::bail!("VERITY_SPICEDB_WATCH=1 requires VERITY_SPICEDB_URL");
        };
        r.watch_probe().await.map_err(|e| {
            anyhow::anyhow!("VERITY_SPICEDB_WATCH=1 but the SpiceDB watch stream is unusable: {e}")
        })?;
        state.watch.set_enabled(true);
        tracing::info!(
            "spicedb watch-driven revocation materialization enabled (accelerator over the windowed baseline; health at GET /v1/admin/rebac-watch)"
        );
        tokio::spawn(rebac_watch::run(Arc::clone(&state)));
    } else {
        tracing::info!(
            "spicedb watch disabled (set VERITY_SPICEDB_WATCH=1 with VERITY_SPICEDB_URL to accelerate out-of-band revocation propagation)"
        );
    }

    // Re-establish persisted local-folder watches (folder_watch.rs): re-scan
    // each active folder for files changed while the server was down, then
    // re-arm the live OS watch. Best-effort — a folder that has gone missing is
    // logged and skipped, never a boot failure.
    folder_watch::reestablish_on_boot(Arc::clone(&state)).await;

    // Re-arm every ENABLED continuous-sync schedule (sync_scheduler.rs): one
    // interval loop per (tenant, source) that fires a short-lived `--once` poll
    // cycle. Durable in `sync_schedules` (migration 0033); a disabled schedule is
    // left inert. Best-effort — an unreadable schedules table logs and skips,
    // never a boot failure.
    sync_scheduler::reestablish_on_boot(Arc::clone(&state)).await;

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    // FTUE §2.3: unconditional stdout on bind, independent of any log filter.
    println!(
        "verity v{} listening on http://{} — console: http://{}/ui",
        env!("CARGO_PKG_VERSION"),
        cli.listen,
        cli.listen
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// The background auto-resolve loop. Every tick, resolve each tenant that is
/// dirty AND past the debounce window (best-effort: log failures, but clear
/// dirty + stamp last-resolve REGARDLESS so a persistently-failing tenant can't
/// hot-loop). Mirrors the Temporal Python hook's semantics.
async fn auto_resolve_loop(state: Arc<AppState>) {
    // Tick faster than the debounce window; the window (not the tick) governs
    // how often a given tenant actually resolves.
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(20));
    loop {
        ticker.tick().await;
        let due = state.resolution.due_tenants(std::time::Instant::now());
        for tenant in due {
            match resolver::run_resolution(&state, tenant).await {
                Ok(report) => tracing::info!(
                    %tenant,
                    evidence_produced = report.evidence_produced,
                    aliases_written = report.materialize.aliases_written,
                    "auto-resolve ran"
                ),
                Err((status, msg)) => tracing::warn!(
                    %tenant, %status, %msg,
                    "auto-resolve failed (dirty cleared + last-resolve stamped anyway to avoid hot-loop)"
                ),
            }
            // Stamp regardless of outcome — see doc comment.
            state
                .resolution
                .stamp_resolved(tenant, std::time::Instant::now());
        }
    }
}

// ---------- open_scope ----------

#[derive(Deserialize)]
struct OpenScopeRequest {
    tenant_id: TenantId,
    // Dev-mode seam (scope.rs): caller-supplied principals, used when ReBAC
    // is disabled (or when no `subject` is given). After minting, scope is
    // immutable and every verb enforces from the signed payload only.
    #[serde(default)]
    principals: Vec<PrincipalToken>,
    /// Identity-resolved minting (task 10): `"user:alice@corp.example"`.
    /// Requires ReBAC (VERITY_SPICEDB_URL); the principal set is resolved
    /// server-side (the user plus its transitive SpiceDB group closure) and
    /// mutually exclusive with caller-supplied `principals`.
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    entity_scope: Vec<String>,
    #[serde(default = "default_confidentiality")]
    max_confidentiality: Confidentiality,
    #[serde(default)]
    actor_sub: Option<String>,
    #[serde(default)]
    actor_azp: Option<String>,
    #[serde(default = "default_ttl")]
    ttl_seconds: i64,
    /// Purpose binding (task 7): when present, the purpose pack CLAMPS the
    /// requested confidentiality and may require an entity-bound scope.
    /// Unknown purposes are rejected — fail closed, never fall through.
    #[serde(default)]
    purpose: Option<String>,
}

fn default_confidentiality() -> Confidentiality {
    Confidentiality::Internal
}

fn default_ttl() -> i64 {
    3600
}

async fn open_scope(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenScopeRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    // Ghost-tenant trap (FTUE §2.2): a handle minted for a tenant that was
    // never born yields a fully plausible, permanently empty session — fail-
    // closed for data must be fail-LOUD at the front door.
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(|e| match e {
            StorageError::UnknownTenant(_) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "error": "unknown tenant",
                    "hint": "create one: POST /v1/admin/tenants, or run verity-cli dev",
                })
                .to_string(),
            ),
            other => storage_status(other),
        })?;
    let mut max_confidentiality = req.max_confidentiality;
    if let Some(purpose) = &req.purpose {
        let rule = state.purposes.get(purpose).ok_or((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unknown purpose {purpose:?}"),
        ))?;
        // Clamp, never raise: the effective ceiling is the min of what the
        // caller asked for and what the purpose allows.
        max_confidentiality = max_confidentiality.min(rule.max_confidentiality);
        if rule.require_entity_scope && req.entity_scope.is_empty() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("purpose {purpose:?} requires a non-empty entity_scope"),
            ));
        }
    }
    // Identity plane (task 10): with ReBAC enabled, a `subject` is resolved
    // server-side into the user's principal token plus its transitive group
    // closure. Self-asserted principals are rejected alongside a subject —
    // identity being live means the caller no longer names its own powers.
    let (principals, subject) = match (&state.rebac, req.subject) {
        (Some(rebac), Some(subject)) => {
            if !req.principals.is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "supply either subject or principals, not both — principals are resolved server-side when identity is live".into(),
                ));
            }
            let Some((rebac::PrincipalKind::User, name)) = rebac::parse_principal(&subject) else {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "subject must be a user principal: \"user:<id>\"".into(),
                ));
            };
            // Fail closed: an unresolvable subject mints nothing.
            let groups = match rebac.user_groups(req.tenant_id, name).await {
                Ok(groups) => groups,
                // A membership CYCLE is infinite-depth for ReBAC, so SpiceDB
                // returns MAXIMUM_DEPTH_EXCEEDED. That's a directory DATA problem
                // for this one user — not a system outage — so don't lock them
                // out of their OWN direct access. Degrade fail-closed to just the
                // user's own principal (the unresolvable groups are DENIED, never
                // granted) and log loudly for an admin to fix the cycle. Any
                // OTHER rebac error (SpiceDB down/timeout) still 502s: a real
                // outage must fail loudly, not silently reduce everyone's access.
                Err(e) if e.is_max_depth() => {
                    tracing::warn!(
                        tenant = %req.tenant_id,
                        subject = %name,
                        "identity resolution hit a membership cycle (max depth) — degrading to \
                         the user's own principal; group access denied until the directory cycle \
                         is fixed"
                    );
                    Vec::new()
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        format!("identity resolution failed: {e}"),
                    ));
                }
            };
            let mut principal_strings = vec![subject.clone()];
            principal_strings.extend(groups);
            let tokens: Vec<PrincipalToken> =
                upsert_principal_tokens(state.pool(), req.tenant_id, &principal_strings)
                    .await?
                    .into_iter()
                    .map(|(_, t)| t)
                    .collect();
            // Resolution-time tombstone subtraction (SPEC §7b rule 3).
            let tokens = state
                .revocations
                .subtract(state.pool(), req.tenant_id, &tokens)
                .await?;
            (tokens, Some(subject))
        }
        (None, Some(_)) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "subject-based scopes require ReBAC (set VERITY_SPICEDB_URL); supply principals directly in dev mode".into(),
            ));
        }
        (_, None) => (req.principals, None),
    };
    let (handle, expires_at) = state.minter.mint(
        ScopePayload {
            tenant_id: req.tenant_id,
            principals,
            entity_scope: req.entity_scope,
            max_confidentiality,
            actor_sub: req.actor_sub,
            actor_azp: req.actor_azp,
            subject,
            expires_at: Utc::now(), // overwritten by mint
        },
        req.ttl_seconds,
    );
    Ok(Json(serde_json::json!({
        "scope_handle": handle,
        "expires_at": expires_at,
    })))
}

// ---------- health ----------

/// Bounded per-dependency probe timeout for `/healthz`. Small enough that a
/// hung dependency surfaces fast to a load balancer, large enough to ride out a
/// momentary GC/network blip.
const HEALTH_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Pure health-decision core (unit-testable without a DB/engine): given the
/// Postgres probe result and the SpiceDB probe result (`None` = ReBAC not
/// configured, so not probed), produce the `/healthz` status + JSON body. 200
/// only when every configured dependency is up; 503 naming the FIRST down
/// dependency (Postgres before SpiceDB). Named-dependency body is the operator
/// signal — no secrets, no tenant data.
fn health_decision(pg_ok: bool, spicedb_ok: Option<bool>) -> (StatusCode, serde_json::Value) {
    if !pg_ok {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"status": "unhealthy", "postgres": "down"}),
        );
    }
    if spicedb_ok == Some(false) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"status": "unhealthy", "spicedb": "down"}),
        );
    }
    (StatusCode::OK, serde_json::json!({"status": "ok"}))
}

/// GET /healthz (UNAUTHENTICATED, M0 deliverable #4). Probes Postgres
/// (`SELECT 1`) and SpiceDB (when configured) each under a bounded timeout,
/// then defers the verdict to [`health_decision`]. 200 `{"status":"ok"}` only
/// when every configured dependency answers; 503 with a small JSON body naming
/// the DOWN dependency otherwise. No secrets, no tenant data.
async fn healthz(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    // Postgres: a trivial round-trip proves the pool + server are live.
    let pg_ok = matches!(
        tokio::time::timeout(
            HEALTH_PROBE_TIMEOUT,
            sqlx::query("SELECT 1").fetch_one(state.pool()),
        )
        .await,
        Ok(Ok(_))
    );
    // SpiceDB: only probed when ReBAC is configured (dev mode has no engine).
    let spicedb_ok = match &state.rebac {
        None => None,
        Some(rebac) => Some(matches!(
            tokio::time::timeout(HEALTH_PROBE_TIMEOUT, rebac.health_ping()).await,
            Ok(Ok(()))
        )),
    };
    let (status, body) = health_decision(pg_ok, spicedb_ok);
    (status, Json(body))
}

#[cfg(test)]
mod health_tests {
    use super::{health_decision, StatusCode};

    #[test]
    fn healthy_pg_no_rebac_is_200() {
        let (status, body) = health_decision(true, None);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[test]
    fn healthy_pg_and_spicedb_is_200() {
        let (status, body) = health_decision(true, Some(true));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[test]
    fn pg_down_is_503_naming_postgres() {
        let (status, body) = health_decision(false, Some(true));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["postgres"], "down");
        // Postgres is checked first: a healthy SpiceDB is not the named dep.
        assert!(body.get("spicedb").is_none());
    }

    #[test]
    fn spicedb_down_is_503_naming_spicedb() {
        let (status, body) = health_decision(true, Some(false));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["spicedb"], "down");
        assert!(body.get("postgres").is_none());
    }

    #[test]
    fn pg_down_takes_precedence_over_spicedb_down() {
        let (status, body) = health_decision(false, Some(false));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["postgres"], "down");
    }
}

// ---------- recall ----------

#[derive(Deserialize)]
struct RecallRequest {
    scope_handle: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    embedding: Option<Vec<f32>>,
    #[serde(default = "default_k")]
    k: usize,
}

fn default_k() -> usize {
    8
}

async fn recall(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecallRequest>,
) -> HandlerResult<Json<Vec<RecallHit>>> {
    // M0 instrumentation: count every recall + observe end-to-end latency
    // (cheap Relaxed atomics; no allocation on the hot path).
    state.metrics.record_recall_request();
    let started = std::time::Instant::now();
    let payload = state.verify_scope(&req.scope_handle)?;
    // Text-only requests get the dense leg via the local encoder (hybrid
    // recall); callers may still send a precomputed embedding instead.
    let embedding = match (req.embedding, &req.text) {
        (Some(e), _) => Some(e),
        (None, Some(text)) => state.encode(text).await?,
        (None, None) => None,
    };
    let query = RecallQuery {
        scope: state.scope_for(&payload).await?,
        embedding,
        text: req.text,
        k: req.k.min(100),
    };
    let summary = query.text.clone();
    let hits = state.storage.recall(query).await.map_err(internal)?;
    // Restricted-class recheck (SPEC §7b rule 4, v0.1 approximation): live
    // re-resolution when ReBAC is on, fail-closed drop when it is off.
    let hits = revocation::enforce_restricted(&state, &payload, hits).await?;
    spawn_audit(
        &state,
        &payload,
        "recall",
        summary.as_deref(),
        hits.iter().map(|h| h.chunk_id).collect(),
    );
    state.metrics.observe_recall_latency(started.elapsed());
    Ok(Json(hits))
}

// ---------- get ----------

#[derive(Deserialize)]
struct RecordQuery {
    scope_handle: String,
    /// Bi-temporal read: the value as of this event time. Absent = current.
    as_of: Option<DateTime<Utc>>,
}

async fn get_record(
    State(state): State<Arc<AppState>>,
    Path((source, entity, field)): Path<(String, String, String)>,
    axum::extract::Query(q): axum::extract::Query<RecordQuery>,
) -> HandlerResult<Json<FactRow>> {
    let payload = state.verify_scope(&q.scope_handle)?;
    // Compile the enforcement scope (visibility + revocations) — previously this
    // handler read with the bare tenant, applying NEITHER, which was the L1
    // fact-visibility leak AND a revocation gap. scope_for closes both.
    let scope = state.scope_for(&payload).await?;
    let key = FactKey {
        source,
        entity_id: entity,
        field,
    };
    let result = match q.as_of {
        Some(as_of) => state.storage.fact_as_of(&scope, &key, as_of).await,
        None => state.storage.current_fact(&scope, &key).await,
    };
    match result {
        Ok(Some(fact)) => {
            spawn_audit(
                &state,
                &payload,
                "get",
                Some(&format!("{}/{}/{}", key.source, key.entity_id, key.field)),
                vec![fact.id],
            );
            Ok(Json(fact))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "no value for that key/time".into())),
        Err(e) => Err(internal(e)),
    }
}

// ---------- cross-source entity resolution & precedence (SPEC §7f, task 50)
// mapping/config is admin-gated; the merged read is scope-handle gated (a
// tenant-scoped L1 read, exactly like get_record) ----------

#[derive(Deserialize)]
struct EntityAliasesRequest {
    tenant_id: TenantId,
    /// The canonical entity key, e.g. "account:acme".
    canonical: String,
    /// The (source, entity_id) pairs that resolve to `canonical`.
    members: Vec<AliasMemberReq>,
}

#[derive(Deserialize)]
struct AliasMemberReq {
    source: String,
    entity_id: String,
}

/// POST /v1/admin/entity-aliases (admin): upsert the alias set for a canonical
/// entity (SPEC §7f resolution). Each member is repointed to `canonical`;
/// idempotent.
async fn admin_entity_aliases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EntityAliasesRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    for m in &req.members {
        state
            .storage
            .inner()
            .upsert_entity_alias(req.tenant_id, &m.source, &m.entity_id, &req.canonical)
            .await
            .map_err(internal)?;
    }
    Ok(Json(serde_json::json!({
        "canonical": req.canonical,
        "members": req.members.len(),
    })))
}

#[derive(Deserialize)]
struct ListEntitiesQuery {
    tenant_id: TenantId,
    #[serde(default = "default_entities_limit")]
    limit: i64,
}

fn default_entities_limit() -> i64 {
    100
}

/// GET /v1/admin/entities (admin): LIST the tenant's canonical entities for the
/// entities browser (§4.3 / §9 Group D). One row per DISTINCT `canonical_entity`
/// in `entity_aliases`, each with its `(source, entity_id)` members, the
/// `entity_link_meta` confidence badge (deterministic / human_confirmed /
/// approximated + strongest_method + evidence_count), and a light `name`/`domain`
/// field summary. Purely additive DERIVED reads — `merged_record`'s
/// field-resolution is UNTOUCHED, zero LLM / live ReBAC / fold. Ordered by
/// canonical key, capped by `limit` (default 100, clamped 1..=1000). Entities
/// with no alias row are their own implicit canonical and are not listed (the
/// browser lists MERGED entities; unmapped ones have nothing to enumerate).
async fn admin_list_entities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListEntitiesQuery>,
) -> HandlerResult<Json<Vec<CanonicalEntitySummary>>> {
    state.admin.check(&headers)?;
    let entities = state
        .storage
        .inner()
        .list_canonical_entities(q.tenant_id, q.limit)
        .await
        .map_err(internal)?;
    Ok(Json(entities))
}

#[derive(Deserialize)]
struct EntityTagsQuery {
    tenant_id: TenantId,
    /// Case-insensitive substring over the tag. Substring only — near-miss
    /// logic is client-side (ENTITY-PICKER.md §6: no server-side fuzz).
    q: Option<String>,
    /// Default true: count only rows the scope filter can return. Erasure
    /// passes false (invalidated rows are legitimate erasure targets).
    #[serde(default = "default_live_only")]
    live_only: bool,
    /// Default 100, clamped 1..=500 in storage.
    #[serde(default = "default_entities_limit")]
    limit: i64,
}

fn default_live_only() -> bool {
    true
}

/// GET /v1/admin/entity-tags (admin): the entity-tag DIRECTORY behind the
/// console's entity picker (docs/design/ENTITY-PICKER.md §4). Distinct tags
/// observed on `chunks.entity_tags ∪ actions.entities` — the SAME rows the
/// scope filter enforces on — with per-tag chunk/action counts, `last_seen`,
/// the observed namespace prefixes, and a display-only merged badge
/// (`canonical_entity`/`link_confidence`). `total_distinct` and `namespaces`
/// ignore `q`/`limit` so a filtered page can never fake emptiness (the
/// Emptiness Law). Complements `GET /v1/admin/entities`, which lists MERGED
/// canonicals only — a usage-born tag with no alias row is invisible there.
/// Admin plane; never consulted by `recall`/`get` (read-path purity holds).
async fn admin_entity_tags(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<EntityTagsQuery>,
) -> HandlerResult<Json<verity_storage::EntityTagDirectory>> {
    state.admin.check(&headers)?;
    let directory = state
        .storage
        .inner()
        .list_entity_tags(q.tenant_id, q.q.as_deref(), q.live_only, q.limit)
        .await
        .map_err(internal)?;
    Ok(Json(directory))
}

#[derive(Deserialize)]
struct MemoriesQuery {
    tenant_id: TenantId,
    /// Chunk/fact `source`; actions match the literal "agent" (the source
    /// their provenance episodes carry).
    source: Option<String>,
    /// Entity-tag containment over the same arrays the scope filter enforces
    /// on; facts match their synthetic `source:entity_id` tag.
    entity: Option<String>,
    /// "chunk" | "fact" | "action" — anything else is a 422.
    kind: Option<String>,
    /// Case-insensitive substring (ILIKE) over content / value / summary.
    q: Option<String>,
    /// Default false = live rows only; true also shows replaced values
    /// (bi-temporal history, never deleted).
    #[serde(default)]
    include_superseded: bool,
    /// Default 50, clamped 1..=200 in storage.
    #[serde(default = "default_memories_limit")]
    limit: i64,
    /// Keyset pagination: rows recorded strictly before this instant (the
    /// previous page's `next_before`).
    before: Option<DateTime<Utc>>,
    /// Tie-breaker half of the cursor (the previous page's `next_before_id`);
    /// same-transaction rows share `recorded_at`, so pass both.
    before_id: Option<uuid::Uuid>,
    /// Single-row detail lookup for the console drawer: full untruncated
    /// content/value, superseded rows included.
    id: Option<uuid::Uuid>,
}

fn default_memories_limit() -> i64 {
    50
}

/// GET /v1/admin/memories (admin): the console's Memories browser — one
/// tenant's chunk ∪ fact ∪ action rows, newest-recorded first, filterable by
/// source / entity / kind / substring / superseded-visibility, keyset-
/// paginated, plus per-source counts for the filter dropdown (computed from
/// the same filtered union). This is an ADMIN-plane read like the audit
/// panel: it sees across all scopes and the UI says so; it grants agents
/// nothing — scoped reads stay enforced at read time. Read-only, ZERO LLM,
/// ZERO live ReBAC (read-path purity holds; this never touches recall/get).
/// Visibility is returned as a token COUNT per row, never the tokens.
async fn admin_memories(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<MemoriesQuery>,
) -> HandlerResult<Json<verity_storage::MemoryBrowsePage>> {
    state.admin.check(&headers)?;
    let page = state
        .storage
        .inner()
        .browse_memories(
            q.tenant_id,
            &verity_storage::MemoryBrowseFilter {
                source: q.source,
                entity: q.entity,
                kind: q.kind,
                q: q.q,
                include_superseded: q.include_superseded,
                limit: q.limit,
                before: q.before,
                before_id: q.before_id,
                id: q.id,
            },
        )
        .await
        .map_err(storage_status)?;
    Ok(Json(page))
}

#[derive(Deserialize)]
struct EntityPrecedenceRequest {
    tenant_id: TenantId,
    /// Defaults to "*" (the global/entity default across all entities).
    #[serde(default = "star")]
    canonical: String,
    /// Defaults to "*" (the default across all fields for `canonical`).
    #[serde(default = "star")]
    field: String,
    /// Ordered source names, highest precedence first.
    source_order: Vec<String>,
}

fn star() -> String {
    "*".into()
}

/// POST /v1/admin/entity-precedence (admin): set the per-field source order
/// (SPEC §7f). `canonical`/`field` default to "*" (the fallbacks).
async fn admin_entity_precedence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EntityPrecedenceRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    state
        .storage
        .inner()
        .set_entity_precedence(req.tenant_id, &req.canonical, &req.field, &req.source_order)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "canonical": req.canonical,
        "field": req.field,
        "source_order": req.source_order,
    })))
}

#[derive(Deserialize)]
struct MergedRecordQuery {
    scope_handle: String,
}

/// The `entity_link_meta` confidence badge (§4.3 item 3) surfaced on the merged
/// entity response. **Additive metadata only** — it does NOT touch
/// `merged_record`'s field-resolution logic. The badge is a read-only projection
/// of the materialized `entity_link_meta` alias-member row: how the canonical was
/// linked (`deterministic` / `human_confirmed` / `approximated`), by which
/// strongest method, and how deeply corroborated. Absent when the canonical has
/// no materialized badge (an admin-only / unmapped entity) — the merged record
/// still serves, just unbadged.
#[derive(Debug, serde::Serialize)]
struct ConfidenceBadge {
    confidence: String,
    strongest_method: Option<String>,
    evidence_count: i16,
}

/// The merged-entity response: the UNCHANGED `MergedRecord` plus the additive
/// badge. `merged` is flattened so existing clients that read `.fields` /
/// `.members` / `.canonical_entity` are byte-for-byte unaffected; `badge` is a
/// new sibling field they can ignore. `Deref` to `MergedRecord` lets callers
/// reach the merged fields directly (`resp.canonical_entity`) — the badge is
/// purely additive, it never shadows or rewrites `merged_record`'s output.
#[derive(Debug, serde::Serialize)]
struct MergedEntityResponse {
    #[serde(flatten)]
    merged: MergedRecord,
    /// The confidence badge, or `null` when no `entity_link_meta` row exists.
    badge: Option<ConfidenceBadge>,
}

impl std::ops::Deref for MergedEntityResponse {
    type Target = MergedRecord;
    fn deref(&self) -> &MergedRecord {
        &self.merged
    }
}

/// GET /v1/entities/{canonical} (scope-handle gated): the merged cross-source
/// entity view (SPEC §7f) + the additive §4.3 confidence badge. Scoping matches
/// get_record exactly — a tenant-scoped L1 read gated at the tenant level by the
/// scope handle; fail-closed (401) on a bad handle. No per-field visibility is
/// invented here (get_record has none). ZERO LLM, ZERO live ReBAC, ZERO fold: the
/// badge is a plain read of the pre-materialized `entity_link_meta` row.
async fn get_merged_entity(
    State(state): State<Arc<AppState>>,
    Path(canonical): Path<String>,
    axum::extract::Query(q): axum::extract::Query<MergedRecordQuery>,
) -> HandlerResult<Json<MergedEntityResponse>> {
    let payload = state.verify_scope(&q.scope_handle)?;
    // Merged precedence resolves over caller-VISIBLE facts only (SPEC §7f/§7e):
    // an invisible higher-precedence fact must not win a field nor leak as an
    // alternative. scope_for compiles visibility + revocations.
    let scope = state.scope_for(&payload).await?;
    let merged = state
        .storage
        .inner()
        .merged_record(&scope, &canonical)
        .await
        .map_err(internal)?;
    // Additive: read the pre-materialized badge (None => unbadged, still serves).
    let badge = state
        .storage
        .inner()
        .link_meta_for_canonical(payload.tenant_id, &canonical)
        .await
        .map_err(internal)?
        .map(|m| ConfidenceBadge {
            confidence: m.confidence,
            strongest_method: m.strongest_method,
            evidence_count: m.evidence_count,
        });
    spawn_audit(
        &state,
        &payload,
        "merged_entity",
        Some(&canonical),
        merged
            .fields
            .values()
            .map(|f| f.provenance)
            .collect::<Vec<_>>(),
    );
    Ok(Json(MergedEntityResponse { merged, badge }))
}

// ---------- entity-resolution evidence ledger + fold (worker/admin plane, §4,
// §9 Group D). All admin-token gated, mirroring admin_entity_aliases. These
// write/read the append-only ledger + config + trigger the materializer; NONE of
// them is on the read path. ----------

#[derive(Deserialize)]
struct EvidenceInsertRequest {
    tenant_id: TenantId,
    left_ref: String,
    right_ref: String,
    tier: i16,
    method: String,
    #[serde(default)]
    key_value: Option<String>,
    #[serde(default)]
    key_namespace: Option<String>,
    #[serde(default)]
    score: Option<f32>,
    #[serde(default)]
    evidence_l0_ref: Option<String>,
    /// +1 = link (default), -1 = anti-link (a human "these are NOT the same").
    #[serde(default = "default_polarity")]
    polarity: i16,
}

fn default_polarity() -> i16 {
    1
}

/// POST /v1/admin/entity-evidence (admin): append one piece of evidence to the
/// ledger (§4.1). Append-only — never updates/deletes. Returns the persisted row
/// (with its stamped `evidence_id`). This is how an admin crosswalk, a Tier-1
/// producer, or a `human_confirmed`/anti-link decision reaches the ledger; the
/// fold picks it up on the next materialize.
async fn admin_evidence_insert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EvidenceInsertRequest>,
) -> HandlerResult<Json<EvidenceRow>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let row = state
        .storage
        .inner()
        .insert_evidence(EvidenceWrite {
            tenant_id: req.tenant_id,
            left_ref: req.left_ref,
            right_ref: req.right_ref,
            tier: req.tier,
            method: req.method,
            key_value: req.key_value,
            key_namespace: req.key_namespace,
            score: req.score,
            evidence_l0_ref: req.evidence_l0_ref,
            polarity: req.polarity,
        })
        .await
        .map_err(internal)?;
    Ok(Json(row))
}

#[derive(Deserialize)]
struct EvidenceRetractRequest {
    tenant_id: TenantId,
    evidence_id: uuid::Uuid,
    /// Optional replacement row to chain to (bi-temporal `superseded_by`).
    #[serde(default)]
    superseded_by: Option<uuid::Uuid>,
}

/// POST /v1/admin/entity-evidence/retract (admin): retract a live evidence row
/// (§3.3 invalidate-don't-delete) — stamps `valid_to`, never DELETEs, so the fold
/// stops reading it while the audit trail survives. Retract-a-row + re-fold is
/// the entire unmerge mechanism. Returns how many rows were retracted (0 if
/// already retracted / not found).
async fn admin_evidence_retract(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EvidenceRetractRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let retracted = state
        .storage
        .inner()
        .retract_evidence(req.tenant_id, req.evidence_id, req.superseded_by)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "evidence_id": req.evidence_id,
        "retracted": retracted,
    })))
}

#[derive(Deserialize)]
struct ResolutionConfigQuery {
    tenant_id: TenantId,
}

/// GET /v1/admin/entity-resolution-config (admin): list the tenant's key-quality
/// config rows (§4.1 — the over-merge SECURITY control). Empty list => the tenant
/// runs on `EntityResolutionConfig::defaults` everywhere.
async fn admin_resolution_config_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ResolutionConfigQuery>,
) -> HandlerResult<Json<Vec<EntityResolutionConfig>>> {
    state.admin.check(&headers)?;
    let rows = state
        .storage
        .inner()
        .list_resolution_config(q.tenant_id)
        .await
        .map_err(internal)?;
    Ok(Json(rows))
}

/// PUT /v1/admin/entity-resolution-config (admin): upsert one `(key_kind,
/// key_namespace)` config row (§4.1). Idempotent on the primary key.
async fn admin_resolution_config_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(cfg): Json<EntityResolutionConfig>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(cfg.tenant_id)
        .await
        .map_err(storage_status)?;
    state
        .storage
        .inner()
        .write_resolution_config(&cfg)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "tenant_id": cfg.tenant_id,
        "key_kind": cfg.key_kind,
        "key_namespace": cfg.key_namespace,
    })))
}

#[derive(Deserialize)]
struct TriggerFoldRequest {
    tenant_id: TenantId,
}

/// POST /v1/admin/entity-resolution/fold (admin): run the fold for a tenant and
/// MATERIALIZE its plan into `entity_aliases` + chunk `entity_tags` +
/// `entity_link_meta` (§4.2 S4, §4.3). This is the sole writer of the resolution
/// rows the read path consumes; it runs in the worker/admin plane, NEVER on the
/// read path. Returns a per-run report (evidence considered, rows written,
/// review items, canonicals).
async fn admin_trigger_fold(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TriggerFoldRequest>,
) -> HandlerResult<Json<resolver::MaterializeReport>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let report = resolver::run_full_fold(&state, req.tenant_id).await?;
    Ok(Json(report))
}

/// POST /v1/admin/entity-resolution/run (admin): the LIVE Tier-1 resolution run
/// (§4.2 S1 → S4). First populates the ledger from the tenant's CURRENT L1 facts
/// via the S0/S1 producers (idempotent, deterministic `evidence_id` +
/// `ON CONFLICT DO NOTHING`), THEN runs the `run_full_fold` materializer over the
/// now-populated ledger. This is the endpoint that makes Tier-1 resolution live
/// end-to-end — the manual `/fold` only materializes an EXISTING ledger, this one
/// fills it first. Runs in the worker/admin plane, NEVER on the read path.
/// Returns `{ evidence_produced, ...MaterializeReport }`.
async fn admin_run_resolution(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TriggerFoldRequest>,
) -> HandlerResult<Json<resolver::RunReport>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let report = resolver::run_resolution(&state, req.tenant_id).await?;
    Ok(Json(report))
}

#[derive(Deserialize)]
struct EntityDecisionRequest {
    tenant_id: TenantId,
    /// A canonicalized ref, e.g. `salesforce:001xACME`.
    left_ref: String,
    /// The other ref, e.g. `hubspot:4207`.
    right_ref: String,
    /// `confirm` (these ARE the same) or `reject` (these are NOT — anti-link).
    decision: EntityDecision,
    /// Optional reviewer note, stored as the evidence lineage pointer for audit.
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EntityDecision {
    Confirm,
    Reject,
}

/// The human-gate decision response (§4.2 S4, §6): the evidence row the decision
/// wrote, the fresh `MaterializeReport` from re-running the fold so the decision
/// takes effect immediately, and the canonical each ref now resolves to.
#[derive(Debug, serde::Serialize)]
struct EntityDecisionResponse {
    /// The `entity_evidence` row this decision appended (human_confirmed +1, or
    /// the human_rejected −1 anti-link).
    evidence: EvidenceRow,
    /// The fold report after re-materializing (so the decision is live).
    materialize: resolver::MaterializeReport,
    /// The canonical `left_ref` now resolves to (its own ref when unmapped).
    left_canonical: String,
    /// The canonical `right_ref` now resolves to (its own ref when unmapped).
    right_canonical: String,
}

/// POST /v1/admin/entity-resolution/decide (admin): the HUMAN GATE the fold
/// requires for Tier-2 (§4.2 S4 step 3, §6). `confirm` appends a
/// `method="human_confirmed"`, `tier=2`, `polarity=+1` evidence row — the only
/// thing that lets the fold form a Tier-2 edge. `reject` appends a
/// `method="human_rejected"`, `polarity=-1` **anti-link** — a PERMANENT
/// must-not-link no positive evidence can override, so the same bad merge cannot
/// re-form on the next ingestion (§6 invalidate-don't-delete: nothing is deleted;
/// the anti-link is a standing guardrail). After writing, the fold is re-run
/// (`run_full_fold`) so the decision takes effect immediately; the response
/// carries the updated `MaterializeReport` and the resulting canonical(s) for the
/// two refs. Admin/worker plane only — NEVER on the read path.
async fn admin_entity_decide(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EntityDecisionRequest>,
) -> HandlerResult<Json<EntityDecisionResponse>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let (method, polarity) = match req.decision {
        EntityDecision::Confirm => ("human_confirmed", 1i16),
        EntityDecision::Reject => ("human_rejected", -1i16),
    };
    // 1. Append the human decision to the append-only ledger. Tier-2: a human
    //    confirm is the sole edge-former for the fuzzy tier; a reject is the
    //    permanent anti-link. `note` rides the lineage pointer for audit.
    let evidence = state
        .storage
        .inner()
        .insert_evidence(EvidenceWrite {
            tenant_id: req.tenant_id,
            left_ref: req.left_ref.clone(),
            right_ref: req.right_ref.clone(),
            tier: 2,
            method: method.to_string(),
            key_value: None,
            key_namespace: None,
            score: None,
            evidence_l0_ref: req.note.clone(),
            polarity,
        })
        .await
        .map_err(internal)?;

    // 2. Re-fold so the decision takes effect immediately (a confirm can merge
    //    two refs; a reject splits their component). The fold is the sole writer
    //    of the read-path rows; this is the same materializer /fold calls.
    let materialize = resolver::run_full_fold(&state, req.tenant_id).await?;

    // 3. Report the canonical each ref now resolves to. `resolve_canonical`
    //    returns None for an unmapped ref — it is then its own canonical.
    let left_canonical = state
        .storage
        .inner()
        .resolve_canonical_for_ref(req.tenant_id, &req.left_ref)
        .await
        .map_err(internal)?;
    let right_canonical = state
        .storage
        .inner()
        .resolve_canonical_for_ref(req.tenant_id, &req.right_ref)
        .await
        .map_err(internal)?;

    Ok(Json(EntityDecisionResponse {
        evidence,
        materialize,
        left_canonical,
        right_canonical,
    }))
}

#[derive(Deserialize)]
struct ReviewQueueQuery {
    tenant_id: TenantId,
    #[serde(default = "default_review_limit")]
    limit: i64,
}

fn default_review_limit() -> i64 {
    100
}

/// One enriched review-queue candidate (§4.3 review enrichment): everything a
/// side-by-side human review needs. Both refs, each ref's member field summary
/// (from current facts), the method/score/key_value/key_namespace off the
/// evidence row, and the judge/reviewer rationale.
#[derive(Debug, serde::Serialize)]
struct ReviewCandidate {
    evidence_id: uuid::Uuid,
    left_ref: String,
    right_ref: String,
    /// `left_ref`'s light name/domain summary (empty for a `key:*`/`chunk:*` ref).
    left_summary: EntityFieldSummary,
    /// `right_ref`'s light name/domain summary.
    right_summary: EntityFieldSummary,
    tier: i16,
    method: String,
    score: Option<f32>,
    key_value: Option<String>,
    key_namespace: Option<String>,
    polarity: i16,
    /// The judge/reviewer rationale. It rides `entity_evidence.evidence_l0_ref`
    /// — the lineage pointer the S2 judge stores its rationale on and where the
    /// decide endpoint's `note` lands (the design keeps the free-text rationale
    /// off the match-key columns). `None` when the producer left it unset.
    rationale: Option<String>,
    valid_from: DateTime<Utc>,
    /// Prioritization (design §8 Later — review-queue prioritization + SLA). The
    /// combined priority score the queue is ORDERed by (DESC). Higher = surfaced
    /// sooner. Unbounded because of the linear aging term, so a long-waiting
    /// candidate can never be indefinitely buried. Ordering only — no fold/merge
    /// behaviour changes, read path untouched.
    priority: f64,
    /// SLA read-out: seconds this candidate has waited (now() − `valid_from`).
    /// Surfaced so an operator can watch the oldest-waiting candidate directly.
    wait_age_secs: f64,
    /// FREQUENCY signal: live evidence rows recurring on this unordered ref-pair.
    frequency: i64,
    /// ENTITY VALUE signal: distinct alias members in the two refs' clusters.
    entity_value: i64,
}

/// GET /v1/admin/entity-resolution/review-queue (admin): live Tier-2/Tier-3
/// evidence awaiting a human decision (§4.1, §4.3), ENRICHED for side-by-side
/// review AND PRIORITIZED (design §8 Later — review-queue prioritization + SLA).
/// Tier-2 needs a `human_confirmed` before it can form an edge; Tier-3 never
/// auto-merges. Each candidate carries both refs, their member field summaries,
/// the method/score/key_value/key_namespace, the rationale, and — new — its
/// `priority`, `wait_age_secs`, `frequency`, and `entity_value`. Ordered by
/// priority DESC (see `PostgresAdapter::review_queue` for the formula + the
/// anti-starvation aging term). Empty in the MVP (no Tier-2/3 producers ship
/// yet) but fully wired so the surface exists the day they turn on. Capped.
/// Purely additive derived reads — no LLM, no live ReBAC, no fold; ordering
/// only, read path untouched.
async fn admin_review_queue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ReviewQueueQuery>,
) -> HandlerResult<Json<Vec<ReviewCandidate>>> {
    state.admin.check(&headers)?;
    let items = state
        .storage
        .inner()
        .review_queue(q.tenant_id, q.limit)
        .await
        .map_err(internal)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let e = item.evidence;
        // Attach each ref's light field summary for the side-by-side view.
        let left_summary = state
            .storage
            .inner()
            .ref_field_summary(q.tenant_id, &e.left_ref)
            .await
            .map_err(internal)?;
        let right_summary = state
            .storage
            .inner()
            .ref_field_summary(q.tenant_id, &e.right_ref)
            .await
            .map_err(internal)?;
        out.push(ReviewCandidate {
            evidence_id: e.evidence_id,
            left_ref: e.left_ref,
            right_ref: e.right_ref,
            left_summary,
            right_summary,
            tier: e.tier,
            method: e.method,
            score: e.score,
            key_value: e.key_value,
            key_namespace: e.key_namespace,
            polarity: e.polarity,
            rationale: e.evidence_l0_ref,
            valid_from: e.valid_from,
            priority: item.priority,
            wait_age_secs: item.wait_age_secs,
            frequency: item.frequency,
            entity_value: item.entity_value,
        });
    }
    Ok(Json(out))
}

// ---------- ingest (trusted connector plane — admin-token gated, task 3;
// not scope-handle gated) ----------

#[derive(Deserialize)]
struct IngestParams {
    tenant_id: TenantId,
    /// Primary-key field within the row image.
    #[serde(default = "default_pk")]
    pk: String,
    /// The static visibility policy bound to this connector at ingest time
    /// (SPEC §5e). Debezium envelopes carry no native per-row ACL, so unless a
    /// row declares an inline `verity_acl` block, its facts materialize against
    /// THIS admin-supplied token set. Absent here AND absent inline => the fact
    /// is REFUSED (fail closed), never indexed at a permissive default. Empty
    /// (`visibility=[]`) is a deliberate "writes memory nobody can read", still
    /// a policy, distinct from "no policy".
    ///
    /// Carried as a comma-separated token list on the query string
    /// (`?visibility=1,2`). A URL query is `serde_urlencoded`, which cannot
    /// deserialize a `Vec` from repeated keys, so the wire form is one string
    /// that we split here — the ONLY way a connector can reach the
    /// admin-assigned bound-policy path over HTTP.
    #[serde(default, deserialize_with = "de_comma_tokens")]
    visibility: Option<Vec<PrincipalToken>>,
    #[serde(default)]
    confidentiality: Option<Confidentiality>,
}

/// Parse `?visibility=1,2,3` into tokens. Absent => `None` (no bound policy =>
/// the fact is refused unless it declares an inline ACL). Present-but-empty
/// (`?visibility=`) => `Some(vec![])`, the deliberate "nobody can read this"
/// policy — still a policy, never widened. A non-integer token fails the whole
/// request (fail closed) rather than being silently dropped.
fn de_comma_tokens<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<PrincipalToken>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    let Some(raw) = raw else { return Ok(None) };
    let mut tokens = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        tokens.push(
            part.parse::<PrincipalToken>()
                .map_err(serde::de::Error::custom)?,
        );
    }
    Ok(Some(tokens))
}

#[cfg(test)]
mod ingest_visibility_param_tests {
    //! Regression lock for the connector-bound visibility policy on the wire.
    //! `?visibility=1,2` is a URL query, deserialized by `serde_urlencoded`,
    //! which CANNOT build a `Vec` from repeated keys — so the field MUST arrive
    //! as one comma string that `de_comma_tokens` splits. Before this parser
    //! existed, every form of the param 400'd and the only reachable ACL path
    //! was inline (provenance `mirrored`) — wrong for tier-C CRM connectors,
    //! which have no source ACL and must land `admin-assigned`. We exercise the
    //! real `IngestParams` field (deserialize_with hookup + parser) through a
    //! JSON string, which presents the value exactly as a query string does.
    use super::IngestParams;
    use serde_json::json;

    fn visibility_of(raw: Option<&str>) -> Result<Option<Vec<i32>>, serde_json::Error> {
        let mut obj = json!({ "tenant_id": "00000000-0000-0000-0000-000000000000" });
        if let Some(v) = raw {
            obj["visibility"] = json!(v);
        }
        let params: IngestParams = serde_json::from_value(obj)?;
        Ok(params.visibility)
    }

    #[test]
    fn comma_list_becomes_tokens() {
        assert_eq!(visibility_of(Some("1,2,3")).unwrap(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn whitespace_around_tokens_is_trimmed() {
        assert_eq!(
            visibility_of(Some(" 1 , 2 ,3 ")).unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn empty_string_is_the_nobody_can_read_policy_not_none() {
        // `?visibility=` is a deliberate empty policy — Some(vec![]), still a
        // policy the server binds; distinct from absent (no policy => refuse).
        assert_eq!(visibility_of(Some("")).unwrap(), Some(vec![]));
    }

    #[test]
    fn absent_is_none_so_the_fact_is_refused_not_widened() {
        assert_eq!(visibility_of(None).unwrap(), None);
    }

    #[test]
    fn a_non_integer_token_fails_the_whole_request() {
        // Fail closed: never silently drop a malformed token and bind a
        // narrower-than-intended policy.
        assert!(visibility_of(Some("1,notatoken,3")).is_err());
    }
}

#[cfg(test)]
mod secret_intake_auth_tests {
    //! Hermetic locks for the Phase-2 secret-intake auth + CSRF gate, the
    //! `Secret` redacting newtype, and the bind-time transport gate. All pure —
    //! no socket, no DB, no process env — so they run in CI without fixtures.
    use super::{bind_gate_decision, AdminAuth, Secret};
    use axum::http::{header, HeaderMap, StatusCode};

    fn headers(pairs: &[(axum::http::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(k.clone(), v.parse().unwrap());
        }
        h
    }

    // --- SecretIntakeAuth: no dev-open branch (require) --------------------

    #[test]
    fn require_refuses_when_no_admin_token_configured() {
        // The whole point of SecretIntakeAuth: an unset VERITY_ADMIN_TOKEN must
        // 401, NOT dev-open like AdminAuth::check.
        let auth = AdminAuth::for_test(None, None);
        let err = auth
            .require(&headers(&[(header::AUTHORIZATION, "Bearer whatever")]))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_is_dev_open_but_require_is_not_for_the_same_state() {
        // Same no-token AdminAuth: check() passes (dev mode), require() refuses.
        let auth = AdminAuth::for_test(None, None);
        let h = headers(&[]);
        assert!(auth.check(&h).is_ok());
        assert!(auth.require(&h).is_err());
    }

    #[test]
    fn require_rejects_missing_bearer() {
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        let err = auth.require(&headers(&[])).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_rejects_wrong_bearer() {
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        let err = auth
            .require(&headers(&[(header::AUTHORIZATION, "Bearer wrong")]))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_accepts_correct_bearer() {
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        assert!(auth
            .require(&headers(&[(header::AUTHORIZATION, "Bearer s3cret")]))
            .is_ok());
    }

    #[test]
    fn require_never_reads_bearer_from_cookie() {
        // A cookie-borne token is the CSRF vector; only Authorization counts.
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        let err = auth
            .require(&headers(&[(header::COOKIE, "Authorization=Bearer s3cret")]))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    // --- SecretIntakeAuth: Origin / same-origin CSRF gate ------------------

    #[test]
    fn origin_absent_is_allowed_server_to_server() {
        let auth = AdminAuth::for_test(Some("s3cret"), Some("https://console.example"));
        assert!(auth.check_origin(&headers(&[])).is_ok());
    }

    #[test]
    fn origin_matching_allowlist_is_allowed() {
        let auth = AdminAuth::for_test(Some("s3cret"), Some("https://console.example"));
        assert!(auth
            .check_origin(&headers(&[(header::ORIGIN, "https://console.example")]))
            .is_ok());
    }

    #[test]
    fn cross_origin_is_refused_even_with_valid_bearer() {
        // A valid bearer alone is insufficient: a mismatched Origin still 403s.
        let auth = AdminAuth::for_test(Some("s3cret"), Some("https://console.example"));
        let err = auth
            .check_origin(&headers(&[(header::ORIGIN, "https://evil.example")]))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn browser_origin_with_no_allowlist_is_refused() {
        // Fail closed: a browser Origin with no VERITY_ALLOWED_ORIGIN configured
        // is refused, never defaulted-permissive.
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        let err = auth
            .check_origin(&headers(&[(header::ORIGIN, "https://console.example")]))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    // --- Secret redacting newtype -----------------------------------------

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let s = Secret::new("hush-abcd1234".to_string());
        assert_eq!(format!("{s}"), "***");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert!(!format!("{s} {s:?}").contains("abcd1234"));
    }

    #[test]
    fn secret_exposes_plaintext_for_the_crypto_choke_point() {
        let s = Secret::new("hush-abcd1234".to_string());
        assert_eq!(s.expose(), "hush-abcd1234");
    }

    #[test]
    fn secret_deserializes_from_a_json_string() {
        let s: Secret = serde_json::from_value(serde_json::json!("tok-xyz")).unwrap();
        assert_eq!(s.expose(), "tok-xyz");
        // And even after deserialize it stays redacted when formatted.
        assert_eq!(format!("{s:?}"), "Secret(***)");
    }

    // --- Bind-time gate decision ------------------------------------------

    fn sa(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_binds_without_any_env() {
        assert!(bind_gate_decision(sa("127.0.0.1:7717"), false, false).is_ok());
        assert!(bind_gate_decision(sa("[::1]:7717"), false, false).is_ok());
    }

    #[test]
    fn non_loopback_missing_env_refuses() {
        let err = bind_gate_decision(sa("10.0.0.5:7717"), false, false).unwrap_err();
        assert!(err.contains("refusing to bind"));
        // Either one missing is still a refusal.
        assert!(bind_gate_decision(sa("10.0.0.5:7717"), true, false).is_err());
        assert!(bind_gate_decision(sa("10.0.0.5:7717"), false, true).is_err());
    }

    #[test]
    fn non_loopback_with_both_env_binds() {
        assert!(bind_gate_decision(sa("10.0.0.5:7717"), true, true).is_ok());
    }

    #[test]
    fn unspecified_address_is_treated_as_non_loopback() {
        // 0.0.0.0 / :: expose every interface and are NOT loopback → gated.
        assert!(bind_gate_decision(sa("0.0.0.0:7717"), false, false).is_err());
        assert!(bind_gate_decision(sa("[::]:7717"), false, false).is_err());
        assert!(bind_gate_decision(sa("0.0.0.0:7717"), true, true).is_ok());
    }
}

fn default_pk() -> String {
    "id".into()
}

async fn ingest_debezium(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<IngestParams>,
    Json(body): Json<serde_json::Value>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let envelopes: Vec<&serde_json::Value> = match &body {
        serde_json::Value::Array(items) => items.iter().collect(),
        one => vec![one],
    };

    // The connector-bound static ACL policy (SPEC §5e). Present only when the
    // admin bound one on the ingest call; otherwise rows must declare their own
    // inline `verity_acl` block or be refused. A bound policy with an empty
    // token set is a deliberate "nobody can read this", still a policy.
    let bound_policy = p.visibility.as_ref().map(|vis| ingest::ResolvedAcl {
        visibility: vis.clone(),
        confidentiality: p.confidentiality.unwrap_or(Confidentiality::Internal),
        provenance: AclProvenance::AdminAssigned,
    });

    let (mut written, mut superseded, mut retired, mut unchanged, mut refused) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for envelope in envelopes {
        let ev = ingest::parse_envelope(envelope, &p.pk, bound_policy.as_ref())
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

        let episode = state
            .storage
            .append_episode(NewEpisode {
                tenant_id: p.tenant_id,
                source: ev.source.clone(),
                source_entity: Some(ev.entity_id.clone()),
                kind: EpisodeKind::CdcEvent,
                content_hash: format!("{:x}", md5ish(&ev.raw.to_string())),
                payload: ev.raw.clone(),
                trust_tier: TrustTier::Authoritative,
                writer_sub: None,
                writer_azp: None,
            })
            .await
            .map_err(internal)?;

        match ev.op {
            ingest::Op::Delete => {
                retired += state
                    .storage
                    .retire_entity(p.tenant_id, &ev.source, &ev.entity_id, ev.occurred_at)
                    .await
                    .map_err(internal)?;
            }
            ingest::Op::Upsert => {
                // Fail-closed choke point: an upsert with no resolvable ACL
                // (no inline block, no bound policy) writes NO readable fact.
                // The L0 episode above is already durable for audit/re-ingest;
                // we skip the L1 upsert rather than default to permissive.
                let Some(acl) = ev.acl.clone() else {
                    refused += ev.fields.len() as u64;
                    slo::record_sample(state.pool(), p.tenant_id, &ev.source, ev.occurred_at).await;
                    continue;
                };
                for (field, value) in ev.fields {
                    let outcome = state
                        .storage
                        .upsert_fact(FactWrite {
                            tenant_id: p.tenant_id,
                            key: FactKey {
                                source: ev.source.clone(),
                                entity_id: ev.entity_id.clone(),
                                field,
                            },
                            value,
                            valid_from: ev.occurred_at,
                            visibility: acl.visibility.clone(),
                            confidentiality: acl.confidentiality,
                            provenance: episode,
                            acl_provenance: acl.provenance,
                        })
                        .await
                        .map_err(internal)?;
                    match outcome {
                        FactUpsertOutcome::Inserted => written += 1,
                        FactUpsertOutcome::Superseded => superseded += 1,
                        FactUpsertOutcome::Unchanged => unchanged += 1,
                        FactUpsertOutcome::StaleEvent => {}
                    }
                }
            }
        }
        // Freshness SLO sample (task 21): envelope event time vs the moment
        // the derived writes above became queryable. Best-effort telemetry.
        slo::record_sample(state.pool(), p.tenant_id, &ev.source, ev.occurred_at).await;
    }

    // Auto-resolve trigger: mark the tenant dirty only if L1 actually changed
    // (a batch of purely-unchanged upserts is a no-op — nothing to re-resolve).
    // Never affects the response; the background loop does the work.
    if written + superseded + retired > 0 {
        state.resolution.mark_dirty(p.tenant_id);
    }

    Ok(Json(serde_json::json!({
        "facts_inserted": written,
        "facts_superseded": superseded,
        "facts_unchanged": unchanged,
        "facts_retired": retired,
        // Upsert fields dropped for want of a resolvable ACL (fail closed). A
        // non-zero count means the connector is missing a bound visibility
        // policy (or its rows an inline `verity_acl` block) — the L0 events are
        // preserved for re-ingest once a policy is supplied.
        "facts_refused_no_acl": refused,
    })))
}

// ---------- ingest: whole documents (connector contract, task 7 of v0.1) ----------

#[derive(Deserialize)]
struct IngestDocumentsRequest {
    tenant_id: TenantId,
    source: String,
    document_id: String,
    /// Pre-extracted text. `None` (with no `content_base64`) is a declared
    /// metadata-only delivery — an episode is recorded, nothing is indexed.
    #[serde(default)]
    content: Option<String>,
    /// Binary path (Tier-1 extraction, extract.rs): raw file bytes, base64.
    /// The SERVER extracts text (PDF/PPTX/XLS(X), deterministic, no OCR) so
    /// connectors stay extraction-free. Chosen over posting to /v1/files
    /// because /v1/files stamps the uploader scope's principals — it would
    /// REPLACE the connector's mirrored per-item ACL, which is the whole
    /// point of Tier-A connectors. Mutually exclusive with `content`.
    #[serde(default)]
    content_base64: Option<String>,
    /// Filename hint for format detection (magic bytes still win).
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    entities: Vec<String>,
    /// Materialized principal tokens (see POST /v1/admin/principals).
    visibility: Vec<PrincipalToken>,
    /// mirrored | approximated | admin-assigned — the connector must label
    /// how it derived the visibility set (SPEC §5e). Quarantined is not a
    /// connector-assignable label.
    acl_provenance: AclProvenance,
    #[serde(default)]
    valid_from: Option<DateTime<Utc>>,
}

/// POST /v1/ingest/documents (admin): one document version in → one L0
/// episode + deterministic paragraph chunks out, under connector-supplied
/// visibility and ACL provenance. The contract the Google Drive connector
/// codes against. `content` carries pre-extracted text; `content_base64`
/// carries raw PDF/PPTX/XLS(X) bytes for server-side Tier-1 extraction
/// (extract.rs); neither = declared metadata-only.
async fn ingest_documents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<IngestDocumentsRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if req.acl_provenance == AclProvenance::Quarantined {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "acl_provenance must be mirrored, approximated, or admin-assigned".into(),
        ));
    }
    // Resolve what (if anything) gets indexed. Three delivery shapes:
    //   * `content`         — pre-extracted text, indexed as before;
    //   * `content_base64`  — raw bytes; the server runs Tier-1 extraction
    //     (extract.rs). Success indexes the text with the method recorded in
    //     provenance; a typed failure lands METADATA-ONLY with the reason on
    //     the episode AND in the response (fail-visible, never silent);
    //   * neither           — declared metadata-only (the Drive connector's
    //     long-standing shape for content it cannot deliver).
    if req.content.is_some() && req.content_base64.is_some() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "send content OR content_base64, not both".into(),
        ));
    }
    let delivered = match (req.content, req.content_base64) {
        (Some(c), None) => DeliveredContent::Text(c),
        (None, Some(b64)) => {
            use base64::Engine as _;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("content_base64 is not valid base64: {e}"),
                    )
                })?;
            // Keep the delivered base64 for the idempotency hash (see
            // DocumentIngest::content_hash): what was DELIVERED, not extracted.
            DeliveredContent::Bytes {
                raw,
                hash_over: b64,
            }
        }
        _ => DeliveredContent::None,
    };

    let outcome = ingest_document(
        &state,
        DocumentIngest {
            tenant_id: req.tenant_id,
            source: req.source,
            document_id: req.document_id,
            filename: req.filename,
            entities: req.entities,
            visibility: req.visibility,
            confidentiality: Confidentiality::Internal,
            acl_provenance: req.acl_provenance,
            valid_from: req.valid_from,
            delivered,
        },
    )
    .await?;

    let mut resp = serde_json::json!({
        "episode_id": outcome.episode_id,
        "chunks_indexed": outcome.chunks_indexed,
    });
    if let Some(x) = outcome.extraction_receipt {
        resp["extraction"] = x;
    }
    Ok(Json(resp))
}

/// What a document delivery carried. Both the HTTP handler and the folder
/// watcher build one of these, so extraction/chunking/idempotency live in ONE
/// place ([`ingest_document`]) — the watcher never self-HTTPs or duplicates
/// extract.rs.
pub(crate) enum DeliveredContent {
    /// Pre-extracted text, indexed as-is.
    Text(String),
    /// Raw file bytes for server-side Tier-1 extraction (extract.rs). `hash_over`
    /// is the string the idempotency hash is taken over (the base64 for the HTTP
    /// path, the raw UTF-8 for the watcher) — what was DELIVERED, so a changed
    /// file re-ingests even if extraction failed both times.
    Bytes { raw: Vec<u8>, hash_over: String },
    /// Declared metadata-only: an episode is recorded, nothing is indexed.
    None,
}

/// One document version to ingest under a resolved visibility policy. The
/// shared shape behind POST /v1/ingest/documents and the folder watcher.
pub(crate) struct DocumentIngest {
    pub(crate) tenant_id: TenantId,
    pub(crate) source: String,
    pub(crate) document_id: String,
    pub(crate) filename: Option<String>,
    pub(crate) entities: Vec<String>,
    /// Materialized principal tokens (SPEC §5e); empty = invisible, never
    /// permissive. The caller resolves these at the write-time ACL choke point.
    pub(crate) visibility: Vec<PrincipalToken>,
    pub(crate) confidentiality: Confidentiality,
    pub(crate) acl_provenance: AclProvenance,
    /// Event time (when true in the world); receipt time when absent.
    pub(crate) valid_from: Option<DateTime<Utc>>,
    pub(crate) delivered: DeliveredContent,
}

pub(crate) struct DocumentIngestOutcome {
    pub(crate) episode_id: EpisodeId,
    pub(crate) chunks_indexed: usize,
    pub(crate) extraction_receipt: Option<serde_json::Value>,
}

/// Shared document-ingest choke point: one document version in → one L0
/// episode + deterministic paragraph chunks out, under the caller-resolved
/// visibility + ACL provenance. This is the SINGLE place that runs Tier-1
/// extraction, chunking, idempotency, the auto-resolve trigger, and the
/// freshness sample — both the HTTP handler and the folder watcher route
/// through here so neither reimplements extraction or self-HTTPs.
pub(crate) async fn ingest_document(
    state: &AppState,
    req: DocumentIngest,
) -> HandlerResult<DocumentIngestOutcome> {
    // Freshness SLO (task 21): receipt time, not `valid_from` — a connector
    // backfilling last year's documents is not "a year behind on ingest".
    let received_at = Utc::now();
    let valid_from = req.valid_from.unwrap_or(received_at);

    // Run extraction (bytes) or pass text through; a typed failure lands
    // metadata-only with the reason disclosed (fail-visible, never silent).
    let mut extraction_receipt: Option<serde_json::Value> = None;
    let (text, hash_over): (Option<String>, String) = match req.delivered {
        DeliveredContent::Text(c) => {
            let hash = c.clone();
            (Some(c), hash)
        }
        DeliveredContent::Bytes { raw, hash_over } => {
            let text = match extract::extract(&raw, req.filename.as_deref()) {
                extract::ExtractOutcome::Extracted(ex) => {
                    extraction_receipt = Some(serde_json::json!({
                        "method": ex.method, "truncated": ex.truncated,
                    }));
                    Some(ex.text)
                }
                extract::ExtractOutcome::Failed(f) => {
                    extraction_receipt = Some(serde_json::json!({ "failure": f.reason() }));
                    None
                }
                // Bytes we have no Tier-1 extractor for: disclosed, not
                // guessed at — the connector should have inlined text.
                extract::ExtractOutcome::NotHandled => {
                    extraction_receipt = Some(serde_json::json!({
                        "failure": extract::ExtractFailure::UnrecognizedFormat.reason(),
                    }));
                    None
                }
            };
            (text, hash_over)
        }
        DeliveredContent::None => (None, String::new()),
    };

    // Idempotency hash covers what was DELIVERED, not what extraction produced.
    let content_hash = format!("{:x}", md5ish(&hash_over));
    let mut episode_payload = serde_json::json!({
        "document_id": req.document_id,
        "content_hash": content_hash,
        "bytes": text.as_ref().map_or(0, |t| t.len()),
    });
    if let Some(name) = &req.filename {
        episode_payload["filename"] = serde_json::json!(name);
    }
    if let Some(x) = &extraction_receipt {
        episode_payload["extraction"] = x.clone();
    }
    let episode_id = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: req.tenant_id,
            source: req.source.clone(),
            source_entity: Some(req.document_id.clone()),
            kind: EpisodeKind::DocVersion,
            payload: episode_payload,
            content_hash: content_hash.clone(),
            // Connector-mirrored documents track a system of record.
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .map_err(internal)?;

    let mut writes = Vec::new();
    for (seq, content) in media::split_text(text.as_deref().unwrap_or(""), media::CHUNK_CHARS)
        .into_iter()
        .enumerate()
    {
        let embedding = state.encode(&content).await.ok().flatten();
        writes.push(ChunkWrite {
            tenant_id: req.tenant_id,
            source: req.source.clone(),
            document_id: req.document_id.clone(),
            seq: seq as i32,
            content,
            content_hash: format!("{content_hash}-{seq}"),
            embedding,
            visibility: req.visibility.clone(),
            entity_tags: req.entities.clone(),
            confidentiality: req.confidentiality,
            trust_tier: TrustTier::Authoritative,
            valid_from,
            provenance: episode_id,
            acl_provenance: req.acl_provenance,
        });
    }
    let chunks_indexed = state
        .storage
        .upsert_chunks(writes)
        .await
        .map_err(internal)?;
    // Auto-resolve trigger: a document version wrote an L0 episode + chunks
    // (new entity_tags/aliases can feed resolution). Never affects the response.
    state.resolution.mark_dirty(req.tenant_id);
    slo::record_sample(state.pool(), req.tenant_id, &req.source, received_at).await;
    Ok(DocumentIngestOutcome {
        episode_id,
        chunks_indexed,
        extraction_receipt,
    })
}

// ---------- remember ----------

#[derive(Deserialize)]
struct RememberRequest {
    scope_handle: String,
    observation: String,
    #[serde(default)]
    entities: Vec<String>,
}

async fn remember(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RememberRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    // Freshness SLO event time (task 21): an agent observation carries no
    // source clock, so receipt time is the event time — the sample measures
    // receipt→queryable, same convention as webhooks. This also makes a bare
    // first memory OBSERVABLE server-side (the FTUE checklist's "memory in"
    // derives from counts; without a sample, the clean path never greened).
    let received_at = Utc::now();
    let payload = state.verify_scope(&req.scope_handle)?;
    let entities = resolve_entities(&payload, req.entities)?;

    let episode_id = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: payload.tenant_id,
            source: "agent".into(),
            // Entity attribution rides on the episode: it drives the knowledge
            // layer's distinct-entity support counting. Single-column for now;
            // multi-entity observations attribute to their first entity.
            source_entity: entities.first().cloned(),
            kind: EpisodeKind::Observation,
            payload: serde_json::json!({ "observation": req.observation, "entities": entities }),
            content_hash: format!("{:x}", md5ish(&req.observation)),
            trust_tier: TrustTier::Observation,
            writer_sub: payload.actor_sub.clone(),
            writer_azp: payload.actor_azp.clone(),
        })
        .await
        .map_err(internal)?;

    // Deterministic Tier-2 materialization (SPEC §2): embedded when the local
    // encoder is up, BM25-searchable regardless. Visible to the writer's own
    // principal set.
    let embedding = state.encode(&req.observation).await.ok().flatten();
    state
        .storage
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: payload.tenant_id,
            source: "agent".into(),
            document_id: format!("obs:{episode_id}"),
            seq: 0,
            content: req.observation,
            content_hash: format!("obs-{episode_id}"),
            embedding,
            visibility: payload.principals.clone(),
            entity_tags: entities,
            confidentiality: payload.max_confidentiality,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: episode_id,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .map_err(internal)?;

    slo::record_sample(state.pool(), payload.tenant_id, "agent", received_at).await;
    Ok(Json(serde_json::json!({ "episode_id": episode_id })))
}

/// Cheap content hash for L0 idempotency metadata (not security-relevant).
pub(crate) fn md5ish(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// ---------- record_action ----------

#[derive(Deserialize)]
struct RecordActionRequest {
    scope_handle: String,
    action_id: String,
    action_type: String,
    #[serde(default)]
    entities: Vec<String>,
    summary: String,
    #[serde(default)]
    payload: serde_json::Value,
    outcome: ActionOutcome,
    occurred_at: DateTime<Utc>,
}

async fn record_action(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecordActionRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(&req.scope_handle)?;
    let entities = resolve_entities(&payload, req.entities)?;
    let recorded = state
        .storage
        .record_action(ActionWrite {
            tenant_id: payload.tenant_id,
            action_id: req.action_id,
            // Actor identity comes from the signed scope, never the request.
            actor_sub: payload.actor_sub.clone(),
            actor_azp: payload.actor_azp.clone(),
            action_type: req.action_type,
            entities,
            summary: req.summary,
            payload: req.payload,
            outcome: req.outcome,
            occurred_at: req.occurred_at,
            visibility: payload.principals.clone(),
            confidentiality: payload.max_confidentiality,
        })
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "recorded": recorded })))
}

// ---------- activity ----------

#[derive(Deserialize)]
struct ActivityParams {
    scope_handle: String,
    entity: String,
    since: Option<DateTime<Utc>>,
    /// Comma-separated exact types or "prefix.*" patterns.
    action_types: Option<String>,
    #[serde(default = "default_activity_limit")]
    limit: usize,
}

fn default_activity_limit() -> usize {
    50
}

async fn activity(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(p): axum::extract::Query<ActivityParams>,
) -> HandlerResult<Json<Vec<ActionRecord>>> {
    let payload = state.verify_scope(&p.scope_handle)?;
    let query = ActivityQuery {
        scope: state.scope_for(&payload).await?,
        entity: p.entity,
        since: p.since,
        action_types: p
            .action_types
            .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
            .unwrap_or_default(),
        actors: vec![],
        limit: p.limit,
    };
    let summary = query.entity.clone();
    let actions = state.storage.activity(query).await.map_err(internal)?;
    spawn_audit(
        &state,
        &payload,
        "activity",
        Some(&summary),
        actions.iter().map(|a| a.id).collect(),
    );
    Ok(Json(actions))
}

// ---------- forget ----------

#[derive(Deserialize)]
struct ForgetRequest {
    scope_handle: String,
    /// {"kind": "chunk"|"episode", "id": "<uuid>"}
    #[serde(rename = "ref")]
    reference: ForgetRef,
    reason: String,
}

/// memory.forget (task 5): retire a chunk, or an episode plus its derived
/// chunks/facts and the knowledge retraction cascade. Tenant comes from the
/// verified scope handle, never the request body.
async fn forget(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForgetRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(&req.scope_handle)?;
    let retired = state
        .storage
        .forget(payload.tenant_id, req.reference, &req.reason)
        .await
        .map_err(internal)?;
    let (kind, id) = match req.reference {
        ForgetRef::Chunk(id) => ("chunk", id),
        ForgetRef::Episode(id) => ("episode", id),
    };
    spawn_audit(
        &state,
        &payload,
        "forget",
        Some(&format!("{kind}:{id} reason={}", req.reason)),
        vec![id],
    );
    Ok(Json(serde_json::json!({ "retired": retired })))
}

// ---------- admin (trusted plane, bearer-token gated — task 3) ----------

#[derive(Deserialize)]
struct CreateTenantRequest {
    name: String,
}

async fn create_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateTenantRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let id = state
        .storage
        .create_tenant(&req.name)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "tenant_id": id })))
}

/// GET /v1/admin/tenants/{id} (admin, FTUE §2.1): confirm one tenant id names a
/// REAL space. The picker/wizard call this when a pasted or deep-linked id is
/// absent from the (possibly truncated) directory page — a `200` proves the
/// space exists and is safe to adopt (returning its human name for the "loaded
/// by id" label), a `404` is the definitive ghost-tenant hard stop. Gated
/// exactly like the directory read.
async fn get_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<TenantId>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    match state
        .storage
        .get_tenant(tenant_id)
        .await
        .map_err(storage_status)?
    {
        Some(t) => Ok(Json(serde_json::json!({
            "tenant_id": t.tenant_id,
            "name": t.name,
            "created_at": t.created_at,
        }))),
        None => Err((
            StatusCode::NOT_FOUND,
            "no tenant with that id on this server".into(),
        )),
    }
}

#[derive(Deserialize)]
struct ListTenantsQuery {
    /// Picker page cap; clamped to [1, 1000] server-side.
    #[serde(default = "default_tenant_limit")]
    limit: i64,
}

fn default_tenant_limit() -> i64 {
    100
}

/// GET /v1/admin/tenants (admin, FTUE §2.1): the tenant directory. The console
/// derives first-run state from this on every load — `200` + empty list means
/// virgin server (State A), non-empty feeds the picker (State B), `401` is the
/// locked admin plane (State C). Gated exactly like the POST.
async fn list_tenants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListTenantsQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let limit = q.limit.clamp(1, 1000);
    let tenants = state
        .storage
        .list_tenants(limit)
        .await
        .map_err(storage_status)?;
    let count = tenants.len();
    // `count` is the page size (FTUE contract); `total` is the whole table,
    // so the picker can disclose truncation instead of passing as complete.
    let total = state
        .storage
        .count_tenants()
        .await
        .map_err(storage_status)?;
    Ok(Json(serde_json::json!({
        "tenants": tenants,
        "count": count,
        "total": total,
    })))
}

#[derive(Deserialize)]
struct PrincipalsRequest {
    tenant_id: TenantId,
    principals: Vec<String>,
}

/// Map principal strings to materialized int tokens, allocating where absent.
/// Allocation is max(token)+1 per tenant inside one transaction (serialized
/// by a per-tenant advisory lock); existing principals keep their token
/// forever — idempotent. Shared by POST /v1/admin/principals, identity-
/// resolved open_scope, and the group plane (task 10).
pub(crate) async fn upsert_principal_tokens(
    pool: &sqlx::PgPool,
    tenant_id: TenantId,
    principals: &[String],
) -> HandlerResult<Vec<(String, PrincipalToken)>> {
    let mut tx = pool.begin().await.map_err(internal)?;
    // Serialize concurrent allocators for the same tenant so max(token)+1
    // can't race the UNIQUE (tenant_id, token) constraint into an error.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text))")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let mut mappings = Vec::with_capacity(principals.len());
    for principal in principals {
        let existing: Option<i32> = sqlx::query_scalar(
            "SELECT token FROM principals WHERE tenant_id = $1 AND principal = $2",
        )
        .bind(tenant_id)
        .bind(principal)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        let token = match existing {
            Some(t) => t,
            None => {
                let next: i32 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(token), 0) + 1 FROM principals WHERE tenant_id = $1",
                )
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?;
                sqlx::query(
                    "INSERT INTO principals (tenant_id, principal, token) VALUES ($1, $2, $3)",
                )
                .bind(tenant_id)
                .bind(principal)
                .bind(next)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
                next
            }
        };
        mappings.push((principal.clone(), token));
    }
    tx.commit().await.map_err(internal)?;
    Ok(mappings)
}

/// POST /v1/admin/principals (admin): connector-facing principal→token upsert.
async fn admin_principals(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PrincipalsRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let mappings: serde_json::Map<String, serde_json::Value> =
        upsert_principal_tokens(state.pool(), req.tenant_id, &req.principals)
            .await?
            .into_iter()
            .map(|(p, t)| (p, serde_json::json!(t)))
            .collect();
    Ok(Json(serde_json::json!({ "mappings": mappings })))
}

#[derive(Deserialize)]
struct ListPrincipalsQuery {
    tenant_id: TenantId,
    /// Keyset cursor: return rows with `token > after_token` (tokens are
    /// allocated from 1, so the default 0 starts at the beginning).
    #[serde(default)]
    after_token: PrincipalToken,
    /// Page size, clamped to 1..=1000.
    #[serde(default = "default_principals_limit")]
    limit: i64,
}

fn default_principals_limit() -> i64 {
    500
}

/// GET /v1/admin/principals (admin): LIST the tenant's principal directory —
/// the string ↔ materialized-token map the POST upsert writes (UI-ACTIONS N5).
/// Ordered by token, keyset-paginated (`after_token`, `limit`); the response's
/// `next_after_token` is non-null when another page may exist. Read-only and
/// admin-bearer-gated; the token map never renders in any scope-handle
/// context, and an unknown tenant simply reads as empty — nothing is created.
async fn admin_list_principals(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListPrincipalsQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let limit = q.limit.clamp(1, 1000);
    let rows = state
        .storage
        .inner()
        .list_principals(q.tenant_id, q.after_token, limit)
        .await
        .map_err(internal)?;
    // A full page means more MAY exist; the client walks until a short page.
    let next_after_token = if rows.len() as i64 == limit {
        rows.last().map(|(_, t)| *t)
    } else {
        None
    };
    let principals: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(principal, token)| serde_json::json!({ "principal": principal, "token": token }))
        .collect();
    let count = principals.len();
    Ok(Json(serde_json::json!({
        "tenant_id": q.tenant_id,
        "principals": principals,
        "count": count,
        "next_after_token": next_after_token,
    })))
}

// ---------- admin: group membership (task 10 — the tuple plane) ----------

#[derive(Deserialize)]
struct GroupMembershipRequest {
    tenant_id: TenantId,
    /// `"group:sales"` — SpiceDB object ids are tenant-prefixed server-side
    /// (`group:<tenant>_sales`), so tenants can never cross even in a shared
    /// SpiceDB (see rebac.rs).
    group: String,
    /// `"user:alice@corp.example"` or `"group:inner"` (nested).
    member: String,
}

fn parse_membership(
    req: &GroupMembershipRequest,
) -> HandlerResult<(&str, rebac::PrincipalKind, &str)> {
    let Some((rebac::PrincipalKind::Group, group_name)) = rebac::parse_principal(&req.group) else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "group must be \"group:<name>\"".into(),
        ));
    };
    let Some((member_kind, member_name)) = rebac::parse_principal(&req.member) else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "member must be \"user:<id>\" or \"group:<name>\"".into(),
        ));
    };
    if member_kind == rebac::PrincipalKind::Group && member_name == group_name {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "a group cannot be a member of itself".into(),
        ));
    }
    Ok((group_name, member_kind, member_name))
}

fn require_rebac(state: &AppState) -> HandlerResult<&Rebac> {
    state.rebac.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "group management requires ReBAC (set VERITY_SPICEDB_URL)".into(),
    ))
}

// ==========================================================================
//  Permission Graph — admin/operator plane (permission-graph-viz).
//
//  Two READ-ONLY god-view endpoints. INVARIANTS (spec §2, §5):
//    • First line of EVERY handler: `state.admin.require(&headers)?` — the
//      no-dev-open 401-when-unset variant (NEVER `check`).
//    • `require_rebac(&state)?` → 503 when ReBAC is unset.
//    • tenant_id is a mandatory leading predicate; unknown tenant 404s.
//    • They MUST NOT call `enforce_restricted`, `current_token_set`,
//      `scope_for`, or `storage.recall`, and are never referenced from
//      recall/get. The in-window revocation subtraction is re-implemented
//      INLINE (a `revocations`-table read via `windowed_revoked_tokens`) so it
//      matches the read path WITHOUT sharing `scope_for`.
//    • Metadata only: no chunk `content` is ever selected or returned (NG2).
//    • Fail-closed: empty/unresolvable subject → empty token set → empty
//      aggregate (never "show everything"); visibility={} is invisible.
//    • Every query writes one append-only `admin_access_audit` row (0034).
// ==========================================================================

#[derive(Deserialize)]
struct AccessSubjectQuery {
    tenant_id: TenantId,
    subject: String,
    #[serde(default)]
    max_confidentiality: Option<i16>,
    #[serde(default)]
    include_facts: Option<bool>,
    #[serde(default)]
    docs_limit: Option<i64>,
    /// `(valid_from, id)` stored-column keyset cursor, formatted
    /// `<rfc3339>|<uuid>` (matches `documents.next_after`).
    #[serde(default)]
    docs_after: Option<String>,
}

/// Parse a `<rfc3339>|<uuid>` docs cursor into the stored-column keyset.
fn parse_docs_after(raw: &str) -> HandlerResult<(DateTime<Utc>, uuid::Uuid)> {
    let (ts, id) = raw.split_once('|').ok_or((
        StatusCode::BAD_REQUEST,
        "docs_after must be \"<rfc3339>|<uuid>\"".to_string(),
    ))?;
    let ts = DateTime::parse_from_rfc3339(ts.trim())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "docs_after timestamp is not RFC3339".to_string(),
            )
        })?
        .with_timezone(&Utc);
    let id = uuid::Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "docs_after id is not a uuid".to_string(),
        )
    })?;
    Ok((ts, id))
}

/// GET /v1/admin/access/subject — "what does subject X see?" (spec §3).
async fn admin_access_subject(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AccessSubjectQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    // 1. Gate (no dev-open) + ReBAC + tenant existence.
    state.admin.require(&headers)?;
    let rebac = require_rebac(&state)?;
    if state
        .storage
        .get_tenant(q.tenant_id)
        .await
        .map_err(storage_status)?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            "no tenant with that id on this server".into(),
        ));
    }
    let pg = state.storage.inner();
    let max_conf = q.max_confidentiality.unwrap_or(3).clamp(0, 3);
    let include_facts = q.include_facts.unwrap_or(true);
    let docs_limit = q.docs_limit.unwrap_or(50).clamp(1, 200);
    let gateway = |e: rebac::RebacError| (StatusCode::BAD_GATEWAY, format!("spicedb: {e}"));

    // Parse the subject like parse_membership. Only user:/group: are valid.
    let Some((subject_kind, subject_name)) = rebac::parse_principal(&q.subject) else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "subject must be \"user:<id>\" or \"group:<name>\"".into(),
        ));
    };

    // 2. Forward closure (live ReBAC). Build closure nodes/edges: subject +
    //    each group it transitively belongs to, with stepwise ancestor edges.
    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut edges: Vec<serde_json::Value> = Vec::new();
    let mut closure_principals: Vec<String> = vec![q.subject.clone()];

    // The subject's transitive group set.
    let groups: Vec<String> = match subject_kind {
        rebac::PrincipalKind::User => rebac
            .user_groups(q.tenant_id, subject_name)
            .await
            .map_err(gateway)?,
        rebac::PrincipalKind::Group => rebac
            .group_and_ancestors(q.tenant_id, subject_name)
            .await
            .map_err(gateway)?,
    };
    for g in &groups {
        if !closure_principals.contains(g) {
            closure_principals.push(g.clone());
        }
    }

    // Resolve every closure principal to a token in one query (fail-closed:
    // principals with no materialized token simply don't appear).
    let resolved: Vec<(String, PrincipalToken)> = pg
        .resolve_principals(q.tenant_id, &closure_principals)
        .await
        .map_err(storage_status)?;
    let token_of: std::collections::HashMap<String, PrincipalToken> =
        resolved.iter().cloned().collect();
    let subject_resolved = token_of.contains_key(&q.subject) || !groups.is_empty();

    // Subject node.
    nodes.push(serde_json::json!({
        "id": q.subject,
        "kind": subject_kind.object_type(),
        "label": subject_name,
        "token": token_of.get(&q.subject),
    }));
    // Group nodes + stepwise edges (subject → group; group → ancestor group).
    // Bounded to CLOSURE_NODE_CAP; beyond it we collapse and flag.
    const CLOSURE_NODE_CAP: usize = 400;
    let mut closure_truncated = false;
    for (i, g) in groups.iter().enumerate() {
        if i >= CLOSURE_NODE_CAP {
            closure_truncated = true;
            break;
        }
        let name = g.strip_prefix("group:").unwrap_or(g);
        nodes.push(serde_json::json!({
            "id": g,
            "kind": "group",
            "label": name,
            "token": token_of.get(g),
        }));
        edges.push(serde_json::json!({
            "from": q.subject, "to": g, "relation": "member",
        }));
    }

    // 3. Resolve → tokens, then subtract in-window revocations INLINE (parity
    //    with scope_for; NOT by calling scope_for). A revocations-table read.
    let mut tokens: Vec<PrincipalToken> = resolved.iter().map(|(_, t)| *t).collect();
    tokens.sort_unstable();
    tokens.dedup();
    let revoked: Vec<PrincipalToken> = pg
        .windowed_revoked_tokens(q.tenant_id, state.revocations.window_secs())
        .await
        .map_err(storage_status)?;
    let revocation_window_active = tokens.iter().any(|t| revoked.contains(t));
    tokens.retain(|t| !revoked.contains(t));

    // 4. Corpus aggregate (3× GROUP BY + total) over the post-revocation token
    //    set, with the enforcement pre-filter predicate. Statement-timeout
    //    bounded; empty tokens → empty corpus (fail-closed inside the method).
    let (corpus, approximate_counts) = pg
        .access_corpus_aggregate(
            q.tenant_id,
            &tokens,
            max_conf,
            include_facts,
            ACCESS_STATEMENT_TIMEOUT_MS,
        )
        .await
        .map_err(storage_status)?;

    // 5. Grant-confidence: normalize by_provenance chunk counts to fractions.
    let prov_total: i64 = corpus.by_provenance.iter().map(|c| c.chunks).sum();
    let mut grant_confidence = serde_json::Map::new();
    for lane in ["mirrored", "approximated", "admin-assigned", "quarantined"] {
        let n: i64 = corpus
            .by_provenance
            .iter()
            .filter(|c| c.key == lane)
            .map(|c| c.chunks)
            .sum();
        let frac = if prov_total > 0 {
            n as f64 / prov_total as f64
        } else {
            0.0
        };
        grant_confidence.insert(lane.to_string(), serde_json::json!(frac));
    }
    grant_confidence.insert("basis".to_string(), serde_json::json!("chunks"));

    // 6. Documents page (stored (valid_from,id) keyset; page-local rollup).
    let after = match q.docs_after.as_deref() {
        Some(raw) if !raw.is_empty() => Some(parse_docs_after(raw)?),
        _ => None,
    };
    // Fetch a chunk page with fan-out headroom, then roll up per-document.
    let chunk_page = docs_limit * 4;
    let rows = pg
        .access_documents_page(q.tenant_id, &tokens, max_conf, after, chunk_page)
        .await
        .map_err(storage_status)?;
    let next_after = rows
        .last()
        .map(|r| format!("{}|{}", r.valid_from.to_rfc3339(), r.id));
    // Page-local per-document rollup (order-preserving).
    let mut doc_order: Vec<String> = Vec::new();
    let mut doc_rollup: std::collections::HashMap<String, (String, i32, DateTime<Utc>, i64)> =
        std::collections::HashMap::new();
    for r in &rows {
        match doc_rollup.get_mut(&r.document_id) {
            Some(entry) => {
                entry.1 = entry.1.min(r.confidentiality);
                if r.valid_from > entry.2 {
                    entry.2 = r.valid_from;
                }
                entry.3 += 1;
            }
            None => {
                doc_order.push(r.document_id.clone());
                doc_rollup.insert(
                    r.document_id.clone(),
                    (r.source.clone(), r.confidentiality, r.valid_from, 1),
                );
            }
        }
    }
    let doc_items: Vec<serde_json::Value> = doc_order
        .iter()
        .map(|id| {
            let (source, min_conf, last_seen, n) = &doc_rollup[id];
            serde_json::json!({
                "document_id": id,
                "source": source,
                "min_confidentiality": min_conf,
                "last_seen": last_seen.to_rfc3339(),
                "n_chunks": n,
                "page_local": true,
            })
        })
        .collect();

    // 7. Audit (counts only, NG2) then respond.
    let params = serde_json::json!({
        "max_confidentiality": max_conf,
        "include_facts": include_facts,
        "docs_limit": docs_limit,
    });
    let result_meta = serde_json::json!({
        "total_chunks": corpus.total_chunks,
        "total_docs": corpus.total_docs,
        "closure_nodes": nodes.len(),
        "tokens": tokens.len(),
    });
    pg.write_access_audit(
        q.tenant_id,
        &state.admin.actor_fingerprint(&headers),
        "access/subject",
        &q.subject,
        &params,
        &result_meta,
    )
    .await
    .map_err(storage_status)?;

    let by_source: Vec<serde_json::Value> = corpus
        .by_source
        .iter()
        .map(|c| serde_json::json!({ "source": c.key, "chunks": c.chunks, "docs": c.docs }))
        .collect();
    let by_conf: Vec<serde_json::Value> = corpus
        .by_confidentiality
        .iter()
        .map(|c| serde_json::json!({ "level": c.level, "chunks": c.chunks, "docs": c.docs }))
        .collect();
    let by_prov: Vec<serde_json::Value> = corpus
        .by_provenance
        .iter()
        .map(|c| serde_json::json!({ "provenance": c.key, "chunks": c.chunks, "docs": c.docs }))
        .collect();

    Ok(Json(serde_json::json!({
        "tenant_id": q.tenant_id,
        "subject": q.subject,
        "subject_resolved": subject_resolved,
        "closure": { "nodes": nodes, "edges": edges },
        "tokens": tokens,
        "corpus": {
            "total": { "chunks": corpus.total_chunks, "docs": corpus.total_docs },
            "by_source": by_source,
            "by_confidentiality": by_conf,
            "by_provenance": by_prov,
        },
        "grant_confidence": grant_confidence,
        "documents": { "items": doc_items, "next_after": next_after },
        "flags": {
            "approximate_counts": approximate_counts,
            "closure_truncated": closure_truncated,
            "revocation_window_active": revocation_window_active,
        },
    })))
}

#[derive(Deserialize)]
struct AccessObjectQuery {
    tenant_id: TenantId,
    #[serde(default)]
    document_id: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    entity: Option<String>,
    #[serde(default)]
    users_limit: Option<usize>,
}

/// GET /v1/admin/access/object — "who can see object Y?" (spec §4).
async fn admin_access_object(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AccessObjectQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.require(&headers)?;
    let rebac = require_rebac(&state)?;
    if state
        .storage
        .get_tenant(q.tenant_id)
        .await
        .map_err(storage_status)?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            "no tenant with that id on this server".into(),
        ));
    }
    let pg = state.storage.inner();
    let gateway = |e: rebac::RebacError| (StatusCode::BAD_GATEWAY, format!("spicedb: {e}"));
    let users_limit = q.users_limit.unwrap_or(1000).clamp(1, 10_000);

    // Exactly one selector.
    let (selector, obj_kind, obj_id): (verity_storage::ObjectSelector, &str, String) =
        match (&q.document_id, &q.source, &q.entity) {
            (Some(d), None, None) if !d.is_empty() => (
                verity_storage::ObjectSelector::Document(d),
                "document",
                d.clone(),
            ),
            (None, Some(s), None) if !s.is_empty() => (
                verity_storage::ObjectSelector::Source(s),
                "source",
                s.clone(),
            ),
            (None, None, Some(e)) if !e.is_empty() => (
                verity_storage::ObjectSelector::Entity(e),
                "entity",
                e.clone(),
            ),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "exactly one of document_id / source / entity is required".into(),
                ))
            }
        };

    // 2. Object → visibility tokens decode (bounded; source/entity gated).
    let decode = pg
        .access_object_tokens(
            q.tenant_id,
            selector,
            ACCESS_STATEMENT_TIMEOUT_MS,
            ACCESS_OBJECT_CORPUS_CEILING,
        )
        .await
        .map_err(storage_status)?;
    if decode.refused_over_ceiling {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "source/entity mode is refused above the corpus ceiling until a supporting index exists — query by document_id".into(),
        ));
    }

    // 3. Tokens → principal strings (BUILD 4a).
    let resolved: Vec<(PrincipalToken, String)> = pg
        .resolve_tokens(q.tenant_id, &decode.tokens)
        .await
        .map_err(storage_status)?;
    let principals: Vec<serde_json::Value> = resolved
        .iter()
        .map(|(tok, p)| {
            let kind = if p.starts_with("group:") {
                "group"
            } else if p.starts_with("user:") {
                "user"
            } else {
                "other"
            };
            serde_json::json!({ "token": tok, "principal": p, "kind": kind })
        })
        .collect();

    // 4 + 5. Group principals → reachable users, RETAINING the granting group
    //    path (BUILD 4b). Direct user: principals are terminal.
    let group_principals: Vec<String> = resolved
        .iter()
        .filter(|(_, p)| p.starts_with("group:"))
        .map(|(_, p)| p.clone())
        .collect();
    let (via_users, fanout_truncated) = rebac
        .users_reachable_via_groups(q.tenant_id, &group_principals, users_limit)
        .await
        .map_err(gateway)?;

    // Direct users carried on the object (a user: token on the chunk).
    let direct_users: std::collections::HashSet<String> = resolved
        .iter()
        .filter(|(_, p)| p.starts_with("user:"))
        .map(|(_, p)| p.clone())
        .collect();

    let mut reachable: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (user, via_groups) in &via_users {
        seen.insert(user.clone());
        let via: Vec<Vec<String>> = via_groups.iter().map(|g| vec![g.clone()]).collect();
        reachable.push(serde_json::json!({
            "user": user,
            "via": via,
            "direct": direct_users.contains(user),
        }));
    }
    // Direct users not reached via any group still appear (their own token).
    for u in &direct_users {
        if !seen.contains(u) {
            reachable.push(serde_json::json!({
                "user": u,
                "via": Vec::<Vec<String>>::new(),
                "direct": true,
            }));
        }
    }

    // 6. Audit (counts only) then respond.
    let params = serde_json::json!({ "mode": obj_kind });
    let result_meta = serde_json::json!({
        "visibility_tokens": decode.tokens.len(),
        "principals": principals.len(),
        "reachable_users": reachable.len(),
    });
    pg.write_access_audit(
        q.tenant_id,
        &state.admin.actor_fingerprint(&headers),
        "access/object",
        &obj_id,
        &params,
        &result_meta,
    )
    .await
    .map_err(storage_status)?;

    let provenance = if decode.provenance.len() == 1 {
        serde_json::json!(decode.provenance[0])
    } else {
        serde_json::json!(decode.provenance)
    };

    Ok(Json(serde_json::json!({
        "tenant_id": q.tenant_id,
        "object": { "kind": obj_kind, "id": obj_id },
        "visibility_tokens": decode.tokens,
        "confidentiality": decode.min_confidentiality,
        "provenance": provenance,
        "principals": principals,
        "reachable_users": reachable,
        "reachable_users_next_after": serde_json::Value::Null,
        "flags": {
            "approximate": decode.approximate,
            "fanout_truncated": fanout_truncated,
        },
    })))
}

/// Bound on the Permission Graph aggregate/decode scans (BUILD ITEM 7):
/// `SET LOCAL statement_timeout` in the same transaction, so a low-selectivity
/// company-wide token set (or a corpus-spanning source/entity decode) degrades
/// to an `approximate` result instead of hanging a pooled connection.
const ACCESS_STATEMENT_TIMEOUT_MS: i64 = 4000;

/// Corpus-size ceiling above which unindexed `source`/`entity` object decode is
/// refused (§4.4/§6). `document_id` mode is exempt.
const ACCESS_OBJECT_CORPUS_CEILING: i64 = 2_000_000;

/// POST /v1/admin/groups (admin): write a membership tuple. The group's
/// principal token is allocated eagerly so visibility sets and revocation
/// tombstones can reference it.
async fn admin_group_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GroupMembershipRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let rebac = require_rebac(&state)?;
    let (group_name, member_kind, member_name) = parse_membership(&req)?;
    let mappings = upsert_principal_tokens(
        state.pool(),
        req.tenant_id,
        &[req.group.clone(), req.member.clone()],
    )
    .await?;
    rebac
        .write_membership(req.tenant_id, group_name, member_kind, member_name)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("spicedb write failed: {e}"),
            )
        })?;
    let tokens: serde_json::Map<String, serde_json::Value> = mappings
        .into_iter()
        .map(|(p, t)| (p, serde_json::json!(t)))
        .collect();
    Ok(Json(
        serde_json::json!({ "written": true, "tokens": tokens }),
    ))
}

/// DELETE /v1/admin/groups (admin): remove a membership tuple, writing
/// revocation tombstones FIRST (fail-closed ordering — a failure here aborts
/// the delete and over-hides, never under-hides).
///
/// Conservative resolution: the removed member subtree (the user, or every
/// transitive user of the removed inner group) loses the group principal and
/// all its transitive ancestors. Tombstone semantics are tenant-wide token
/// subtraction for the revocation window — see revocation.rs.
async fn admin_group_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GroupMembershipRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let rebac = require_rebac(&state)?;
    let (group_name, member_kind, member_name) = parse_membership(&req)?;
    let gateway = |e: rebac::RebacError| (StatusCode::BAD_GATEWAY, format!("spicedb: {e}"));

    // 1. Resolve — while the tuple graph still holds — who loses what.
    let affected: Vec<String> = match member_kind {
        rebac::PrincipalKind::User => vec![req.member.clone()],
        rebac::PrincipalKind::Group => {
            let mut users = rebac
                .group_users(req.tenant_id, member_name)
                .await
                .map_err(gateway)?;
            // The inner group itself is part of the removed subtree; record
            // it even when it currently has no user members.
            users.push(req.member.clone());
            users
        }
    };
    let lost_principals = rebac
        .group_and_ancestors(req.tenant_id, group_name)
        .await
        .map_err(gateway)?;
    // Only principals that ever materialized a token can appear in a
    // visibility set or a handle; unmaterialized ones have nothing to revoke.
    let lost_tokens: Vec<(String, PrincipalToken)> = {
        let rows: Vec<(String, i32)> = sqlx::query_as(
            "SELECT principal, token FROM principals
             WHERE tenant_id = $1 AND principal = ANY($2)",
        )
        .bind(req.tenant_id)
        .bind(&lost_principals)
        .fetch_all(state.pool())
        .await
        .map_err(internal)?;
        rows
    };

    // 2. Durable tombstones BEFORE the tuple delete.
    let tombstones = state
        .revocations
        .record(state.pool(), req.tenant_id, &affected, &lost_tokens)
        .await?;

    // 3. Remove the tuple.
    rebac
        .delete_membership(req.tenant_id, group_name, member_kind, member_name)
        .await
        .map_err(gateway)?;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "tombstones": tombstones,
        "revoked_principals": lost_tokens.iter().map(|(p, _)| p).collect::<Vec<_>>(),
        "affected_members": affected,
    })))
}

#[derive(Deserialize)]
struct GroupMembersQuery {
    tenant_id: TenantId,
    /// `"group:sales"` — same shape rule as the write endpoints (422 otherwise).
    group: String,
}

/// GET /v1/admin/groups/members (admin): the membership roster read.
///
/// `direct` is the EDITABLE roster — one row per exact SpiceDB tuple, so each
/// row is precisely what DELETE /v1/admin/groups removes; nested groups appear
/// as one `kind: "group"` row, unresolved. `people_total` is the TRANSITIVE
/// user count (nested groups resolved, same closure as revocation uses) — the
/// UI must label it as such. An empty roster is a 200 with `direct: []` —
/// valid truth, never an error.
///
/// Tenant handling deliberately differs from the writes: a READ must never
/// create a tenant, so an unknown id 404s (like GET /v1/admin/tenants/{id})
/// instead of `ensure_tenant`.
async fn admin_group_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<GroupMembersQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if state
        .storage
        .get_tenant(q.tenant_id)
        .await
        .map_err(storage_status)?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            "no tenant with that id on this server".into(),
        ));
    }
    let rebac = require_rebac(&state)?;
    let Some((rebac::PrincipalKind::Group, group_name)) = rebac::parse_principal(&q.group) else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "group must be \"group:<name>\"".into(),
        ));
    };
    let gateway = |e: rebac::RebacError| (StatusCode::BAD_GATEWAY, format!("spicedb: {e}"));

    // Sorted and deduped inside group_direct_members (fail-closed parsing too).
    let direct: Vec<serde_json::Value> = rebac
        .group_direct_members(q.tenant_id, group_name)
        .await
        .map_err(gateway)?
        .into_iter()
        .map(|(kind, name)| {
            serde_json::json!({
                "member": format!("{}:{name}", kind.object_type()),
                "kind": kind.object_type(),
            })
        })
        .collect();
    // Transitive user closure — the honest "how many people can this key
    // reach" number, distinct from the editable tuple list above.
    let people_total = rebac
        .group_users(q.tenant_id, group_name)
        .await
        .map_err(gateway)?
        .len();

    Ok(Json(serde_json::json!({
        "group": format!("group:{group_name}"),
        "direct": direct,
        "people_total": people_total,
        "read_at": Utc::now().to_rfc3339(),
    })))
}

// ---------- brief ----------

#[derive(Deserialize)]
struct BriefQuery {
    scope_handle: String,
}

/// On-read refresh debounce (SPEC §2: "recompute lazily"): a stale brief older
/// than this since its last sync is refreshed on read; a stale brief refreshed
/// more recently serves its cached body and defers to the batch/sleep-time
/// path, so a hot entity under write pressure doesn't refresh on every GET.
const BRIEF_REFRESH_DEBOUNCE_SECS: i64 = 5;

/// The entity brief (SPEC §2 L3): current state of an entity in one call —
/// newest memory + recent agent activity + L3 staleness metadata.
///
/// SCOPE SOUNDNESS (the load-bearing decision): the materialized `briefs` row
/// is computed under a BROAD materialization scope, so it must NEVER be served
/// as items. Instead:
///   - `recent_memory` / `recent_activity` are re-derived HERE under the
///     CALLER's scope via the same scoped `latest_chunks`/`activity` +
///     restricted recheck that `recall` uses — so a caller can never see an
///     item their scope excludes (the fuzzer's brief predicate holds by
///     construction: these are the exact scoped read paths it already probes).
///   - the materialized row supplies ONLY metadata (`is_stale`,
///     `last_synced_at`, `source_version`) and a cached `summary`.
///   - derived-scope inheritance (SPEC §2): the cached `summary` is gated by
///     the brief's `source_visibility` = INTERSECTION of contributing source
///     visibilities. A caller missing from ANY source cannot see the
///     brief-level summary (it is withheld: `summary: null`), even though they
///     may still see the subset of individual items their own scope admits.
async fn brief(
    State(state): State<Arc<AppState>>,
    Path(entity): Path<String>,
    axum::extract::Query(q): axum::extract::Query<BriefQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(&q.scope_handle)?;
    let scope = state.scope_for(&payload).await?;

    // Lazy materialization: fetch (or first-time create) the brief row, then
    // refresh if stale and past the debounce window. Refresh recomputes the
    // metadata + cached summary; it is not on the item-serving path.
    let materialized = state
        .storage
        .get_brief(scope.tenant_id, &entity)
        .await
        .map_err(internal)?;
    let materialized = match materialized {
        None => Some(
            state
                .storage
                .refresh_brief(scope.tenant_id, &entity)
                .await
                .map_err(internal)?,
        ),
        Some(b) if b.is_stale && brief_refresh_due(&b) => Some(
            state
                .storage
                .refresh_brief(scope.tenant_id, &entity)
                .await
                .map_err(internal)?,
        ),
        Some(b) => Some(b),
    };

    // Items always served under the CALLER's scope (no materialized item ever
    // leaves this handler).
    let (memory, actions) = tokio::join!(
        state.storage.latest_chunks(&scope, &entity, 10),
        state.storage.activity(ActivityQuery {
            scope: scope.clone(),
            entity: entity.clone(),
            since: None,
            action_types: vec![],
            actors: vec![],
            limit: 10,
        })
    );
    let memory = memory.map_err(internal)?;
    // Restricted-class recheck applies to the brief's memory leg exactly as
    // to recall (SPEC §7b rule 4).
    let memory = revocation::enforce_restricted(&state, &payload, memory).await?;
    let actions = actions.map_err(internal)?;

    // Derived-scope inheritance gate on the cached summary (SPEC §2): the
    // summary is visible only to a caller whose principals intersect the
    // brief's source_visibility (the intersection of ALL contributing
    // sources). Empty source_visibility => visible to nobody (fail-closed).
    let (is_stale, last_synced_at, source_version, summary) = match &materialized {
        Some(b) => {
            let visible = b
                .source_visibility
                .iter()
                .any(|t| scope.principals.contains(t));
            let summary = if visible {
                b.body
                    .get("memory_count")
                    .zip(b.body.get("activity_count"))
                    .map(|(m, a)| serde_json::json!({ "memory_count": m, "activity_count": a }))
            } else {
                None
            };
            (b.is_stale, b.last_synced_at, b.source_version, summary)
        }
        None => (true, None, 0, None),
    };

    spawn_audit(
        &state,
        &payload,
        "brief",
        Some(&entity),
        memory
            .iter()
            .map(|h| h.chunk_id)
            .chain(actions.iter().map(|a| a.id))
            .collect(),
    );
    Ok(Json(serde_json::json!({
        "entity": entity,
        "generated_at": Utc::now(),
        "recent_memory": memory,
        "recent_activity": actions,
        // L3 staleness metadata (SPEC §2: returned on every read).
        "is_stale": is_stale,
        "last_synced_at": last_synced_at,
        "source_version": source_version,
        // Cached brief-level summary, gated by derived-scope inheritance; null
        // when the caller isn't in the intersection of all contributing sources.
        "summary": summary,
        // L1 record linkage lands with cross-source entity resolution (§7f).
    })))
}

/// A stale brief is refreshed on read only if it hasn't synced within the
/// debounce window (or never synced).
fn brief_refresh_due(b: &verity_core::types::MaterializedBrief) -> bool {
    match b.last_synced_at {
        None => true,
        Some(t) => (Utc::now() - t).num_seconds() >= BRIEF_REFRESH_DEBOUNCE_SECS,
    }
}

// ---------- admin: L3 brief batch refresh (the sleep-time path) ----------

#[derive(Deserialize)]
struct AdminTenantParam {
    tenant: TenantId,
}

/// POST /v1/admin/briefs/refresh?tenant= — recompute every stale brief for a
/// tenant (SPEC §2 L3 sleep-time recompute). Admin-gated. Returns the count.
async fn admin_refresh_briefs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<AdminTenantParam>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(p.tenant)
        .await
        .map_err(storage_status)?;
    let refreshed = state
        .storage
        .refresh_stale_briefs(p.tenant)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "refreshed": refreshed })))
}

// ---------- admin: embedding-migration tooling (SPEC §5c) ----------

#[derive(Deserialize)]
struct ReembedBatchRequest {
    /// Target model id; registered on first batch (idempotent).
    model: String,
    /// Restrict to one tenant, else backfill across all tenants.
    #[serde(default)]
    tenant: Option<TenantId>,
    #[serde(default = "default_reembed_batch")]
    batch: i64,
}

fn default_reembed_batch() -> i64 {
    256
}

/// POST /v1/admin/reembed/batch — the encoder lives in the server, so the CLI
/// drives batches and the server re-embeds. Walks up to `batch` current chunks
/// lacking `embedding_v2`, re-encodes each from its stored canonical text
/// (SPEC §5c: re-embed, never re-fetch), and fills `embedding_v2`. Returns
/// counts + remaining coverage so the CLI can loop and show progress. Requires
/// the local encoder (503 when sparse-only).
async fn admin_reembed_batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ReembedBatchRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if state.encoder.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "reembed requires the local encoder; this server is sparse-only".into(),
        ));
    }
    if let Some(tenant) = req.tenant {
        state
            .storage
            .inner()
            .ensure_tenant(tenant)
            .await
            .map_err(storage_status)?;
    }
    // Dims match today (both 384); register the target so the registry + the
    // per-chunk model marker are honest. A true dim change needs a wider
    // column (docs/EMBEDDING_MIGRATION.md).
    state
        .storage
        .register_embedding_model(&req.model, verity_encoder::DIM as i32)
        .await
        .map_err(internal)?;

    let pending = state
        .storage
        .chunks_needing_v2(req.tenant, req.batch.clamp(1, 10_000))
        .await
        .map_err(internal)?;

    let mut filled_rows: Vec<(ChunkId, Vec<f32>)> = Vec::with_capacity(pending.len());
    for (id, content) in &pending {
        if let Some(vec) = state.encode(content).await? {
            filled_rows.push((*id, vec));
        }
    }
    let written = state
        .storage
        .fill_embedding_v2(&req.model, &filled_rows)
        .await
        .map_err(internal)?;

    let coverage = state
        .storage
        .embedding_v2_coverage(req.tenant)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "model": req.model,
        "scanned": pending.len(),
        "written": written,
        "coverage": { "total": coverage.total, "covered": coverage.covered,
                      "fraction": coverage.fraction() },
        "done": pending.is_empty(),
    })))
}

#[derive(Deserialize)]
struct CutoverRequest {
    /// Restrict the cutover to one tenant, else flip the global default.
    #[serde(default)]
    tenant: Option<TenantId>,
    /// Route to flip to (default v2 — the point of cutover).
    #[serde(default = "default_cutover_route")]
    route: EmbeddingRoute,
    /// Force the flip below 100% backfill coverage (SPEC §5c: uncovered chunks
    /// fall back to sparse-only for the new route — an explicit acknowledgment).
    #[serde(default)]
    force: bool,
}

fn default_cutover_route() -> EmbeddingRoute {
    EmbeddingRoute::V2
}

/// POST /v1/admin/reembed/cutover — flip the dense query route (SPEC §5c step
/// 2). Coverage-gated: refuses to flip to V2 below 100% backfill unless
/// `force` (which acknowledges uncovered chunks drop to sparse-only for the new
/// route). Flipping back to V1 is always allowed (rollback).
async fn admin_reembed_cutover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CutoverRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if let Some(tenant) = req.tenant {
        state
            .storage
            .inner()
            .ensure_tenant(tenant)
            .await
            .map_err(storage_status)?;
    }
    let coverage = state
        .storage
        .embedding_v2_coverage(req.tenant)
        .await
        .map_err(internal)?;
    if req.route == EmbeddingRoute::V2 && !coverage.is_complete() && !req.force {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "backfill coverage {:.1}% (< 100%); pass force=true to cut over anyway (uncovered chunks fall back to sparse-only for the new route)",
                coverage.fraction() * 100.0
            ),
        ));
    }
    state
        .storage
        .set_embedding_route(req.tenant, req.route)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "route": req.route.as_str(),
        "tenant": req.tenant,
        "coverage": { "total": coverage.total, "covered": coverage.covered,
                      "fraction": coverage.fraction() },
        "forced": req.force && !coverage.is_complete(),
    })))
}

// ---------- knowledge (SPEC v1.3 §2) ----------

#[derive(Deserialize)]
struct ProposeLearningRequest {
    scope_handle: String,
    statement: String,
    #[serde(default)]
    categories: Vec<String>,
    /// Supporting L0 episode ids; attribution is read server-side.
    #[serde(default)]
    evidence: Vec<EpisodeId>,
}

/// A proposal, never a publish: runs the de-identification gate; gate failures
/// are stored quarantined (auditable), gate passes await review + k-support.
async fn propose_learning(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProposeLearningRequest>,
) -> HandlerResult<Json<KnowledgeItem>> {
    let payload = state.verify_scope(&req.scope_handle)?;

    // A bare proposal (no evidence episodes) IS an L0 event: "this agent,
    // scoped to this entity, hypothesized this lesson" — the design's n=1.
    // Materialize it as an Observation episode so the EXISTING evidence
    // attribution machinery counts it. Previously an evidence-less proposal
    // supported nothing (distinct_entities 0), so three customers proposing
    // the identical lesson showed as three clones each claiming no support.
    let mut evidence = req.evidence;
    if evidence.is_empty() {
        let scope_entity = payload.entity_scope.first().cloned();
        let episode = state
            .storage
            .append_episode(NewEpisode {
                tenant_id: payload.tenant_id,
                source: "agent:propose_learning".into(),
                source_entity: scope_entity,
                kind: EpisodeKind::Observation,
                payload: serde_json::json!({
                    "kind": "knowledge_proposal",
                    "statement": req.statement,
                }),
                // Unique per proposal: the same lesson proposed twice by the
                // same scope is two distinct n=1 observations on the record.
                content_hash: format!("propose:{}", uuid::Uuid::now_v7()),
                trust_tier: TrustTier::Observation,
                writer_sub: payload.actor_sub.clone(),
                writer_azp: payload.actor_azp.clone(),
            })
            .await
            .map_err(internal)?;
        evidence.push(episode);
    }

    let item = state
        .storage
        .propose_knowledge(KnowledgeProposal {
            tenant_id: payload.tenant_id,
            statement: req.statement,
            categories: req.categories,
            evidence,
            proposed_by_sub: payload.actor_sub.clone(),
            proposed_by_azp: payload.actor_azp.clone(),
            // The human/agent propose path carries no canonical form; the
            // rejection memory + the exact-statement accrual fast path then
            // match on the exact statement. (The consolidation worker supplies
            // the canonical form for its stronger match.)
            canonical_statement: None,
        })
        .await
        .map_err(internal)?;

    // Same acceptability policy as the consolidation path (§5): a candidate
    // that crossed k-support with corroboration becomes ELIGIBLE — still
    // human-gated, never auto-published from here.
    if item.status == KnowledgeStatus::Candidate
        && item.distinct_entities >= consolidation::K_SUPPORT_MIN
        && (item.writer_count >= 2 || item.has_tier1_evidence)
    {
        let moved = state
            .storage
            .inner()
            .mark_knowledge_eligible(payload.tenant_id, item.id)
            .await
            .map_err(internal)?;
        if moved {
            return state
                .storage
                .inner()
                .get_knowledge(payload.tenant_id, item.id)
                .await
                .map(Json)
                .map_err(internal);
        }
    }
    Ok(Json(item))
}

#[derive(Deserialize)]
struct ListKnowledgeParams {
    tenant_id: TenantId,
    status: Option<KnowledgeStatus>,
}

/// Review queue (admin/audit plane — bearer-token gated, task 3). Each item
/// carries status, the ADMIN-exact distinct_entities, the bucketed
/// support_tier, the judge's merge_reason, and the evidence episode/entity list
/// (knowledge-merge-tuning.md §5). Exact counts and evidence stay behind the
/// admin token; agents only ever see the tier on recall hits.
async fn list_knowledge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListKnowledgeParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let items = state
        .storage
        .list_knowledge(p.tenant_id, p.status)
        .await
        .map_err(internal)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let evidence = state
            .storage
            .inner()
            .knowledge_evidence(p.tenant_id, item.id)
            .await
            .map_err(internal)?;
        out.push(knowledge_admin_json(&item, evidence, None));
    }
    Ok(Json(serde_json::json!({ "items": out })))
}

/// Shared admin serialization: the item's review-surface fields plus its
/// evidence lineage, and optionally a de-identification gate result.
fn knowledge_admin_json(
    item: &KnowledgeItem,
    evidence: Vec<serde_json::Value>,
    deid_gate: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": item.id,
        "statement": item.statement,
        "categories": item.categories,
        "status": item.status,
        // ADMIN-exact — never surfaced to an agent.
        "distinct_entities": item.distinct_entities,
        // The bucketed disclosure agents would see.
        "support_tier": item.support_tier,
        "episode_count": item.episode_count,
        "writer_count": item.writer_count,
        "has_tier1_evidence": item.has_tier1_evidence,
        "merge_reason": item.merge_reason,
        "quarantine_reason": item.quarantine_reason,
        "first_seen": item.first_seen,
        "last_reinforced": item.last_reinforced,
        "published_at": item.published_at,
        "evidence": evidence,
    });
    if let Some(gate) = deid_gate {
        v["deid_gate"] = gate;
    }
    v
}

/// GET /v1/admin/knowledge/{id} — the full review detail for one item
/// (knowledge-merge-tuning.md §5): status, admin-exact support + tier, the
/// judge's merge_reason, the de-identification gate result, and the complete
/// evidence episode/entity list. Bearer-gated.
async fn admin_knowledge_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    axml_tenant: axum::extract::Query<TenantQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let tenant = axml_tenant.0.tenant_id;
    let item = state
        .storage
        .inner()
        .knowledge_item(tenant, id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "no such knowledge item".to_string()))?;
    let evidence = state
        .storage
        .inner()
        .knowledge_evidence(tenant, id)
        .await
        .map_err(internal)?;
    // De-identification gate result: a quarantined item failed it (reason
    // recorded); anything past the gate passed it. Deterministic, auditable.
    let deid_gate = serde_json::json!({
        "passed": item.status != KnowledgeStatus::Quarantined,
        "reason": item.quarantine_reason,
    });
    Ok(Json(knowledge_admin_json(&item, evidence, Some(deid_gate))))
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: TenantId,
}

#[derive(Deserialize)]
struct RejectKnowledgeRequest {
    tenant_id: TenantId,
    #[serde(default)]
    reason: String,
}

/// POST /v1/admin/knowledge/{id}/reject — a reviewer refuses a candidate/
/// eligible item. REMEMBERED (knowledge-merge-tuning.md §5): status becomes
/// 'rejected' with the reason, and the same canonical_statement will not
/// resurrect as a fresh candidate (enforced in propose_knowledge). Rejecting a
/// published item is refused — retraction is `forget`'s job. Bearer-gated.
async fn admin_reject_knowledge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<RejectKnowledgeRequest>,
) -> HandlerResult<Json<KnowledgeItem>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let reason = if req.reason.trim().is_empty() {
        "rejected by reviewer".to_string()
    } else {
        req.reason.trim().to_string()
    };
    state
        .storage
        .inner()
        .reject_knowledge(req.tenant_id, id, &reason)
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or((
            StatusCode::UNPROCESSABLE_ENTITY,
            "no candidate/eligible knowledge item with that id (already published/rejected?)"
                .to_string(),
        ))
}

#[derive(Deserialize)]
struct PublishKnowledgeRequest {
    tenant_id: TenantId,
    /// Broad principal set the published knowledge is visible to.
    visibility: Vec<PrincipalToken>,
    #[serde(default = "default_k_min")]
    k_min: i32,
}

fn default_k_min() -> i32 {
    3
}

async fn publish_knowledge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<PublishKnowledgeRequest>,
) -> HandlerResult<Json<KnowledgeItem>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    // k_min is clamped server-side: k=2 lets either supporting party infer
    // the other's interaction (SPEC v1.3 §2).
    let k_min = req.k_min.max(3);
    // Embed the statement so published knowledge rides the dense leg too.
    let items = state
        .storage
        .list_knowledge(req.tenant_id, Some(KnowledgeStatus::Candidate))
        .await
        .map_err(internal)?;
    let statement = items
        .iter()
        .find(|k| k.id == id)
        .map(|k| k.statement.clone());
    let embedding = match statement {
        Some(s) => state.encode(&s).await.ok().flatten(),
        None => None,
    };
    state
        .storage
        .publish_knowledge(req.tenant_id, id, req.visibility, k_min, embedding)
        .await
        .map(Json)
        .map_err(storage_status)
}

// ---------- admin debug-recall "why-out" trace (UI-SPEC §6 Later; §5 Screen 1
// boundary-trace honesty note). OFF the hot path by construction: a separate
// admin-token-gated endpoint that does the extra per-candidate work the pure
// read path refuses. recall/get are untouched. ----------

#[derive(Deserialize)]
struct DebugRecallRequest {
    /// The scope being debugged — a real, unexpired handle. The trace explains
    /// what THIS boundary admits/drops; an expired or tampered handle fails
    /// closed (401) exactly like the read path.
    scope_handle: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    embedding: Option<Vec<f32>>,
    /// How many tenant-wide top-similarity candidates to trace (default 50,
    /// clamped to 500).
    #[serde(default = "default_debug_candidates")]
    candidates: usize,
}

fn default_debug_candidates() -> usize {
    50
}

fn confidentiality_name(v: i16) -> &'static str {
    match v {
        0 => "public",
        1 => "internal",
        2 => "confidential",
        _ => "restricted",
    }
}

/// POST /v1/admin/debug/recall — per-candidate DROP REASONS for a scope+query.
///
/// Re-runs the query over the tenant's chunks with ONLY the tenant filter,
/// then evaluates each mandatory pre-filter (visibility tokens, entity scope,
/// confidentiality ceiling, staleness) per candidate in the admin plane and
/// names why each near-miss was excluded. Requires BOTH the admin bearer token
/// AND a valid scope handle; every invocation is audited (`verb =
/// "debug_recall"`, result_ids = every chunk id the trace disclosed).
///
/// Honest limits (also returned in the response's `honesty` array):
/// - Filters are evaluated against the index AS OF NOW — this cannot
///   reconstruct why a PAST recall dropped a candidate if visibility/tags/
///   validity changed since.
/// - The candidate set is a similarity top-N under a tenant-only ordering;
///   a chunk outside that top-N (including ANN traversal misses) is not
///   enumerable.
/// - The live restricted-class ReBAC recheck is NOT executed here; restricted
///   candidates are flagged with the recheck outcome the read path WOULD
///   apply structurally (fail-closed drop when ReBAC is off), never re-resolved.
async fn admin_debug_recall(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DebugRecallRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let payload = state.verify_scope(&req.scope_handle)?;
    if req.text.is_none() && req.embedding.is_none() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "debug recall needs text or an embedding".into(),
        ));
    }
    // Same effective principal set as the real read: the handle's tokens minus
    // in-window revocation tombstones.
    let scope = state.scope_for(&payload).await?;
    let revoked: Vec<PrincipalToken> = payload
        .principals
        .iter()
        .copied()
        .filter(|t| !scope.principals.contains(t))
        .collect();

    let embedding = match (req.embedding, &req.text) {
        (Some(e), _) => Some(e),
        (None, Some(text)) => state.encode(text).await?,
        (None, None) => None,
    };
    let leg = if embedding.is_some() { "dense" } else { "bm25" };
    let limit = req.candidates.clamp(1, 500) as i64;
    let candidates = state
        .storage
        .inner()
        .debug_recall_candidates(
            scope.tenant_id,
            embedding.as_deref(),
            req.text.as_deref(),
            limit,
        )
        .await
        .map_err(storage_status)?;

    let ceiling = scope.max_confidentiality as i16;
    let mut traced = Vec::with_capacity(candidates.len());
    let mut all_ids = Vec::with_capacity(candidates.len());
    for c in &candidates {
        all_ids.push(c.chunk_id);
        let mut drop_reasons: Vec<&'static str> = Vec::new();
        let mut notes: Vec<&'static str> = Vec::new();
        // Staleness: superseded/invalidated rows never enter recall.
        if c.valid_to.is_some() {
            drop_reasons.push("stale_superseded");
        }
        // Visibility tokens: empty = invisible (fail closed); otherwise the
        // effective principal set must overlap.
        if c.visibility.is_empty() {
            drop_reasons.push("visibility_empty");
        } else if !c.visibility.iter().any(|t| scope.principals.contains(t)) {
            drop_reasons.push("visibility_no_overlap");
        }
        // Confidentiality ceiling.
        if c.confidentiality > ceiling {
            drop_reasons.push("confidentiality_above_ceiling");
        }
        // Entity scope (deny-by-default subset semantics, §7d; knowledge
        // carve-out §7g).
        if !scope.entity_scope.is_empty() && c.kind != "knowledge" {
            if c.entity_tags.is_empty() {
                drop_reasons.push("entity_scope_untagged");
            } else if !c.entity_tags.iter().all(|t| scope.entity_scope.contains(t)) {
                drop_reasons.push("entity_scope_outside");
            }
        }
        // Restricted-class recheck (SPEC §7b rule 4): mirror the read path's
        // STRUCTURAL behavior without calling ReBAC.
        if c.confidentiality >= Confidentiality::Restricted as i16 && drop_reasons.is_empty() {
            match &state.rebac {
                None if !state.allow_restricted_without_rebac => {
                    drop_reasons.push("restricted_dropped_no_rebac")
                }
                None => notes.push("restricted_served_without_rebac_by_explicit_override"),
                Some(_) => notes.push("restricted_subject_to_live_recheck_not_reproduced_here"),
            }
        }
        let preview: String = c.content.chars().take(240).collect();
        traced.push(serde_json::json!({
            "chunk_id": c.chunk_id,
            "document_id": c.document_id,
            "seq": c.seq,
            "score": c.score,
            "kind": c.kind,
            "entity_tags": c.entity_tags,
            "visibility_token_count": c.visibility.len(),
            // The member tokens themselves, not just the count: the endpoint
            // is admin-gated and audited, and the console names tokens via
            // GET /v1/admin/principals (UI-ACTIONS N5). Agent-facing surfaces
            // never see this trace — the provenance firewall is untouched.
            "visibility_tokens": c.visibility,
            "confidentiality": confidentiality_name(c.confidentiality),
            "acl_provenance": c.acl_provenance,
            "trust_tier": if c.trust_tier == 1 { "authoritative" } else { "observation" },
            "valid_from": c.valid_from,
            "valid_to": c.valid_to,
            "provenance": c.provenance,
            "admitted": drop_reasons.is_empty(),
            "drop_reasons": drop_reasons,
            "notes": notes,
            "content_preview": preview,
        }));
    }

    // Audited like every scoped read — but under its own verb so a reviewer can
    // find every time this widened trace was invoked, by whom, over what.
    spawn_audit(
        &state,
        &payload,
        "debug_recall",
        req.text.as_deref().or(Some("<embedding-only>")),
        all_ids,
    );

    Ok(Json(serde_json::json!({
        "query": {
            "text": req.text,
            "leg": leg,
            "candidates_requested": limit,
            "candidates_traced": traced.len(),
        },
        "scope": {
            "tenant_id": scope.tenant_id,
            "entity_scope": scope.entity_scope,
            "max_confidentiality": confidentiality_name(ceiling),
            "principals_effective": scope.principals,
            "principals_revoked": revoked,
        },
        "candidates": traced,
        "honesty": [
            "Filters are evaluated against the index AS OF NOW; a past recall's drops are not reconstructable if visibility/tags/validity changed since.",
            "Candidate set = top-N by similarity under a tenant-only ordering; chunks outside that top-N (including ANN traversal misses) are not enumerable.",
            "The live restricted-class ReBAC recheck is not executed here; restricted candidates are flagged structurally, never re-resolved.",
            "This endpoint is admin-gated, audited, and OFF the read path — recall/get never do this work.",
        ],
    })))
}

// ---------- quarantine lifecycle write surface (UI-SPEC §5 Screen 6 — the
// formerly-disabled seam). Re-ingest routes ONLY through an admin-supplied
// corrected ACL mapping; there is deliberately NO "index it anyway" path — no
// request shape exists that indexes a quarantined payload under its original
// (unmappable) ACL or under any default. ----------

/// Audit an admin quarantine disposition (worker/admin-plane event — no scope
/// handle involved, so actor is the admin surface itself). Non-blocking,
/// mirroring `audit::spawn_audit`.
fn spawn_quarantine_audit(
    state: &Arc<AppState>,
    tenant: TenantId,
    verb: &'static str,
    summary: String,
    result_ids: Vec<uuid::Uuid>,
) {
    let pool = state.pool().clone();
    let summary: String = summary.chars().take(120).collect();
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, 'admin', $3, $4, $5, 0, $6, $7)",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(tenant)
        .bind(verb)
        .bind(Vec::<PrincipalToken>::new())
        .bind(Vec::<String>::new())
        .bind(&summary)
        .bind(&result_ids)
        .execute(&pool)
        .await;
        if let Err(e) = result {
            tracing::warn!(verb, "quarantine audit insert failed: {e}");
        }
    });
}

/// The corrected ACL mapping an admin supplies to re-admit a quarantined
/// payload. `visibility` and `confidentiality` are REQUIRED and explicit —
/// there is no default, no "inherit whatever the webhook had", and no shape
/// that indexes without them.
#[derive(Deserialize)]
struct QuarantineReingestRequest {
    tenant_id: TenantId,
    /// Explicit principal tokens. An empty set is accepted and fail-closed:
    /// it writes memory nobody can read (never a permissive default).
    visibility: Vec<PrincipalToken>,
    confidentiality: Confidentiality,
    #[serde(default)]
    entity_tags: Vec<String>,
    /// Optional corrected text extraction — for `unrecognized shape` payloads
    /// whose text lives under a field the native parser doesn't know. The
    /// ORIGINAL payload is preserved verbatim as the episode body, so the
    /// admin's extraction is itself auditable against the source.
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// The subset of the native fact shape re-ingest will honor from the stored
/// payload (mirrors webhooks::NativeFact).
#[derive(Deserialize)]
struct ReingestFact {
    source: String,
    entity_id: String,
    field: String,
    value: serde_json::Value,
    #[serde(default)]
    valid_from: Option<DateTime<Utc>>,
}

/// POST /v1/admin/quarantine/{id}/reingest — re-admit a quarantined payload
/// THROUGH a corrected, admin-supplied ACL mapping (visibility +
/// confidentiality + entity tags), stamped `acl_provenance = admin-assigned`.
///
/// What it ingests: the payload's own `content`/`observation` (or its
/// preserved `raw` text for invalid-JSON quarantines, or the admin's explicit
/// `content` extraction) as an L0 episode + chunk, plus any parseable native
/// `facts` as deterministic L1 upserts. A payload that still carries nothing
/// ingestible is refused (422) — re-ingest never fabricates content and there
/// is no path that indexes a payload under its original unmappable ACL.
///
/// Lifecycle: the row is atomically claimed (`resolution = 'reingested'`,
/// only from OPEN — concurrent double-claims lose with 409); if ingestion then
/// fails the claim is reverted so the item returns to triage. The quarantine
/// row itself survives for audit (invalidate-don't-delete). Audited under
/// `verb = "quarantine_reingest"`.
async fn admin_quarantine_reingest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<QuarantineReingestRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let item = state
        .storage
        .inner()
        .quarantine_item(req.tenant_id, id)
        .await
        .map_err(internal)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no such quarantined item".to_string(),
        ))?;
    if let Some(res) = &item.resolution {
        return Err((
            StatusCode::CONFLICT,
            format!("quarantine item already resolved ({res})"),
        ));
    }

    // Extract what the payload can honestly yield BEFORE claiming the row.
    let content: Option<String> = req
        .content
        .clone()
        .or_else(|| {
            item.payload
                .get("content")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .or_else(|| {
            item.payload
                .get("observation")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .or_else(|| {
            // Invalid-JSON quarantines preserved the raw text (truncated at
            // 4096 chars at capture time — disclosed below).
            item.payload
                .get("raw")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    // Native-shaped facts, if present AND parseable. Unparseable facts are
    // skipped fail-closed (never guessed into L1) and disclosed in the reply.
    let (facts, facts_unparseable) = match item.payload.get("facts") {
        None => (Vec::new(), false),
        Some(v) => match serde_json::from_value::<Vec<ReingestFact>>(v.clone()) {
            Ok(f) => (f, false),
            Err(_) => (Vec::new(), true),
        },
    };
    if content.is_none() && facts.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "payload carries nothing ingestible (no content/observation/raw text, no parseable facts); \
             re-ingest never fabricates content — supply a corrected `content` extraction or fix at the source"
                .to_string(),
        ));
    }

    // Claim the row first: the OPEN->reingested stamp is the concurrency gate
    // (a parallel re-ingest of the same item loses here with 409).
    let claimed = state
        .storage
        .inner()
        .resolve_quarantine(req.tenant_id, id, "reingested", req.note.as_deref())
        .await
        .map_err(storage_status)?;
    if !claimed {
        return Err((
            StatusCode::CONFLICT,
            "quarantine item already resolved".to_string(),
        ));
    }

    // Ingest through the SAME write paths as an accepted webhook payload —
    // only the ACL mapping differs (admin-supplied, admin-assigned).
    let ingest = async {
        let source =
            match sqlx::query_scalar::<_, String>("SELECT name FROM webhooks WHERE id = $1")
                .bind(item.webhook_id)
                .fetch_optional(state.pool())
                .await
                .map_err(internal)?
            {
                Some(name) => format!("webhook:{name}"),
                None => format!("webhook:{}", item.webhook_id),
            };
        let episode_id = state
            .storage
            .append_episode(NewEpisode {
                tenant_id: req.tenant_id,
                source: source.clone(),
                source_entity: req.entity_tags.first().cloned(),
                kind: EpisodeKind::Webhook,
                content_hash: format!("{:x}", md5ish(&item.payload.to_string())),
                // The ORIGINAL quarantined payload, verbatim — provenance for
                // the admin's mapping/extraction.
                payload: item.payload.clone(),
                trust_tier: TrustTier::Authoritative,
                writer_sub: None,
                writer_azp: Some(format!("admin-reingest:{id}")),
            })
            .await
            .map_err(internal)?;
        let mut chunks_indexed = 0usize;
        if let Some(text) = &content {
            let embedding = state.encode(text).await.ok().flatten();
            chunks_indexed = state
                .storage
                .upsert_chunks(vec![ChunkWrite {
                    tenant_id: req.tenant_id,
                    source: source.clone(),
                    document_id: format!("qr:{episode_id}"),
                    seq: 0,
                    content: text.clone(),
                    content_hash: format!("qr-{episode_id}"),
                    embedding,
                    visibility: req.visibility.clone(),
                    entity_tags: req.entity_tags.clone(),
                    confidentiality: req.confidentiality,
                    trust_tier: TrustTier::Authoritative,
                    valid_from: Utc::now(),
                    provenance: episode_id,
                    // The whole point: explicit admin policy, never a mirrored
                    // or approximated (unmappable) source ACL.
                    acl_provenance: AclProvenance::AdminAssigned,
                }])
                .await
                .map_err(internal)?;
        }
        let mut facts_written = 0u64;
        for fact in &facts {
            state
                .storage
                .upsert_fact(FactWrite {
                    tenant_id: req.tenant_id,
                    key: FactKey {
                        source: fact.source.clone(),
                        entity_id: fact.entity_id.clone(),
                        field: fact.field.clone(),
                    },
                    value: fact.value.clone(),
                    valid_from: fact.valid_from.unwrap_or_else(Utc::now),
                    // The corrected ACL the admin supplied for the re-ingest —
                    // the same explicit policy the sibling chunk got. This is
                    // the ONLY way a quarantined payload re-enters L1.
                    visibility: req.visibility.clone(),
                    confidentiality: req.confidentiality,
                    provenance: episode_id,
                    acl_provenance: AclProvenance::AdminAssigned,
                })
                .await
                .map_err(internal)?;
            facts_written += 1;
        }
        Ok::<(uuid::Uuid, usize, u64), (StatusCode, String)>((
            episode_id,
            chunks_indexed,
            facts_written,
        ))
    };
    let (episode_id, chunks_indexed, facts_written) = match ingest.await {
        Ok(v) => v,
        Err(e) => {
            // Compensation: put the item back in the triage queue (best-effort;
            // a failure here is logged, and the item shows as claimed-but-
            // unresolved evidence in the audit trail either way).
            if let Err(re) = state
                .storage
                .inner()
                .reopen_quarantine(req.tenant_id, id)
                .await
            {
                tracing::warn!(%id, "re-ingest failed AND reopen failed: {re}");
            }
            return Err(e);
        }
    };

    state.resolution.mark_dirty(req.tenant_id);
    spawn_quarantine_audit(
        &state,
        req.tenant_id,
        "quarantine_reingest",
        format!(
            "quarantine {id} -> episode {episode_id} (vis={} tokens, conf={})",
            req.visibility.len(),
            confidentiality_name(req.confidentiality as i16),
        ),
        vec![id, episode_id],
    );
    Ok(Json(serde_json::json!({
        "reingested": true,
        "quarantine_id": id,
        "episode_id": episode_id,
        "chunks_indexed": chunks_indexed,
        "facts_written": facts_written,
        // Honesty flags: what the re-ingest could NOT carry over.
        "facts_unparseable_skipped": facts_unparseable,
        "raw_text_truncated_at_capture": req.content.is_none()
            && item.payload.get("content").and_then(|v| v.as_str()).is_none()
            && item.payload.get("observation").and_then(|v| v.as_str()).is_none()
            && item.payload.get("raw").is_some(),
    })))
}

#[derive(Deserialize)]
struct QuarantineDismissRequest {
    tenant_id: TenantId,
    #[serde(default)]
    note: Option<String>,
}

/// POST /v1/admin/quarantine/{id}/dismiss — acknowledge a quarantined payload
/// WITHOUT indexing anything. Stamps `resolution = 'dismissed'` (only from
/// OPEN; 409 if already resolved); the row survives for audit. Audited under
/// `verb = "quarantine_dismiss"`. This and re-ingest-through-corrected-mapping
/// are the ONLY two exits from quarantine.
async fn admin_quarantine_dismiss(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<QuarantineDismissRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let dismissed = state
        .storage
        .inner()
        .resolve_quarantine(req.tenant_id, id, "dismissed", req.note.as_deref())
        .await
        .map_err(storage_status)?;
    if !dismissed {
        // Distinguish "never existed" from "already resolved" for the console.
        return match state
            .storage
            .inner()
            .quarantine_item(req.tenant_id, id)
            .await
            .map_err(internal)?
        {
            None => Err((StatusCode::NOT_FOUND, "no such quarantined item".into())),
            Some(item) => Err((
                StatusCode::CONFLICT,
                format!(
                    "quarantine item already resolved ({})",
                    item.resolution.as_deref().unwrap_or("unknown")
                ),
            )),
        };
    }
    spawn_quarantine_audit(
        &state,
        req.tenant_id,
        "quarantine_dismiss",
        format!("quarantine {id} dismissed"),
        vec![id],
    );
    Ok(Json(serde_json::json!({
        "dismissed": true,
        "quarantine_id": id,
    })))
}

pub(crate) fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Central `StorageError` → HTTP mapper for write handlers. Client-caused
/// errors get clean 4xx; only genuine `Database` failures are 500. Notably an
/// unknown tenant (which would otherwise bubble up as a raw FK violation →
/// `Database` → 500) becomes a 404.
pub(crate) fn storage_status(e: StorageError) -> (StatusCode, String) {
    match e {
        StorageError::UnknownTenant(_) => (StatusCode::NOT_FOUND, e.to_string()),
        StorageError::InvalidInput(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        StorageError::Database(_) => internal(e),
    }
}

#[cfg(test)]
mod permission_graph_tests {
    //! Permission Graph plane-purity (§9 T7) + gating (§9 T7b) + cursor parse.
    //! Pure — no socket, no DB — so they run in CI without fixtures. The
    //! DB-backed scope-parity (T1) + fail-closed (T2) tests live in
    //! `verity-storage/tests/access_graph_parity.rs` (VERITY_TEST_DSN-gated).
    use super::{parse_docs_after, AdminAuth};
    use axum::http::{header, HeaderMap, StatusCode};

    /// The two new handlers' source with comment lines stripped — the T7 grep
    /// asserts the CODE never *calls* a read-path helper. The handlers document
    /// (in comments) that they deliberately avoid `scope_for` et al.; those
    /// prose mentions are not references, so line-comments are removed first.
    fn handler_src() -> String {
        let src = include_str!("main.rs");
        // Slice out just the two admin_access_* handlers, so the grep targets
        // our code, not the read-path functions elsewhere in the file.
        let start = src
            .find("async fn admin_access_subject")
            .expect("subject handler present");
        let end = src
            .find("const ACCESS_OBJECT_CORPUS_CEILING")
            .expect("ceiling const present");
        src[start..end]
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // --- T7: plane purity (structural grep) --------------------------------

    #[test]
    fn new_handlers_do_not_touch_read_path_helpers() {
        let body = handler_src();
        for forbidden in [
            "enforce_restricted",
            "current_token_set",
            "scope_for",
            ".recall(",
            "storage.recall",
        ] {
            assert!(
                !body.contains(forbidden),
                "Permission Graph handler must not reference read-path helper `{forbidden}`"
            );
        }
    }

    #[test]
    fn recall_get_do_not_reference_new_handlers() {
        let src = include_str!("main.rs");
        // The recall handler is `async fn recall(`; assert its body (up to the
        // next top-level `async fn`) never calls the new admin handlers.
        let start = src
            .find("async fn recall(")
            .expect("recall handler present");
        let rest = &src[start + 1..];
        let end = rest
            .find("\nasync fn ")
            .map(|i| start + 1 + i)
            .unwrap_or(src.len());
        let recall_body = &src[start..end];
        assert!(!recall_body.contains("admin_access_subject"));
        assert!(!recall_body.contains("admin_access_object"));
        assert!(!recall_body.contains("access_corpus_aggregate"));
    }

    #[test]
    fn every_new_handler_gates_with_require_not_check() {
        let body = handler_src();
        assert!(
            body.matches("state.admin.require(&headers)?").count() >= 2,
            "both handlers must gate with require() (no dev-open)"
        );
        // The god-view must never use the dev-open `check` on its own gate line.
        assert!(
            !body.contains("state.admin.check(&headers)"),
            "Permission Graph must not use dev-open check()"
        );
        // And both must demand ReBAC.
        assert!(body.matches("require_rebac(&state)?").count() >= 2);
    }

    // --- T7b: gating returns 401 when no admin token is configured ---------

    #[test]
    fn god_view_gate_refuses_without_admin_token() {
        // `require` is the gate both handlers call first; with no configured
        // token it 401s (unlike dev-open `check`), even on a loopback bind.
        let auth = AdminAuth::for_test(None, None);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer anything".parse().unwrap());
        let err = auth.require(&h).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn actor_fingerprint_is_stable_and_non_raw() {
        let auth = AdminAuth::for_test(Some("s3cret"), None);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        let fp = auth.actor_fingerprint(&h);
        assert!(fp.starts_with("bearer:"));
        assert!(!fp.contains("s3cret"), "must never leak the raw token");
        // Deterministic for the same key + token.
        assert_eq!(fp, auth.actor_fingerprint(&h));
        // No bearer → dev-open marker.
        assert_eq!(auth.actor_fingerprint(&HeaderMap::new()), "dev-open");
    }

    // --- cursor parse ------------------------------------------------------

    #[test]
    fn docs_after_roundtrips_and_rejects_garbage() {
        let ts = "2026-07-01T00:00:00+00:00";
        let id = "0190a0aa-0000-7000-8000-000000000000";
        let (parsed_ts, parsed_id) = parse_docs_after(&format!("{ts}|{id}")).unwrap();
        assert_eq!(parsed_ts.to_rfc3339(), ts);
        assert_eq!(parsed_id.to_string(), id);
        assert!(parse_docs_after("no-pipe").is_err());
        assert!(parse_docs_after("not-a-date|not-a-uuid").is_err());
    }
}
