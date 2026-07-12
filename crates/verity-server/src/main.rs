//! Verity server — API plane (Milestone A engine + Milestone B scope seam).
//!
//! Every read/write verb takes a MemoryScope handle (see scope.rs); scope
//! parameters cannot be widened by request arguments. Handle MINTING still
//! accepts caller-supplied principals until the identity/ReBAC planes land —
//! that seam is documented in scope.rs and POST /v1/scopes.

mod audit;
mod backfill;
mod compliance;
mod connectors;
#[cfg(test)]
mod console_later_tests;
mod consolidation;
#[cfg(test)]
mod consolidation_tests;
#[cfg(test)]
mod entity_resolution_tests;
#[cfg(test)]
mod identity_tests;
mod ingest;
#[cfg(test)]
mod manifest_tests;
mod manifests;
mod media;
#[cfg(test)]
mod media_tests;
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
}

/// Admin/ingest-plane bearer auth (roadmap task 3). When `VERITY_ADMIN_TOKEN`
/// is set, admin surfaces require `Authorization: Bearer <token>`; the check
/// is constant-time (HMAC tags under a per-process random key compared via
/// `Mac::verify_slice`). Unset = dev mode: warned once at startup, allowed.
pub(crate) struct AdminAuth {
    key: [u8; 32],
    expected_tag: Option<Vec<u8>>,
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
        Self { key, expected_tag }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let pg = PostgresAdapter::connect(&cli.dsn).await?;
    pg.migrate().await?;
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
        revocations: RevocationPlane::from_env(),
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
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // Read-only scope-inspector UI (SPEC §11d) — embedded, zero-build.
        .route("/ui", get(ui::ui_page))
        .route("/v1/scopes", post(open_scope))
        .route("/v1/recall", post(recall))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
        .route("/v1/entities/{canonical}", get(get_merged_entity))
        .route("/v1/admin/entities", get(admin_list_entities))
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
        .route("/v1/admin/tenants", post(create_tenant))
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
        .route(
            "/v1/admin/groups",
            post(admin_group_add).delete(admin_group_remove),
        )
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

    tracing::info!("verity listening on {}", cli.listen);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
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
            let groups = rebac.user_groups(req.tenant_id, name).await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("identity resolution failed: {e}"),
                )
            })?;
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
    let key = FactKey {
        source,
        entity_id: entity,
        field,
    };
    let result = match q.as_of {
        Some(as_of) => {
            state
                .storage
                .fact_as_of(payload.tenant_id, &key, as_of)
                .await
        }
        None => state.storage.current_fact(payload.tenant_id, &key).await,
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
    // Field-resolution is untouched: merged_record runs exactly as before.
    let merged = state
        .storage
        .inner()
        .merged_record(payload.tenant_id, &canonical)
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

    let (mut written, mut superseded, mut retired, mut unchanged) = (0u64, 0u64, 0u64, 0u64);
    for envelope in envelopes {
        let ev = ingest::parse_envelope(envelope, &p.pk)
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
                            provenance: episode,
                            acl_provenance: AclProvenance::Mirrored,
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
    })))
}

// ---------- ingest: whole documents (connector contract, task 7 of v0.1) ----------

#[derive(Deserialize)]
struct IngestDocumentsRequest {
    tenant_id: TenantId,
    source: String,
    document_id: String,
    content: String,
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
/// codes against.
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
    let valid_from = req.valid_from.unwrap_or_else(Utc::now);
    let content_hash = format!("{:x}", md5ish(&req.content));
    let episode_id = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: req.tenant_id,
            source: req.source.clone(),
            source_entity: Some(req.document_id.clone()),
            kind: EpisodeKind::DocVersion,
            payload: serde_json::json!({
                "document_id": req.document_id,
                "content_hash": content_hash,
                "bytes": req.content.len(),
            }),
            content_hash: content_hash.clone(),
            // Connector-mirrored documents track a system of record.
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .map_err(internal)?;

    let mut writes = Vec::new();
    for (seq, content) in media::split_text(&req.content, media::CHUNK_CHARS)
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
            confidentiality: Confidentiality::Internal,
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
    Ok(Json(serde_json::json!({
        "episode_id": episode_id,
        "chunks_indexed": chunks_indexed,
    })))
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
    state
        .storage
        .propose_knowledge(KnowledgeProposal {
            tenant_id: payload.tenant_id,
            statement: req.statement,
            categories: req.categories,
            evidence: req.evidence,
            proposed_by_sub: payload.actor_sub.clone(),
            proposed_by_azp: payload.actor_azp.clone(),
            // The human/agent propose path carries no canonical form; the
            // rejection memory then matches on the exact statement. (The
            // consolidation worker supplies the canonical form for its stronger
            // match.)
            canonical_statement: None,
        })
        .await
        .map(Json)
        .map_err(internal)
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
