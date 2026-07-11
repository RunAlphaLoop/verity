//! Verity server — API plane (Milestone A engine + Milestone B scope seam).
//!
//! Every read/write verb takes a MemoryScope handle (see scope.rs); scope
//! parameters cannot be widened by request arguments. Handle MINTING still
//! accepts caller-supplied principals until the identity/ReBAC planes land —
//! that seam is documented in scope.rs and POST /v1/scopes.

mod audit;
mod compliance;
mod connectors;
mod consolidation;
#[cfg(test)]
mod consolidation_tests;
#[cfg(test)]
mod identity_tests;
mod ingest;
#[cfg(test)]
mod manifest_tests;
mod manifests;
mod media;
mod purpose;
mod rebac;
mod revocation;
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
        auto_tag: std::env::var("VERITY_AUTO_TAG").is_ok_and(|v| v == "1"),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // Read-only scope-inspector UI (SPEC §11d) — embedded, zero-build.
        .route("/ui", get(ui::ui_page))
        .route("/v1/scopes", post(open_scope))
        .route("/v1/recall", post(recall))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
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
        .route("/v1/admin/erasure", post(compliance::admin_erasure))
        .route("/v1/admin/dsar/export", get(compliance::dsar_export))
        .route("/v1/admin/audit", get(audit::admin_audit))
        .route("/v1/admin/quarantine", get(webhooks::admin_quarantine))
        .route("/v1/admin/media", get(media::admin_list_media))
        .route(
            "/v1/admin/connector-status",
            post(connectors::post_status).get(connectors::get_status),
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
        .route("/v1/admin/principals", post(admin_principals))
        .route(
            "/v1/admin/groups",
            post(admin_group_add).delete(admin_group_remove),
        )
        .route("/v1/knowledge", post(propose_learning).get(list_knowledge))
        .route("/v1/knowledge/{id}/publish", post(publish_knowledge))
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
        .with_state(state);

    tracing::info!("verity listening on {}", cli.listen);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
    let mappings: serde_json::Map<String, serde_json::Value> =
        upsert_principal_tokens(state.pool(), req.tenant_id, &req.principals)
            .await?
            .into_iter()
            .map(|(p, t)| (p, serde_json::json!(t)))
            .collect();
    Ok(Json(serde_json::json!({ "mappings": mappings })))
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

/// Review queue (admin/audit plane — bearer-token gated, task 3).
async fn list_knowledge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListKnowledgeParams>,
) -> HandlerResult<Json<Vec<KnowledgeItem>>> {
    state.admin.check(&headers)?;
    state
        .storage
        .list_knowledge(p.tenant_id, p.status)
        .await
        .map(Json)
        .map_err(internal)
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
        .map_err(|e| match e {
            StorageError::InvalidInput(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            other => internal(other),
        })
}

pub(crate) fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
