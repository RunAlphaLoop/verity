//! Verity server — API plane (Milestone A engine + Milestone B scope seam).
//!
//! Every read/write verb takes a MemoryScope handle (see scope.rs); scope
//! parameters cannot be widened by request arguments. Handle MINTING still
//! accepts caller-supplied principals until the identity/ReBAC planes land —
//! that seam is documented in scope.rs and POST /v1/scopes.

mod ingest;
mod scope;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use clap::Parser;
use serde::Deserialize;

use scope::{ScopeMinter, ScopePayload};
use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

/// `verity_core::types::Result` shadows std's; handlers need the two-arg form.
type HandlerResult<T> = std::result::Result<T, (StatusCode, String)>;

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

struct AppState {
    storage: CachedAdapter<PostgresAdapter>,
    /// Local query encoder (SPEC §4a). None = sparse-only recall; the server
    /// stays up if model download fails, it just loses the dense leg.
    encoder: Option<Arc<verity_encoder::QueryEncoder>>,
    minter: ScopeMinter,
}

impl AppState {
    fn verify_scope(&self, handle: &str) -> HandlerResult<ScopePayload> {
        self.minter
            .verify(handle)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
    }

    async fn encode(&self, text: &str) -> HandlerResult<Option<Vec<f32>>> {
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
fn resolve_entities(payload: &ScopePayload, requested: Vec<String>) -> HandlerResult<Vec<String>> {
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
    // L1 current-truth cache: the `get` hot path (SPEC §4b). 1M entries ≈ a
    // few hundred MB ceiling; invalidated on upsert, so never serves stale.
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 1_000_000),
        encoder,
        minter: ScopeMinter::from_env(),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/scopes", post(open_scope))
        .route("/v1/recall", post(recall))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
        .route("/v1/episodes", post(remember))
        .route("/v1/actions", post(record_action))
        .route("/v1/activity", get(activity))
        .route("/v1/ingest/debezium", post(ingest_debezium))
        .route("/v1/briefs/{entity}", get(brief))
        .route("/v1/admin/tenants", post(create_tenant))
        .route("/v1/knowledge", post(propose_learning).get(list_knowledge))
        .route("/v1/knowledge/{id}/publish", post(publish_knowledge))
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
    // Milestone seam (scope.rs): principals are caller-supplied at mint time
    // until token→identity→ReBAC resolution exists. After minting, scope is
    // immutable and every verb enforces from the signed payload only.
    principals: Vec<PrincipalToken>,
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
    let (handle, expires_at) = state.minter.mint(
        ScopePayload {
            tenant_id: req.tenant_id,
            principals: req.principals,
            entity_scope: req.entity_scope,
            max_confidentiality: req.max_confidentiality,
            actor_sub: req.actor_sub,
            actor_azp: req.actor_azp,
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
        scope: payload.to_scope(),
        embedding,
        text: req.text,
        k: req.k.min(100),
    };
    state
        .storage
        .recall(query)
        .await
        .map(Json)
        .map_err(internal)
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
        Ok(Some(fact)) => Ok(Json(fact)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "no value for that key/time".into())),
        Err(e) => Err(internal(e)),
    }
}

// ---------- ingest (trusted connector plane — not scope-handle gated;
// authn for connectors arrives with the ingest-token work) ----------

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
    axum::extract::Query(p): axum::extract::Query<IngestParams>,
    Json(body): Json<serde_json::Value>,
) -> HandlerResult<Json<serde_json::Value>> {
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
    }

    Ok(Json(serde_json::json!({
        "facts_inserted": written,
        "facts_superseded": superseded,
        "facts_unchanged": unchanged,
        "facts_retired": retired,
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
        }])
        .await
        .map_err(internal)?;

    Ok(Json(serde_json::json!({ "episode_id": episode_id })))
}

/// Cheap content hash for L0 idempotency metadata (not security-relevant).
fn md5ish(s: &str) -> u64 {
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
        scope: payload.to_scope(),
        entity: p.entity,
        since: p.since,
        action_types: p
            .action_types
            .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
            .unwrap_or_default(),
        actors: vec![],
        limit: p.limit,
    };
    state
        .storage
        .activity(query)
        .await
        .map(Json)
        .map_err(internal)
}

// ---------- admin (trusted plane, same auth seam as ingest) ----------

#[derive(Deserialize)]
struct CreateTenantRequest {
    name: String,
}

async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTenantRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    let id = state
        .storage
        .create_tenant(&req.name)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "tenant_id": id })))
}

// ---------- brief ----------

#[derive(Deserialize)]
struct BriefQuery {
    scope_handle: String,
}

/// The entity brief (SPEC §2 L3, v0.1 deterministic form): current state of an
/// entity in one call — newest memory + recent agent activity. Assembled
/// on-read under the CALLER's scope, so derived-visibility inheritance is
/// trivially correct; precomputed briefs with lineage-intersection visibility
/// arrive with the async L3 workers.
async fn brief(
    State(state): State<Arc<AppState>>,
    Path(entity): Path<String>,
    axum::extract::Query(q): axum::extract::Query<BriefQuery>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(&q.scope_handle)?;
    let scope = payload.to_scope();
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
    let actions = actions.map_err(internal)?;
    Ok(Json(serde_json::json!({
        "entity": entity,
        "generated_at": Utc::now(),
        "recent_memory": memory,
        "recent_activity": actions,
        // L1 record linkage lands with cross-source entity resolution (§7f).
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

/// Review queue (admin/audit plane — same auth seam as ingest).
async fn list_knowledge(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(p): axum::extract::Query<ListKnowledgeParams>,
) -> HandlerResult<Json<Vec<KnowledgeItem>>> {
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
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<PublishKnowledgeRequest>,
) -> HandlerResult<Json<KnowledgeItem>> {
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

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
