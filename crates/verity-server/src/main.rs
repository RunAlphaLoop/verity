//! Verity server — API plane skeleton (Milestone A).
//!
//! REST substrate only for now; the MCP server and gRPC hot path layer on top
//! of the same handlers (SPEC §9). Scope handling here is a placeholder until
//! the scope engine lands in Milestone B: callers pass explicit principal sets,
//! which is acceptable ONLY because there is no permission materialization yet.
//! The fail-closed rule already applies: an empty principal set reads nothing.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::Deserialize;

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
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/recall", post(recall))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
        .route("/v1/actions", post(record_action))
        .route("/v1/activity", get(activity))
        .with_state(state);

    tracing::info!("verity listening on {}", cli.listen);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
struct RecallRequest {
    tenant_id: TenantId,
    principals: Vec<PrincipalToken>,
    #[serde(default)]
    entity_scope: Vec<String>,
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
    // Text-only requests get the dense leg via the local encoder (hybrid
    // recall); callers may still send a precomputed embedding instead.
    let embedding = match (req.embedding, &req.text, &state.encoder) {
        (Some(e), _, _) => Some(e),
        (None, Some(text), Some(encoder)) => {
            let encoder = Arc::clone(encoder);
            let text = text.clone();
            Some(
                tokio::task::spawn_blocking(move || encoder.encode(&text))
                    .await
                    .map_err(internal)?
                    .map_err(internal)?,
            )
        }
        (None, _, _) => None,
    };
    let query = RecallQuery {
        scope: Scope {
            tenant_id: req.tenant_id,
            principals: req.principals,
            entity_scope: req.entity_scope,
            max_confidentiality: Confidentiality::Confidential,
        },
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

#[derive(Deserialize)]
struct RecordQuery {
    tenant_id: TenantId,
}

async fn get_record(
    State(state): State<Arc<AppState>>,
    Path((source, entity, field)): Path<(String, String, String)>,
    axum::extract::Query(q): axum::extract::Query<RecordQuery>,
) -> HandlerResult<Json<FactRow>> {
    let key = FactKey {
        source,
        entity_id: entity,
        field,
    };
    match state.storage.current_fact(q.tenant_id, &key).await {
        Ok(Some(fact)) => Ok(Json(fact)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "no current value".into())),
        Err(e) => Err(internal(e)),
    }
}

#[derive(Deserialize)]
struct RecordActionRequest {
    tenant_id: TenantId,
    action_id: String,
    // Placeholder until the scope engine lands (Milestone B): identity will be
    // taken from the auth token, and visibility from the scope handle.
    actor_sub: Option<String>,
    actor_azp: Option<String>,
    action_type: String,
    entities: Vec<String>,
    summary: String,
    #[serde(default)]
    payload: serde_json::Value,
    outcome: ActionOutcome,
    occurred_at: chrono::DateTime<chrono::Utc>,
    visibility: Vec<PrincipalToken>,
}

async fn record_action(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecordActionRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    let recorded = state
        .storage
        .record_action(ActionWrite {
            tenant_id: req.tenant_id,
            action_id: req.action_id,
            actor_sub: req.actor_sub,
            actor_azp: req.actor_azp,
            action_type: req.action_type,
            entities: req.entities,
            summary: req.summary,
            payload: req.payload,
            outcome: req.outcome,
            occurred_at: req.occurred_at,
            visibility: req.visibility,
            confidentiality: Confidentiality::Internal,
        })
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "recorded": recorded })))
}

#[derive(Deserialize)]
struct ActivityParams {
    tenant_id: TenantId,
    entity: String,
    /// Comma-separated principal tokens (scope-engine placeholder).
    principals: String,
    since: Option<chrono::DateTime<chrono::Utc>>,
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
    let principals: Vec<PrincipalToken> = p
        .principals
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let query = ActivityQuery {
        scope: Scope {
            tenant_id: p.tenant_id,
            principals,
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Confidential,
        },
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

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
