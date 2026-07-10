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
use verity_storage::PostgresAdapter;

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
    storage: PostgresAdapter,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let storage = PostgresAdapter::connect(&cli.dsn).await?;
    storage.migrate().await?;
    let state = Arc::new(AppState { storage });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/recall", post(recall))
        .route("/v1/records/{source}/{entity}/{field}", get(get_record))
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
    let query = RecallQuery {
        scope: Scope {
            tenant_id: req.tenant_id,
            principals: req.principals,
            entity_scope: req.entity_scope,
            max_confidentiality: Confidentiality::Confidential,
        },
        embedding: req.embedding,
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

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
