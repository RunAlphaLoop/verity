//! Connector heartbeat plane (v0.2 observability, task 28).
//!
//! Ingest sinks (ingest/verity_ingest/connectors) POST a small best-effort
//! heartbeat here after each delivery batch; `/ui` renders the result as the
//! "connectors" panel. Telemetry contract, stated honestly: heartbeats are
//! fire-and-forget on the connector side (a failed heartbeat never fails a
//! sync), so `items_synced` accumulates reported batch deltas and can
//! undercount — it is a liveness/staleness signal, not an audit ledger. The
//! authoritative sync state stays in the connector's own cursor file and in
//! the L0/L1 rows the ingest endpoints wrote.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{internal, storage_status, AppState, HandlerResult};

#[derive(Deserialize)]
pub(crate) struct HeartbeatRequest {
    pub(crate) tenant_id: Uuid,
    pub(crate) source: String,
    /// Connector checkpoint, opaque (ISO timestamp, Drive pageToken, …).
    /// Absent → the stored cursor is kept.
    #[serde(default)]
    pub(crate) cursor: Option<String>,
    /// Items delivered in THIS batch; the row accumulates the deltas.
    #[serde(default)]
    pub(crate) items_synced: i64,
    /// Source-side timestamp of the newest event in the batch. The stored
    /// value only moves forward (GREATEST), so late heartbeats can't rewind
    /// the staleness signal.
    #[serde(default)]
    pub(crate) last_event_at: Option<DateTime<Utc>>,
}

/// Upsert one heartbeat row. Factored off the handler so DSN-gated tests
/// exercise the exact SQL without an HTTP layer.
pub(crate) async fn record_heartbeat(pool: &PgPool, req: &HeartbeatRequest) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO connector_status (tenant_id, source, cursor, items_synced, last_event_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (tenant_id, source) DO UPDATE SET
             cursor        = COALESCE(EXCLUDED.cursor, connector_status.cursor),
             items_synced  = connector_status.items_synced + EXCLUDED.items_synced,
             last_event_at = GREATEST(EXCLUDED.last_event_at, connector_status.last_event_at),
             updated_at    = now()",
    )
    .bind(req.tenant_id)
    .bind(&req.source)
    .bind(&req.cursor)
    .bind(req.items_synced.max(0))
    .bind(req.last_event_at)
    .execute(pool)
    .await
    .map(|_| ())
}

/// POST /v1/admin/connector-status (admin): one heartbeat in, upserted.
pub(crate) async fn post_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    record_heartbeat(state.pool(), &req)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "recorded": true })))
}

pub(crate) async fn list_status_rows(
    pool: &PgPool,
    tenant_id: Uuid,
) -> sqlx::Result<Vec<serde_json::Value>> {
    let rows = sqlx::query(
        "SELECT source, cursor, items_synced, last_event_at, updated_at
         FROM connector_status WHERE tenant_id = $1
         ORDER BY source",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(serde_json::json!({
                "source": row.try_get::<String, _>("source")?,
                "cursor": row.try_get::<Option<String>, _>("cursor")?,
                "items_synced": row.try_get::<i64, _>("items_synced")?,
                "last_event_at": row.try_get::<Option<DateTime<Utc>>, _>("last_event_at")?,
                "updated_at": row.try_get::<DateTime<Utc>, _>("updated_at")?,
            }))
        })
        .collect()
}

#[derive(Deserialize)]
pub(crate) struct ListParams {
    tenant_id: Uuid,
}

/// GET /v1/admin/connector-status?tenant_id= (admin): every source's latest
/// heartbeat for the tenant, alphabetical by source.
pub(crate) async fn get_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    list_status_rows(state.pool(), p.tenant_id)
        .await
        .map(Json)
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verity_core::adapter::StorageAdapter;
    use verity_storage::PostgresAdapter;

    /// DSN-gated (VERITY_TEST_DSN): upsert accumulates items, keeps the
    /// cursor on cursor-less heartbeats, never rewinds last_event_at; list
    /// returns per-source rows for the right tenant only.
    #[tokio::test]
    async fn heartbeat_upsert_and_list() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let pg = PostgresAdapter::connect_with_kek(&dsn, None)
            .await
            .expect("connect");
        pg.migrate().await.expect("migrate");
        let tenant = pg
            .create_tenant(&format!("connector-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant");
        let pool = pg.pool();

        let t0 = Utc::now();
        record_heartbeat(
            pool,
            &HeartbeatRequest {
                tenant_id: tenant,
                source: "hubspot".into(),
                cursor: Some("2026-07-09T00:00:00+00:00".into()),
                items_synced: 5,
                last_event_at: Some(t0),
            },
        )
        .await
        .expect("first heartbeat");
        // Second batch: no cursor, older event time — cursor kept, event time
        // not rewound, items accumulated.
        record_heartbeat(
            pool,
            &HeartbeatRequest {
                tenant_id: tenant,
                source: "hubspot".into(),
                cursor: None,
                items_synced: 3,
                last_event_at: Some(t0 - chrono::Duration::hours(1)),
            },
        )
        .await
        .expect("second heartbeat");
        record_heartbeat(
            pool,
            &HeartbeatRequest {
                tenant_id: tenant,
                source: "gdrive".into(),
                cursor: Some("387".into()),
                items_synced: 2,
                last_event_at: None,
            },
        )
        .await
        .expect("gdrive heartbeat");

        let rows = list_status_rows(pool, tenant).await.expect("list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["source"], "gdrive");
        assert_eq!(rows[0]["cursor"], "387");
        assert_eq!(rows[0]["items_synced"], 2);
        assert!(rows[0]["last_event_at"].is_null());
        assert_eq!(rows[1]["source"], "hubspot");
        assert_eq!(rows[1]["items_synced"], 8, "batch deltas accumulate");
        assert_eq!(rows[1]["cursor"], "2026-07-09T00:00:00+00:00");
        let stored: DateTime<Utc> =
            serde_json::from_value(rows[1]["last_event_at"].clone()).expect("timestamp");
        assert_eq!(
            stored.timestamp_millis(),
            t0.timestamp_millis(),
            "last_event_at never rewinds"
        );

        // Tenant isolation: a stranger tenant sees nothing.
        let other = pg
            .create_tenant(&format!("connector-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant2");
        assert!(list_status_rows(pool, other)
            .await
            .expect("list2")
            .is_empty());
    }
}
