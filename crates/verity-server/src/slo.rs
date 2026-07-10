//! Freshness SLO plane (roadmap task 21): how long does an event take to
//! become queryable?
//!
//! Every ingest lane records one `freshness_samples` row per event: `event_at`
//! is the source-side event time (Debezium envelope ts_ms; receipt time for
//! webhooks, which carry no source clock), `queryable_at` is the database
//! clock at insert — stamped AFTER the derived writes committed, so the delta
//! is an honest upper bound on end-to-end freshness for that event.
//!
//! Recording is best-effort telemetry: a failed sample is logged and never
//! fails the ingest that produced it. The read side
//! (`GET /v1/slo/freshness`, admin-gated) computes p50/p95 in SQL via
//! `percentile_cont` — every measured number reported from real samples,
//! per the CLAUDE.md honesty rule.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use verity_core::types::TenantId;

use crate::{internal, AppState, HandlerResult};

/// Record one freshness sample. Best-effort: errors are logged, not returned —
/// telemetry must never fail the ingest write it measures.
pub(crate) async fn record_sample(
    pool: &PgPool,
    tenant_id: TenantId,
    source: &str,
    event_at: DateTime<Utc>,
) {
    let result = sqlx::query(
        "INSERT INTO freshness_samples (id, tenant_id, source, event_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(source)
    .bind(event_at)
    .execute(pool)
    .await;
    if let Err(e) = result {
        tracing::warn!(source, "freshness sample insert failed: {e}");
    }
}

#[derive(Deserialize)]
pub(crate) struct FreshnessParams {
    tenant_id: TenantId,
    /// Restrict to one source; absent = all sources, one row each.
    source: Option<String>,
    #[serde(default = "default_window_hours")]
    window_hours: i32,
}

fn default_window_hours() -> i32 {
    24
}

/// GET /v1/slo/freshness (admin): per-source freshness percentiles over the
/// window, computed in SQL. Windowing keys on `queryable_at` (when we learned
/// of the event), so late-arriving events with old `event_at` still count.
pub(crate) async fn freshness(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<FreshnessParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT source,
                count(*) AS samples,
                percentile_cont(0.5) WITHIN GROUP
                    (ORDER BY extract(epoch FROM (queryable_at - event_at))::float8 * 1000)
                    AS p50_ms,
                percentile_cont(0.95) WITHIN GROUP
                    (ORDER BY extract(epoch FROM (queryable_at - event_at))::float8 * 1000)
                    AS p95_ms
         FROM freshness_samples
         WHERE tenant_id = $1
           AND queryable_at > now() - make_interval(hours => $2)
           AND ($3::text IS NULL OR source = $3)
         GROUP BY source
         ORDER BY source",
    )
    .bind(p.tenant_id)
    .bind(p.window_hours.clamp(1, 24 * 90))
    .bind(&p.source)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "source": row.try_get::<String, _>("source").map_err(internal)?,
                "samples": row.try_get::<i64, _>("samples").map_err(internal)?,
                "p50_ms": row.try_get::<Option<f64>, _>("p50_ms").map_err(internal)?,
                "p95_ms": row.try_get::<Option<f64>, _>("p95_ms").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<Vec<_>>>()?;
    Ok(Json(items))
}
