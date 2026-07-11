//! Connector backfill dashboard (task 49).
//!
//! A backfill run is the bounded, historical initial-sync job that catches a
//! cold source up before the change feed takes over. This is deliberately a
//! DIFFERENT surface from the connector heartbeat ([`crate::connectors`]): a
//! heartbeat is an unbounded, monotonic liveness counter with no denominator,
//! while a backfill run is a *job* — a discovered/estimated total, a running
//! processed count, a lifecycle state, and a terminal outcome. That's what a
//! progress bar and an ETA need, and neither is derivable from a heartbeat.
//!
//! Telemetry contract, same honesty as the heartbeat: the ingest side posts
//! progress best-effort (a failed post never fails or replays a sync that
//! already delivered), so `processed` accumulates reported deltas and can
//! undercount on a missed post — a progress signal, not an audit ledger. The
//! authoritative row count stays in the L0/L1 rows the ingest endpoints wrote.
//!
//! `/ui` renders the latest run per source as the "backfill" panel.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{internal, AppState, HandlerResult};

/// The lifecycle states a backfill run may report. Kept in sync with the CHECK
/// constraint in migrations/0021_backfill_runs.sql; validated here so a bad
/// value is a clean 400, not a Postgres constraint 500.
const VALID_STATES: [&str; 4] = ["running", "paused", "completed", "failed"];

#[derive(Deserialize)]
pub(crate) struct BackfillProgressRequest {
    /// Run identity, minted by the orchestration when a backfill begins and
    /// threaded through every progress post for this run (like the cursor).
    pub(crate) run_id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) source: String,
    /// Lifecycle transition. Absent → the stored state is kept (a plain
    /// progress advance doesn't restate it).
    #[serde(default)]
    pub(crate) state: Option<String>,
    /// Discovered/estimated total for the window. Absent → kept (set once at
    /// start; NULL means "uncountable", and the UI shows an indeterminate bar).
    #[serde(default)]
    pub(crate) total: Option<i64>,
    /// Items processed in THIS post; the row accumulates the deltas.
    #[serde(default)]
    pub(crate) processed_delta: i64,
    /// The backfill's own checkpoint, opaque. Absent → the stored cursor kept.
    #[serde(default)]
    pub(crate) cursor: Option<String>,
    /// Set only alongside `state = "failed"`: the operator-facing error. Any
    /// post that doesn't carry one clears a stale error (you're advancing
    /// again, so you're no longer failed).
    #[serde(default)]
    pub(crate) error: Option<String>,
}

/// Upsert one progress post. Factored off the handler so DSN-gated tests
/// exercise the exact SQL without an HTTP layer. `state` is assumed already
/// validated by the caller (the handler) against [`VALID_STATES`].
pub(crate) async fn record_progress(
    pool: &PgPool,
    req: &BackfillProgressRequest,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO backfill_run
             (id, tenant_id, source, state, total, processed, cursor, error, started_at, updated_at)
         VALUES ($1, $2, $3, COALESCE($4, 'running'), $5, $6, $7, $8, now(), now())
         ON CONFLICT (id) DO UPDATE SET
             state      = COALESCE(EXCLUDED.state, backfill_run.state),
             total      = COALESCE(EXCLUDED.total, backfill_run.total),
             processed  = backfill_run.processed + EXCLUDED.processed,
             cursor     = COALESCE(EXCLUDED.cursor, backfill_run.cursor),
             error      = EXCLUDED.error,
             updated_at = now()",
    )
    .bind(req.run_id)
    .bind(req.tenant_id)
    .bind(&req.source)
    .bind(&req.state)
    .bind(req.total)
    .bind(req.processed_delta.max(0))
    .bind(&req.cursor)
    .bind(&req.error)
    .execute(pool)
    .await
    .map(|_| ())
}

/// POST /v1/admin/backfill (admin): one progress post in, upserted by run_id.
pub(crate) async fn post_progress(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackfillProgressRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if let Some(s) = &req.state {
        if !VALID_STATES.contains(&s.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown state {s:?}; expected one of {VALID_STATES:?}"),
            ));
        }
    }
    record_progress(state.pool(), &req)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({ "recorded": true })))
}

/// The latest run per source for a tenant — the dashboard's default view.
/// DISTINCT ON keeps one row per source, the most recently started.
pub(crate) async fn latest_runs(
    pool: &PgPool,
    tenant_id: Uuid,
) -> sqlx::Result<Vec<serde_json::Value>> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (source)
             id, source, state, total, processed, cursor, error, started_at, updated_at
         FROM backfill_run
         WHERE tenant_id = $1
         ORDER BY source, started_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(serde_json::json!({
                "run_id": row.try_get::<Uuid, _>("id")?,
                "source": row.try_get::<String, _>("source")?,
                "state": row.try_get::<String, _>("state")?,
                "total": row.try_get::<Option<i64>, _>("total")?,
                "processed": row.try_get::<i64, _>("processed")?,
                "cursor": row.try_get::<Option<String>, _>("cursor")?,
                "error": row.try_get::<Option<String>, _>("error")?,
                "started_at": row.try_get::<DateTime<Utc>, _>("started_at")?,
                "updated_at": row.try_get::<DateTime<Utc>, _>("updated_at")?,
            }))
        })
        .collect()
}

#[derive(Deserialize)]
pub(crate) struct ListParams {
    tenant_id: Uuid,
}

/// GET /v1/admin/backfill?tenant_id= (admin): the latest backfill run per
/// source for the tenant, alphabetical by source.
pub(crate) async fn get_runs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    latest_runs(state.pool(), p.tenant_id)
        .await
        .map(Json)
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verity_core::adapter::StorageAdapter;
    use verity_storage::PostgresAdapter;

    #[allow(clippy::too_many_arguments)] // a test row-builder; explicit args keep call sites readable
    fn req(
        run_id: Uuid,
        tenant: Uuid,
        source: &str,
        state: Option<&str>,
        total: Option<i64>,
        delta: i64,
        cursor: Option<&str>,
        error: Option<&str>,
    ) -> BackfillProgressRequest {
        BackfillProgressRequest {
            run_id,
            tenant_id: tenant,
            source: source.into(),
            state: state.map(Into::into),
            total,
            processed_delta: delta,
            cursor: cursor.map(Into::into),
            error: error.map(Into::into),
        }
    }

    /// DSN-gated (VERITY_TEST_DSN): a run starts with a total, accumulates
    /// processed deltas, keeps its total/cursor across posts, transitions state
    /// on completion, and clears a transient error; a second run for the same
    /// source supersedes the first in the latest-per-source view; tenants are
    /// isolated.
    #[tokio::test]
    async fn progress_upsert_and_latest_per_source() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let pg = PostgresAdapter::connect_with_kek(&dsn, None)
            .await
            .expect("connect");
        pg.migrate().await.expect("migrate");
        let tenant = pg
            .create_tenant(&format!("backfill-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant");
        let pool = pg.pool();

        // Start a gdrive backfill: total discovered, first page delivered.
        let run1 = Uuid::now_v7();
        record_progress(
            pool,
            &req(
                run1,
                tenant,
                "gdrive",
                Some("running"),
                Some(100),
                40,
                Some("page-2"),
                None,
            ),
        )
        .await
        .expect("start");
        // Advance: no total/state restated, cursor moves, delta accumulates.
        record_progress(
            pool,
            &req(run1, tenant, "gdrive", None, None, 35, Some("page-3"), None),
        )
        .await
        .expect("advance");
        // Complete: state flips, final delta lands.
        record_progress(
            pool,
            &req(
                run1,
                tenant,
                "gdrive",
                Some("completed"),
                None,
                25,
                Some("done"),
                None,
            ),
        )
        .await
        .expect("complete");

        let rows = latest_runs(pool, tenant).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "gdrive");
        assert_eq!(rows[0]["state"], "completed");
        assert_eq!(rows[0]["total"], 100, "total set once and kept");
        assert_eq!(rows[0]["processed"], 100, "deltas accumulate");
        assert_eq!(rows[0]["cursor"], "done");
        assert!(rows[0]["error"].is_null());

        // A source with no up-front count: total stays NULL (indeterminate).
        let run_hs = Uuid::now_v7();
        record_progress(
            pool,
            &req(
                run_hs,
                tenant,
                "hubspot",
                Some("running"),
                None,
                12,
                None,
                None,
            ),
        )
        .await
        .expect("hubspot start");
        // It then fails, recording an error.
        record_progress(
            pool,
            &req(
                run_hs,
                tenant,
                "hubspot",
                Some("failed"),
                None,
                0,
                None,
                Some("401 from source"),
            ),
        )
        .await
        .expect("hubspot fail");

        let rows = latest_runs(pool, tenant).await.expect("list2");
        // Alphabetical by source: gdrive, hubspot.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["source"], "hubspot");
        assert_eq!(rows[1]["state"], "failed");
        assert!(
            rows[1]["total"].is_null(),
            "uncountable source stays indeterminate"
        );
        assert_eq!(rows[1]["processed"], 12);
        assert_eq!(rows[1]["error"], "401 from source");

        // A fresh run for gdrive (re-onboard) supersedes the first in the view.
        let run2 = Uuid::now_v7();
        record_progress(
            pool,
            &req(
                run2,
                tenant,
                "gdrive",
                Some("running"),
                Some(50),
                10,
                Some("re-1"),
                None,
            ),
        )
        .await
        .expect("second gdrive run");
        let rows = latest_runs(pool, tenant).await.expect("list3");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["source"], "gdrive");
        assert_eq!(
            rows[0]["run_id"],
            serde_json::json!(run2),
            "latest run wins"
        );
        assert_eq!(rows[0]["state"], "running");
        assert_eq!(rows[0]["total"], 50);
        assert_eq!(rows[0]["processed"], 10);

        // Tenant isolation: a stranger sees nothing.
        let other = pg
            .create_tenant(&format!("backfill-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant2");
        assert!(latest_runs(pool, other).await.expect("list4").is_empty());
    }
}
