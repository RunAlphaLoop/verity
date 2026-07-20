//! Scoped-read audit log (roadmap task 6, SPEC §7e): who asked what, under
//! which scope, and which ids came back. Writes are spawned off the request
//! path — audit failures are logged, never surfaced, and never add latency
//! to the read verbs.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use verity_core::types::TenantId;

use crate::scope::ScopePayload;
use crate::{internal, AppState, HandlerResult};

/// Record a successful scoped read/forget. Non-blocking: the insert runs on a
/// spawned task; the handler's response never waits on it.
pub(crate) fn spawn_audit(
    state: &Arc<AppState>,
    payload: &ScopePayload,
    verb: &'static str,
    query_summary: Option<&str>,
    result_ids: Vec<Uuid>,
) {
    let pool = state.pool().clone();
    let tenant_id = payload.tenant_id;
    let actor_sub = payload.actor_sub.clone();
    let actor_azp = payload.actor_azp.clone();
    let principals = payload.principals.clone();
    let entity_scope = payload.entity_scope.clone();
    let confidentiality = payload.max_confidentiality as i16;
    // First 120 chars of the query text/ref — a summary, never full content.
    let query_summary: Option<String> = query_summary.map(|s| s.chars().take(120).collect());
    let metrics = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(&actor_sub)
        .bind(&actor_azp)
        .bind(verb)
        .bind(&principals)
        .bind(&entity_scope)
        .bind(confidentiality)
        .bind(&query_summary)
        .bind(&result_ids)
        .execute(&pool)
        .await;
        if let Err(e) = result {
            metrics.record_audit_drop();
            tracing::warn!(verb, "audit_log insert failed: {e}");
        }
    });
}

/// Record a fold's justification for one canonical link (§4.3 audit extension):
/// which live `entity_evidence` rows justified merging `member_ref` into
/// `canonical`. Lightweight — mirrors how knowledge merges store the judge's
/// yes/no + rationale, making every worker-folded link auditable and reversible.
/// Non-blocking, exactly like [`spawn_audit`]; the fold never waits on it.
///
/// `verb = "fold_link"`, `query_summary = "<canonical> <= <member_ref>"`,
/// `result_ids = the justifying evidence uuids`. No scope handle is involved
/// (this is a worker-plane event), so actor/principals/entity_scope are empty.
pub(crate) fn spawn_fold_audit(
    state: &Arc<AppState>,
    tenant_id: TenantId,
    canonical: &str,
    member_ref: &str,
    justifying_evidence: Vec<Uuid>,
) {
    let pool = state.pool().clone();
    // The canonical is NAMED after its lexically-min member, so the anchor
    // member's own link row would read "canon:X <= X" — a legitimate event
    // that looks like a self-link bug (a cold reviewer flagged exactly this).
    // Phrase the anchor case as what it is instead.
    let summary: String = if canonical == format!("canon:{member_ref}") {
        format!("{canonical} anchored at {member_ref}")
    } else {
        format!("{canonical} <= {member_ref}")
    }
    .chars()
    .take(120)
    .collect();
    let metrics = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, NULL, 'fold_link', $3, $4, 0, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(Vec::<i32>::new())
        .bind(Vec::<String>::new())
        .bind(&summary)
        .bind(&justifying_evidence)
        .execute(&pool)
        .await;
        if let Err(e) = result {
            metrics.record_audit_drop();
            tracing::warn!("fold_link audit insert failed: {e}");
        }
    });
}

/// Record a connector-credential lifecycle event (Phase-2 secret intake): a
/// `credential.create` or `credential.revoke` on one (tenant, source). Actor is
/// the admin secret-intake surface itself (`actor_azp = 'admin'`, no scope
/// handle). The `query_summary` carries ONLY the source and the salted-HMAC
/// `fingerprint` — NEVER the secret, never the token, never the path plaintext.
/// Append-only and non-blocking, exactly like [`spawn_audit`].
pub(crate) fn spawn_credential_audit(
    state: &Arc<AppState>,
    tenant_id: TenantId,
    verb: &'static str,
    source: &str,
    fingerprint: &str,
) {
    let pool = state.pool().clone();
    // Source + fingerprint only. The fingerprint is a salted-HMAC prefix, safe
    // to persist; the secret itself is never in scope here.
    let summary: String = format!("{source} fingerprint={fingerprint}")
        .chars()
        .take(120)
        .collect();
    let metrics = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, 'admin', $3, $4, $5, 0, $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(verb)
        .bind(Vec::<i32>::new())
        .bind(Vec::<String>::new())
        .bind(&summary)
        .bind(Vec::<Uuid>::new())
        .execute(&pool)
        .await;
        if let Err(e) = result {
            metrics.record_audit_drop();
            tracing::warn!(verb, "credential audit insert failed: {e}");
        }
    });
}

#[derive(Deserialize)]
pub(crate) struct AuditParams {
    tenant_id: TenantId,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// GET /v1/admin/audit — recent audit rows, newest first (admin plane).
pub(crate) async fn admin_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<AuditParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT id, tenant_id, actor_sub, actor_azp, verb, principals, entity_scope,
                confidentiality, query_summary, result_ids, at
         FROM audit_log WHERE tenant_id = $1 ORDER BY at DESC LIMIT $2",
    )
    .bind(p.tenant_id)
    .bind(p.limit.clamp(1, 1000))
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "tenant_id": row.try_get::<Uuid, _>("tenant_id").map_err(internal)?,
                "actor_sub": row.try_get::<Option<String>, _>("actor_sub").map_err(internal)?,
                "actor_azp": row.try_get::<Option<String>, _>("actor_azp").map_err(internal)?,
                "verb": row.try_get::<String, _>("verb").map_err(internal)?,
                "principals": row.try_get::<Vec<i32>, _>("principals").map_err(internal)?,
                "entity_scope": row.try_get::<Vec<String>, _>("entity_scope").map_err(internal)?,
                "confidentiality": row.try_get::<i16, _>("confidentiality").map_err(internal)?,
                "query_summary": row.try_get::<Option<String>, _>("query_summary").map_err(internal)?,
                "result_ids": row.try_get::<Vec<Uuid>, _>("result_ids").map_err(internal)?,
                "at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("at").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<Vec<_>>>()?;
    Ok(Json(items))
}
