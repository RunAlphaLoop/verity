//! Compliance plane v0 (SPEC §8, roadmap task 23): the admin-only erasure
//! and DSAR-export surfaces.
//!
//! Both are admin verbs, never reachable from an agent scope handle
//! (SPEC §8f — an injected prompt must not be able to trigger destruction of
//! evidence). The heavy lifting lives in verity-storage (erasure.rs); this
//! module is auth + plumbing + the L1 cache flush erasure requires.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use verity_core::types::{StorageError, TenantId};

use crate::{internal, AppState, HandlerResult};

#[derive(Deserialize)]
pub(crate) struct ErasureRequest {
    tenant_id: TenantId,
    /// Data subject: erases episodes with `writer_sub = subject`, actions
    /// with `actor_sub = subject`, the subject's audit rows, and everything
    /// derived from those episodes.
    #[serde(default)]
    subject: Option<String>,
    /// Entity: erases episodes with `source_entity = entity`, facts keyed on
    /// it, chunks tagged with it (multi-tag chunks deleted whole), actions
    /// targeting it. At least one of subject/entity is required.
    #[serde(default)]
    entity: Option<String>,
}

/// POST /v1/admin/erasure (admin) — the GDPR hard-purge path (SPEC §8b),
/// distinct from `memory.forget` invalidation. One transaction; returns
/// per-table hard-delete counts; leaves exactly one audit row (verb
/// 'erasure', sha256-hashed identifiers, no plaintext PII).
pub(crate) async fn admin_erasure(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ErasureRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let report = state
        .storage
        .inner()
        .erase(req.tenant_id, req.subject.as_deref(), req.entity.as_deref())
        .await
        .map_err(|e| match e {
            StorageError::InvalidInput(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            other => internal(other),
        })?;
    // Facts were hard-deleted underneath the L1 current-truth cache.
    state.storage.flush_facts();
    Ok(Json(serde_json::json!({ "erased": report })))
}

#[derive(Deserialize)]
pub(crate) struct DsarParams {
    tenant_id: TenantId,
    subject: String,
}

/// GET /v1/admin/dsar/export?tenant_id=&subject= (admin, SPEC §8e): one
/// machine-readable JSON bundle of everything attributable to the subject —
/// episodes (payloads decrypted under admin authority), their derived
/// chunks, the subject's actions, access-event skeleton, and proposed
/// knowledge items. The export itself is audited.
pub(crate) async fn dsar_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<DsarParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let bundle = state
        .storage
        .inner()
        .dsar_export(p.tenant_id, &p.subject)
        .await
        .map_err(internal)?;
    // Decrypted-under-admin-authority access is itself audited (SPEC §8e).
    let pool = state.pool().clone();
    let tenant_id = p.tenant_id;
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, NULL, 'dsar_export', '{}', '{}', 0, $3, '{}')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind("dsar export (subject withheld from log)")
        .execute(&pool)
        .await;
        if let Err(e) = result {
            tracing::warn!("dsar_export audit insert failed: {e}");
        }
    });
    Ok(Json(bundle))
}
