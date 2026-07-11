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
    /// targeting it. At least one of subject/entity/media_ids is required.
    #[serde(default)]
    entity: Option<String>,
    /// Explicit media blobs to purge in the same transaction (tenant-checked
    /// in storage). Media rows carry no subject attribution in v0, so the
    /// operator names them — GET /v1/admin/media lists the candidates.
    #[serde(default)]
    media_ids: Vec<Uuid>,
}

/// POST /v1/admin/erasure (admin) — the GDPR hard-purge path (SPEC §8b),
/// distinct from `memory.forget` invalidation. One transaction; returns
/// per-table hard-delete counts; leaves exactly one audit row (verb
/// 'erasure', sha256-hashed identifiers, no plaintext PII).
///
/// ReBAC ordering (task 28, fail closed): when SpiceDB is configured and the
/// subject is a `user:` principal, the subject's relationship tuples are
/// deleted FIRST. A tuple-delete failure aborts the whole erasure with 502 —
/// nothing is purged, nothing is half-erased; the operator retries once
/// SpiceDB is healthy. The alternative order (storage first) could leave a
/// deleted subject still granting group membership after a partial failure,
/// which is the direction that leaks; this order at worst over-RETAINS
/// (tuples gone, data pending retry), never over-grants.
pub(crate) async fn admin_erasure(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ErasureRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let mut rebac_tuples_deleted = false;
    if let (Some(rebac), Some(subject)) = (&state.rebac, req.subject.as_deref()) {
        if let Some((crate::rebac::PrincipalKind::User, name)) =
            crate::rebac::parse_principal(subject)
        {
            rebac
                .delete_subject_relationships(req.tenant_id, name)
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("spicedb tuple delete failed — erasure aborted (fail closed, nothing was purged): {e}"),
                    )
                })?;
            rebac_tuples_deleted = true;
        }
        // Non-`user:` subjects have no SpiceDB object by construction
        // (rebac.rs models users and groups only) — nothing to delete.
    }
    // Object-store purge (task 47, SPEC §8): the DB `erase()` DELETEs media
    // rows in one transaction inside verity-storage, but the physical blobs of
    // storage_ref-backed rows live in object storage and must be purged too.
    // Capture the storage_refs of the named media_ids BEFORE the DB delete,
    // then delete the objects AFTER the row purge commits — so a failed DB
    // erasure never orphans a live row from its deleted blob. bytea rows have
    // NULL storage_ref and are purged with the transaction, nothing to do.
    let storage_refs: Vec<String> = if state.media_store.is_some() && !req.media_ids.is_empty() {
        sqlx::query_scalar(
            "SELECT storage_ref FROM media
             WHERE tenant_id = $1 AND id = ANY($2) AND storage_ref IS NOT NULL",
        )
        .bind(req.tenant_id)
        .bind(&req.media_ids)
        .fetch_all(state.pool())
        .await
        .map_err(internal)?
    } else {
        Vec::new()
    };

    let report = state
        .storage
        .inner()
        .erase(
            req.tenant_id,
            req.subject.as_deref(),
            req.entity.as_deref(),
            &req.media_ids,
        )
        .await
        .map_err(|e| match e {
            StorageError::InvalidInput(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            other => internal(other),
        })?;

    // Rows are gone; now purge their objects. Best-effort per object (a
    // missing object is a no-op); a hard object-store failure surfaces as 502
    // so the operator knows a blob may survive in the bucket and can retry the
    // named media_ids (the DB rows are already gone — re-running erasure with
    // the same ids is a safe no-op on the DB side).
    if let Some(ms) = &state.media_store {
        for key in &storage_refs {
            ms.delete(key).await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("media row purged but object storage delete failed for {key}: {e}"),
                )
            })?;
        }
    }
    // Facts were hard-deleted underneath the L1 current-truth cache.
    state.storage.flush_facts();
    Ok(Json(serde_json::json!({
        "erased": report,
        // Honest signal for the operator runbook: false means either ReBAC
        // is not configured (delete tuples via SpiceDB directly) or the
        // subject was not a `user:` principal (no tuples exist for it).
        "rebac_tuples_deleted": rebac_tuples_deleted,
    })))
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
