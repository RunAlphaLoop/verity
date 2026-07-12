//! Source-manifest plane (SPEC §5e.3, task 30): upload → human gate →
//! webhook-bound execution.
//!
//! - POST /v1/manifests (admin): validate YAML with verity-manifest, store as
//!   a DRAFT. Re-uploading a name replaces the YAML and demotes to draft —
//!   every change re-crosses the human gate.
//! - POST /v1/manifests/{id}/activate (admin): THE human gate. Refuses when
//!   acl_policy is absent or violates the declared tier contract; records the
//!   approver on the row and in audit_log.
//! - GET /v1/manifests (admin): list, with parsed acl/tier summary.
//! - `deliver`: the webhook-path hook. A minted webhook bound to a manifest
//!   routes inbound payloads through the manifest runtime instead of the
//!   native shape; anything the runtime cannot claim lands in
//!   quarantine_preview (fail closed, never mis-filed).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_manifest::{
    resolve_secret_ref, runtime, schema, verify_hmac_sha256_hex, Applied, Manifest,
};

use crate::webhooks::{quarantine, Webhook};
use crate::{internal, md5ish, upsert_principal_tokens, AppState, HandlerResult};

// ---------- upload ----------

#[derive(Deserialize)]
pub(crate) struct UploadManifestRequest {
    tenant_id: TenantId,
    yaml: String,
}

/// POST /v1/manifests (admin): validated YAML in, draft row out.
pub(crate) async fn upload_manifest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UploadManifestRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let manifest = Manifest::from_yaml(&req.yaml)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let id = Uuid::now_v7();
    // Same-name re-upload replaces the YAML and demotes to draft: an edited
    // manifest must re-cross the human gate before it executes again.
    let row = sqlx::query(
        "INSERT INTO manifests (id, tenant_id, name, yaml, status)
         VALUES ($1, $2, $3, $4, 'draft')
         ON CONFLICT (tenant_id, name) DO UPDATE SET
             yaml = EXCLUDED.yaml, status = 'draft', approved_by = NULL, updated_at = now()
         RETURNING id",
    )
    .bind(id)
    .bind(req.tenant_id)
    .bind(&manifest.source.name)
    .bind(&req.yaml)
    .fetch_one(state.pool())
    .await
    .map_err(internal)?;
    let id: Uuid = row.try_get("id").map_err(internal)?;
    Ok(Json(serde_json::json!({
        "manifest_id": id,
        "name": manifest.source.name,
        "status": "draft",
        "tier": manifest.source.tier,
        "acl_mode": manifest.acl_mode(),
        // Advisory preview of the gate — activation still requires the call.
        "activation_ready": manifest.activation_check().err().map_or(
            serde_json::json!(true),
            |e| serde_json::json!({ "refused": e.to_string() }),
        ),
    })))
}

// ---------- activate: the human gate ----------

#[derive(Deserialize)]
pub(crate) struct ActivateManifestRequest {
    tenant_id: TenantId,
    /// The approving human — required; this is an explicit approval record,
    /// not a flag flip.
    approved_by: String,
}

/// POST /v1/manifests/{id}/activate (admin).
pub(crate) async fn activate_manifest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ActivateManifestRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let approved_by = req.approved_by.trim().to_string();
    if approved_by.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "activation requires approved_by — the human gate is an approval record".into(),
        ));
    }
    let row = sqlx::query("SELECT name, yaml FROM manifests WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(req.tenant_id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "unknown manifest".to_string()))?;
    let name: String = row.try_get("name").map_err(internal)?;
    let yaml: String = row.try_get("yaml").map_err(internal)?;
    let manifest = Manifest::from_yaml(&yaml)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    // The gate: absent/tier-invalid acl_policy refuses activation.
    manifest
        .activation_check()
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    sqlx::query(
        "UPDATE manifests SET status = 'active', approved_by = $1, updated_at = now()
         WHERE id = $2",
    )
    .bind(&approved_by)
    .bind(id)
    .execute(state.pool())
    .await
    .map_err(internal)?;
    // SPEC §5e.3: admin approval is recorded in the audit log.
    let audit = sqlx::query(
        "INSERT INTO audit_log (id, tenant_id, actor_sub, verb, principals, entity_scope,
                                confidentiality, query_summary, result_ids)
         VALUES ($1, $2, $3, 'manifest_activate', '{}', '{}', 0, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(req.tenant_id)
    .bind(&approved_by)
    .bind(format!(
        "manifest {name:?} mode={:?} tier={:?}",
        manifest.acl_mode(),
        manifest.source.tier
    ))
    .bind(vec![id])
    .execute(state.pool())
    .await;
    if let Err(e) = audit {
        tracing::warn!(manifest = %id, "audit_log insert for activation failed: {e}");
    }
    Ok(Json(serde_json::json!({
        "manifest_id": id,
        "name": name,
        "status": "active",
        "approved_by": approved_by,
    })))
}

// ---------- list ----------

#[derive(Deserialize)]
pub(crate) struct ListManifestsParams {
    tenant_id: TenantId,
}

/// GET /v1/manifests?tenant_id= (admin).
pub(crate) async fn list_manifests(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListManifestsParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT id, name, yaml, status, approved_by, created_at, updated_at
         FROM manifests WHERE tenant_id = $1 ORDER BY name",
    )
    .bind(p.tenant_id)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    rows.iter()
        .map(|row| {
            let yaml: String = row.try_get("yaml").map_err(internal)?;
            let parsed = Manifest::from_yaml(&yaml).ok();
            Ok(serde_json::json!({
                "manifest_id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "name": row.try_get::<String, _>("name").map_err(internal)?,
                "status": row.try_get::<String, _>("status").map_err(internal)?,
                "approved_by": row.try_get::<Option<String>, _>("approved_by").map_err(internal)?,
                "tier": parsed.as_ref().and_then(|m| m.source.tier),
                "acl_mode": parsed.as_ref().map(|m| m.acl_mode()),
                "created_at": row.try_get::<DateTime<Utc>, _>("created_at").map_err(internal)?,
                "updated_at": row.try_get::<DateTime<Utc>, _>("updated_at").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<Vec<_>>>()
        .map(Json)
}

// ---------- dry-run: the live preview backend ----------

#[derive(Deserialize)]
pub(crate) struct DryRunManifestRequest {
    #[allow(dead_code)]
    tenant_id: TenantId,
    /// The (in-progress) manifest, serialized to YAML by the wizard on every
    /// preview so dry-run and activation parse identical bytes.
    manifest_yaml: String,
    /// One real sample message to run through the manifest.
    sample_payload: serde_json::Value,
}

/// POST /v1/manifests/dry-run (admin): the wizard's live-preview backend.
///
/// Pure `from_yaml` + `runtime::apply` + serialize — it NEVER persists (zero
/// DB queries, no episode append, no fact/chunk upsert, no principal-token
/// allocation), so it is safe to call on every keystroke. It runs the SAME
/// engine `deliver()` runs, so the preview is byte-honest.
///
/// Determinism: `apply` runs under `RuntimeOptions::fixture_clock()` (pins
/// `$now()` to 2026-01-01T00:00:00Z) so the preview is reproducible AND
/// identical to what a generated fixture asserts.
///
/// Fail-closed: a manifest whose `acl_policy` is absent (or mode quarantine,
/// or whose principal extraction matched nothing) does NOT return a permissive
/// default — it returns a visible `{"outcome":"quarantine","reason":…}` so the
/// wizard shows "this would be held — no one could see it until you set who
/// can", surfacing the runtime's real reason verbatim.
pub(crate) async fn dry_run_manifest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DryRunManifestRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    // 422 with the verbatim ManifestError powers the wizard's live field
    // validation (a probe manifest with one bad route.when returns the
    // predicate.rs error, mapped client-side to the offending step).
    let manifest = Manifest::from_yaml(&req.manifest_yaml)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let applied = runtime::apply(
        &manifest,
        &req.sample_payload,
        &runtime::RuntimeOptions::fixture_clock(),
    );
    // The identity namespace only labels the who-can-see-it rendering for
    // map mode; static/quarantine ignore it.
    let namespace = manifest
        .acl_policy
        .as_ref()
        .and_then(|p| p.identity_namespace);
    Ok(Json(applied.to_json(namespace)))
}

// ---------- the webhook-path hook ----------

/// Inbound delivery for a manifest-bound webhook. Fail-closed at every step:
/// inactive manifest, unresolvable secret, unparseable payload, unmatched
/// route, or any mapping/ACL failure ⇒ quarantine_preview (202); a declared
/// signature that does not verify ⇒ 401 and no ingestion at all.
pub(crate) async fn deliver(
    state: &Arc<AppState>,
    hook: &Webhook,
    manifest_id: Uuid,
    headers: &HeaderMap,
    body: &[u8],
    received_at: DateTime<Utc>,
) -> HandlerResult<(StatusCode, Json<serde_json::Value>)> {
    let raw_preview = || {
        serde_json::json!({
            "raw": String::from_utf8_lossy(body).chars().take(4096).collect::<String>()
        })
    };
    let row = sqlx::query("SELECT name, yaml, status FROM manifests WHERE id = $1")
        .bind(manifest_id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?;
    let Some(row) = row else {
        let resp = quarantine(
            state,
            hook,
            raw_preview(),
            "bound manifest row missing".into(),
        )
        .await?;
        return Ok((StatusCode::ACCEPTED, resp));
    };
    let name: String = row.try_get("name").map_err(internal)?;
    let yaml: String = row.try_get("yaml").map_err(internal)?;
    let status: String = row.try_get("status").map_err(internal)?;
    let manifest = match Manifest::from_yaml(&yaml) {
        Ok(m) => m,
        Err(e) => {
            let resp = quarantine(
                state,
                hook,
                raw_preview(),
                format!("stored manifest {name:?} no longer parses: {e}"),
            )
            .await?;
            return Ok((StatusCode::ACCEPTED, resp));
        }
    };

    // Signature verification (hmac_sha256 header scheme), before any parsing
    // of attacker-controlled JSON.
    if let Some(sig) = manifest
        .source
        .webhook
        .as_ref()
        .and_then(|w| w.signature.as_ref())
    {
        let Some(secret) = resolve_secret_ref(&sig.secret_ref) else {
            let resp = quarantine(
                state,
                hook,
                raw_preview(),
                format!(
                    "webhook signature secret {} unresolvable (set {})",
                    sig.secret_ref,
                    verity_manifest::signature::secret_ref_env_var(&sig.secret_ref)
                        .unwrap_or_else(|| "a valid secret:// ref".into()),
                ),
            )
            .await?;
            return Ok((StatusCode::ACCEPTED, resp));
        };
        let provided = headers
            .get(sig.header.as_str())
            .and_then(|v| v.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                format!("missing signature header {}", sig.header),
            ))?;
        match sig.scheme {
            schema::SignatureScheme::HmacSha256 => {
                if !verify_hmac_sha256_hex(secret.as_bytes(), body, provided) {
                    return Err((StatusCode::UNAUTHORIZED, "webhook signature invalid".into()));
                }
            }
        }
    }

    if status != "active" {
        let resp = quarantine(
            state,
            hook,
            raw_preview(),
            format!("manifest {name:?} is {status}, not active — awaiting the human gate"),
        )
        .await?;
        return Ok((StatusCode::ACCEPTED, resp));
    }

    let payload: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            let resp = quarantine(state, hook, raw_preview(), format!("invalid JSON: {e}")).await?;
            return Ok((StatusCode::ACCEPTED, resp));
        }
    };

    let applied = runtime::apply(&manifest, &payload, &runtime::RuntimeOptions::default());
    let (source, writes, acl) = match applied {
        Applied::Quarantine { reason } => {
            let resp = quarantine(state, hook, payload, reason).await?;
            return Ok((StatusCode::ACCEPTED, resp));
        }
        Applied::Writes {
            source,
            writes,
            acl,
        } => (source, writes, acl),
    };

    // Resolve the ACL envelope into principal tokens + a provenance tag.
    // Principal strings allocate registry tokens on first sight (idempotent);
    // the caller's side of the intersection comes from directory sync /
    // POST /v1/admin/principals mapping the same strings.
    let (visibility, acl_provenance): (Vec<PrincipalToken>, AclProvenance) = match &acl {
        verity_manifest::AclEnvelope::Static { principals: None } => {
            (hook.visibility.clone(), AclProvenance::AdminAssigned)
        }
        verity_manifest::AclEnvelope::Static {
            principals: Some(strings),
        } => {
            let tokens = upsert_principal_tokens(state.pool(), hook.tenant_id, strings)
                .await?
                .into_iter()
                .map(|(_, t)| t)
                .collect();
            (tokens, AclProvenance::AdminAssigned)
        }
        verity_manifest::AclEnvelope::Mapped {
            principals,
            approximated,
        } => {
            let tokens = upsert_principal_tokens(state.pool(), hook.tenant_id, principals)
                .await?
                .into_iter()
                .map(|(_, t)| t)
                .collect();
            let provenance = if *approximated {
                AclProvenance::Approximated
            } else {
                AclProvenance::Mirrored
            };
            (tokens, provenance)
        }
    };

    let episode_id = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: hook.tenant_id,
            source: source.clone(),
            source_entity: writes.first().map(|w| w.entity_id.clone()),
            kind: EpisodeKind::Webhook,
            content_hash: format!("{:x}", md5ish(&payload.to_string())),
            payload,
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: Some(format!("webhook:{}", hook.id)),
        })
        .await
        .map_err(internal)?;

    let mut facts_written = 0u64;
    let mut chunk_writes = Vec::new();
    let mut entities = Vec::with_capacity(writes.len());
    for write in &writes {
        entities.push(format!("{}:{}", write.entity_type, write.entity_id));
        for (field, value) in &write.fields {
            state
                .storage
                .upsert_fact(FactWrite {
                    tenant_id: hook.tenant_id,
                    key: FactKey {
                        source: source.clone(),
                        entity_id: write.entity_id.clone(),
                        field: field.clone(),
                    },
                    value: value.clone(),
                    valid_from: write.valid_from,
                    // The materialized ACL the manifest resolved for this write,
                    // identical to the sibling chunk's — facts carry the same
                    // visibility the chunk enforces (the L1 leak was dropping it).
                    visibility: visibility.clone(),
                    confidentiality: hook.confidentiality,
                    provenance: episode_id,
                    acl_provenance,
                })
                .await
                .map_err(internal)?;
            facts_written += 1;
        }
        if let Some(content) = &write.content {
            let embedding = state.encode(content).await.ok().flatten();
            chunk_writes.push(ChunkWrite {
                tenant_id: hook.tenant_id,
                source: source.clone(),
                document_id: format!("{}:{}", write.entity_type, write.entity_id),
                seq: 0,
                content: content.clone(),
                content_hash: format!("{:x}", md5ish(content)),
                embedding,
                visibility: visibility.clone(),
                entity_tags: vec![format!("{}:{}", write.entity_type, write.entity_id)],
                confidentiality: hook.confidentiality,
                trust_tier: TrustTier::Authoritative,
                valid_from: write.valid_from,
                provenance: episode_id,
                acl_provenance,
            });
        }
    }
    let chunks_indexed = if chunk_writes.is_empty() {
        0
    } else {
        state
            .storage
            .upsert_chunks(chunk_writes)
            .await
            .map_err(internal)?
    };

    crate::slo::record_sample(state.pool(), hook.tenant_id, &source, received_at).await;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "episode_id": episode_id,
            "manifest": name,
            "source": source,
            "entities": entities,
            "facts_written": facts_written,
            "chunks_indexed": chunks_indexed,
            "acl_provenance": acl_provenance.as_str(),
        })),
    ))
}
