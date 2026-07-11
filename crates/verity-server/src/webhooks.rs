//! Minted scoped webhook URLs (roadmap task 8): an admin mints a capability
//! URL bound to a tenant + visibility + entity scope + confidentiality; any
//! system that can POST JSON becomes a memory source, with no code on the
//! sender side. The URL token IS the credential — only its sha256 is stored,
//! and posted payloads can NARROW the bound visibility but never widen it.
//! Unparseable or unknown-shaped payloads land in `quarantine_preview` for
//! admin review instead of being permissively indexed (fail closed, SPEC §5e).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

use crate::{internal, md5ish, AppState, HandlerResult};

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

// ---------- mint ----------

#[derive(Deserialize)]
pub(crate) struct MintWebhookRequest {
    tenant_id: TenantId,
    name: String,
    visibility: Vec<PrincipalToken>,
    #[serde(default)]
    entity_scope: Vec<String>,
    #[serde(default = "default_confidentiality")]
    confidentiality: Confidentiality,
    /// Manifest binding (SPEC §5e.3, task 30): inbound payloads route through
    /// the manifest runtime instead of the native shape. Binding a draft is
    /// legal — it quarantines everything until the manifest passes the human
    /// gate.
    #[serde(default)]
    manifest_id: Option<Uuid>,
}

fn default_confidentiality() -> Confidentiality {
    Confidentiality::Internal
}

/// POST /v1/webhooks (admin): mint a scoped ingest URL. The raw token is
/// returned exactly once; only its hash persists.
pub(crate) async fn mint_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MintWebhookRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    if req.visibility.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "a webhook needs a non-empty visibility set (empty = nothing it writes is ever readable)".into(),
        ));
    }
    if let Some(manifest_id) = req.manifest_id {
        // Bindable = exists in this tenant; activation state is checked per
        // delivery so revoking approval takes effect immediately.
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM manifests WHERE id = $1 AND tenant_id = $2")
                .bind(manifest_id)
                .bind(req.tenant_id)
                .fetch_optional(state.pool())
                .await
                .map_err(internal)?;
        if exists.is_none() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "manifest_id does not name a manifest in this tenant".into(),
            ));
        }
    }
    let mut raw = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, name, token_hash, visibility, entity_scope,
                               confidentiality, manifest_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(req.tenant_id)
    .bind(&req.name)
    .bind(token_hash(&token))
    .bind(&req.visibility)
    .bind(&req.entity_scope)
    .bind(req.confidentiality as i16)
    .bind(req.manifest_id)
    .execute(state.pool())
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "webhook_id": id,
        "url": format!("/wh/{token}"),
    })))
}

/// DELETE /v1/webhooks/{id} (admin): revoke — the URL stops resolving.
pub(crate) async fn revoke_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let result =
        sqlx::query("UPDATE webhooks SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(id)
            .execute(state.pool())
            .await
            .map_err(internal)?;
    Ok(Json(
        serde_json::json!({ "revoked": result.rows_affected() > 0 }),
    ))
}

// ---------- inbound post ----------

/// The native payload shape. Anything that fails to parse into this — or
/// parses but carries neither content nor facts — is quarantined, not dropped
/// and not permissively indexed.
#[derive(Deserialize)]
struct NativePayload {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    observation: Option<String>,
    #[serde(default)]
    entities: Vec<String>,
    #[serde(default)]
    facts: Vec<NativeFact>,
    /// May NARROW the webhook's bound visibility (subset), never widen.
    #[serde(default)]
    visibility: Option<Vec<PrincipalToken>>,
}

#[derive(Deserialize)]
struct NativeFact {
    source: String,
    entity_id: String,
    field: String,
    value: serde_json::Value,
    #[serde(default)]
    valid_from: Option<DateTime<Utc>>,
}

pub(crate) struct Webhook {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: TenantId,
    pub(crate) name: String,
    pub(crate) visibility: Vec<PrincipalToken>,
    pub(crate) entity_scope: Vec<String>,
    pub(crate) confidentiality: Confidentiality,
    /// Manifest binding: Some ⇒ payloads route through the manifest runtime
    /// (manifests::deliver), never the native shape below.
    pub(crate) manifest_id: Option<Uuid>,
}

pub(crate) async fn quarantine(
    state: &AppState,
    hook: &Webhook,
    payload: serde_json::Value,
    reason: String,
) -> HandlerResult<Json<serde_json::Value>> {
    sqlx::query(
        "INSERT INTO quarantine_preview (id, tenant_id, webhook_id, payload, reason)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(hook.tenant_id)
    .bind(hook.id)
    .bind(payload)
    .bind(&reason)
    .execute(state.pool())
    .await
    .map_err(internal)?;
    tracing::info!(webhook = %hook.id, reason, "webhook payload quarantined");
    Ok(Json(serde_json::json!({ "quarantined": true })))
}

/// POST /wh/{token}: the inbound lane. Content/observation becomes an L0
/// episode + Tier-2 chunk under the webhook's bound scope; facts become
/// deterministic L1 upserts. Response is 200 with counts, or 202
/// {"quarantined":true} when the payload can't be understood.
pub(crate) async fn webhook_post(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> HandlerResult<(StatusCode, Json<serde_json::Value>)> {
    // Freshness SLO event time (task 21): webhooks carry no source clock, so
    // receipt time is the event time — the sample measures receipt→queryable.
    let received_at = Utc::now();
    let row = sqlx::query(
        "SELECT id, tenant_id, name, visibility, entity_scope, confidentiality, manifest_id
         FROM webhooks WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(token_hash(&token))
    .fetch_optional(state.pool())
    .await
    .map_err(internal)?
    .ok_or((StatusCode::NOT_FOUND, "unknown webhook".to_string()))?;
    let hook = Webhook {
        id: row.try_get("id").map_err(internal)?,
        tenant_id: row.try_get("tenant_id").map_err(internal)?,
        name: row.try_get("name").map_err(internal)?,
        visibility: row.try_get("visibility").map_err(internal)?,
        entity_scope: row.try_get("entity_scope").map_err(internal)?,
        confidentiality: conf_from_i16(row.try_get("confidentiality").map_err(internal)?),
        manifest_id: row.try_get("manifest_id").map_err(internal)?,
    };

    // Manifest-bound webhooks route through the manifest runtime (SPEC §5e.3)
    // instead of the native shape below.
    if let Some(manifest_id) = hook.manifest_id {
        return crate::manifests::deliver(&state, &hook, manifest_id, &headers, &body, received_at)
            .await;
    }

    // Unparseable bytes → quarantine (the raw text is preserved for preview).
    let raw: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let preview = serde_json::json!({ "raw": String::from_utf8_lossy(&body).chars().take(4096).collect::<String>() });
            let resp = quarantine(&state, &hook, preview, format!("invalid JSON: {e}")).await?;
            return Ok((StatusCode::ACCEPTED, resp));
        }
    };
    // Known JSON, unknown shape → quarantine.
    let native: NativePayload = match serde_json::from_value(raw.clone()) {
        Ok(n) => n,
        Err(e) => {
            let resp = quarantine(&state, &hook, raw, format!("unrecognized shape: {e}")).await?;
            return Ok((StatusCode::ACCEPTED, resp));
        }
    };
    let text = native.content.as_ref().or(native.observation.as_ref());
    if text.is_none() && native.facts.is_empty() {
        let resp = quarantine(
            &state,
            &hook,
            raw,
            "payload carries neither content/observation nor facts".into(),
        )
        .await?;
        return Ok((StatusCode::ACCEPTED, resp));
    }

    // Visibility narrowing only: requested ⊆ bound, else 403. (An empty
    // subset is legal and fail-closed: it writes memory nobody can read.)
    let visibility = match &native.visibility {
        None => hook.visibility.clone(),
        Some(req) if req.iter().all(|t| hook.visibility.contains(t)) => req.clone(),
        Some(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                "payload visibility may narrow the webhook's bound set, never widen it".into(),
            ))
        }
    };
    // Entity binding, same subset semantics as scope handles (SPEC §7c).
    let entities = if hook.entity_scope.is_empty() {
        native.entities.clone()
    } else if native.entities.is_empty() {
        hook.entity_scope.clone()
    } else if native
        .entities
        .iter()
        .all(|e| hook.entity_scope.contains(e))
    {
        native.entities.clone()
    } else {
        return Err((
            StatusCode::FORBIDDEN,
            "entities outside the webhook's entity_scope".into(),
        ));
    };

    let source = format!("webhook:{}", hook.name);
    let episode_id = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: hook.tenant_id,
            source: source.clone(),
            source_entity: entities.first().cloned(),
            kind: EpisodeKind::Webhook,
            content_hash: format!("{:x}", md5ish(&raw.to_string())),
            payload: raw,
            // Webhook-derived content mirrors an external system of record.
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: Some(format!("webhook:{}", hook.id)),
        })
        .await
        .map_err(internal)?;

    let mut chunks_indexed = 0usize;
    if let Some(text) = text {
        let embedding = state.encode(text).await.ok().flatten();
        chunks_indexed = state
            .storage
            .upsert_chunks(vec![ChunkWrite {
                tenant_id: hook.tenant_id,
                source: source.clone(),
                document_id: format!("wh:{episode_id}"),
                seq: 0,
                content: text.clone(),
                content_hash: format!("wh-{episode_id}"),
                embedding,
                visibility: visibility.clone(),
                entity_tags: entities.clone(),
                confidentiality: hook.confidentiality,
                trust_tier: TrustTier::Authoritative,
                valid_from: Utc::now(),
                provenance: episode_id,
                // Bound at mint time by an admin — explicit policy, not a
                // mirrored or approximated source ACL.
                acl_provenance: AclProvenance::AdminAssigned,
            }])
            .await
            .map_err(internal)?;
    }

    let mut facts_written = 0u64;
    for fact in &native.facts {
        state
            .storage
            .upsert_fact(FactWrite {
                tenant_id: hook.tenant_id,
                key: FactKey {
                    source: fact.source.clone(),
                    entity_id: fact.entity_id.clone(),
                    field: fact.field.clone(),
                },
                value: fact.value.clone(),
                valid_from: fact.valid_from.unwrap_or_else(Utc::now),
                provenance: episode_id,
                acl_provenance: AclProvenance::AdminAssigned,
            })
            .await
            .map_err(internal)?;
        facts_written += 1;
    }

    // Sampled only for accepted payloads — quarantined ones never became
    // queryable, so they carry no freshness signal.
    crate::slo::record_sample(state.pool(), hook.tenant_id, &source, received_at).await;

    // Auto-resolve trigger: an accepted payload wrote L1 (facts and/or a
    // chunk). Quarantine paths returned 202 above and never reach here. Never
    // affects the response; the background loop does the work.
    state.resolution.mark_dirty(hook.tenant_id);

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "episode_id": episode_id,
            "chunks_indexed": chunks_indexed,
            "facts_written": facts_written,
        })),
    ))
}

fn conf_from_i16(v: i16) -> Confidentiality {
    match v {
        0 => Confidentiality::Public,
        1 => Confidentiality::Internal,
        2 => Confidentiality::Confidential,
        _ => Confidentiality::Restricted,
    }
}

// ---------- quarantine preview ----------

#[derive(Deserialize)]
pub(crate) struct QuarantineParams {
    tenant_id: TenantId,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// GET /v1/admin/quarantine (admin): recent quarantined payloads, newest first.
pub(crate) async fn admin_quarantine(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<QuarantineParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT id, webhook_id, payload, reason, at FROM quarantine_preview
         WHERE tenant_id = $1 ORDER BY at DESC LIMIT $2",
    )
    .bind(p.tenant_id)
    .bind(p.limit.clamp(1, 500))
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "webhook_id": row.try_get::<Uuid, _>("webhook_id").map_err(internal)?,
                "payload": row.try_get::<serde_json::Value, _>("payload").map_err(internal)?,
                "reason": row.try_get::<String, _>("reason").map_err(internal)?,
                "at": row.try_get::<DateTime<Utc>, _>("at").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<Vec<_>>>()?;
    Ok(Json(items))
}
