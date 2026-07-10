//! MediaObject + signed URIs (roadmap task 9): blobs live in the `media`
//! table, addressed by uuid, served ONLY through HMAC-signed, expiring URLs
//! minted under a scope handle. Text-like media additionally chunks into the
//! retrieval index under the uploader's scope; binary media is store-only.
//!
//! v0.2 seam, stated honestly: the signed GET enforces signature + expiry
//! (and the sign step enforces the tenant match), but per-principal media
//! visibility is not modeled yet — whoever holds an unexpired signed URL can
//! fetch the bytes. Scoped media ACLs land in v0.2.

use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

use crate::audit::spawn_audit;
use crate::{internal, resolve_entities, AppState, HandlerResult};

/// Target chunk size for text media, in chars (~500 tokens).
pub(crate) const CHUNK_CHARS: usize = 2000;

/// Split text into ~`max`-char chunks on paragraph boundaries. Paragraphs are
/// packed greedily; a single paragraph longer than `max` is hard-split at
/// char boundaries. Deterministic — no LLM anywhere near the write path.
pub(crate) fn split_text(text: &str, max: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for para in text.split("\n\n") {
        let para = para.trim_end();
        if para.is_empty() {
            continue;
        }
        if !current.is_empty() && current.len() + 2 + para.len() > max {
            chunks.push(std::mem::take(&mut current));
        }
        if para.len() > max {
            // Oversized paragraph: flush and hard-split at char boundaries.
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            let mut rest = para;
            while rest.len() > max {
                let mut cut = max;
                while !rest.is_char_boundary(cut) {
                    cut -= 1;
                }
                chunks.push(rest[..cut].to_string());
                rest = &rest[cut..];
            }
            current = rest.to_string();
        } else {
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            current.push_str(para);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// text/*, application/json, and .md files chunk into the index; everything
/// else is store-only in v0.1.
fn is_text_like(mime: &str, filename: Option<&str>) -> bool {
    mime.starts_with("text/")
        || mime == "application/json"
        || filename.is_some_and(|f| f.to_ascii_lowercase().ends_with(".md"))
}

/// POST /v1/files — multipart: scope_handle, file, entities? (comma-sep).
pub(crate) async fn upload_file(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> HandlerResult<Json<serde_json::Value>> {
    let mut scope_handle: Option<String> = None;
    let mut entities_field: Option<String> = None;
    let mut file: Option<(Vec<u8>, String, Option<String>)> = None; // bytes, mime, filename
    let bad = |e: &dyn std::fmt::Display| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string());
    while let Some(field) = multipart.next_field().await.map_err(|e| bad(&e))? {
        match field.name() {
            Some("scope_handle") => scope_handle = Some(field.text().await.map_err(|e| bad(&e))?),
            Some("entities") => entities_field = Some(field.text().await.map_err(|e| bad(&e))?),
            Some("file") => {
                let mime = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let filename = field.file_name().map(str::to_string);
                let bytes = field.bytes().await.map_err(|e| bad(&e))?;
                file = Some((bytes.to_vec(), mime, filename));
            }
            _ => {}
        }
    }
    let handle = scope_handle.ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing scope_handle field".to_string(),
    ))?;
    let payload = state.verify_scope(&handle)?;
    let (bytes, mime, filename) = file.ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing file field".to_string(),
    ))?;
    let entities = resolve_entities(
        &payload,
        entities_field
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )?;

    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let media_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO media (id, tenant_id, sha256, mime, filename, bytes, size_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(media_id)
    .bind(payload.tenant_id)
    .bind(&sha256)
    .bind(&mime)
    .bind(&filename)
    .bind(&bytes)
    .bind(bytes.len() as i64)
    .execute(state.pool())
    .await
    .map_err(internal)?;

    // Text-like media joins the retrieval index; binary (or non-UTF-8) media
    // is store-only. Invalid UTF-8 under a text mime is treated as binary
    // rather than lossily indexed.
    let text = if is_text_like(&mime, filename.as_deref()) {
        std::str::from_utf8(&bytes).ok().map(str::to_string)
    } else {
        None
    };
    let mut chunks_indexed = 0usize;
    if let Some(text) = text {
        let episode_id = state
            .storage
            .append_episode(NewEpisode {
                tenant_id: payload.tenant_id,
                source: "file".into(),
                source_entity: entities.first().cloned(),
                kind: EpisodeKind::DocVersion,
                payload: serde_json::json!({
                    "media_id": media_id, "filename": filename,
                    "mime": mime, "sha256": sha256, "size_bytes": bytes.len(),
                }),
                content_hash: sha256.clone(),
                trust_tier: TrustTier::Observation,
                writer_sub: payload.actor_sub.clone(),
                writer_azp: payload.actor_azp.clone(),
            })
            .await
            .map_err(internal)?;

        let now = Utc::now();
        let mut writes = Vec::new();
        for (seq, content) in split_text(&text, CHUNK_CHARS).into_iter().enumerate() {
            let embedding = state.encode(&content).await.ok().flatten();
            writes.push(ChunkWrite {
                tenant_id: payload.tenant_id,
                source: "file".into(),
                document_id: format!("media:{media_id}"),
                seq: seq as i32,
                content,
                content_hash: format!("{sha256}-{seq}"),
                embedding,
                visibility: payload.principals.clone(),
                entity_tags: entities.clone(),
                confidentiality: payload.max_confidentiality,
                trust_tier: TrustTier::Observation,
                valid_from: now,
                provenance: episode_id,
                acl_provenance: AclProvenance::AdminAssigned,
            });
        }
        chunks_indexed = state
            .storage
            .upsert_chunks(writes)
            .await
            .map_err(internal)?;
    }

    Ok(Json(serde_json::json!({
        "media_id": media_id,
        "chunks_indexed": chunks_indexed,
    })))
}

// ---------- signing ----------

#[derive(Deserialize)]
pub(crate) struct SignMediaRequest {
    scope_handle: String,
    #[serde(default = "default_ttl")]
    ttl_seconds: i64,
}

fn default_ttl() -> i64 {
    300
}

/// POST /v1/media/{id}/sign: mint a signed, expiring URL for a blob the
/// caller's tenant owns. Missing and cross-tenant media both answer 404 so
/// the endpoint is not an existence oracle.
pub(crate) async fn sign_media(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<SignMediaRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(&req.scope_handle)?;
    let tenant: Option<Uuid> = sqlx::query_scalar("SELECT tenant_id FROM media WHERE id = $1")
        .bind(id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?;
    if tenant != Some(payload.tenant_id) {
        return Err((StatusCode::NOT_FOUND, "unknown media".into()));
    }
    let exp = Utc::now().timestamp() + req.ttl_seconds.clamp(30, 24 * 60 * 60);
    let sig = state.minter.sign_media(id, exp);
    spawn_audit(
        &state,
        &payload,
        "media_sign",
        Some(&id.to_string()),
        vec![id],
    );
    Ok(Json(serde_json::json!({
        "url": format!("/v1/media/{id}?sig={sig}&exp={exp}"),
        "expires_at": exp,
    })))
}

#[derive(Deserialize)]
pub(crate) struct MediaGetParams {
    sig: String,
    exp: i64,
}

/// GET /v1/media/{id}?sig=&exp=: verify the signature and expiry, then stream
/// the bytes with the stored content-type. (Per-principal media visibility is
/// v0.2 — see the module header.)
pub(crate) async fn get_media(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::extract::Query(p): axum::extract::Query<MediaGetParams>,
) -> HandlerResult<impl IntoResponse> {
    state
        .minter
        .verify_media(id, p.exp, &p.sig)
        .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    let row = sqlx::query("SELECT mime, bytes FROM media WHERE id = $1")
        .bind(id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "unknown media".to_string()))?;
    let mime: String = row.try_get("mime").map_err(internal)?;
    let bytes: Vec<u8> = row.try_get("bytes").map_err(internal)?;
    Ok(([(header::CONTENT_TYPE, mime)], bytes))
}

#[cfg(test)]
mod tests {
    use super::split_text;

    #[test]
    fn splits_on_paragraphs_and_packs_greedily() {
        let text = format!(
            "{}\n\n{}\n\n{}",
            "a".repeat(1200),
            "b".repeat(1200),
            "c".repeat(300)
        );
        let chunks = split_text(&text, 2000);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].len() <= 2000 && chunks[0].starts_with('a'));
        assert!(chunks[1].contains("b") && chunks[1].contains("c"));
        // Paragraph boundary preserved inside the packed chunk.
        assert!(chunks[1].contains("\n\n"));
    }

    #[test]
    fn hard_splits_oversized_paragraphs_on_char_boundaries() {
        let text = "é".repeat(3000); // 2-byte chars force boundary care
        let chunks = split_text(&text, 2000);
        assert!(chunks.len() >= 3);
        assert!(chunks.iter().all(|c| c.len() <= 2000));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn empty_and_whitespace_input_yield_nothing() {
        assert!(split_text("", 2000).is_empty());
        assert!(split_text("\n\n \n\n", 2000).is_empty());
    }
}
