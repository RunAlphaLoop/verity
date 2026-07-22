//! MediaObject + signed URIs (roadmap task 9): blobs live in the `media`
//! table, addressed by uuid, served ONLY through HMAC-signed, expiring URLs
//! minted under a scope handle. Text-like media additionally chunks into the
//! retrieval index under the uploader's scope; PDF / PPTX / XLS(X) go through
//! the Tier-1 extractor (extract.rs — deterministic, Rust-native, no OCR) and
//! index the extracted text, with the method + truncation recorded in
//! provenance and typed extraction failures stored metadata-only, disclosed
//! in both the response and the episode record. Other binary media is
//! store-only.
//!
//! v0.2 seam, stated honestly: the signed GET enforces signature + expiry
//! (and the sign step enforces the tenant match), but per-principal media
//! visibility is not modeled yet — whoever holds an unexpired signed URL can
//! fetch the bytes. Scoped media ACLs land in v0.2.
//!
//! Storage tier (task 47, SPEC §10): blobs live in Postgres `bytea` by
//! default (dev-grade — captured by pg_dump, but bloats the transactional
//! store). When an object store is configured (`VERITY_MEDIA_S3_ENDPOINT` +
//! `VERITY_MEDIA_BUCKET` + access/secret keys), POST /v1/files streams the
//! blob to S3-compatible storage under key `media/<tenant>/<sha256>` and the
//! media row stores that key in `storage_ref` with NULL `bytes`; GET streams
//! it back from object storage. The two backings are mutually exclusive per
//! row (migration 0019 CHECK). The signed-URL scheme is UNCHANGED — URLs stay
//! Verity-HMAC-signed, never S3-presigned, so scoping/expiry/audit stay inside
//! Verity (S3 presigned URLs are a future option; see docs/OPERATIONS.md).

use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use object_store::aws::AmazonS3Builder;
use object_store::{ObjectStore, ObjectStoreExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

use crate::audit::spawn_audit;
use crate::{internal, resolve_entities, AppState, HandlerResult};

/// Object-store seam for media blobs (task 47). `Some` when the S3 env is
/// configured; `None` falls back to the Postgres `bytea` path unchanged.
#[derive(Clone)]
pub(crate) struct MediaStore {
    store: Arc<dyn ObjectStore>,
    /// For operator diagnostics/logging only — the bucket is baked into `store`.
    pub(crate) bucket: String,
}

impl MediaStore {
    /// Build from env, mirroring the SpiceDB/ReBAC seam. Enabled only when both
    /// `VERITY_MEDIA_S3_ENDPOINT` and `VERITY_MEDIA_BUCKET` are set; returns
    /// `Ok(None)` (bytea fallback) when they are not. Credentials come from
    /// `VERITY_MEDIA_ACCESS_KEY` / `VERITY_MEDIA_SECRET_KEY` (falling back to
    /// the standard AWS_* names); region defaults to `us-east-1` (MinIO
    /// ignores it). `allow_http` is enabled for `http://` endpoints (MinIO in
    /// dev) — real S3/GCS/R2 use https and this is a no-op.
    pub(crate) fn from_env() -> anyhow::Result<Option<Self>> {
        let (Ok(endpoint), Ok(bucket)) = (
            std::env::var("VERITY_MEDIA_S3_ENDPOINT"),
            std::env::var("VERITY_MEDIA_BUCKET"),
        ) else {
            return Ok(None);
        };
        let access = std::env::var("VERITY_MEDIA_ACCESS_KEY")
            .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
            .map_err(|_| anyhow::anyhow!("VERITY_MEDIA_ACCESS_KEY not set"))?;
        let secret = std::env::var("VERITY_MEDIA_SECRET_KEY")
            .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
            .map_err(|_| anyhow::anyhow!("VERITY_MEDIA_SECRET_KEY not set"))?;
        let region =
            std::env::var("VERITY_MEDIA_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let allow_http = endpoint.starts_with("http://");
        let store = AmazonS3Builder::new()
            .with_endpoint(&endpoint)
            .with_bucket_name(&bucket)
            .with_access_key_id(access)
            .with_secret_access_key(secret)
            .with_region(region)
            .with_allow_http(allow_http)
            // MinIO speaks path-style; virtual-hosted needs bucket DNS.
            .with_virtual_hosted_style_request(false)
            .build()?;
        tracing::info!(bucket = %bucket, endpoint = %endpoint, "media object store enabled");
        Ok(Some(Self {
            store: Arc::new(store),
            bucket,
        }))
    }

    /// Deterministic object key: `media/<tenant>/<sha256>`. Content-addressed,
    /// so identical bytes under a tenant collapse to one object.
    fn key(tenant: Uuid, sha256: &str) -> object_store::path::Path {
        object_store::path::Path::from(format!("media/{tenant}/{sha256}"))
    }

    async fn put(&self, tenant: Uuid, sha256: &str, bytes: Vec<u8>) -> anyhow::Result<String> {
        let path = Self::key(tenant, sha256);
        self.store
            .put(&path, bytes::Bytes::from(bytes).into())
            .await?;
        tracing::debug!(bucket = %self.bucket, key = %path, "media blob written to object store");
        Ok(path.to_string())
    }

    async fn get(&self, storage_ref: &str) -> anyhow::Result<Vec<u8>> {
        let path = object_store::path::Path::from(storage_ref);
        let got = self.store.get(&path).await?;
        Ok(got.bytes().await?.to_vec())
    }

    /// Best-effort object delete for erasure (§8). A missing object is not an
    /// error — the DB row is the source of truth for what erasure must remove.
    pub(crate) async fn delete(&self, storage_ref: &str) -> anyhow::Result<()> {
        let path = object_store::path::Path::from(storage_ref);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

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

/// text/*, application/json, and .md files chunk into the index verbatim;
/// PDF/PPTX/XLS(X) are handled by extract.rs before this check; everything
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
    let (bytes, mime, filename) = file.ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing file field".to_string(),
    ))?;
    ingest_file(&state, &handle, bytes, mime, filename, entities_field).await
}

/// The post-parse core of [`upload_file`], callable without a multipart body so
/// the file-ingest path — including its entity-resolution `mark_dirty` signal —
/// is unit-testable. Verifies the scope handle, persists the blob, indexes
/// extractable/text content, and marks the tenant dirty for resolution.
pub(crate) async fn ingest_file(
    state: &AppState,
    handle: &str,
    bytes: Vec<u8>,
    mime: String,
    filename: Option<String>,
    entities_field: Option<String>,
) -> HandlerResult<Json<serde_json::Value>> {
    let payload = state.verify_scope(handle)?;
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
    let size_bytes = bytes.len() as i64;
    // Object-store tier when configured, else inline bytea. Exactly one of
    // (bytes, storage_ref) is non-NULL per row (migration 0019). The blob is
    // written to object storage BEFORE the row so a crash never leaves a row
    // pointing at an absent object; a rare orphaned object (row insert fails)
    // is harmless dead weight, garbage-collectable by key.
    let (stored_bytes, storage_ref): (Option<Vec<u8>>, Option<String>) =
        if let Some(ms) = &state.media_store {
            let key = ms
                .put(payload.tenant_id, &sha256, bytes.clone())
                .await
                .map_err(internal)?;
            (None, Some(key))
        } else {
            (Some(bytes.clone()), None)
        };
    sqlx::query(
        "INSERT INTO media (id, tenant_id, sha256, mime, filename, bytes, size_bytes, storage_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(media_id)
    .bind(payload.tenant_id)
    .bind(&sha256)
    .bind(&mime)
    .bind(&filename)
    .bind(&stored_bytes)
    .bind(size_bytes)
    .bind(&storage_ref)
    .execute(state.pool())
    .await
    .map_err(internal)?;

    // What joins the retrieval index (fail-visible, never silently empty):
    //   * PDF / PPTX / XLS(X) → Tier-1 extraction (extract.rs). Success
    //     indexes the extracted text with method + truncation in provenance;
    //     a typed failure stores the episode METADATA-ONLY with the reason
    //     disclosed on the record and in the response — the same fail-visible
    //     pattern the Drive connector uses for non-extractable mimetypes.
    //   * text-like media indexes verbatim. Invalid UTF-8 under a text mime
    //     is treated as binary rather than lossily indexed.
    //   * everything else is store-only in v0.1 (no episode, as before).
    enum Plan {
        Index {
            text: String,
            method: &'static str,
            truncated: bool,
        },
        Refuse(crate::extract::ExtractFailure),
        StoreOnly,
    }
    let plan = match crate::extract::extract(&bytes, filename.as_deref()) {
        crate::extract::ExtractOutcome::Extracted(ex) => Plan::Index {
            text: ex.text,
            method: ex.method,
            truncated: ex.truncated,
        },
        crate::extract::ExtractOutcome::Failed(f) => Plan::Refuse(f),
        crate::extract::ExtractOutcome::NotHandled => {
            match is_text_like(&mime, filename.as_deref())
                .then(|| std::str::from_utf8(&bytes).ok())
                .flatten()
            {
                Some(s) => Plan::Index {
                    text: s.to_string(),
                    method: "utf-8",
                    truncated: false,
                },
                None => Plan::StoreOnly,
            }
        }
    };

    let mut chunks_indexed = 0usize;
    let mut extraction_receipt: Option<serde_json::Value> = None;
    match plan {
        Plan::Index {
            text,
            method,
            truncated,
        } => {
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
                        "extraction": { "method": method, "truncated": truncated },
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
            // Mark the tenant dirty so entity resolution materializes tags/
            // aliases for these freshly-indexed chunks — the same signal
            // ingest_documents (main.rs), the debezium sink, and webhooks all
            // emit after a write. Its absence here meant file content added via
            // `verity-cli add` (POST /v1/files) was never entity-resolved.
            state.resolution.mark_dirty(payload.tenant_id);
            extraction_receipt = Some(serde_json::json!({
                "method": method,
                "truncated": truncated,
            }));
        }
        Plan::Refuse(failure) => {
            let reason = failure.reason();
            state
                .storage
                .append_episode(NewEpisode {
                    tenant_id: payload.tenant_id,
                    source: "file".into(),
                    source_entity: entities.first().cloned(),
                    kind: EpisodeKind::DocVersion,
                    payload: serde_json::json!({
                        "media_id": media_id, "filename": filename,
                        "mime": mime, "sha256": sha256, "size_bytes": bytes.len(),
                        "extraction": { "failure": reason },
                    }),
                    content_hash: sha256.clone(),
                    trust_tier: TrustTier::Observation,
                    writer_sub: payload.actor_sub.clone(),
                    writer_azp: payload.actor_azp.clone(),
                })
                .await
                .map_err(internal)?;
            extraction_receipt = Some(serde_json::json!({ "failure": reason }));
        }
        Plan::StoreOnly => {}
    }

    let mut resp = serde_json::json!({
        "media_id": media_id,
        "chunks_indexed": chunks_indexed,
    });
    if let Some(x) = extraction_receipt {
        resp["extraction"] = x;
    }
    Ok(Json(resp))
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
    let row = sqlx::query("SELECT mime, bytes, storage_ref FROM media WHERE id = $1")
        .bind(id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "unknown media".to_string()))?;
    let mime: String = row.try_get("mime").map_err(internal)?;
    let storage_ref: Option<String> = row.try_get("storage_ref").map_err(internal)?;
    // storage_ref => object store; else inline bytea (migration 0019 CHECK
    // guarantees exactly one is set). A storage_ref row on a server with no
    // media store configured is an operator misconfiguration, reported 500.
    let bytes = match storage_ref {
        Some(key) => {
            let ms = state.media_store.as_ref().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "media row references object storage but no media store is configured".to_string(),
            ))?;
            ms.get(&key).await.map_err(internal)?
        }
        None => row.try_get("bytes").map_err(internal)?,
    };
    Ok(([(header::CONTENT_TYPE, mime)], bytes))
}

// ---------- admin listing (erasure support, task 28) ----------

#[derive(Deserialize)]
pub(crate) struct AdminMediaParams {
    tenant_id: Uuid,
    #[serde(default = "default_media_limit")]
    limit: usize,
}

fn default_media_limit() -> usize {
    200
}

/// GET /v1/admin/media?tenant_id= (admin): list a tenant's media blobs —
/// id, filename, sha256, size, created — newest first. This is the operator
/// surface for finding subject-attributable blobs to name in an erasure
/// request's `media_ids` (media rows carry no subject attribution in v0).
/// Metadata only; bytes are never returned here.
pub(crate) async fn admin_list_media(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(p): axum::extract::Query<AdminMediaParams>,
) -> HandlerResult<Json<Vec<serde_json::Value>>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT id, filename, sha256, mime, size_bytes, created_at
         FROM media WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2",
    )
    .bind(p.tenant_id)
    .bind(p.limit.clamp(1, 1000) as i64)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    rows.iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "filename": row.try_get::<Option<String>, _>("filename").map_err(internal)?,
                "sha256": row.try_get::<String, _>("sha256").map_err(internal)?,
                "mime": row.try_get::<String, _>("mime").map_err(internal)?,
                "size_bytes": row.try_get::<i64, _>("size_bytes").map_err(internal)?,
                "created_at": row.try_get::<chrono::DateTime<Utc>, _>("created_at").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<Vec<_>>>()
        .map(Json)
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
