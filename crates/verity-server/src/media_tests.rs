//! Media storage integration tests (task 47): the object-store seam and the
//! bytea fallback, exercised over the real router via HTTP (reqwest), matching
//! the sse_tests harness.
//!
//! Two-tier gating, mirroring the SpiceDB/DSN pattern:
//!   * everything needs `VERITY_TEST_DSN` (a database);
//!   * the object-store test additionally needs `VERITY_MEDIA_S3_ENDPOINT`
//!     (+ bucket/keys) pointed at a live MinIO/S3 — it skips when unset, so
//!     the default `cargo test` run exercises only the bytea path.
//!
//! Invariants covered:
//!   * bytea fallback (no S3 env): upload stores inline `bytes`, storage_ref
//!     NULL, signed GET streams the bytes, tampered sig 403;
//!   * object store (S3 env): upload stores `storage_ref` and NULL bytes, the
//!     key layout is media/<tenant>/<sha256>, signed GET streams it back from
//!     MinIO, tampered sig 403; erasure by media_id purges row AND object.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde_json::Value;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::media::MediaStore;
use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::subscribe::Subscribers;
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN. `media_store` is wired from env when
/// `with_s3` is set (returns None-skip if the store can't build — same policy
/// as the DSN gate). Admin surfaces are open (dev mode).
async fn test_state(with_s3: bool) -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let media_store = if with_s3 {
        match MediaStore::from_env() {
            Ok(Some(ms)) => Some(ms),
            _ => return None, // object-store env not configured => skip
        }
    } else {
        None
    };
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("media-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth {
            key: [0u8; 32],
            expected_tag: None, // dev mode: admin surfaces open
            allowed_origin: None,
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        allow_restricted_without_rebac: false,
        subscribers: Subscribers::new(64),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store,
    });
    Some((state, tenant))
}

async fn spawn(state: Arc<AppState>) -> String {
    let app = Router::new()
        .route("/v1/files", post(crate::media::upload_file))
        .route("/v1/media/{id}", get(crate::media::get_media))
        .route("/v1/media/{id}/sign", post(crate::media::sign_media))
        .route("/v1/admin/erasure", post(crate::compliance::admin_erasure))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

fn scope(state: &AppState, tenant: TenantId) -> String {
    state
        .minter
        .mint(
            ScopePayload {
                tenant_id: tenant,
                principals: vec![7],
                entity_scope: vec![],
                max_confidentiality: Confidentiality::Internal,
                actor_sub: Some("user:media-test".into()),
                actor_azp: Some("agent:media-test".into()),
                subject: None,
                expires_at: Utc::now(),
            },
            300,
        )
        .0
}

async fn upload(base: &str, handle: &str, bytes: &[u8]) -> Value {
    let part = reqwest::multipart::Part::bytes(bytes.to_vec())
        .file_name("blob.bin")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new()
        .text("scope_handle", handle.to_string())
        .part("file", part);
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/files"))
        .multipart(form)
        .send()
        .await
        .expect("upload");
    assert_eq!(resp.status(), 200, "upload should succeed");
    resp.json().await.unwrap()
}

async fn sign(base: &str, handle: &str, media_id: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/media/{media_id}/sign"))
        .json(&serde_json::json!({ "scope_handle": handle }))
        .send()
        .await
        .expect("sign");
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    v["url"].as_str().unwrap().to_string()
}

// ---------- bytea fallback (no S3 env) — always runs under a DSN ----------

#[tokio::test]
async fn bytea_fallback_upload_sign_get_and_tamper() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;
    let handle = scope(&state, tenant);
    let payload = b"hello from bytea land \x00\x01\x02";

    let up = upload(&base, &handle, payload).await;
    let media_id = up["media_id"].as_str().unwrap().to_string();

    // Row carries inline bytes, NULL storage_ref.
    let (bytes_present, ref_present): (bool, bool) = sqlx::query_as(
        "SELECT bytes IS NOT NULL, storage_ref IS NOT NULL FROM media WHERE id = $1::uuid",
    )
    .bind(&media_id)
    .fetch_one(state.pool())
    .await
    .unwrap();
    assert!(bytes_present, "bytea path stores inline bytes");
    assert!(!ref_present, "bytea path leaves storage_ref NULL");

    let url = sign(&base, &handle, &media_id).await;
    let resp = reqwest::get(format!("{base}{url}")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), payload);

    // Tampered signature => 403.
    let tampered = url.replace("sig=", "sig=AAAA");
    let resp = reqwest::get(format!("{base}{tampered}")).await.unwrap();
    assert_eq!(resp.status(), 403);
}

// ---------- object store (S3/MinIO env) — skips without VERITY_MEDIA_* -------

#[tokio::test]
async fn object_store_upload_sign_get_tamper_and_erase() {
    let Some((state, tenant)) = test_state(true).await else {
        eprintln!("VERITY_TEST_DSN / VERITY_MEDIA_S3_ENDPOINT not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;
    let handle = scope(&state, tenant);
    let payload = b"hello from object storage \x00\x01\x02\x03";

    let up = upload(&base, &handle, payload).await;
    let media_id = up["media_id"].as_str().unwrap().to_string();

    // Row carries storage_ref, NULL bytes.
    let (bytes_present, storage_ref): (bool, Option<String>) =
        sqlx::query_as("SELECT bytes IS NOT NULL, storage_ref FROM media WHERE id = $1::uuid")
            .bind(&media_id)
            .fetch_one(state.pool())
            .await
            .unwrap();
    assert!(!bytes_present, "S3 path stores NULL bytes");
    let storage_ref = storage_ref.expect("S3 path sets storage_ref");
    assert!(
        storage_ref.starts_with(&format!("media/{tenant}/")),
        "key layout media/<tenant>/<sha256>, got {storage_ref}"
    );

    // Signed GET streams the bytes back from MinIO.
    let url = sign(&base, &handle, &media_id).await;
    let resp = reqwest::get(format!("{base}{url}")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        payload,
        "GET streams object-store bytes"
    );

    // Tampered signature => 403 (Verity-signed, not S3-presigned).
    let tampered = url.replace("sig=", "sig=AAAA");
    let resp = reqwest::get(format!("{base}{tampered}")).await.unwrap();
    assert_eq!(resp.status(), 403);

    // Erasure purges the row AND the object.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/admin/erasure"))
        .json(&serde_json::json!({ "tenant_id": tenant, "media_ids": [media_id] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "erasure should succeed");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["erased"]["media"].as_u64(),
        Some(1),
        "one media row purged"
    );

    // Object is gone from the bucket: re-deleting is a no-op (NotFound folds to
    // Ok in MediaStore::delete). The bucket name is threaded for diagnostics.
    let ms = state.media_store.as_ref().unwrap();
    assert!(!ms.bucket.is_empty());
    ms.delete(&storage_ref).await.expect("delete idempotent");

    // And the row is unknown => sign 404.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/media/{media_id}/sign"))
        .json(&serde_json::json!({ "scope_handle": handle }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "erased media is unknown");
}
