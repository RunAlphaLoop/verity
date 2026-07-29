//! Tier-1 extraction integration tests (DSN-gated, same harness pattern as
//! media_tests): upload → extract → chunk → SCOPED recall over the real
//! router, plus the fail-visible path (typed failure ⇒ metadata-only episode
//! with the reason on the record and in the response, zero chunks indexed).
//!
//! All fixture files are generated programmatically (extract::fixtures) — no
//! binaries in the repo. Skips without `VERITY_TEST_DSN`.

use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use chrono::Utc;
use serde_json::Value;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::extract::fixtures;
use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::subscribe::Subscribers;
use crate::{AdminAuth, AppState};

async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("extract-test-{}", uuid::Uuid::now_v7()))
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
        watch_staleness_fence_secs: 900,
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: std::sync::Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        entra_directory: crate::directory_worker::EntraDirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: false,
        subscribers: Subscribers::new(64),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

async fn spawn(state: Arc<AppState>) -> String {
    let app = Router::new()
        .route("/v1/files", post(crate::media::upload_file))
        .route("/v1/recall", post(crate::recall))
        .route("/v1/ingest/documents", post(crate::ingest_documents))
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

fn scope(state: &AppState, tenant: TenantId, principals: Vec<PrincipalToken>) -> String {
    state
        .minter
        .mint(
            ScopePayload {
                tenant_id: tenant,
                principals,
                entity_scope: vec![],
                max_confidentiality: Confidentiality::Internal,
                actor_sub: Some("user:extract-test".into()),
                actor_azp: Some("agent:extract-test".into()),
                subject: None,
                issued_at: Utc::now(),
                expires_at: Utc::now(),
            },
            300,
        )
        .0
}

async fn upload(base: &str, handle: &str, bytes: Vec<u8>, filename: &str, mime: &str) -> Value {
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(mime)
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

async fn recall(base: &str, handle: &str, text: &str) -> Vec<Value> {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/recall"))
        .json(&serde_json::json!({ "scope_handle": handle, "text": text }))
        .send()
        .await
        .expect("recall");
    assert_eq!(resp.status(), 200, "recall should succeed");
    resp.json().await.unwrap()
}

// ---------------------------------------------------------------------------
// /v1/files: upload → extract → chunk → scoped recall
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pdf_upload_extracts_indexes_and_scoped_recall_finds_the_sentence() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;
    let handle = scope(&state, tenant, vec![7]);

    let pdf = fixtures::text_pdf(&["The falcon codeword is zanzibar.", "Second line of proof."]);
    let up = upload(&base, &handle, pdf, "codewords.pdf", "application/pdf").await;
    assert!(up["chunks_indexed"].as_u64().unwrap() >= 1);
    assert_eq!(up["extraction"]["method"].as_str(), Some("pdf-text"));
    assert_eq!(up["extraction"]["truncated"].as_bool(), Some(false));

    // Same-scope recall finds the extracted sentence (BM25 leg; no encoder).
    let hits = recall(&base, &handle, "zanzibar").await;
    assert!(
        hits.iter().any(|h| h["content"]
            .as_str()
            .unwrap_or("")
            .contains("The falcon codeword is zanzibar.")),
        "scoped recall must find the extracted PDF sentence, got {hits:?}"
    );

    // A scope with disjoint principals sees NOTHING — extraction inherits the
    // write pass's visibility, nothing wider.
    let other = scope(&state, tenant, vec![8]);
    let hits = recall(&base, &other, "zanzibar").await;
    assert!(hits.is_empty(), "disjoint scope must recall nothing");
}

#[tokio::test]
async fn encrypted_pdf_upload_is_metadata_only_with_the_reason_on_record() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;
    let handle = scope(&state, tenant, vec![7]);

    let up = upload(
        &base,
        &handle,
        fixtures::encrypted_pdf(),
        "secret.pdf",
        "application/pdf",
    )
    .await;
    let media_id = up["media_id"].as_str().unwrap().to_string();
    assert_eq!(up["chunks_indexed"].as_u64(), Some(0));
    assert_eq!(up["extraction"]["failure"].as_str(), Some("encrypted PDF"));

    // The reason is on the stored record too (fail-visible, not just in the
    // response), and NOTHING joined the index.
    let (payload,): (Value,) = sqlx::query_as(
        "SELECT payload FROM episodes
         WHERE tenant_id = $1 AND source = 'file'
           AND payload->>'media_id' = $2",
    )
    .bind(tenant)
    .bind(&media_id)
    .fetch_one(state.pool())
    .await
    .expect("failure episode stored");
    assert_eq!(
        payload["extraction"]["failure"].as_str(),
        Some("encrypted PDF")
    );
    let (chunks,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM chunks WHERE tenant_id = $1 AND document_id = $2")
            .bind(tenant)
            .bind(format!("media:{media_id}"))
            .fetch_one(state.pool())
            .await
            .unwrap();
    assert_eq!(chunks, 0, "typed failure must index zero chunks");
}

// ---------------------------------------------------------------------------
// /v1/ingest/documents: the connector binary path (content_base64)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn documents_binary_path_extracts_xlsx_under_mirrored_visibility() {
    use base64::Engine as _;
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;

    let xlsx = fixtures::xlsx_two_sheets(
        &[&["Account", "ACV"], &["Osmium Dynamics", "77000"]],
        &[&["Quarter"], &["Q4"]],
    );
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/ingest/documents"))
        .json(&serde_json::json!({
            "tenant_id": tenant,
            "source": "gdrive",
            "document_id": "drive-file-xlsx-1",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&xlsx),
            "filename": "pipeline.xlsx",
            "visibility": [7],
            "acl_provenance": "mirrored",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert!(v["chunks_indexed"].as_u64().unwrap() >= 1);
    assert_eq!(v["extraction"]["method"].as_str(), Some("calamine"));

    // The mirrored visibility (token 7) governs recall, exactly as for text.
    let hits = recall(&base, &scope(&state, tenant, vec![7]), "Osmium").await;
    assert!(
        hits.iter().any(|h| h["content"]
            .as_str()
            .unwrap_or("")
            .contains("Osmium Dynamics\t77000")),
        "recall must find the extracted cell row, got {hits:?}"
    );
    let hits = recall(&base, &scope(&state, tenant, vec![9]), "Osmium").await;
    assert!(hits.is_empty(), "unmirrored principal must see nothing");
}

#[tokio::test]
async fn documents_binary_path_failure_is_metadata_only_and_disclosed() {
    use base64::Engine as _;
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn(Arc::clone(&state)).await;

    // Bytes that claim .pdf but aren't one: magic wins, typed refusal.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/ingest/documents"))
        .json(&serde_json::json!({
            "tenant_id": tenant,
            "source": "gdrive",
            "document_id": "drive-file-bogus-1",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(b"not a pdf"),
            "filename": "bogus.pdf",
            "visibility": [7],
            "acl_provenance": "mirrored",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["chunks_indexed"].as_u64(), Some(0));
    assert_eq!(
        v["extraction"]["failure"].as_str(),
        Some("unrecognized format")
    );

    // Reason rides the episode record (fail-visible).
    let (payload,): (Value,) = sqlx::query_as(
        "SELECT payload FROM episodes
         WHERE tenant_id = $1 AND source = 'gdrive'
           AND payload->>'document_id' = 'drive-file-bogus-1'",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .expect("metadata-only episode stored");
    assert_eq!(
        payload["extraction"]["failure"].as_str(),
        Some("unrecognized format")
    );
    assert_eq!(payload["bytes"].as_u64(), Some(0));
}
