//! Principal-directory read + named-token why-trace tests (UI-ACTIONS N5):
//! GET /v1/admin/principals (the read counterpart to the POST upsert) and the
//! debug-recall trace's `visibility_tokens` array, exercising the REAL
//! handlers in-process. DSN-gated on VERITY_TEST_DSN, like identity_tests /
//! console_later_tests — each test skips (passes trivially) when it's absent.
//!
//! What these tests pin down:
//! - the GET returns exactly the string→token map the POST upsert wrote,
//!   ordered by token, and keyset pagination (`after_token`/`limit`) walks the
//!   directory without overlap or omission (`next_after_token` is null only on
//!   the final short page);
//! - an unknown tenant reads as EMPTY — the read creates nothing;
//! - debug-recall serializes the member tokens (`visibility_tokens`), not just
//!   `visibility_token_count`, so the console can name tokens via the new
//!   directory read.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN (no encoder — debug-recall runs its
/// BM25 leg here).
async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("principals-test-{}", Uuid::now_v7()))
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
        watch: Arc::new(crate::rebac_watch::WatchStatus::new()),
        folder_watchers: Arc::new(crate::folder_watch::WatcherRegistry::new()),
        knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

async fn upsert(state: &Arc<AppState>, tenant: TenantId, principals: &[&str]) -> serde_json::Value {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principals": principals,
    }))
    .expect("request shape");
    let Json(v) = crate::admin_principals(State(Arc::clone(state)), HeaderMap::new(), Json(req))
        .await
        .expect("upsert principals");
    v
}

async fn list(state: &Arc<AppState>, query: serde_json::Value) -> serde_json::Value {
    let q = serde_json::from_value(query).expect("query shape");
    let Json(v) =
        crate::admin_list_principals(State(Arc::clone(state)), HeaderMap::new(), Query(q))
            .await
            .expect("list principals");
    v
}

/// DSN-only: the GET returns exactly what the POST upsert materialized —
/// ordered by token — and keyset pagination walks the full directory with no
/// overlap and no omission.
#[tokio::test]
async fn principals_read_returns_upserted_directory_and_paginates() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    let minted = upsert(
        &state,
        tenant,
        &["user:alice@corp.example", "group:sales", "user:demo"],
    )
    .await;
    let mappings = minted["mappings"].as_object().expect("mappings object");
    assert_eq!(mappings.len(), 3);

    // One-page read: every upserted principal comes back with ITS token,
    // ordered by token ascending, final page ⇒ next_after_token null.
    let v = list(&state, json!({ "tenant_id": tenant })).await;
    let rows = v["principals"].as_array().expect("principals array");
    assert_eq!(rows.len(), 3);
    assert_eq!(v["count"], 3);
    assert!(v["next_after_token"].is_null());
    let mut prev_token = 0i64;
    for row in rows {
        let principal = row["principal"].as_str().expect("principal string");
        let token = row["token"].as_i64().expect("token int");
        assert_eq!(
            mappings[principal].as_i64().unwrap(),
            token,
            "GET must report the same token the upsert minted for {principal}"
        );
        assert!(token > prev_token, "rows must be ordered by token");
        prev_token = token;
    }

    // Keyset walk with limit=1: three full pages (each advertising a cursor),
    // then the cursor past the last row yields the empty final page. Union of
    // pages == the one-shot read, no overlap.
    let mut cursor = 0i64;
    let mut walked: Vec<(String, i64)> = Vec::new();
    for _ in 0..3 {
        let page = list(
            &state,
            json!({ "tenant_id": tenant, "after_token": cursor, "limit": 1 }),
        )
        .await;
        let page_rows = page["principals"].as_array().unwrap();
        assert_eq!(page_rows.len(), 1);
        let token = page_rows[0]["token"].as_i64().unwrap();
        walked.push((
            page_rows[0]["principal"].as_str().unwrap().to_string(),
            token,
        ));
        // A full page advertises a cursor (it can't know it was the last row).
        assert_eq!(page["next_after_token"].as_i64().unwrap(), token);
        cursor = token;
    }
    let tail = list(
        &state,
        json!({ "tenant_id": tenant, "after_token": cursor, "limit": 1 }),
    )
    .await;
    assert_eq!(tail["principals"].as_array().unwrap().len(), 0);
    assert!(tail["next_after_token"].is_null());
    let one_shot: Vec<(String, i64)> = rows
        .iter()
        .map(|r| {
            (
                r["principal"].as_str().unwrap().to_string(),
                r["token"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(walked, one_shot, "paged walk must equal the one-shot read");

    // Idempotence stays observable through the read: re-upserting an existing
    // principal changes nothing.
    upsert(&state, tenant, &["group:sales"]).await;
    let again = list(&state, json!({ "tenant_id": tenant })).await;
    assert_eq!(again["principals"], v["principals"]);

    // A tenant nobody wrote to reads as empty — the read creates nothing.
    let empty = list(&state, json!({ "tenant_id": Uuid::now_v7() })).await;
    assert_eq!(empty["principals"].as_array().unwrap().len(), 0);
    assert_eq!(empty["count"], 0);
    assert!(empty["next_after_token"].is_null());
}

/// DSN-only: the debug-recall trace emits the member tokens themselves
/// (`visibility_tokens`), alongside the pre-existing count, for admitted AND
/// dropped candidates — the array the console joins against
/// GET /v1/admin/principals to name tokens in the why-trace.
#[tokio::test]
async fn debug_recall_trace_names_visibility_tokens() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    // Two chunks: one visible to token 3, one requiring tokens {11, 12}.
    for (doc, visibility) in [("doc-mine", vec![3]), ("doc-theirs", vec![11, 12])] {
        let episode = state
            .storage
            .append_episode(NewEpisode {
                tenant_id: tenant,
                source: "test".into(),
                source_entity: Some(doc.into()),
                kind: EpisodeKind::DocVersion,
                payload: json!({ "doc": doc }),
                content_hash: format!("{doc}-hash"),
                trust_tier: TrustTier::Authoritative,
                writer_sub: None,
                writer_azp: None,
            })
            .await
            .expect("episode");
        state
            .storage
            .upsert_chunks(vec![ChunkWrite {
                tenant_id: tenant,
                source: "test".into(),
                document_id: doc.into(),
                seq: 0,
                content: "quarterly kryptonite forecast".into(),
                content_hash: format!("{doc}-0"),
                embedding: None,
                visibility,
                entity_tags: vec![],
                confidentiality: Confidentiality::Internal,
                trust_tier: TrustTier::Authoritative,
                valid_from: Utc::now(),
                provenance: episode,
                acl_provenance: AclProvenance::Mirrored,
            }])
            .await
            .expect("chunk");
    }

    let (handle, _) = state.minter.mint(
        ScopePayload {
            tenant_id: tenant,
            principals: vec![3],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Internal,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            expires_at: Utc::now(),
        },
        300,
    );
    let req = serde_json::from_value(json!({
        "scope_handle": handle,
        "text": "kryptonite forecast",
    }))
    .expect("request shape");
    let Json(v) = crate::admin_debug_recall(State(Arc::clone(&state)), HeaderMap::new(), Json(req))
        .await
        .expect("debug recall");

    let candidates = v["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 2);
    for c in candidates {
        let tokens: Vec<i64> = c["visibility_tokens"]
            .as_array()
            .expect("visibility_tokens array — count alone is not enough to name tokens")
            .iter()
            .map(|t| t.as_i64().unwrap())
            .collect();
        // The array and the pre-existing count must agree.
        assert_eq!(
            tokens.len() as i64,
            c["visibility_token_count"].as_i64().unwrap()
        );
        match c["document_id"].as_str().unwrap() {
            "doc-mine" => {
                assert_eq!(tokens, vec![3]);
                assert_eq!(c["admitted"], true);
            }
            "doc-theirs" => {
                assert_eq!(tokens, vec![11, 12]);
                assert_eq!(c["admitted"], false);
                let reasons: Vec<&str> = c["drop_reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap())
                    .collect();
                assert!(reasons.contains(&"visibility_no_overlap"));
            }
            other => panic!("unexpected candidate {other}"),
        }
    }
}
