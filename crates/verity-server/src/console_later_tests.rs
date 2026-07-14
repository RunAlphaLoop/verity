//! Console-"Later" write-surface integration tests (UI-SPEC §5 Screen 6, §6):
//! the admin debug-recall why-out trace and the quarantine re-ingest/dismiss
//! lifecycle, exercising the REAL handlers in-process. DSN-gated on
//! VERITY_TEST_DSN, like identity_tests/manifest_tests — each test skips
//! (passes trivially) when the DSN is absent.
//!
//! What these tests pin down:
//! - debug-recall names WHY each near-miss candidate was dropped
//!   (visibility_no_overlap / visibility_empty / confidentiality_above_ceiling
//!   / entity-scope reasons) and admits the readable one — and every response
//!   carries the honesty block.
//! - quarantine re-ingest has NO "index it anyway" shape: the request REQUIRES
//!   an explicit admin-supplied visibility + confidentiality (serde rejects a
//!   body without them), and what gets indexed is stamped
//!   `acl_provenance = 'admin-assigned'` — never the original unmappable ACL.
//! - the lifecycle is atomic and terminal: OPEN→reingested/dismissed once;
//!   the second disposition gets 409; dismiss indexes NOTHING; a
//!   nothing-ingestible payload is refused (422) and stays open.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
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
/// BM25 leg, which is what these tests query with).
async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("console-later-test-{}", Uuid::now_v7()))
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
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

async fn index_chunk(
    state: &AppState,
    tenant: TenantId,
    doc: &str,
    content: &str,
    visibility: Vec<PrincipalToken>,
    confidentiality: Confidentiality,
) {
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
            content: content.into(),
            content_hash: format!("{doc}-0"),
            embedding: None,
            visibility,
            entity_tags: vec![],
            confidentiality,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        }])
        .await
        .expect("chunk");
}

fn mint(state: &AppState, tenant: TenantId, principals: Vec<PrincipalToken>) -> String {
    let (handle, _) = state.minter.mint(
        ScopePayload {
            tenant_id: tenant,
            principals,
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Internal,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            expires_at: Utc::now(),
        },
        300,
    );
    handle
}

async fn debug_recall(
    state: &Arc<AppState>,
    body: serde_json::Value,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(body).expect("request shape");
    crate::admin_debug_recall(State(Arc::clone(state)), HeaderMap::new(), Json(req))
        .await
        .map(|Json(v)| v)
}

/// DSN-only: the debug-recall trace names a per-candidate drop reason for each
/// mandatory pre-filter, admits what the scope can actually read, and always
/// discloses its honesty bounds.
#[tokio::test]
async fn debug_recall_reports_per_candidate_drop_reasons() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // Four chunks share the query token; only one is admissible to principal 41
    // at ceiling Internal.
    index_chunk(
        &state,
        tenant,
        "doc-visible",
        "zanzibar readable memo",
        vec![41],
        Confidentiality::Internal,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-other-team",
        "zanzibar other-team memo",
        vec![99],
        Confidentiality::Internal,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-no-tokens",
        "zanzibar tokenless memo",
        vec![],
        Confidentiality::Internal,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-secret",
        "zanzibar confidential memo",
        vec![41],
        Confidentiality::Confidential,
    )
    .await;

    let handle = mint(&state, tenant, vec![41]);
    let v = debug_recall(
        &state,
        json!({ "scope_handle": handle, "text": "zanzibar", "candidates": 50 }),
    )
    .await
    .expect("trace");

    let candidates = v["candidates"].as_array().expect("candidates");
    assert_eq!(candidates.len(), 4, "all four tenant chunks traced: {v}");
    let by_doc = |doc: &str| -> &serde_json::Value {
        candidates
            .iter()
            .find(|c| c["document_id"] == doc)
            .unwrap_or_else(|| panic!("candidate {doc} missing from trace"))
    };

    let visible = by_doc("doc-visible");
    assert_eq!(visible["admitted"], true);
    assert!(visible["drop_reasons"].as_array().unwrap().is_empty());

    let other = by_doc("doc-other-team");
    assert_eq!(other["admitted"], false);
    assert_eq!(other["drop_reasons"], json!(["visibility_no_overlap"]));

    let tokenless = by_doc("doc-no-tokens");
    assert_eq!(tokenless["admitted"], false);
    assert_eq!(tokenless["drop_reasons"], json!(["visibility_empty"]));

    let secret = by_doc("doc-secret");
    assert_eq!(secret["admitted"], false);
    assert_eq!(
        secret["drop_reasons"],
        json!(["confidentiality_above_ceiling"])
    );

    // The honesty block is not optional.
    assert!(
        !v["honesty"].as_array().expect("honesty").is_empty(),
        "debug-recall must disclose its bounds"
    );
    assert_eq!(v["query"]["leg"], "bm25");

    // Fail closed exactly like the read path: a garbage handle is 401.
    let err = debug_recall(
        &state,
        json!({ "scope_handle": "not-a-handle", "text": "zanzibar" }),
    )
    .await
    .expect_err("tampered handle must fail closed");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

/// Seed one webhook + one quarantined payload directly (the same rows the
/// webhook fail-closed path writes), returning the quarantine id.
async fn seed_quarantine(state: &AppState, tenant: TenantId, payload: serde_json::Value) -> Uuid {
    let webhook_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, name, token_hash, visibility, entity_scope, confidentiality)
         VALUES ($1, $2, 'console-later-test-hook', $3, '{}', '{}', 1)",
    )
    .bind(webhook_id)
    .bind(tenant)
    .bind(format!("test-hash-{webhook_id}"))
    .execute(state.pool())
    .await
    .expect("webhook row");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO quarantine_preview (id, tenant_id, webhook_id, payload, reason)
         VALUES ($1, $2, $3, $4, 'unrecognized shape: test')",
    )
    .bind(id)
    .bind(tenant)
    .bind(webhook_id)
    .bind(payload)
    .execute(state.pool())
    .await
    .expect("quarantine row");
    id
}

async fn reingest(
    state: &Arc<AppState>,
    id: Uuid,
    body: serde_json::Value,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(body).expect("request shape");
    crate::admin_quarantine_reingest(
        State(Arc::clone(state)),
        HeaderMap::new(),
        Path(id),
        Json(req),
    )
    .await
    .map(|Json(v)| v)
}

async fn dismiss(
    state: &Arc<AppState>,
    id: Uuid,
    body: serde_json::Value,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(body).expect("request shape");
    crate::admin_quarantine_dismiss(
        State(Arc::clone(state)),
        HeaderMap::new(),
        Path(id),
        Json(req),
    )
    .await
    .map(|Json(v)| v)
}

/// DSN-only: re-ingest routes ONLY through the corrected admin mapping — the
/// request shape cannot omit the ACL, the indexed chunk is stamped
/// admin-assigned with EXACTLY the supplied visibility, and the lifecycle is
/// atomic (second disposition → 409).
#[tokio::test]
async fn quarantine_reingest_routes_only_through_corrected_mapping() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };

    // THE no-index-anyway guarantee at the request-shape level: a body that
    // omits the corrected ACL mapping (visibility and/or confidentiality) does
    // not even deserialize — there is no shape that inherits or defaults.
    for body in [
        json!({ "tenant_id": tenant }),
        json!({ "tenant_id": tenant, "visibility": [7] }),
        json!({ "tenant_id": tenant, "confidentiality": "Internal" }),
    ] {
        assert!(
            serde_json::from_value::<crate::QuarantineReingestRequest>(body.clone()).is_err(),
            "re-ingest without an explicit corrected ACL mapping must be unrepresentable: {body}"
        );
    }

    let id = seed_quarantine(
        &state,
        tenant,
        json!({
            "content": "quarantined zebra memo",
            "facts": [
                { "source": "linear", "entity_id": "T-1", "field": "status", "value": "done" }
            ]
        }),
    )
    .await;

    let v = reingest(
        &state,
        id,
        json!({
            "tenant_id": tenant,
            "visibility": [7],
            "confidentiality": "Internal",
            "entity_tags": ["account:acme"],
            "note": "mapped to team 7 by admin",
        }),
    )
    .await
    .expect("reingest through corrected mapping");
    assert_eq!(v["reingested"], true);
    assert_eq!(v["chunks_indexed"], 1);
    assert_eq!(v["facts_written"], 1);

    // What landed in the index carries the ADMIN mapping, never the original
    // (unmappable) source ACL: admin-assigned provenance, exactly vis=[7].
    let row: (Vec<i32>, String, i16) = sqlx::query_as(
        "SELECT visibility, acl_provenance, confidentiality FROM chunks
         WHERE tenant_id = $1 AND content = 'quarantined zebra memo'",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .expect("reingested chunk");
    assert_eq!(row.0, vec![7]);
    assert_eq!(row.1, "admin-assigned");
    assert_eq!(row.2, Confidentiality::Internal as i16);
    let fact_prov: String = sqlx::query_scalar(
        "SELECT acl_provenance FROM facts
         WHERE tenant_id = $1 AND source = 'linear' AND entity_id = 'T-1' AND field = 'status'
           AND valid_to IS NULL",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .expect("reingested fact");
    assert_eq!(fact_prov, "admin-assigned");

    // Terminal lifecycle: the claim is atomic — a second re-ingest AND a
    // dismiss of the same row both lose with 409.
    let err = reingest(
        &state,
        id,
        json!({ "tenant_id": tenant, "visibility": [7], "confidentiality": "Internal" }),
    )
    .await
    .expect_err("double re-ingest");
    assert_eq!(err.0, StatusCode::CONFLICT);
    let err = dismiss(&state, id, json!({ "tenant_id": tenant }))
        .await
        .expect_err("dismiss after re-ingest");
    assert_eq!(err.0, StatusCode::CONFLICT);

    // Invalidate-don't-delete: the quarantine row survives with its
    // disposition stamped.
    let (resolution, note): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT resolution, resolution_note FROM quarantine_preview WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_one(state.pool())
    .await
    .expect("quarantine row survives");
    assert_eq!(resolution.as_deref(), Some("reingested"));
    assert_eq!(note.as_deref(), Some("mapped to team 7 by admin"));
}

/// DSN-only: dismiss indexes NOTHING; a nothing-ingestible payload is refused
/// with 422 and stays OPEN (the 422 never claims the row).
#[tokio::test]
async fn quarantine_dismiss_indexes_nothing_and_empty_payload_is_refused() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };

    // A payload with no content/observation/raw and no facts: re-ingest must
    // refuse (422) rather than fabricate — and must NOT claim the row.
    let empty_id = seed_quarantine(&state, tenant, json!({ "widget": 42 })).await;
    let err = reingest(
        &state,
        empty_id,
        json!({ "tenant_id": tenant, "visibility": [7], "confidentiality": "Internal" }),
    )
    .await
    .expect_err("nothing ingestible");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

    // Still OPEN after the 422 — dismiss succeeds (and only once).
    let v = dismiss(
        &state,
        empty_id,
        json!({ "tenant_id": tenant, "note": "noise" }),
    )
    .await
    .expect("dismiss open item");
    assert_eq!(v["dismissed"], true);
    let err = dismiss(&state, empty_id, json!({ "tenant_id": tenant }))
        .await
        .expect_err("double dismiss");
    assert_eq!(err.0, StatusCode::CONFLICT);

    // Dismiss indexed NOTHING for this tenant.
    let chunks: i64 = sqlx::query_scalar("SELECT count(*) FROM chunks WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(state.pool())
        .await
        .expect("count");
    assert_eq!(chunks, 0, "dismiss must never index a quarantined payload");

    // Unknown id → 404 (distinguished from the 409 already-resolved case).
    let err = dismiss(&state, Uuid::now_v7(), json!({ "tenant_id": tenant }))
        .await
        .expect_err("unknown id");
    assert_eq!(err.0, StatusCode::NOT_FOUND);
}
