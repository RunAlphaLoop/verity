//! `POST /v1/admin/retire` integration tests — the enforcement half of a
//! connector-detected retraction (the SharePoint parked-retractions drain),
//! exercising the real handler in-process against `VERITY_TEST_DSN`.
//!
//! Gating is HARD-ERROR (panic), not silent-skip (the `identity_tests` /
//! `crosswalk_tests` posture): these are enforcement-soundness tests — a
//! missing database is a misconfiguration to surface loudly, never a class of
//! test to silently no-op.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde_json::json;
use sqlx::Row;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState, HandlerResult};

const TEST_ADMIN_TOKEN: &str = "test-admin-token";

/// Minimal real AppState against `VERITY_TEST_DSN` with a configured admin
/// bearer (the retire route is `check`-gated; a configured token makes the
/// gate real instead of dev-open). No encoder/ReBAC — unused on this plane.
async fn retire_state() -> (Arc<AppState>, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the /v1/admin/retire enforcement tests; \
         refusing to silently no-op",
    );
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("retire-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth::for_test(Some(TEST_ADMIN_TOKEN), None),
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
        source_freshness: crate::source_freshness::SourceFreshnessPlane::new(None),
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: true,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    (state, tenant)
}

fn admin_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {TEST_ADMIN_TOKEN}").parse().unwrap(),
    );
    h
}

/// Seed one document with `seqs` current chunks under a real visibility set —
/// the state a connector's mirrored ingest leaves behind.
async fn index_document(state: &AppState, tenant: TenantId, source: &str, doc: &str, seqs: i32) {
    let episode = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
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
    let chunks: Vec<ChunkWrite> = (0..seqs)
        .map(|seq| ChunkWrite {
            tenant_id: tenant,
            source: source.into(),
            document_id: doc.into(),
            seq,
            content: format!("{doc} chunk {seq}"),
            content_hash: format!("{doc}-{seq}"),
            embedding: None,
            visibility: vec![101, 202],
            entity_tags: vec![],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .collect();
    state.storage.upsert_chunks(chunks).await.expect("chunks");
}

async fn retire(
    state: &Arc<AppState>,
    tenant: TenantId,
    source: &str,
    document_id: &str,
    reason: &str,
) -> HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": source,
        "document_id": document_id,
        "reason": reason,
    }))
    .expect("request shape");
    let Json(v) =
        crate::admin_retire_document(State(Arc::clone(state)), admin_headers(), Json(req)).await?;
    Ok(v)
}

/// `(current_rows, blanked_closed_rows, total_rows)` for one lineage.
async fn lineage_counts(
    state: &AppState,
    tenant: TenantId,
    source: &str,
    doc: &str,
) -> (i64, i64, i64) {
    let row = sqlx::query(
        "SELECT count(*) FILTER (WHERE valid_to IS NULL) AS current,
                count(*) FILTER (WHERE valid_to IS NOT NULL AND visibility = '{}') AS blanked,
                count(*) AS total
         FROM chunks WHERE tenant_id = $1 AND source = $2 AND document_id = $3",
    )
    .bind(tenant)
    .bind(source)
    .bind(doc)
    .fetch_one(state.storage.inner().pool())
    .await
    .expect("lineage counts");
    (
        row.get::<i64, _>("current"),
        row.get::<i64, _>("blanked"),
        row.get::<i64, _>("total"),
    )
}

/// The tenant's ledger rows as `(source, document_id, reason, chunks_retired)`
/// in `retired_at` order.
async fn ledger_rows(state: &AppState, tenant: TenantId) -> Vec<(String, String, String, i64)> {
    sqlx::query(
        "SELECT source, document_id, reason, chunks_retired
         FROM document_retire_ledger WHERE tenant_id = $1
         ORDER BY retired_at, id",
    )
    .bind(tenant)
    .fetch_all(state.storage.inner().pool())
    .await
    .expect("ledger rows")
    .iter()
    .map(|r| {
        (
            r.get("source"),
            r.get("document_id"),
            r.get("reason"),
            r.get("chunks_retired"),
        )
    })
    .collect()
}

#[tokio::test]
async fn retire_closes_current_chunks_blanks_visibility_and_ledgers() {
    let (state, tenant) = retire_state().await;
    index_document(&state, tenant, "sharepoint", "b!drive:item-gone", 2).await;
    index_document(&state, tenant, "sharepoint", "b!drive:item-keeps", 1).await;

    let v = retire(&state, tenant, "sharepoint", "b!drive:item-gone", "removed")
        .await
        .expect("retire ok");
    assert_eq!(v, json!({ "chunks_retired": 2 }));

    // The lineage is closed AND over-hidden: no current rows, every closed row
    // carries the blanked visibility. Nothing was DELETEd (bi-temporal).
    let (current, blanked, total) =
        lineage_counts(&state, tenant, "sharepoint", "b!drive:item-gone").await;
    assert_eq!((current, blanked, total), (0, 2, 2));

    // Scoping: the neighboring document's chunks are untouched and current.
    let (current, _, total) =
        lineage_counts(&state, tenant, "sharepoint", "b!drive:item-keeps").await;
    assert_eq!((current, total), (1, 1));

    // One append-only evidence row, carrying the honest count.
    assert_eq!(
        ledger_rows(&state, tenant).await,
        vec![(
            "sharepoint".into(),
            "b!drive:item-gone".into(),
            "removed".into(),
            2
        )]
    );
}

#[tokio::test]
async fn retire_replay_is_idempotent_and_still_ledgered() {
    let (state, tenant) = retire_state().await;
    index_document(&state, tenant, "sharepoint", "b!drive:item-q", 1).await;

    let v = retire(
        &state,
        tenant,
        "sharepoint",
        "b!drive:item-q",
        "quarantined",
    )
    .await
    .expect("first retire");
    assert_eq!(v, json!({ "chunks_retired": 1 }));

    // The replay (the connector drain re-driving a parked entry) matches no
    // current rows: 0 retired, 200 — never a 404 — and STILL a ledger row, so
    // the re-drive is recorded evidence.
    let v = retire(
        &state,
        tenant,
        "sharepoint",
        "b!drive:item-q",
        "quarantined",
    )
    .await
    .expect("replay retire");
    assert_eq!(v, json!({ "chunks_retired": 0 }));

    // A never-indexed document behaves like a replay: recorded, not an error
    // (the drain must be able to unpark a signal the index never held).
    let v = retire(
        &state,
        tenant,
        "sharepoint",
        "b!drive:never-seen",
        "acl_unresolvable",
    )
    .await
    .expect("never-indexed retire");
    assert_eq!(v, json!({ "chunks_retired": 0 }));

    assert_eq!(
        ledger_rows(&state, tenant).await,
        vec![
            (
                "sharepoint".into(),
                "b!drive:item-q".into(),
                "quarantined".into(),
                1
            ),
            (
                "sharepoint".into(),
                "b!drive:item-q".into(),
                "quarantined".into(),
                0
            ),
            (
                "sharepoint".into(),
                "b!drive:never-seen".into(),
                "acl_unresolvable".into(),
                0
            ),
        ]
    );
}

/// Current rows still carrying the seeded visibility `{101,202}` — proof a
/// lineage was neither closed nor blanked by a neighboring retire.
async fn current_intact(state: &AppState, tenant: TenantId, source: &str, doc: &str) -> i64 {
    sqlx::query(
        "SELECT count(*) AS n FROM chunks
         WHERE tenant_id = $1 AND source = $2 AND document_id = $3
           AND valid_to IS NULL AND visibility = '{101,202}'",
    )
    .bind(tenant)
    .bind(source)
    .bind(doc)
    .fetch_one(state.storage.inner().pool())
    .await
    .expect("intact count")
    .get::<i64, _>("n")
}

#[tokio::test]
async fn retire_is_scoped_to_its_tenant_and_source() {
    // The retire predicate is (tenant_id, source, document_id) — a connector
    // drain replay in tenant A / source X must leave tenant B's and source
    // Y's lineages for the SAME document_id untouched: still current, with
    // visibility intact (never blanked cross-scope).
    let (state, tenant_a) = retire_state().await;
    let tenant_b = state
        .storage
        .create_tenant(&format!("retire-test-b-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant b");

    let doc = "b!drive:item-shared";
    index_document(&state, tenant_a, "sharepoint", doc, 2).await; // the target
    index_document(&state, tenant_a, "gdrive", doc, 1).await; // source Y, same tenant
    index_document(&state, tenant_b, "sharepoint", doc, 1).await; // tenant B, same source

    let v = retire(&state, tenant_a, "sharepoint", doc, "removed")
        .await
        .expect("retire ok");
    assert_eq!(v, json!({ "chunks_retired": 2 }));

    // The target lineage closed + blanked.
    let (current, blanked, total) = lineage_counts(&state, tenant_a, "sharepoint", doc).await;
    assert_eq!((current, blanked, total), (0, 2, 2));
    assert_eq!(current_intact(&state, tenant_a, "sharepoint", doc).await, 0);

    // Cross-SOURCE (tenant A, gdrive): untouched — valid_to NULL, visibility intact.
    let (current, blanked, total) = lineage_counts(&state, tenant_a, "gdrive", doc).await;
    assert_eq!((current, blanked, total), (1, 0, 1));
    assert_eq!(current_intact(&state, tenant_a, "gdrive", doc).await, 1);

    // Cross-TENANT (tenant B, sharepoint): untouched — valid_to NULL, visibility intact.
    let (current, blanked, total) = lineage_counts(&state, tenant_b, "sharepoint", doc).await;
    assert_eq!((current, blanked, total), (1, 0, 1));
    assert_eq!(current_intact(&state, tenant_b, "sharepoint", doc).await, 1);

    // Evidence is scoped too: one ledger row for tenant A, none for tenant B.
    assert_eq!(
        ledger_rows(&state, tenant_a).await,
        vec![("sharepoint".into(), doc.into(), "removed".into(), 2)]
    );
    assert_eq!(ledger_rows(&state, tenant_b).await, vec![]);
}

#[tokio::test]
async fn retire_rejects_unknown_reason_with_422_and_writes_nothing() {
    let (state, tenant) = retire_state().await;
    index_document(&state, tenant, "sharepoint", "b!drive:item-x", 1).await;

    let err = retire(&state, tenant, "sharepoint", "b!drive:item-x", "cleanup")
        .await
        .expect_err("unaudited reason must 422");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

    let (current, _, _) = lineage_counts(&state, tenant, "sharepoint", "b!drive:item-x").await;
    assert_eq!(current, 1, "a refused retire must not touch the index");
    assert_eq!(ledger_rows(&state, tenant).await, vec![]);
}

#[tokio::test]
async fn retire_unknown_tenant_is_404_and_gate_refuses_bad_bearer() {
    let (state, tenant) = retire_state().await;

    // Fail-closed on an unknown tenant: 404 (UnknownTenant), no ledger row.
    let bogus: TenantId = uuid::Uuid::now_v7();
    let err = retire(&state, bogus, "sharepoint", "b!drive:item-x", "removed")
        .await
        .expect_err("unknown tenant must not 200");
    assert_eq!(err.0, StatusCode::NOT_FOUND);

    // The check-gate is real once a token is configured: a wrong bearer 401s.
    let mut wrong = HeaderMap::new();
    wrong.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer not-the-token".parse().unwrap(),
    );
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "sharepoint",
        "document_id": "b!drive:item-x",
        "reason": "removed",
    }))
    .expect("request shape");
    let err = crate::admin_retire_document(State(Arc::clone(&state)), wrong, Json(req))
        .await
        .expect_err("wrong bearer must not pass");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}
