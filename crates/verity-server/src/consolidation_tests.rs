//! Consolidation-plane integration tests (v0.3 task 33), exercising the real
//! handlers in-process against Postgres. Gating follows the VERITY_TEST_DSN
//! pattern: tests skip without it.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{consolidation, AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN (no encoder: the knowledge merge
/// path under test is the deterministic normalized-exact-match leg).
async fn test_state(auto_tag: bool) -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("consolidation-test-{}", Uuid::now_v7()))
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
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag,
        knowledge_merge_threshold: consolidation::DEFAULT_MERGE_THRESHOLD,
    });
    Some((state, tenant))
}

async fn append(
    state: &AppState,
    tenant: TenantId,
    kind: EpisodeKind,
    entity: &str,
    text: &str,
) -> EpisodeId {
    state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "agent".into(),
            source_entity: Some(entity.into()),
            kind,
            payload: json!({ "observation": text, "entities": [entity] }),
            content_hash: format!("{:x}", crate::md5ish(text)),
            trust_tier: TrustTier::Observation,
            writer_sub: Some("user:test".into()),
            writer_azp: Some("agent:test".into()),
        })
        .await
        .expect("episode")
}

async fn lease_ids(state: &Arc<AppState>, tenant: TenantId) -> Vec<Uuid> {
    let req = serde_json::from_value(json!({ "tenant_id": tenant, "limit": 50 })).unwrap();
    let Json(body) = consolidation::lease(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .expect("lease");
    body["episodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["episode_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

async fn expire_leases(state: &AppState, tenant: TenantId) {
    sqlx::query(
        "UPDATE episode_processing SET leased_until = now() - interval '1 second'
         WHERE tenant_id = $1",
    )
    .bind(tenant)
    .execute(state.pool())
    .await
    .expect("expire");
}

async fn complete(
    state: &Arc<AppState>,
    body: serde_json::Value,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(body).unwrap();
    consolidation::complete(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .map(|Json(v)| v)
}

// ---------- lease semantics ----------

#[tokio::test]
async fn lease_excludes_cdc_and_expired_leases_are_reclaimed() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // CDC is deterministic at ingest (SPEC §2 L1) — must never be leased.
    let cdc = append(&state, tenant, EpisodeKind::CdcEvent, "acct-1", "row image").await;
    let obs1 = append(
        &state,
        tenant,
        EpisodeKind::Observation,
        "acct-1",
        "note one",
    )
    .await;
    let obs2 = append(
        &state,
        tenant,
        EpisodeKind::Observation,
        "acct-2",
        "note two",
    )
    .await;

    let ids = lease_ids(&state, tenant).await;
    assert!(!ids.contains(&cdc), "cdc episode must not be leased");
    assert!(ids.contains(&obs1) && ids.contains(&obs2));
    assert_eq!(ids.len(), 2);

    // Live lease: nothing to hand out.
    assert!(lease_ids(&state, tenant).await.is_empty());

    // Expired lease (dead worker) → both come back.
    expire_leases(&state, tenant).await;
    let ids = lease_ids(&state, tenant).await;
    assert_eq!(ids.len(), 2, "expired leases must be re-leasable");

    // Completed episodes stay terminal even after expiry.
    complete(&state, json!({ "tenant_id": tenant, "episode_id": obs1 }))
        .await
        .expect("complete");
    expire_leases(&state, tenant).await;
    let ids = lease_ids(&state, tenant).await;
    assert_eq!(ids, vec![obs2], "processed episode must never re-lease");

    // Completing again is an idempotent no-op, not an error.
    let body = complete(&state, json!({ "tenant_id": tenant, "episode_id": obs1 }))
        .await
        .expect("idempotent complete");
    assert_eq!(body["already_processed"], json!(true));

    // Completing an episode that was never leased fails closed.
    let stray = append(&state, tenant, EpisodeKind::Observation, "acct-9", "stray").await;
    let err = complete(&state, json!({ "tenant_id": tenant, "episode_id": stray })).await;
    assert!(err.is_err(), "unleased episode must not complete");
}

// ---------- L2 facts: supersession through the L1 machinery ----------

#[tokio::test]
async fn complete_writes_l2_facts_with_subject_relation_supersession() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "acct-1", "one").await;
    // Later event time for the second write so it supersedes, not StaleEvent.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "acct-1", "two").await;
    lease_ids(&state, tenant).await;

    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "l2_facts": [{ "subject": "Acme  Corp", "relation": "Renewal Stage", "object": "negotiation" }],
        }),
    )
    .await
    .expect("complete 1");
    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "l2_facts": [{ "subject": "acme corp", "relation": "renewal stage", "object": "closed_won" }],
        }),
    )
    .await
    .expect("complete 2");

    // Normalized (subject, relation) keying: both writes hit ONE key, so the
    // second structurally retires the first — exactly one current row.
    let key = FactKey {
        source: "l2".into(),
        entity_id: "acme corp".into(),
        field: "renewal stage".into(),
    };
    let current = state
        .storage
        .current_fact(tenant, &key)
        .await
        .expect("read")
        .expect("current fact");
    assert_eq!(current.value, json!("closed_won"));

    let current_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM facts
         WHERE tenant_id = $1 AND source = 'l2' AND entity_id = 'acme corp'
           AND field = 'renewal stage' AND valid_to IS NULL",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .expect("count");
    assert_eq!(current_rows, 1, "supersession must leave one current row");

    // Bi-temporal history intact: the superseded value is as-of queryable.
    let asof = state
        .storage
        .fact_as_of(
            tenant,
            &key,
            Utc::now() - chrono::Duration::milliseconds(15),
        )
        .await
        .expect("as-of");
    assert!(asof.is_some());
}

// ---------- knowledge merge: support accrual ----------

#[tokio::test]
async fn similar_statement_merges_and_accrues_support() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    let statement = "Healthcare customers consistently require DPA redlines before review.";
    let body1 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{ "statement": statement, "categories": ["industry:healthcare"], "evidence": [obs1] }],
        }),
    )
    .await
    .expect("complete 1");
    assert_eq!(body1["knowledge"][0]["merged"], json!(false));
    let kid = body1["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Whitespace/case variation still merges: the check is normalized.
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{ "statement": "healthcare customers  consistently require dpa redlines before review.", "evidence": [obs2] }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(body2["knowledge"][0]["merged"], json!(true));
    assert_eq!(
        body2["knowledge"][0]["knowledge_id"].as_str().unwrap(),
        kid,
        "similar statement must accrue on the existing item, not mint a new one"
    );

    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 1, "no duplicate knowledge item");
    let item = &items[0];
    assert_eq!(item.distinct_entities, 2, "distinct-entity support accrued");
    assert_eq!(item.episode_count, 2);
    assert!(item.last_reinforced >= item.first_seen);
}

// ---------- tag suggestions: suggest-only default, opt-in auto-apply ----------

async fn episode_with_chunk(
    state: &Arc<AppState>,
    tenant: TenantId,
    entity: &str,
    text: &str,
) -> (EpisodeId, Uuid) {
    let ep = append(state, tenant, EpisodeKind::Observation, entity, text).await;
    state
        .storage
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "agent".into(),
            document_id: format!("obs:{ep}"),
            seq: 0,
            content: text.into(),
            content_hash: format!("obs-{ep}"),
            embedding: None,
            visibility: vec![1],
            entity_tags: vec![],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: ep,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .expect("chunk");
    let chunk_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM chunks WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL",
    )
    .bind(tenant)
    .bind(ep)
    .fetch_one(state.pool())
    .await
    .expect("chunk id");
    (ep, chunk_id)
}

async fn chunk_tags(state: &AppState, tenant: TenantId, chunk_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT entity_tags FROM chunks WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(chunk_id)
        .fetch_one(state.pool())
        .await
        .expect("tags")
}

#[tokio::test]
async fn auto_tag_is_off_by_default_and_approve_applies() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let (ep, chunk_id) = episode_with_chunk(&state, tenant, "account:acme", "acme wants X").await;
    lease_ids(&state, tenant).await;

    let body = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": ep,
            "tag_suggestions": [{ "chunk_id": chunk_id, "tag": "account:acme", "confidence": 0.95 }],
        }),
    )
    .await
    .expect("complete");
    assert_eq!(body["tag_suggestions"]["suggested"], json!(1));
    assert_eq!(body["tag_suggestions"]["auto_applied"], json!(0));
    assert!(
        chunk_tags(&state, tenant, chunk_id).await.is_empty(),
        "default is suggest-only: the chunk must be untouched"
    );

    // Review queue lists it; approval applies the tag.
    let params =
        serde_json::from_value(json!({ "tenant_id": tenant, "status": "suggested" })).unwrap();
    let Json(listed) =
        consolidation::list_tag_suggestions(State(state.clone()), HeaderMap::new(), Query(params))
            .await
            .expect("list");
    let suggestion = &listed["suggestions"][0];
    assert_eq!(suggestion["tag"], json!("account:acme"));
    let sid: Uuid = suggestion["id"].as_str().unwrap().parse().unwrap();

    let approve_req = serde_json::from_value(json!({ "tenant_id": tenant })).unwrap();
    let Json(approved) = consolidation::approve_tag_suggestion(
        State(state.clone()),
        HeaderMap::new(),
        Path(sid),
        Json(approve_req),
    )
    .await
    .expect("approve");
    assert_eq!(approved["status"], json!("approved"));
    assert_eq!(
        chunk_tags(&state, tenant, chunk_id).await,
        vec!["account:acme".to_string()]
    );

    // Approving twice fails closed (already approved).
    let approve_req = serde_json::from_value(json!({ "tenant_id": tenant })).unwrap();
    let again = consolidation::approve_tag_suggestion(
        State(state.clone()),
        HeaderMap::new(),
        Path(sid),
        Json(approve_req),
    )
    .await;
    assert!(again.is_err());
}

#[tokio::test]
async fn auto_tag_applies_immediately_when_opted_in() {
    let Some((state, tenant)) = test_state(true).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let (ep, chunk_id) = episode_with_chunk(&state, tenant, "account:zed", "zed wants Y").await;
    lease_ids(&state, tenant).await;

    let body = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": ep,
            "tag_suggestions": [
                { "chunk_id": chunk_id, "tag": "account:zed", "confidence": 0.95 },
                // Below the 0.9 floor: stays a suggestion even with auto-tag on.
                { "chunk_id": chunk_id, "tag": "account:maybe", "confidence": 0.6 },
            ],
        }),
    )
    .await
    .expect("complete");
    assert_eq!(body["tag_suggestions"]["auto_applied"], json!(1));
    assert_eq!(body["tag_suggestions"]["suggested"], json!(1));
    assert_eq!(
        chunk_tags(&state, tenant, chunk_id).await,
        vec!["account:zed".to_string()]
    );
}
