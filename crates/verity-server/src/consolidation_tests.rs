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

/// Real AppState against VERITY_TEST_DSN. No encoder: the blocker's cosine leg
/// is dead here, so the ONLY merges exercisable are the deterministic
/// canonical-exact fast path and the worker-supplied JUDGED merge (`merge_into`)
/// — exactly the two paths Phase 2 permits (the bare cosine auto-merge is gone).
async fn test_state(auto_tag: bool) -> Option<(Arc<AppState>, TenantId)> {
    test_state_cfg(auto_tag, true).await
}

/// As `test_state`, but with the `VERITY_KNOWLEDGE_AUTO_MERGE` kill switch
/// explicitly set: `auto_merge = false` degrades consolidation to canonical-
/// exact + human clustering (worker `merge_into` is ignored).
async fn test_state_cfg(auto_tag: bool, auto_merge: bool) -> Option<(Arc<AppState>, TenantId)> {
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
            allowed_origin: None,
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag,
        knowledge_auto_merge: auto_merge,
        media_store: None,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        watch: Arc::new(crate::rebac_watch::WatchStatus::new()),
        watch_staleness_fence_secs: 900,
        folder_watchers: Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
    });
    Some((state, tenant))
}

/// Like `test_state` but WITH the local encoder wired, so the blocker's cosine
/// leg (merge-candidates) is live. Returns None when the encoder can't load
/// (offline model download) — the test then skips, same policy as VERITY_TEST_DSN.
async fn test_state_with_encoder() -> Option<(Arc<AppState>, TenantId)> {
    let (state, tenant) = test_state(false).await?;
    let encoder = tokio::task::spawn_blocking(verity_encoder::QueryEncoder::load)
        .await
        .ok()?
        .ok()?;
    // Rebuild AppState with the encoder set (fields are pub(crate) in-crate).
    let AppState {
        storage,
        minter,
        purposes,
        admin,
        rebac,
        revocations,
        allow_restricted_without_rebac,
        subscribers,
        auto_tag,
        knowledge_auto_merge,
        watch,
        folder_watchers,
        folder_scans,
        ..
    } = Arc::try_unwrap(state).ok()?;
    Some((
        Arc::new(AppState {
            storage,
            encoder: Some(Arc::new(encoder)),
            minter,
            purposes,
            admin,
            rebac,
            revocations,
            allow_restricted_without_rebac,
            subscribers,
            auto_tag,
            knowledge_auto_merge,
            media_store: None,
            resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
            watch,
            watch_staleness_fence_secs: 900,
            folder_watchers,
            folder_scans,
            knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
            directory: crate::directory_worker::DirectoryPlane::disabled(),
            connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
            sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
            repo_root: None,
            listen: "127.0.0.1:0".to_string(),
            admin_token: None,
            metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        }),
        tenant,
    ))
}

async fn merge_candidates(state: &Arc<AppState>, body: serde_json::Value) -> serde_json::Value {
    let req = serde_json::from_value(body).unwrap();
    let Json(v) =
        consolidation::merge_candidates(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .expect("merge-candidates");
    v
}

async fn append(
    state: &AppState,
    tenant: TenantId,
    kind: EpisodeKind,
    entity: &str,
    text: &str,
) -> EpisodeId {
    append_w(state, tenant, kind, entity, "agent:test", text).await
}

/// `append` with an explicit writer azp — needed to exercise the corroboration
/// gate (>= 2 distinct writers) on the eligible/auto-publish promotion path.
async fn append_w(
    state: &AppState,
    tenant: TenantId,
    kind: EpisodeKind,
    entity: &str,
    writer: &str,
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
            writer_azp: Some(writer.into()),
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

/// Read the CURRENT value of an L1 key straight from `facts` (bypassing the
/// scoped `current_fact` pre-filter). These L2 consolidation tests use
/// chunkless observation episodes, so `derive_l2_acl` intersects an empty chunk
/// set → the fact is visible to NOBODY (fail-closed derived-scope inheritance).
/// That is CORRECT — the scoped read would (rightly) return None — so a test of
/// bi-temporal supersession mechanics reads the value from the admin-plane
/// projection (raw SQL), exactly like the sibling row-count assertions.
async fn current_value_raw(
    state: &AppState,
    tenant: TenantId,
    key: &FactKey,
) -> Option<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT value FROM facts
         WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
           AND valid_to IS NULL",
    )
    .bind(tenant)
    .bind(&key.source)
    .bind(&key.entity_id)
    .bind(&key.field)
    .fetch_optional(state.pool())
    .await
    .expect("raw current read")
}

/// Value as-of a point in event time, from the admin-plane projection (see
/// `current_value_raw` for why the scoped read cannot serve these invisible
/// L2 facts).
async fn value_as_of_raw(
    state: &AppState,
    tenant: TenantId,
    key: &FactKey,
    as_of: chrono::DateTime<Utc>,
) -> Option<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT value FROM facts
         WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
           AND valid_from <= $5 AND (valid_to IS NULL OR valid_to > $5)
         ORDER BY valid_from DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(&key.source)
    .bind(&key.entity_id)
    .bind(&key.field)
    .bind(as_of)
    .fetch_optional(state.pool())
    .await
    .expect("raw as-of read")
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
    let current = current_value_raw(&state, tenant, &key)
        .await
        .expect("current fact");
    assert_eq!(current, json!("closed_won"));

    // The scoped read (any scope) sees NOTHING: this L2 fact was derived from a
    // chunkless episode, so its materialized visibility is empty — invisible by
    // fail-closed derived-scope inheritance.
    let broad = Scope {
        tenant_id: tenant,
        principals: (0..=64).collect(),
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    };
    assert!(
        state
            .storage
            .current_fact(&broad, &key)
            .await
            .expect("read")
            .is_none(),
        "a chunkless-episode L2 fact is visible to nobody"
    );

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

    // Bi-temporal history intact: the superseded value is as-of queryable
    // (admin-plane projection; the fact is invisible to scoped reads).
    let asof = value_as_of_raw(
        &state,
        tenant,
        &key,
        Utc::now() - chrono::Duration::milliseconds(15),
    )
    .await;
    assert!(asof.is_some());
}

// ---------- knowledge merge: JUDGED merge (worker-supplied merge_into) ----------

#[tokio::test]
async fn judged_merge_into_accrues_support_and_records_reason() {
    // Phase 2: the worker's judge decided two paraphrases are the SAME
    // generalization and passed merge_into + judge_reason. The server VALIDATES
    // the target and accrues evidence (distinct_entities 1 -> 2), recording the
    // reason. No encoder here, so this is purely the judged path — proof the
    // merge is the cascade, not the removed cosine auto-merge.
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    let body1 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{
                "statement": "Enterprise security teams require a signed DPA before a security review.",
                "categories": ["security"], "evidence": [obs1],
            }],
        }),
    )
    .await
    .expect("complete 1");
    assert_eq!(body1["knowledge"][0]["merged"], json!(false));
    let kid = body1["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A DIFFERENT paraphrase with NO shared canonical form, but the worker's
    // judge ruled SAME and supplied merge_into — the server merges on that.
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{
                "statement": "Procurement blocks the security evaluation until the DPA is executed.",
                "evidence": [obs2],
                "merge_into": kid,
                "judge_reason": "same DPA-before-security-review generalization",
            }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(body2["knowledge"][0]["merged"], json!(true));
    assert_eq!(body2["knowledge"][0]["merge"], json!("judge"));
    assert_eq!(
        body2["knowledge"][0]["knowledge_id"].as_str().unwrap(),
        kid,
        "judged merge must accrue on the existing item, not mint a new one"
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

    // The judge's reason is recorded on the merge (auditable, §5).
    let reason: Option<String> =
        sqlx::query_scalar("SELECT merge_reason FROM knowledge WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(kid.parse::<Uuid>().unwrap())
            .fetch_one(state.pool())
            .await
            .expect("merge_reason");
    assert_eq!(
        reason.as_deref(),
        Some("same DPA-before-security-review generalization")
    );
}

#[tokio::test]
async fn invalid_merge_into_fails_closed_to_fresh_candidate() {
    // The server VALIDATES the worker's merge_into. A nonexistent id, or one in
    // another tenant, must NOT merge — it fails closed to a fresh candidate.
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // A foreign item in a DIFFERENT tenant — a cross-tenant merge must be refused.
    let other = state
        .storage
        .inner()
        .create_tenant(&format!("other-{}", Uuid::now_v7()))
        .await
        .expect("other tenant");
    let ep_other = append(&state, other, EpisodeKind::Observation, "x", "x").await;
    lease_ids(&state, other).await;
    let foreign = complete(
        &state,
        json!({
            "tenant_id": other, "episode_id": ep_other,
            "knowledge_candidates": [{ "statement": "Some other generalization here.", "evidence": [ep_other] }],
        }),
    )
    .await
    .expect("foreign complete");
    let foreign_kid = foreign["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .to_string();

    let obs = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    lease_ids(&state, tenant).await;

    // Case 1: merge_into a NONEXISTENT id → fresh.
    let nonexistent = Uuid::now_v7();
    let body1 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs,
            "knowledge_candidates": [{
                "statement": "Enterprise buyers negotiate hard on price.",
                "evidence": [obs], "merge_into": nonexistent,
                "judge_reason": "should be ignored",
            }],
        }),
    )
    .await
    .expect("complete nonexistent");
    assert_eq!(
        body1["knowledge"][0]["merged"],
        json!(false),
        "nonexistent merge_into must fail closed to a fresh candidate"
    );

    // Case 2: merge_into an id in ANOTHER tenant → fresh (cross-tenant refused).
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{
                "statement": "Enterprise buyers prefer annual billing.",
                "evidence": [obs2], "merge_into": foreign_kid,
            }],
        }),
    )
    .await
    .expect("complete foreign");
    assert_eq!(
        body2["knowledge"][0]["merged"],
        json!(false),
        "cross-tenant merge_into must fail closed"
    );

    // Two fresh candidates minted in THIS tenant; the foreign item untouched.
    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(
        items.len(),
        2,
        "both invalid merges became fresh candidates"
    );
    let foreign_distinct: i32 = sqlx::query_scalar(
        "SELECT distinct_entities FROM knowledge WHERE tenant_id = $1 AND id = $2",
    )
    .bind(other)
    .bind(foreign_kid.parse::<Uuid>().unwrap())
    .fetch_one(state.pool())
    .await
    .expect("foreign item");
    assert_eq!(
        foreign_distinct, 1,
        "the foreign item must not have accrued cross-tenant evidence"
    );
}

#[tokio::test]
async fn identical_statement_accrues_support_without_canonical() {
    // LLM-unavailable / judge-NO path: the worker omits merge_into and no
    // canonical is supplied. PARAPHRASES must never bare-auto-merge — but two
    // BYTE-IDENTICAL statements are the same lesson by definition (exact string
    // equality is stricter than the canonical fast path), so the second
    // proposal ACCRUES SUPPORT on the first instead of minting a clone
    // (amended 2026-07-11: three customers proposing the identical lesson used
    // to render as three items each claiming lone support).
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    // Two byte-identical statements but NO canonical_statement and NO merge_into:
    // the server has no authority to merge (the normalized-exact leg is removed).
    let stmt = "Enterprise buyers negotiate hard on price.";
    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{ "statement": stmt, "evidence": [obs1] }],
        }),
    )
    .await
    .expect("complete 1");
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{ "statement": stmt, "evidence": [obs2] }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(
        body2["knowledge"][0]["merged"],
        json!(false),
        "the worker's merge machinery did not fire — accrual is the storage fast path"
    );
    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 1, "identical statement accrues, never clones");
    assert_eq!(items[0].distinct_entities, 2, "support spans both entities");
    assert_eq!(items[0].episode_count, 2, "both evidence episodes attached");
}

// ---------- exact-canonical-match fast path (Phase 1) ----------

#[tokio::test]
async fn identical_canonical_statement_merges_via_fast_path() {
    // Two candidates with DIFFERENT human statements (paraphrases) but an
    // IDENTICAL canonical_statement must merge via the no-embedding fast path,
    // accruing distinct-entity support 1 -> 2. The test state has NO encoder, so
    // a merge here can ONLY be the canonical fast path (the cosine leg is dead).
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    assert!(
        state.encoder.is_none(),
        "no encoder: fast path is the only merge"
    );
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    let canon = "segment_buyer requires signed_dpa before security_review";
    let body1 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{
                "statement": "Enterprise security teams require a signed DPA before a security review.",
                "canonical_statement": canon,
                "evidence": [obs1],
            }],
        }),
    )
    .await
    .expect("complete 1");
    assert_eq!(body1["knowledge"][0]["merged"], json!(false));
    let kid = body1["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A DIFFERENT paraphrase (cosine would NOT catch it) but same canonical form.
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{
                "statement": "Procurement blocks the security review until the data processing agreement is executed.",
                "canonical_statement": canon,
                "evidence": [obs2],
            }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(body2["knowledge"][0]["merged"], json!(true));
    assert_eq!(body2["knowledge"][0]["merge"], json!("canonical_exact"));
    assert_eq!(
        body2["knowledge"][0]["knowledge_id"].as_str().unwrap(),
        kid,
        "identical canonical form must accrue on the existing item"
    );

    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 1, "no duplicate knowledge item");
    assert_eq!(
        items[0].distinct_entities, 2,
        "canonical fast path accrued distinct-entity support 1 -> 2"
    );
}

#[tokio::test]
async fn distinct_canonical_statements_do_not_fast_path_merge() {
    // The precision guard: two DIFFERENT canonical forms must NOT merge, even
    // with no encoder (fast path only fires on byte-identical canonical forms).
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{
                "statement": "Enterprise buyers require a DPA before security review.",
                "canonical_statement": "segment_buyer requires signed_dpa before security_review",
                "evidence": [obs1],
            }],
        }),
    )
    .await
    .expect("complete 1");
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{
                "statement": "Enterprise buyers require a SOC 2 report before security review.",
                "canonical_statement": "segment_buyer requires 2 report soc before security_review",
                "evidence": [obs2],
            }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(
        body2["knowledge"][0]["merged"],
        json!(false),
        "distinct forms stay distinct"
    );
    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 2, "two distinct generalizations, two items");
}

// ---------- merge-candidates: the BLOCKER set (Phase 2) ----------

#[tokio::test]
async fn merge_candidates_returns_blocker_set_with_category_filter_and_cap() {
    // The blocker (stage 1): cosine >= τ_block AND shared >= 1 category, capped.
    // Needs the encoder for the cosine leg; skips if it can't load.
    let Some((state, tenant)) = test_state_with_encoder().await else {
        eprintln!("VERITY_TEST_DSN or encoder unavailable; skipping");
        return;
    };
    let ep = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    lease_ids(&state, tenant).await;

    // Seed three fresh candidates directly via propose_knowledge (complete is
    // idempotent per-episode): two about DPA-before-security (security category),
    // one about pricing (a different category AND a distant statement).
    for (stmt, cats) in [
        (
            "Enterprise buyers require a signed DPA before a security review.",
            vec!["security", "compliance"],
        ),
        (
            "Procurement blocks the security review until the data processing agreement is executed.",
            vec!["security"],
        ),
        ("SMB buyers are highly price-sensitive.", vec!["pricing"]),
    ] {
        let item = state
            .storage
            .propose_knowledge(verity_core::types::KnowledgeProposal {
                tenant_id: tenant,
                statement: stmt.into(),
                categories: cats.into_iter().map(String::from).collect(),
                evidence: vec![],
                proposed_by_sub: None,
                proposed_by_azp: Some("test".into()),
                canonical_statement: None,
            })
            .await
            .expect("seed item");
        if let Some(v) = state.encode(stmt).await.expect("encode") {
            sqlx::query(
                "UPDATE knowledge SET statement_embedding = $3 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant)
            .bind(item.id)
            .bind(pgvector::Vector::from(v))
            .execute(state.pool())
            .await
            .expect("embed");
        }
    }
    let _ = ep; // episode leased above; seeds use propose_knowledge directly

    // Query the blocker for a DPA paraphrase in the security category. The two
    // security items should surface; the pricing item is filtered out (no shared
    // category AND low cosine).
    let out = merge_candidates(
        &state,
        json!({
            "tenant_id": tenant,
            "statement": "Enterprise accounts require a Data Processing Agreement before any security assessment.",
            "categories": ["security"],
        }),
    )
    .await;
    let cands = out["candidates"].as_array().expect("candidates");
    let statements: Vec<&str> = cands
        .iter()
        .map(|c| c["statement"].as_str().unwrap())
        .collect();
    assert!(
        statements.iter().all(|s| !s.contains("price-sensitive")),
        "pricing item must be filtered by the category pre-filter, got {statements:?}"
    );
    assert!(
        !cands.is_empty(),
        "the security DPA items must be in the blocker set"
    );
    // Every returned item is at or above τ_block and shares the category.
    for c in cands {
        assert!(
            c["cosine"].as_f64().unwrap() >= consolidation::TAU_BLOCK as f64 - 1e-6,
            "blocker must enforce τ_block"
        );
    }
    assert!(cands.len() <= 8, "the blocker set is capped at 8");
}

#[tokio::test]
async fn merge_candidates_empty_without_encoder_fails_closed() {
    // No encoder: the blocker cannot shrink the space, so it returns an empty set
    // (the worker mints fresh) — never a bare merge.
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let out = merge_candidates(
        &state,
        json!({
            "tenant_id": tenant,
            "statement": "anything at all",
            "categories": ["security"],
        }),
    )
    .await;
    assert_eq!(out["candidates"].as_array().unwrap().len(), 0);
}

// ---------- L2 supersession aligns on canonical_predicate (Phase 1) ----------

#[tokio::test]
async fn l2_canonical_predicate_aligns_supersession_across_relations() {
    // The finding: "requires" and "requires_before_security_assessment" must key
    // to the SAME (subject, relation) fact so the later extraction supersedes.
    // Both carry canonical_predicate "requires_before"; the free-text relations
    // differ. Exactly one current fact must survive.
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "acct-1", "one").await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "acct-1", "two").await;
    lease_ids(&state, tenant).await;

    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "l2_facts": [{
                "subject": "Acme Corp", "relation": "requires",
                "object": "dpa", "canonical_predicate": "requires_before",
            }],
        }),
    )
    .await
    .expect("complete 1");
    complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "l2_facts": [{
                "subject": "Acme Corp", "relation": "requires_before_security_assessment",
                "object": "signed_dpa", "canonical_predicate": "requires_before",
            }],
        }),
    )
    .await
    .expect("complete 2");

    // Both keyed (l2, "acme corp", "requires_before") — the second supersedes.
    let key = FactKey {
        source: "l2".into(),
        entity_id: "acme corp".into(),
        field: "requires_before".into(),
    };
    let current = current_value_raw(&state, tenant, &key)
        .await
        .expect("current fact");
    assert_eq!(current, json!("signed_dpa"));

    let current_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM facts
         WHERE tenant_id = $1 AND source = 'l2' AND entity_id = 'acme corp'
           AND field = 'requires_before' AND valid_to IS NULL",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .expect("count");
    assert_eq!(
        current_rows, 1,
        "canonical predicate aligns supersession to one row"
    );
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

// ---------- Phase 3: kill switch, eligible/auto-publish, rejection memory ----------

/// VERITY_KNOWLEDGE_AUTO_MERGE=0 (auto_merge=false): the server IGNORES a
/// worker-supplied merge_into entirely. Only the deterministic canonical-exact
/// fast path can merge; a judged merge_into degrades to a FRESH candidate
/// (assisted/human-clustered, never a silent judged merge).
#[tokio::test]
async fn kill_switch_ignores_worker_merge_into() {
    let Some((state, tenant)) = test_state_cfg(false, false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let obs1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    let obs2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    lease_ids(&state, tenant).await;

    let body1 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs1,
            "knowledge_candidates": [{
                "statement": "Enterprise buyers require a signed DPA before a security review.",
                "categories": ["security"], "evidence": [obs1],
            }],
        }),
    )
    .await
    .expect("complete 1");
    let kid = body1["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Worker's judge said SAME and passed merge_into — but the kill switch is
    // engaged, so the server ignores it and mints a fresh candidate instead.
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs2,
            "knowledge_candidates": [{
                "statement": "Procurement blocks the security evaluation until the DPA is executed.",
                "evidence": [obs2],
                "merge_into": kid,
                "judge_reason": "same generalization",
            }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(
        body2["knowledge"][0]["merged"],
        json!(false),
        "kill switch must ignore merge_into and mint fresh"
    );
    assert_ne!(
        body2["knowledge"][0]["knowledge_id"].as_str().unwrap(),
        kid,
        "no judged merge under the kill switch"
    );
    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(
        items.len(),
        2,
        "two separate candidates — no silent judged merge"
    );

    // The canonical-exact fast path STILL works under the kill switch.
    let obs3 = append(&state, tenant, EpisodeKind::Observation, "cust-c", "c").await;
    let obs4 = append(&state, tenant, EpisodeKind::Observation, "cust-d", "d").await;
    expire_leases(&state, tenant).await;
    lease_ids(&state, tenant).await;
    let canon = "segment_buyer requires signed_dpa before security_review";
    let b3 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs3,
            "knowledge_candidates": [{ "statement": "DPA before review, phrasing one.",
                "canonical_statement": canon, "evidence": [obs3] }],
        }),
    )
    .await
    .expect("c3");
    let b4 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": obs4,
            "knowledge_candidates": [{ "statement": "DPA before review, phrasing two.",
                "canonical_statement": canon, "evidence": [obs4] }],
        }),
    )
    .await
    .expect("c4");
    assert_eq!(b3["knowledge"][0]["merged"], json!(false));
    assert_eq!(
        b4["knowledge"][0]["merged"],
        json!(true),
        "canonical-exact still merges"
    );
    assert_eq!(b4["knowledge"][0]["merge"], json!("canonical_exact"));
}

/// Auto-publish OFF (the default): a candidate crossing k-support + corroboration
/// becomes `eligible` — reviewed-ready, NOT published, NOT retrievable. The
/// promotion is reported on the complete() response.
#[tokio::test]
async fn auto_publish_off_marks_eligible_not_published() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Default is OFF.
    assert!(!state
        .storage
        .inner()
        .knowledge_auto_publish(tenant)
        .await
        .unwrap());

    // Three distinct entities, two distinct writers → k-support + corroboration.
    let e1 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-a",
        "agent:x",
        "a",
    )
    .await;
    let e2 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-b",
        "agent:x",
        "b",
    )
    .await;
    let e3 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-c",
        "agent:y",
        "c",
    )
    .await;
    lease_ids(&state, tenant).await;

    let canon = "segment_buyer requires signed_dpa before security_review";
    // Three canonical-exact candidates accrue onto ONE item; the third crossing
    // k=3 should flip it to eligible.
    let mut last = json!(null);
    for (i, ep) in [e1, e2, e3].iter().enumerate() {
        last = complete(
            &state,
            json!({
                "tenant_id": tenant, "episode_id": ep,
                "knowledge_candidates": [{
                    "statement": format!("Buyers need a DPA before review, phrasing {i}."),
                    "canonical_statement": canon, "evidence": [ep],
                }],
            }),
        )
        .await
        .expect("complete");
    }
    // The final complete promoted it to eligible.
    assert_eq!(
        last["knowledge"][0]["promotion"]["action"],
        json!("marked_eligible")
    );
    assert_eq!(
        last["knowledge"][0]["promotion"]["auto_publish"],
        json!(false)
    );

    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].status,
        KnowledgeStatus::Eligible,
        "must be eligible, NEVER auto-published"
    );
    assert_eq!(items[0].distinct_entities, 3);

    // An eligible item is not retrievable — no carve-out chunk exists.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = state
        .storage
        .recall(RecallQuery {
            scope,
            embedding: None,
            text: Some("DPA before review".into()),
            k: 20,
        })
        .await
        .expect("recall");
    assert!(
        !hits.iter().any(|h| h.kind == "knowledge"),
        "eligible item must not be retrievable"
    );
}

/// Auto-publish ON (per-tenant opt-in) + a configured default visibility: the
/// same k-support crossing auto-publishes THROUGH THE GATE on the worker path.
/// Still never on the read path — publish mints the carve-out chunk as usual.
#[tokio::test]
async fn auto_publish_on_publishes_through_the_gate() {
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    state
        .storage
        .inner()
        .set_knowledge_auto_publish(Some(tenant), true)
        .await
        .unwrap();
    // Configure the default publish visibility for the auto path.
    sqlx::query(
        "INSERT INTO settings (tenant_id, key, value) VALUES ($1, 'knowledge_auto_publish_visibility', '7')",
    ).bind(tenant).execute(state.pool()).await.expect("set visibility");

    let e1 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-a",
        "agent:x",
        "a",
    )
    .await;
    let e2 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-b",
        "agent:x",
        "b",
    )
    .await;
    let e3 = append_w(
        &state,
        tenant,
        EpisodeKind::Observation,
        "cust-c",
        "agent:y",
        "c",
    )
    .await;
    lease_ids(&state, tenant).await;

    let canon = "segment_buyer requires signed_dpa before security_review";
    let mut last = json!(null);
    for (i, ep) in [e1, e2, e3].iter().enumerate() {
        last = complete(
            &state,
            json!({
                "tenant_id": tenant, "episode_id": ep,
                "knowledge_candidates": [{
                    "statement": format!("Buyers need a DPA before review, phrasing {i}."),
                    "canonical_statement": canon, "evidence": [ep],
                }],
            }),
        )
        .await
        .expect("complete");
    }
    assert_eq!(
        last["knowledge"][0]["promotion"]["action"],
        json!("auto_published")
    );

    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items[0].status, KnowledgeStatus::Published);

    // Now it IS retrievable (publish minted the carve-out chunk), carrying the
    // emerging tier — never the exact count.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["cust-a".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = state
        .storage
        .recall(RecallQuery {
            scope,
            embedding: None,
            text: Some("DPA before review".into()),
            k: 20,
        })
        .await
        .expect("recall");
    let kh = hits
        .iter()
        .find(|h| h.kind == "knowledge")
        .expect("published knowledge retrievable");
    assert_eq!(kh.support_tier, Some(SupportTier::Emerging));
}

/// The reject endpoint remembers: POST reject -> status=rejected, and a
/// re-propose of the same canonical form via complete() does NOT resurrect it.
#[tokio::test]
async fn reject_endpoint_remembers_and_blocks_resurrection() {
    use axum::extract::{Path as AxPath, Query as AxQuery};
    let Some((state, tenant)) = test_state(false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let e1 = append(&state, tenant, EpisodeKind::Observation, "cust-a", "a").await;
    lease_ids(&state, tenant).await;
    let canon = "segment_buyer requires signed_dpa before security_review";
    let body = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": e1,
            "knowledge_candidates": [{
                "statement": "Buyers require a DPA before review.",
                "canonical_statement": canon, "evidence": [e1],
            }],
        }),
    )
    .await
    .expect("complete");
    let kid: Uuid = body["knowledge"][0]["knowledge_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Reject via the admin endpoint.
    let req: crate::RejectKnowledgeRequest =
        serde_json::from_value(json!({ "tenant_id": tenant, "reason": "not durable" })).unwrap();
    let Json(rejected) = crate::admin_reject_knowledge(
        State(state.clone()),
        HeaderMap::new(),
        AxPath(kid),
        Json(req),
    )
    .await
    .expect("reject");
    assert_eq!(rejected.status, KnowledgeStatus::Rejected);

    // Re-propose the SAME canonical form via complete(): must NOT resurrect.
    let e2 = append(&state, tenant, EpisodeKind::Observation, "cust-b", "b").await;
    expire_leases(&state, tenant).await;
    lease_ids(&state, tenant).await;
    let body2 = complete(
        &state,
        json!({
            "tenant_id": tenant, "episode_id": e2,
            "knowledge_candidates": [{
                "statement": "A paraphrase of the same rejected pattern.",
                "canonical_statement": canon, "evidence": [e2],
            }],
        }),
    )
    .await
    .expect("complete 2");
    assert_eq!(body2["knowledge"][0]["rejected_memory"], json!(true));
    assert_eq!(
        body2["knowledge"][0]["knowledge_id"].as_str().unwrap(),
        kid.to_string()
    );

    // Still exactly one item, still rejected — no fresh candidate resurrected.
    let items = state
        .storage
        .list_knowledge(tenant, None)
        .await
        .expect("list");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].status, KnowledgeStatus::Rejected);

    // The detail endpoint returns the item with its de-id gate result + evidence.
    let q: AxQuery<crate::TenantQuery> =
        AxQuery(serde_json::from_value(json!({ "tenant_id": tenant })).unwrap());
    let Json(detail) =
        crate::admin_knowledge_detail(State(state.clone()), HeaderMap::new(), AxPath(kid), q)
            .await
            .expect("detail");
    assert_eq!(detail["status"], json!("rejected"));
    assert_eq!(detail["deid_gate"]["passed"], json!(true));
    assert!(detail["evidence"].is_array());
}
