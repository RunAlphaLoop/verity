//! Identity-plane integration tests (roadmap task 10), exercising the real
//! handlers in-process.
//!
//! Gating is HARD-ERROR (panic), not silent-skip: these are enforcement-
//! soundness tests (restricted tier-3 live BatchCheck + post-revocation
//! subtraction — the classes the read path is NOT yet pure on). Postgres-only
//! tests panic without `VERITY_TEST_DSN`; ReBAC tests additionally panic
//! without `VERITY_SPICEDB_URL`. CI provides both (deploy/docker-compose.yml
//! has spicedb; the `rust` job runs it), so a missing engine is a
//! misconfiguration to surface loudly, never a test to silently no-op.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::rebac::Rebac;
use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState, HandlerResult};

/// Build a real AppState against VERITY_TEST_DSN (no encoder — recall runs
/// BM25-only, which is what these tests query with).
async fn test_state(rebac: Option<Rebac>, allow_restricted: bool) -> (Arc<AppState>, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the identity/restricted-tier soundness tests; \
         refusing to silently no-op",
    );
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("identity-test-{}", uuid::Uuid::now_v7()))
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
        rebac,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: std::sync::Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: allow_restricted,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    (state, tenant)
}

/// The ReBAC engine for a SpiceDB soundness test: HARD-ERROR when
/// `VERITY_SPICEDB_URL` is absent. CI provides SpiceDB, so a missing engine is
/// a misconfiguration to surface, never a class of soundness test to skip.
fn require_rebac(test: &str) -> Rebac {
    Rebac::from_env().unwrap_or_else(|| {
        panic!(
            "VERITY_SPICEDB_URL must be set for the ReBAC soundness test {test}; \
             refusing to silently no-op"
        )
    })
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

async fn mint_with_subject(
    state: &Arc<AppState>,
    tenant: TenantId,
    subject: &str,
) -> HandlerResult<String> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "subject": subject,
        "max_confidentiality": "Restricted",
    }))
    .expect("request shape");
    let Json(v) = crate::open_scope(State(Arc::clone(state)), Json(req)).await?;
    Ok(v["scope_handle"].as_str().expect("handle").to_string())
}

async fn recall_docs(
    state: &Arc<AppState>,
    handle: &str,
    text: &str,
) -> HandlerResult<Vec<String>> {
    let req = serde_json::from_value(json!({
        "scope_handle": handle,
        "text": text,
        "k": 20,
    }))
    .expect("request shape");
    let Json(hits) = crate::recall(State(Arc::clone(state)), Json(req)).await?;
    Ok(hits.into_iter().map(|h| h.document_id).collect())
}

async fn group_change(
    state: &Arc<AppState>,
    tenant: TenantId,
    group: &str,
    member: &str,
    add: bool,
) -> HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "group": group,
        "member": member,
    }))
    .expect("request shape");
    let (state, headers) = (State(Arc::clone(state)), HeaderMap::new());
    let Json(v) = if add {
        crate::admin_group_add(state, headers, Json(req)).await?
    } else {
        crate::admin_group_remove(state, headers, Json(req)).await?
    };
    Ok(v)
}

/// DSN-only (SpiceDB explicitly absent): restricted-class hits are DROPPED
/// when ReBAC is disabled unless VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC=1.
#[tokio::test]
async fn restricted_hits_drop_without_rebac() {
    let (state, tenant) = test_state(None, false).await;
    index_chunk(
        &state,
        tenant,
        "doc-restricted",
        "xylophone pricing is restricted business",
        vec![41],
        Confidentiality::Restricted,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-internal",
        "xylophone maintenance is internal business",
        vec![41],
        Confidentiality::Internal,
    )
    .await;

    // Dev-mode mint: caller-supplied principals, restricted ceiling.
    let (handle, _) = state.minter.mint(
        crate::scope::ScopePayload {
            tenant_id: tenant,
            principals: vec![41],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            expires_at: Utc::now(),
        },
        300,
    );

    let docs = recall_docs(&state, &handle, "xylophone")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-internal".to_string()),
        "internal hit survives: {docs:?}"
    );
    assert!(
        !docs.contains(&"doc-restricted".to_string()),
        "restricted hit dropped without ReBAC (fail closed): {docs:?}"
    );

    // Explicit opt-out: same corpus, allow flag set.
    let (state_allow, tenant2) = test_state(None, true).await;
    index_chunk(
        &state_allow,
        tenant2,
        "doc-restricted",
        "xylophone pricing is restricted business",
        vec![41],
        Confidentiality::Restricted,
    )
    .await;
    let (handle2, _) = state_allow.minter.mint(
        crate::scope::ScopePayload {
            tenant_id: tenant2,
            principals: vec![41],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            expires_at: Utc::now(),
        },
        300,
    );
    let docs = recall_docs(&state_allow, &handle2, "xylophone")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-restricted".to_string()),
        "VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC=1 serves restricted: {docs:?}"
    );
}

/// DSN-only: subject-based minting without ReBAC is rejected (422), and the
/// caller-supplied dev path still works.
#[tokio::test]
async fn subject_requires_rebac() {
    let (state, tenant) = test_state(None, false).await;
    let err = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect_err("subject without ReBAC must 422");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

    // Dev path unchanged.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principals": [7, 9],
    }))
    .expect("request shape");
    let Json(v) = crate::open_scope(State(Arc::clone(&state)), Json(req))
        .await
        .expect("dev mint works");
    let payload = state
        .minter
        .verify(v["scope_handle"].as_str().unwrap())
        .expect("verifies");
    assert_eq!(payload.principals, vec![7, 9]);
}

/// DSN + SpiceDB: the full task-10 flow. Nested membership → subject-resolved
/// open_scope → recall sees the group-visible chunk; membership delete →
/// durable tombstones → immediate exclusion on the already-minted handle AND
/// on freshly resolved scopes; subject+principals → 422.
#[tokio::test]
async fn identity_resolution_end_to_end() {
    let rebac = require_rebac("identity_resolution_end_to_end");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    // Nested groups: group:sales <- group:sales-west <- user:alice.
    group_change(&state, tenant, "group:sales", "group:sales-west", true)
        .await
        .expect("nest group");
    let added = group_change(
        &state,
        tenant,
        "group:sales-west",
        "user:alice@corp.example",
        true,
    )
    .await
    .expect("add alice");
    assert_eq!(added["written"], json!(true));

    // A chunk visible only to the OUTER group's token.
    let sales_token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["group:sales".to_string()])
            .await
            .expect("token")[0]
            .1;
    index_chunk(
        &state,
        tenant,
        "doc-sales",
        "the quarterly zeppelin forecast",
        vec![sales_token],
        Confidentiality::Internal,
    )
    .await;

    // Subject + principals is self-assertion: rejected.
    let both = serde_json::from_value(json!({
        "tenant_id": tenant,
        "subject": "user:alice@corp.example",
        "principals": [1],
    }))
    .expect("request shape");
    let err = crate::open_scope(State(Arc::clone(&state)), Json(both))
        .await
        .expect_err("both subject and principals must 422");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

    // Identity-resolved mint: alice reaches the chunk through the nested
    // group closure.
    let handle = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect("mint");
    let payload = state.minter.verify(&handle).expect("verifies");
    assert_eq!(payload.subject.as_deref(), Some("user:alice@corp.example"));
    assert_eq!(payload.principals.len(), 3, "user + 2 groups: {payload:?}");
    let docs = recall_docs(&state, &handle, "zeppelin")
        .await
        .expect("recall");
    assert!(docs.contains(&"doc-sales".to_string()), "{docs:?}");

    // An unknown user resolves to just itself and sees nothing (fail closed).
    let stranger = mint_with_subject(&state, tenant, "user:mallory@corp.example")
        .await
        .expect("mint");
    let docs = recall_docs(&state, &stranger, "zeppelin")
        .await
        .expect("recall");
    assert!(docs.is_empty(), "{docs:?}");

    // Remove the nested group from sales: tombstones for group:sales land
    // durably, and the ALREADY-MINTED handle stops seeing the chunk now —
    // no waiting on SpiceDB propagation or handle expiry.
    let removed = group_change(&state, tenant, "group:sales", "group:sales-west", false)
        .await
        .expect("remove");
    assert!(removed["tombstones"].as_u64().unwrap() >= 1, "{removed:?}");
    assert!(removed["revoked_principals"]
        .as_array()
        .unwrap()
        .contains(&json!("group:sales")));

    let docs = recall_docs(&state, &handle, "zeppelin")
        .await
        .expect("recall");
    assert!(
        docs.is_empty(),
        "revoked token subtracted from minted handle at read time: {docs:?}"
    );
    // Fresh resolution excludes it too (tombstone window + SpiceDB agree).
    let fresh = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect("re-mint");
    let docs = recall_docs(&state, &fresh, "zeppelin")
        .await
        .expect("recall");
    assert!(docs.is_empty(), "{docs:?}");

    // The brief path applies the same subtraction.
    let Json(brief) = crate::brief(
        State(Arc::clone(&state)),
        Path("account:acme".to_string()),
        Query(serde_json::from_value(json!({ "scope_handle": handle })).unwrap()),
    )
    .await
    .expect("brief");
    assert_eq!(brief["recent_memory"], json!([]));
}

/// DSN + SpiceDB: restricted-class hits are re-checked against the CURRENT
/// resolved set — a subject whose group membership was revoked loses
/// restricted hits even before tombstone bookkeeping is consulted, because
/// re-resolution is live.
#[tokio::test]
async fn restricted_recheck_follows_live_membership() {
    let rebac = require_rebac("restricted_recheck_follows_live_membership");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    group_change(
        &state,
        tenant,
        "group:pricing",
        "user:bob@corp.example",
        true,
    )
    .await
    .expect("add bob");
    let token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["group:pricing".to_string()])
            .await
            .expect("token")[0]
            .1;
    index_chunk(
        &state,
        tenant,
        "doc-quote",
        "the walrus quote is 84000 dollars",
        vec![token],
        Confidentiality::Restricted,
    )
    .await;

    let handle = mint_with_subject(&state, tenant, "user:bob@corp.example")
        .await
        .expect("mint");
    let docs = recall_docs(&state, &handle, "walrus")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-quote".to_string()),
        "member passes live recheck: {docs:?}"
    );

    group_change(
        &state,
        tenant,
        "group:pricing",
        "user:bob@corp.example",
        false,
    )
    .await
    .expect("remove bob");
    let docs = recall_docs(&state, &handle, "walrus")
        .await
        .expect("recall");
    assert!(
        docs.is_empty(),
        "revoked member loses restricted hits on the live handle: {docs:?}"
    );
}

/// M0 deliverable #2 — SCOPE-FUZZER EXTENSION over the two classes the read
/// path is NOT yet pure on and CI did not previously fuzz, both asserted against
/// an INDEPENDENT oracle (the same predicate shape the storage fuzzer uses:
/// `doc.visibility ∩ current_resolved_tokens ≠ ∅`):
///
///   (a) the RESTRICTED tier-3 LIVE-BatchCheck path
///       (`enforce_restricted` → `current_token_set` → `rebac.user_groups`):
///       a member of a group sees that group's restricted doc, a non-member
///       does not — decided by live SpiceDB resolution, not the minted handle.
///   (b) POST-REVOCATION states: a token revoked within the window must be
///       SUBTRACTED from the resolved set; recall must DROP every restricted
///       doc reachable only via a revoked group.
///
/// The corpus is a fixed adversarial matrix (one restricted doc per group, one
/// multi-group doc) probed by three subjects with different live memberships;
/// each recall result is checked equal to the oracle's admit set. Deterministic
/// (no seed can hide a regression) and non-skippable (hard-errors without
/// DSN+SpiceDB).
#[tokio::test]
async fn restricted_tier3_and_post_revocation_vs_oracle() {
    let rebac = require_rebac("restricted_tier3_and_post_revocation_vs_oracle");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    // Three groups; three subjects with distinct live membership. `solo` is in
    // group:red only, `both` in red+blue, `none` in no group.
    let groups = ["group:red", "group:blue", "group:green"];
    for g in groups {
        group_change(
            &state,
            tenant,
            g,
            "user:solo@corp.example",
            g == "group:red",
        )
        .await
        .expect("solo membership");
    }
    for g in ["group:red", "group:blue"] {
        group_change(&state, tenant, g, "user:both@corp.example", true)
            .await
            .expect("both membership");
    }

    // Mint a token per group and index one RESTRICTED doc visible only to that
    // group's token, plus one doc visible to red+blue (multi-group contention).
    let mut group_token = std::collections::HashMap::new();
    for g in groups {
        let tok = crate::upsert_principal_tokens(state.pool(), tenant, &[g.to_string()])
            .await
            .expect("token")[0]
            .1;
        group_token.insert(g.to_string(), tok);
    }
    // (doc_id, visibility tokens). MAGIC term "obsidian" so one recall matches all.
    let corpus: Vec<(&str, Vec<PrincipalToken>)> = vec![
        ("doc-red", vec![group_token["group:red"]]),
        ("doc-blue", vec![group_token["group:blue"]]),
        ("doc-green", vec![group_token["group:green"]]),
        (
            "doc-red-blue",
            vec![group_token["group:red"], group_token["group:blue"]],
        ),
    ];
    for (doc, vis) in &corpus {
        index_chunk(
            &state,
            tenant,
            doc,
            "the obsidian pricing dossier",
            vis.clone(),
            Confidentiality::Restricted,
        )
        .await;
    }

    // The independent oracle: the CURRENT resolved token set for a subject is
    // the tokens minted for the groups the subject LIVE-belongs-to, minus any
    // in-window revoked tokens; a restricted doc is admitted iff its visibility
    // overlaps that set. `live_groups` mirrors what SpiceDB should return.
    let admit_set =
        |live_groups: &[&str], revoked: &[PrincipalToken]| -> std::collections::BTreeSet<String> {
            let resolved: Vec<PrincipalToken> = live_groups
                .iter()
                .map(|g| group_token[*g])
                .filter(|t| !revoked.contains(t))
                .collect();
            corpus
                .iter()
                .filter(|(_, vis)| vis.iter().any(|t| resolved.contains(t)))
                .map(|(doc, _)| (*doc).to_string())
                .collect()
        };

    async fn recall_set(state: &Arc<AppState>, handle: &str) -> std::collections::BTreeSet<String> {
        recall_docs(state, handle, "obsidian")
            .await
            .expect("recall")
            .into_iter()
            .collect()
    }

    // (a) LIVE BatchCheck: each subject sees exactly the oracle's admit set,
    // decided by live SpiceDB resolution.
    let solo = mint_with_subject(&state, tenant, "user:solo@corp.example")
        .await
        .expect("mint solo");
    assert_eq!(
        recall_set(&state, &solo).await,
        admit_set(&["group:red"], &[]),
        "restricted tier-3: solo (red only) must see exactly red's restricted docs"
    );
    let both = mint_with_subject(&state, tenant, "user:both@corp.example")
        .await
        .expect("mint both");
    assert_eq!(
        recall_set(&state, &both).await,
        admit_set(&["group:red", "group:blue"], &[]),
        "restricted tier-3: both (red+blue) must see red, blue, and red-blue docs"
    );
    let none = mint_with_subject(&state, tenant, "user:none@corp.example")
        .await
        .expect("mint none");
    assert_eq!(
        recall_set(&state, &none).await,
        std::collections::BTreeSet::new(),
        "restricted tier-3: a non-member sees NO restricted docs (fail closed)"
    );

    // (b) POST-REVOCATION: revoke group:blue from `both`. The blue token is
    // subtracted in-window; recall must drop doc-blue but keep doc-red and
    // doc-red-blue (still reachable via red). Assert equal to the oracle with
    // the blue token revoked.
    let removed = group_change(
        &state,
        tenant,
        "group:blue",
        "user:both@corp.example",
        false,
    )
    .await
    .expect("revoke blue from both");
    assert!(
        removed["tombstones"].as_u64().unwrap_or(0) >= 1,
        "revocation wrote a tombstone: {removed:?}"
    );
    let blue_tok = group_token["group:blue"];
    // On the ALREADY-MINTED handle: live re-resolution + in-window subtraction.
    assert_eq!(
        recall_set(&state, &both).await,
        admit_set(&["group:red", "group:blue"], &[blue_tok]),
        "post-revocation: doc-blue drops on the live handle; red + red-blue survive"
    );
    // A freshly minted handle agrees (SpiceDB no longer resolves blue).
    let both_fresh = mint_with_subject(&state, tenant, "user:both@corp.example")
        .await
        .expect("re-mint both");
    assert_eq!(
        recall_set(&state, &both_fresh).await,
        admit_set(&["group:red"], &[]),
        "post-revocation: fresh resolution excludes blue entirely"
    );
    // solo is untouched by the blue revocation.
    assert_eq!(
        recall_set(&state, &solo).await,
        admit_set(&["group:red"], &[]),
        "post-revocation: an unrelated subject's admit set is unchanged"
    );
}

// ---- §6c conformance locks (mirror ingest/tests/test_gdirectory.py) ----

/// DSN + SpiceDB: a THREE-level nest (`all ⊃ eng ⊃ eng-leads ⊃ alice`) —
/// deeper than `identity_resolution_end_to_end`'s two levels — resolves so the
/// bottom user reaches a doc shared only with the TOP group. Server-side proof
/// that `rebac.user_groups` returns the full transitive closure.
#[tokio::test]
async fn nested_three_level_closure_resolves() {
    let rebac = require_rebac("nested_three_level_closure_resolves");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    group_change(&state, tenant, "group:all", "group:eng", true)
        .await
        .expect("all <- eng");
    group_change(&state, tenant, "group:eng", "group:eng-leads", true)
        .await
        .expect("eng <- eng-leads");
    group_change(
        &state,
        tenant,
        "group:eng-leads",
        "user:alice@corp.example",
        true,
    )
    .await
    .expect("eng-leads <- alice");

    // A doc visible ONLY to the top group's token, three levels above alice.
    let all_token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["group:all".to_string()])
            .await
            .expect("token")[0]
            .1;
    index_chunk(
        &state,
        tenant,
        "doc-top",
        "the platinum falcon dossier",
        vec![all_token],
        Confidentiality::Internal,
    )
    .await;

    let handle = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect("mint");
    let payload = state.minter.verify(&handle).expect("verifies");
    assert_eq!(
        payload.principals.len(),
        4,
        "user + 3 nested groups: {payload:?}"
    );
    let docs = recall_docs(&state, &handle, "falcon")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-top".to_string()),
        "the nested member reaches the top-group doc: {docs:?}"
    );
}

/// DSN + SpiceDB: a membership CYCLE (`loop-a ⊃ loop-b ⊃ loop-a`) must
/// TERMINATE — SpiceDB owns cycle-safety, and a subject-mint over a member of
/// the cycle returns instead of hanging.
#[tokio::test]
async fn membership_cycle_terminates() {
    let rebac = require_rebac("membership_cycle_terminates");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    group_change(&state, tenant, "group:loop-a", "group:loop-b", true)
        .await
        .expect("loop-a <- loop-b");
    group_change(&state, tenant, "group:loop-b", "group:loop-a", true)
        .await
        .expect("loop-b <- loop-a");
    group_change(
        &state,
        tenant,
        "group:loop-a",
        "user:cyril@corp.example",
        true,
    )
    .await
    .expect("loop-a <- cyril");

    // A doc visible only to the cyclic group.
    let loop_a_token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["group:loop-a".to_string()])
            .await
            .expect("token")[0]
            .1;
    index_chunk(
        &state,
        tenant,
        "doc-loop",
        "the cyclic zucchini memo",
        vec![loop_a_token],
        Confidentiality::Internal,
    )
    .await;

    // A true membership cycle is infinite-depth for ReBAC, so SpiceDB's max-depth
    // guard makes `user_groups` ERROR rather than hang. The invariant for §6c:
    // the server TERMINATES (returns promptly, never loops) and degrades
    // FAIL-CLOSED but GRACEFULLY — `open_scope` doesn't lock cyril out of ALL
    // access with a 502; it mints a scope carrying only his OWN principal, and
    // the unresolvable cyclic groups are DENIED (never a partial or looping
    // grant, never a leak). Real Google directories reject cyclic nesting, so
    // this is a defensive edge; the point is a malformed sync can't lock a user
    // out of their direct content.
    let handle = mint_with_subject(&state, tenant, "user:cyril@corp.example")
        .await
        .expect("a cycle degrades to a minted scope, never a lockout/502");
    let payload = state.minter.verify(&handle).expect("verifies");
    assert_eq!(
        payload.principals.len(),
        1,
        "degraded to cyril's own principal only (cyclic groups denied): {payload:?}"
    );
    let docs = recall_docs(&state, &handle, "zucchini")
        .await
        .expect("recall");
    assert!(
        docs.is_empty(),
        "the unresolvable cyclic group is denied — cyril cannot see its doc: {docs:?}"
    );
}

/// DSN + SpiceDB: an email-only / unmapped subject (never added to any group)
/// resolves to just itself and sees nothing group-shared — the §6c "email-only
/// user denied when mapping is off" case, at the server.
#[tokio::test]
async fn email_only_subject_confers_nothing() {
    let rebac = require_rebac("email_only_subject_confers_nothing");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;

    group_change(
        &state,
        tenant,
        "group:staff",
        "user:insider@corp.example",
        true,
    )
    .await
    .expect("add insider");
    let staff_token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["group:staff".to_string()])
            .await
            .expect("token")[0]
            .1;
    index_chunk(
        &state,
        tenant,
        "doc-staff",
        "the tangerine offsite agenda",
        vec![staff_token],
        Confidentiality::Internal,
    )
    .await;

    // The insider sees it; the email-only outsider does not.
    let insider = mint_with_subject(&state, tenant, "user:insider@corp.example")
        .await
        .expect("mint");
    assert!(
        recall_docs(&state, &insider, "tangerine")
            .await
            .expect("recall")
            .contains(&"doc-staff".to_string()),
        "a real member sees the group doc"
    );
    let outsider = mint_with_subject(&state, tenant, "user:partner@outside.example")
        .await
        .expect("mint");
    assert!(
        recall_docs(&state, &outsider, "tangerine")
            .await
            .expect("recall")
            .is_empty(),
        "an email-only non-member sees nothing"
    );
}
