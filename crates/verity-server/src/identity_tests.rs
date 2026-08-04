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
        allow_restricted_without_rebac: allow_restricted,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    (state, tenant)
}

/// The fixed admin bearer the `require`-gated M2 2a routes accept in-test.
const TEST_ADMIN_TOKEN: &str = "test-admin-token";

/// Like `test_state`, but with a configured admin token so the `require`-gated
/// revoke/reinstate routes return `Ok` (dev-open `expected_tag: None` would 401
/// them). Pair with [`admin_headers`] to build the matching bearer.
async fn test_state_admin(
    rebac: Option<Rebac>,
    allow_restricted: bool,
) -> (Arc<AppState>, TenantId) {
    let (state, tenant) = test_state(rebac, allow_restricted).await;
    // Rebuild AppState with a token-configured AdminAuth. AppState isn't Clone,
    // so mint a fresh one sharing the same storage handle via a fresh connect —
    // cheaper to just swap the admin field through Arc::get_mut, which is unique
    // here (we just created the Arc).
    let mut state = state;
    let app = Arc::get_mut(&mut state).expect("unique AppState");
    app.admin = AdminAuth::for_test(Some(TEST_ADMIN_TOKEN), None);
    (state, tenant)
}

/// The `Authorization: Bearer` header the `require`-gated routes accept when the
/// state was built by [`test_state_admin`].
fn admin_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {TEST_ADMIN_TOKEN}").parse().unwrap(),
    );
    h
}

/// Durably revoke a principal through the real `require`-gated route. Returns
/// the JSON body (`swept_documents`, `token`, …).
async fn revoke_principal(
    state: &Arc<AppState>,
    tenant: TenantId,
    principal: &str,
) -> HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principal": principal,
    }))
    .expect("request shape");
    let Json(v) =
        crate::admin_principal_revoke(State(Arc::clone(state)), admin_headers(), Json(req)).await?;
    Ok(v)
}

/// Reinstate a principal through the real `require`-gated route.
async fn reinstate_principal(
    state: &Arc<AppState>,
    tenant: TenantId,
    principal: &str,
) -> HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principal": principal,
    }))
    .expect("request shape");
    let Json(v) =
        crate::admin_principal_reinstate(State(Arc::clone(state)), admin_headers(), Json(req))
            .await?;
    Ok(v)
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
    let (_headers, Json(hits)) = crate::recall(State(Arc::clone(state)), Json(req)).await?;
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
    // Send the admin bearer: harmless under dev-open `check` (ignored when no
    // token is configured), and required when the state carries a token
    // (`test_state_admin`). The M1 group routes are `check`-gated.
    let (state, headers) = (State(Arc::clone(state)), admin_headers());
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
            issued_at: Utc::now(),
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
            issued_at: Utc::now(),
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
/// M3 load-bearing guard: because Restricted (tier-3) now rides the SAME
/// materialized set as tier-≤2 (no per-read live recheck), it MUST also enter the
/// staleness fence. A subject-less tier-3 handle serves its doc while the watch is
/// fresh (materialized set trusted), but is EMPTIED once the watch goes stale
/// (fail closed). If a regression re-exempts tier-3 from `fence_stale_scope`, the
/// stale read would still serve the doc and this fails — the tripwire on the one
/// change that makes deleting the recheck safe.
#[tokio::test]
async fn restricted_tier3_enters_the_staleness_fence() {
    let rebac = require_rebac("restricted_tier3_enters_the_staleness_fence");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state(Some(rebac), false).await;
    index_chunk(
        &state,
        tenant,
        "doc-restricted",
        "the obsidian pricing dossier",
        vec![41],
        Confidentiality::Restricted,
    )
    .await;
    // Dev-mode subject-less handle at the Restricted ceiling (principals baked).
    let (handle, _) = state.minter.mint(
        crate::scope::ScopePayload {
            tenant_id: tenant,
            principals: vec![41],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        },
        300,
    );
    // Watch fresh (disabled) → materialized set is trusted → tier-3 doc served.
    let fresh = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    assert!(
        fresh.contains(&"doc-restricted".to_string()),
        "fresh watch serves tier-3 from the materialized set: {fresh:?}"
    );
    // Watch enabled + never advanced → STALE → fence fires → subject-less handle
    // is emptied (fail closed), so the tier-3 doc is dropped WITHOUT any recheck.
    state.watch.set_enabled(true);
    let stale = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    assert!(
        !stale.contains(&"doc-restricted".to_string()),
        "a stale watch must fence tier-3 (fail closed), not serve it: {stale:?}"
    );
}

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

// ===================================================================
// M2 2a — DIRECT-GRANT REVOCATION PLANE + MINT ACTIVE-GATE
// ===================================================================

/// Age a durable revocation's `revoked_at` into the distant past so a test can
/// prove the subtraction is INDEFINITE — it must still bite past the ~13h M1
/// `RETENTION_SECS` window (which only bounds the SEPARATE `revocations`
/// tombstone table). No wall-clock waiting.
async fn age_revocation(state: &AppState, tenant: TenantId, token: PrincipalToken, hours: i32) {
    sqlx::query(
        "UPDATE revoked_principal
            SET revoked_at = now() - make_interval(hours => $3)
          WHERE tenant_id = $1 AND token = $2",
    )
    .bind(tenant)
    .bind(token)
    .bind(hours)
    .execute(state.pool())
    .await
    .expect("age revocation");
}

/// Dev-mode direct mint of a live 12h handle over caller-supplied principals
/// (no ReBAC): the analog of a DIRECT grant handle. `issued_at` is pinned to
/// `now` by the minter; the durable revoked-set subtraction is
/// `issued_at`-independent, so a live handle still drops a revoked token.
fn direct_handle(state: &AppState, tenant: TenantId, principals: Vec<PrincipalToken>) -> String {
    let now = Utc::now();
    let (handle, _) = state.minter.mint(
        crate::scope::ScopePayload {
            tenant_id: tenant,
            principals,
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            issued_at: now,
            expires_at: now, // overwritten by mint() to now + 12h
        },
        crate::scope::MAX_TTL_SECONDS,
    );
    handle
}

/// The live current visibility of a document's chunk (valid_to IS NULL).
async fn live_visibility(state: &AppState, tenant: TenantId, doc: &str) -> Vec<PrincipalToken> {
    sqlx::query_scalar::<_, Vec<i32>>(
        "SELECT visibility FROM chunks
          WHERE tenant_id = $1 AND source = 'test' AND document_id = $2
            AND valid_to IS NULL
          ORDER BY seq LIMIT 1",
    )
    .bind(tenant)
    .bind(doc)
    .fetch_one(state.pool())
    .await
    .expect("live visibility")
}

/// Count `chunk_acl_audit` rows for a document at a given reason.
async fn audit_count(state: &AppState, tenant: TenantId, doc: &str, reason: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM chunk_acl_audit
          WHERE tenant_id = $1 AND source = 'test' AND document_id = $2 AND reason = $3",
    )
    .bind(tenant)
    .bind(doc)
    .bind(reason)
    .fetch_one(state.pool())
    .await
    .expect("audit count")
}

/// N2 (the point of 2a — DSN-only, no ReBAC): a DIRECT-granted chunk keyed to
/// `T_A` alone (no group tuple). A 12h handle minted BEFORE revoke must, on its
/// NEXT recall AFTER revoke — and PAST the ~13h `RETENTION_SECS` window — DROP
/// the chunk, because the durable revoked-principal subtraction is INDEFINITE
/// and `issued_at`-independent. Bob's direct-granted chunk is UNAFFECTED.
#[tokio::test]
async fn m2a_direct_grant_revocation_is_indefinite() {
    let (state, tenant) = test_state_admin(None, true).await;
    let t_a = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:alice@corp.example".to_string()],
    )
    .await
    .expect("token")[0]
        .1;
    let t_b = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:bob@corp.example".to_string()],
    )
    .await
    .expect("token")[0]
        .1;

    // Chunk D: a DIRECT grant to Alice only. Chunk E: a direct grant to Bob.
    index_chunk(
        &state,
        tenant,
        "doc-alice",
        "the direct-granted narwhal memo",
        vec![t_a],
        Confidentiality::Internal,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-bob",
        "the direct-granted narwhal ledger",
        vec![t_b],
        Confidentiality::Internal,
    )
    .await;

    // (1) A 12h handle minted for Alice BEFORE revoke sees D.
    let handle = direct_handle(&state, tenant, vec![t_a]);
    let docs = recall_docs(&state, &handle, "narwhal")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-alice".to_string()),
        "before revoke: {docs:?}"
    );

    // (2) Admin REVOKES Alice.
    let body = revoke_principal(&state, tenant, "user:alice@corp.example")
        .await
        .expect("revoke");
    assert_eq!(body["revoked"], json!(true));
    assert_eq!(body["token"], json!(t_a));
    assert_eq!(
        body["swept_documents"],
        json!(1),
        "only D carried T_A: {body}"
    );

    // (3) Age the revocation past RETENTION_SECS (~13h) — the durable set has NO
    //     time bound, so the SAME live handle's next recall STILL drops D.
    age_revocation(&state, tenant, t_a, 20).await;
    let docs = recall_docs(&state, &handle, "narwhal")
        .await
        .expect("recall");
    assert!(
        !docs.contains(&"doc-alice".to_string()),
        "revoked direct grant dropped past the window (indefinite): {docs:?}"
    );

    // Negative: Bob's direct grant is UNAFFECTED by Alice's revoke.
    let bob_handle = direct_handle(&state, tenant, vec![t_b]);
    let docs = recall_docs(&state, &bob_handle, "narwhal")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-bob".to_string()) && !docs.contains(&"doc-alice".to_string()),
        "Bob unaffected: {docs:?}"
    );
}

/// N2-sweep + N3 (DSN-only): the sweep INVALIDATES D's materialized T_A
/// (invalidate-don't-delete + a `principal_revoke` audit row), preserving every
/// OTHER grant on the chunk. A fresh direct handle for the reused token then
/// sees nothing (email-reuse safety). Reinstate lets NEW grants resolve but does
/// NOT resurrect the swept chunk.
#[tokio::test]
async fn m2a_sweep_retracts_token_and_reinstate_is_honest() {
    let (state, tenant) = test_state_admin(None, true).await;
    let t_a = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:alice@corp.example".to_string()],
    )
    .await
    .expect("token")[0]
        .1;
    let t_b = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:bob@corp.example".to_string()],
    )
    .await
    .expect("token")[0]
        .1;

    // Chunk D is DIRECTLY shared to BOTH Alice and Bob.
    index_chunk(
        &state,
        tenant,
        "doc-shared",
        "the direct-granted okapi brief",
        vec![t_a, t_b],
        Confidentiality::Internal,
    )
    .await;

    revoke_principal(&state, tenant, "user:alice@corp.example")
        .await
        .expect("revoke");

    // N2-sweep: T_A retracted from the LIVE chunk; Bob's T_B survives; audited.
    let vis = live_visibility(&state, tenant, "doc-shared").await;
    assert!(
        !vis.contains(&t_a),
        "T_A retracted from materialized chunk: {vis:?}"
    );
    assert!(vis.contains(&t_b), "T_B (Bob) preserved: {vis:?}");
    assert!(
        audit_count(&state, tenant, "doc-shared", "principal_revoke").await >= 1,
        "a principal_revoke audit row exists"
    );

    // Bob (via a fresh direct handle) still sees D — the sweep is surgical.
    let bob_handle = direct_handle(&state, tenant, vec![t_b]);
    assert!(
        recall_docs(&state, &bob_handle, "okapi")
            .await
            .expect("recall")
            .contains(&"doc-shared".to_string()),
        "Bob still sees the shared doc after Alice's revoke"
    );

    // N3 (email-reuse): a fresh direct handle bearing the OLD T_A sees nothing —
    // the residual token was retracted from the chunk AND the durable set denies
    // it — so a re-vouched human at the same email inherits nothing.
    let reused = direct_handle(&state, tenant, vec![t_a]);
    assert!(
        recall_docs(&state, &reused, "okapi")
            .await
            .expect("recall")
            .is_empty(),
        "email-reuse inherits nothing (swept + durably denied)"
    );

    // Reinstate: NEW grants resolve again, but the SWEPT chunk stays invalidated
    // (honest — 2a does not resurrect historical direct grants).
    let body = reinstate_principal(&state, tenant, "user:alice@corp.example")
        .await
        .expect("reinstate");
    assert_eq!(body["reinstated"], json!(true));
    assert_eq!(body["was_revoked"], json!(true));

    // A NEW direct grant to Alice's token now resolves (durable denial cleared).
    index_chunk(
        &state,
        tenant,
        "doc-new",
        "the fresh okapi addendum",
        vec![t_a],
        Confidentiality::Internal,
    )
    .await;
    let after = direct_handle(&state, tenant, vec![t_a]);
    let docs = recall_docs(&state, &after, "okapi").await.expect("recall");
    assert!(
        docs.contains(&"doc-new".to_string()),
        "new grant resolves: {docs:?}"
    );
    assert!(
        !docs.contains(&"doc-shared".to_string()),
        "already-swept chunk stays invalidated after reinstate (honest): {docs:?}"
    );
}

/// A revoke of an as-yet-unmaterialized principal is idempotent and denies any
/// FUTURE grant; a non-`user:` principal is 422; the route is `require`-gated.
#[tokio::test]
async fn m2a_revoke_edge_cases() {
    let (state, tenant) = test_state_admin(None, true).await;

    // 422: a group principal is not a deprovisionable human.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant, "principal": "group:sales",
    }))
    .expect("shape");
    let err = crate::admin_principal_revoke(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect_err("group principal 422");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);

    // 401: the release-gate route refuses without the admin bearer.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant, "principal": "user:ghost@corp.example",
    }))
    .expect("shape");
    let err = crate::admin_principal_revoke(State(Arc::clone(&state)), HeaderMap::new(), Json(req))
        .await
        .expect_err("no bearer 401");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);

    // Revoke a principal that never carried a token: swept 0, future grant denied.
    let body = revoke_principal(&state, tenant, "user:ghost@corp.example")
        .await
        .expect("revoke ghost");
    assert_eq!(body["swept_documents"], json!(0));
    let ghost = body["token"].as_i64().expect("token") as i32;

    // A LATER direct grant to that token is denied on the live handle.
    index_chunk(
        &state,
        tenant,
        "doc-ghost",
        "the posthumous quokka file",
        vec![ghost],
        Confidentiality::Internal,
    )
    .await;
    let handle = direct_handle(&state, tenant, vec![ghost]);
    assert!(
        recall_docs(&state, &handle, "quokka")
            .await
            .expect("recall")
            .is_empty(),
        "a grant made AFTER deprovision is still denied (durable, indefinite)"
    );

    // Reinstate a never-revoked principal reports was_revoked=false.
    let body = reinstate_principal(&state, tenant, "user:nobody@corp.example")
        .await
        .expect("reinstate");
    assert_eq!(body["was_revoked"], json!(false));
}

/// DSN + SpiceDB: the MINT ACTIVE-GATE (deliverable #4). After a deprovision,
/// a FRESH subject-resolved mint for the same email OMITS the self-token, so the
/// direct-granted chunk is not in scope — even though a new mint would otherwise
/// re-prepend it. Group tokens are untouched (M1 owns those). A group-membership
/// revoke (M1) still behaves unchanged in the same tenant.
#[tokio::test]
async fn m2a_mint_active_gate_omits_revoked_self_token() {
    let rebac = require_rebac("m2a_mint_active_gate_omits_revoked_self_token");
    rebac.ensure_schema().await.expect("schema");
    let (state, tenant) = test_state_admin(Some(rebac), false).await;

    // Alice is in group:eng; a group chunk + a DIRECT-granted chunk both exist.
    group_change(&state, tenant, "group:eng", "user:alice@corp.example", true)
        .await
        .expect("add alice");
    let t_a = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:alice@corp.example".to_string()],
    )
    .await
    .expect("token")[0]
        .1;
    let eng = crate::upsert_principal_tokens(state.pool(), tenant, &["group:eng".to_string()])
        .await
        .expect("token")[0]
        .1;
    index_chunk(
        &state,
        tenant,
        "doc-direct",
        "the platypus onboarding memo",
        vec![t_a],
        Confidentiality::Internal,
    )
    .await;
    index_chunk(
        &state,
        tenant,
        "doc-group",
        "the platypus team roster",
        vec![eng],
        Confidentiality::Internal,
    )
    .await;

    // Before revoke, a subject mint sees BOTH (direct + group).
    let before = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect("mint");
    let docs = recall_docs(&state, &before, "platypus")
        .await
        .expect("recall");
    assert!(docs.contains(&"doc-direct".to_string()), "{docs:?}");
    assert!(docs.contains(&"doc-group".to_string()), "{docs:?}");

    // Deprovision Alice.
    revoke_principal(&state, tenant, "user:alice@corp.example")
        .await
        .expect("revoke");

    // A FRESH subject mint OMITS the self-token: the direct-granted chunk is
    // gone. (The group chunk is also gone here only because the sweep + durable
    // denial hit the direct grant; the group token itself is NOT in the durable
    // set — verify the minted scope has the group token but NOT the self-token.)
    let fresh = mint_with_subject(&state, tenant, "user:alice@corp.example")
        .await
        .expect("re-mint");
    let payload = state.minter.verify(&fresh).expect("verifies");
    assert!(
        !payload.principals.contains(&t_a),
        "mint active-gate omits the revoked self-token: {:?}",
        payload.principals
    );
    assert!(
        payload.principals.contains(&eng),
        "group token retained (M1 owns group revocation): {:?}",
        payload.principals
    );
    let docs = recall_docs(&state, &fresh, "platypus")
        .await
        .expect("recall");
    assert!(
        !docs.contains(&"doc-direct".to_string()),
        "post-revoke mint cannot reach the direct grant: {docs:?}"
    );

    // Non-regression: a group-membership revoke (M1) still works unchanged.
    let removed = group_change(
        &state,
        tenant,
        "group:eng",
        "user:alice@corp.example",
        false,
    )
    .await
    .expect("remove alice");
    assert_eq!(removed["deleted"], json!(true));
}

// ==== M2 2b — CANONICAL-PRINCIPAL REGISTRY + CROSSWALK (end-to-end conformance) ====
//
// These are the BUILD #3 release tests: the full ingest → mint → recall
// acceptance trace and its negatives, proven through the REAL server sink
// (`admin_principals`) and the crosswalk resolvers — NOT by hand-stamping the
// canonical token on a chunk (spike trap #4). Every chunk's visibility token is
// obtained by resolving a SOURCE-LOCAL owner id (Drive grant email / SF
// FederationIdentifier / HubSpot ownerId) through the crosswalk, then stamping
// exactly what the resolver returned. If the resolver ever produced a token that
// differs from the one `open_scope` mints for `user:alice@corp.com`, recall would
// come up empty — so a passing recall is the disjoint-space proof.
//
// Hard-error without DSN is inherited from `test_state`/`test_state_admin`.

/// The source-local owner a connector would emit for a chunk, tagged by the
/// registry path it resolves through. NO variant carries a canonical string.
#[allow(clippy::enum_variant_names)]
enum Owner<'a> {
    /// Drive grant `emailAddress` / Gmail header address → `resolve_idp_subject`.
    DriveEmail(&'a str),
    /// SF `FederationIdentifier` matched against `principal_sso_alias.alias`
    /// (reuses `resolve_idp_subject`); `User.Email` is NEVER passed.
    SfFederation(&'a str),
    /// HubSpot `ownerId` → `resolve_crosswalk` (admin_explicit link).
    HubspotOwner(&'a str),
}

/// The NAMED populate that closes spike trap #2 (empty crosswalk): a fixture
/// gdirectory reconcile writing `canonical_principal` + `principal_sso_alias`
/// rows + a self `principal_crosswalk (gdirectory,<dir-id>)` — all through the
/// real B1.4 admin routes. `aliases` are the SSO subjects (SF FederationIdentifier
/// targets) the admin declared for this human.
async fn seed_directory_reconcile(
    state: &Arc<AppState>,
    tenant: TenantId,
    primary_email: &str,
    aliases: &[&str],
) {
    let canonical = format!("user:{primary_email}");
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principals": [{ "canonical": canonical, "kind": "user", "idp_subject": primary_email }],
    }))
    .expect("canonical shape");
    let Json(v) =
        crate::admin_registry_canonical(State(Arc::clone(state)), admin_headers(), Json(req))
            .await
            .expect("seed canonical");
    assert_eq!(
        v["upserted"].as_array().unwrap().len(),
        1,
        "the fixture reconcile registered the canonical (crosswalk is NOT empty)"
    );

    if !aliases.is_empty() {
        let alias_rows: Vec<_> = aliases
            .iter()
            .map(|a| json!({ "canonical": canonical, "alias": a, "source": "google_customschema" }))
            .collect();
        let req = serde_json::from_value(json!({
            "tenant_id": tenant,
            "aliases": alias_rows,
        }))
        .expect("alias shape");
        let Json(_) =
            crate::admin_registry_alias(State(Arc::clone(state)), admin_headers(), Json(req))
                .await
                .expect("seed aliases");
    }

    // Self crosswalk (gdirectory, <dir-id>) → canonical, directory_vouched.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "gdirectory",
        "local_id": format!("dir-{primary_email}"),
        "canonical": canonical,
        "link_method": "directory_vouched",
    }))
    .expect("self-crosswalk shape");
    let Json(_) = crate::admin_crosswalk_link(State(Arc::clone(state)), admin_headers(), Json(req))
        .await
        .expect("seed self crosswalk");
}

/// Register an admin_explicit `(source, local_id) → user:<email>` link (HubSpot).
async fn seed_admin_crosswalk(
    state: &Arc<AppState>,
    tenant: TenantId,
    source: &str,
    local_id: &str,
    primary_email: &str,
) {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": source,
        "local_id": local_id,
        "canonical": format!("user:{primary_email}"),
        "link_method": "admin_explicit",
    }))
    .expect("crosswalk shape");
    let Json(_) = crate::admin_crosswalk_link(State(Arc::clone(state)), admin_headers(), Json(req))
        .await
        .expect("seed admin crosswalk");
}

/// Resolve a source-local owner id through the REAL sink and return the tokens
/// the connector would stamp. Empty `Vec` == the server quarantined (all owners
/// dropped, fail closed). NO canonical string is named here — the caller only
/// ever hands us the source-local id.
async fn resolve_owner_tokens(
    state: &Arc<AppState>,
    tenant: TenantId,
    owner: &Owner<'_>,
) -> Vec<PrincipalToken> {
    let body = match owner {
        Owner::DriveEmail(email) | Owner::SfFederation(email) => json!({
            "tenant_id": tenant,
            "emails": [email],
        }),
        Owner::HubspotOwner(id) => json!({
            "tenant_id": tenant,
            "resolvable": [{ "source": "hubspot", "local_id": id }],
        }),
    };
    let req = serde_json::from_value(body).expect("principals request shape");
    let Json(v) = crate::admin_principals(State(Arc::clone(state)), admin_headers(), Json(req))
        .await
        .expect("admin_principals");
    if v["quarantined"] == json!(true) {
        return vec![];
    }
    v["mappings"]
        .as_object()
        .expect("mappings object")
        .values()
        .map(|t| t.as_i64().expect("token int") as PrincipalToken)
        .collect()
}

/// Index a chunk whose visibility is obtained by resolving a SOURCE-LOCAL owner
/// id through the crosswalk (the real ingest path). Returns the stamped tokens
/// so a test can assert WHICH token was used (e.g. ≠ token("user:<sf-email>")).
async fn index_chunk_via_crosswalk(
    state: &Arc<AppState>,
    tenant: TenantId,
    doc: &str,
    content: &str,
    owner: Owner<'_>,
    confidentiality: Confidentiality,
) -> Vec<PrincipalToken> {
    let visibility = resolve_owner_tokens(state, tenant, &owner).await;
    // Fail-closed: an all-dropped owner leaves visibility empty; the chunk is
    // indexed with NO principal (invisible), never permissively.
    index_chunk(
        state,
        tenant,
        doc,
        content,
        visibility.clone(),
        confidentiality,
    )
    .await;
    visibility
}

/// THE GATE (invariant a): ingest D (Drive email), A (SF FederationIdentifier,
/// User.Email divergent), H (HubSpot ownerId) — all resolved through the REAL
/// crosswalk — then mint `user:alice@corp.com` and recall ALL THREE. No test
/// line stamps the canonical token on a chunk (trap #4 avoided): each chunk's
/// token came from resolving a source-local owner id at the sink.
#[tokio::test]
async fn m2b_acceptance_trace_d_a_h_via_canonical() {
    // Subject-based mint requires ReBAC (open_scope rejects a `subject` in dev
    // mode). The subject `user:alice@corp.com` resolves to its self-token even
    // with no group tuples; the crosswalk join is pure Postgres either way.
    let (state, tenant) =
        test_state_admin(Some(require_rebac("m2b_acceptance_trace")), false).await;

    // Named populate (trap #2 closed): Alice's canonical + the SSO alias the SF
    // FederationIdentifier will match + her self crosswalk.
    seed_directory_reconcile(&state, tenant, "alice@corp.com", &["alice@corp.com"]).await;
    // HubSpot has no SSO subject → admin_explicit link on ownerId 77.
    seed_admin_crosswalk(&state, tenant, "hubspot", "77", "alice@corp.com").await;

    // D — Drive doc shared with grant emailAddress alice@corp.com.
    let d_tokens = index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-D",
        "obsidian roadmap shared on drive",
        Owner::DriveEmail("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    // A — SF Account owned via FederationIdentifier=alice@corp.com; the roster's
    // User.Email is alice.n@corp.sf and is NEVER passed to the resolver.
    let a_tokens = index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-A",
        "obsidian account in salesforce",
        Owner::SfFederation("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    // H — HubSpot deal owned by ownerId 77.
    let h_tokens = index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-H",
        "obsidian deal in hubspot",
        Owner::HubspotOwner("77"),
        Confidentiality::Internal,
    )
    .await;

    // All three resolved to the SAME canonical token (byte-exact overlap).
    assert_eq!(d_tokens.len(), 1, "D resolved to exactly one token");
    assert_eq!(
        a_tokens, d_tokens,
        "A's SF-Federation token == D's Drive token"
    );
    assert_eq!(
        h_tokens, d_tokens,
        "H's HubSpot-owner token == D's Drive token"
    );

    // Trap #3 proof: the SF chunk was NOT keyed on User.Email. The token for the
    // divergent login string is DIFFERENT from what A was stamped with.
    let sf_email_token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["user:alice.n@corp.sf".to_string()])
            .await
            .expect("sf-email token")[0]
            .1;
    assert!(
        !a_tokens.contains(&sf_email_token),
        "SF visibility must NOT derive from User.Email (alice.n@corp.sf)"
    );

    // Mint for the DIRECTORY-VERIFIED primary email — the same string that
    // upsert_principal_tokens keyed the chunks on — and recall all three.
    let handle = mint_with_subject(&state, tenant, "user:alice@corp.com")
        .await
        .expect("mint alice");
    let docs = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    for d in ["doc-D", "doc-A", "doc-H"] {
        assert!(
            docs.contains(&d.to_string()),
            "acceptance trace: {d} must be visible to user:alice@corp.com via the canonical crosswalk, got {docs:?}"
        );
    }
}

/// N1: Bob resolves to a DIFFERENT canonical token, so the same D/A/H corpus is
/// invisible to him (pure static-int disjointness — no registry read on recall).
#[tokio::test]
async fn m2b_bob_sees_none() {
    let (state, tenant) = test_state_admin(Some(require_rebac("m2b_bob_sees_none")), false).await;
    seed_directory_reconcile(&state, tenant, "alice@corp.com", &["alice@corp.com"]).await;
    seed_admin_crosswalk(&state, tenant, "hubspot", "77", "alice@corp.com").await;
    seed_directory_reconcile(&state, tenant, "bob@corp.com", &["bob@corp.com"]).await;

    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-D",
        "obsidian roadmap",
        Owner::DriveEmail("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-A",
        "obsidian account",
        Owner::SfFederation("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-H",
        "obsidian deal",
        Owner::HubspotOwner("77"),
        Confidentiality::Internal,
    )
    .await;

    let handle = mint_with_subject(&state, tenant, "user:bob@corp.com")
        .await
        .expect("mint bob");
    let docs = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    assert!(
        docs.is_empty(),
        "Bob's canonical token overlaps none of Alice's D/A/H: {docs:?}"
    );
}

/// N2 / T3 (needs SpiceDB): a DEPROVISIONED Alice sees none. The deprovision
/// route flips `canonical_principal.active=false` AND fires the 2a durable
/// revoke; a FRESH mint drops the self-token, and the denial is durable across
/// the 20h aging window.
#[tokio::test]
async fn m2b_deprovisioned_alice_sees_none() {
    let (state, tenant) =
        test_state_admin(Some(require_rebac("m2b_deprovisioned_alice")), false).await;
    seed_directory_reconcile(&state, tenant, "alice@corp.com", &["alice@corp.com"]).await;
    seed_admin_crosswalk(&state, tenant, "hubspot", "77", "alice@corp.com").await;

    let d_tokens = index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-D",
        "obsidian roadmap",
        Owner::DriveEmail("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-A",
        "obsidian account",
        Owner::SfFederation("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-H",
        "obsidian deal",
        Owner::HubspotOwner("77"),
        Confidentiality::Internal,
    )
    .await;
    let t_a = d_tokens[0];

    // Before deprovision: Alice sees all three.
    let handle = mint_with_subject(&state, tenant, "user:alice@corp.com")
        .await
        .expect("mint alice");
    let docs = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    assert_eq!(docs.len(), 3, "pre-deprovision Alice sees D/A/H: {docs:?}");

    // Deprovision through the B1.5 route (the gdirectory-suspend path).
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principal": "user:alice@corp.com",
    }))
    .expect("deprovision shape");
    let Json(v) = crate::admin_deprovision(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect("deprovision");
    assert_eq!(v["deprovisioned"], json!(true));

    // canonical flipped inactive.
    let active: bool =
        sqlx::query_scalar("SELECT active FROM canonical_principal WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(state.pool())
            .await
            .unwrap();
    assert!(
        !active,
        "deprovision flipped canonical_principal.active=false"
    );

    // 2a durable revoke fired: the token is in the revoked set.
    let revoked = state
        .revocations
        .revoked_set(state.pool(), tenant)
        .await
        .expect("revoked set");
    assert!(
        revoked.contains(&t_a),
        "deprovision fired 2a durable revoke"
    );

    // A FRESH mint drops the self-token → recall empty.
    let fresh = mint_with_subject(&state, tenant, "user:alice@corp.com")
        .await
        .expect("re-mint");
    let docs = recall_docs(&state, &fresh, "obsidian")
        .await
        .expect("recall");
    assert!(docs.is_empty(), "deprovisioned Alice sees none: {docs:?}");

    // T3b durability: age the durable record 20h; a re-mint STILL sees none.
    age_revocation(&state, tenant, t_a, 20).await;
    let fresh2 = mint_with_subject(&state, tenant, "user:alice@corp.com")
        .await
        .expect("re-mint aged");
    let docs = recall_docs(&state, &fresh2, "obsidian")
        .await
        .expect("recall");
    assert!(
        docs.is_empty(),
        "deprovision denial is durable across 20h: {docs:?}"
    );
}

/// N4 / T5 (no false weld): a SECOND SF User presents a DIFFERENT
/// FederationIdentifier but the SAME Email attribute (alice@corp.com). The email
/// weld MUST be refused — the second Federation subject, having no declared
/// alias, resolves to NOTHING (its chunk indexes invisible); meanwhile the
/// established `user:alice@corp.com` is untouched and still recalls its doc.
#[tokio::test]
async fn m2b_no_false_weld_sf_twin() {
    let (state, tenant) =
        test_state_admin(Some(require_rebac("m2b_no_false_weld_sf_twin")), false).await;
    // Established Alice: primary alice@corp.com, SSO alias alice@corp.com.
    seed_directory_reconcile(&state, tenant, "alice@corp.com", &["alice@corp.com"]).await;

    // Alice's own SF-owned doc (Federation matches her declared alias).
    let a_tokens = index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-A",
        "obsidian alice account",
        Owner::SfFederation("alice@corp.com"),
        Confidentiality::Internal,
    )
    .await;
    assert_eq!(a_tokens.len(), 1, "Alice's SF owner resolves");

    // The TWIN: a DIFFERENT human whose SF FederationIdentifier is a distinct SSO
    // subject (twin-sso@corp.com) that no admin ever declared — even though this
    // SF row's Email attribute happens to read alice@corp.com. The resolver keys
    // ONLY on the FederationIdentifier alias, which is unvouched → quarantine.
    let twin_tokens =
        resolve_owner_tokens(&state, tenant, &Owner::SfFederation("twin-sso@corp.com")).await;
    assert!(
        twin_tokens.is_empty(),
        "an undeclared FederationIdentifier confers NO visibility — no email weld: {twin_tokens:?}"
    );

    // The twin's chunk therefore indexes invisible.
    index_chunk_via_crosswalk(
        &state,
        tenant,
        "doc-TWIN",
        "obsidian twin account",
        Owner::SfFederation("twin-sso@corp.com"),
        Confidentiality::Internal,
    )
    .await;

    // The established principal is unaffected: Alice still recalls her own doc,
    // and never the twin's (they never welded into one canonical).
    let handle = mint_with_subject(&state, tenant, "user:alice@corp.com")
        .await
        .expect("mint alice");
    let docs = recall_docs(&state, &handle, "obsidian")
        .await
        .expect("recall");
    assert!(
        docs.contains(&"doc-A".to_string()),
        "established canonical untouched — Alice still recalls doc-A: {docs:?}"
    );
    assert!(
        !docs.contains(&"doc-TWIN".to_string()),
        "the twin's chunk is invisible (no weld): {docs:?}"
    );
}
