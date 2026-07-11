//! Identity-plane integration tests (roadmap task 10), exercising the real
//! handlers in-process.
//!
//! Gating follows the VERITY_TEST_DSN pattern: tests needing Postgres skip
//! without `VERITY_TEST_DSN`; tests needing SpiceDB additionally skip without
//! `VERITY_SPICEDB_URL` (start it via
//! `docker compose -f deploy/docker-compose.yml up -d spicedb`).

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
async fn test_state(
    rebac: Option<Rebac>,
    allow_restricted: bool,
) -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
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
        },
        rebac,
        revocations: RevocationPlane::new(300),
        allow_restricted_without_rebac: allow_restricted,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
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
    let Some((state, tenant)) = test_state(None, false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
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
    let Some((state_allow, tenant2)) = test_state(None, true).await else {
        return;
    };
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
    let Some((state, tenant)) = test_state(None, false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
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
    let Some(rebac) = Rebac::from_env() else {
        eprintln!("VERITY_SPICEDB_URL not set; skipping");
        return;
    };
    rebac.ensure_schema().await.expect("schema");
    let Some((state, tenant)) = test_state(Some(rebac), false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

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
    let Some(rebac) = Rebac::from_env() else {
        eprintln!("VERITY_SPICEDB_URL not set; skipping");
        return;
    };
    rebac.ensure_schema().await.expect("schema");
    let Some((state, tenant)) = test_state(Some(rebac), false).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

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
