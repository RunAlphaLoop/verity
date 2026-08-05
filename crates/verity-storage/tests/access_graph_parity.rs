//! Permission Graph — scope-parity + fail-closed storage locks (spec §9 T1/T2).
//!
//! T1 (the load-bearing test, G4): the Endpoint-1 corpus aggregate MUST equal
//! the ENFORCEMENT pre-filter set — `tenant_id + visibility && tokens +
//! confidentiality <= ceiling + valid_to IS NULL` over the POST-revocation
//! token set — NOT recall's ANN-returnable set. So the baseline deliberately
//! excludes `{col} IS NOT NULL` / entity_scope / kind shaping. Includes the
//! revoke-in-window sub-case: revoking a token in-window must drop the docs it
//! alone granted, exactly as `scope_for`/`RevocationPlane::subtract` would.
//!
//! Requires VERITY_TEST_DSN; HARD-ERRORS (panics) when absent — the aggregate
//! must equal the enforcement pre-filter (incl. empty-token → empty and
//! revoke-in-window subtraction); a soundness gate that silently skips is the
//! process gap this milestone closes.

use chrono::Utc;
use serde_json::json;
use sqlx::Row;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{AclCorrectionReason, ObjectSelector, PostgresAdapter};

async fn setup() -> (PostgresAdapter, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the access-graph parity soundness tests (spec §9 \
         T1/T2/T4/T5); refusing to silently no-op",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    (adapter, tenant)
}

#[allow(clippy::too_many_arguments)]
async fn seed_chunk(
    a: &PostgresAdapter,
    tenant: TenantId,
    doc: &str,
    source: &str,
    visibility: Vec<PrincipalToken>,
    conf: Confidentiality,
    prov: AclProvenance,
) {
    let episode = a
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(doc.into()),
            kind: EpisodeKind::Observation,
            payload: json!({}),
            content_hash: format!("i-{doc}"),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: Some("agent:seed".into()),
        })
        .await
        .unwrap();
    a.upsert_chunks(vec![ChunkWrite {
        tenant_id: tenant,
        source: source.into(),
        document_id: doc.into(),
        seq: 0,
        content: format!("body {doc}"),
        content_hash: format!("c-{doc}"),
        embedding: None,
        visibility,
        entity_tags: vec![],
        confidentiality: conf,
        trust_tier: TrustTier::Observation,
        valid_from: Utc::now(),
        provenance: episode,
        acl_provenance: prov,
        derived_from: vec![],
    }])
    .await
    .unwrap();
}

/// The independent baseline: the exact enforcement pre-filter, run directly.
async fn enforcement_docs(
    a: &PostgresAdapter,
    tenant: TenantId,
    tokens: &[PrincipalToken],
    max_conf: i16,
) -> i64 {
    sqlx::query(
        "SELECT count(DISTINCT document_id)::bigint AS docs FROM chunks
          WHERE tenant_id = $1 AND visibility && $2
            AND confidentiality <= $3 AND valid_to IS NULL",
    )
    .bind(tenant)
    .bind(tokens)
    .bind(max_conf)
    .fetch_one(a.pool())
    .await
    .unwrap()
    .try_get("docs")
    .unwrap()
}

#[tokio::test]
async fn t1_aggregate_equals_enforcement_prefilter() {
    let (a, tenant) = setup().await;
    // Tokens: 10=eng, 11=all-staff. Docs seeded with varied visibility/conf/prov.
    seed_chunk(
        &a,
        tenant,
        "d/a",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    seed_chunk(
        &a,
        tenant,
        "d/b",
        "gdrive",
        vec![11],
        Confidentiality::Confidential,
        AclProvenance::Approximated,
    )
    .await;
    seed_chunk(
        &a,
        tenant,
        "d/c",
        "gmail",
        vec![10, 11],
        Confidentiality::Public,
        AclProvenance::Mirrored,
    )
    .await;
    // Invisible to our tokens (token 99) — must never count.
    seed_chunk(
        &a,
        tenant,
        "d/x",
        "gmail",
        vec![99],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;

    let tokens = vec![10, 11];
    let (corpus, approx) = a
        .access_corpus_aggregate(tenant, &tokens, 3, false, 4000)
        .await
        .unwrap();
    assert!(!approx, "small corpus must not time out");

    let baseline = enforcement_docs(&a, tenant, &tokens, 3).await;
    assert_eq!(
        corpus.total_docs, baseline,
        "aggregate total_docs must equal the enforcement pre-filter set"
    );
    assert_eq!(corpus.total_docs, 3, "d/a,d/b,d/c visible; d/x invisible");

    // Per-source parity.
    let gdrive = corpus.by_source.iter().find(|c| c.key == "gdrive").unwrap();
    assert_eq!(gdrive.docs, 2);

    // max_confidentiality ceiling: at ceiling 0 only the Public d/c remains.
    let (c0, _) = a
        .access_corpus_aggregate(tenant, &tokens, 0, false, 4000)
        .await
        .unwrap();
    assert_eq!(
        c0.total_docs,
        enforcement_docs(&a, tenant, &tokens, 0).await
    );
    assert_eq!(c0.total_docs, 1);
}

#[tokio::test]
async fn t1_revoke_in_window_drops_docs() {
    let (a, tenant) = setup().await;
    // d/only-eng is reachable ONLY via token 10.
    seed_chunk(
        &a,
        tenant,
        "d/only-eng",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    seed_chunk(
        &a,
        tenant,
        "d/shared",
        "gdrive",
        vec![10, 11],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;

    // Before revocation: both docs visible to {10,11}.
    let tokens = vec![10, 11];
    let (before, _) = a
        .access_corpus_aggregate(tenant, &tokens, 3, false, 4000)
        .await
        .unwrap();
    assert_eq!(before.total_docs, 2);

    // Revoke token 10 IN WINDOW (write a fresh revocations row).
    sqlx::query("INSERT INTO revocations (id, tenant_id, principal, token) VALUES ($1,$2,$3,$4)")
        .bind(uuid::Uuid::now_v7())
        .bind(tenant)
        .bind("group:eng")
        .bind(10_i32)
        .execute(a.pool())
        .await
        .unwrap();

    // The admin plane subtracts in-window revoked tokens INLINE, exactly as the
    // read path's scope_for/subtract does.
    let revoked = a.windowed_revoked_tokens(tenant, 300).await.unwrap();
    assert!(revoked.contains(&10));
    let post: Vec<PrincipalToken> = tokens
        .iter()
        .copied()
        .filter(|t| !revoked.contains(t))
        .collect();
    assert_eq!(post, vec![11]);

    let (after, _) = a
        .access_corpus_aggregate(tenant, &post, 3, false, 4000)
        .await
        .unwrap();
    // d/only-eng is gone (granted only by the revoked token); d/shared remains
    // (still reachable via 11) — parity would FAIL without the subtraction.
    assert_eq!(after.total_docs, 1);
    assert_eq!(
        after.total_docs,
        enforcement_docs(&a, tenant, &post, 3).await
    );
}

/// M2 2a sweep oracle: the chunk-visibility sweep (`retract_token_from_chunks`)
/// strips JUST the revoked token from every carrying chunk — the doc granted ONLY
/// by that token vanishes from the enforcement pre-filter, a co-granted doc keeps
/// its OTHER grant, an audit row is written per swept current chunk, and the
/// value-history carve-out holds (a superseded row cannot resurface the token via
/// `?as_of=`). Fail-closed direction: the swept token never re-admits a chunk.
#[tokio::test]
async fn m2a_sweep_retracts_token_and_audits_preserving_other_grants() {
    let (a, tenant) = setup().await;
    // 10 = Alice's DIRECT-grant token (T_A); 11 = Bob's (T_B).
    seed_chunk(
        &a,
        tenant,
        "d/alice-only",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    seed_chunk(
        &a,
        tenant,
        "d/shared",
        "gdrive",
        vec![10, 11],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    seed_chunk(
        &a,
        tenant,
        "d/bob-only",
        "gdrive",
        vec![11],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;

    // Before: {10} sees both alice-only and shared.
    assert_eq!(enforcement_docs(&a, tenant, &[10], 3).await, 2);

    let swept = a
        .retract_token_from_chunks(
            tenant,
            10,
            AclCorrectionReason::PrincipalRevoke,
            "admin:test",
        )
        .await
        .unwrap();
    assert_eq!(swept, 2, "alice-only + shared carried token 10");

    // After: token 10 admits NOTHING (alice-only blanked to {}, shared -> {11}).
    assert_eq!(
        enforcement_docs(&a, tenant, &[10], 3).await,
        0,
        "revoked token re-admits no chunk"
    );
    // Bob (11) is UNAFFECTED: still sees shared + bob-only.
    assert_eq!(enforcement_docs(&a, tenant, &[11], 3).await, 2);

    // No LIVE chunk row still carries token 10 (current + superseded stripped).
    let residual: i64 = sqlx::query(
        "SELECT count(*)::bigint AS n FROM chunks
          WHERE tenant_id = $1 AND visibility @> ARRAY[10]::int[]",
    )
    .bind(tenant)
    .fetch_one(a.pool())
    .await
    .unwrap()
    .try_get("n")
    .unwrap();
    assert_eq!(
        residual, 0,
        "value-history carve-out: no row retains the token"
    );

    // Audit trail: one principal_revoke row per swept current chunk.
    let audited: i64 = sqlx::query(
        "SELECT count(*)::bigint AS n FROM chunk_acl_audit
          WHERE tenant_id = $1 AND reason = 'principal_revoke'",
    )
    .bind(tenant)
    .fetch_one(a.pool())
    .await
    .unwrap()
    .try_get("n")
    .unwrap();
    assert_eq!(audited, 2, "one audit row per swept current chunk");

    // Idempotent re-sweep of an already-swept token touches nothing.
    let again = a
        .retract_token_from_chunks(
            tenant,
            10,
            AclCorrectionReason::PrincipalRevoke,
            "admin:test",
        )
        .await
        .unwrap();
    assert_eq!(again, 0);
}

#[tokio::test]
async fn t2_empty_token_set_is_empty_aggregate() {
    let (a, tenant) = setup().await;
    seed_chunk(
        &a,
        tenant,
        "d/a",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    // Fail-closed: an empty token set (unresolvable subject) sees NOTHING —
    // never "show everything".
    let (corpus, approx) = a
        .access_corpus_aggregate(tenant, &[], 3, false, 4000)
        .await
        .unwrap();
    assert!(!approx);
    assert_eq!(corpus.total_docs, 0);
    assert_eq!(corpus.total_chunks, 0);
    assert!(corpus.by_source.is_empty());
}

#[tokio::test]
async fn t5_object_decode_and_reverse_resolve() {
    let (a, tenant) = setup().await;
    seed_chunk(
        &a,
        tenant,
        "d/obj",
        "gdrive",
        vec![10, 11],
        Confidentiality::Confidential,
        AclProvenance::Mirrored,
    )
    .await;
    // Materialize the token→principal mapping the reverse-resolve needs.
    sqlx::query("INSERT INTO principals (tenant_id, principal, token) VALUES ($1,'group:eng',10),($1,'group:all-staff',11) ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(a.pool())
        .await
        .unwrap();

    let decode = a
        .access_object_tokens(tenant, ObjectSelector::Document("d/obj"), 4000, 2_000_000)
        .await
        .unwrap();
    assert!(!decode.refused_over_ceiling);
    let mut toks = decode.tokens.clone();
    toks.sort_unstable();
    assert_eq!(toks, vec![10, 11]);
    assert_eq!(decode.min_confidentiality, Some(2));

    let mut resolved = a.resolve_tokens(tenant, &decode.tokens).await.unwrap();
    resolved.sort_by_key(|(t, _)| *t);
    assert_eq!(
        resolved,
        vec![
            (10, "group:eng".to_string()),
            (11, "group:all-staff".to_string())
        ]
    );
}

/// T6 — metadata-not-content (NG2), static grep. The Permission Graph data
/// methods must never project the chunk `content` column.
#[test]
fn t6_access_methods_never_select_content() {
    let src = include_str!("../src/postgres.rs");
    let start = src
        .find("Permission Graph (admin/operator plane, permission-graph-viz)")
        .expect("permission-graph section present");
    let end = src[start..]
        .find("quarantine lifecycle")
        .map(|i| start + i)
        .expect("section end marker present");
    // Strip comment lines first: the section documents (in prose) that it is a
    // metadata-not-content surface, and those mentions are not SQL. The check
    // is that the CODE — the SQL strings — never names the `content` column.
    let code: String = src[start..end]
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("content"),
        "Permission Graph SQL must not select chunk content (NG2)"
    );
}

#[tokio::test]
async fn t4_tenant_isolation() {
    let (a, tenant_a) = setup().await;
    let tenant_b = a
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    // Same document_id string in both tenants, disjoint content.
    seed_chunk(
        &a,
        tenant_a,
        "d/same",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;
    seed_chunk(
        &a,
        tenant_b,
        "d/same",
        "gdrive",
        vec![10],
        Confidentiality::Internal,
        AclProvenance::Mirrored,
    )
    .await;

    // Aggregate for tenant A's tokens counts ONLY tenant A's doc.
    let (a_corpus, _) = a
        .access_corpus_aggregate(tenant_a, &[10], 3, false, 4000)
        .await
        .unwrap();
    assert_eq!(a_corpus.total_docs, 1);
    // A token minted in A must not resolve against B's principals.
    sqlx::query("INSERT INTO principals (tenant_id, principal, token) VALUES ($1,'group:eng',10) ON CONFLICT DO NOTHING")
        .bind(tenant_a)
        .execute(a.pool())
        .await
        .unwrap();
    let cross = a.resolve_tokens(tenant_b, &[10]).await.unwrap();
    assert!(cross.is_empty(), "tenant B has no token 10");
}
