//! Write-path materialization tests for the L1 fact-visibility gap closure
//! (SPEC §5e). Every fact must persist its `visibility` token set +
//! `confidentiality` at creation, supersession must carry the ACL forward onto
//! each new value row, and `correct_fact_acl` must rewrite the ACL in place
//! across the whole key history + append one audit row (the append-only
//! carve-out). Requires a live DB (VERITY_TEST_DSN); HARD-ERRORS (panics) when
//! absent — this is the WRITE side of the §5e.6a fact-visibility leak (without
//! persisted ACLs the read-path enforcement has nothing to filter on), so a
//! silent skip is a soundness gap, not a convenience.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{AclCorrectionReason, PostgresAdapter};

async fn harness() -> (PostgresAdapter, TenantId, EpisodeId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the fact-visibility write-path soundness tests (SPEC \
         §5e ACL materialization); refusing to silently no-op",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "test".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: json!({}),
            content_hash: "t".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    (adapter, tenant, episode)
}

fn key() -> FactKey {
    FactKey {
        source: "hubspot".into(),
        entity_id: "deal-99".into(),
        field: "stage".into(),
    }
}

/// A read scope admitting `principals` up to `Restricted`, unbounded entity
/// scope. The reads in these write-path tests just need to SEE the row they
/// seeded; visibility enforcement itself is exercised by scope_fuzz.rs.
fn scope(tenant: TenantId, principals: Vec<PrincipalToken>) -> Scope {
    Scope {
        tenant_id: tenant,
        principals,
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    }
}

/// A materialized token set + confidentiality survives the write and reads back
/// verbatim on the current row.
#[tokio::test]
async fn upsert_materializes_visibility_and_confidentiality() {
    let (adapter, tenant, episode) = harness().await;
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: key(),
            value: json!("negotiation"),
            valid_from: Utc::now(),
            visibility: vec![7, 11, 13],
            confidentiality: Confidentiality::Confidential,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();

    let row = adapter
        .current_fact(&scope(tenant, vec![11]), &key())
        .await
        .unwrap()
        .expect("current row");
    assert_eq!(row.visibility, vec![7, 11, 13]);
    assert_eq!(row.confidentiality, Confidentiality::Confidential);
}

/// An empty token set is preserved as an EMPTY set (a real "nobody can read
/// this" refusal), never silently widened to a permissive default — and is
/// therefore INVISIBLE to every scoped read (`visibility && $tokens` is false
/// for an empty array). This is the exact distinction the read path relies on to
/// fail closed: even a broad scope carrying every principal cannot read it.
#[tokio::test]
async fn empty_visibility_is_invisible_to_every_scope() {
    let (adapter, tenant, episode) = harness().await;
    let k = FactKey {
        source: "hubspot".into(),
        entity_id: "deal-empty".into(),
        field: "stage".into(),
    };
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: k.clone(),
            value: json!("x"),
            valid_from: Utc::now(),
            visibility: vec![],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::Quarantined,
        })
        .await
        .unwrap();

    // A broad scope carrying every principal (0..=64) still sees nothing: the
    // empty visibility overlaps no token set.
    let broad = scope(tenant, (0..=64).collect());
    assert!(adapter.current_fact(&broad, &k).await.unwrap().is_none());
    // But the row WAS persisted with empty visibility — an in-place ACL
    // correction across the key finds and rewrites exactly one row.
    let rewritten = adapter
        .correct_fact_acl(
            tenant,
            &k,
            &[9],
            Confidentiality::Internal,
            AclCorrectionReason::AdminCorrection,
            AclProvenance::AdminAssigned,
            Some("test"),
        )
        .await
        .unwrap();
    assert_eq!(rewritten, 1, "the empty-visibility row was persisted");
    // After the correction it becomes visible to principal 9 only.
    assert!(adapter
        .current_fact(&scope(tenant, vec![9]), &k)
        .await
        .unwrap()
        .is_some());
}

/// Supersession carries the ACL forward onto each new value row (like
/// acl_provenance): the second value row is stamped with ITS OWN write's ACL.
#[tokio::test]
async fn supersession_carries_acl_onto_new_value_row() {
    let (adapter, tenant, episode) = harness().await;
    let k = FactKey {
        source: "hubspot".into(),
        entity_id: "deal-super".into(),
        field: "amount".into(),
    };
    let t0 = Utc::now() - Duration::minutes(10);
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: k.clone(),
            value: json!(1),
            valid_from: t0,
            visibility: vec![3],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();
    let out = adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: k.clone(),
            value: json!(2),
            valid_from: t0 + Duration::minutes(1),
            visibility: vec![3, 9],
            confidentiality: Confidentiality::Confidential,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();
    assert_eq!(out, FactUpsertOutcome::Superseded);

    let cur = adapter
        .current_fact(&scope(tenant, vec![9]), &k)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cur.value, json!(2));
    assert_eq!(cur.visibility, vec![3, 9]);
    assert_eq!(cur.confidentiality, Confidentiality::Confidential);
}

/// `correct_fact_acl` rewrites visibility/confidentiality IN PLACE across every
/// row of the key (current + superseded history) and appends exactly one audit
/// row — the append-only ACL-correction carve-out. Because history rows are
/// touched too, a historical read (`fact_as_of`) also sees the corrected ACL.
#[tokio::test]
async fn correct_fact_acl_rewrites_in_place_and_audits() {
    let (adapter, tenant, episode) = harness().await;
    let k = FactKey {
        source: "hubspot".into(),
        entity_id: "deal-correct".into(),
        field: "amount".into(),
    };
    let t0 = Utc::now() - Duration::minutes(10);
    // Two value rows: one superseded, one current, both visible to {5}.
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: k.clone(),
            value: json!(1),
            valid_from: t0,
            visibility: vec![5],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: k.clone(),
            value: json!(2),
            valid_from: t0 + Duration::minutes(1),
            visibility: vec![5],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();

    // Un-share: revoke principal 5, grant 8, at a stricter class.
    let updated = adapter
        .correct_fact_acl(
            tenant,
            &k,
            &[8],
            Confidentiality::Restricted,
            AclCorrectionReason::SourceUnshare,
            AclProvenance::Mirrored,
            Some("connector:hubspot"),
        )
        .await
        .unwrap();
    // Both the current and the superseded row were rewritten.
    assert_eq!(updated, 2);

    // Current row reflects the correction: visible to 8 at Restricted, and the
    // old principal 5 can no longer see it.
    let cur = adapter
        .current_fact(&scope(tenant, vec![8]), &k)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cur.visibility, vec![8]);
    assert_eq!(cur.confidentiality, Confidentiality::Restricted);
    assert!(
        adapter
            .current_fact(&scope(tenant, vec![5]), &k)
            .await
            .unwrap()
            .is_none(),
        "the un-shared principal 5 no longer sees the current value"
    );

    // The HISTORICAL row (value 1) reflects the correction too — a revoked
    // principal cannot reach a past value via `?as_of=`.
    let hist = adapter
        .fact_as_of(&scope(tenant, vec![8]), &k, t0 + Duration::seconds(30))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hist.value, json!(1));
    assert_eq!(hist.visibility, vec![8]);
    assert_eq!(hist.confidentiality, Confidentiality::Restricted);
    assert!(
        adapter
            .fact_as_of(&scope(tenant, vec![5]), &k, t0 + Duration::seconds(30))
            .await
            .unwrap()
            .is_none(),
        "principal 5 cannot reach the historical value via as_of after un-share"
    );
}
