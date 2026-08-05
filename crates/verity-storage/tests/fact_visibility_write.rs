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

/// `correct_chunk_acl` is the object-level twin of `correct_fact_acl`: a source
/// record fans out to MANY chunks under one `(source, document_id)` (only `seq`
/// varies). Tightening the record must rewrite `visibility`/`confidentiality`
/// IN PLACE across EVERY derived chunk — every seq AND every superseded history
/// row (the value-history carve-out) — append one `chunk_acl_audit` row per
/// current chunk, and leave a reader who lost the token unable to recall any of
/// them. This is the leak M1 closes: before, un-share retracted nothing on the
/// chunk side.
#[tokio::test]
async fn correct_chunk_acl_rewrites_lineage_and_audits() {
    let (adapter, tenant, episode) = harness().await;
    let source = "gdrive";
    let document_id = "doc-lineage-1";
    let entity = "e:acme";
    let t0 = Utc::now() - Duration::minutes(10);

    // Seed a document that fans out to 3 chunks (seq 0,1,2), all visible to {5}.
    // seq 0 additionally gets a superseded history row (an older version), so the
    // lineage has 4 rows total: 3 current + 1 superseded.
    let mut writes = Vec::new();
    // Older version of seq 0 (will be superseded by the current seq-0 write).
    writes.push(ChunkWrite {
        tenant_id: tenant,
        source: source.into(),
        document_id: document_id.into(),
        seq: 0,
        content: "old version of chunk zero".into(),
        content_hash: "h0-old".into(),
        embedding: None,
        visibility: vec![5],
        entity_tags: vec![entity.into()],
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Authoritative,
        valid_from: t0,
        provenance: episode,
        acl_provenance: AclProvenance::Mirrored,
        derived_from: vec![],
    });
    for seq in 0..3 {
        writes.push(ChunkWrite {
            tenant_id: tenant,
            source: source.into(),
            document_id: document_id.into(),
            seq,
            content: format!("chunk {seq} content"),
            content_hash: format!("h{seq}"),
            embedding: None,
            visibility: vec![5],
            entity_tags: vec![entity.into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: t0 + Duration::minutes(1),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
            derived_from: vec![],
        });
    }
    adapter.upsert_chunks(writes).await.unwrap();

    // Reader 5 recalls all 3 current chunks before the correction.
    let before = adapter
        .latest_chunks(&scope(tenant, vec![5]), entity, 100)
        .await
        .unwrap();
    assert_eq!(before.len(), 3, "reader 5 sees all 3 current chunks first");

    // Un-share: revoke principal 5, grant 8, at a stricter class.
    let rewritten = adapter
        .correct_chunk_acl(
            tenant,
            source,
            document_id,
            &[8],
            Confidentiality::Restricted,
            AclCorrectionReason::SourceUnshare,
            AclProvenance::Mirrored,
            Some("connector:gdrive"),
        )
        .await
        .unwrap();
    // Every row of the lineage was rewritten: 3 current + 1 superseded = 4.
    assert_eq!(
        rewritten, 4,
        "every derived chunk row (current + superseded) rewritten"
    );

    // The reader who LOST the token recalls NONE of the chunks now.
    let after_5 = adapter
        .latest_chunks(&scope(tenant, vec![5]), entity, 100)
        .await
        .unwrap();
    assert!(
        after_5.is_empty(),
        "un-shared principal 5 no longer recalls any derived chunk"
    );

    // The new grantee sees all 3 current chunks at the new (Restricted) class.
    let after_8 = adapter
        .latest_chunks(&scope(tenant, vec![8]), entity, 100)
        .await
        .unwrap();
    assert_eq!(
        after_8.len(),
        3,
        "principal 8 now recalls all 3 current chunks"
    );

    // One `chunk_acl_audit` row per CURRENT chunk (3), old->new recorded.
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chunk_acl_audit
         WHERE tenant_id = $1 AND source = $2 AND document_id = $3",
    )
    .bind(tenant)
    .bind(source)
    .bind(document_id)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 3, "one audit row per current chunk");

    // The superseded history row was rewritten too — its `visibility` no longer
    // carries 5, so `?as_of=` cannot resurface the old permissive ACL.
    let stale_vis_with_5: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chunks
         WHERE tenant_id = $1 AND source = $2 AND document_id = $3
           AND 5 = ANY(visibility)",
    )
    .bind(tenant)
    .bind(source)
    .bind(document_id)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(
        stale_vis_with_5, 0,
        "no chunk row (current or superseded) still carries the un-shared token 5"
    );
}

/// The `current_chunk_confidentiality` helper the dispatch layer uses to clamp a
/// tightening correction returns the MAX class across the live lineage, so an
/// un-share can never be told to downgrade below the strictest derived chunk.
#[tokio::test]
async fn current_chunk_confidentiality_reports_lineage_max() {
    let (adapter, tenant, episode) = harness().await;
    let source = "gdrive";
    let document_id = "doc-mixed-conf";
    let t0 = Utc::now() - Duration::minutes(5);
    for (seq, conf) in [
        (0, Confidentiality::Internal),
        (1, Confidentiality::Restricted),
        (2, Confidentiality::Confidential),
    ] {
        adapter
            .upsert_chunks(vec![ChunkWrite {
                tenant_id: tenant,
                source: source.into(),
                document_id: document_id.into(),
                seq,
                content: format!("chunk {seq}"),
                content_hash: format!("hmc{seq}"),
                embedding: None,
                visibility: vec![5],
                entity_tags: vec!["e:acme".into()],
                confidentiality: conf,
                trust_tier: TrustTier::Authoritative,
                valid_from: t0,
                provenance: episode,
                acl_provenance: AclProvenance::Mirrored,
                derived_from: vec![],
            }])
            .await
            .unwrap();
    }
    let max = adapter
        .current_chunk_confidentiality(tenant, source, document_id)
        .await
        .unwrap();
    assert_eq!(
        max,
        Some(Confidentiality::Restricted),
        "clamp source must report the strictest derived chunk's class"
    );
    // Unknown object → None (dispatch then applies no clamp).
    let none = adapter
        .current_chunk_confidentiality(tenant, source, "no-such-doc")
        .await
        .unwrap();
    assert_eq!(none, None);
}

/// Fail-closed on an unknown object: `correct_chunk_acl` on a document that has
/// no chunks returns 0 (the caller must treat this as "unknown object", never as
/// a successful retraction) and writes no audit rows.
#[tokio::test]
async fn correct_chunk_acl_unknown_object_returns_zero() {
    let (adapter, tenant, _episode) = harness().await;
    let rewritten = adapter
        .correct_chunk_acl(
            tenant,
            "gdrive",
            "doc-does-not-exist",
            &[8],
            Confidentiality::Restricted,
            AclCorrectionReason::SourceUnshare,
            AclProvenance::Mirrored,
            Some("connector:gdrive"),
        )
        .await
        .unwrap();
    assert_eq!(rewritten, 0, "unknown object retracts nothing");

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chunk_acl_audit
         WHERE tenant_id = $1 AND document_id = $2",
    )
    .bind(tenant)
    .bind("doc-does-not-exist")
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 0, "no audit row for an unknown object");
}
