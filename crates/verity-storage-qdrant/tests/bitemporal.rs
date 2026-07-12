//! Bi-temporal L1 + fail-closed recall against the Qdrant hybrid profile.
//! Adapted copy of `verity-storage/tests/bitemporal.rs` (facts delegate to
//! Postgres; recall exercises the Qdrant dense leg and the delegated BM25
//! leg), plus a retire_entity case for this profile's chunk-retirement
//! superset. Requires VERITY_TEST_DSN + VERITY_QDRANT_URL; skips when absent.

use chrono::{Duration, Utc};
use rand::Rng;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage_qdrant::QdrantAdapter;

async fn test_adapter() -> Option<(QdrantAdapter, TenantId, EpisodeId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let qurl = std::env::var("VERITY_QDRANT_URL").ok()?;
    let adapter = QdrantAdapter::connect(&dsn, &qurl).await.expect("connect");
    adapter.inner().migrate().await.expect("migrate");
    // Unique tenant per run keeps tests independent of prior state.
    let tenant = adapter
        .create_tenant(&format!("qtest-{}", uuid::Uuid::now_v7()))
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
    Some((adapter, tenant, episode))
}

fn key() -> FactKey {
    FactKey {
        source: "hubspot".into(),
        entity_id: "deal-42".into(),
        field: "amount".into(),
    }
}

/// A scope admitting the facts these tests seed (visibility `[1]`).
fn read_scope(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    }
}

fn unit_vec() -> Vec<f32> {
    let mut rng = rand::rng();
    let v: Vec<f32> = (0..384).map(|_| rng.random_range(-1.0..1.0)).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.into_iter().map(|x| x / n).collect()
}

#[tokio::test]
async fn supersession_lifecycle() {
    let Some((adapter, tenant, episode)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    let t0 = Utc::now() - Duration::minutes(10);
    let write = |value: serde_json::Value, at| FactWrite {
        tenant_id: tenant,
        key: key(),
        value,
        valid_from: at,
        visibility: vec![1],
        confidentiality: Confidentiality::Internal,
        provenance: episode,
        acl_provenance: AclProvenance::AdminAssigned,
    };

    // First value ever.
    let outcome = adapter.upsert_fact(write(json!(50_000), t0)).await.unwrap();
    assert_eq!(outcome, FactUpsertOutcome::Inserted);

    // Identical replay is idempotent.
    let outcome = adapter.upsert_fact(write(json!(50_000), t0)).await.unwrap();
    assert_eq!(outcome, FactUpsertOutcome::Unchanged);

    // A newer value structurally retires the old one.
    let t1 = t0 + Duration::minutes(5);
    let outcome = adapter.upsert_fact(write(json!(84_000), t1)).await.unwrap();
    assert_eq!(outcome, FactUpsertOutcome::Superseded);

    let current = adapter
        .current_fact(&read_scope(tenant), &key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.value, json!(84_000));
    assert_eq!(current.valid_to, None);

    // Bi-temporal read: the world as of t0 still shows the old value,
    // with its supersession recorded.
    let as_of = adapter
        .fact_as_of(&read_scope(tenant), &key(), t0 + Duration::minutes(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(as_of.value, json!(50_000));
    assert_eq!(as_of.valid_to, Some(t1));
    assert_eq!(as_of.superseded_by, Some(current.id));

    // A late-arriving older event never clobbers current truth.
    let outcome = adapter
        .upsert_fact(write(json!(10_000), t0 - Duration::minutes(5)))
        .await
        .unwrap();
    assert_eq!(outcome, FactUpsertOutcome::StaleEvent);
    let current = adapter
        .current_fact(&read_scope(tenant), &key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.value, json!(84_000));
}

#[tokio::test]
async fn recall_fails_closed() {
    let Some((adapter, tenant, episode)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: "d1".into(),
            seq: 0,
            content: "acme corp renewal pricing discussion".into(),
            content_hash: "c1".into(),
            // Embedded so the fail-closed checks hit the Qdrant dense leg,
            // not only the delegated BM25 leg (deviation from the Postgres
            // copy, which uses embedding: None).
            embedding: Some(unit_vec()),
            visibility: vec![7],
            entity_tags: vec!["account:acme".into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .unwrap();

    let base = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    };
    let query = |scope: Scope| RecallQuery {
        scope,
        embedding: Some(unit_vec()),
        text: Some("renewal pricing".into()),
        k: 5,
    };

    // Visible with the right principal.
    let hits = adapter.recall(query(base.clone())).await.unwrap();
    assert_eq!(hits.len(), 1);

    // Empty principal set: nothing, ever.
    let mut scope = base.clone();
    scope.principals = vec![];
    assert!(adapter.recall(query(scope)).await.unwrap().is_empty());

    // Wrong principal: nothing.
    let mut scope = base.clone();
    scope.principals = vec![8];
    assert!(adapter.recall(query(scope)).await.unwrap().is_empty());

    // Entity-bound scope for a different entity: nothing (deny-by-default
    // intersection semantics).
    let mut scope = base.clone();
    scope.entity_scope = vec!["account:globex".into()];
    assert!(adapter.recall(query(scope)).await.unwrap().is_empty());

    // Entity-bound scope covering the chunk's tags: visible.
    let mut scope = base;
    scope.entity_scope = vec!["account:acme".into()];
    assert_eq!(adapter.recall(query(scope)).await.unwrap().len(), 1);
}

/// This profile's documented superset: retire_entity also retires the
/// entity's chunks (Postgres row + Qdrant point), so a deleted entity stops
/// surfacing in recall on both legs.
#[tokio::test]
async fn retire_entity_retires_chunks_too() {
    let Some((adapter, tenant, episode)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: "test".into(),
                entity_id: "account:doomed".into(),
                field: "stage".into(),
            },
            value: json!("active"),
            valid_from: Utc::now() - Duration::hours(1),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: "doomed-1".into(),
            seq: 0,
            content: "doomed entity churn negotiation notes".into(),
            content_hash: "doomed-1".into(),
            embedding: Some(unit_vec()),
            visibility: vec![7],
            entity_tags: vec!["account:doomed".into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now() - Duration::hours(1),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .unwrap();

    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    };
    let query = || RecallQuery {
        scope: scope.clone(),
        embedding: Some(unit_vec()),
        text: Some("doomed churn negotiation".into()),
        k: 10,
    };
    assert!(!adapter.recall(query()).await.unwrap().is_empty());

    let facts = adapter
        .retire_entity(tenant, "test", "account:doomed", Utc::now())
        .await
        .unwrap();
    assert_eq!(facts, 1);
    let key = FactKey {
        source: "test".into(),
        entity_id: "account:doomed".into(),
        field: "stage".into(),
    };
    // Scope admits the fact's visibility (`[1]`), so a None here proves the row
    // was RETIRED, not merely filtered out by scope.
    assert!(adapter
        .current_fact(&read_scope(tenant), &key)
        .await
        .unwrap()
        .is_none());
    assert!(
        adapter
            .recall(query())
            .await
            .unwrap()
            .iter()
            .all(|h| h.document_id != "doomed-1"),
        "retired entity's chunk still surfaces in recall"
    );
}
