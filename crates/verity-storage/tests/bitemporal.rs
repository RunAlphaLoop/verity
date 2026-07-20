//! Integration tests for the deterministic bi-temporal L1 contract (SPEC §2).
//! Requires a live database: VERITY_TEST_DSN=postgres://verity:verity@localhost:5433/verity
//! HARD-ERRORS (panics) when the env var is absent: `supersession_lifecycle`
//! gates the invalidate-don't-delete bi-temporal contract (a stale-leak vector)
//! and `recall_fails_closed` is a direct empty-principal fail-closed assertion —
//! a soundness gate that silently skips is worse than no gate.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

async fn test_adapter() -> (PostgresAdapter, TenantId, EpisodeId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the bi-temporal soundness tests (SPEC §2 \
         invalidate-don't-delete + fail-closed recall); refusing to silently no-op",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    // Unique tenant per run keeps tests independent of prior state.
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
        entity_id: "deal-42".into(),
        field: "amount".into(),
    }
}

/// A scope admitting the facts these tests seed (visibility `[1]`), unbounded
/// entity scope, up to Restricted. Fact reads now take a Scope pre-filter.
fn read_scope(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    }
}

#[tokio::test]
async fn supersession_lifecycle() {
    let (adapter, tenant, episode) = test_adapter().await;
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
    let (adapter, tenant, episode) = test_adapter().await;
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: "d1".into(),
            seq: 0,
            content: "acme corp renewal pricing discussion".into(),
            content_hash: "c1".into(),
            embedding: None,
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
        embedding: None,
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
