//! Cache coherence for the L1 current-truth projection: a cached read must
//! never serve a superseded value. Requires VERITY_TEST_DSN; skips when absent.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

#[tokio::test]
async fn cached_read_never_serves_superseded_value() {
    let Some(dsn) = std::env::var("VERITY_TEST_DSN").ok() else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let adapter = CachedAdapter::new(pg, 10_000);
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
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
        .unwrap();
    let key = FactKey {
        source: "hubspot".into(),
        entity_id: "deal-9".into(),
        field: "stage".into(),
    };
    let t0 = Utc::now() - Duration::minutes(10);
    let write = |value: serde_json::Value, at| FactWrite {
        tenant_id: tenant,
        key: key.clone(),
        value,
        valid_from: at,
        provenance: episode,
    };

    adapter
        .upsert_fact(write(json!("negotiation"), t0))
        .await
        .unwrap();
    // Populate the cache.
    let v1 = adapter.current_fact(tenant, &key).await.unwrap().unwrap();
    assert_eq!(v1.value, json!("negotiation"));
    // Cache hit returns the same row.
    assert_eq!(
        adapter
            .current_fact(tenant, &key)
            .await
            .unwrap()
            .unwrap()
            .id,
        v1.id
    );

    // Supersede through the SAME adapter: invalidation must evict the entry.
    adapter
        .upsert_fact(write(json!("closed_won"), t0 + Duration::minutes(5)))
        .await
        .unwrap();
    let v2 = adapter.current_fact(tenant, &key).await.unwrap().unwrap();
    assert_eq!(v2.value, json!("closed_won"));
    assert_ne!(v2.id, v1.id);
}
