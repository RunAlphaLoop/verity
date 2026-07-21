//! `verity fsck` cross-store integrity scan (M3 sub-item). Requires
//! VERITY_TEST_DSN; the schema already FK/unique-enforces lineage, so fsck covers
//! the NON-enforceable invariants — this proves it actually catches them.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

async fn setup() -> (PostgresAdapter, sqlx::PgPool, TenantId, EpisodeId) {
    let dsn = std::env::var("VERITY_TEST_DSN")
        .expect("VERITY_TEST_DSN must be set for the fsck integrity test");
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let pool = sqlx::PgPool::connect(&dsn).await.expect("pool");
    let tenant = adapter
        .create_tenant(&format!("fsck-{}", uuid::Uuid::now_v7()))
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
    (adapter, pool, tenant, episode)
}

#[tokio::test]
async fn fsck_catches_out_of_range_confidentiality_and_bitemporal_inversion() {
    let (adapter, pool, tenant, episode) = setup().await;

    // A fresh tenant with no corrupt rows must pass (no error-severity findings).
    let clean = adapter.fsck(Some(tenant)).await.expect("fsck clean");
    assert!(clean.ok(), "empty tenant must be clean: {clean:?}");

    // Seed ONE chunk that is doubly corrupt: confidentiality=9 (outside [0,3]) and
    // valid_to BEFORE valid_from (bitemporal inversion) — both invariants the
    // schema cannot enforce.
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO chunks \
         (id, tenant_id, source, document_id, seq, content, content_hash, \
          visibility, confidentiality, trust_tier, valid_from, valid_to, provenance) \
         VALUES ($1, $2, 'test', 'doc-bad', 0, 'x', 'h', \
                 ARRAY[1]::int[], 9, 1, $3, $4, $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(tenant)
    .bind(now)
    .bind(now - Duration::hours(1))
    .bind(episode)
    .execute(&pool)
    .await
    .expect("insert corrupt chunk");

    let report = adapter.fsck(Some(tenant)).await.expect("fsck");
    assert!(!report.ok(), "a corrupt chunk must fail fsck: {report:?}");
    let errors: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == "error")
        .map(|f| f.check.as_str())
        .collect();
    assert!(
        errors.contains(&"confidentiality_out_of_range"),
        "must flag out-of-range confidentiality: {report:?}"
    );
    assert!(
        errors.contains(&"bitemporal_inverted_chunks"),
        "must flag bitemporal inversion: {report:?}"
    );
}
