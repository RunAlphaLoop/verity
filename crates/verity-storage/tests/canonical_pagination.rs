//! Tier-3 canonical pagination (SPEC §7d precondition (a)): the fold must see
//! EVERY folded canonical, not a display-capped page. `all_canonical_keys` is
//! the uncapped, internally-paged DISTINCT projection the resolver uses;
//! `list_canonical_entities` stays a capped browser read. With >1000 canonicals
//! the old capped list under-reports and the uncapped read must not.
//! Requires VERITY_TEST_DSN; skips (passes trivially) when absent.

use verity_core::adapter::StorageAdapter;
use verity_core::types::TenantId;
use verity_storage::PostgresAdapter;

async fn setup() -> Option<(PostgresAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

/// DSN-only: with 1,500 distinct canonicals (each with a multi-member alias
/// set, so DISTINCT is doing real work), `all_canonical_keys` returns every
/// key exactly once, in stable sorted order — strictly more than the 1000-row
/// display cap the fold used to inherit.
#[tokio::test]
async fn all_canonical_keys_returns_every_canonical_past_the_display_cap() {
    let Some((adapter, tenant)) = setup().await else {
        return;
    };
    const N: i64 = 1_500;
    // Bulk-seed via generate_series: every canonical has a primary member, and
    // every third one a second member from another source (same canonical —
    // duplicates the DISTINCT projection must collapse).
    sqlx::query(
        "INSERT INTO entity_aliases (tenant_id, source, entity_id, canonical_entity)
         SELECT $1, 'hubspot', 'hs-' || g, 'canon-' || lpad(g::text, 6, '0')
           FROM generate_series(1, $2) g",
    )
    .bind(tenant)
    .bind(N)
    .execute(adapter.pool())
    .await
    .expect("seed primary members");
    sqlx::query(
        "INSERT INTO entity_aliases (tenant_id, source, entity_id, canonical_entity)
         SELECT $1, 'salesforce', 'sf-' || g, 'canon-' || lpad(g::text, 6, '0')
           FROM generate_series(1, $2) g
          WHERE g % 3 = 0",
    )
    .bind(tenant)
    .bind(N)
    .execute(adapter.pool())
    .await
    .expect("seed secondary members");

    let keys = adapter
        .all_canonical_keys(tenant)
        .await
        .expect("all_canonical_keys");

    assert_eq!(
        keys.len(),
        N as usize,
        "every distinct canonical must be returned exactly once (no 1000 cap, no dupes)"
    );
    // Complete, deduplicated, and in stable sorted order.
    let mut expected: Vec<String> = (1..=N).map(|g| format!("canon-{g:06}")).collect();
    expected.sort();
    assert_eq!(keys, expected, "stable sorted order, nothing missing");

    // Contrast: the capped browser read at limit 1000 stays capped — the fold
    // must never be built on it.
    let capped = adapter
        .list_canonical_entities(tenant, 1000)
        .await
        .expect("list_canonical_entities");
    assert!(
        capped.len() <= 1000,
        "browser read is display-capped by design"
    );
    assert!(
        keys.len() > capped.len(),
        "the uncapped read must see canonicals the capped browser read cannot"
    );
}

/// DSN-only: tenant isolation — another tenant's canonicals never leak into
/// the fold's key set, and an empty tenant folds over an empty set (fail
/// closed, not an error).
#[tokio::test]
async fn all_canonical_keys_is_tenant_scoped_and_empty_safe() {
    let Some((adapter, tenant_a)) = setup().await else {
        return;
    };
    let tenant_b = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant b");
    adapter
        .upsert_entity_alias(tenant_a, "hubspot", "hs-1", "canon-a")
        .await
        .expect("alias");

    let a = adapter.all_canonical_keys(tenant_a).await.expect("a");
    let b = adapter.all_canonical_keys(tenant_b).await.expect("b");
    assert_eq!(a, vec!["canon-a".to_string()]);
    assert!(b.is_empty(), "empty tenant → empty key set, never a leak");
}
