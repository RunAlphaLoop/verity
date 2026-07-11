//! Cross-source entity resolution & per-field precedence (SPEC §7f, task 50):
//! when HubSpot and Salesforce both hold the same account, `merged_record`
//! resolves ONE view with deterministic per-field source precedence, and the
//! losing source(s) surface in `superseded_alternatives`. L1 rows are never
//! merged or mutated — this is a view-time projection.
//! Requires VERITY_TEST_DSN; skips (passes trivially) when absent.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
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

/// Write one current L1 fact for (source, entity_id, field)=value, event-time
/// `valid_from`. Each carries its own L0 episode as provenance.
async fn fact(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    source: &str,
    entity_id: &str,
    field: &str,
    value: serde_json::Value,
    valid_from: chrono::DateTime<Utc>,
) -> EpisodeId {
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(entity_id.into()),
            kind: EpisodeKind::CdcEvent,
            payload: json!({ "field": field, "value": value }),
            content_hash: format!("h-{source}-{entity_id}-{field}-{value}"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: source.into(),
                entity_id: entity_id.into(),
                field: field.into(),
            },
            value,
            valid_from,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();
    episode
}

/// Two sources with a current fact for the same field on aliased entities →
/// `merged_record` picks the precedence-winning source; the other appears in
/// `superseded_alternatives`.
#[tokio::test]
async fn two_sources_precedence_winner_and_alternative() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    fact(&a, t, "hubspot", "hs-1", "name", json!("Acme (HS)"), now).await;
    fact(&a, t, "salesforce", "sf-1", "name", json!("Acme (SF)"), now).await;

    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();
    // salesforce wins `name`.
    a.set_entity_precedence(
        t,
        "account:acme",
        "name",
        &["salesforce".into(), "hubspot".into()],
    )
    .await
    .unwrap();

    let merged = a.merged_record(t, "account:acme").await.unwrap();
    assert_eq!(merged.members.len(), 2);
    let name = &merged.fields["name"];
    assert_eq!(name.winning_source, "salesforce");
    assert_eq!(name.value, json!("Acme (SF)"));
    assert_eq!(name.superseded_alternatives.len(), 1);
    assert_eq!(name.superseded_alternatives[0].source, "hubspot");
    assert_eq!(name.superseded_alternatives[0].value, json!("Acme (HS)"));
}

/// Per-field precedence resolves each field independently: amount from
/// salesforce, name from hubspot.
#[tokio::test]
async fn per_field_precedence_independent() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    fact(&a, t, "hubspot", "hs-1", "name", json!("Acme HS"), now).await;
    fact(&a, t, "salesforce", "sf-1", "name", json!("Acme SF"), now).await;
    fact(&a, t, "hubspot", "hs-1", "amount", json!(100), now).await;
    fact(&a, t, "salesforce", "sf-1", "amount", json!(200), now).await;

    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();
    a.set_entity_precedence(
        t,
        "account:acme",
        "name",
        &["hubspot".into(), "salesforce".into()],
    )
    .await
    .unwrap();
    a.set_entity_precedence(
        t,
        "account:acme",
        "amount",
        &["salesforce".into(), "hubspot".into()],
    )
    .await
    .unwrap();

    let merged = a.merged_record(t, "account:acme").await.unwrap();
    assert_eq!(merged.fields["name"].winning_source, "hubspot");
    assert_eq!(merged.fields["name"].value, json!("Acme HS"));
    assert_eq!(merged.fields["amount"].winning_source, "salesforce");
    assert_eq!(merged.fields["amount"].value, json!(200));
}

/// Changing precedence flips the winner deterministically — same facts, new
/// config, different merged view (SPEC §7f: "changing the config just rebuilds
/// L3").
#[tokio::test]
async fn precedence_change_flips_winner() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    fact(&a, t, "hubspot", "hs-1", "phone", json!("111"), now).await;
    fact(&a, t, "salesforce", "sf-1", "phone", json!("222"), now).await;
    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();

    a.set_entity_precedence(
        t,
        "account:acme",
        "phone",
        &["hubspot".into(), "salesforce".into()],
    )
    .await
    .unwrap();
    let m1 = a.merged_record(t, "account:acme").await.unwrap();
    assert_eq!(m1.fields["phone"].winning_source, "hubspot");
    assert_eq!(m1.fields["phone"].value, json!("111"));

    // Flip it.
    a.set_entity_precedence(
        t,
        "account:acme",
        "phone",
        &["salesforce".into(), "hubspot".into()],
    )
    .await
    .unwrap();
    let m2 = a.merged_record(t, "account:acme").await.unwrap();
    assert_eq!(m2.fields["phone"].winning_source, "salesforce");
    assert_eq!(m2.fields["phone"].value, json!("222"));
}

/// An unmapped entity (no alias) → `merged_record` over its own single
/// (source, entity_id) returns just that source's facts.
#[tokio::test]
async fn unmapped_entity_returns_own_facts() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    // No alias written; the canonical key IS the source-native entity_id.
    fact(&a, t, "hubspot", "solo-1", "name", json!("Solo Co"), now).await;
    fact(&a, t, "hubspot", "solo-1", "amount", json!(42), now).await;

    let merged = a.merged_record(t, "solo-1").await.unwrap();
    assert!(merged.members.is_empty(), "unmapped: no alias members");
    assert_eq!(merged.fields["name"].winning_source, "hubspot");
    assert_eq!(merged.fields["name"].value, json!("Solo Co"));
    assert!(merged.fields["name"].superseded_alternatives.is_empty());
    assert_eq!(merged.fields["amount"].value, json!(42));

    // resolve_canonical returns None for an unmapped pair.
    assert_eq!(
        a.resolve_canonical(t, "hubspot", "solo-1").await.unwrap(),
        None
    );
}

/// A field present in only one source → that source wins regardless of
/// precedence (even when the precedence order lists another source first).
#[tokio::test]
async fn field_in_one_source_wins_regardless() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    // `website` exists only in hubspot; precedence prefers salesforce.
    fact(&a, t, "hubspot", "hs-1", "website", json!("acme.com"), now).await;
    fact(&a, t, "salesforce", "sf-1", "name", json!("Acme"), now).await;
    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();
    a.set_entity_precedence(
        t,
        "account:acme",
        "*",
        &["salesforce".into(), "hubspot".into()],
    )
    .await
    .unwrap();

    let merged = a.merged_record(t, "account:acme").await.unwrap();
    let website = &merged.fields["website"];
    assert_eq!(website.winning_source, "hubspot");
    assert_eq!(website.value, json!("acme.com"));
    assert!(website.superseded_alternatives.is_empty());
}

/// Precedence resolution is most-specific-wins: (canonical,'*') entity default
/// applies when there is no (canonical, field) row, and a source absent from
/// the order ranks last (tie broken by most-recent valid_from).
#[tokio::test]
async fn entity_default_and_unlisted_source_ranking() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    let older = now - Duration::hours(2);
    // Three sources; precedence only names hubspot. salesforce & other are
    // unlisted → tie last, broken by most-recent valid_from.
    fact(&a, t, "hubspot", "hs-1", "name", json!("HS"), now).await;
    fact(&a, t, "salesforce", "sf-1", "name", json!("SF-recent"), now).await;
    fact(&a, t, "other", "o-1", "name", json!("OT-old"), older).await;
    for (s, e) in [
        ("hubspot", "hs-1"),
        ("salesforce", "sf-1"),
        ("other", "o-1"),
    ] {
        a.upsert_entity_alias(t, s, e, "account:acme")
            .await
            .unwrap();
    }
    // Entity-level default (field '*'): only hubspot listed.
    a.set_entity_precedence(t, "account:acme", "*", &["hubspot".into()])
        .await
        .unwrap();

    let merged = a.merged_record(t, "account:acme").await.unwrap();
    let name = &merged.fields["name"];
    assert_eq!(name.winning_source, "hubspot", "listed source wins");
    // Alternatives are ranked: the more-recent unlisted source (salesforce)
    // ranks ahead of the older unlisted source (other).
    assert_eq!(name.superseded_alternatives.len(), 2);
    assert_eq!(name.superseded_alternatives[0].source, "salesforce");
    assert_eq!(name.superseded_alternatives[1].source, "other");
}

/// Global ('*','*') default applies when neither a (canonical, field) nor a
/// (canonical,'*') row exists.
#[tokio::test]
async fn global_default_precedence() {
    let Some((a, t)) = setup().await else {
        return;
    };
    let now = Utc::now();
    fact(&a, t, "hubspot", "hs-1", "name", json!("HS"), now).await;
    fact(&a, t, "salesforce", "sf-1", "name", json!("SF"), now).await;
    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();
    // Only the global default, no entity/field-specific row.
    a.set_entity_precedence(t, "*", "*", &["salesforce".into(), "hubspot".into()])
        .await
        .unwrap();

    let merged = a.merged_record(t, "account:acme").await.unwrap();
    assert_eq!(merged.fields["name"].winning_source, "salesforce");
}

/// list_entity_aliases + resolve_canonical round-trip.
#[tokio::test]
async fn alias_listing_and_reverse_lookup() {
    let Some((a, t)) = setup().await else {
        return;
    };
    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:acme")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "sf-1", "account:acme")
        .await
        .unwrap();

    let members = a.list_entity_aliases(t, "account:acme").await.unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&AliasMember {
        source: "hubspot".into(),
        entity_id: "hs-1".into()
    }));

    assert_eq!(
        a.resolve_canonical(t, "salesforce", "sf-1").await.unwrap(),
        Some("account:acme".into())
    );

    // Repointing a member updates the canonical (idempotent upsert).
    a.upsert_entity_alias(t, "hubspot", "hs-1", "account:other")
        .await
        .unwrap();
    assert_eq!(
        a.resolve_canonical(t, "hubspot", "hs-1").await.unwrap(),
        Some("account:other".into())
    );
    assert_eq!(
        a.list_entity_aliases(t, "account:acme")
            .await
            .unwrap()
            .len(),
        1
    );
}
