//! The entity-tag directory behind the console's entity picker
//! (docs/design/ENTITY-PICKER.md §4): distinct tags from
//! `chunks.entity_tags ∪ actions.entities` with honest counts, the
//! enforcement-consistency invariant (directory counts equal what the scoped
//! reads actually match), live/total split for erasure, `q`/`limit`
//! semantics, observed namespaces, the merged badge, and tenant isolation.
//! Requires VERITY_TEST_DSN; skips (passes trivially) when absent.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{EntityTagRow, PostgresAdapter};

async fn setup() -> Option<(PostgresAdapter, TenantId, EpisodeId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("tags-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "test".into(),
            source_entity: None,
            kind: EpisodeKind::Observation,
            payload: json!({}),
            content_hash: format!("ep-{}", uuid::Uuid::now_v7()),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    Some((adapter, tenant, episode))
}

fn chunk(
    tenant: TenantId,
    ep: EpisodeId,
    doc: &str,
    tags: &[&str],
    at: chrono::DateTime<Utc>,
) -> ChunkWrite {
    ChunkWrite {
        tenant_id: tenant,
        source: "test".into(),
        document_id: doc.into(),
        seq: 0,
        content: format!("memory in {doc} tagged {tags:?}"),
        content_hash: format!("h-{doc}-{at}"),
        embedding: None,
        visibility: vec![1],
        entity_tags: tags.iter().map(|t| t.to_string()).collect(),
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Observation,
        valid_from: at,
        provenance: ep,
        acl_provenance: AclProvenance::AdminAssigned,
    }
}

fn action(
    tenant: TenantId,
    action_id: &str,
    entities: &[&str],
    at: chrono::DateTime<Utc>,
) -> ActionWrite {
    ActionWrite {
        tenant_id: tenant,
        action_id: action_id.into(),
        actor_sub: Some("user:jane".into()),
        actor_azp: Some("agent:test-bot".into()),
        action_type: "quote.issued".into(),
        entities: entities.iter().map(|e| e.to_string()).collect(),
        summary: format!("action {action_id}"),
        payload: json!({}),
        outcome: ActionOutcome::Succeeded,
        occurred_at: at,
        visibility: vec![1],
        confidentiality: Confidentiality::Internal,
    }
}

/// An unbounded scope wide enough to see everything the seeds wrote — used
/// for the enforcement-consistency cross-checks.
fn unbounded(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    }
}

fn row<'a>(dir: &'a verity_storage::EntityTagDirectory, tag: &str) -> &'a EntityTagRow {
    dir.tags
        .iter()
        .find(|t| t.tag == tag)
        .unwrap_or_else(|| panic!("directory is missing tag {tag}"))
}

#[tokio::test]
async fn directory_counts_are_honest_and_tenant_isolated() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let t0 = Utc::now() - Duration::hours(3);

    // Tenant seeds: tags spread across chunks AND actions, some overlapping.
    a.upsert_chunks(vec![
        chunk(tenant, ep, "d1", &["account:acme"], t0),
        chunk(
            tenant,
            ep,
            "d2",
            &["account:acme", "deal:renewal"],
            t0 + Duration::minutes(1),
        ),
        chunk(tenant, ep, "d3", &["user:jane"], t0 + Duration::minutes(2)),
    ])
    .await
    .unwrap();
    assert!(a
        .record_action(action(tenant, "a1", &["account:acme"], t0))
        .await
        .unwrap());
    assert!(a
        .record_action(action(
            tenant,
            "a2",
            &["deal:renewal"],
            t0 + Duration::minutes(1)
        ))
        .await
        .unwrap());

    // A second tenant with its own tag — must never bleed either way.
    let other = a
        .create_tenant(&format!("tags-iso-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    let other_ep = a
        .append_episode(NewEpisode {
            tenant_id: other,
            source: "test".into(),
            source_entity: None,
            kind: EpisodeKind::Observation,
            payload: json!({}),
            content_hash: format!("ep-{}", uuid::Uuid::now_v7()),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();
    a.upsert_chunks(vec![chunk(other, other_ep, "d9", &["account:other"], t0)])
        .await
        .unwrap();

    // Action summaries are also indexed as Tier-2 chunks carrying the action's
    // entities (record_action's contract), so chunk counts below include them.
    let dir = a.list_entity_tags(tenant, None, true, 100).await.unwrap();
    assert_eq!(
        dir.total_distinct, 3,
        "account:acme, deal:renewal, user:jane"
    );
    assert!(!dir.truncated);
    assert_eq!(dir.namespaces, vec!["account", "deal", "user"]);
    assert_eq!(
        dir.tags.first().map(|t| t.tag.as_str()),
        Some("account:acme"),
        "most-carried tag orders first"
    );

    // Enforcement-consistency invariant (§4): per-tag counts equal what the
    // scoped reads themselves match. `latest_chunks` scans live chunks with
    // the same containment the scope filter enforces; `activity` is the
    // `entities @>` predicate verbatim.
    let scope = unbounded(tenant);
    for tag in ["account:acme", "deal:renewal", "user:jane"] {
        let r = row(&dir, tag);
        let live = a.latest_chunks(&scope, tag, 100).await.unwrap().len() as i64;
        let acts = a
            .activity(ActivityQuery {
                scope: scope.clone(),
                entity: tag.into(),
                since: None,
                action_types: vec![],
                actors: vec![],
                limit: 100,
            })
            .await
            .unwrap()
            .len() as i64;
        assert_eq!(
            r.chunk_count, live,
            "chunk_count for {tag} = live rows a scoped read matches"
        );
        assert_eq!(
            r.action_count, acts,
            "action_count for {tag} = activity containment rows"
        );
        assert!(r.chunk_count > 0, "{tag} was seeded on at least one chunk");
        assert!(r.last_seen.is_some());
        assert_eq!(r.total_chunk_count, None, "live_only omits the total split");
    }
    assert_eq!(row(&dir, "account:acme").action_count, 1);
    assert_eq!(row(&dir, "deal:renewal").action_count, 1);
    assert_eq!(row(&dir, "user:jane").action_count, 0);

    // Tenant isolation, both directions.
    assert!(
        !dir.tags.iter().any(|t| t.tag == "account:other"),
        "another tenant's tag must not appear"
    );
    let other_dir = a.list_entity_tags(other, None, true, 100).await.unwrap();
    assert_eq!(other_dir.total_distinct, 1);
    assert_eq!(other_dir.tags[0].tag, "account:other");

    // q: substring filter narrows the page but must NOT fake emptiness.
    let filtered = a
        .list_entity_tags(tenant, Some("acme"), true, 100)
        .await
        .unwrap();
    assert_eq!(
        filtered
            .tags
            .iter()
            .map(|t| t.tag.as_str())
            .collect::<Vec<_>>(),
        vec!["account:acme"]
    );
    assert_eq!(filtered.total_distinct, 3, "total_distinct ignores q");
    assert!(!filtered.truncated);

    // limit: page caps and reports truncation; totals stay whole.
    let capped = a.list_entity_tags(tenant, None, true, 1).await.unwrap();
    assert_eq!(capped.tags.len(), 1);
    assert!(capped.truncated);
    assert_eq!(capped.total_distinct, 3);
}

#[tokio::test]
async fn live_only_false_surfaces_invalidated_rows_for_erasure() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let t0 = Utc::now() - Duration::hours(2);
    a.upsert_chunks(vec![chunk(tenant, ep, "d1", &["user:jane"], t0)])
        .await
        .unwrap();
    // Re-upserting the same (source, doc, seq) invalidates the old row
    // (valid_to set) — user:jane now lives ONLY on an invalidated row.
    a.upsert_chunks(vec![chunk(
        tenant,
        ep,
        "d1",
        &["user:john"],
        t0 + Duration::hours(1),
    )])
    .await
    .unwrap();

    // Live directory: the superseded tag is honestly gone (the scope filter
    // can no longer return any row carrying it).
    let live = a.list_entity_tags(tenant, None, true, 100).await.unwrap();
    assert_eq!(live.total_distinct, 1);
    assert!(!live.tags.iter().any(|t| t.tag == "user:jane"));
    assert_eq!(row(&live, "user:john").chunk_count, 1);

    // Erasure directory (live_only=false): the invalidated tag IS a target —
    // invalidate-don't-delete keeps the physical row until hard purge.
    let all = a.list_entity_tags(tenant, None, false, 100).await.unwrap();
    assert_eq!(all.total_distinct, 2);
    let jane = row(&all, "user:jane");
    assert_eq!(jane.chunk_count, 0, "no live row carries it");
    assert_eq!(jane.total_chunk_count, Some(1), "the invalidated row does");
    let john = row(&all, "user:john");
    assert_eq!(john.chunk_count, 1);
    assert_eq!(john.total_chunk_count, Some(1));
}

#[tokio::test]
async fn merged_badge_is_a_display_hint_and_empty_tenant_reports_zero() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Empty tenant first: the Emptiness Law's input must be an honest zero.
    let empty = a.list_entity_tags(tenant, None, true, 100).await.unwrap();
    assert_eq!(empty.total_distinct, 0);
    assert!(empty.tags.is_empty());
    assert!(empty.namespaces.is_empty());
    assert!(!empty.truncated);

    // A source-native tag with an alias row gets the merged badge; a
    // usage-born tag without one stays unbadged (the common case).
    let t0 = Utc::now() - Duration::hours(1);
    a.upsert_chunks(vec![
        chunk(tenant, ep, "d1", &["hubspot:hs-1"], t0),
        chunk(tenant, ep, "d2", &["account:acme"], t0),
    ])
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO entity_aliases (tenant_id, source, entity_id, canonical_entity)
         VALUES ($1, 'hubspot', 'hs-1', 'account:acme')",
    )
    .bind(tenant)
    .execute(a.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO entity_link_meta
             (tenant_id, subject_kind, subject_ref, canonical_entity, confidence)
         VALUES ($1, 'alias_member', 'hubspot:hs-1', 'account:acme', 'deterministic')",
    )
    .bind(tenant)
    .execute(a.pool())
    .await
    .unwrap();

    let dir = a.list_entity_tags(tenant, None, true, 100).await.unwrap();
    assert_eq!(dir.total_distinct, 2);
    let merged = row(&dir, "hubspot:hs-1");
    assert_eq!(merged.canonical_entity.as_deref(), Some("account:acme"));
    assert_eq!(merged.link_confidence.as_deref(), Some("deterministic"));
    assert_eq!(merged.chunk_count, 1, "the badge never inflates counts");
    let unmerged = row(&dir, "account:acme");
    assert_eq!(unmerged.canonical_entity, None);
    assert_eq!(unmerged.link_confidence, None);
}
