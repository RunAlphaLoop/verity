//! The console's Memories browser read (`browse_memories`, behind
//! `GET /v1/admin/memories`): chunks ∪ facts ∪ actions in one shape, with the
//! source / entity / kind / substring filters, the superseded toggle
//! (bi-temporal history, never deleted), per-source counts, tie-safe keyset
//! pagination, the full-content `id` lookup, and tenant isolation.
//! Requires VERITY_TEST_DSN; skips (passes trivially) when absent.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{MemoryBrowseFilter, MemoryBrowsePage, PostgresAdapter};

async fn connect() -> Option<PostgresAdapter> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    Some(adapter)
}

async fn episode(a: &PostgresAdapter, tenant: TenantId, source: &str) -> EpisodeId {
    a.append_episode(NewEpisode {
        tenant_id: tenant,
        source: source.into(),
        source_entity: None,
        kind: EpisodeKind::Observation,
        payload: json!({}),
        content_hash: format!("ep-{}", uuid::Uuid::now_v7()),
        trust_tier: TrustTier::Observation,
        writer_sub: None,
        writer_azp: None,
    })
    .await
    .expect("episode")
}

fn chunk(
    tenant: TenantId,
    ep: EpisodeId,
    source: &str,
    doc: &str,
    tags: &[&str],
    content: &str,
    at: chrono::DateTime<Utc>,
) -> ChunkWrite {
    ChunkWrite {
        tenant_id: tenant,
        source: source.into(),
        document_id: doc.into(),
        seq: 0,
        content: content.into(),
        content_hash: format!("h-{doc}-{at}"),
        embedding: None,
        visibility: vec![1, 2],
        entity_tags: tags.iter().map(|t| t.to_string()).collect(),
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Observation,
        valid_from: at,
        provenance: ep,
        acl_provenance: AclProvenance::AdminAssigned,
        derived_from: vec![],
    }
}

fn fact(
    tenant: TenantId,
    ep: EpisodeId,
    source: &str,
    entity: &str,
    field: &str,
    value: &str,
    at: chrono::DateTime<Utc>,
) -> FactWrite {
    FactWrite {
        tenant_id: tenant,
        key: FactKey {
            source: source.into(),
            entity_id: entity.into(),
            field: field.into(),
        },
        value: json!(value),
        valid_from: at,
        visibility: vec![1],
        confidentiality: Confidentiality::Internal,
        provenance: ep,
        acl_provenance: AclProvenance::Mirrored,
    }
}

async fn browse(a: &PostgresAdapter, tenant: TenantId, f: MemoryBrowseFilter) -> MemoryBrowsePage {
    a.browse_memories(tenant, &f).await.expect("browse")
}

fn default_filter() -> MemoryBrowseFilter {
    MemoryBrowseFilter {
        limit: 50,
        ..Default::default()
    }
}

fn source_count(page: &MemoryBrowsePage, source: &str) -> i64 {
    page.sources
        .iter()
        .find(|s| s.source == source)
        .map(|s| s.count)
        .unwrap_or(0)
}

/// Seed one tenant with two sources across all three kinds (plus a second
/// tenant that must never bleed through) and exercise every filter.
#[tokio::test]
async fn browse_filters_by_source_entity_kind_q_and_superseded_and_isolates_tenants() {
    let Some(a) = connect().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let tenant = a
        .create_tenant(&format!("mem-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let ep_hub = episode(&a, tenant, "hubspot").await;
    let ep_gd = episode(&a, tenant, "gdrive").await;
    let t0 = Utc::now() - Duration::hours(3);

    // Chunks: two sources. The gdrive one is >240 chars to prove the preview
    // cap + the full-content id lookup. Separate upserts so recorded_at
    // ordering between them is meaningful.
    let long_content = format!("globex onboarding notes {}", "x".repeat(400));
    a.upsert_chunks(vec![chunk(
        tenant,
        ep_hub,
        "hubspot",
        "d1",
        &["account:acme"],
        "pricing discussion with acme",
        t0,
    )])
    .await
    .unwrap();
    a.upsert_chunks(vec![chunk(
        tenant,
        ep_gd,
        "gdrive",
        "d2",
        &["account:globex"],
        &long_content,
        t0 + Duration::minutes(1),
    )])
    .await
    .unwrap();

    // Facts: one key superseded once (jane → mike), one key in the other source.
    assert_eq!(
        a.upsert_fact(fact(
            tenant, ep_hub, "hubspot", "acme-1", "owner", "jane", t0
        ))
        .await
        .unwrap(),
        FactUpsertOutcome::Inserted
    );
    assert_eq!(
        a.upsert_fact(fact(
            tenant,
            ep_hub,
            "hubspot",
            "acme-1",
            "owner",
            "mike",
            t0 + Duration::hours(1)
        ))
        .await
        .unwrap(),
        FactUpsertOutcome::Superseded
    );
    a.upsert_fact(fact(
        tenant,
        ep_gd,
        "gdrive",
        "globex-1",
        "domain",
        "globex.com",
        t0,
    ))
    .await
    .unwrap();

    // One action (record_action also indexes its summary as a source='agent'
    // Tier-2 chunk carrying the same entities — both rows are real store
    // content, so the browser shows both).
    assert!(a
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: "a1".into(),
            actor_sub: Some("user:jane".into()),
            actor_azp: Some("agent:quote-bot".into()),
            action_type: "quote.issued".into(),
            entities: vec!["account:acme".into()],
            summary: "issued quote for acme".into(),
            payload: json!({}),
            outcome: ActionOutcome::Succeeded,
            occurred_at: t0 + Duration::minutes(2),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .unwrap());

    // A second tenant whose rows must never appear in the first's browse.
    let other = a
        .create_tenant(&format!("mem-iso-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    let other_ep = episode(&a, other, "hubspot").await;
    a.upsert_chunks(vec![chunk(
        other,
        other_ep,
        "hubspot",
        "d9",
        &["account:other"],
        "other tenant secret",
        t0,
    )])
    .await
    .unwrap();

    // ---- default browse: live rows only, all kinds, newest-recorded first ----
    let page = browse(&a, tenant, default_filter()).await;
    // 3 chunks (d1, d2, the action's agent chunk) + 2 live facts + 1 action.
    assert_eq!(page.rows.len(), 6, "live rows across all three kinds");
    assert!(page.next_before.is_none(), "one page holds everything");
    assert!(
        !page
            .rows
            .iter()
            .any(|r| r.preview.contains("other tenant secret")),
        "tenant isolation: another tenant's rows never appear"
    );
    assert!(
        page.rows
            .windows(2)
            .all(|w| w[0].recorded_at >= w[1].recorded_at),
        "newest-recorded first"
    );
    assert!(
        !page.rows.iter().any(|r| r.preview.contains("jane")),
        "the superseded value is hidden by default"
    );
    // Per-source counts mirror the same rows.
    assert_eq!(source_count(&page, "hubspot"), 2, "chunk d1 + fact owner");
    assert_eq!(source_count(&page, "gdrive"), 2, "chunk d2 + fact domain");
    assert_eq!(source_count(&page, "agent"), 2, "action + its Tier-2 chunk");
    // Per-kind shape honesty.
    let chunk_row = page
        .rows
        .iter()
        .find(|r| r.kind == "chunk" && r.document_id.as_deref() == Some("d1"))
        .expect("chunk d1");
    assert_eq!(chunk_row.visible_to, Some(2), "token COUNT, not the tokens");
    assert_eq!(chunk_row.confidentiality, Some(1));
    assert_eq!(chunk_row.acl_provenance.as_deref(), Some("admin-assigned"));
    assert_eq!(chunk_row.trust_tier, Some(2));
    assert_eq!(chunk_row.provenance, ep_hub, "citation → the L0 episode");
    let fact_row = page
        .rows
        .iter()
        .find(|r| r.kind == "fact" && r.field.as_deref() == Some("owner"))
        .expect("owner fact");
    assert_eq!(fact_row.entity_id.as_deref(), Some("acme-1"));
    assert_eq!(
        fact_row.entities,
        vec!["hubspot:acme-1".to_string()],
        "facts carry their synthetic source:entity_id tag"
    );
    assert_eq!(fact_row.visible_to, None, "L1 has no per-row tokens");
    assert_eq!(fact_row.acl_provenance.as_deref(), Some("mirrored"));
    let action_row = page
        .rows
        .iter()
        .find(|r| r.kind == "action")
        .expect("action row");
    assert_eq!(action_row.source, "agent");
    assert_eq!(action_row.action_type.as_deref(), Some("quote.issued"));
    assert_eq!(action_row.outcome.as_deref(), Some("succeeded"));
    assert_eq!(action_row.entities, vec!["account:acme".to_string()]);

    // ---- source filter ----
    let hub = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            source: Some("hubspot".into()),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(hub.rows.len(), 2);
    assert!(hub.rows.iter().all(|r| r.source == "hubspot"));
    // The dropdown counts ignore the source filter itself: every reachable
    // source stays listed.
    assert_eq!(source_count(&hub, "gdrive"), 2);

    // ---- entity filter (containment across all three kinds) ----
    let acme = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            entity: Some("account:acme".into()),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(
        acme.rows.len(),
        3,
        "chunk d1 + the action + the action's tagged agent chunk"
    );
    assert!(acme
        .rows
        .iter()
        .all(|r| r.entities.contains(&"account:acme".to_string())));
    let fact_by_tag = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            entity: Some("hubspot:acme-1".into()),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(fact_by_tag.rows.len(), 1, "the fact via its synthetic tag");
    assert_eq!(fact_by_tag.rows[0].kind, "fact");

    // ---- kind filter (and the refused unknown kind) ----
    for (kind, expect) in [("chunk", 3), ("fact", 2), ("action", 1)] {
        let p = browse(
            &a,
            tenant,
            MemoryBrowseFilter {
                kind: Some(kind.into()),
                ..default_filter()
            },
        )
        .await;
        assert_eq!(p.rows.len(), expect, "kind={kind}");
        assert!(p.rows.iter().all(|r| r.kind == kind));
    }
    let bad = a
        .browse_memories(
            tenant,
            &MemoryBrowseFilter {
                kind: Some("episode".into()),
                ..default_filter()
            },
        )
        .await;
    assert!(
        matches!(bad, Err(StorageError::InvalidInput(_))),
        "unknown kind is refused, never silently unfiltered"
    );

    // ---- q: case-insensitive substring over content/value/summary ----
    let q = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            q: Some("GLOBEX".into()),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(
        q.rows.len(),
        2,
        "the gdrive chunk + the domain fact (ILIKE)"
    );
    assert_eq!(source_count(&q, "gdrive"), 2);
    assert_eq!(source_count(&q, "hubspot"), 0);
    let q2 = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            q: Some("issued quote".into()),
            ..default_filter()
        },
    )
    .await;
    assert!(
        q2.rows.iter().any(|r| r.kind == "action"),
        "q reaches action summaries too"
    );

    // ---- the superseded toggle: bi-temporal history, never deleted ----
    let hist = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            kind: Some("fact".into()),
            entity: Some("hubspot:acme-1".into()),
            include_superseded: true,
            ..default_filter()
        },
    )
    .await;
    assert_eq!(hist.rows.len(), 2, "current + replaced value");
    let old = hist
        .rows
        .iter()
        .find(|r| r.preview.contains("jane"))
        .expect("the replaced value is browsable");
    let cur = hist
        .rows
        .iter()
        .find(|r| r.preview.contains("mike"))
        .expect("current value");
    assert!(old.valid_to.is_some(), "old row is closed, not deleted");
    assert_eq!(old.superseded_by, Some(cur.id), "the chain links old → new");
    assert!(cur.valid_to.is_none() && cur.superseded_by.is_none());

    // ---- preview cap + the full-content id lookup ----
    let capped = page
        .rows
        .iter()
        .find(|r| r.document_id.as_deref() == Some("d2"))
        .expect("long chunk");
    assert_eq!(capped.preview.chars().count(), 240);
    assert!(capped.preview_truncated);
    let full = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            id: Some(capped.id),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(full.rows.len(), 1);
    assert_eq!(
        full.rows[0].preview, long_content,
        "id lookup is untruncated"
    );
    assert!(!full.rows[0].preview_truncated);
    // A replaced row stays inspectable by id even without the toggle.
    let old_by_id = browse(
        &a,
        tenant,
        MemoryBrowseFilter {
            id: Some(old.id),
            ..default_filter()
        },
    )
    .await;
    assert_eq!(old_by_id.rows.len(), 1);
    assert!(old_by_id.rows[0].valid_to.is_some());
    // Cross-tenant id lookup discloses nothing.
    let cross = browse(
        &a,
        other,
        MemoryBrowseFilter {
            id: Some(capped.id),
            ..default_filter()
        },
    )
    .await;
    assert!(cross.rows.is_empty(), "an id read never crosses tenants");

    // ---- tie-safe keyset pagination walks every row exactly once ----
    let mut seen: Vec<uuid::Uuid> = Vec::new();
    let mut cursor: (Option<chrono::DateTime<Utc>>, Option<uuid::Uuid>) = (None, None);
    for _ in 0..10 {
        let p = browse(
            &a,
            tenant,
            MemoryBrowseFilter {
                limit: 2,
                before: cursor.0,
                before_id: cursor.1,
                ..MemoryBrowseFilter::default()
            },
        )
        .await;
        seen.extend(p.rows.iter().map(|r| r.id));
        if p.next_before.is_none() {
            break;
        }
        cursor = (p.next_before, p.next_before_id);
    }
    let mut expected: Vec<uuid::Uuid> = page.rows.iter().map(|r| r.id).collect();
    expected.sort();
    let mut got = seen.clone();
    got.sort();
    got.dedup();
    assert_eq!(got.len(), seen.len(), "pagination never repeats a row");
    assert_eq!(got, expected, "pagination reaches every row exactly once");
}
