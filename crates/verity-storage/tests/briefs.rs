//! L3 materialized briefs (SPEC §2 L3): staleness lifecycle, derived-scope
//! inheritance (source_visibility = intersection of contributing sources), and
//! the scope-soundness guarantee that a materialized brief never leaks an item
//! the caller's scope excludes. Requires VERITY_TEST_DSN; skips when absent.

use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

async fn setup() -> Option<(PostgresAdapter, TenantId, EpisodeId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("brief-{}", uuid::Uuid::now_v7()))
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
    entity: &str,
    visibility: Vec<i32>,
) -> ChunkWrite {
    ChunkWrite {
        tenant_id: tenant,
        source: "test".into(),
        document_id: doc.into(),
        seq: 0,
        content: format!("memory for {entity} via {doc}"),
        content_hash: format!("h-{doc}"),
        embedding: None,
        visibility,
        entity_tags: vec![entity.into()],
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Observation,
        valid_from: Utc::now(),
        provenance: ep,
        acl_provenance: AclProvenance::AdminAssigned,
        derived_from: vec![],
    }
}

/// write → is_stale true → refresh → is_stale false; a subsequent write flips
/// it stale again and bumps source_version.
#[tokio::test]
async fn staleness_lifecycle() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let entity = "account:acme";

    // First read materializes lazily via refresh_brief (server does this on
    // GET). Simulate: refresh, expect not stale.
    let b = a.refresh_brief(tenant, entity).await.unwrap();
    assert!(!b.is_stale, "freshly refreshed brief is not stale");
    assert!(b.last_synced_at.is_some());
    let v0 = b.source_version;

    // A new chunk for the entity marks the brief stale synchronously.
    a.upsert_chunks(vec![chunk(tenant, ep, "d1", entity, vec![1, 2])])
        .await
        .unwrap();
    let b = a.get_brief(tenant, entity).await.unwrap().unwrap();
    assert!(b.is_stale, "write to the entity marks its brief stale");
    assert!(b.source_version > v0, "stale-marking bumps source_version");

    // Refresh clears staleness and picks up the new memory.
    let b = a.refresh_brief(tenant, entity).await.unwrap();
    assert!(!b.is_stale);
    assert_eq!(b.body["memory_count"].as_i64().unwrap(), 1);

    // An action for the entity also marks it stale.
    a.record_action(ActionWrite {
        tenant_id: tenant,
        action_id: "act-1".into(),
        actor_sub: None,
        actor_azp: Some("agent:x".into()),
        action_type: "email.sent".into(),
        entities: vec![entity.into()],
        summary: "sent".into(),
        payload: json!({}),
        outcome: ActionOutcome::Succeeded,
        occurred_at: Utc::now(),
        visibility: vec![1, 2],
        confidentiality: Confidentiality::Internal,
    })
    .await
    .unwrap();
    let b = a.get_brief(tenant, entity).await.unwrap().unwrap();
    assert!(b.is_stale, "action write marks the brief stale");

    // Batch refresh (the sleep-time path) clears all stale briefs.
    let refreshed = a.refresh_stale_briefs(tenant).await.unwrap();
    assert!(refreshed >= 1);
    let b = a.get_brief(tenant, entity).await.unwrap().unwrap();
    assert!(!b.is_stale);
    assert_eq!(b.body["activity_count"].as_i64().unwrap(), 1);
}

/// source_visibility = INTERSECTION of contributing source visibilities. A
/// principal present in only SOME sources is NOT in the brief-level visibility.
#[tokio::test]
async fn derived_scope_inheritance_is_intersection() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let entity = "account:globex";
    // Source A visible to {1,2}; source B visible to {2,3}. Intersection = {2}.
    a.upsert_chunks(vec![
        chunk(tenant, ep, "gx-a", entity, vec![1, 2]),
        chunk(tenant, ep, "gx-b", entity, vec![2, 3]),
    ])
    .await
    .unwrap();
    let b = a.refresh_brief(tenant, entity).await.unwrap();
    assert_eq!(
        b.source_visibility,
        vec![2],
        "brief visibility is the intersection of its sources"
    );
    assert!(
        !b.source_visibility.contains(&1) && !b.source_visibility.contains(&3),
        "a principal in only one source is not in the brief-level visibility"
    );
}

/// Disjoint sources => empty intersection => brief-level summary visible to
/// nobody (fail-closed).
#[tokio::test]
async fn disjoint_sources_yield_empty_visibility() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let entity = "account:initech";
    a.upsert_chunks(vec![
        chunk(tenant, ep, "in-a", entity, vec![1]),
        chunk(tenant, ep, "in-b", entity, vec![2]),
    ])
    .await
    .unwrap();
    let b = a.refresh_brief(tenant, entity).await.unwrap();
    assert!(
        b.source_visibility.is_empty(),
        "disjoint sources => no principal in ALL => fail-closed empty visibility"
    );
}

/// The materialized brief's cached body is broad (materialization scope), but
/// the storage-level served item paths (latest_chunks) still enforce the
/// caller's scope — so a narrow-scope caller never sees a broad-scope item.
#[tokio::test]
async fn served_items_stay_caller_scoped() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let entity = "account:umbrella";
    // Two memories: one visible to {1}, one visible to {9}.
    a.upsert_chunks(vec![
        chunk(tenant, ep, "um-1", entity, vec![1]),
        chunk(tenant, ep, "um-9", entity, vec![9]),
    ])
    .await
    .unwrap();
    // Materialize under the broad path: body sees both.
    let b = a.refresh_brief(tenant, entity).await.unwrap();
    assert_eq!(b.body["memory_count"].as_i64().unwrap(), 2);

    // A caller scoped to principal {1} serving items via latest_chunks (the
    // exact path the brief handler uses) must see ONLY the {1}-visible memory.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    };
    let hits = a.latest_chunks(&scope, entity, 10).await.unwrap();
    assert_eq!(hits.len(), 1, "caller sees only its own scope's item");
    assert_eq!(hits[0].document_id, "um-1");
    // The {9}-only memory materialized into the broad body must never reach a
    // {1}-scoped caller through the served items.
    assert!(hits.iter().all(|h| h.document_id != "um-9"));
}
