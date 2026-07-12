//! memory.forget + knowledge retraction cascade (roadmap task 5). Chunk
//! forget removes the chunk from recall; episode forget retires derived
//! chunks/facts and pulls published knowledge whose k-support drops below 3,
//! including its §7g carve-out chunk. Requires VERITY_TEST_DSN; skips when
//! absent.

use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

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

/// One scoped interaction: an episode attributed to `entity`/`writer`, plus a
/// chunk carrying the entity tag (same shape as the knowledge tests).
async fn interaction(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    entity: &str,
    writer: &str,
) -> EpisodeId {
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "test".into(),
            source_entity: Some(entity.into()),
            kind: EpisodeKind::Observation,
            payload: json!({}),
            content_hash: format!("i-{entity}-{writer}"),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: Some(writer.into()),
        })
        .await
        .unwrap();
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: format!("doc-{entity}-{writer}"),
            seq: 0,
            content: format!("churn signal renewal negotiation notes for {entity}"),
            content_hash: format!("c-{entity}-{writer}"),
            embedding: None,
            visibility: vec![7],
            entity_tags: vec![entity.into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .unwrap();
    episode
}

fn scope(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    }
}

async fn recall_text(
    adapter: &impl StorageAdapter,
    tenant: TenantId,
    text: &str,
) -> Vec<RecallHit> {
    adapter
        .recall(RecallQuery {
            scope: scope(tenant),
            embedding: None,
            text: Some(text.into()),
            k: 50,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn chunk_forget_disappears_from_recall() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    interaction(&adapter, tenant, "account:acme", "agent:sales").await;

    let hits = recall_text(&adapter, tenant, "churn renewal").await;
    let target = hits
        .iter()
        .find(|h| h.entity_tags.contains(&"account:acme".to_string()))
        .expect("chunk retrievable before forget");

    // Wrong-tenant forget retires nothing (tenant-checked).
    let stranger = adapter
        .create_tenant(&format!("t2-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    assert_eq!(
        adapter
            .forget(stranger, ForgetRef::Chunk(target.chunk_id), "gdpr")
            .await
            .unwrap(),
        0
    );

    let retired = adapter
        .forget(tenant, ForgetRef::Chunk(target.chunk_id), "gdpr request")
        .await
        .unwrap();
    assert_eq!(retired, 1);
    let hits = recall_text(&adapter, tenant, "churn renewal").await;
    assert!(
        !hits.iter().any(|h| h.chunk_id == target.chunk_id),
        "forgotten chunk still surfaces in recall"
    );
    // Idempotent replay retires nothing further.
    assert_eq!(
        adapter
            .forget(tenant, ForgetRef::Chunk(target.chunk_id), "again")
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn episode_forget_cascades_published_knowledge() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let adapter = CachedAdapter::new(adapter, 1024);

    // Exactly k=3 distinct entities support a published generalization.
    let e1 = interaction(adapter.inner(), tenant, "account:medcore", "agent:sales").await;
    let e2 = interaction(
        adapter.inner(),
        tenant,
        "account:healthfirst",
        "agent:sales",
    )
    .await;
    let e3 = interaction(
        adapter.inner(),
        tenant,
        "account:vitalgroup",
        "agent:support",
    )
    .await;

    let item = adapter
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: "Buyers in this segment escalate renewal pricing to procurement.".into(),
            categories: vec!["objection:pricing".into()],
            evidence: vec![e1, e2, e3],
            proposed_by_sub: None,
            proposed_by_azp: Some("agent:proposer".into()),
            canonical_statement: None,
        })
        .await
        .unwrap();
    assert_eq!(item.status, KnowledgeStatus::Candidate);
    let published = adapter
        .publish_knowledge(tenant, item.id, vec![7], 3, None)
        .await
        .unwrap();
    assert_eq!(published.status, KnowledgeStatus::Published);

    // The episode's fact is retired by the cascade too.
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: "test".into(),
                entity_id: "account:medcore".into(),
                field: "stage".into(),
            },
            value: json!("negotiation"),
            valid_from: Utc::now(),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
            provenance: e1,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();

    // Published knowledge surfaces via the §7g carve-out in an entity-bound
    // scope before the forget.
    let bound = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:healthfirst".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope: bound.clone(),
            embedding: None,
            text: Some("renewal pricing procurement".into()),
            k: 50,
        })
        .await
        .unwrap();
    assert!(
        hits.iter().any(|h| h.kind == "knowledge"),
        "published knowledge must surface before forget"
    );

    // Forget the medcore episode: support drops 3 → 2, below the k=3 floor.
    let retired = adapter
        .forget(tenant, ForgetRef::Episode(e1), "customer data deletion")
        .await
        .unwrap();
    // At least the episode's chunk and its fact were retired.
    assert!(retired >= 2, "expected chunk+fact retired, got {retired}");

    let key = FactKey {
        source: "test".into(),
        entity_id: "account:medcore".into(),
        field: "stage".into(),
    };
    // Scope admits the fact's visibility (`[1]`) and entity, so a None proves
    // the row was RETIRED by the cascade, not filtered out by scope.
    let read = Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    };
    assert!(
        adapter.current_fact(&read, &key).await.unwrap().is_none(),
        "episode-derived fact must be retired (and not cached)"
    );

    let items = adapter
        .list_knowledge(tenant, Some(KnowledgeStatus::Invalidated))
        .await
        .unwrap();
    let invalidated = items
        .iter()
        .find(|k| k.id == item.id)
        .expect("knowledge item invalidated when support dropped below 3");
    assert_eq!(invalidated.distinct_entities, 2);

    // The §7g carve-out chunk is retired with it.
    let hits = adapter
        .recall(RecallQuery {
            scope: bound,
            embedding: None,
            text: Some("renewal pricing procurement".into()),
            k: 50,
        })
        .await
        .unwrap();
    assert!(
        !hits
            .iter()
            .any(|h| h.kind == "knowledge" && h.content.contains("escalate renewal pricing")),
        "invalidated knowledge chunk still surfaces via the carve-out"
    );
}
