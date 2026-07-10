//! memory.forget + knowledge retraction cascade against the Qdrant hybrid
//! profile: chunk forget must remove the chunk from BOTH legs (the Postgres
//! row is retired by the inner adapter, the Qdrant point is re-mirrored with
//! valid_to); episode forget retires derived chunks/facts and pulls published
//! knowledge below the k=3 floor, including its §7g carve-out chunk on both
//! legs. Adapted copy of `verity-storage/tests/forget.rs` (chunks get
//! embeddings so the dense leg is exercised). Requires VERITY_TEST_DSN +
//! VERITY_QDRANT_URL; skips when absent.

use chrono::Utc;
use rand::Rng;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::CachedAdapter;
use verity_storage_qdrant::QdrantAdapter;

async fn setup() -> Option<(QdrantAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let qurl = std::env::var("VERITY_QDRANT_URL").ok()?;
    let adapter = QdrantAdapter::connect(&dsn, &qurl).await.expect("connect");
    adapter.inner().migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("qtest-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

fn unit_vec() -> Vec<f32> {
    let mut rng = rand::rng();
    let v: Vec<f32> = (0..384).map(|_| rng.random_range(-1.0..1.0)).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.into_iter().map(|x| x / n).collect()
}

/// One scoped interaction: an episode attributed to `entity`/`writer`, plus a
/// chunk carrying the entity tag (same shape as the knowledge tests).
async fn interaction(
    adapter: &QdrantAdapter,
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
            embedding: Some(unit_vec()),
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

/// Hybrid recall (Qdrant dense + delegated BM25) so a leak on either leg is
/// caught.
async fn recall_hybrid(
    adapter: &impl StorageAdapter,
    tenant: TenantId,
    text: &str,
) -> Vec<RecallHit> {
    adapter
        .recall(RecallQuery {
            scope: scope(tenant),
            embedding: Some(unit_vec()),
            text: Some(text.into()),
            k: 50,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn chunk_forget_disappears_from_recall() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    interaction(&adapter, tenant, "account:acme", "agent:sales").await;

    let hits = recall_hybrid(&adapter, tenant, "churn renewal").await;
    let target = hits
        .iter()
        .find(|h| h.entity_tags.contains(&"account:acme".to_string()))
        .expect("chunk retrievable before forget");

    // Wrong-tenant forget retires nothing (tenant-checked).
    let stranger = adapter
        .create_tenant(&format!("qt2-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    assert_eq!(
        adapter
            .forget(stranger, ForgetRef::Chunk(target.chunk_id), "gdpr")
            .await
            .unwrap(),
        0
    );
    // The wrong-tenant attempt must not have touched the point either.
    assert!(recall_hybrid(&adapter, tenant, "churn renewal")
        .await
        .iter()
        .any(|h| h.chunk_id == target.chunk_id));

    let retired = adapter
        .forget(tenant, ForgetRef::Chunk(target.chunk_id), "gdpr request")
        .await
        .unwrap();
    assert_eq!(retired, 1);
    let hits = recall_hybrid(&adapter, tenant, "churn renewal").await;
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
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
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
        })
        .await
        .unwrap();
    assert_eq!(item.status, KnowledgeStatus::Candidate);
    let published = adapter
        .publish_knowledge(tenant, item.id, vec![7], 3, Some(unit_vec()))
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
            provenance: e1,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();

    // Published knowledge surfaces via the §7g carve-out in an entity-bound
    // scope before the forget — on both legs.
    let bound = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:healthfirst".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope: bound.clone(),
            embedding: Some(unit_vec()),
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
    assert!(
        adapter.current_fact(tenant, &key).await.unwrap().is_none(),
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

    // The §7g carve-out chunk is retired with it — checked on the hybrid path
    // (dense leg included), so a stale Qdrant point would fail here.
    let hits = adapter
        .recall(RecallQuery {
            scope: bound,
            embedding: Some(unit_vec()),
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
    // And the medcore interaction chunk is gone from the dense leg too.
    let hits = adapter
        .recall(RecallQuery {
            scope: scope(tenant),
            embedding: Some(unit_vec()),
            text: None,
            k: 50,
        })
        .await
        .unwrap();
    assert!(
        !hits
            .iter()
            .any(|h| h.document_id == "doc-account:medcore-agent:sales"),
        "episode-forgotten chunk still surfaces on the dense leg"
    );
}
