//! Knowledge-layer lifecycle (SPEC v1.3 §2, §7g): de-identification gate,
//! k-support + corroboration promotion checks, and the entity-bound-scope
//! carve-out. Requires VERITY_TEST_DSN; skips when absent.

use chrono::Utc;
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

/// One scoped interaction: an episode attributed to `entity`/`writer`, plus a
/// chunk carrying the entity tag (which also feeds the gate lexicon).
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
            content: format!("scoped interaction detail for {entity}"),
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

fn proposal(tenant: TenantId, statement: &str, evidence: Vec<EpisodeId>) -> KnowledgeProposal {
    KnowledgeProposal {
        tenant_id: tenant,
        statement: statement.into(),
        categories: vec!["industry:healthcare".into(), "objection:dpa".into()],
        evidence,
        proposed_by_sub: Some("user:test".into()),
        proposed_by_azp: Some("agent:proposer".into()),
    }
}

#[tokio::test]
async fn gate_k_support_and_carveout() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    // Three interactions: distinct entities, two distinct writers.
    let e1 = interaction(&adapter, tenant, "account:medcore", "agent:sales").await;
    let e2 = interaction(&adapter, tenant, "account:healthfirst", "agent:sales").await;
    let e3 = interaction(&adapter, tenant, "account:vitalgroup", "agent:support").await;

    // 1) A statement naming a known entity is quarantined by the gate.
    let leaky = adapter
        .propose_knowledge(proposal(
            tenant,
            "Medcore-style healthcare customers always demand DPA redlines.",
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();
    assert_eq!(leaky.status, KnowledgeStatus::Quarantined);
    assert!(leaky
        .quarantine_reason
        .as_deref()
        .unwrap()
        .contains("medcore"));

    // 2) A clean generalization becomes a candidate with computed support.
    let clean = adapter
        .propose_knowledge(proposal(
            tenant,
            "Healthcare-segment buyers consistently require DPA redlines before security review.",
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();
    assert_eq!(clean.status, KnowledgeStatus::Candidate);
    assert_eq!(clean.distinct_entities, 3);
    assert_eq!(clean.writer_count, 2);

    // 3) k-support is enforced: two entities cannot publish at k_min=3.
    let thin = adapter
        .propose_knowledge(proposal(
            tenant,
            "Buyers in this segment push hard on renewal pricing terms.",
            vec![e1, e2],
        ))
        .await
        .unwrap();
    assert_eq!(thin.status, KnowledgeStatus::Candidate);
    let err = adapter
        .publish_knowledge(tenant, thin.id, vec![7], 3, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("k-support unmet"), "{err}");

    // 4) The clean candidate publishes...
    let published = adapter
        .publish_knowledge(tenant, clean.id, vec![7], 3, None)
        .await
        .unwrap();
    assert_eq!(published.status, KnowledgeStatus::Published);
    // ...and republish is refused.
    assert!(adapter
        .publish_knowledge(tenant, clean.id, vec![7], 3, None)
        .await
        .is_err());

    // 5) The §7g carve-out: an entity-bound scope for ONE customer retrieves
    // its own scoped memory AND the published knowledge — never the other
    // customers' interactions, never the quarantined item.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:medcore".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope: scope.clone(),
            embedding: None,
            text: Some("DPA redlines healthcare".into()),
            k: 20,
        })
        .await
        .unwrap();
    assert!(
        hits.iter()
            .any(|h| h.kind == "knowledge" && h.content.contains("Healthcare-segment")),
        "published knowledge must surface in an entity-bound scope"
    );
    for hit in &hits {
        assert!(
            hit.kind == "knowledge" || hit.entity_tags.contains(&"account:medcore".to_string()),
            "cross-entity leak through the carve-out: {} ({:?})",
            hit.content,
            hit.entity_tags
        );
        assert!(
            !hit.content.contains("Medcore-style"),
            "quarantined statement leaked into recall"
        );
    }

    // 6) Wrong-principal scopes see no knowledge either — the carve-out
    // bypasses entity binding only, never visibility.
    let mut stranger = scope.clone();
    stranger.principals = vec![9];
    let hits = adapter
        .recall(RecallQuery {
            scope: stranger,
            embedding: None,
            text: Some("DPA redlines healthcare".into()),
            k: 20,
        })
        .await
        .unwrap();
    assert!(hits.is_empty());
}
