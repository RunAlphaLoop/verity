//! Phase 3 acceptability surface (knowledge-merge-tuning.md §5): the storage
//! primitives behind the never-automatic promises — support-tier bucketing and
//! non-leakage of exact counts, publish-from-eligible, and rejection memory
//! (a rejected canonical form does not resurrect as a fresh candidate).
//! Requires VERITY_TEST_DSN; skips when absent.

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

/// A scoped interaction attributed to `entity`/`writer`, plus a tagged chunk
/// (which also feeds the de-id gate lexicon).
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
            derived_from: vec![],
        }])
        .await
        .unwrap();
    episode
}

fn proposal(
    tenant: TenantId,
    statement: &str,
    canonical: Option<&str>,
    evidence: Vec<EpisodeId>,
) -> KnowledgeProposal {
    KnowledgeProposal {
        tenant_id: tenant,
        statement: statement.into(),
        categories: vec!["industry:healthcare".into(), "objection:dpa".into()],
        evidence,
        proposed_by_sub: Some("user:test".into()),
        proposed_by_azp: Some("agent:proposer".into()),
        canonical_statement: canonical.map(str::to_string),
    }
}

/// SupportTier bucketing is deterministic and monotone; below k=3 there is no
/// tier to disclose (nothing that thin ever publishes).
#[test]
fn support_tier_buckets() {
    assert_eq!(SupportTier::from_distinct(0), None);
    assert_eq!(SupportTier::from_distinct(2), None);
    assert_eq!(SupportTier::from_distinct(3), Some(SupportTier::Emerging));
    assert_eq!(SupportTier::from_distinct(4), Some(SupportTier::Emerging));
    assert_eq!(
        SupportTier::from_distinct(5),
        Some(SupportTier::Established)
    );
    assert_eq!(
        SupportTier::from_distinct(9),
        Some(SupportTier::Established)
    );
    assert_eq!(SupportTier::from_distinct(10), Some(SupportTier::Extensive));
    assert_eq!(SupportTier::from_distinct(50), Some(SupportTier::Extensive));
}

/// A published item surfaces to an entity-bound scope carrying its BUCKETED
/// support tier — and the exact distinct-entity count is never on the recall
/// hit (SPEC §2 membership-inference: exact counts are admin-only).
#[tokio::test]
async fn recall_hit_carries_tier_not_exact_count() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Three distinct entities, two writers → emerging (3-4).
    let e1 = interaction(&adapter, tenant, "account:alpha", "agent:sales").await;
    let e2 = interaction(&adapter, tenant, "account:bravo", "agent:sales").await;
    let e3 = interaction(&adapter, tenant, "account:charlie", "agent:support").await;

    let cand = adapter
        .propose_knowledge(proposal(
            tenant,
            "Segment buyers consistently require DPA redlines before security review.",
            None,
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();
    assert_eq!(cand.status, KnowledgeStatus::Candidate);
    assert_eq!(cand.distinct_entities, 3);
    // The item struct exposes the bucket alongside the admin-exact count.
    assert_eq!(cand.support_tier, Some(SupportTier::Emerging));

    let published = adapter
        .publish_knowledge(tenant, cand.id, vec![7], 3, None)
        .await
        .unwrap();
    assert_eq!(published.status, KnowledgeStatus::Published);

    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:alpha".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope,
            embedding: None,
            text: Some("DPA redlines security review".into()),
            k: 20,
        })
        .await
        .unwrap();
    let knowledge_hit = hits
        .iter()
        .find(|h| h.kind == "knowledge")
        .expect("published knowledge must surface via the §7g carve-out");
    // The recall hit carries the BUCKET...
    assert_eq!(knowledge_hit.support_tier, Some(SupportTier::Emerging));
    // ...and the RecallHit type has no field that could carry the exact count.
    // The serialized hit must not contain the number 3 as a distinct-entity
    // disclosure — only the tier string.
    let serialized = serde_json::to_string(knowledge_hit).unwrap();
    assert!(
        serialized.contains("emerging"),
        "tier must be disclosed: {serialized}"
    );
    assert!(
        !serialized.contains("distinct_entities"),
        "exact distinct-entity count must NEVER appear on a recall hit: {serialized}"
    );
}

/// Publishing is allowed from `eligible` (the auto-publish-OFF waiting state),
/// not just `candidate`. The eligible transition itself is exercised, then the
/// human/policy publish call promotes it.
#[tokio::test]
async fn eligible_can_publish_through_the_gate() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let e1 = interaction(&adapter, tenant, "account:one", "agent:a").await;
    let e2 = interaction(&adapter, tenant, "account:two", "agent:a").await;
    let e3 = interaction(&adapter, tenant, "account:three", "agent:b").await;
    let cand = adapter
        .propose_knowledge(proposal(
            tenant,
            "Segment buyers escalate procurement before signing.",
            None,
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();

    // Simulate the auto-publish-OFF promotion: candidate → eligible.
    let moved = adapter
        .mark_knowledge_eligible(tenant, cand.id)
        .await
        .unwrap();
    assert!(moved);
    let eligible = adapter
        .knowledge_item(tenant, cand.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(eligible.status, KnowledgeStatus::Eligible);

    // An eligible item is NOT retrievable — no carve-out chunk exists yet.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:one".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope,
            embedding: None,
            text: Some("procurement escalate signing".into()),
            k: 20,
        })
        .await
        .unwrap();
    assert!(
        !hits.iter().any(|h| h.kind == "knowledge"),
        "an eligible (unpublished) item must never be retrievable"
    );

    // The human/policy publish call promotes it through the gate.
    let published = adapter
        .publish_knowledge(tenant, cand.id, vec![7], 3, None)
        .await
        .unwrap();
    assert_eq!(published.status, KnowledgeStatus::Published);
}

/// mark_knowledge_eligible only moves a candidate — a re-mark is a no-op.
#[tokio::test]
async fn mark_eligible_is_candidate_only() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let e1 = interaction(&adapter, tenant, "account:x", "agent:a").await;
    let cand = adapter
        .propose_knowledge(proposal(tenant, "Thin generalization.", None, vec![e1]))
        .await
        .unwrap();
    assert!(adapter
        .mark_knowledge_eligible(tenant, cand.id)
        .await
        .unwrap());
    // Second call: already eligible, not a candidate → no move.
    assert!(!adapter
        .mark_knowledge_eligible(tenant, cand.id)
        .await
        .unwrap());
}

/// Rejection is REMEMBERED: rejecting a candidate sets status='rejected', and a
/// re-propose of the SAME canonical form returns the remembered rejected item —
/// it never resurrects as a fresh candidate.
#[tokio::test]
async fn rejection_is_remembered_and_does_not_resurrect() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let e1 = interaction(&adapter, tenant, "account:red", "agent:a").await;
    let e2 = interaction(&adapter, tenant, "account:green", "agent:a").await;
    let e3 = interaction(&adapter, tenant, "account:blue", "agent:b").await;

    let canon = "segment_buyer requires signed_dpa before security_review";
    let cand = adapter
        .propose_knowledge(proposal(
            tenant,
            "Segment buyers require a signed DPA before security review.",
            Some(canon),
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();
    assert_eq!(cand.status, KnowledgeStatus::Candidate);

    // A reviewer rejects it.
    let rejected = adapter
        .reject_knowledge(tenant, cand.id, "not a durable pattern")
        .await
        .unwrap()
        .expect("candidate is rejectable");
    assert_eq!(rejected.status, KnowledgeStatus::Rejected);

    // Re-propose the SAME canonical form (a paraphrase, different human text):
    // the rejection memory returns the remembered rejected item, unchanged.
    let re = adapter
        .propose_knowledge(proposal(
            tenant,
            "Buyers in the segment insist on a DPA signature prior to any security assessment.",
            Some(canon),
            vec![e1, e2, e3],
        ))
        .await
        .unwrap();
    assert_eq!(re.status, KnowledgeStatus::Rejected, "must not resurrect");
    assert_eq!(re.id, cand.id, "same remembered row, not a new candidate");

    // And it is not retrievable, ever.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec!["account:red".into()],
        max_confidentiality: Confidentiality::Confidential,
    };
    let hits = adapter
        .recall(RecallQuery {
            scope,
            embedding: None,
            text: Some("DPA signed security review".into()),
            k: 20,
        })
        .await
        .unwrap();
    assert!(!hits.iter().any(|h| h.kind == "knowledge"));

    // A published item cannot be rejected (retraction is forget's job).
    let e4 = interaction(&adapter, tenant, "account:amber", "agent:a").await;
    let e5 = interaction(&adapter, tenant, "account:cyan", "agent:a").await;
    let e6 = interaction(&adapter, tenant, "account:violet", "agent:b").await;
    let pubcand = adapter
        .propose_knowledge(proposal(
            tenant,
            "A different durable pattern about renewals.",
            Some("segment_buyer negotiates renewal_terms"),
            vec![e4, e5, e6],
        ))
        .await
        .unwrap();
    adapter
        .publish_knowledge(tenant, pubcand.id, vec![7], 3, None)
        .await
        .unwrap();
    let refused = adapter
        .reject_knowledge(tenant, pubcand.id, "too late")
        .await
        .unwrap();
    assert!(refused.is_none(), "published items cannot be rejected");
}

/// The per-tenant auto-publish flag defaults OFF (the OSS-conservative stance)
/// and is togglable; a per-tenant row wins over the global default.
#[tokio::test]
async fn auto_publish_defaults_off_and_is_togglable() {
    let Some((adapter, tenant)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Default: OFF.
    assert!(!adapter.knowledge_auto_publish(tenant).await.unwrap());
    // Opt in per-tenant.
    adapter
        .set_knowledge_auto_publish(Some(tenant), true)
        .await
        .unwrap();
    assert!(adapter.knowledge_auto_publish(tenant).await.unwrap());
    // Opt back out.
    adapter
        .set_knowledge_auto_publish(Some(tenant), false)
        .await
        .unwrap();
    assert!(!adapter.knowledge_auto_publish(tenant).await.unwrap());
}
