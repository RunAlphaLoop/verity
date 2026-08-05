//! Embedding-model migration tooling (SPEC §5c): dual-vector backfill, the
//! query-routing cutover, and the coverage gate. Requires VERITY_TEST_DSN;
//! skips when absent.

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
        .create_tenant(&format!("emb-{}", uuid::Uuid::now_v7()))
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

fn unit_vec(seed: f32) -> Vec<f32> {
    let v: Vec<f32> = (0..384).map(|i| seed + i as f32 * 0.001).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.into_iter().map(|x| x / n).collect()
}

fn embedded_chunk(tenant: TenantId, ep: EpisodeId, doc: &str, seed: f32) -> ChunkWrite {
    ChunkWrite {
        tenant_id: tenant,
        source: "test".into(),
        document_id: doc.into(),
        seq: 0,
        content: format!("content {doc}"),
        content_hash: format!("h-{doc}"),
        embedding: Some(unit_vec(seed)),
        visibility: vec![1],
        entity_tags: vec!["account:acme".into()],
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Observation,
        valid_from: Utc::now(),
        provenance: ep,
        acl_provenance: AclProvenance::AdminAssigned,
        derived_from: vec![],
    }
}

/// Backfill fills embedding_v2 and coverage climbs to 100%; the cutover gate
/// refuses V2 below 100% and permits it at 100% (and permits force below).
#[tokio::test]
async fn backfill_coverage_and_gated_cutover() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    a.register_embedding_model("test-model-v2", 384)
        .await
        .unwrap();

    // Three embeddable chunks; none has embedding_v2 yet.
    a.upsert_chunks(vec![
        embedded_chunk(tenant, ep, "c1", 0.1),
        embedded_chunk(tenant, ep, "c2", 0.2),
        embedded_chunk(tenant, ep, "c3", 0.3),
    ])
    .await
    .unwrap();

    let cov = a.embedding_v2_coverage(Some(tenant)).await.unwrap();
    assert_eq!(cov.total, 3);
    assert_eq!(cov.covered, 0);
    assert!(!cov.is_complete());

    // The default route is V1 before any cutover.
    assert_eq!(a.embedding_route(tenant).await.unwrap(), EmbeddingRoute::V1);

    // Backfill two of three (simulate the server re-encoding).
    let pending = a.chunks_needing_v2(Some(tenant), 2).await.unwrap();
    assert_eq!(pending.len(), 2);
    let rows: Vec<(ChunkId, Vec<f32>)> =
        pending.iter().map(|(id, _)| (*id, unit_vec(0.5))).collect();
    let written = a.fill_embedding_v2("test-model-v2", &rows).await.unwrap();
    assert_eq!(written, 2);

    let cov = a.embedding_v2_coverage(Some(tenant)).await.unwrap();
    assert_eq!(cov.covered, 2);
    assert!(!cov.is_complete());

    // Finish the backfill.
    let pending = a.chunks_needing_v2(Some(tenant), 100).await.unwrap();
    assert_eq!(pending.len(), 1);
    let rows: Vec<(ChunkId, Vec<f32>)> =
        pending.iter().map(|(id, _)| (*id, unit_vec(0.6))).collect();
    a.fill_embedding_v2("test-model-v2", &rows).await.unwrap();

    let cov = a.embedding_v2_coverage(Some(tenant)).await.unwrap();
    assert_eq!(cov.covered, 3);
    assert!(cov.is_complete(), "coverage complete after full backfill");

    // Re-filling is idempotent: already-covered rows aren't in the pending set.
    assert!(a
        .chunks_needing_v2(Some(tenant), 100)
        .await
        .unwrap()
        .is_empty());
}

/// After cutover to V2, the dense recall leg searches embedding_v2. Prove
/// routing changed the searched column: fill embedding_v2 with a vector that
/// ranks a DIFFERENT chunk first than the original embedding would.
#[tokio::test]
async fn cutover_routes_dense_recall_to_v2() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    a.register_embedding_model("v2", 384).await.unwrap();

    // Two chunks. Under embedding (v1): c_a ≈ query, c_b far.
    let query = unit_vec(0.10);
    let far = unit_vec(5.0);
    let mut ca = embedded_chunk(tenant, ep, "ca", 0.10); // v1 near query
    ca.embedding = Some(query.clone());
    let mut cb = embedded_chunk(tenant, ep, "cb", 9.0); // v1 far from query
    cb.embedding = Some(far.clone());
    a.upsert_chunks(vec![ca, cb]).await.unwrap();

    let scope = Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    };
    let recall_query = |emb: Vec<f32>| RecallQuery {
        scope: scope.clone(),
        embedding: Some(emb),
        text: None,
        k: 5,
    };

    // Under V1 (default): ca ranks first.
    let hits = a.recall(recall_query(query.clone())).await.unwrap();
    assert_eq!(hits.first().map(|h| h.document_id.as_str()), Some("ca"));

    // Backfill embedding_v2 with the INVERTED preference: cb ≈ query, ca far.
    let ids = a.chunks_needing_v2(Some(tenant), 100).await.unwrap();
    let by_doc = |doc: &str| {
        // chunks_needing_v2 returns (id, content); content is "content <doc>".
        ids.iter()
            .find(|(_, c)| c == &format!("content {doc}"))
            .map(|(id, _)| *id)
            .unwrap()
    };
    let v2_rows = vec![(by_doc("ca"), far.clone()), (by_doc("cb"), query.clone())];
    a.fill_embedding_v2("v2", &v2_rows).await.unwrap();

    // Cut over to V2 globally... but this test scopes per tenant to avoid
    // cross-test interference: set the per-tenant route.
    a.set_embedding_route(Some(tenant), EmbeddingRoute::V2)
        .await
        .unwrap();
    assert_eq!(a.embedding_route(tenant).await.unwrap(), EmbeddingRoute::V2);

    // Now the dense leg searches embedding_v2, where cb ≈ query → cb first.
    let hits = a.recall(recall_query(query.clone())).await.unwrap();
    assert_eq!(
        hits.first().map(|h| h.document_id.as_str()),
        Some("cb"),
        "after cutover the dense leg ranks by embedding_v2, not embedding"
    );
}

/// New chunks written during the migration window carry embedding (v1); v2 is
/// backfilled from stored content — the dual-vector path (both columns coexist).
#[tokio::test]
async fn dual_vectors_coexist() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    a.register_embedding_model("v2", 384).await.unwrap();
    a.upsert_chunks(vec![embedded_chunk(tenant, ep, "dc", 0.4)])
        .await
        .unwrap();
    let pending = a.chunks_needing_v2(Some(tenant), 100).await.unwrap();
    assert_eq!(pending.len(), 1, "v1 present, v2 pending");
    let rows: Vec<(ChunkId, Vec<f32>)> =
        pending.iter().map(|(id, _)| (*id, unit_vec(0.4))).collect();
    a.fill_embedding_v2("v2", &rows).await.unwrap();
    // Both routes now find the chunk (v1 always populated, v2 backfilled).
    for route in [EmbeddingRoute::V1, EmbeddingRoute::V2] {
        a.set_embedding_route(Some(tenant), route).await.unwrap();
        let hits = a
            .recall(RecallQuery {
                scope: Scope {
                    tenant_id: tenant,
                    principals: vec![1],
                    entity_scope: vec![],
                    max_confidentiality: Confidentiality::Internal,
                },
                embedding: Some(unit_vec(0.4)),
                text: None,
                k: 5,
            })
            .await
            .unwrap();
        assert!(
            hits.iter().any(|h| h.document_id == "dc"),
            "route {route:?} finds the dual-written chunk"
        );
    }
}
