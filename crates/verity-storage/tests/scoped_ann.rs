//! Scoped-ANN broad-scope safety + sanity (perf-scoped-ann).
//!
//! The dense recall leg routes by selectivity (recall_dense in postgres.rs):
//! an EXPLAIN row estimate <= EXACT_SCAN_MAX_ROWS (20k) takes the exact
//! brute-force branch; a larger estimate takes the HNSW branch, which now sets
//! `hnsw.ef_search = 200` + `hnsw.iterative_scan = strict_order` (SET LOCAL,
//! tx-scoped). Those GUCs change only HOW the ANN is scanned — the mandatory
//! scope pre-filters (tenant_id, valid_to IS NULL, visibility && $scope,
//! confidentiality <= ceiling, entity fence) stay HARD pre-filters on the
//! ranked SELECT.
//!
//! The other recall tests (embedding_migration, scope_fuzz) seed only a
//! handful / a few hundred chunks, so they exercise the EXACT branch. This
//! file deliberately seeds > 20k in-scope chunks so the planner takes the
//! **HNSW branch** and we prove two things there:
//!   (1) SCOPE SAFETY: an out-of-scope chunk that is a genuine near-neighbor
//!       (distance 0 — an exact copy of the query vector) is NEVER returned,
//!       even though the ANN would rank it first if the filter were dropped.
//!   (2) SANITY: recall still returns in-scope results (the ef_search=200 fix
//!       — default 40 silently returned 0 hits on the large real corpus).
//!
//! Requires VERITY_TEST_DSN; skips when absent.

use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

/// Enough in-scope live chunks that the planner's EXPLAIN estimate clears
/// EXACT_SCAN_MAX_ROWS (20_000) and recall_dense takes the HNSW branch. A
/// margin over 20k keeps the routing decision robust to estimate noise.
const N_INSCOPE: usize = 25_000;

/// The scope-visible principal token vs. the out-of-scope one. The two are
/// disjoint, so `visibility && $scope` admits IN only.
const TOK_IN: i32 = 1;
const TOK_OUT: i32 = 2;

async fn setup() -> Option<(PostgresAdapter, TenantId, EpisodeId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("scoped-ann-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "scoped-ann".into(),
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

/// A unit-norm 384-d vector parameterized by `seed`. Distinct seeds give
/// distinct, non-parallel directions so cosine distance is meaningful.
fn unit_vec(seed: f32) -> Vec<f32> {
    let v: Vec<f32> = (0..384).map(|i| (seed + i as f32 * 0.017).sin()).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    v.into_iter().map(|x| x / n).collect()
}

fn chunk(
    tenant: TenantId,
    ep: EpisodeId,
    doc: &str,
    embedding: Vec<f32>,
    visibility: Vec<i32>,
) -> ChunkWrite {
    ChunkWrite {
        tenant_id: tenant,
        source: "scoped-ann".into(),
        document_id: doc.into(),
        seq: 0,
        content: format!("content {doc}"),
        content_hash: format!("h-{doc}-{}", uuid::Uuid::now_v7()),
        embedding: Some(embedding),
        visibility,
        entity_tags: vec!["account:acme".into()],
        confidentiality: Confidentiality::Internal,
        trust_tier: TrustTier::Observation,
        valid_from: Utc::now(),
        provenance: ep,
        acl_provenance: AclProvenance::AdminAssigned,
        derived_from: vec![],
    }
}

/// Broad-scope HNSW branch: an out-of-scope exact-copy near-neighbor is never
/// returned, and in-scope recall still yields results.
#[tokio::test]
async fn broad_scope_hnsw_never_leaks_out_of_scope_neighbor() {
    let Some((a, tenant, ep)) = setup().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    // The query vector. We plant an EXACT copy of it under an OUT-of-scope
    // token — a distance-0 candidate the ANN would surface first if the scope
    // pre-filter were not enforced. This is the adversarial near-neighbor.
    let query = unit_vec(42.0);

    // Seed the out-of-scope decoy: same embedding as the query (distance 0),
    // but visible only to TOK_OUT.
    a.upsert_chunks(vec![chunk(
        tenant,
        ep,
        "OUT-decoy-exact-copy",
        query.clone(),
        vec![TOK_OUT],
    )])
    .await
    .unwrap();

    // Seed N_INSCOPE in-scope chunks (visible to TOK_IN) with varied
    // embeddings, so the planner estimate clears 20k and the HNSW branch runs.
    // One of them is a close (but not exact) in-scope neighbor so recall has a
    // real in-scope target to find.
    let mut batch = Vec::with_capacity(2_000);
    for i in 0..N_INSCOPE {
        // seed 42.5 is close to the query (42.0) -> a strong in-scope hit.
        let seed = if i == 0 { 42.5 } else { 100.0 + i as f32 };
        batch.push(chunk(
            tenant,
            ep,
            &format!("IN-{i}"),
            unit_vec(seed),
            vec![TOK_IN],
        ));
        if batch.len() == 2_000 {
            a.upsert_chunks(std::mem::take(&mut batch)).await.unwrap();
            batch = Vec::with_capacity(2_000);
        }
    }
    if !batch.is_empty() {
        a.upsert_chunks(batch).await.unwrap();
    }

    // Refresh planner stats so the selectivity router's EXPLAIN estimate
    // reflects the rows we just bulk-inserted (autovacuum lags a fresh bulk
    // load, which would otherwise leave a stale under-estimate and route to the
    // EXACT branch — defeating the purpose of this test). Deterministic.
    sqlx::query("ANALYZE chunks")
        .execute(a.pool())
        .await
        .unwrap();

    // Assert we will actually exercise the HNSW branch: the router takes it
    // only when the EXPLAIN estimate exceeds EXACT_SCAN_MAX_ROWS (20_000). This
    // makes the test self-verifying — if a future stats/threshold change routed
    // this to the exact branch, we'd be silently testing the wrong path.
    let plan: serde_json::Value = sqlx::query_scalar(
        "EXPLAIN (FORMAT JSON) SELECT 1 FROM chunks
         WHERE tenant_id = $1 AND valid_to IS NULL AND embedding IS NOT NULL
           AND visibility && $2 AND confidentiality <= $3",
    )
    .bind(tenant)
    .bind(vec![TOK_IN])
    .bind(Confidentiality::Internal as i16)
    .fetch_one(a.pool())
    .await
    .unwrap();
    let est = plan[0]["Plan"]["Plan Rows"].as_i64().unwrap_or(0);
    assert!(
        est > 20_000,
        "test precondition: planner estimate {est} must exceed the router's \
         EXACT_SCAN_MAX_ROWS (20_000) so recall takes the HNSW branch; seed more \
         chunks if this fails"
    );

    let in_scope = Scope {
        tenant_id: tenant,
        principals: vec![TOK_IN],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    };

    // Dense-only recall (embedding present, no text) so we exercise exactly the
    // recall_dense HNSW branch under test.
    let hits = a
        .recall(RecallQuery {
            scope: in_scope.clone(),
            embedding: Some(query.clone()),
            text: None,
            k: 8,
        })
        .await
        .unwrap();

    // (2) SANITY: the ef_search=200 fix means a large-tenant broad recall
    // returns results (the pgvector default 40 silently returned 0 here).
    assert!(
        !hits.is_empty(),
        "broad-scope HNSW recall returned nothing — the ef_search fix regressed \
         (pgvector default ef_search=40 returns 0/k on large corpora)"
    );

    // (1) SCOPE SAFETY: the distance-0 out-of-scope decoy must NEVER appear,
    // and every hit must be an in-scope IN-* chunk.
    for h in &hits {
        assert_ne!(
            h.document_id, "OUT-decoy-exact-copy",
            "SCOPE LEAK: the out-of-scope exact-copy near-neighbor was returned \
             by the HNSW branch"
        );
        assert!(
            h.document_id.starts_with("IN-"),
            "SCOPE LEAK: recall returned a non-in-scope chunk {} under scope {:?}",
            h.document_id,
            in_scope
        );
    }

    // Mirror proof (guards against a vacuous test): a scope that DOES hold
    // TOK_OUT sees the decoy ranked first — so it is genuinely reachable and
    // genuinely the nearest neighbor; the in-scope run excluded it by the scope
    // pre-filter, not because it was unreachable.
    let out_scope = Scope {
        tenant_id: tenant,
        principals: vec![TOK_OUT],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    };
    let out_hits = a
        .recall(RecallQuery {
            scope: out_scope,
            embedding: Some(query),
            text: None,
            k: 8,
        })
        .await
        .unwrap();
    assert_eq!(
        out_hits.first().map(|h| h.document_id.as_str()),
        Some("OUT-decoy-exact-copy"),
        "mirror check: the OUT scope should see the exact-copy decoy as its top \
         hit — if not, the leak test above is vacuous"
    );

    println!(
        "scoped-ann: broad HNSW branch, {N_INSCOPE} in-scope chunks, {} hits, \
         out-of-scope distance-0 decoy correctly excluded",
        hits.len()
    );
}
