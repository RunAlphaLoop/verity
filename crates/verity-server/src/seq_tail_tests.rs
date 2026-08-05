//! Shrinking-document stale-tail tests — the ingest-side enforcement gap the
//! security review found: a re-delivery with FEWER chunks than the prior
//! version used to leave the old tail (seq beyond the delivered count) open at
//! `valid_to IS NULL`, serving stale content for every connector (a Slack
//! thread that shrinks after a delete, a shortened SharePoint doc, …).
//! Exercises the real `upsert_chunks` path against `VERITY_TEST_DSN`.
//!
//! Gating is HARD-ERROR (panic), not silent-skip (the `retire_tests` posture):
//! these are enforcement-soundness tests — a missing database is a
//! misconfiguration to surface loudly, never a class of test to silently no-op.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::Row;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

/// Real adapter against `VERITY_TEST_DSN`, wrapped in `CachedAdapter` exactly
/// like the server wires it (chunks are not fact-cached; the wrapper is a pure
/// delegator on this path, and running through it proves that).
async fn tail_state() -> (CachedAdapter<PostgresAdapter>, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the shrinking-document stale-tail tests; \
         refusing to silently no-op",
    );
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("seq-tail-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    (CachedAdapter::new(pg, 10_000), tenant)
}

/// Deliver one document version: `seqs` chunks (seq 0..seqs-1) at `valid_from`,
/// all tagged with `tag` so the read path (`latest_chunks`) can be asserted.
/// Returns the number of chunk rows actually written (the ON CONFLICT count).
async fn deliver(
    storage: &CachedAdapter<PostgresAdapter>,
    tenant: TenantId,
    source: &str,
    doc: &str,
    seqs: i32,
    valid_from: DateTime<Utc>,
    tag: &str,
) -> usize {
    let episode = storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(doc.into()),
            kind: EpisodeKind::DocVersion,
            payload: json!({ "doc": doc, "chunks": seqs }),
            content_hash: format!("{doc}-{valid_from}-hash"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    let chunks: Vec<ChunkWrite> = (0..seqs)
        .map(|seq| ChunkWrite {
            tenant_id: tenant,
            source: source.into(),
            document_id: doc.into(),
            seq,
            content: format!("{doc} v{valid_from} chunk {seq}"),
            content_hash: format!("{doc}-{valid_from}-{seq}"),
            embedding: None,
            visibility: vec![101, 202],
            entity_tags: vec![tag.into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .collect();
    storage.upsert_chunks(chunks).await.expect("chunks")
}

/// Every row of one `(source, document_id)` lineage as
/// `(seq, valid_from, valid_to)`, ordered — the full bi-temporal state, so a
/// test can assert closes AND the absence of extra closes row-by-row.
async fn lineage(
    storage: &CachedAdapter<PostgresAdapter>,
    tenant: TenantId,
    source: &str,
    doc: &str,
) -> Vec<(i32, DateTime<Utc>, Option<DateTime<Utc>>)> {
    sqlx::query(
        "SELECT seq, valid_from, valid_to FROM chunks
         WHERE tenant_id = $1 AND source = $2 AND document_id = $3
         ORDER BY seq, valid_from",
    )
    .bind(tenant)
    .bind(source)
    .bind(doc)
    .fetch_all(storage.inner().pool())
    .await
    .expect("lineage rows")
    .iter()
    .map(|r| (r.get("seq"), r.get("valid_from"), r.get("valid_to")))
    .collect()
}

fn scope(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![101],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    }
}

#[tokio::test]
async fn shrink_redelivery_closes_the_stale_tail() {
    let (storage, tenant) = tail_state().await;
    let t0 = Utc::now() - Duration::seconds(60);
    let t1 = t0 + Duration::seconds(30);
    let tag = "account:shrink";

    deliver(&storage, tenant, "slack", "thread-1", 3, t0, tag).await;
    // The thread shrinks (a message was deleted): re-delivery carries ONE chunk.
    deliver(&storage, tenant, "slack", "thread-1", 1, t1, tag).await;

    let rows = lineage(&storage, tenant, "slack", "thread-1").await;
    // Bi-temporal, invalidate-don't-delete: all 4 rows still exist.
    // seq 0: old version superseded at t1 (the per-seq retire), new current.
    // seqs 1,2: the stale tail — CLOSED at t1, not left open.
    assert_eq!(
        rows,
        vec![
            (0, t0, Some(t1)),
            (0, t1, None),
            (1, t0, Some(t1)),
            (2, t0, Some(t1)),
        ]
    );

    // The current view serves ONLY the single new chunk.
    let hits = storage
        .latest_chunks(&scope(tenant), tag, 10)
        .await
        .expect("latest_chunks");
    assert_eq!(hits.len(), 1, "only the re-delivered chunk is current");
    assert_eq!(hits[0].seq, 0);
    assert_eq!(hits[0].content, format!("thread-1 v{t1} chunk 0"));
}

#[tokio::test]
async fn shrink_replay_is_idempotent() {
    let (storage, tenant) = tail_state().await;
    let t0 = Utc::now() - Duration::seconds(60);
    let t1 = t0 + Duration::seconds(30);
    let tag = "account:replay";

    deliver(&storage, tenant, "slack", "thread-2", 3, t0, tag).await;
    deliver(&storage, tenant, "slack", "thread-2", 1, t1, tag).await;
    let before = lineage(&storage, tenant, "slack", "thread-2").await;

    // Replay of the SAME 1-chunk delivery (same valid_from): ON CONFLICT
    // writes nothing, and strict `valid_from < $new` means zero additional
    // closes — the full bi-temporal state is byte-for-byte unchanged.
    let written = deliver(&storage, tenant, "slack", "thread-2", 1, t1, tag).await;
    assert_eq!(written, 0, "replay must not re-insert");
    let after = lineage(&storage, tenant, "slack", "thread-2").await;
    assert_eq!(before, after, "replay must not re-close or double-close");

    let hits = storage
        .latest_chunks(&scope(tenant), tag, 10)
        .await
        .expect("latest_chunks");
    assert_eq!(hits.len(), 1);
}

#[tokio::test]
async fn tail_close_is_scoped_to_its_document_and_source() {
    let (storage, tenant) = tail_state().await;
    let t0 = Utc::now() - Duration::seconds(60);
    let t1 = t0 + Duration::seconds(30);

    // The shrink target, a NEIGHBOR document in the same source, and the SAME
    // document_id in a different source.
    deliver(
        &storage,
        tenant,
        "slack",
        "thread-3",
        3,
        t0,
        "account:target",
    )
    .await;
    deliver(
        &storage,
        tenant,
        "slack",
        "thread-other",
        3,
        t0,
        "account:neighbor",
    )
    .await;
    deliver(
        &storage,
        tenant,
        "gdrive",
        "thread-3",
        3,
        t0,
        "account:crosssource",
    )
    .await;

    deliver(
        &storage,
        tenant,
        "slack",
        "thread-3",
        1,
        t1,
        "account:target",
    )
    .await;

    // Neighbor document: all 3 chunks still current, nothing closed.
    let neighbor = lineage(&storage, tenant, "slack", "thread-other").await;
    assert_eq!(neighbor, vec![(0, t0, None), (1, t0, None), (2, t0, None)]);

    // Same document_id, different source: untouched too.
    let cross = lineage(&storage, tenant, "gdrive", "thread-3").await;
    assert_eq!(cross, vec![(0, t0, None), (1, t0, None), (2, t0, None)]);

    // And the target really did shrink to one current chunk.
    let target = lineage(&storage, tenant, "slack", "thread-3").await;
    assert_eq!(
        target,
        vec![
            (0, t0, Some(t1)),
            (0, t1, None),
            (1, t0, Some(t1)),
            (2, t0, Some(t1)),
        ]
    );
}

#[tokio::test]
async fn growth_redelivery_is_unaffected() {
    let (storage, tenant) = tail_state().await;
    let t0 = Utc::now() - Duration::seconds(60);
    let t1 = t0 + Duration::seconds(30);
    let tag = "account:growth";

    deliver(&storage, tenant, "slack", "thread-4", 1, t0, tag).await;
    // The document GROWS: 1 chunk → 3 chunks. The tail close must not touch
    // anything (there is nothing past the new highest seq).
    deliver(&storage, tenant, "slack", "thread-4", 3, t1, tag).await;

    let rows = lineage(&storage, tenant, "slack", "thread-4").await;
    assert_eq!(
        rows,
        vec![
            (0, t0, Some(t1)),
            (0, t1, None),
            (1, t1, None),
            (2, t1, None),
        ]
    );

    let mut hits = storage
        .latest_chunks(&scope(tenant), tag, 10)
        .await
        .expect("latest_chunks");
    hits.sort_by_key(|h| h.seq);
    assert_eq!(
        hits.iter().map(|h| h.seq).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "all three new chunks are current"
    );
}
