-- BM25 full filter pushdown (docs/BENCHMARKS.md 1M entry, finding 3).
-- pg_search cannot push the array-overlap operator (&&) into Tantivy — the
-- adapter now expresses visibility as paradedb.term_set. valid_to joins the
-- index so pg_search rewrites `valid_to IS NULL` to a must_not-exists clause
-- instead of heap-filtering ~540k candidate rows per query.
-- Measured at 1M: 264ms -> 9.8ms (1% selectivity), 280ms -> 13.0ms (broad).

DROP INDEX IF EXISTS chunks_bm25_idx;
CREATE INDEX chunks_bm25_idx ON chunks
    USING bm25 (id, content, tenant_id, visibility, confidentiality, valid_to)
    WITH (key_field = 'id');
