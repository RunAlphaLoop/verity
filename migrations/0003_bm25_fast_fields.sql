-- BM25 p99 fix (docs/BENCHMARKS.md 2026-07-09 entry, finding 4): include the
-- mandatory scope-filter columns in the Tantivy index as fast fields so
-- pg_search filters inside the index instead of on the heap.
-- Measured at 100k chunks / 1% selectivity: p99 87.2ms -> 32.6ms.

DROP INDEX IF EXISTS chunks_bm25_idx;
CREATE INDEX chunks_bm25_idx ON chunks
    USING bm25 (id, content, tenant_id, visibility, confidentiality)
    WITH (key_field = 'id');
