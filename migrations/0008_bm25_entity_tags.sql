-- Entity-bound BM25 breach fix (docs/BENCHMARKS.md load entry): entity_tags
-- and kind join the Tantivy index — with KEYWORD tokenizers, since the
-- default tokenizer splits "account:0" and term_set can never match raw
-- values — so entity-bound scopes pre-filter inside the boolean query
-- instead of heap-filtering the full broad-token match set
-- (measured 542ms p50 -> ~20ms warm).

DROP INDEX IF EXISTS chunks_bm25_idx;
CREATE INDEX chunks_bm25_idx ON chunks
    USING bm25 (id, content, tenant_id, visibility, confidentiality, valid_to,
                entity_tags, kind)
    WITH (key_field = 'id',
          text_fields = '{"entity_tags": {"tokenizer": {"type": "keyword"}, "fast": true},
                          "kind": {"tokenizer": {"type": "keyword"}, "fast": true}}');
