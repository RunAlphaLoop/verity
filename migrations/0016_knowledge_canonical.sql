-- Canonicalization for knowledge merge (knowledge-merge-tuning.md §3, Phase 1).
-- Append-only migration.
--
-- The extractors now emit, alongside the human-readable statement, a normalized
-- CANONICAL statement (lowercased, article/filler stripped, predicate mapped to
-- a controlled vocabulary). The canonical form drives an exact-match FAST-PATH
-- merge: an incoming candidate whose canonical_statement is byte-identical to an
-- existing candidate/published item merges immediately with NO embedding/LLM
-- cost (accrue evidence, distinct-entity support). The human statement stays for
-- display; the canonical form is the matching key.
--
-- Canonicalization is a RECALL AID, never a merge authority: two genuinely
-- different generalizations must not share a canonical form (enforced at
-- extraction time, tested), so the existing cosine-threshold merge remains as
-- the fallback for near-paraphrases that do not canonicalize identically.
--
-- Nullable: rows proposed before this migration (or where the extractor emits no
-- canonical form) simply never take the exact-match fast path.
ALTER TABLE knowledge ADD COLUMN canonical_statement text;

-- Fast-path lookup: exact-canonical-match within a tenant. Partial index skips
-- the pre-migration NULL rows.
CREATE INDEX knowledge_canonical_idx
    ON knowledge (tenant_id, canonical_statement)
    WHERE canonical_statement IS NOT NULL;

-- NOTE on L2 supersession alignment (the second finding): L2 facts already ride
-- the (source=l2, entity_id, field) key. Phase 1 keys `field` on the extractor's
-- canonical_predicate (a controlled vocabulary: requires_before / blocks_until /
-- requires / ...) instead of the free-text relation, so re-extractions of the
-- same relation ("requires" vs "requires_before_security_assessment") align and
-- supersede. That is a change to what the server writes into the EXISTING facts
-- column — no schema change is required here.
