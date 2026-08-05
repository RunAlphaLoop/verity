-- Input-derived visibility for agent writes (SPEC §2 L3 invariant extended to
-- Tier-2): chunks carry their declared derivation lineage as L0 episode ids.
-- Empty = non-derived write. The GIN index serves the (named follow-up)
-- ancestor-narrow invalidation walk: "which chunks derive from episode X".
-- NOTE: chunks.provenance is already indexed (chunks_provenance_idx, 0011) —
-- resolve_derivation_inputs' episode-ref leg rides that existing index.
ALTER TABLE chunks ADD COLUMN derived_from uuid[] NOT NULL DEFAULT '{}';
CREATE INDEX chunks_derived_from_idx ON chunks USING gin (derived_from);
