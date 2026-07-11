-- Phase 3: the acceptability surface (knowledge-merge-tuning.md §5).
-- Append-only migration.
--
-- Auto-derived cross-customer knowledge is the most trust-sensitive thing
-- Verity does. This migration adds the schema for the load-bearing promises:
--
--   1. Publishing is NEVER automatic on the read path, and auto-publish is
--      opt-in per tenant (default OFF). A candidate that crosses k-support but
--      has NOT been auto-published becomes status = 'eligible' — reviewed-ready,
--      waiting for a human/policy publish call. The publish endpoint stays the
--      human gate. Auto-publish, when a tenant opts in, promotes eligible items
--      through the SAME gate on a background/admin path, never on recall.
--
--   2. Rejection is REMEMBERED. A reviewer rejecting a candidate sets
--      status = 'rejected' with a reason; the same canonical_statement must not
--      re-surface as a new candidate (enforced on propose). rejected_at /
--      rejected_reason record the decision for audit.
--
--   3. Support TIERS are bucketed on published/eligible items and carried onto
--      the §7g recall carve-out chunk, so a consuming agent sees a coarse tier
--      (emerging / established / extensive) — never an exact distinct-entity
--      count (SPEC §2 membership-inference: exact counts stay admin-only).

-- New knowledge lifecycle states. `status` is a free-text column (no CHECK
-- constraint historically), so no type change is required — these are the two
-- new values the code writes/reads:
--   'eligible' : crossed k-support with auto-publish OFF; awaiting human/policy
--                publish. Between 'candidate' and 'published'.
--   'rejected' : a reviewer refused it; remembered so the same canonical form
--                does not resurrect as a fresh candidate.
ALTER TABLE knowledge ADD COLUMN eligible_at    timestamptz;
ALTER TABLE knowledge ADD COLUMN rejected_at    timestamptz;
ALTER TABLE knowledge ADD COLUMN rejected_reason text;

-- Rejection memory fast path: a rejected canonical form is looked up on every
-- propose/merge so it cannot resurface. Partial index over the rejected rows
-- that carry a canonical form (the only ones the memory can match on).
CREATE INDEX knowledge_rejected_canonical_idx
    ON knowledge (tenant_id, canonical_statement)
    WHERE status = 'rejected' AND canonical_statement IS NOT NULL;

-- Support tier carried onto the published §7g carve-out chunk so recall hits
-- expose a BUCKET, never the exact count. Nullable: only kind='knowledge'
-- chunks ever set it; content chunks stay NULL. Recomputed on support accrual.
--   emerging    : 3-4 distinct entities
--   established : 5-9
--   extensive   : 10+
-- (< 3 never publishes — the k-support floor.)
ALTER TABLE chunks ADD COLUMN support_tier text;

-- Note on the auto-publish opt-in flag: it reuses the EXISTING settings table
-- (0015) under key 'knowledge_auto_publish', per-tenant or global (NULL tenant).
-- Absent row = OFF (the OSS-conservative default). No schema change needed:
--   INSERT INTO settings (tenant_id, key, value) VALUES ($tenant, 'knowledge_auto_publish', 'true');
