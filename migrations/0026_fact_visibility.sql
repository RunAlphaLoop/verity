-- 0026_fact_visibility.sql — close the L1 fact-visibility gap (SPEC §5e.6a/§5e.6b, §7e).
-- Facts mirror chunks: a materialized principal-token array + confidentiality class,
-- enforced by the same `visibility && $tokens AND confidentiality <= $M` pre-filter
-- recall already uses. Fail-closed: rows without explicit visibility read as invisible
-- to scoped reads (admin plane may still see them).

-- 1. Columns. visibility nullable at first so the ALTER is instant and the backfill
--    can be explicit; confidentiality gets its default immediately (matches chunks).
ALTER TABLE facts ADD COLUMN visibility      int[];
ALTER TABLE facts ADD COLUMN confidentiality smallint NOT NULL DEFAULT 1;
--    0 public / 1 internal / 2 confidential / 3 restricted — identical to chunks.

-- 2. Fail-closed backfill: every legacy row becomes visible to NOBODY on scoped reads.
--    This is deliberate — we do NOT invent permissive tokens or derive from acl_provenance
--    (that is the "unmappable ACL -> permissive" the non-negotiables forbid). Admin-plane
--    reads (bypass path) still see these rows for remediation/re-ingest.
UPDATE facts SET visibility = '{}'::int[] WHERE visibility IS NULL;

-- 3. Enforce NOT NULL + default, matching chunks.visibility.
ALTER TABLE facts ALTER COLUMN visibility SET NOT NULL;
ALTER TABLE facts ALTER COLUMN visibility SET DEFAULT '{}'::int[];

-- 4. GIN index for the `&&` overlap pre-filter (mirrors chunks_visibility_idx).
CREATE INDEX facts_visibility_idx ON facts USING gin (visibility);

-- 5. Append-only ACL-correction audit trail (§5e.6b). Visibility is NOT part of the
--    bi-temporal VALUE history; a re-share/un-share UPDATEs the column in place across
--    the key's rows and appends here (effect is immediate, like a tombstone). The
--    "who could see value V when current" forensic history is reconstructed by
--    replaying this log, never by freezing a per-row ACL.
CREATE TABLE fact_acl_audit (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    source              text NOT NULL,
    entity_id           text NOT NULL,
    field               text NOT NULL,
    fact_id             uuid REFERENCES facts(id),   -- current row at correction time (NULL for key-level gaps)
    old_visibility      int[],                        -- NULL for the initial materialization
    new_visibility      int[]      NOT NULL,
    old_confidentiality smallint,
    new_confidentiality smallint   NOT NULL,
    reason              text NOT NULL,   -- 'materialized'|'source_reshare'|'source_unshare'|'admin_correction'|'rebac_watch_delete'|'quarantine'
    acl_provenance      text NOT NULL,   -- mirrored|approximated|admin-assigned|quarantined
    provenance          uuid REFERENCES episodes(id),
    changed_by          text,            -- admin sub / 'rebac_watch' / connector id
    changed_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX fact_acl_audit_key_idx ON fact_acl_audit (tenant_id, source, entity_id, field, changed_at DESC);
