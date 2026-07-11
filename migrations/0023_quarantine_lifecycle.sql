-- Quarantine re-ingest / dismiss write surface (UI-SPEC §5 Screen 6 — the
-- currently-disabled seam). The read-only quarantine_preview table gains a
-- terminal lifecycle: a row is either OPEN (awaiting triage), REINGESTED
-- (re-admitted ONLY through an admin-supplied corrected ACL mapping — never an
-- "index it anyway" path), or DISMISSED (acknowledged, not indexed). This is
-- invalidate-don't-delete: the payload row survives for audit; only its
-- disposition is stamped. There is deliberately NO permissive re-admit column.
ALTER TABLE quarantine_preview
    ADD COLUMN IF NOT EXISTS resolution     text,        -- NULL = open; else 'reingested' | 'dismissed'
    ADD COLUMN IF NOT EXISTS resolved_at    timestamptz, -- when the disposition was stamped
    ADD COLUMN IF NOT EXISTS resolution_note text;        -- admin note (dismiss reason / reingest ref)

-- Triage queries filter open items; a partial index keeps that cheap.
CREATE INDEX IF NOT EXISTS quarantine_preview_open_idx
    ON quarantine_preview (tenant_id, at DESC)
    WHERE resolution IS NULL;
