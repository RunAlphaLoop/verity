-- 0040_document_retire_ledger.sql — append-only evidence for server-side
-- document RETIRE (POST /v1/admin/retire), the enforcement half of a
-- connector-detected retraction (source deletion, quarantine transition,
-- unresolvable ACL — e.g. the SharePoint parked-retractions drain).
--
-- The retire op itself closes every CURRENT chunk of (tenant, source,
-- document_id) — valid_to = now() plus a blanked visibility as defense-in-
-- depth over-hide — and appends ONE row here per call, INCLUDING replays that
-- retired 0 chunks: idempotency lives in the UPDATE's `valid_to IS NULL`
-- predicate (a replay matches nothing), never in a uniqueness key on this
-- table, and a recorded 0-chunk replay is evidence the signal was re-driven,
-- not an error. Append-only: rows are never updated or deleted (hard purge
-- stays the §8 pipeline).
CREATE TABLE document_retire_ledger (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    source         text NOT NULL,
    document_id    text NOT NULL,
    reason         text NOT NULL,   -- removed|quarantined|acl_unresolvable
    chunks_retired bigint NOT NULL, -- 0 = replay (already retired / never indexed)
    retired_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX document_retire_ledger_key_idx
    ON document_retire_ledger (tenant_id, source, document_id);
