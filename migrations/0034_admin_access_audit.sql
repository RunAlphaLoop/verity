-- Permission Graph (admin/operator plane) audit trail.
--
-- The Permission Graph endpoints (GET /v1/admin/access/subject,
-- GET /v1/admin/access/object) are a god-view over org structure + access
-- patterns: per-principal closure, who-can-see-what, reachable-user fan-out.
-- Because this surface reveals who-can-see-what, EVERY query is logged before
-- the response is returned.
--
-- Append-only, mirroring the existing append-only ACL-correction audit trail
-- fact_acl_audit (0026): rows are only ever INSERTed, never UPDATEd or DELETEd.
-- `result_meta` records COUNTS ONLY (total docs/chunks, #closure nodes,
-- #reachable users) — never document content — so the audit log itself
-- respects the metadata-not-content boundary (NG2).
CREATE TABLE admin_access_audit (
    id           uuid PRIMARY KEY,
    tenant_id    uuid        NOT NULL REFERENCES tenants(id),
    actor        text        NOT NULL,   -- admin identity: bearer fingerprint / 'dev-open'
    endpoint     text        NOT NULL,   -- 'access/subject' | 'access/object'
    query_target text        NOT NULL,   -- the subject/object queried
    params       jsonb       NOT NULL,   -- max_confidentiality, mode, etc.
    result_meta  jsonb       NOT NULL,   -- counts only (NOT content)
    queried_at   timestamptz NOT NULL DEFAULT now()
);

-- Forensic read pattern: "what did this tenant's admins query, most recent
-- first", mirroring fact_acl_audit_key_idx's (tenant, …, changed_at DESC).
CREATE INDEX admin_access_audit_tenant_idx
    ON admin_access_audit (tenant_id, queried_at DESC);
