-- ACL provenance tags (SPEC §5e: mirrored | approximated | admin-assigned |
-- quarantined) and the scoped-read audit log (SPEC §7e).

ALTER TABLE chunks ADD COLUMN acl_provenance text NOT NULL DEFAULT 'admin-assigned';
ALTER TABLE facts  ADD COLUMN acl_provenance text NOT NULL DEFAULT 'admin-assigned';

-- Existing CDC-derived facts mirror their source system.
UPDATE facts SET acl_provenance = 'mirrored'
WHERE source LIKE 'postgresql:%' OR source LIKE 'mysql:%' OR source LIKE 'debezium%';

CREATE TABLE audit_log (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    actor_sub    text,
    actor_azp    text,
    verb         text NOT NULL,          -- recall | get | activity | brief | forget
    principals   int[] NOT NULL,
    entity_scope text[] NOT NULL,
    confidentiality smallint NOT NULL,
    query_summary text,                  -- truncated query text / ref, never full content
    result_ids   uuid[] NOT NULL,
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_tenant_at_idx ON audit_log (tenant_id, at DESC);
