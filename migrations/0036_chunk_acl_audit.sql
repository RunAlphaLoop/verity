-- 0036_chunk_acl_audit.sql — object-level ACL retraction for chunks (SPEC §5e.6b).
-- Chunks mirror facts: an ACL correction UPDATEs visibility/confidentiality in
-- place across EVERY row of the (tenant,source,document_id) lineage (current +
-- superseded), so ?as_of= cannot resurface the old permissive ACL. Visibility is
-- NOT part of the bi-temporal VALUE history (that lives in content/valid_from);
-- this table is the forensic old->new log, one row per rewritten CURRENT chunk.
--
-- The lineage walk is by document_id: ingest_document writes every chunk of one
-- source record under the SAME (source, document_id) (only seq varies) and the
-- SAME provenance episode, so one source-record un-share fans out to MANY chunk
-- rows via this key — the natural, indexed object identity.
CREATE TABLE chunk_acl_audit (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    source              text NOT NULL,
    document_id         text NOT NULL,
    seq                 integer,                       -- the rewritten chunk's seq (NULL only for key-level gaps)
    chunk_id            uuid REFERENCES chunks(id),    -- the specific current row snapshotted
    old_visibility      int[],                         -- NULL if the row had none
    new_visibility      int[]      NOT NULL,
    old_confidentiality smallint,
    new_confidentiality smallint   NOT NULL,
    reason              text NOT NULL,   -- source_reshare|source_unshare|admin_correction|rebac_watch_delete
    acl_provenance      text NOT NULL,   -- mirrored|approximated|admin-assigned|quarantined
    provenance          uuid REFERENCES episodes(id),
    changed_by          text,            -- admin sub / 'rebac_watch' / connector id
    changed_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX chunk_acl_audit_key_idx
    ON chunk_acl_audit (tenant_id, source, document_id, changed_at DESC);
