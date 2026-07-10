-- Compliance plane v0 (SPEC §8, roadmap task 23): envelope-encryption
-- plumbing for L0 payloads + the hard-purge/DSAR substrate. Append-only
-- migration file.

-- Per-tenant data-encryption keys (SPEC §8a, v0 granularity: per-tenant, not
-- yet per-data-subject/per-source). 32 random bytes, generated lazily on the
-- first L0 write for a tenant. Stored wrapped under the deployment KEK
-- (env VERITY_KEK, 64 hex chars) as AES-256-GCM nonce(12) || ciphertext+tag
-- (48) = 60 bytes; when no KEK is configured the DEK is stored as the raw
-- 32 plaintext bytes (warned at startup). Length is the wrap marker:
-- 32 bytes = plaintext, anything longer = KEK-wrapped.
CREATE TABLE tenant_deks (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
    dek        bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- L0 at-rest encryption (v0 contract, documented in
-- crates/verity-storage/src/crypto.rs): when VERITY_KEK is set,
-- append_episode stores AES-256-GCM(payload) under the tenant DEK in
-- payload_enc (nonce || ciphertext+tag) and writes the '{}'::jsonb sentinel
-- into payload; payload_encrypted marks the row. Reads that need the payload
-- decrypt on demand via PostgresAdapter::episode_payload. Rows written
-- before this migration (or without a KEK) keep plaintext payload and
-- NULL payload_enc / payload_encrypted.
ALTER TABLE episodes ADD COLUMN payload_enc bytea;
ALTER TABLE episodes ADD COLUMN payload_encrypted boolean;

-- Hard purge (SPEC §8b) walks lineage from episodes: writer_sub drives
-- subject erasure, source_entity drives entity erasure.
CREATE INDEX episodes_writer_sub_idx ON episodes (tenant_id, writer_sub)
    WHERE writer_sub IS NOT NULL;
CREATE INDEX episodes_source_entity_idx ON episodes (tenant_id, source_entity)
    WHERE source_entity IS NOT NULL;
-- Provenance walks (chunks/facts derived from an erased episode set).
CREATE INDEX chunks_provenance_idx ON chunks (provenance);
CREATE INDEX facts_provenance_idx ON facts (provenance);
CREATE INDEX actions_actor_sub_idx ON actions (tenant_id, actor_sub)
    WHERE actor_sub IS NOT NULL;
CREATE INDEX audit_log_actor_sub_idx ON audit_log (tenant_id, actor_sub)
    WHERE actor_sub IS NOT NULL;
