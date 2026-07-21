-- 0038_revoked_principal.sql — durable, INDEFINITE deprovision record (M2 2a).
--
-- Distinct from `revocations` (0009), which is WINDOWED to RETENTION_SECS (~13h)
-- and HANDLE-RELATIVE (`at >= issued_at`). A principal DEPROVISION is permanent:
-- a deprovisioned human re-minting `user:<verified-email>` years later must STILL
-- be denied their old DIRECT-granted chunks. So this set has NO time bound and is
-- consulted UNCONDITIONALLY (no `issued_at` comparison) by the read-path subtract
-- and the mint active-gate.
--
-- `reinstated_at IS NULL` => currently revoked. Reinstate is an in-place UPDATE
-- (invalidate-don't-delete); already-swept chunks stay invalidated until re-ingest
-- (honest — a reinstate only lets NEW grants resolve again).
CREATE TABLE revoked_principal (
    tenant_id     uuid        NOT NULL REFERENCES tenants(id),
    token         int         NOT NULL,
    principal     text        NOT NULL,            -- canonical user:<verified-email>, forensic
    revoked_at    timestamptz NOT NULL DEFAULT now(),
    reinstated_at timestamptz,                     -- NULL = currently revoked
    PRIMARY KEY (tenant_id, token)
);

-- Keeps the recall subtraction O(revoked-in-tenant): a partial index over the
-- ACTIVE (currently-revoked) rows only, no time predicate. The read-path fetch is
-- `SELECT token FROM revoked_principal WHERE tenant_id=$1 AND reinstated_at IS NULL`.
CREATE INDEX revoked_principal_active_idx
    ON revoked_principal (tenant_id) WHERE reinstated_at IS NULL;
