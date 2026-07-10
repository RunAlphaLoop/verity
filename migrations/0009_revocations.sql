-- Revocation tombstones (SPEC §7b rule 3, roadmap task 10). Written
-- synchronously on group-membership DELETE, BEFORE the SpiceDB tuple is
-- removed — fail-closed ordering: over-hide during the window, never
-- under-hide. Durable in Postgres so the exclusion survives cold start.
--
-- v0.1 contract (documented in crates/verity-server/src/revocation.rs):
-- a row's `token` is subtracted from EVERY resolved principal set in this
-- tenant for VERITY_REVOCATION_WINDOW_SECS (default 300s) after `at` — at
-- scope-resolution time (open_scope) and at read time for already-minted
-- handles (recall/activity/brief). `principal` records which member subtree
-- lost the group principal, for audit; enforcement keys on (tenant, token, at).
CREATE TABLE revocations (
    id        uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    principal text NOT NULL,
    token     int  NOT NULL,
    at        timestamptz NOT NULL DEFAULT now()
);
-- The read-path query: all tokens revoked in-window for a tenant.
CREATE INDEX revocations_tenant_at_idx ON revocations (tenant_id, at DESC);
