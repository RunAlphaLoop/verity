-- Source manifests v1 (SPEC §5e.3, task 30): connectors are config. The YAML
-- is stored verbatim (it is the reviewable artifact an admin approved); the
-- server re-parses it with verity-manifest on every use — no derived columns
-- to drift. Append-only migration file.

CREATE TABLE manifests (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    name        text NOT NULL,
    yaml        text NOT NULL,
    -- draft | active. Uploads (and re-uploads) are always drafts; only
    -- POST /v1/manifests/{id}/activate — the human gate — makes one active,
    -- and any yaml change demotes it back to draft for re-approval.
    status      text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active')),
    -- Who approved activation (the recorded human gate; also mirrored into
    -- audit_log by the activate handler).
    approved_by text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX manifests_tenant_idx ON manifests (tenant_id, created_at DESC);

-- A minted webhook may be bound to a manifest at mint time: inbound payloads
-- then route through the manifest runtime (signature verify → predicate
-- routing → mapping → acl_policy) instead of the native payload shape.
ALTER TABLE webhooks ADD COLUMN manifest_id uuid REFERENCES manifests(id);
