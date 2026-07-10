-- Minted scoped webhook URLs + quarantine preview (roadmap task 8), the
-- principal-token registry the connector plane allocates against, and the
-- MediaObject blob store (task 9). Append-only migration file.

-- A webhook is a capability: the URL token IS the credential, so only its
-- sha256 is stored. Visibility/entity_scope/confidentiality are bound at
-- mint time by an admin; posted payloads may NARROW visibility, never widen.
CREATE TABLE webhooks (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    token_hash      text NOT NULL UNIQUE,
    visibility      int[] NOT NULL,
    entity_scope    text[] NOT NULL DEFAULT '{}',
    confidentiality smallint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz
);
CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id, created_at DESC);

-- Unparseable / unknown-shaped webhook payloads land here for admin preview
-- instead of being permissively indexed (fail closed, SPEC §5e).
CREATE TABLE quarantine_preview (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    webhook_id uuid NOT NULL REFERENCES webhooks(id),
    payload    jsonb NOT NULL,
    reason     text NOT NULL,
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quarantine_preview_tenant_at_idx ON quarantine_preview (tenant_id, at DESC);

-- Principal-token registry: connectors map source-native principals
-- (email addresses, group ids) to the materialized int tokens chunks carry.
-- Allocation is max(token)+1 per tenant, stable for existing principals.
CREATE TABLE principals (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    principal text NOT NULL,
    token     int  NOT NULL,
    PRIMARY KEY (tenant_id, principal),
    UNIQUE (tenant_id, token)
);

-- MediaObject store (task 9): raw blobs, addressed by uuid, served only via
-- HMAC-signed URLs. Text-like media additionally chunk into the retrieval
-- index; binary media is store-only in v0.1.
CREATE TABLE media (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    sha256     text NOT NULL,
    mime       text NOT NULL,
    filename   text,
    bytes      bytea NOT NULL,
    size_bytes bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX media_tenant_idx ON media (tenant_id, created_at DESC);
