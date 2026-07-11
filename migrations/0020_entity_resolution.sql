-- Task #50: cross-source entity resolution & per-field source precedence
-- (SPEC §7f). When HubSpot and Salesforce both hold the "Acme" account, the L1
-- rows stay per-source and unmutated (§2: "a CRM row stays a row") — the merge
-- is a deterministic VIEW-TIME projection. Two config tables drive it:
--
--   entity_aliases      maps a source-native (source, entity_id) to a canonical
--                       entity key. The resolver (§7f) writes these; a
--                       (source, entity_id) with no alias is its own canonical.
--   entity_precedence   the per-field source order (§7f: `Amount: [salesforce,
--                       hubspot]`). Resolution is most-specific-wins:
--                       (canonical, field) → (canonical, '*') → ('*', '*').
--
-- Both are append-mostly config, upserted by admin; changing them just changes
-- what the merged view projects — no L1 row is ever rewritten.

CREATE TABLE entity_aliases (
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    source           text NOT NULL,
    entity_id        text NOT NULL,
    -- The canonical entity key these source rows resolve to, e.g. "account:acme".
    canonical_entity text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source, entity_id)
);

-- Forward lookup: every (source, entity_id) member of a canonical entity.
CREATE INDEX entity_aliases_canonical_idx
    ON entity_aliases (tenant_id, canonical_entity);

CREATE TABLE entity_precedence (
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    -- '*' = default across all canonical entities.
    canonical_entity text NOT NULL,
    -- '*' = default across all fields for this canonical entity.
    field            text NOT NULL,
    -- Ordered source names, highest precedence first. A source absent from this
    -- list ranks last at merge time; ties break by most-recent valid_from.
    source_order     text[] NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, canonical_entity, field)
);
