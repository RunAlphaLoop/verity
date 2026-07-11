-- Cross-source entity resolution — the evidence ledger + config + fold output
-- (docs/design/cross-source-entity-resolution.md §4.1). This sits UPSTREAM of
-- the §7f resolver shipped in 0020: it is the append-only substrate the offline
-- fold (S4) reads to PRODUCE the `entity_aliases` rows `merged_record` already
-- consumes. The read path (merged_record, load_precedence, the entity_tags
-- pre-filter) is unchanged — these tables are written only in the worker plane.
--
-- Guiding model (§design intro): "resolution decisions are evidence, not edits."
-- A canonical entity is a cluster a pure deterministic fold produces from this
-- append-only, provenance-tagged ledger. An unmerge is just retracting an edge
-- (stamping valid_to) + re-folding — reversibility is structural.

-- entity_evidence — THE LEDGER. Append-only. Source of truth; everything else
-- (entity_aliases, chunk entity_tags, entity_link_meta) is derived from it.
-- Invalidate-don't-delete: a retraction stamps valid_to, never DELETE (§2 L1).
-- A row is *live* iff valid_to IS NULL; the fold reads only live rows.
CREATE TABLE entity_evidence (
    evidence_id      uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    -- The two canonicalized refs this evidence links, e.g.
    -- left  = 'salesforce:001xACME', right = 'hubspot:4207'.
    left_ref         text NOT NULL,
    right_ref        text NOT NULL,
    -- 1 = deterministic strong key, 2 = strong-but-fuzzy, 3 = unstructured mention.
    tier             smallint NOT NULL,
    -- admin_crosswalk / crm_fk / email_exact / domain_match / external_id /
    -- name+domain_fuzzy / llm_mention / human_confirmed / human_rejected.
    method           text NOT NULL,
    -- The actual matched value ('jane@acme.dev', 'acme.com') — load-bearing for
    -- denylist enforcement + audit.
    key_value        text,
    -- e.g. 'customer_contact' vs 'internal_directory' — the actor-email
    -- population fence (§4.4). An edge may only form WITHIN a namespace.
    key_namespace    text,
    -- null for Tier-1 (deterministic); blocker/judge score for Tier-2/3.
    score            real,
    -- Lineage pointer back to the L0 record/chunk that produced this evidence.
    evidence_l0_ref  text,
    -- +1 = link, -1 = anti-link (a human "these are NOT the same" / must-not-link).
    polarity         smallint NOT NULL DEFAULT 1,
    valid_from       timestamptz NOT NULL DEFAULT now(),
    -- invalidate-don't-delete: retraction stamps valid_to, never DELETE.
    valid_to         timestamptz,
    -- bi-temporal chain (§2 L1).
    superseded_by    uuid REFERENCES entity_evidence(evidence_id)
);

-- Fold traversal: pull all live evidence touching a given ref (either side).
CREATE INDEX entity_evidence_left_idx  ON entity_evidence (tenant_id, left_ref);
CREATE INDEX entity_evidence_right_idx ON entity_evidence (tenant_id, right_ref);
-- Review-queue view (§4.1): live evidence by tier.
CREATE INDEX entity_evidence_tier_idx  ON entity_evidence (tenant_id, tier, valid_to);

-- entity_resolution_config — key-quality allowlist + denylist + merge guards
-- (§4.1). The over-merge control; a SECURITY control, mandatory even in MVP
-- (§3.2: a false merge is a scope leak). Tenant-scoped, admin-driven, versioned.
-- Keyed per (tenant, key_kind, key_namespace) so an edge may only form within a
-- namespace (the actor-email fence, §4.4).
CREATE TABLE entity_resolution_config (
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    -- email / domain / phone / external_id.
    key_kind            text NOT NULL,
    -- e.g. 'customer_contact', 'internal_directory' — an edge may only form
    -- within a namespace.
    key_namespace       text NOT NULL,
    -- May this key kind ever FORM a merge edge.
    eligible_as_edge    boolean NOT NULL DEFAULT true,
    -- Free-mail ('gmail.com'), role locals ('info@','sales@'), placeholders
    -- ('example.com') — NEVER an edge.
    denylist_values     text[] NOT NULL DEFAULT '{}',
    -- default 2 — a single MEDIUM key (e.g. shared domain) may not auto-merge
    -- alone (grafted from P0).
    min_independent_keys smallint NOT NULL DEFAULT 2,
    -- OSS default true.
    auto_merge_tier1    boolean NOT NULL DEFAULT true,
    -- default FALSE — the Tier-3 auto-link kill switch.
    auto_link_tier3     boolean NOT NULL DEFAULT false,
    -- Tier-3 NIL threshold (§5).
    tau_nil             real,
    -- Tier-3 top1-top2 abstain margin (§5).
    margin_delta        real,
    -- Union-find components exceeding this are quarantined, not merged.
    component_size_cap  integer,
    PRIMARY KEY (tenant_id, key_kind, key_namespace)
);

-- entity_link_meta — materialized fold output the read path is allowed to see
-- (§4.1, §4.3). One row per live canonical link AND per materialized chunk tag:
-- folds the confidence badge (per link) and the per-tag provenance sidecar into
-- one surface, so "which evidence added which tag/link" is explicit for the
-- scope inspector and for surgical audit / split.
CREATE TABLE entity_link_meta (
    tenant_id          uuid NOT NULL REFERENCES tenants(id),
    -- 'alias_member' (a (source,entity_id)) or 'chunk_tag' (a (chunk_id, tag)).
    subject_kind       text NOT NULL,
    -- The member ref or the chunk_id.
    subject_ref        text NOT NULL,
    -- The link target: the canonical entity, or the tag value.
    canonical_entity   text NOT NULL,
    -- deterministic / human_confirmed / approximated.
    confidence         text NOT NULL,
    -- Highest-tier method that justified it.
    strongest_method   text,
    -- The live entity_evidence rows that produced it — enables surgical per-tag
    -- removal on split.
    justifying_evidence uuid[] NOT NULL DEFAULT '{}',
    -- Corroboration depth.
    evidence_count     smallint NOT NULL DEFAULT 0,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_kind, subject_ref, canonical_entity)
);
