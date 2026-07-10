-- Knowledge layer (SPEC v1.3 §2): entity-free semantic memories promoted from
-- scoped episodic memory. This migration ships the deterministic slice:
-- proposals, evidence lineage, review states, and the chunk-side carve-out
-- marker. Automatic candidate extraction arrives with L2 workers.

CREATE TABLE knowledge (
    id                 uuid PRIMARY KEY,
    tenant_id          uuid NOT NULL REFERENCES tenants(id),
    statement          text NOT NULL,
    categories         text[] NOT NULL DEFAULT '{}',
    status             text NOT NULL,   -- candidate | quarantined | published | invalidated
    quarantine_reason  text,
    distinct_entities  int NOT NULL DEFAULT 0,
    episode_count      int NOT NULL DEFAULT 0,
    writer_count       int NOT NULL DEFAULT 0,
    has_tier1_evidence boolean NOT NULL DEFAULT false,
    proposed_by_sub    text,
    proposed_by_azp    text,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_reinforced    timestamptz NOT NULL DEFAULT now(),
    published_at       timestamptz,
    invalidated_at     timestamptz,
    invalidated_reason text
);
CREATE INDEX knowledge_tenant_status_idx ON knowledge (tenant_id, status);

-- Lineage: which scoped episodes support which knowledge. Powers k-support
-- counting, audit, and the retraction cascade. Never exposed in recall.
CREATE TABLE knowledge_evidence (
    knowledge_id uuid NOT NULL REFERENCES knowledge(id),
    episode_id   uuid NOT NULL REFERENCES episodes(id),
    entity       text,            -- entity attribution for distinct-entity support
    writer_azp   text,
    trust_tier   smallint NOT NULL,
    PRIMARY KEY (knowledge_id, episode_id)
);
CREATE INDEX knowledge_evidence_episode_idx ON knowledge_evidence (episode_id);

-- Chunk-side carve-out marker (SPEC §7g): entity-bound scopes admit
-- kind='knowledge' chunks as the one verified exception to zero-tag exclusion.
ALTER TABLE chunks ADD COLUMN kind text NOT NULL DEFAULT 'content';
ALTER TABLE chunks ADD COLUMN categories text[] NOT NULL DEFAULT '{}';
CREATE INDEX chunks_kind_idx ON chunks (tenant_id, kind) WHERE kind <> 'content';
