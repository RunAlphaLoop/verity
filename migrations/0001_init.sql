-- Verity Milestone A schema: L0 evidence log, L1 bi-temporal facts, chunk store.
-- SPEC.md §2 (memory model), §3 (storage). Append-only migration file.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_search;

CREATE TABLE tenants (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- L0: immutable evidence log. Nothing here is ever updated or deleted
-- (hard purge is a separate crypto-shredding pipeline, SPEC §8).
CREATE TABLE episodes (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    source        text NOT NULL,           -- e.g. 'hubspot', 'gdrive', 'agent'
    source_entity text,                    -- source-native entity id
    kind          text NOT NULL,           -- cdc_event | webhook | doc_version | observation | ...
    payload       jsonb NOT NULL,
    content_hash  text NOT NULL,
    trust_tier    smallint NOT NULL,       -- 1 = authoritative (CDC), 2 = observation
    writer_sub    text,                    -- user principal from the auth token
    writer_azp    text,                    -- agent identity
    recorded_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX episodes_tenant_source_idx ON episodes (tenant_id, source, recorded_at);
CREATE INDEX episodes_hash_idx ON episodes (tenant_id, content_hash);

-- L1: canonical records, bi-temporal, deterministic keyed upserts.
-- Current value of a field = row with valid_to IS NULL.
CREATE TABLE facts (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    source        text NOT NULL,
    entity_id     text NOT NULL,
    field         text NOT NULL,
    value         jsonb NOT NULL,
    valid_from    timestamptz NOT NULL,    -- event time: when true in the world
    valid_to      timestamptz,             -- NULL = current
    superseded_by uuid REFERENCES facts(id),
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    provenance    uuid NOT NULL REFERENCES episodes(id)
);
-- Exactly one current row per key.
CREATE UNIQUE INDEX facts_current_key_idx
    ON facts (tenant_id, source, entity_id, field) WHERE valid_to IS NULL;
-- As-of-time queries.
CREATE INDEX facts_asof_idx ON facts (tenant_id, source, entity_id, field, valid_from);

-- Chunk store: the retrieval unit for unstructured content.
-- Scope payload (visibility tokens, entity tags) is indexed for mandatory pre-filtering.
CREATE TABLE chunks (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    source        text NOT NULL,
    document_id   text NOT NULL,           -- stable source document id
    seq           int  NOT NULL,           -- chunk order within document
    content       text NOT NULL,
    content_hash  text NOT NULL,           -- drives incremental re-embedding
    embedding     vector(384),             -- named-vector registry comes with model migration (§5c)
    visibility    int[] NOT NULL,          -- materialized principal-token ids; empty = invisible (fail closed)
    entity_tags   text[] NOT NULL DEFAULT '{}',
    confidentiality smallint NOT NULL DEFAULT 1,  -- 0 public / 1 internal / 2 confidential / 3 restricted
    trust_tier    smallint NOT NULL,
    valid_from    timestamptz NOT NULL,
    valid_to      timestamptz,             -- NULL = current
    provenance    uuid NOT NULL REFERENCES episodes(id),
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source, document_id, seq, valid_from)
);
CREATE INDEX chunks_visibility_idx ON chunks USING gin (visibility);
CREATE INDEX chunks_entity_tags_idx ON chunks USING gin (entity_tags);
CREATE INDEX chunks_embedding_idx ON chunks
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

-- BM25 (pg_search / Tantivy) index over current chunk content.
CREATE INDEX chunks_bm25_idx ON chunks
    USING bm25 (id, content) WITH (key_field = 'id');
