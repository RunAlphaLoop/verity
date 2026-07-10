-- Task #35 (v0.3): L3 materialized briefs + embedding-model migration tooling.
-- SPEC §2 (L3 derived views, derived-scope inheritance), §5c (embedding-model
-- migration: dual named-vector backfill + query routing cutover). Append-only.

-- =========================================================================
-- PART A — L3 materialized briefs (SPEC §2 L3).
-- =========================================================================
-- One materialized brief per (tenant, entity). The body is the recomputed
-- summary (recent_memory + recent_activity, materialized under a broad
-- MATERIALIZATION scope), NOT the served payload — the served brief is always
-- re-derived under the CALLER's scope at read time (main.rs::brief), so the
-- materialized row can never leak an item the caller couldn't see.
--
-- source_visibility is the INTERSECTION of the visibility arrays of every
-- contributing chunk/action (SPEC §2 "derived-scope inheritance": a brief is
-- visible only to principals present in ALL its sources — fail-closed). It
-- gates only the brief-level SUMMARY metadata, never per-item serving. An
-- empty intersection ('{}') means the summary is visible to nobody: strictly
-- fail-closed, exactly like an empty chunk visibility.
--
-- Staleness is APP-MARKED (Rust), never a DB trigger (keeps lineage logic in
-- one place and off the write hot path). A write to any chunk/action/fact for
-- an entity flips is_stale=true synchronously (cheap UPDATE); recompute is
-- lazy (on-read, debounced) or batch (the sleep-time refresh endpoint).
CREATE TABLE briefs (
    tenant_id         uuid NOT NULL REFERENCES tenants(id),
    entity            text NOT NULL,
    body              jsonb NOT NULL DEFAULT '{}',
    -- INTERSECTION of contributing chunk/action visibilities (fail-closed).
    -- '{}' = summary visible to nobody.
    source_visibility int[] NOT NULL DEFAULT '{}',
    is_stale          boolean NOT NULL DEFAULT true,
    last_synced_at    timestamptz,
    -- Monotonic marker bumped on every stale-marking write; lets a reader tell
    -- whether the materialized body predates known writes (SPEC §2 metadata).
    source_version    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, entity)
);
-- The batch refresh endpoint (the sleep-time path) scans stale rows per tenant.
CREATE INDEX briefs_stale_idx ON briefs (tenant_id) WHERE is_stale;

-- =========================================================================
-- PART B — Embedding-model migration tooling (SPEC §5c).
-- =========================================================================
-- The model registry (SPEC §5c named-vector record: {model_id, dim, revision}).
-- is_default marks the model the ingest/query paths use unless a cutover is
-- active. The dual-vector migration registers a SECOND model here, backfills
-- chunks.embedding_v2 under it, then flips the routing setting to cut over.
CREATE TABLE embedding_models (
    id         text PRIMARY KEY,          -- e.g. 'all-MiniLM-L6-v2', 'bge-small-en-v2'
    dim        int NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    is_default boolean NOT NULL DEFAULT false
);
-- The bundled encoder is the initial default (matches the vector(384) schema
-- and verity_encoder::MODEL_ID's short name). Idempotent seed.
INSERT INTO embedding_models (id, dim, is_default)
VALUES ('all-MiniLM-L6-v2', 384, true)
ON CONFLICT (id) DO NOTHING;

-- The second named vector (SPEC §5c step 1: dual named-vector backfill). Same
-- dim (384) as the primary column, so this is honest plumbing + routing, NOT a
-- real model swap — a true dim change needs a wider column (documented in
-- docs/EMBEDDING_MIGRATION.md). Nullable: NULL = not yet backfilled under the
-- new model; the backfill worker walks these and fills them from stored
-- canonical content (re-embed from text, never re-fetch — SPEC §5c).
ALTER TABLE chunks ADD COLUMN embedding_v2 vector(384);
-- Per-chunk marker of which model filled embedding_v2 (lineage; also lets the
-- backfill skip rows already done under the target model on restart).
ALTER TABLE chunks ADD COLUMN embedding_v2_model text REFERENCES embedding_models(id);
CREATE INDEX chunks_embedding_v2_idx ON chunks
    USING hnsw (embedding_v2 vector_cosine_ops) WITH (m = 16, ef_construction = 64);
-- Backfill-coverage probe (the cutover gate reads this): current chunks still
-- lacking embedding_v2. Partial so it stays cheap on a fully-backfilled corpus.
CREATE INDEX chunks_embedding_v2_missing_idx ON chunks (tenant_id)
    WHERE valid_to IS NULL AND embedding IS NOT NULL AND embedding_v2 IS NULL;

-- Runtime settings (SPEC §5c step 2: query routing cutover is a routing
-- decision, per-tenant or global). A row per (tenant, key); tenant_id NULL =
-- global default. The recall dense leg reads embedding_v2 when
-- 'embedding_route' = 'v2' for the query's tenant (row match wins over global).
CREATE TABLE settings (
    tenant_id  uuid REFERENCES tenants(id),   -- NULL = global default
    key        text NOT NULL,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- One row per (scope, key); the NULL-tenant global row needs its own uniqueness.
CREATE UNIQUE INDEX settings_key_idx
    ON settings (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key);
