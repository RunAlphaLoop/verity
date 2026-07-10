-- Sleep-time consolidation plane (SPEC §2 L2 + knowledge items, §7d tagging):
-- lease bookkeeping for the async worker, tag suggestions from probabilistic
-- tagging, and a stored statement embedding on knowledge for similarity-merge
-- (support accrual). Append-only migration file.

-- One row per episode the consolidation worker has ever leased. An episode is
-- eligible for (re-)lease when it has no row, or its row is unprocessed and
-- the lease expired (worker died mid-extraction). processed_at set = terminal.
-- CDC episodes never appear here: L1 extraction from CDC is deterministic at
-- ingest time (SPEC §2 L1 — "never LLM extraction"), so the lease query skips
-- kind = 'cdc_event' entirely.
CREATE TABLE episode_processing (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    episode_id   uuid NOT NULL REFERENCES episodes(id),
    leased_until timestamptz NOT NULL,
    processed_at timestamptz,
    worker       text,
    PRIMARY KEY (tenant_id, episode_id)
);
CREATE INDEX episode_processing_unprocessed_idx
    ON episode_processing (tenant_id, leased_until) WHERE processed_at IS NULL;

-- Probabilistic entity-tag suggestions (SPEC §7d): inferred tags are
-- suggestions by default — a human (or the explicit VERITY_AUTO_TAG=1 opt-in
-- at >= 0.9 confidence) applies them. Applying a tag to a previously
-- narrower/zero-tag chunk WIDENS what entity-bound scopes can retrieve, which
-- is why suggest-only is the default posture.
CREATE TABLE tag_suggestions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    chunk_id   uuid NOT NULL REFERENCES chunks(id),
    tag        text NOT NULL,
    confidence real NOT NULL,
    status     text NOT NULL DEFAULT 'suggested',  -- suggested | approved | rejected | auto_applied
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tag_suggestions_tenant_status_idx ON tag_suggestions (tenant_id, status);

-- Statement embedding for knowledge similarity-merge (SPEC v1.3 §2, candidate
-- extraction step 1: similar proposals accrue support on the existing item
-- instead of minting duplicates). Candidates have no §7g chunk until publish,
-- so the merge check compares against embeddings stored on the knowledge row
-- itself (candidate AND published), with normalized-exact-match as the
-- encoder-less fallback. Nullable: rows proposed before this migration (or
-- while the encoder is down) simply never embedding-merge.
ALTER TABLE knowledge ADD COLUMN statement_embedding vector(384);
