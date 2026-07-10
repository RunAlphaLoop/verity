use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::types::*;

/// The single pluggability seam (SPEC §3). Everything above this trait —
/// scope compilation, enforcement, ranking — is shared across profiles;
/// everything below is engine-specific (Postgres profile now, Qdrant later).
///
/// Contract every adapter must uphold:
/// - Reads honor `Scope` exactly: visibility intersection, entity-tag subset
///   semantics, confidentiality ceiling, tenant partition. An empty principal
///   set returns nothing.
/// - `upsert_fact` is deterministic and idempotent: same write replayed yields
///   `Unchanged`, never a duplicate current row.
/// - L0/L1 rows are never updated in place or deleted.
#[async_trait]
pub trait StorageAdapter: Send + Sync {
    async fn create_tenant(&self, name: &str) -> Result<TenantId>;

    /// Append to the immutable L0 evidence log.
    async fn append_episode(&self, episode: NewEpisode) -> Result<EpisodeId>;

    /// Deterministic bi-temporal L1 upsert keyed on (source, entity_id, field).
    async fn upsert_fact(&self, fact: FactWrite) -> Result<FactUpsertOutcome>;

    /// Current value for a key (valid_to IS NULL). The hot path behind `get`.
    async fn current_fact(&self, tenant: TenantId, key: &FactKey) -> Result<Option<FactRow>>;

    /// Value as of a point in event time (bi-temporal read).
    async fn fact_as_of(
        &self,
        tenant: TenantId,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>>;

    /// Idempotent chunk upsert keyed on (source, document_id, seq, valid_from).
    async fn upsert_chunks(&self, chunks: Vec<ChunkWrite>) -> Result<usize>;

    /// Scoped hybrid recall: filtered ANN and/or BM25, fused. Filters are
    /// pushed into the index — pre-filtering only, never truncate-then-authorize.
    async fn recall(&self, query: RecallQuery) -> Result<Vec<RecallHit>>;

    /// Append to the activity timeline (SPEC §2, Action records): writes the
    /// L0 episode and the timeline row in one transaction, and indexes the
    /// summary as a Tier-2 chunk so semantic recall surfaces it. Idempotent on
    /// (tenant, action_id) — returns false when the action was already recorded.
    async fn record_action(&self, action: ActionWrite) -> Result<bool>;

    /// Scoped timeline read. Same fail-closed contract as `recall`: empty
    /// principal set reads nothing; an entity-bound scope may only query
    /// entities it covers.
    async fn activity(&self, query: ActivityQuery) -> Result<Vec<ActionRecord>>;

    /// Newest current chunks for an entity — the brief's memory section and a
    /// timeline-style read. Same scope contract as `recall`; ordered by
    /// valid_from descending.
    async fn latest_chunks(
        &self,
        scope: &Scope,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<RecallHit>>;

    /// Propose a generalization for the knowledge layer (SPEC v1.3 §2). Runs
    /// the deterministic de-identification gate against the tenant's entity
    /// lexicon: gate-passing proposals become `Candidate`, failures are stored
    /// `Quarantined` with the reason (auditable, never retrievable). Support
    /// metrics (distinct entities, writers, tier-1 presence) are computed from
    /// the evidence episodes, never trusted from the caller.
    async fn propose_knowledge(&self, proposal: KnowledgeProposal) -> Result<KnowledgeItem>;

    /// Publish a candidate at broad visibility. Enforces the promotion gates:
    /// `distinct_entities >= k_min` and (`writer_count >= 2` or tier-1
    /// evidence). On success the statement is indexed as a `kind='knowledge'`
    /// chunk retrievable via the §7g carve-out. The category-size floor is NOT
    /// yet enforceable (needs entity→category facts) and is documented as such.
    async fn publish_knowledge(
        &self,
        tenant: TenantId,
        id: uuid::Uuid,
        visibility: Vec<PrincipalToken>,
        k_min: i32,
        embedding: Option<Vec<f32>>,
    ) -> Result<KnowledgeItem>;

    /// Review-queue listing (admin/audit plane).
    async fn list_knowledge(
        &self,
        tenant: TenantId,
        status: Option<KnowledgeStatus>,
    ) -> Result<Vec<KnowledgeItem>>;

    /// `memory.forget` (roadmap task 5): retire a chunk, or an episode and
    /// everything derived from it. Episode forget retires the episode's chunks
    /// and facts (valid_to = now), then runs the knowledge retraction cascade:
    /// its `knowledge_evidence` rows are deleted, distinct-entity support is
    /// recounted, and any published item whose support drops below 3 becomes
    /// `invalidated` (reason `support_withdrawn`) with its knowledge chunk
    /// retired. Invalidate-don't-delete throughout. Returns rows retired.
    async fn forget(&self, tenant: TenantId, ref_kind: ForgetRef, reason: &str) -> Result<u64>;

    /// Source hard-delete propagation (SPEC §8c, bi-temporal half): close all
    /// current facts for an entity at `deleted_at`. History stays queryable
    /// via `fact_as_of`; crypto-shred hard purge is a separate admin pipeline.
    /// Returns the number of facts retired.
    async fn retire_entity(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64>;

    // ---- L3 materialized briefs (SPEC §2 L3) ----
    //
    // These carry default implementations so profiles that have not yet built
    // the derived-view plane (e.g. the Qdrant adapter) stay compiling and fail
    // explicit rather than silently. The Postgres profile overrides them all.

    /// Recompute the materialized brief for `(tenant, entity)`: body =
    /// {recent_memory, recent_activity} materialized under a BROAD scope, and
    /// `source_visibility` = the INTERSECTION of the contributing chunk/action
    /// visibilities (derived-scope inheritance, fail-closed — SPEC §2). Clears
    /// `is_stale` and stamps `last_synced_at`. The returned row is the
    /// materialized metadata + cached summary, NEVER a served item set: the
    /// serving path re-derives items under the caller's scope.
    async fn refresh_brief(&self, _tenant: TenantId, _entity: &str) -> Result<MaterializedBrief> {
        Err(unsupported("refresh_brief"))
    }

    /// Read the materialized brief row (metadata + cached summary). None when
    /// the entity has never been materialized. No scope filtering here — the
    /// caller (server) gates the summary against `source_visibility` and serves
    /// items under the caller's scope.
    async fn get_brief(
        &self,
        _tenant: TenantId,
        _entity: &str,
    ) -> Result<Option<MaterializedBrief>> {
        Ok(None)
    }

    /// Synchronously mark every brief whose lineage includes any of `entities`
    /// STALE (SPEC §2: cheap lineage-walk marking on source change). Idempotent;
    /// bumps `source_version`. Non-existent briefs are ignored — they are
    /// materialized lazily on first read. Returns rows marked.
    async fn mark_briefs_stale(&self, _tenant: TenantId, _entities: &[String]) -> Result<u64> {
        Ok(0)
    }

    /// Batch-refresh all stale briefs for a tenant (the sleep-time path behind
    /// POST /v1/admin/briefs/refresh). Returns the number refreshed.
    async fn refresh_stale_briefs(&self, _tenant: TenantId) -> Result<u64> {
        Ok(0)
    }

    // ---- Embedding-model migration (SPEC §5c) ----

    /// Register a model in the named-vector registry (idempotent).
    async fn register_embedding_model(&self, _id: &str, _dim: i32) -> Result<()> {
        Err(unsupported("register_embedding_model"))
    }

    /// Chunks lacking `embedding_v2` (current, embeddable), for the backfill
    /// worker. Returns `(chunk_id, content)` so the caller re-embeds from stored
    /// canonical text (SPEC §5c: re-embed, never re-fetch). `tenant` None =
    /// all tenants. Ordered by id for stable batch pagination.
    async fn chunks_needing_v2(
        &self,
        _tenant: Option<TenantId>,
        _limit: i64,
    ) -> Result<Vec<(ChunkId, String)>> {
        Ok(Vec::new())
    }

    /// Write backfilled `embedding_v2` vectors under `model`. Returns rows
    /// written. Idempotent (only fills NULL v2 slots for the given ids).
    async fn fill_embedding_v2(&self, _model: &str, _rows: &[(ChunkId, Vec<f32>)]) -> Result<u64> {
        Err(unsupported("fill_embedding_v2"))
    }

    /// Backfill coverage over current embeddable chunks (SPEC §5c cutover gate).
    /// `tenant` None = global.
    async fn embedding_v2_coverage(&self, _tenant: Option<TenantId>) -> Result<EmbeddingCoverage> {
        Ok(EmbeddingCoverage {
            total: 0,
            covered: 0,
        })
    }

    /// The dense route in effect for `tenant` (per-tenant row wins over the
    /// global default; default V1). Read on the recall hot path.
    async fn embedding_route(&self, _tenant: TenantId) -> Result<EmbeddingRoute> {
        Ok(EmbeddingRoute::V1)
    }

    /// Flip the query-routing cutover (SPEC §5c step 2). `tenant` None = global.
    /// Storage records the setting unconditionally; the coverage gate lives in
    /// the server handler (refuse below 100% unless forced).
    async fn set_embedding_route(
        &self,
        _tenant: Option<TenantId>,
        _route: EmbeddingRoute,
    ) -> Result<()> {
        Err(unsupported("set_embedding_route"))
    }
}

fn unsupported(op: &str) -> StorageError {
    StorageError::InvalidInput(format!("{op} unsupported by this storage profile"))
}
