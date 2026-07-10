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
}
