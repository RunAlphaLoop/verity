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
}
