//! In-memory L1 current-truth projection (SPEC §3, §4b): the `get` hot path.
//!
//! `CachedAdapter` wraps any `StorageAdapter` and serves `current_fact` from a
//! bounded in-process cache, write-through-invalidated by `upsert_fact`. This
//! is correct for the single-process deployment Milestone A targets; replica
//! coherence arrives with the changelog stream in Milestone B, at which point
//! this cache is fed by changelog events instead of local invalidation.
//!
//! Enforcement note: `current_fact` carries no visibility filtering yet (L1
//! records are tenant-partitioned only until the scope engine lands); the
//! cache therefore never has to answer a scoped read from memory. When brief
//! scoping lands, cached reads pass the same enforcement gate as everything
//! else — the cache sits BELOW the gate, keyed by tenant.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use moka::sync::Cache;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

pub struct CachedAdapter<S> {
    inner: S,
    facts: Cache<(TenantId, FactKey), FactRow>,
}

impl<S: StorageAdapter> CachedAdapter<S> {
    pub fn new(inner: S, capacity: u64) -> Self {
        Self {
            inner,
            facts: Cache::new(capacity),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

#[async_trait]
impl<S: StorageAdapter> StorageAdapter for CachedAdapter<S> {
    async fn create_tenant(&self, name: &str) -> Result<TenantId> {
        self.inner.create_tenant(name).await
    }

    async fn append_episode(&self, episode: NewEpisode) -> Result<EpisodeId> {
        self.inner.append_episode(episode).await
    }

    async fn upsert_fact(&self, fact: FactWrite) -> Result<FactUpsertOutcome> {
        let cache_key = (fact.tenant_id, fact.key.clone());
        let outcome = self.inner.upsert_fact(fact).await?;
        match outcome {
            FactUpsertOutcome::Inserted | FactUpsertOutcome::Superseded => {
                // Invalidate-on-write: the next read repopulates from the store,
                // so the cache can never serve a superseded value.
                self.facts.invalidate(&cache_key);
            }
            FactUpsertOutcome::Unchanged | FactUpsertOutcome::StaleEvent => {}
        }
        Ok(outcome)
    }

    async fn current_fact(&self, tenant: TenantId, key: &FactKey) -> Result<Option<FactRow>> {
        let cache_key = (tenant, key.clone());
        if let Some(hit) = self.facts.get(&cache_key) {
            return Ok(Some(hit));
        }
        let row = self.inner.current_fact(tenant, key).await?;
        if let Some(ref fact) = row {
            self.facts.insert(cache_key, fact.clone());
        }
        Ok(row)
    }

    async fn fact_as_of(
        &self,
        tenant: TenantId,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        // Historical reads always go to the store.
        self.inner.fact_as_of(tenant, key, as_of).await
    }

    async fn upsert_chunks(&self, chunks: Vec<ChunkWrite>) -> Result<usize> {
        self.inner.upsert_chunks(chunks).await
    }

    async fn recall(&self, query: RecallQuery) -> Result<Vec<RecallHit>> {
        self.inner.recall(query).await
    }

    async fn record_action(&self, action: ActionWrite) -> Result<bool> {
        self.inner.record_action(action).await
    }

    async fn retire_entity(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64> {
        let retired = self
            .inner
            .retire_entity(tenant, source, entity_id, deleted_at)
            .await?;
        if retired > 0 {
            // The cache is keyed by (tenant, FactKey) and can't enumerate an
            // entity's fields; deletes are rare, so a full flush keeps the
            // never-serve-superseded guarantee without per-key bookkeeping.
            self.facts.invalidate_all();
        }
        Ok(retired)
    }

    async fn activity(&self, query: ActivityQuery) -> Result<Vec<ActionRecord>> {
        self.inner.activity(query).await
    }
}
