//! In-memory L1 current-truth projection (SPEC §3, §4b): the `get` hot path.
//!
//! `CachedAdapter` wraps any `StorageAdapter` and serves `current_fact` from a
//! bounded in-process cache, write-through-invalidated by `upsert_fact`. This
//! is correct for the single-process deployment Milestone A targets; replica
//! coherence arrives with the changelog stream in Milestone B, at which point
//! this cache is fed by changelog events instead of local invalidation.
//!
//! Enforcement note: the cache sits BELOW the scope gate. Its key is
//! scope-INDEPENDENT (`(tenant, FactKey)`) so every principal shares one cached
//! row and the hit rate is not fragmented per-scope. Visibility is enforced
//! ABOVE the cache — on both a HIT and a MISS — by applying the shared
//! `fact_visible` predicate (verity-core) to whatever the cache/store yields.
//! This is the "one shared layer above StorageAdapter" the non-negotiables
//! require: the SQL predicate the Postgres profile pushes and this Rust check
//! are the same rule, and must agree. The cache never stores a scope, so it can
//! never leak a row across scopes.

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

    /// Drop every cached L1 row. Used by the hard-purge path (SPEC §8b
    /// erasure), which deletes fact rows underneath this cache via the inner
    /// adapter — same rationale as the retire_entity flush: purges are rare,
    /// correctness beats bookkeeping.
    pub fn flush_facts(&self) {
        self.facts.invalidate_all();
    }
}

#[async_trait]
impl<S: StorageAdapter> StorageAdapter for CachedAdapter<S> {
    async fn create_tenant(&self, name: &str) -> Result<TenantId> {
        self.inner.create_tenant(name).await
    }

    async fn list_tenants(&self, limit: i64) -> Result<Vec<TenantRow>> {
        self.inner.list_tenants(limit).await
    }

    async fn count_tenants(&self) -> Result<i64> {
        self.inner.count_tenants().await
    }

    async fn get_tenant(&self, tenant: TenantId) -> Result<Option<TenantRow>> {
        self.inner.get_tenant(tenant).await
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

    async fn current_fact(&self, scope: &Scope, key: &FactKey) -> Result<Option<FactRow>> {
        // The cache key is scope-independent (preserves hit rate across
        // principals); the scope gate is applied ABOVE the cache to the row it
        // yields — on both HIT and MISS — via the shared `fact_visible`.
        let cache_key = (scope.tenant_id, key.clone());
        if let Some(hit) = self.facts.get(&cache_key) {
            // Re-gate the cached row against THIS scope: the row was cached by
            // whichever principal populated it, but visibility is decided here,
            // not by who warmed the cache.
            return Ok(fact_visible(scope, &hit).then_some(hit));
        }
        // MISS: the inner adapter applies the SQL visibility pre-filter, so it
        // only returns a row this scope may see. That row is a real, current
        // fact — safe to cache under the scope-independent key. A narrower scope
        // that can't see the fact simply gets None, caches nothing, and a wider
        // scope re-fetches: a missed caching opportunity, never a leak. We still
        // re-check `fact_visible` above (defense in depth; the SQL already
        // filtered).
        let row = self.inner.current_fact(scope, key).await?;
        if let Some(ref fact) = row {
            self.facts.insert(cache_key, fact.clone());
        }
        Ok(row.filter(|r| fact_visible(scope, r)))
    }

    async fn fact_as_of(
        &self,
        scope: &Scope,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        // Historical reads always go to the store; the store applies the SQL
        // visibility pre-filter, and we re-check above for defense in depth.
        Ok(self
            .inner
            .fact_as_of(scope, key, as_of)
            .await?
            .filter(|r| fact_visible(scope, r)))
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

    async fn latest_chunks(
        &self,
        scope: &Scope,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<RecallHit>> {
        self.inner.latest_chunks(scope, entity, limit).await
    }

    async fn propose_knowledge(&self, proposal: KnowledgeProposal) -> Result<KnowledgeItem> {
        self.inner.propose_knowledge(proposal).await
    }

    async fn publish_knowledge(
        &self,
        tenant: TenantId,
        id: uuid::Uuid,
        visibility: Vec<PrincipalToken>,
        k_min: i32,
        embedding: Option<Vec<f32>>,
    ) -> Result<KnowledgeItem> {
        self.inner
            .publish_knowledge(tenant, id, visibility, k_min, embedding)
            .await
    }

    async fn list_knowledge(
        &self,
        tenant: TenantId,
        status: Option<KnowledgeStatus>,
    ) -> Result<Vec<KnowledgeItem>> {
        self.inner.list_knowledge(tenant, status).await
    }

    async fn forget(&self, tenant: TenantId, ref_kind: ForgetRef, reason: &str) -> Result<u64> {
        let retired = self.inner.forget(tenant, ref_kind, reason).await?;
        // Episode forget may retire L1 facts; the count blends chunks and
        // facts, so any non-zero episode forget flushes (same rationale as
        // retire_entity: forgets are rare, correctness beats bookkeeping).
        // Chunk forget never touches facts, so the cache stays warm.
        if retired > 0 && matches!(ref_kind, ForgetRef::Episode(_)) {
            self.facts.invalidate_all();
        }
        Ok(retired)
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

    async fn refresh_brief(&self, tenant: TenantId, entity: &str) -> Result<MaterializedBrief> {
        self.inner.refresh_brief(tenant, entity).await
    }

    async fn get_brief(&self, tenant: TenantId, entity: &str) -> Result<Option<MaterializedBrief>> {
        self.inner.get_brief(tenant, entity).await
    }

    async fn mark_briefs_stale(&self, tenant: TenantId, entities: &[String]) -> Result<u64> {
        self.inner.mark_briefs_stale(tenant, entities).await
    }

    async fn refresh_stale_briefs(&self, tenant: TenantId) -> Result<u64> {
        self.inner.refresh_stale_briefs(tenant).await
    }

    async fn register_embedding_model(&self, id: &str, dim: i32) -> Result<()> {
        self.inner.register_embedding_model(id, dim).await
    }

    async fn chunks_needing_v2(
        &self,
        tenant: Option<TenantId>,
        limit: i64,
    ) -> Result<Vec<(ChunkId, String)>> {
        self.inner.chunks_needing_v2(tenant, limit).await
    }

    async fn fill_embedding_v2(&self, model: &str, rows: &[(ChunkId, Vec<f32>)]) -> Result<u64> {
        self.inner.fill_embedding_v2(model, rows).await
    }

    async fn embedding_v2_coverage(&self, tenant: Option<TenantId>) -> Result<EmbeddingCoverage> {
        self.inner.embedding_v2_coverage(tenant).await
    }

    async fn embedding_route(&self, tenant: TenantId) -> Result<EmbeddingRoute> {
        self.inner.embedding_route(tenant).await
    }

    async fn set_embedding_route(
        &self,
        tenant: Option<TenantId>,
        route: EmbeddingRoute,
    ) -> Result<()> {
        self.inner.set_embedding_route(tenant, route).await
    }

    // Phase-2 connector-credential intake: pure pass-through to the inner
    // adapter (no L1 caching — these are operator config, not the fact hot
    // path). Without these delegations the trait defaults would return
    // `unsupported`, silently killing the secret-intake surface behind the
    // cache the live server actually uses.
    async fn store_connector_bearer(
        &self,
        tenant: TenantId,
        source: &str,
        plaintext: &[u8],
        visibility: &[i32],
    ) -> Result<String> {
        self.inner
            .store_connector_bearer(tenant, source, plaintext, visibility)
            .await
    }

    async fn store_connector_path(
        &self,
        tenant: TenantId,
        source: &str,
        path: &str,
        subject: Option<&str>,
    ) -> Result<String> {
        self.inner
            .store_connector_path(tenant, source, path, subject)
            .await
    }

    async fn get_connector_credential_status(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorCredentialStatus>> {
        self.inner
            .get_connector_credential_status(tenant, source)
            .await
    }

    async fn materialize_connector_path(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorPathCredential>> {
        self.inner.materialize_connector_path(tenant, source).await
    }

    async fn materialize_connector_bearer(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.inner
            .materialize_connector_bearer(tenant, source)
            .await
    }

    async fn revoke_connector_credential(&self, tenant: TenantId, source: &str) -> Result<bool> {
        self.inner.revoke_connector_credential(tenant, source).await
    }
}
