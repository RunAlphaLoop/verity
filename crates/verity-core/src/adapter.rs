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

    /// Tenant directory for the admin plane (FTUE §2.1): the data source for
    /// the console's tenant picker and first-run detection (empty list =
    /// virgin server). Ordered by creation time DESCENDING (a just-created
    /// tenant must land on the first page), capped at `limit`.
    /// Default fails explicit — a profile that hasn't built the admin plane
    /// must never masquerade as a virgin server by returning an empty list.
    async fn list_tenants(&self, _limit: i64) -> Result<Vec<TenantRow>> {
        Err(unsupported("list_tenants"))
    }

    /// Total tenant count, so a capped directory page can disclose its own
    /// truncation ("showing 500 of 5,500") instead of passing as complete.
    async fn count_tenants(&self) -> Result<i64> {
        Err(unsupported("count_tenants"))
    }

    /// One tenant by id (admin plane): the point lookup the console's tenant
    /// picker and FTUE wizard need to confirm a pasted/deep-linked id names a
    /// REAL space, even when it falls outside the truncated directory page. A
    /// `None` (not an error) is a definitive "no such tenant" — the wizard's
    /// ghost-tenant hard stop and the picker's "loaded by id" label both key
    /// off this instead of guessing from directory membership.
    async fn get_tenant(&self, _tenant: TenantId) -> Result<Option<TenantRow>> {
        Err(unsupported("get_tenant"))
    }

    /// Append to the immutable L0 evidence log.
    async fn append_episode(&self, episode: NewEpisode) -> Result<EpisodeId>;

    /// Deterministic bi-temporal L1 upsert keyed on (source, entity_id, field).
    async fn upsert_fact(&self, fact: FactWrite) -> Result<FactUpsertOutcome>;

    /// Current value for a key (valid_to IS NULL). The hot path behind `get`.
    ///
    /// Scoped read: the caller's `Scope` is a MANDATORY pre-filter — the visible
    /// row is returned only if it overlaps `scope.principals`, sits at/below
    /// `scope.max_confidentiality`, and satisfies the entity-scope fence. Empty
    /// principals → `None` (fail closed). `scope.tenant_id` carries the tenant
    /// partition. Enforcement is the shared `fact_visible` predicate (types.rs)
    /// pushed into SQL by the Postgres profile and applied above the cache by
    /// `CachedAdapter`; no adapter may serve an out-of-scope fact.
    async fn current_fact(&self, scope: &Scope, key: &FactKey) -> Result<Option<FactRow>>;

    /// Value as of a point in event time (bi-temporal read). Same mandatory
    /// scope pre-filter as `current_fact`. Because ACL corrections are applied
    /// in place across every row of a key (SPEC §5e.6b), the visibility filter
    /// here reflects NOW-ACL even for a historical value — an un-shared principal
    /// cannot reach a superseded value via `as_of`.
    async fn fact_as_of(
        &self,
        scope: &Scope,
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
    /// via `fact_as_of`; hard purge is a separate admin pipeline.
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

    // ---- Connector credential intake (SPEC §5e, Phase-2 secret intake) ----
    //
    // ALL crypto stays inside the storage profile: the trait surface is
    // plaintext-in / decrypted-out; the AES-256-GCM envelope, the tenant DEK,
    // and the salted-HMAC fingerprint are computed in the impl and never
    // exposed here. Returns are only a fingerprint or a decrypted-on-demand
    // value — the server never touches raw key material.

    /// Store a tier-C bearer token (HubSpot/Salesforce) encrypted-at-rest under
    /// the tenant DEK, returning its salted-HMAC fingerprint prefix. HARD-REFUSES
    /// (never warn-and-store-plaintext) when `VERITY_KEK` is unset OR the tenant
    /// DEK is plaintext-provenance (stored length <= 32) — a secret must not be
    /// written against a DEK that isn't actually KEK-wrapped. Upsert on
    /// (tenant, source): a second store rotates the secret in place.
    ///
    /// `visibility` is the tier-C sharing policy: a set of principal tokens
    /// (`PrincipalToken` = i32) applied to every record a store-backed backfill
    /// spawn ingests. It is NOT a secret and does NOT alter the fingerprint —
    /// it is persisted alongside the ciphertext (bearer rows only) so a Phase-4
    /// backfill can resolve `--visibility` from the store.
    async fn store_connector_bearer(
        &self,
        _tenant: TenantId,
        _source: &str,
        _plaintext: &[u8],
        _visibility: &[i32],
    ) -> Result<String> {
        Err(unsupported("store_connector_bearer"))
    }

    /// Store a tier-A Google SA-key file PATH (not a secret; no crypto),
    /// returning its salted-HMAC fingerprint prefix. Upsert on (tenant, source).
    /// `subject` is the non-secret domain-wide-delegation impersonation address
    /// (a Workspace admin) resolved at spawn time for `--subject`; `None` when
    /// unset (gdrive may omit it, gmail requires it). The fingerprint covers the
    /// path bytes only — the subject does not alter it.
    async fn store_connector_path(
        &self,
        _tenant: TenantId,
        _source: &str,
        _path: &str,
        _subject: Option<&str>,
    ) -> Result<String> {
        Err(unsupported("store_connector_path"))
    }

    /// Non-secret status of a stored credential (kind, fingerprint, updated_at),
    /// or `None` when nothing is stored for (tenant, source). NEVER returns the
    /// secret or the path plaintext.
    async fn get_connector_credential_status(
        &self,
        _tenant: TenantId,
        _source: &str,
    ) -> Result<Option<ConnectorCredentialStatus>> {
        Err(unsupported("get_connector_credential_status"))
    }

    /// Read back a stored Google `path` credential for a Phase-3 backfill spawn:
    /// the SA-key file PATH plaintext + the non-secret impersonation subject.
    /// Unlike `get_connector_credential_status` this DOES surface the path (the
    /// spawn needs it for `GOOGLE_APPLICATION_CREDENTIALS`); the caller hands it
    /// only to the child's env, never to a client. `None` when nothing is stored
    /// for (tenant, source); an error when the stored row is a `bearer` kind (no
    /// path to materialize).
    async fn materialize_connector_path(
        &self,
        _tenant: TenantId,
        _source: &str,
    ) -> Result<Option<ConnectorPathCredential>> {
        Err(unsupported("materialize_connector_path"))
    }

    /// Decrypt-on-demand read of a stored BEARER secret (Phase-3 spawn /
    /// test-probe use). Decrypts under the tenant DEK — inherits the KEK-unset
    /// fail-closed refusal for free. `None` when no bearer credential is stored;
    /// an error when the row is a `path` kind (no secret to materialize).
    async fn materialize_connector_bearer(
        &self,
        _tenant: TenantId,
        _source: &str,
    ) -> Result<Option<Vec<u8>>> {
        Err(unsupported("materialize_connector_bearer"))
    }

    /// Revoke a stored credential: deletes the (tenant, source) row. Returns
    /// `true` when a row was removed, `false` for an honest no-op (nothing was
    /// stored). Credentials are operator config, not memory — a hard delete here
    /// does NOT violate the invalidate-don't-delete rule (which governs L0/L1
    /// records).
    async fn revoke_connector_credential(&self, _tenant: TenantId, _source: &str) -> Result<bool> {
        Err(unsupported("revoke_connector_credential"))
    }

    // ---- Continuous-sync schedules (Phase-4, migration 0033) ----
    //
    // A continuous-sync schedule is the DURABLE record that (tenant, source) has
    // an interval poll armed. It is operator config, not memory — a durable
    // upsert/toggle, never an L1 fact (so the invalidate-don't-delete rule does
    // not apply; a disable is a soft `enabled=false`, retained for audit). The
    // AUTHORITATIVE cursor is NOT stored here — it lives in the connector's own
    // per-(tenant, source) state file; this surface only carries the schedule.

    /// Upsert the schedule for (tenant, source): set the poll interval and
    /// enabled flag. Idempotent on (tenant, source) — a second call rotates the
    /// interval / flips the flag in place. `interval_secs` is floored at 60s by
    /// the DB CHECK; a sub-floor value is rejected by storage (never silently
    /// clamped), so the interval-floor guarantee holds even against a direct
    /// storage caller. Returns the resulting row.
    async fn upsert_sync_schedule(
        &self,
        _tenant: TenantId,
        _source: &str,
        _interval_secs: i32,
        _enabled: bool,
    ) -> Result<SyncSchedule> {
        Err(unsupported("upsert_sync_schedule"))
    }

    /// The schedule for (tenant, source), or `None` when none is stored. The
    /// toggle endpoint and the connectors readiness row read this to report the
    /// per-source sync state (enabled / interval / last run).
    async fn get_sync_schedule(
        &self,
        _tenant: TenantId,
        _source: &str,
    ) -> Result<Option<SyncSchedule>> {
        Err(unsupported("get_sync_schedule"))
    }

    /// Every ENABLED schedule across all tenants — the boot re-arm read. On
    /// server boot the scheduler re-arms one interval loop per row returned here
    /// (mirrors `folder_watches` re-establishment). Disabled schedules are
    /// omitted (they stay durable for audit but are not re-armed). Ordered by
    /// (tenant_id, source) for a stable re-arm sequence.
    async fn list_enabled_sync_schedules(&self) -> Result<Vec<SyncSchedule>> {
        Err(unsupported("list_enabled_sync_schedules"))
    }

    /// Stamp `last_run_at = now()` for (tenant, source) after a `--once` poll
    /// cycle fires. Lightweight telemetry (display-only "last synced N ago"); the
    /// authoritative cursor stays in the connector state file. An honest no-op
    /// (0 rows) when no schedule exists for the key. Returns `true` when a row was
    /// stamped.
    async fn touch_sync_schedule_last_run(&self, _tenant: TenantId, _source: &str) -> Result<bool> {
        Err(unsupported("touch_sync_schedule_last_run"))
    }
}

fn unsupported(op: &str) -> StorageError {
    StorageError::InvalidInput(format!("{op} unsupported by this storage profile"))
}
