use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pgvector::Vector;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

pub struct PostgresAdapter {
    pool: PgPool,
    /// Deployment KEK (SPEC §8a, crypto.rs). None = envelope encryption
    /// disabled: L0 payloads stay plaintext, DEKs are stored unwrapped.
    kek: Option<crate::crypto::Kek>,
    /// Unwrapped per-tenant DEKs, cached after first use (bounded; the DEK is
    /// 32 bytes and provisioning is one row per tenant, ever).
    deks: moka::sync::Cache<TenantId, [u8; crate::crypto::DEK_BYTES]>,
}

impl PostgresAdapter {
    /// Connect with the KEK from env `VERITY_KEK` (warned when absent).
    pub async fn connect(dsn: &str) -> Result<Self> {
        let kek = crate::crypto::Kek::from_env()?;
        Self::connect_with_kek(dsn, kek).await
    }

    /// Explicit-KEK constructor: the test seam (no env mutation) and the
    /// future config-file/KMS profiles.
    pub async fn connect_with_kek(dsn: &str, kek: Option<crate::crypto::Kek>) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(dsn)
            .await
            .map_err(db_err)?;
        Ok(Self {
            pool,
            kek,
            deks: moka::sync::Cache::new(10_000),
        })
    }

    /// The tenant's data-encryption key, provisioning it lazily on first use
    /// (SPEC §8a). Stored KEK-wrapped when a KEK is configured, plaintext
    /// otherwise; a concurrent first-writer race is settled by the primary
    /// key — the loser re-reads the winner's DEK.
    async fn tenant_dek(&self, tenant: TenantId) -> Result<[u8; crate::crypto::DEK_BYTES]> {
        if let Some(dek) = self.deks.get(&tenant) {
            return Ok(dek);
        }
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        let dek = match stored {
            Some(bytes) => crate::crypto::unwrap_dek(self.kek.as_ref(), &bytes)?,
            None => {
                let dek = crate::crypto::generate_dek();
                let to_store = match &self.kek {
                    Some(kek) => crate::crypto::wrap_dek(kek, &dek)?,
                    None => dek.to_vec(),
                };
                let inserted = sqlx::query(
                    "INSERT INTO tenant_deks (tenant_id, dek) VALUES ($1, $2)
                     ON CONFLICT (tenant_id) DO NOTHING",
                )
                .bind(tenant)
                .bind(&to_store)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
                if inserted.rows_affected() == 0 {
                    // Lost the provisioning race: adopt the winner's DEK.
                    let bytes: Vec<u8> =
                        sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
                            .bind(tenant)
                            .fetch_one(&self.pool)
                            .await
                            .map_err(db_err)?;
                    crate::crypto::unwrap_dek(self.kek.as_ref(), &bytes)?
                } else {
                    dek
                }
            }
        };
        self.deks.insert(tenant, dek);
        Ok(dek)
    }

    /// Decrypt-on-demand read of one L0 payload (SPEC §8a; used by DSAR
    /// export and admin forensics — never by the serving read path). Returns
    /// the plaintext payload whether or not the row is encrypted; None for an
    /// unknown episode.
    pub async fn episode_payload(
        &self,
        tenant: TenantId,
        id: EpisodeId,
    ) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query(
            "SELECT payload, payload_enc FROM episodes WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let payload: serde_json::Value = row.try_get("payload").map_err(db_err)?;
        let payload_enc: Option<Vec<u8>> = row.try_get("payload_enc").map_err(db_err)?;
        self.decrypt_payload(tenant, payload, payload_enc)
            .await
            .map(Some)
    }

    /// Shared decrypt helper: `payload_enc` present → decrypt under the
    /// tenant DEK (requires the KEK for wrapped DEKs, fail closed); absent →
    /// the plaintext `payload` column is authoritative.
    pub(crate) async fn decrypt_payload(
        &self,
        tenant: TenantId,
        payload: serde_json::Value,
        payload_enc: Option<Vec<u8>>,
    ) -> Result<serde_json::Value> {
        match payload_enc {
            None => Ok(payload),
            Some(blob) => {
                let dek = self.tenant_dek(tenant).await?;
                let plain = crate::crypto::decrypt(&dek, &blob)?;
                serde_json::from_slice(&plain).map_err(db_err)
            }
        }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn get_knowledge(&self, tenant: TenantId, id: Uuid) -> Result<KnowledgeItem> {
        let row = sqlx::query("SELECT * FROM knowledge WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        row_to_knowledge(&row)
    }

    /// Below this many matching rows, brute-force distance over the filtered
    /// subset beats HNSW iterative traversal (measured at 1M chunks: exact
    /// 11ms vs HNSW 72ms p50 at 1% selectivity — docs/BENCHMARKS.md). The
    /// probe that decides is capped at this bound, so broad scopes pay a few
    /// bounded milliseconds, not a full count.
    const EXACT_SCAN_MAX_ROWS: i64 = 20_000;

    async fn recall_dense(&self, q: &RecallQuery, embedding: &[f32]) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // Selectivity router: ask the planner for its row estimate (pure
        // planning, no scan — an actual count via GIN builds the full bitmap
        // before LIMIT and costs ~100ms on broad scopes), then pick the
        // winning plan. The 1–10% selectivity band is where HNSW-under-filter
        // collapses (the "valley", docs/BENCHMARKS.md finding 2). Estimates
        // come from pg_stats' most_common_elems on the visibility array;
        // order-of-magnitude accuracy is all the routing decision needs.
        let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (FORMAT JSON) SELECT 1 FROM chunks
             WHERE tenant_id = $1
               AND valid_to IS NULL
               AND embedding IS NOT NULL
               AND visibility && $2
               AND confidentiality <= $3
               {}",
            entity_scope_predicate(scope, "$4"),
        )))
        .bind(scope.tenant_id)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(&scope.entity_scope)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        let estimated_rows = plan[0]["Plan"]["Plan Rows"].as_i64().unwrap_or(i64::MAX);

        if estimated_rows <= Self::EXACT_SCAN_MAX_ROWS {
            // Small filtered set: exact top-k over it (perfect recall, and
            // faster than graph traversal under selective filters).
            sqlx::query("SET LOCAL enable_indexscan = off")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        } else {
            // Broad set: HNSW with iterative scans so selective predicates
            // don't collapse recall (pgvector 0.8, SPEC §4).
            sqlx::query("SET LOCAL hnsw.iterative_scan = relaxed_order")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }
        // Safe: the predicate string is assembled from constants only; all
        // caller data goes through binds.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, document_id, seq, content, entity_tags, kind, acl_provenance, trust_tier, valid_from, provenance,
                    1 - (embedding <=> $1) AS score
             FROM chunks
             WHERE tenant_id = $2
               AND valid_to IS NULL
               AND embedding IS NOT NULL
               AND visibility && $3
               AND confidentiality <= $4
               {}
             ORDER BY embedding <=> $1
             LIMIT $5",
            entity_scope_predicate(scope, "$6"),
        )))
        .bind(Vector::from(embedding.to_vec()))
        .bind(scope.tenant_id)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(q.k as i64)
        .bind(&scope.entity_scope)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }

    async fn recall_bm25(&self, q: &RecallQuery, text: &str) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        // Visibility rides INTO the Tantivy query: `&&` is not a pushable
        // operator for pg_search, and heap-filtering the raw match set costs
        // ~280ms at 1M rows (docs/BENCHMARKS.md finding 3). term_set on the
        // int[] fast field has exact overlap semantics — and matches nothing
        // for an empty principal array, preserving fail-closed. tenant/
        // confidentiality/valid_to push down as indexed scalars (0004).
        // Entity-bound scopes pre-filter INSIDE Tantivy: term_set on the
        // keyword-tokenized entity_tags field is any-overlap — a superset of
        // the required subset semantics — with the §7g knowledge carve-out
        // OR'd in on the indexed kind field. The exact `<@` residual check
        // runs over a MATERIALIZED candidate set that is bounded by the
        // entity's own chunk count (never the corpus), because mixing the
        // residual into the @@@ query breaks the TopK plan and heap-scans the
        // full match set (measured 542ms p50; docs/BENCHMARKS.md). This is
        // filter-then-rank, never truncate-then-authorize.
        let sql = if scope.entity_scope.is_empty() {
            "SELECT id, document_id, seq, content, entity_tags, kind, acl_provenance, trust_tier, valid_from, provenance,
                    paradedb.score(id) AS score
             FROM chunks
             WHERE content @@@ $1
               AND id @@@ paradedb.term_set('visibility', $3)
               AND tenant_id = $2
               AND valid_to IS NULL
               AND confidentiality <= $4
             ORDER BY paradedb.score(id) DESC
             LIMIT $5"
                .to_string()
        } else {
            "WITH cand AS MATERIALIZED (
                 SELECT id, paradedb.score(id) AS score
                 FROM chunks
                 WHERE content @@@ $1
                   AND id @@@ paradedb.term_set('visibility', $3)
                   AND id @@@ paradedb.boolean(should => ARRAY[
                           paradedb.term_set('entity_tags', $6),
                           paradedb.term('kind', 'knowledge')
                       ])
                   AND tenant_id = $2
                   AND valid_to IS NULL
                   AND confidentiality <= $4
             )
             SELECT c.id, document_id, seq, content, entity_tags, kind, acl_provenance, trust_tier, valid_from, provenance,
                    cand.score AS score
             FROM cand JOIN chunks c ON c.id = cand.id
             WHERE (c.kind = 'knowledge'
                    OR (c.entity_tags <> '{}' AND c.entity_tags <@ $6))
             ORDER BY cand.score DESC
             LIMIT $5"
                .to_string()
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(text)
            .bind(scope.tenant_id)
            .bind(&scope.principals)
            .bind(scope.max_confidentiality as i16)
            .bind(q.k as i64)
            .bind(&scope.entity_scope)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }
}

/// Entity scoping, deny-by-default (SPEC §7d): in an entity-bound scope a chunk
/// is retrievable only when its tags are non-empty and a subset of the scope's
/// entity set; zero-tag content is excluded. The one verified exception (§7g):
/// `kind = 'knowledge'` chunks — positively entity-free, published through the
/// de-identification gates — are admitted into entity-bound scopes.
fn entity_scope_predicate(scope: &Scope, bind: &str) -> String {
    if scope.entity_scope.is_empty() {
        String::new()
    } else {
        format!("AND (kind = 'knowledge' OR (entity_tags <> '{{}}' AND entity_tags <@ {bind}))")
    }
}

fn row_to_hit(row: &PgRow) -> Result<RecallHit> {
    Ok(RecallHit {
        chunk_id: row.try_get("id").map_err(db_err)?,
        document_id: row.try_get("document_id").map_err(db_err)?,
        seq: row.try_get("seq").map_err(db_err)?,
        content: row.try_get("content").map_err(db_err)?,
        score: row
            .try_get::<f64, _>("score")
            .map(|s| s as f32)
            .or_else(|_| row.try_get::<f32, _>("score"))
            .map_err(db_err)?,
        entity_tags: row.try_get("entity_tags").map_err(db_err)?,
        kind: row.try_get("kind").map_err(db_err)?,
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
        ),
        trust_tier: tier_from_i16(row.try_get("trust_tier").map_err(db_err)?),
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
    })
}

fn row_to_knowledge(row: &PgRow) -> Result<KnowledgeItem> {
    let status = match row.try_get::<String, _>("status").map_err(db_err)?.as_str() {
        "candidate" => KnowledgeStatus::Candidate,
        "quarantined" => KnowledgeStatus::Quarantined,
        "published" => KnowledgeStatus::Published,
        _ => KnowledgeStatus::Invalidated,
    };
    Ok(KnowledgeItem {
        id: row.try_get("id").map_err(db_err)?,
        statement: row.try_get("statement").map_err(db_err)?,
        categories: row.try_get("categories").map_err(db_err)?,
        status,
        quarantine_reason: row.try_get("quarantine_reason").map_err(db_err)?,
        distinct_entities: row.try_get("distinct_entities").map_err(db_err)?,
        episode_count: row.try_get("episode_count").map_err(db_err)?,
        writer_count: row.try_get("writer_count").map_err(db_err)?,
        has_tier1_evidence: row.try_get("has_tier1_evidence").map_err(db_err)?,
        first_seen: row.try_get("first_seen").map_err(db_err)?,
        last_reinforced: row.try_get("last_reinforced").map_err(db_err)?,
        published_at: row.try_get("published_at").map_err(db_err)?,
    })
}

fn tier_from_i16(v: i16) -> TrustTier {
    if v == 1 {
        TrustTier::Authoritative
    } else {
        TrustTier::Observation
    }
}

pub(crate) fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// Reciprocal-rank fusion of the dense and sparse result lists.
fn rrf_fuse(lists: Vec<Vec<RecallHit>>, k: usize) -> Vec<RecallHit> {
    const RRF_K: f32 = 60.0;
    let mut scores: HashMap<Uuid, (f32, RecallHit)> = HashMap::new();
    for list in lists {
        for (rank, hit) in list.into_iter().enumerate() {
            let contribution = 1.0 / (RRF_K + rank as f32 + 1.0);
            scores
                .entry(hit.chunk_id)
                .and_modify(|(s, _)| *s += contribution)
                .or_insert((contribution, hit));
        }
    }
    let mut fused: Vec<(f32, RecallHit)> = scores.into_values().collect();
    fused.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    fused
        .into_iter()
        .take(k)
        .map(|(score, mut hit)| {
            hit.score = score;
            hit
        })
        .collect()
}

#[async_trait]
impl StorageAdapter for PostgresAdapter {
    async fn create_tenant(&self, name: &str) -> Result<TenantId> {
        let id = Uuid::now_v7();
        let row = sqlx::query(
            "INSERT INTO tenants (id, name) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
             RETURNING id",
        )
        .bind(id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_get("id").map_err(db_err)
    }

    async fn append_episode(&self, ep: NewEpisode) -> Result<EpisodeId> {
        let id = Uuid::now_v7();
        // Envelope encryption (SPEC §8a, v0 contract — crypto.rs): the DEK is
        // provisioned lazily either way; with a KEK configured the payload is
        // stored AES-256-GCM in payload_enc and the jsonb column carries the
        // '{}' sentinel. Reads that need the payload go through
        // episode_payload(); the serving read path never does.
        let dek = self.tenant_dek(ep.tenant_id).await?;
        let (payload, payload_enc, encrypted): (serde_json::Value, Option<Vec<u8>>, Option<bool>) =
            if self.kek.is_some() {
                let plaintext = serde_json::to_vec(&ep.payload).map_err(db_err)?;
                (
                    serde_json::json!({}),
                    Some(crate::crypto::encrypt(&dek, &plaintext)?),
                    Some(true),
                )
            } else {
                (ep.payload.clone(), None, None)
            };
        sqlx::query(
            "INSERT INTO episodes (id, tenant_id, source, source_entity, kind, payload,
                                   payload_enc, payload_encrypted,
                                   content_hash, trust_tier, writer_sub, writer_azp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(ep.tenant_id)
        .bind(&ep.source)
        .bind(&ep.source_entity)
        .bind(ep.kind.as_str())
        .bind(&payload)
        .bind(&payload_enc)
        .bind(encrypted)
        .bind(&ep.content_hash)
        .bind(ep.trust_tier as i16)
        .bind(&ep.writer_sub)
        .bind(&ep.writer_azp)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(id)
    }

    async fn upsert_fact(&self, fact: FactWrite) -> Result<FactUpsertOutcome> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let current = sqlx::query(
            "SELECT id, value, valid_from FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL
             FOR UPDATE",
        )
        .bind(fact.tenant_id)
        .bind(&fact.key.source)
        .bind(&fact.key.entity_id)
        .bind(&fact.key.field)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let new_id = Uuid::now_v7();
        let outcome = match current {
            None => {
                insert_fact_row(&mut tx, new_id, &fact, None).await?;
                FactUpsertOutcome::Inserted
            }
            Some(row) => {
                let cur_id: Uuid = row.try_get("id").map_err(db_err)?;
                let cur_value: serde_json::Value = row.try_get("value").map_err(db_err)?;
                let cur_from: DateTime<Utc> = row.try_get("valid_from").map_err(db_err)?;
                if cur_value == fact.value {
                    FactUpsertOutcome::Unchanged
                } else if fact.valid_from <= cur_from {
                    // Late-arriving event: record as already-superseded history;
                    // the current row is untouched.
                    insert_fact_row(&mut tx, new_id, &fact, Some(cur_from)).await?;
                    FactUpsertOutcome::StaleEvent
                } else {
                    // Retire before insert: the one-current-row unique index is
                    // checked immediately, so the old row must lose valid_to NULL
                    // first. superseded_by is linked after insert (FK target).
                    sqlx::query("UPDATE facts SET valid_to = $1 WHERE id = $2")
                        .bind(fact.valid_from)
                        .bind(cur_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    insert_fact_row(&mut tx, new_id, &fact, None).await?;
                    sqlx::query("UPDATE facts SET superseded_by = $1 WHERE id = $2")
                        .bind(new_id)
                        .bind(cur_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    FactUpsertOutcome::Superseded
                }
            }
        };
        tx.commit().await.map_err(db_err)?;
        Ok(outcome)
    }

    async fn current_fact(&self, tenant: TenantId, key: &FactKey) -> Result<Option<FactRow>> {
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| row_to_fact(&r)).transpose()
    }

    async fn fact_as_of(
        &self,
        tenant: TenantId,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_from <= $5 AND (valid_to IS NULL OR valid_to > $5)
             ORDER BY valid_from DESC
             LIMIT 1",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(as_of)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| row_to_fact(&r)).transpose()
    }

    async fn upsert_chunks(&self, chunks: Vec<ChunkWrite>) -> Result<usize> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let mut written = 0usize;
        for c in &chunks {
            // Retire the previous current version of this chunk position.
            sqlx::query(
                "UPDATE chunks SET valid_to = $1
                 WHERE tenant_id = $2 AND source = $3 AND document_id = $4 AND seq = $5
                   AND valid_to IS NULL AND valid_from < $1",
            )
            .bind(c.valid_from)
            .bind(c.tenant_id)
            .bind(&c.source)
            .bind(&c.document_id)
            .bind(c.seq)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

            let result = sqlx::query(
                "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                     content_hash, embedding, visibility, entity_tags,
                                     confidentiality, trust_tier, valid_from, provenance,
                                     acl_provenance)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                 ON CONFLICT (tenant_id, source, document_id, seq, valid_from) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(c.tenant_id)
            .bind(&c.source)
            .bind(&c.document_id)
            .bind(c.seq)
            .bind(&c.content)
            .bind(&c.content_hash)
            .bind(c.embedding.as_ref().map(|e| Vector::from(e.clone())))
            .bind(&c.visibility)
            .bind(&c.entity_tags)
            .bind(c.confidentiality as i16)
            .bind(c.trust_tier as i16)
            .bind(c.valid_from)
            .bind(c.provenance)
            .bind(c.acl_provenance.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            written += result.rows_affected() as usize;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(written)
    }

    async fn recall(&self, query: RecallQuery) -> Result<Vec<RecallHit>> {
        // Fail closed: no principals, no results — checked here in the shared
        // layer so no adapter can forget it.
        if query.scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        match (&query.embedding, &query.text) {
            (Some(embedding), Some(text)) => {
                let (dense, sparse) = tokio::join!(
                    self.recall_dense(&query, embedding),
                    self.recall_bm25(&query, text)
                );
                Ok(rrf_fuse(vec![dense?, sparse?], query.k))
            }
            (Some(embedding), None) => self.recall_dense(&query, embedding).await,
            (None, Some(text)) => self.recall_bm25(&query, text).await,
            (None, None) => Err(StorageError::InvalidInput(
                "recall requires an embedding, text, or both".into(),
            )),
        }
    }

    async fn record_action(&self, action: ActionWrite) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let episode_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO episodes (id, tenant_id, source, source_entity, kind, payload,
                                   content_hash, trust_tier, writer_sub, writer_azp)
             VALUES ($1, $2, 'agent', $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(episode_id)
        .bind(action.tenant_id)
        .bind(&action.action_id)
        .bind(EpisodeKind::AgentAction.as_str())
        .bind(serde_json::to_value(&action).map_err(db_err)?)
        .bind(format!("action-{}", action.action_id))
        .bind(TrustTier::Observation as i16)
        .bind(&action.actor_sub)
        .bind(&action.actor_azp)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        let inserted = sqlx::query(
            "INSERT INTO actions (id, tenant_id, action_id, actor_sub, actor_azp, action_type,
                                  entities, summary, payload, outcome, occurred_at,
                                  visibility, confidentiality, provenance)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (tenant_id, action_id) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(action.tenant_id)
        .bind(&action.action_id)
        .bind(&action.actor_sub)
        .bind(&action.actor_azp)
        .bind(&action.action_type)
        .bind(&action.entities)
        .bind(&action.summary)
        .bind(&action.payload)
        .bind(action.outcome.as_str())
        .bind(action.occurred_at)
        .bind(&action.visibility)
        .bind(action.confidentiality as i16)
        .bind(episode_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if inserted.rows_affected() == 0 {
            // Idempotent replay: discard the episode too.
            tx.rollback().await.map_err(db_err)?;
            return Ok(false);
        }
        Self::insert_action_chunk(&mut tx, &action, episode_id).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(true)
    }

    async fn propose_knowledge(&self, proposal: KnowledgeProposal) -> Result<KnowledgeItem> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // Evidence attribution comes from the episodes themselves.
        let evidence = sqlx::query(
            "SELECT id, source_entity, writer_azp, trust_tier FROM episodes
             WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(proposal.tenant_id)
        .bind(&proposal.evidence)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;

        // De-identification gate (SPEC v1.3 §2, deterministic): the statement
        // must not contain any known entity identifier — entity tags on chunks
        // and actions (with and without their "type:" prefix) or L1 entity ids.
        // Terms shorter than 4 chars are skipped as false-positive noise; such
        // identifiers are caught by review, which is on by default.
        let lexicon: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT term FROM (
                 SELECT unnest(entity_tags) AS term FROM chunks WHERE tenant_id = $1
                 UNION SELECT unnest(entities) FROM actions WHERE tenant_id = $1
                 UNION SELECT entity_id FROM facts WHERE tenant_id = $1
             ) t",
        )
        .bind(proposal.tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        let statement_lc = proposal.statement.to_lowercase();
        let leaked = lexicon.iter().find_map(|term| {
            let bare = term.rsplit(':').next().unwrap_or(term);
            [term.as_str(), bare]
                .into_iter()
                .find(|t| t.len() >= 4 && statement_lc.contains(&t.to_lowercase()))
                .map(str::to_string)
        });

        let mut distinct_entities: Vec<String> = Vec::new();
        let mut writers: Vec<String> = Vec::new();
        let mut has_tier1 = false;
        for row in &evidence {
            if let Ok(Some(e)) = row.try_get::<Option<String>, _>("source_entity") {
                if !distinct_entities.contains(&e) {
                    distinct_entities.push(e);
                }
            }
            if let Ok(Some(w)) = row.try_get::<Option<String>, _>("writer_azp") {
                if !writers.contains(&w) {
                    writers.push(w);
                }
            }
            has_tier1 |= matches!(row.try_get::<i16, _>("trust_tier"), Ok(1));
        }

        let (status, reason) = match &leaked {
            Some(term) => (
                KnowledgeStatus::Quarantined,
                Some(format!(
                    "statement contains known entity identifier {term:?}"
                )),
            ),
            None => (KnowledgeStatus::Candidate, None),
        };

        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO knowledge (id, tenant_id, statement, categories, status,
                                    quarantine_reason, distinct_entities, episode_count,
                                    writer_count, has_tier1_evidence,
                                    proposed_by_sub, proposed_by_azp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(proposal.tenant_id)
        .bind(&proposal.statement)
        .bind(&proposal.categories)
        .bind(status.as_str())
        .bind(&reason)
        .bind(distinct_entities.len() as i32)
        .bind(evidence.len() as i32)
        .bind(writers.len() as i32)
        .bind(has_tier1)
        .bind(&proposal.proposed_by_sub)
        .bind(&proposal.proposed_by_azp)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        for row in &evidence {
            sqlx::query(
                "INSERT INTO knowledge_evidence (knowledge_id, episode_id, entity, writer_azp, trust_tier)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(row.try_get::<Uuid, _>("id").map_err(db_err)?)
            .bind(row.try_get::<Option<String>, _>("source_entity").map_err(db_err)?)
            .bind(row.try_get::<Option<String>, _>("writer_azp").map_err(db_err)?)
            .bind(row.try_get::<i16, _>("trust_tier").map_err(db_err)?)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        self.get_knowledge(proposal.tenant_id, id).await
    }

    async fn publish_knowledge(
        &self,
        tenant: TenantId,
        id: Uuid,
        visibility: Vec<PrincipalToken>,
        k_min: i32,
        embedding: Option<Vec<f32>>,
    ) -> Result<KnowledgeItem> {
        if visibility.is_empty() {
            return Err(StorageError::InvalidInput(
                "publishing requires a non-empty visibility set".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let row = sqlx::query(
            "SELECT statement, categories, status, distinct_entities, writer_count,
                    has_tier1_evidence
             FROM knowledge WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| StorageError::InvalidInput("unknown knowledge item".into()))?;

        let status: String = row.try_get("status").map_err(db_err)?;
        if status != "candidate" {
            return Err(StorageError::InvalidInput(format!(
                "only candidates can be published (status: {status})"
            )));
        }
        // Promotion gates (SPEC v1.3 §2). Category-size floor is not yet
        // enforceable — it needs entity→category facts (documented seam).
        let distinct: i32 = row.try_get("distinct_entities").map_err(db_err)?;
        let writers: i32 = row.try_get("writer_count").map_err(db_err)?;
        let tier1: bool = row.try_get("has_tier1_evidence").map_err(db_err)?;
        if distinct < k_min {
            return Err(StorageError::InvalidInput(format!(
                "k-support unmet: {distinct} distinct entities < k_min {k_min}"
            )));
        }
        if writers < 2 && !tier1 {
            return Err(StorageError::InvalidInput(
                "corroboration unmet: needs >=2 distinct writers or tier-1 evidence".into(),
            ));
        }

        let statement: String = row.try_get("statement").map_err(db_err)?;
        let categories: Vec<String> = row.try_get("categories").map_err(db_err)?;

        let episode_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO episodes (id, tenant_id, source, source_entity, kind, payload,
                                   content_hash, trust_tier, writer_sub, writer_azp)
             VALUES ($1, $2, 'knowledge', $3, $4, $5, $6, $7, NULL, NULL)",
        )
        .bind(episode_id)
        .bind(tenant)
        .bind(id.to_string())
        .bind(EpisodeKind::KnowledgePublish.as_str())
        .bind(serde_json::json!({ "knowledge_id": id, "statement": statement }))
        .bind(format!("knowledge-{id}"))
        .bind(TrustTier::Observation as i16)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // The §7g carve-out artifact: kind='knowledge', entity-free, broad
        // visibility. Lineage lives in knowledge_evidence, NEVER here.
        sqlx::query(
            "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                 content_hash, embedding, visibility, entity_tags,
                                 confidentiality, trust_tier, valid_from, provenance,
                                 kind, categories)
             VALUES ($1, $2, 'knowledge', $3, 0, $4, $5, $6, $7, '{}', $8, $9, now(), $10,
                     'knowledge', $11)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(format!("knowledge:{id}"))
        .bind(&statement)
        .bind(format!("knowledge-{id}"))
        .bind(embedding.map(Vector::from))
        .bind(&visibility)
        .bind(Confidentiality::Internal as i16)
        .bind(TrustTier::Observation as i16)
        .bind(episode_id)
        .bind(&categories)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        sqlx::query(
            "UPDATE knowledge SET status = 'published', published_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        self.get_knowledge(tenant, id).await
    }

    async fn list_knowledge(
        &self,
        tenant: TenantId,
        status: Option<KnowledgeStatus>,
    ) -> Result<Vec<KnowledgeItem>> {
        let rows = sqlx::query(
            "SELECT * FROM knowledge
             WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)
             ORDER BY first_seen DESC LIMIT 200",
        )
        .bind(tenant)
        .bind(status.map(|s| s.as_str()))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_knowledge).collect()
    }

    async fn latest_chunks(
        &self,
        scope: &Scope,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<RecallHit>> {
        if scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        // An entity-bound scope may only read entities it covers (same rule
        // as activity()).
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&entity.to_string()) {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT id, document_id, seq, content, entity_tags, kind, acl_provenance, trust_tier, valid_from, provenance,
                    0.0::float8 AS score
             FROM chunks
             WHERE tenant_id = $1
               AND valid_to IS NULL
               AND entity_tags @> ARRAY[$2]::text[]
               AND visibility && $3
               AND confidentiality <= $4
             ORDER BY valid_from DESC
             LIMIT $5",
        )
        .bind(scope.tenant_id)
        .bind(entity)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(limit.clamp(1, 100) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }

    async fn forget(&self, tenant: TenantId, ref_kind: ForgetRef, reason: &str) -> Result<u64> {
        match ref_kind {
            ForgetRef::Chunk(chunk_id) => {
                // Tenant-checked structural retire — the row stays for audit,
                // it just stops being current (invalidate-don't-delete).
                let result = sqlx::query(
                    "UPDATE chunks SET valid_to = now()
                     WHERE tenant_id = $1 AND id = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(chunk_id)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
                tracing::info!(%chunk_id, reason, "forget: chunk retired");
                Ok(result.rows_affected())
            }
            ForgetRef::Episode(episode_id) => {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let chunks_retired = sqlx::query(
                    "UPDATE chunks SET valid_to = now()
                     WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(episode_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                let facts_retired = sqlx::query(
                    "UPDATE facts SET valid_to = now()
                     WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(episode_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();

                // Knowledge retraction cascade: withdraw this episode's
                // evidence, recount support, and pull published items whose
                // k-support falls below the k=3 privacy floor.
                let knowledge_ids: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT ke.knowledge_id FROM knowledge_evidence ke
                     JOIN knowledge k ON k.id = ke.knowledge_id
                     WHERE ke.episode_id = $1 AND k.tenant_id = $2
                     FOR UPDATE OF k",
                )
                .bind(episode_id)
                .bind(tenant)
                .fetch_all(&mut *tx)
                .await
                .map_err(db_err)?;

                for kid in knowledge_ids {
                    sqlx::query(
                        "DELETE FROM knowledge_evidence
                         WHERE knowledge_id = $1 AND episode_id = $2",
                    )
                    .bind(kid)
                    .bind(episode_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    let row = sqlx::query(
                        "SELECT count(DISTINCT entity) AS entities, count(*) AS episodes
                         FROM knowledge_evidence WHERE knowledge_id = $1",
                    )
                    .bind(kid)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    let distinct: i64 = row.try_get("entities").map_err(db_err)?;
                    let episodes: i64 = row.try_get("episodes").map_err(db_err)?;
                    sqlx::query(
                        "UPDATE knowledge SET distinct_entities = $2, episode_count = $3
                         WHERE id = $1",
                    )
                    .bind(kid)
                    .bind(distinct as i32)
                    .bind(episodes as i32)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    if distinct < 3 {
                        let invalidated = sqlx::query(
                            "UPDATE knowledge
                             SET status = 'invalidated', invalidated_at = now(),
                                 invalidated_reason = 'support_withdrawn'
                             WHERE id = $1 AND status = 'published'",
                        )
                        .bind(kid)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        if invalidated.rows_affected() > 0 {
                            // Retire the §7g carve-out artifact so the
                            // statement stops surfacing in recall.
                            sqlx::query(
                                "UPDATE chunks SET valid_to = now()
                                 WHERE tenant_id = $1 AND document_id = $2
                                   AND valid_to IS NULL",
                            )
                            .bind(tenant)
                            .bind(format!("knowledge:{kid}"))
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        }
                    }
                }
                tx.commit().await.map_err(db_err)?;
                tracing::info!(
                    %episode_id,
                    reason,
                    chunks_retired,
                    facts_retired,
                    "forget: episode retired"
                );
                Ok(chunks_retired + facts_retired)
            }
        }
    }

    async fn retire_entity(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE facts SET valid_to = $1
             WHERE tenant_id = $2 AND source = $3 AND entity_id = $4 AND valid_to IS NULL",
        )
        .bind(deleted_at)
        .bind(tenant)
        .bind(source)
        .bind(entity_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn activity(&self, query: ActivityQuery) -> Result<Vec<ActionRecord>> {
        let scope = &query.scope;
        // Fail closed, same contract as recall.
        if scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        // An entity-bound scope may only query entities it covers.
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&query.entity) {
            return Ok(Vec::new());
        }
        // Patterns split into exact matches and "prefix.*" wildcards so the SQL
        // stays fully bind-parameterized.
        let (exact, prefixes): (Vec<String>, Vec<String>) = query
            .action_types
            .iter()
            .cloned()
            .partition(|t| !t.ends_with(".*"));
        let prefixes: Vec<String> = prefixes
            .into_iter()
            .map(|p| p.trim_end_matches(".*").to_string())
            .collect();

        let rows = sqlx::query(
            "SELECT * FROM actions
             WHERE tenant_id = $1
               AND entities @> ARRAY[$2]::text[]
               AND visibility && $3
               AND confidentiality <= $4
               AND occurred_at >= COALESCE($5, '-infinity'::timestamptz)
               AND (cardinality($6::text[]) = 0 AND cardinality($7::text[]) = 0
                    OR action_type = ANY($6)
                    OR EXISTS (SELECT 1 FROM unnest($7::text[]) p
                               WHERE action_type LIKE p || '.%'))
               AND (cardinality($8::text[]) = 0 OR actor_azp = ANY($8))
             ORDER BY occurred_at DESC
             LIMIT $9",
        )
        .bind(scope.tenant_id)
        .bind(&query.entity)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(query.since)
        .bind(&exact)
        .bind(&prefixes)
        .bind(&query.actors)
        .bind(query.limit.clamp(1, 500) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_action).collect()
    }
}

impl PostgresAdapter {
    async fn insert_action_chunk(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        a: &ActionWrite,
        episode: EpisodeId,
    ) -> Result<()> {
        // Actions surface in semantic recall too (SPEC §2): the summary is
        // indexed as a Tier-2 chunk. Embedding is added when the local encoder
        // joins the write path; BM25 covers it until then.
        sqlx::query(
            "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                 content_hash, embedding, visibility, entity_tags,
                                 confidentiality, trust_tier, valid_from, provenance,
                                 acl_provenance)
             VALUES ($1, $2, 'agent', $3, 0, $4, $5, NULL, $6, $7, $8, $9, $10, $11,
                     'admin-assigned')
             ON CONFLICT (tenant_id, source, document_id, seq, valid_from) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(a.tenant_id)
        .bind(format!("action:{}", a.action_id))
        .bind(format!("{}: {}", a.action_type, a.summary))
        .bind(format!("action-{}", a.action_id))
        .bind(&a.visibility)
        .bind(&a.entities)
        .bind(a.confidentiality as i16)
        .bind(TrustTier::Observation as i16)
        .bind(a.occurred_at)
        .bind(episode)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
        Ok(())
    }
}

async fn insert_fact_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    fact: &FactWrite,
    valid_to: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO facts (id, tenant_id, source, entity_id, field, value,
                            valid_from, valid_to, provenance, acl_provenance)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(fact.tenant_id)
    .bind(&fact.key.source)
    .bind(&fact.key.entity_id)
    .bind(&fact.key.field)
    .bind(&fact.value)
    .bind(fact.valid_from)
    .bind(valid_to)
    .bind(fact.provenance)
    .bind(fact.acl_provenance.as_str())
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

fn row_to_action(row: &PgRow) -> Result<ActionRecord> {
    let outcome = match row
        .try_get::<String, _>("outcome")
        .map_err(db_err)?
        .as_str()
    {
        "succeeded" => ActionOutcome::Succeeded,
        "failed" => ActionOutcome::Failed,
        _ => ActionOutcome::Pending,
    };
    Ok(ActionRecord {
        id: row.try_get("id").map_err(db_err)?,
        action_id: row.try_get("action_id").map_err(db_err)?,
        actor_sub: row.try_get("actor_sub").map_err(db_err)?,
        actor_azp: row.try_get("actor_azp").map_err(db_err)?,
        action_type: row.try_get("action_type").map_err(db_err)?,
        entities: row.try_get("entities").map_err(db_err)?,
        summary: row.try_get("summary").map_err(db_err)?,
        payload: row.try_get("payload").map_err(db_err)?,
        outcome,
        occurred_at: row.try_get("occurred_at").map_err(db_err)?,
        recorded_at: row.try_get("recorded_at").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
    })
}

fn row_to_fact(row: &PgRow) -> Result<FactRow> {
    Ok(FactRow {
        id: row.try_get("id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        key: FactKey {
            source: row.try_get("source").map_err(db_err)?,
            entity_id: row.try_get("entity_id").map_err(db_err)?,
            field: row.try_get("field").map_err(db_err)?,
        },
        value: row.try_get("value").map_err(db_err)?,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_to: row.try_get("valid_to").map_err(db_err)?,
        superseded_by: row.try_get("superseded_by").map_err(db_err)?,
        recorded_at: row.try_get("recorded_at").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
        ),
    })
}
