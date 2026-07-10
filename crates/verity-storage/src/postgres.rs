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
}

impl PostgresAdapter {
    pub async fn connect(dsn: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(dsn)
            .await
            .map_err(db_err)?;
        Ok(Self { pool })
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

    async fn recall_dense(&self, q: &RecallQuery, embedding: &[f32]) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // Iterative scans keep filtered recall from collapsing under selective
        // predicates (pgvector 0.8, SPEC §4).
        sqlx::query("SET LOCAL hnsw.iterative_scan = relaxed_order")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        // Safe: the predicate string is assembled from constants only; all
        // caller data goes through binds.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, document_id, seq, content, entity_tags, trust_tier, valid_from, provenance,
                    1 - (embedding <=> $1) AS score
             FROM chunks
             WHERE tenant_id = $2
               AND valid_to IS NULL
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
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, document_id, seq, content, entity_tags, trust_tier, valid_from, provenance,
                    paradedb.score(id) AS score
             FROM chunks
             WHERE content @@@ $1
               AND tenant_id = $2
               AND valid_to IS NULL
               AND visibility && $3
               AND confidentiality <= $4
               {}
             ORDER BY paradedb.score(id) DESC
             LIMIT $5",
            entity_scope_predicate(scope, "$6"),
        )))
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
/// entity set; zero-tag content is excluded from entity-bound scopes.
fn entity_scope_predicate(scope: &Scope, bind: &str) -> String {
    if scope.entity_scope.is_empty() {
        String::new()
    } else {
        format!("AND entity_tags <> '{{}}' AND entity_tags <@ {bind}")
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
        trust_tier: tier_from_i16(row.try_get("trust_tier").map_err(db_err)?),
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
    })
}

fn tier_from_i16(v: i16) -> TrustTier {
    if v == 1 {
        TrustTier::Authoritative
    } else {
        TrustTier::Observation
    }
}

fn db_err(e: impl std::fmt::Display) -> StorageError {
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
        sqlx::query(
            "INSERT INTO episodes (id, tenant_id, source, source_entity, kind, payload,
                                   content_hash, trust_tier, writer_sub, writer_azp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(ep.tenant_id)
        .bind(&ep.source)
        .bind(&ep.source_entity)
        .bind(ep.kind.as_str())
        .bind(&ep.payload)
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
                                     confidentiality, trust_tier, valid_from, provenance)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
}

async fn insert_fact_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    fact: &FactWrite,
    valid_to: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO facts (id, tenant_id, source, entity_id, field, value,
                            valid_from, valid_to, provenance)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
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
    })
}
