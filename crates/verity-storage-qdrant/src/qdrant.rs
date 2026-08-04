use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pgvector::Vector;
use qdrant_client::qdrant::{
    Condition, CreateCollectionBuilder, CreateFieldIndexCollectionBuilder, Direction, Distance,
    FieldType, Filter, OrderBy, OrderByBuilder, PointStruct, Query, QueryPointsBuilder, Range,
    ScrollPointsBuilder, UpsertPointsBuilder, VectorParamsBuilder, VectorsConfigBuilder,
};
use qdrant_client::{Payload, Qdrant};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

/// Embedding dimensionality — must match the Postgres profile's
/// `vector(384)` schema (SPEC §4a, same-model constraint).
pub const DIM: u64 = 384;

/// Name of the (single) named vector. Named so points without an embedding —
/// action chunks indexed for BM25 only — are storable; Qdrant requires the
/// default unnamed vector on every point, but named vectors may be omitted.
pub const DENSE_VECTOR: &str = "dense";

/// Oversampling for the entity-bound dense leg: the exact `<@` subset
/// residual (SPEC §7d) cannot be expressed as a Qdrant filter, so the filter
/// pre-selects any-overlap ∪ knowledge (a superset), a bounded candidate set
/// is fetched, and the exact subset check runs client-side — same
/// filter-then-rank shape as the Postgres profile's MATERIALIZED candidate
/// set. The residual only ever REMOVES results (soundness lives in the
/// filter + residual pair); oversampling bounds the completeness loss for
/// multi-tag chunks.
const ENTITY_CANDIDATE_FACTOR: usize = 4;
const ENTITY_CANDIDATE_MIN: usize = 64;

/// The SCALE-profile adapter (SPEC §3): chunks in Qdrant, everything else
/// delegated to the inner Postgres adapter. See the crate docs for the
/// hybrid-profile contract.
pub struct QdrantAdapter {
    inner: PostgresAdapter,
    qdrant: Qdrant,
    /// Tenants whose collection is known to exist (positive cache only).
    ensured: tokio::sync::Mutex<HashSet<TenantId>>,
}

/// Per-tenant collection: physical isolation per the SPEC §3 tenant model.
pub fn collection_name(tenant: TenantId) -> String {
    format!("verity_{tenant}")
}

/// Deterministic point id: uuid5 over the chunk's natural key
/// (tenant, source, document_id, seq, valid_from) — replaying the same write
/// upserts the same point (idempotent), and every version of a chunk position
/// is its own point.
pub fn point_id(
    tenant: TenantId,
    source: &str,
    document_id: &str,
    seq: i32,
    valid_from: DateTime<Utc>,
) -> Uuid {
    let name = format!(
        "{tenant}|{source}|{document_id}|{seq}|{}",
        valid_from.timestamp_micros()
    );
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}

/// One chunk row as mirrored into a Qdrant point. The Postgres row stays the
/// system of record; a point is always a pure function of its row, so
/// re-mirroring is idempotent and retirement (valid_to) follows automatically.
pub struct ChunkRow {
    pub id: Uuid,
    pub source: String,
    pub document_id: String,
    pub seq: i32,
    pub content: String,
    pub content_hash: String,
    pub embedding: Option<Vec<f32>>,
    pub visibility: Vec<i32>,
    pub entity_tags: Vec<String>,
    pub confidentiality: i16,
    pub trust_tier: i16,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub provenance: Uuid,
    pub acl_provenance: String,
    pub kind: String,
}

/// Build the Qdrant point for a chunk row. Payload carries every scope filter
/// the recall contract needs (visibility, entity_tags, confidentiality, kind,
/// valid_from/valid_to as epoch micros) plus the fields a `RecallHit` returns.
/// `pg_id` links the point back to its Postgres row so both recall legs speak
/// the same chunk ids.
pub fn chunk_point(tenant: TenantId, row: &ChunkRow) -> PointStruct {
    let mut payload = serde_json::json!({
        "pg_id": row.id.to_string(),
        "source": row.source,
        "document_id": row.document_id,
        "seq": row.seq,
        "content": row.content,
        "content_hash": row.content_hash,
        "visibility": row.visibility,
        "entity_tags": row.entity_tags,
        "confidentiality": row.confidentiality,
        "trust_tier": row.trust_tier,
        "kind": row.kind,
        "acl_provenance": row.acl_provenance,
        "valid_from": row.valid_from.timestamp_micros(),
        "provenance": row.provenance.to_string(),
    });
    if let Some(valid_to) = row.valid_to {
        // Only retired rows carry the key: "current" is filtered with
        // is_empty(valid_to), which matches absent keys.
        payload["valid_to"] = serde_json::json!(valid_to.timestamp_micros());
    }
    let vectors: HashMap<String, Vec<f32>> = match &row.embedding {
        Some(e) => HashMap::from([(DENSE_VECTOR.to_string(), e.clone())]),
        None => HashMap::new(),
    };
    let payload = Payload::try_from(payload).expect("chunk payload is a JSON object");
    PointStruct::new(
        point_id(
            tenant,
            &row.source,
            &row.document_id,
            row.seq,
            row.valid_from,
        )
        .to_string(),
        vectors,
        payload,
    )
}

impl QdrantAdapter {
    /// Connect both engines. `pg_dsn` is the durable tier (system of record),
    /// `qdrant_url` the serving tier (gRPC, e.g. `http://localhost:6334`).
    pub async fn connect(pg_dsn: &str, qdrant_url: &str) -> Result<Self> {
        let inner = PostgresAdapter::connect(pg_dsn).await?;
        Self::with_inner(inner, qdrant_url)
    }

    /// Wrap an already-connected Postgres adapter (test/bench seam).
    pub fn with_inner(inner: PostgresAdapter, qdrant_url: &str) -> Result<Self> {
        let qdrant = Qdrant::from_url(qdrant_url).build().map_err(qd_err)?;
        Ok(Self {
            inner,
            qdrant,
            ensured: tokio::sync::Mutex::new(HashSet::new()),
        })
    }

    /// The delegated Postgres adapter (also the migration seam for tests).
    pub fn inner(&self) -> &PostgresAdapter {
        &self.inner
    }

    /// The raw Qdrant client (bench/ops seam).
    pub fn qdrant(&self) -> &Qdrant {
        &self.qdrant
    }

    /// Ensure the tenant's collection exists, creating it (with payload
    /// indexes for every filterable field) on first write. Read paths use
    /// [`Self::collection_ready`] instead — reads never create state.
    pub async fn ensure_collection(&self, tenant: TenantId) -> Result<()> {
        {
            let ensured = self.ensured.lock().await;
            if ensured.contains(&tenant) {
                return Ok(());
            }
        }
        let name = collection_name(tenant);
        let exists = self.qdrant.collection_exists(&name).await.map_err(qd_err)?;
        if !exists {
            let mut vectors = VectorsConfigBuilder::default();
            vectors.add_named_vector_params(
                DENSE_VECTOR,
                VectorParamsBuilder::new(DIM, Distance::Cosine),
            );
            let created = self
                .qdrant
                .create_collection(CreateCollectionBuilder::new(&name).vectors_config(vectors))
                .await;
            if let Err(e) = created {
                // Lost a concurrent-creation race: fine iff it exists now.
                if !self.qdrant.collection_exists(&name).await.map_err(qd_err)? {
                    return Err(qd_err(e));
                }
            }
            // Payload indexes: the scope filters (visibility, entity_tags,
            // confidentiality, kind) so scoped ANN pre-filters ride the
            // filter-aware HNSW; valid_from (integer) additionally powers
            // latest_chunks' order_by; the rest serve the mirror/forget paths.
            for (field, ftype) in [
                ("visibility", FieldType::Integer),
                ("entity_tags", FieldType::Keyword),
                ("confidentiality", FieldType::Integer),
                ("kind", FieldType::Keyword),
                ("valid_from", FieldType::Integer),
                ("document_id", FieldType::Keyword),
                ("source", FieldType::Keyword),
                ("provenance", FieldType::Keyword),
            ] {
                self.qdrant
                    .create_field_index(
                        CreateFieldIndexCollectionBuilder::new(&name, field, ftype).wait(true),
                    )
                    .await
                    .map_err(qd_err)?;
            }
        }
        self.ensured.lock().await.insert(tenant);
        Ok(())
    }

    /// Read-path collection check: true iff the tenant has a collection.
    /// A tenant that never wrote a chunk has nothing to read — fail closed,
    /// create nothing.
    async fn collection_ready(&self, tenant: TenantId) -> Result<bool> {
        {
            let ensured = self.ensured.lock().await;
            if ensured.contains(&tenant) {
                return Ok(true);
            }
        }
        let exists = self
            .qdrant
            .collection_exists(collection_name(tenant))
            .await
            .map_err(qd_err)?;
        if exists {
            self.ensured.lock().await.insert(tenant);
        }
        Ok(exists)
    }

    /// Mirror a set of Postgres chunk rows into Qdrant points (idempotent
    /// full-point upsert; deterministic ids make replays overwrite in place).
    async fn mirror_rows(&self, tenant: TenantId, rows: Vec<ChunkRow>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.ensure_collection(tenant).await?;
        let points: Vec<PointStruct> = rows.iter().map(|r| chunk_point(tenant, r)).collect();
        self.qdrant
            .upsert_points(UpsertPointsBuilder::new(collection_name(tenant), points).wait(true))
            .await
            .map_err(qd_err)?;
        Ok(())
    }

    /// Fetch chunk rows from the system of record by an arbitrary predicate
    /// over `$1 = tenant_id` and one extra bind `$2`. The predicate string is
    /// assembled from constants only; caller data goes through the bind.
    async fn fetch_rows_where(
        &self,
        tenant: TenantId,
        where_sql: &str,
        bind: RowBind<'_>,
    ) -> Result<Vec<ChunkRow>> {
        let sql = format!(
            "SELECT id, source, document_id, seq, content, content_hash, embedding,
                    visibility, entity_tags, confidentiality, trust_tier,
                    valid_from, valid_to, provenance, acl_provenance, kind
             FROM chunks WHERE tenant_id = $1 AND ({where_sql})"
        );
        let query = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(tenant);
        let query = match bind {
            RowBind::Uuid(v) => query.bind(v),
            RowBind::Text(v) => query.bind(v.to_string()),
        };
        let rows = query.fetch_all(self.inner.pool()).await.map_err(db_err)?;
        rows.iter().map(row_to_chunk_row).collect()
    }

    /// Mirror every version of the given (source, document_id, seq) positions
    /// — after a Postgres write this carries both the new rows and the
    /// retirements (valid_to) it caused on prior versions.
    async fn mirror_positions(
        &self,
        tenant: TenantId,
        positions: &[(String, String, i32)],
    ) -> Result<()> {
        if positions.is_empty() {
            return Ok(());
        }
        let mut sources = Vec::with_capacity(positions.len());
        let mut docs = Vec::with_capacity(positions.len());
        let mut seqs = Vec::with_capacity(positions.len());
        for (source, doc, seq) in positions {
            sources.push(source.clone());
            docs.push(doc.clone());
            seqs.push(*seq);
        }
        let rows = sqlx::query(
            "SELECT c.id, c.source, c.document_id, c.seq, c.content, c.content_hash,
                    c.embedding, c.visibility, c.entity_tags, c.confidentiality,
                    c.trust_tier, c.valid_from, c.valid_to, c.provenance,
                    c.acl_provenance, c.kind
             FROM chunks c
             JOIN (SELECT DISTINCT * FROM unnest($2::text[], $3::text[], $4::int4[])
                   AS t(source, document_id, seq)) t
               ON c.source = t.source AND c.document_id = t.document_id AND c.seq = t.seq
             WHERE c.tenant_id = $1",
        )
        .bind(tenant)
        .bind(&sources)
        .bind(&docs)
        .bind(&seqs)
        .fetch_all(self.inner.pool())
        .await
        .map_err(db_err)?;
        let rows: Result<Vec<ChunkRow>> = rows.iter().map(row_to_chunk_row).collect();
        self.mirror_rows(tenant, rows?).await
    }

    /// The dense leg: filtered ANN in Qdrant, mirroring the Postgres profile's
    /// predicate exactly — visibility any-match, confidentiality ceiling,
    /// current-version only, and in entity-bound scopes the any-overlap ∪
    /// knowledge pre-filter with the exact subset residual client-side
    /// (SPEC §7d deny-by-default + §7g carve-out).
    async fn recall_dense(&self, q: &RecallQuery, embedding: &[f32]) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        if !self.collection_ready(scope.tenant_id).await? {
            return Ok(Vec::new());
        }
        let entity_bound = !scope.entity_scope.is_empty();
        let limit = if entity_bound {
            (q.k * ENTITY_CANDIDATE_FACTOR).max(ENTITY_CANDIDATE_MIN)
        } else {
            q.k
        };
        let response = self
            .qdrant
            .query(
                QueryPointsBuilder::new(collection_name(scope.tenant_id))
                    .query(Query::from(embedding.to_vec()))
                    .using(DENSE_VECTOR)
                    .filter(scope_filter(scope))
                    .limit(limit as u64)
                    .with_payload(true),
            )
            .await
            .map_err(qd_err)?;
        let mut hits = Vec::with_capacity(q.k.min(response.result.len()));
        for point in response.result {
            let hit = hit_from_payload(point.payload, point.score)?;
            // Exact subset residual (only ever removes results — see
            // ENTITY_CANDIDATE_FACTOR docs).
            if entity_bound && !entity_scope_admits(scope, &hit) {
                continue;
            }
            hits.push(hit);
            if hits.len() == q.k {
                break;
            }
        }
        Ok(hits)
    }
}

enum RowBind<'a> {
    Uuid(Uuid),
    Text(&'a str),
}

/// The mandatory pre-filter for scoped chunk reads in Qdrant. Soundness lives
/// here (plus the client-side subset residual for entity-bound scopes).
fn scope_filter(scope: &Scope) -> Filter {
    let mut must = vec![
        // Any-overlap between the chunk's visibility tokens and the caller's
        // principal set (`&&` in the Postgres profile). An empty principal
        // set is rejected before any query runs (fail closed).
        Condition::matches("visibility", to_i64(&scope.principals)),
        Condition::range(
            "confidentiality",
            Range {
                lte: Some(scope.max_confidentiality as i16 as f64),
                ..Default::default()
            },
        ),
        // Current version only: retired points carry valid_to; is_empty
        // matches points without the key.
        Condition::is_empty("valid_to"),
    ];
    if !scope.entity_scope.is_empty() {
        // Entity-bound scope: pre-filter to (tags any-overlap scope) OR the
        // §7g knowledge carve-out. Any-overlap is a superset of the required
        // subset semantics; the exact residual runs client-side.
        must.push(Condition::from(Filter::should([
            Condition::matches("entity_tags", scope.entity_scope.clone()),
            Condition::matches("kind", "knowledge".to_string()),
        ])));
    }
    Filter::must(must)
}

fn to_i64(principals: &[PrincipalToken]) -> Vec<i64> {
    principals.iter().map(|p| *p as i64).collect()
}

/// Exact entity predicate, identical to the Postgres profile's
/// `kind = 'knowledge' OR (entity_tags <> '{}' AND entity_tags <@ scope)`.
fn entity_scope_admits(scope: &Scope, hit: &RecallHit) -> bool {
    hit.kind == "knowledge"
        || (!hit.entity_tags.is_empty()
            && hit
                .entity_tags
                .iter()
                .all(|t| scope.entity_scope.contains(t)))
}

fn hit_from_payload(
    payload: HashMap<String, qdrant_client::qdrant::Value>,
    score: f32,
) -> Result<RecallHit> {
    let map: serde_json::Map<String, serde_json::Value> = payload
        .into_iter()
        .map(|(k, v)| (k, v.into_json()))
        .collect();
    let get_str = |key: &str| -> Result<String> {
        map.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| StorageError::Database(format!("qdrant payload missing {key}")))
    };
    let get_i64 = |key: &str| -> Result<i64> {
        map.get(key)
            .and_then(|v| v.as_i64())
            .ok_or_else(|| StorageError::Database(format!("qdrant payload missing {key}")))
    };
    let entity_tags = map
        .get("entity_tags")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(RecallHit {
        chunk_id: Uuid::parse_str(&get_str("pg_id")?).map_err(db_err)?,
        document_id: get_str("document_id")?,
        seq: get_i64("seq")? as i32,
        content: get_str("content")?,
        score,
        entity_tags,
        kind: get_str("kind")?,
        // Knowledge support tier is a publish-time field on the Postgres
        // carve-out chunk; the Qdrant payload does not mirror it (this profile
        // delegates knowledge/publish to Postgres), so it is absent here.
        support_tier: None,
        acl_provenance: AclProvenance::from_str_lossy(&get_str("acl_provenance")?),
        trust_tier: if get_i64("trust_tier")? == 1 {
            TrustTier::Authoritative
        } else {
            TrustTier::Observation
        },
        valid_from: DateTime::from_timestamp_micros(get_i64("valid_from")?)
            .ok_or_else(|| StorageError::Database("bad valid_from micros".into()))?,
        provenance: Uuid::parse_str(&get_str("provenance")?).map_err(db_err)?,
    })
}

fn row_to_chunk_row(row: &sqlx::postgres::PgRow) -> Result<ChunkRow> {
    Ok(ChunkRow {
        id: row.try_get("id").map_err(db_err)?,
        source: row.try_get("source").map_err(db_err)?,
        document_id: row.try_get("document_id").map_err(db_err)?,
        seq: row.try_get("seq").map_err(db_err)?,
        content: row.try_get("content").map_err(db_err)?,
        content_hash: row.try_get("content_hash").map_err(db_err)?,
        embedding: row
            .try_get::<Option<Vector>, _>("embedding")
            .map_err(db_err)?
            .map(|v| v.to_vec()),
        visibility: row.try_get("visibility").map_err(db_err)?,
        entity_tags: row.try_get("entity_tags").map_err(db_err)?,
        confidentiality: row.try_get("confidentiality").map_err(db_err)?,
        trust_tier: row.try_get("trust_tier").map_err(db_err)?,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_to: row.try_get("valid_to").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
        acl_provenance: row.try_get("acl_provenance").map_err(db_err)?,
        kind: row.try_get("kind").map_err(db_err)?,
    })
}

fn qd_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(format!("qdrant: {e}"))
}

fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// Reciprocal-rank fusion of the dense and sparse result lists.
///
/// Duplicated from `verity_storage::postgres` (where it is private): both
/// legs of this profile return Postgres chunk ids (the `pg_id` payload on
/// Qdrant points), so fusion dedupes on `chunk_id` exactly like the Postgres
/// profile. Keep the two copies in sync until fusion moves into the shared
/// layer above the trait.
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
impl StorageAdapter for QdrantAdapter {
    async fn create_tenant(&self, name: &str) -> Result<TenantId> {
        let tenant = self.inner.create_tenant(name).await?;
        self.ensure_collection(tenant).await?;
        Ok(tenant)
    }

    async fn list_tenants(&self, limit: i64) -> Result<Vec<TenantRow>> {
        // Tenants live in the relational inner store; the directory read
        // (FTUE §2.1) delegates like every other tenant-plane call.
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
        self.inner.upsert_fact(fact).await
    }

    async fn current_fact(&self, scope: &Scope, key: &FactKey) -> Result<Option<FactRow>> {
        // Pure delegator: L1 facts live in Postgres (the inner adapter), which
        // applies the scope visibility pre-filter. Just forward the scope.
        self.inner.current_fact(scope, key).await
    }

    async fn fact_as_of(
        &self,
        scope: &Scope,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        self.inner.fact_as_of(scope, key, as_of).await
    }

    /// Dual write: Postgres first (system of record, BM25 leg, bi-temporal
    /// retire of prior versions), then the touched positions are mirrored
    /// into Qdrant — new versions as new deterministic points, retired prior
    /// versions get their valid_to payload via the same idempotent re-mirror.
    async fn upsert_chunks(&self, chunks: Vec<ChunkWrite>) -> Result<usize> {
        if chunks.is_empty() {
            return Ok(0);
        }
        let tenant = chunks[0].tenant_id;
        if chunks.iter().any(|c| c.tenant_id != tenant) {
            return Err(StorageError::InvalidInput(
                "one upsert_chunks batch, one tenant".into(),
            ));
        }
        let positions: Vec<(String, String, i32)> = chunks
            .iter()
            .map(|c| (c.source.clone(), c.document_id.clone(), c.seq))
            .collect();
        let written = self.inner.upsert_chunks(chunks).await?;
        self.mirror_positions(tenant, &positions).await?;
        Ok(written)
    }

    async fn recall(&self, query: RecallQuery) -> Result<Vec<RecallHit>> {
        // Fail closed: no principals, no results — same shared rule as the
        // Postgres profile, checked before any engine is touched.
        if query.scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        match (&query.embedding, &query.text) {
            (Some(embedding), Some(text)) => {
                let sparse_query = RecallQuery {
                    scope: query.scope.clone(),
                    embedding: None,
                    text: Some(text.clone()),
                    k: query.k,
                };
                let (dense, sparse) = tokio::join!(
                    self.recall_dense(&query, embedding),
                    // Text leg delegates to the inner adapter's pg_search
                    // BM25 path (text-only recall).
                    self.inner.recall(sparse_query)
                );
                Ok(rrf_fuse(vec![dense?, sparse?], query.k))
            }
            (Some(embedding), None) => self.recall_dense(&query, embedding).await,
            (None, Some(_)) => self.inner.recall(query).await,
            (None, None) => Err(StorageError::InvalidInput(
                "recall requires an embedding, text, or both".into(),
            )),
        }
    }

    async fn record_action(&self, action: ActionWrite) -> Result<bool> {
        let tenant = action.tenant_id;
        let document_id = format!("action:{}", action.action_id);
        let recorded = self.inner.record_action(action).await?;
        if recorded {
            // Mirror the action's Tier-2 recall chunk (no embedding — the
            // BM25 leg covers it; the point exists so latest_chunks sees it).
            let rows = self
                .fetch_rows_where(
                    tenant,
                    "source = 'agent' AND document_id = $2",
                    RowBind::Text(&document_id),
                )
                .await?;
            self.mirror_rows(tenant, rows).await?;
        }
        Ok(recorded)
    }

    async fn activity(&self, query: ActivityQuery) -> Result<Vec<ActionRecord>> {
        self.inner.activity(query).await
    }

    /// Newest current chunks for an entity, served from Qdrant: same scope
    /// contract as the Postgres profile (fail-closed principals, an
    /// entity-bound scope may only read entities it covers, tag containment,
    /// visibility overlap, confidentiality ceiling), ordered by valid_from
    /// descending via the integer payload index.
    async fn latest_chunks(
        &self,
        scope: &Scope,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<RecallHit>> {
        if scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&entity.to_string()) {
            return Ok(Vec::new());
        }
        if !self.collection_ready(scope.tenant_id).await? {
            return Ok(Vec::new());
        }
        let filter = Filter::must([
            Condition::matches("visibility", to_i64(&scope.principals)),
            Condition::range(
                "confidentiality",
                Range {
                    lte: Some(scope.max_confidentiality as i16 as f64),
                    ..Default::default()
                },
            ),
            Condition::is_empty("valid_to"),
            // `entity_tags @> ARRAY[entity]`: single-value match on a keyword
            // array field is containment.
            Condition::matches("entity_tags", entity.to_string()),
        ]);
        let order_by: OrderBy = OrderByBuilder::new("valid_from")
            .direction(Direction::Desc as i32)
            .build();
        let response = self
            .qdrant
            .scroll(
                ScrollPointsBuilder::new(collection_name(scope.tenant_id))
                    .filter(filter)
                    .order_by(order_by)
                    .limit(limit.clamp(1, 100) as u32)
                    .with_payload(true),
            )
            .await
            .map_err(qd_err)?;
        response
            .result
            .into_iter()
            .map(|point| hit_from_payload(point.payload, 0.0))
            .collect()
    }

    async fn propose_knowledge(&self, proposal: KnowledgeProposal) -> Result<KnowledgeItem> {
        self.inner.propose_knowledge(proposal).await
    }

    async fn publish_knowledge(
        &self,
        tenant: TenantId,
        id: Uuid,
        visibility: Vec<PrincipalToken>,
        k_min: i32,
        embedding: Option<Vec<f32>>,
    ) -> Result<KnowledgeItem> {
        let item = self
            .inner
            .publish_knowledge(tenant, id, visibility, k_min, embedding)
            .await?;
        // Mirror the §7g carve-out chunk so the dense leg serves it too.
        let document_id = format!("knowledge:{id}");
        let rows = self
            .fetch_rows_where(
                tenant,
                "source = 'knowledge' AND document_id = $2",
                RowBind::Text(&document_id),
            )
            .await?;
        self.mirror_rows(tenant, rows).await?;
        Ok(item)
    }

    async fn list_knowledge(
        &self,
        tenant: TenantId,
        status: Option<KnowledgeStatus>,
    ) -> Result<Vec<KnowledgeItem>> {
        self.inner.list_knowledge(tenant, status).await
    }

    /// Delegates the retire (and, for episodes, the knowledge retraction
    /// cascade) to Postgres, then re-mirrors every affected row so the Qdrant
    /// points pick up their valid_to. Invalidate-don't-delete on both engines.
    async fn forget(&self, tenant: TenantId, ref_kind: ForgetRef, reason: &str) -> Result<u64> {
        let retired = self.inner.forget(tenant, ref_kind, reason).await?;
        match ref_kind {
            ForgetRef::Chunk(chunk_id) => {
                let rows = self
                    .fetch_rows_where(tenant, "id = $2", RowBind::Uuid(chunk_id))
                    .await?;
                self.mirror_rows(tenant, rows).await?;
            }
            ForgetRef::Episode(episode_id) => {
                // The episode's own chunks, plus any §7g knowledge chunk the
                // retraction cascade just retired (different provenance — the
                // publish episode). Re-mirroring already-retired knowledge
                // chunks is an idempotent no-op state-wise; bounded by the
                // tenant's retired knowledge items.
                let rows = self
                    .fetch_rows_where(
                        tenant,
                        "provenance = $2
                         OR (document_id LIKE 'knowledge:%' AND valid_to IS NOT NULL)",
                        RowBind::Uuid(episode_id),
                    )
                    .await?;
                self.mirror_rows(tenant, rows).await?;
            }
        }
        Ok(retired)
    }

    /// Source hard-delete propagation. The inner adapter closes the entity's
    /// current facts; this profile ADDITIONALLY retires the entity's current
    /// chunks from that source (Postgres row and Qdrant point both get
    /// valid_to = deleted_at) so the serving index stops surfacing a deleted
    /// entity's content — a documented superset of the Postgres profile's
    /// fact-only behavior (SPEC §8c; history stays queryable via bi-temporal
    /// reads, hard purge remains the §8 hard-purge pipeline). Returns
    /// the number of facts retired (trait contract).
    async fn retire_entity(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64> {
        let facts_retired = self
            .inner
            .retire_entity(tenant, source, entity_id, deleted_at)
            .await?;
        let touched = sqlx::query(
            "UPDATE chunks SET valid_to = $1
             WHERE tenant_id = $2 AND source = $3
               AND entity_tags @> ARRAY[$4]::text[] AND valid_to IS NULL
             RETURNING source, document_id, seq",
        )
        .bind(deleted_at)
        .bind(tenant)
        .bind(source)
        .bind(entity_id)
        .fetch_all(self.inner.pool())
        .await
        .map_err(db_err)?;
        let positions: Vec<(String, String, i32)> = touched
            .iter()
            .map(|r| {
                Ok((
                    r.try_get("source").map_err(db_err)?,
                    r.try_get("document_id").map_err(db_err)?,
                    r.try_get("seq").map_err(db_err)?,
                ))
            })
            .collect::<Result<_>>()?;
        self.mirror_positions(tenant, &positions).await?;
        Ok(facts_retired)
    }

    /// Delegates the retire (chunk close + ledger append) to Postgres, then
    /// re-mirrors every row of the `(source, document_id)` lineage so the
    /// Qdrant points pick up their closed `valid_to` and blanked visibility.
    /// Invalidate-don't-delete on both engines; a 0-chunk replay re-mirrors an
    /// already-retired lineage, which is an idempotent no-op state-wise.
    async fn retire_document(
        &self,
        tenant: TenantId,
        source: &str,
        document_id: &str,
        reason: &str,
    ) -> Result<u64> {
        let retired = self
            .inner
            .retire_document(tenant, source, document_id, reason)
            .await?;
        let touched = sqlx::query(
            "SELECT source, document_id, seq FROM chunks
             WHERE tenant_id = $1 AND source = $2 AND document_id = $3",
        )
        .bind(tenant)
        .bind(source)
        .bind(document_id)
        .fetch_all(self.inner.pool())
        .await
        .map_err(db_err)?;
        let positions: Vec<(String, String, i32)> = touched
            .iter()
            .map(|r| {
                Ok((
                    r.try_get("source").map_err(db_err)?,
                    r.try_get("document_id").map_err(db_err)?,
                    r.try_get("seq").map_err(db_err)?,
                ))
            })
            .collect::<Result<_>>()?;
        self.mirror_positions(tenant, &positions).await?;
        Ok(retired)
    }
}
