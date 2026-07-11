//! Sleep-time consolidation plane (SPEC §2 L2 + knowledge items, §7d) — the
//! admin-gated lease/complete surface the async worker drives.
//!
//! Design notes:
//! - CDC episodes (`kind = 'cdc_event'`) are NEVER leased: their L1 extraction
//!   is deterministic at ingest time (SPEC §2 L1 — structured data is never
//!   run through LLM extraction), so there is nothing for a consolidation
//!   worker to do. Only unstructured kinds (observation, webhook, doc_version)
//!   are eligible.
//! - L2 facts ride the EXISTING L1 upsert machinery under source "l2" with
//!   key (source=l2, entity_id=normalized subject, field=normalized relation),
//!   so (subject, relation) supersession falls out structurally (SPEC §2 L2:
//!   supersession keyed on normalized subject+relation, never similarity).
//! - Tag suggestions are suggest-only by default. With VERITY_AUTO_TAG=1,
//!   suggestions at confidence >= 0.9 are applied to the chunk's entity_tags
//!   immediately (acl_provenance untouched — visibility is unchanged). NOTE:
//!   adding a tag to a chunk WIDENS retrieval scope for entity-bound scopes
//!   (§7d: a missed tag is unsafe, an extra tag on the wrong chunk admits it
//!   into a scope it wasn't retrievable from before), hence the explicit env
//!   opt-in rather than a default.
//! - Knowledge candidates go through the EXISTING propose_knowledge gate, but
//!   only after a similarity-merge check: a statement matching an existing
//!   candidate/published item (normalized-exact or embedding cosine >= the
//!   threshold) accrues evidence on that item (support accrual, SPEC v1.3 §2
//!   "agents are reinforcement voters") instead of minting a duplicate.
//!   Deviation from the recall-over-chunks sketch, documented: candidates have
//!   no §7g chunk until publish, so a recall over kind='knowledge' chunks can
//!   only ever see published items and the required candidate-merge path would
//!   never fire. The check instead runs directly over knowledge rows (both
//!   statuses) using the statement embedding stored at propose time.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

use crate::{internal, AppState, HandlerResult};

/// Lease duration for one worker pass over an episode.
const LEASE_MINUTES: i32 = 5;
/// Auto-apply floor: below this, VERITY_AUTO_TAG=1 still only suggests.
const AUTO_TAG_MIN_CONFIDENCE: f32 = 0.9;
/// Default cosine-similarity threshold for knowledge statement merge.
pub(crate) const DEFAULT_MERGE_THRESHOLD: f32 = 0.85;

/// SPEC §2 L2: supersession is keyed on NORMALIZED (subject, relation).
/// Normalization is deterministic: lowercase, trim, collapse whitespace.
pub(crate) fn normalize_term(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

// ---------- POST /v1/admin/consolidation/lease ----------

#[derive(Deserialize)]
pub(crate) struct LeaseRequest {
    tenant_id: TenantId,
    #[serde(default = "default_lease_limit")]
    limit: i64,
    #[serde(default)]
    worker: Option<String>,
}

fn default_lease_limit() -> i64 {
    16
}

/// Lease unprocessed non-CDC episodes for the consolidation worker, payloads
/// DECRYPTED (the worker runs in the trusted server plane, like connectors).
/// An episode is leasable when it has no processing row, or its row is
/// unprocessed with an expired lease. Leases last 5 minutes.
pub(crate) async fn lease(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LeaseRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let limit = req.limit.clamp(1, 256);
    let worker = req.worker.unwrap_or_else(|| "worker".into());

    // Claim atomically: candidates are inserted-or-release'd in one statement;
    // the ON CONFLICT WHERE guard makes concurrent workers lose gracefully.
    let leased: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "WITH cand AS (
             SELECT e.id FROM episodes e
             LEFT JOIN episode_processing p
               ON p.tenant_id = e.tenant_id AND p.episode_id = e.id
             WHERE e.tenant_id = $1
               AND e.kind IN ('observation', 'webhook', 'doc_version')
               AND (p.episode_id IS NULL
                    OR (p.processed_at IS NULL AND p.leased_until < now()))
             ORDER BY e.recorded_at
             LIMIT $2
         )
         INSERT INTO episode_processing (tenant_id, episode_id, leased_until, worker)
         SELECT $1, id, now() + make_interval(mins => $3), $4 FROM cand
         ON CONFLICT (tenant_id, episode_id) DO UPDATE
           SET leased_until = now() + make_interval(mins => $3),
               worker = EXCLUDED.worker
           WHERE episode_processing.processed_at IS NULL
             AND episode_processing.leased_until < now()
         RETURNING episode_id, leased_until",
    )
    .bind(req.tenant_id)
    .bind(limit)
    .bind(LEASE_MINUTES)
    .bind(&worker)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;

    let mut episodes = Vec::with_capacity(leased.len());
    for (episode_id, leased_until) in leased {
        let row = sqlx::query(
            "SELECT source, source_entity, kind, recorded_at FROM episodes
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(req.tenant_id)
        .bind(episode_id)
        .fetch_one(state.pool())
        .await
        .map_err(internal)?;
        // Decrypt-on-demand via the one sanctioned L0 payload read path.
        let payload = state
            .storage
            .inner()
            .episode_payload(req.tenant_id, episode_id)
            .await
            .map_err(internal)?
            .unwrap_or(serde_json::Value::Null);
        // Derived chunks ride along so the extractor can suggest tags per
        // retrieval unit (tag_suggestions are keyed on chunk_id).
        let chunks: Vec<(Uuid, String, Vec<String>)> = sqlx::query_as(
            "SELECT id, content, entity_tags FROM chunks
             WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL
             ORDER BY seq",
        )
        .bind(req.tenant_id)
        .bind(episode_id)
        .fetch_all(state.pool())
        .await
        .map_err(internal)?;

        episodes.push(serde_json::json!({
            "episode_id": episode_id,
            "source": row.try_get::<String, _>("source").map_err(internal)?,
            "source_entity": row.try_get::<Option<String>, _>("source_entity").map_err(internal)?,
            "kind": row.try_get::<String, _>("kind").map_err(internal)?,
            "recorded_at": row.try_get::<DateTime<Utc>, _>("recorded_at").map_err(internal)?,
            "leased_until": leased_until,
            "payload": payload,
            "chunks": chunks.into_iter().map(|(id, content, entity_tags)| serde_json::json!({
                "chunk_id": id,
                "content": content,
                "entity_tags": entity_tags,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "episodes": episodes })))
}

// ---------- POST /v1/admin/consolidation/complete ----------

#[derive(Deserialize)]
pub(crate) struct L2FactIn {
    subject: String,
    relation: String,
    object: serde_json::Value,
    #[serde(default)]
    valid_from: Option<DateTime<Utc>>,
    /// Controlled-vocabulary predicate the extractor derived from `relation`
    /// (requires_before / blocks_until / requires / ...). Used as the L1
    /// supersession `field` so re-extractions of the same relation align even
    /// when the free-text wording differs. Falls back to the normalized
    /// free-text relation when the extractor omits it.
    #[serde(default)]
    canonical_predicate: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct TagSuggestionIn {
    chunk_id: Uuid,
    tag: String,
    confidence: f32,
}

#[derive(Deserialize)]
pub(crate) struct KnowledgeCandidateIn {
    statement: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    evidence: Vec<EpisodeId>,
    /// Normalized canonical predication of `statement` (lowercased, filler
    /// stripped, controlled-vocab predicate). Drives the exact-match fast-path
    /// merge; the human `statement` is kept for display. `None` when the
    /// extractor emitted no canonical form (that candidate simply never takes
    /// the fast path — the cosine fallback still applies).
    #[serde(default)]
    canonical_statement: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CompleteRequest {
    tenant_id: TenantId,
    episode_id: EpisodeId,
    #[serde(default)]
    l2_facts: Vec<L2FactIn>,
    #[serde(default)]
    tag_suggestions: Vec<TagSuggestionIn>,
    #[serde(default)]
    knowledge_candidates: Vec<KnowledgeCandidateIn>,
}

/// Complete one leased episode: write L2 facts (deterministic bi-temporal
/// upserts under source "l2"), store/apply tag suggestions, and propose-or-
/// merge knowledge candidates. Idempotent on (tenant, episode): a second
/// complete is a no-op reporting `already_processed`.
pub(crate) async fn complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;

    // Terminal-state transition first: exactly one completer wins.
    let marked = sqlx::query(
        "UPDATE episode_processing SET processed_at = now()
         WHERE tenant_id = $1 AND episode_id = $2 AND processed_at IS NULL
         RETURNING episode_id",
    )
    .bind(req.tenant_id)
    .bind(req.episode_id)
    .fetch_optional(state.pool())
    .await
    .map_err(internal)?;
    if marked.is_none() {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT episode_id FROM episode_processing
             WHERE tenant_id = $1 AND episode_id = $2",
        )
        .bind(req.tenant_id)
        .bind(req.episode_id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?;
        return match exists {
            // Idempotent replay after a worker retry: drop the payload, the
            // first completion already wrote it.
            Some(_) => Ok(Json(serde_json::json!({ "already_processed": true }))),
            None => Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "episode was never leased for consolidation".into(),
            )),
        };
    }

    let recorded_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT recorded_at FROM episodes WHERE tenant_id = $1 AND id = $2")
            .bind(req.tenant_id)
            .bind(req.episode_id)
            .fetch_one(state.pool())
            .await
            .map_err(internal)?;

    // --- L2 facts: keyed upserts, supersession for free (SPEC §2 L2). ---
    let (mut inserted, mut superseded, mut unchanged) = (0u64, 0u64, 0u64);
    for fact in &req.l2_facts {
        // Supersession `field` keys on the CANONICAL predicate (a controlled
        // vocabulary) when the extractor supplies one, so re-extractions of the
        // same relation ("requires" vs "requires_before_security_assessment",
        // both -> "requires_before") align onto ONE (subject, relation) key and
        // supersede correctly. Falls back to the normalized free-text relation.
        let field = match fact.canonical_predicate.as_deref() {
            Some(p) if !p.trim().is_empty() => normalize_term(p),
            _ => normalize_term(&fact.relation),
        };
        let outcome = state
            .storage
            .upsert_fact(FactWrite {
                tenant_id: req.tenant_id,
                key: FactKey {
                    source: "l2".into(),
                    entity_id: normalize_term(&fact.subject),
                    field,
                },
                value: fact.object.clone(),
                valid_from: fact.valid_from.unwrap_or(recorded_at),
                provenance: req.episode_id,
                acl_provenance: AclProvenance::AdminAssigned,
            })
            .await
            .map_err(internal)?;
        match outcome {
            FactUpsertOutcome::Inserted => inserted += 1,
            FactUpsertOutcome::Superseded => superseded += 1,
            FactUpsertOutcome::Unchanged => unchanged += 1,
            FactUpsertOutcome::StaleEvent => {}
        }
    }

    // --- Tag suggestions (SPEC §7d): suggest-only unless auto-tag opted in. ---
    let (mut suggested, mut auto_applied) = (0u64, 0u64);
    for ts in &req.tag_suggestions {
        // The chunk must belong to the tenant — fail closed on foreign ids.
        let known: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM chunks WHERE tenant_id = $1 AND id = $2")
                .bind(req.tenant_id)
                .bind(ts.chunk_id)
                .fetch_optional(state.pool())
                .await
                .map_err(internal)?;
        if known.is_none() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("chunk {} not found in tenant", ts.chunk_id),
            ));
        }
        let apply = state.auto_tag && ts.confidence >= AUTO_TAG_MIN_CONFIDENCE;
        let status = if apply { "auto_applied" } else { "suggested" };
        sqlx::query(
            "INSERT INTO tag_suggestions (id, tenant_id, chunk_id, tag, confidence, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(req.tenant_id)
        .bind(ts.chunk_id)
        .bind(&ts.tag)
        .bind(ts.confidence)
        .bind(status)
        .execute(state.pool())
        .await
        .map_err(internal)?;
        if apply {
            apply_tag(&state, req.tenant_id, ts.chunk_id, &ts.tag).await?;
            auto_applied += 1;
        } else {
            suggested += 1;
        }
    }

    // --- Knowledge candidates: merge (support accrual) or propose fresh. ---
    let mut knowledge = Vec::new();
    for cand in &req.knowledge_candidates {
        let outcome = propose_or_merge(&state, req.tenant_id, cand).await?;
        knowledge.push(outcome);
    }

    Ok(Json(serde_json::json!({
        "episode_id": req.episode_id,
        "l2_facts": { "inserted": inserted, "superseded": superseded, "unchanged": unchanged },
        "tag_suggestions": { "suggested": suggested, "auto_applied": auto_applied },
        "knowledge": knowledge,
    })))
}

/// Apply a tag to a chunk's entity_tags in place (dedup'd). acl_provenance
/// and visibility are untouched — this changes ENTITY scoping only, and only
/// runs on the explicitly opted-in auto-tag path or human approval.
async fn apply_tag(
    state: &AppState,
    tenant: TenantId,
    chunk_id: Uuid,
    tag: &str,
) -> HandlerResult<()> {
    sqlx::query(
        "UPDATE chunks SET entity_tags = array_append(entity_tags, $3)
         WHERE tenant_id = $1 AND id = $2 AND NOT ($3 = ANY(entity_tags))",
    )
    .bind(tenant)
    .bind(chunk_id)
    .bind(tag)
    .execute(state.pool())
    .await
    .map_err(internal)?;
    Ok(())
}

/// Similarity-merge seam: an incoming candidate whose statement matches an
/// existing candidate/published item (normalized-exact, or stored-embedding
/// cosine >= threshold) accrues its evidence onto that item instead of
/// creating a new one. Otherwise it goes through the existing
/// propose_knowledge path (de-identification gate included) and its embedding
/// is stored for future merges.
async fn propose_or_merge(
    state: &Arc<AppState>,
    tenant: TenantId,
    cand: &KnowledgeCandidateIn,
) -> HandlerResult<serde_json::Value> {
    // --- Exact-canonical-match FAST PATH (knowledge-merge-tuning.md §3) ---
    // Before any embedding/LLM cost: if an existing candidate/published item in
    // this tenant has a byte-identical canonical_statement, merge immediately.
    // This is the safe, precise path — two paraphrases that canonicalize to the
    // same form ARE the same generalization (extraction guarantees distinct
    // generalizations do not collapse), so no similarity judgement is needed.
    if let Some(canon) = cand
        .canonical_statement
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let fast: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM knowledge
             WHERE tenant_id = $1 AND status IN ('candidate', 'published')
               AND canonical_statement = $2
             ORDER BY first_seen ASC
             LIMIT 1",
        )
        .bind(tenant)
        .bind(canon)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?;
        if let Some((knowledge_id,)) = fast {
            merge_evidence(state, tenant, knowledge_id, &cand.evidence).await?;
            return Ok(serde_json::json!({
                "knowledge_id": knowledge_id,
                "merged": true,
                "merge": "canonical_exact",
            }));
        }
    }

    let embedding = state.encode(&cand.statement).await.ok().flatten();
    let vector = embedding.clone().map(pgvector::Vector::from);

    let target: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM knowledge
         WHERE tenant_id = $1 AND status IN ('candidate', 'published')
           AND (lower(regexp_replace(statement, '\\s+', ' ', 'g')) = $2
                OR ($3::vector IS NOT NULL AND statement_embedding IS NOT NULL
                    AND 1 - (statement_embedding <=> $3) >= $4))
         ORDER BY (lower(regexp_replace(statement, '\\s+', ' ', 'g')) = $2) DESC,
                  statement_embedding <=> $3 ASC NULLS LAST
         LIMIT 1",
    )
    .bind(tenant)
    .bind(normalize_term(&cand.statement))
    .bind(vector.clone())
    .bind(state.knowledge_merge_threshold)
    .fetch_optional(state.pool())
    .await
    .map_err(internal)?;

    if let Some((knowledge_id,)) = target {
        merge_evidence(state, tenant, knowledge_id, &cand.evidence).await?;
        return Ok(serde_json::json!({
            "knowledge_id": knowledge_id,
            "merged": true,
            "merge": "cosine",
        }));
    }

    let item = state
        .storage
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: cand.statement.clone(),
            categories: cand.categories.clone(),
            evidence: cand.evidence.clone(),
            proposed_by_sub: None,
            proposed_by_azp: Some("consolidation-worker".into()),
        })
        .await
        .map_err(internal)?;
    // Store the canonical form for the exact-match fast path on future
    // candidates, and the embedding for the cosine fallback. Both are written on
    // the fresh row (propose_knowledge itself stays canonical-agnostic — the
    // human statement is its input, matching is a consolidation-plane concern).
    if let Some(canon) = cand
        .canonical_statement
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        sqlx::query(
            "UPDATE knowledge SET canonical_statement = $3 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(item.id)
        .bind(canon)
        .execute(state.pool())
        .await
        .map_err(internal)?;
    }
    if let Some(v) = vector {
        sqlx::query(
            "UPDATE knowledge SET statement_embedding = $3 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(item.id)
        .bind(v)
        .execute(state.pool())
        .await
        .map_err(internal)?;
    }
    Ok(serde_json::json!({
        "knowledge_id": item.id,
        "merged": false,
        "status": item.status,
    }))
}

/// Support accrual: add evidence rows (attribution read from the episodes
/// themselves, never caller-supplied — same rule as propose_knowledge),
/// recount support, bump last_reinforced.
async fn merge_evidence(
    state: &AppState,
    tenant: TenantId,
    knowledge_id: Uuid,
    evidence: &[EpisodeId],
) -> HandlerResult<()> {
    let mut tx = state.pool().begin().await.map_err(internal)?;
    let rows = sqlx::query(
        "SELECT id, source_entity, writer_azp, trust_tier FROM episodes
         WHERE tenant_id = $1 AND id = ANY($2)",
    )
    .bind(tenant)
    .bind(evidence)
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    for row in &rows {
        sqlx::query(
            "INSERT INTO knowledge_evidence (knowledge_id, episode_id, entity, writer_azp, trust_tier)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(knowledge_id)
        .bind(row.try_get::<Uuid, _>("id").map_err(internal)?)
        .bind(row.try_get::<Option<String>, _>("source_entity").map_err(internal)?)
        .bind(row.try_get::<Option<String>, _>("writer_azp").map_err(internal)?)
        .bind(row.try_get::<i16, _>("trust_tier").map_err(internal)?)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    sqlx::query(
        "UPDATE knowledge k SET
             distinct_entities = (SELECT count(DISTINCT entity) FROM knowledge_evidence
                                  WHERE knowledge_id = k.id AND entity IS NOT NULL),
             episode_count = (SELECT count(*) FROM knowledge_evidence WHERE knowledge_id = k.id),
             writer_count = (SELECT count(DISTINCT writer_azp) FROM knowledge_evidence
                             WHERE knowledge_id = k.id AND writer_azp IS NOT NULL),
             has_tier1_evidence = k.has_tier1_evidence OR EXISTS (
                 SELECT 1 FROM knowledge_evidence
                 WHERE knowledge_id = k.id AND trust_tier = 1),
             last_reinforced = now()
         WHERE k.id = $1 AND k.tenant_id = $2",
    )
    .bind(knowledge_id)
    .bind(tenant)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(())
}

// ---------- GET /v1/admin/tag-suggestions ----------

#[derive(Deserialize)]
pub(crate) struct ListTagSuggestionsParams {
    tenant_id: TenantId,
    status: Option<String>,
}

pub(crate) async fn list_tag_suggestions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<ListTagSuggestionsParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let rows = sqlx::query(
        "SELECT id, chunk_id, tag, confidence, status, created_at FROM tag_suggestions
         WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)
         ORDER BY created_at DESC LIMIT 500",
    )
    .bind(p.tenant_id)
    .bind(&p.status)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;
    let suggestions: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| -> HandlerResult<serde_json::Value> {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "chunk_id": row.try_get::<Uuid, _>("chunk_id").map_err(internal)?,
                "tag": row.try_get::<String, _>("tag").map_err(internal)?,
                "confidence": row.try_get::<f32, _>("confidence").map_err(internal)?,
                "status": row.try_get::<String, _>("status").map_err(internal)?,
                "created_at": row.try_get::<DateTime<Utc>, _>("created_at").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<_>>()?;
    Ok(Json(serde_json::json!({ "suggestions": suggestions })))
}

// ---------- POST /v1/admin/tag-suggestions/{id}/approve ----------

#[derive(Deserialize)]
pub(crate) struct ApproveTagRequest {
    tenant_id: TenantId,
}

/// Human review: approve a suggested tag, applying it to the chunk. Only
/// `suggested` rows can transition — approving twice (or approving a rejected
/// row) is a 422, not a silent double-apply.
pub(crate) async fn approve_tag_suggestion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ApproveTagRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let row = sqlx::query(
        "UPDATE tag_suggestions SET status = 'approved'
         WHERE tenant_id = $1 AND id = $2 AND status = 'suggested'
         RETURNING chunk_id, tag",
    )
    .bind(req.tenant_id)
    .bind(id)
    .fetch_optional(state.pool())
    .await
    .map_err(internal)?
    .ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "no suggestion in status 'suggested' with that id".to_string(),
    ))?;
    let chunk_id: Uuid = row.try_get("chunk_id").map_err(internal)?;
    let tag: String = row.try_get("tag").map_err(internal)?;
    apply_tag(&state, req.tenant_id, chunk_id, &tag).await?;
    Ok(Json(serde_json::json!({
        "id": id,
        "chunk_id": chunk_id,
        "tag": tag,
        "status": "approved",
    })))
}
