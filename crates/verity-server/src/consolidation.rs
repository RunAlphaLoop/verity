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
//!   only after the three-stage merge cascade (knowledge-merge-tuning.md §2,
//!   Phase 2). A candidate merges (accrues evidence, SPEC v1.3 §2 "agents are
//!   reinforcement voters") into an existing candidate/published item ONLY via:
//!     1. the DETERMINISTIC canonical-exact fast path — byte-identical
//!        canonical_statement, no embedding/LLM cost (Phase 1), or
//!     2. a worker-supplied JUDGED decision — the worker calls the
//!        merge-candidates endpoint (the BLOCKER: low-τ cosine + shared-category
//!        pre-filter over knowledge rows), runs its LLM judge over the returned
//!        set, and passes {merge_into, judge_reason} back in complete(). The
//!        server VALIDATES merge_into (same tenant, still candidate/published)
//!        and records the reason. Fail-closed on invalid → fresh candidate.
//!
//!   The old bare cosine auto-merge (τ=0.85 on the write path) is REMOVED: the
//!   server no longer decides a semantic merge on cosine alone. A false merge
//!   fabricates cross-customer support (§1's governing asymmetry), so the
//!   semantic call is the worker's precision-tuned judge, gated + recorded,
//!   never a 384-d threshold. The stored statement_embedding now feeds the
//!   blocker's candidate-set query, not an auto-merge.
//!
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

use crate::{internal, storage_status, AppState, HandlerResult};

/// Lease duration for one worker pass over an episode.
const LEASE_MINUTES: i32 = 5;
/// Auto-apply floor: below this, VERITY_AUTO_TAG=1 still only suggests.
const AUTO_TAG_MIN_CONFIDENCE: f32 = 0.9;
// NOTE: the legacy cosine merge threshold (VERITY_KNOWLEDGE_MERGE_THRESHOLD,
// default 0.85) is GONE from the write path — Phase 2 removed the bare
// cosine auto-merge (knowledge-merge-tuning.md §2). It survives only as the
// historical baseline the cascade must beat, measured in verity-bench metric #6
// (which keeps its own copy of the constant). The server no longer reads it.
/// BLOCKER threshold (knowledge-merge-tuning.md §2, stage 1): a LOW cosine floor
/// whose only job is to bound the candidate set the judge sees. High recall /
/// low precision by design — precision comes from the stage-2 judge, not here.
pub(crate) const TAU_BLOCK: f32 = 0.45;
/// Cap on the blocker candidate set handed to the judge, top-N by cosine. Bounds
/// the worker's per-candidate LLM-call count (§7 cost mitigation).
const BLOCKER_CANDIDATE_CAP: i64 = 8;
/// k-distinct-entity support floor (SPEC v1.3 §2, default k=3). Below this an
/// item never becomes eligible/published: at k=2 either supporting party could
/// infer the other's interaction (membership inference). The publish gate
/// clamps its own k_min to this too.
pub(crate) const K_SUPPORT_MIN: i32 = 3;

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
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
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
    /// the fast path).
    #[serde(default)]
    canonical_statement: Option<String>,
    /// The judge's DECISION (knowledge-merge-tuning.md §2, stage 2): the existing
    /// knowledge_id the WORKER's LLM judge ruled is the SAME generalization as
    /// this candidate. `None` = no judged merge (blocker empty, judge said NO, or
    /// the LLM was unavailable — all fail-closed to a fresh candidate). The
    /// server VALIDATES this id (same tenant, still candidate/published) before
    /// merging; an invalid id fails closed to a fresh candidate. It never
    /// overrides the canonical-exact fast path (that runs first, deterministically).
    #[serde(default)]
    merge_into: Option<Uuid>,
    /// One-line rationale the judge recorded for `merge_into`. Stored on the
    /// merge (§5: "no merge is authoritative without the judge's recorded
    /// reason") — auditable, reversible.
    #[serde(default)]
    judge_reason: Option<String>,
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
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;

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

// ---------- POST /v1/admin/consolidation/merge-candidates ----------

#[derive(Deserialize)]
pub(crate) struct MergeCandidatesRequest {
    tenant_id: TenantId,
    /// The proposed candidate's canonical form (drives the deterministic exact
    /// fast path the worker mirrors) — echoed back for the worker's convenience.
    #[serde(default)]
    canonical_statement: Option<String>,
    /// Statement to embed for the blocker's cosine leg. The server embeds it with
    /// its own encoder; the worker never supplies vectors.
    #[serde(default)]
    statement: Option<String>,
    /// Categories of the proposed candidate — the shared-category (Jaccard > 0)
    /// pre-filter. Empty categories means no category signal; the blocker then
    /// returns cosine-only matches (the judge is still the decision).
    #[serde(default)]
    categories: Vec<String>,
}

/// BLOCKER (knowledge-merge-tuning.md §2, stage 1): return the candidate SET the
/// WORKER's judge should rule on. Server-side and cheap: embed the statement,
/// find existing candidate/published knowledge in this tenant with cosine at or
/// above τ_block (LOW, recall-oriented) AND sharing at least one category
/// (Jaccard > 0 when the caller supplies categories), capped at the top-N by
/// cosine. An empty set means the worker mints a fresh candidate with no LLM
/// call. This surface makes NO merge decision — it only bounds how many
/// comparisons the judge makes.
///
/// Fail-closed: with no encoder the cosine leg is dead; the endpoint returns an
/// empty set (never a bare merge). The exact-canonical fast path still runs in
/// complete() regardless.
pub(crate) async fn merge_candidates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MergeCandidatesRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;

    let statement = req.statement.as_deref().unwrap_or("");
    let embedding = if statement.is_empty() {
        None
    } else {
        state.encode(statement).await.ok().flatten()
    };
    let Some(embedding) = embedding else {
        // No encoder / empty statement: the blocker cannot shrink the space, so
        // it hands the judge nothing. The worker mints fresh (fail-closed).
        return Ok(Json(serde_json::json!({ "candidates": [] })));
    };
    let vector = pgvector::Vector::from(embedding);

    // Category pre-filter: when the caller supplies categories, require Jaccard
    // overlap > 0 (shared >= 1 category). `&&` is the pg array-overlap operator.
    // Empty categories → no category constraint (cosine-only candidate set).
    let has_categories = !req.categories.is_empty();
    let rows = sqlx::query(
        "SELECT id, statement, categories, 1 - (statement_embedding <=> $2) AS cosine
         FROM knowledge
         WHERE tenant_id = $1
           AND status IN ('candidate', 'published')
           AND statement_embedding IS NOT NULL
           AND 1 - (statement_embedding <=> $2) >= $3
           AND ($4 = false OR categories && $5)
         ORDER BY statement_embedding <=> $2 ASC
         LIMIT $6",
    )
    .bind(req.tenant_id)
    .bind(&vector)
    .bind(TAU_BLOCK)
    .bind(has_categories)
    .bind(&req.categories)
    .bind(BLOCKER_CANDIDATE_CAP)
    .fetch_all(state.pool())
    .await
    .map_err(internal)?;

    let candidates: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| -> HandlerResult<serde_json::Value> {
            Ok(serde_json::json!({
                "knowledge_id": row.try_get::<Uuid, _>("id").map_err(internal)?,
                "statement": row.try_get::<String, _>("statement").map_err(internal)?,
                "categories": row.try_get::<Vec<String>, _>("categories").map_err(internal)?,
                "cosine": row.try_get::<f64, _>("cosine").map_err(internal)?,
            }))
        })
        .collect::<HandlerResult<_>>()?;

    Ok(Json(serde_json::json!({
        "canonical_statement": req.canonical_statement,
        "tau_block": TAU_BLOCK,
        "candidates": candidates,
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

/// The Phase-2 merge cascade for one candidate (knowledge-merge-tuning.md §2).
/// A candidate accrues its evidence onto an existing item ONLY via (1) the
/// DETERMINISTIC canonical-exact fast path (byte-identical canonical_statement,
/// no embedding/LLM cost), or (2) a worker-supplied JUDGED decision carrying
/// `merge_into` and `judge_reason`, which the server VALIDATES (same tenant,
/// still candidate/published) and records. The bare cosine auto-merge is GONE:
/// absent both, the
/// candidate is fresh (a missed merge, the acceptable failure — never a false
/// merge). Its embedding is stored so the blocker can surface it to the judge
/// for future candidates.
async fn propose_or_merge(
    state: &Arc<AppState>,
    tenant: TenantId,
    cand: &KnowledgeCandidateIn,
) -> HandlerResult<serde_json::Value> {
    // --- Stage 1a: exact-canonical-match FAST PATH (deterministic, no LLM). ---
    // If an existing candidate/published item in this tenant has a byte-identical
    // canonical_statement, merge immediately. Two paraphrases that canonicalize
    // to the same form ARE the same generalization (extraction guarantees
    // distinct generalizations do not collapse), so no judge is needed. This runs
    // BEFORE any judged decision — the deterministic path wins.
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
            let promotion = promote_if_eligible(state, tenant, knowledge_id).await?;
            return Ok(serde_json::json!({
                "knowledge_id": knowledge_id,
                "merged": true,
                "merge": "canonical_exact",
                "promotion": promotion,
            }));
        }
    }

    // --- Stage 2: JUDGED merge (the worker's LLM judge already decided). ---
    // The worker called merge-candidates (the blocker), ran its judge over the
    // returned set, and — if the judge said "same generalization" — passed the
    // existing knowledge_id here. The server does NOT re-run the judge; it
    // VALIDATES the decision and fails closed to a fresh candidate on anything
    // invalid (wrong tenant, nonexistent, or no longer candidate/published).
    //
    // Kill switch (VERITY_KNOWLEDGE_AUTO_MERGE=0, §5): when the judged-merge leg
    // is disabled, the server ignores merge_into ENTIRELY — only the
    // canonical-exact fast path above merges, everything else queues as a fresh
    // candidate for human clustering. Consolidation degrades to assisted, never
    // a silent judged merge.
    if let (true, Some(target_id)) = (state.knowledge_auto_merge, cand.merge_into) {
        let valid: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM knowledge
             WHERE tenant_id = $1 AND id = $2 AND status IN ('candidate', 'published')",
        )
        .bind(tenant)
        .bind(target_id)
        .fetch_optional(state.pool())
        .await
        .map_err(internal)?;
        match valid {
            Some((knowledge_id,)) => {
                merge_evidence(state, tenant, knowledge_id, &cand.evidence).await?;
                let reason = cand
                    .judge_reason
                    .as_deref()
                    .map(str::trim)
                    .filter(|r| !r.is_empty());
                if let Some(reason) = reason {
                    sqlx::query(
                        "UPDATE knowledge SET merge_reason = $3
                         WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant)
                    .bind(knowledge_id)
                    .bind(reason)
                    .execute(state.pool())
                    .await
                    .map_err(internal)?;
                }
                let promotion = promote_if_eligible(state, tenant, knowledge_id).await?;
                return Ok(serde_json::json!({
                    "knowledge_id": knowledge_id,
                    "merged": true,
                    "merge": "judge",
                    "judge_reason": reason,
                    "promotion": promotion,
                }));
            }
            None => {
                // Fail closed: the judge's target is invalid. Log and fall
                // through to a fresh candidate — NEVER a bare merge.
                tracing::warn!(
                    tenant = %tenant, merge_into = %target_id,
                    "consolidation: rejecting invalid judged merge_into (wrong tenant, \
                     nonexistent, or not candidate/published); proposing fresh candidate"
                );
            }
        }
    }

    // --- Fresh candidate: blocker empty / judge NO / judge invalid / LLM down. ---
    // The candidate's statement embedding is stored below so the blocker can
    // surface THIS item to the judge when future candidates arrive.
    let embedding = state.encode(&cand.statement).await.ok().flatten();
    let vector = embedding.map(pgvector::Vector::from);

    // Pass the canonical form INTO propose: it drives the rejection-memory check
    // (§5 — a rejected canonical form must not resurrect) and is stored for the
    // exact-match fast path. propose_knowledge returns the remembered rejected
    // item unchanged if this canonical/statement was already rejected.
    let item = state
        .storage
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: cand.statement.clone(),
            categories: cand.categories.clone(),
            evidence: cand.evidence.clone(),
            proposed_by_sub: None,
            proposed_by_azp: Some("consolidation-worker".into()),
            canonical_statement: cand.canonical_statement.clone(),
        })
        .await
        .map_err(internal)?;
    // A rejected canonical form does not resurrect: propose returned the
    // remembered row untouched. Report it, do not accrue support onto it.
    if item.status == verity_core::types::KnowledgeStatus::Rejected {
        return Ok(serde_json::json!({
            "knowledge_id": item.id,
            "merged": false,
            "status": item.status,
            "rejected_memory": true,
        }));
    }
    // Store the statement embedding for the BLOCKER's candidate-set query on
    // future candidates (canonical_statement is already persisted by propose).
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
    let promotion = promote_if_eligible(state, tenant, item.id).await?;
    Ok(serde_json::json!({
        "knowledge_id": item.id,
        "merged": false,
        "status": item.status,
        "promotion": promotion,
    }))
}

/// Promotion decision after support accrual (knowledge-merge-tuning.md §5, the
/// load-bearing promise). A `candidate` that has crossed the k-support floor
/// (distinct_entities >= K_SUPPORT_MIN) and corroboration becomes:
///   - `eligible` (auto-publish OFF, the default) — reviewed-ready, WAITING for
///     a human/policy publish call. It is NOT retrievable; publishing is the
///     only thing that mints the §7g carve-out chunk.
///   - auto-published (auto-publish ON, per-tenant opt-in) — promoted through
///     the SAME publish gate on this background/admin path, using the tenant's
///     configured default visibility. STILL never on the read path.
///
/// Anything not a candidate, or below support, is left untouched. Returns a
/// small JSON describing what happened, for the complete() response + audit.
async fn promote_if_eligible(
    state: &Arc<AppState>,
    tenant: TenantId,
    knowledge_id: Uuid,
) -> HandlerResult<serde_json::Value> {
    // Re-read the freshly-recounted item.
    let Some(item) = state
        .storage
        .inner()
        .knowledge_item(tenant, knowledge_id)
        .await
        .map_err(internal)?
    else {
        return Ok(serde_json::json!({ "action": "none" }));
    };
    use verity_core::types::KnowledgeStatus;
    // Only a candidate is promotable; published/eligible/rejected are terminal
    // for this path. Below k-support (or corroboration) it simply stays a
    // candidate.
    if item.status != KnowledgeStatus::Candidate {
        return Ok(serde_json::json!({ "action": "none", "status": item.status }));
    }
    let corroborated = item.writer_count >= 2 || item.has_tier1_evidence;
    if item.distinct_entities < K_SUPPORT_MIN || !corroborated {
        return Ok(serde_json::json!({ "action": "none", "status": item.status }));
    }

    let auto_publish = state
        .storage
        .inner()
        .knowledge_auto_publish(tenant)
        .await
        .map_err(internal)?;

    if !auto_publish {
        // The DEFAULT, OSS-conservative path: mark eligible and WAIT. Never
        // publishes without a human/policy call.
        let moved = state
            .storage
            .inner()
            .mark_knowledge_eligible(tenant, knowledge_id)
            .await
            .map_err(internal)?;
        return Ok(serde_json::json!({
            "action": if moved { "marked_eligible" } else { "none" },
            "auto_publish": false,
        }));
    }

    // Auto-publish is opted IN for this tenant. Promote through the SAME publish
    // gate (k-support, corroboration, de-id already enforced) on this background
    // path, using the tenant's configured default visibility. If no default
    // visibility is configured, we cannot publish safely — fall back to
    // eligible (fail-safe: never publish to an unknown audience).
    let visibility = default_publish_visibility(state, tenant).await?;
    let Some(visibility) = visibility else {
        let moved = state
            .storage
            .inner()
            .mark_knowledge_eligible(tenant, knowledge_id)
            .await
            .map_err(internal)?;
        tracing::warn!(
            tenant = %tenant, %knowledge_id,
            "auto-publish ON but no knowledge_auto_publish_visibility configured; \
             holding item eligible instead of publishing to an unknown audience"
        );
        return Ok(serde_json::json!({
            "action": if moved { "marked_eligible" } else { "none" },
            "auto_publish": true,
            "note": "no default visibility configured; held eligible",
        }));
    };
    let embedding = state.encode(&item.statement).await.ok().flatten();
    match state
        .storage
        .publish_knowledge(tenant, knowledge_id, visibility, K_SUPPORT_MIN, embedding)
        .await
    {
        Ok(published) => Ok(serde_json::json!({
            "action": "auto_published",
            "auto_publish": true,
            "status": published.status,
        })),
        Err(e) => {
            // A gate failure on the auto path is not fatal to the whole
            // complete() — hold the item as a candidate and surface the reason.
            tracing::warn!(tenant = %tenant, %knowledge_id, error = %e, "auto-publish gate refused");
            Ok(serde_json::json!({
                "action": "auto_publish_refused",
                "auto_publish": true,
                "reason": e.to_string(),
            }))
        }
    }
}

/// The tenant's configured default publish visibility for the auto-publish
/// path, read from the `knowledge_auto_publish_visibility` setting (a
/// comma-separated principal-token list, e.g. "7,9"). `None` = unconfigured;
/// the caller then holds the item eligible rather than publish to an unknown
/// audience.
async fn default_publish_visibility(
    state: &Arc<AppState>,
    tenant: TenantId,
) -> HandlerResult<Option<Vec<i32>>> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM settings
         WHERE key = 'knowledge_auto_publish_visibility'
           AND (tenant_id = $1 OR tenant_id IS NULL)
         ORDER BY tenant_id NULLS LAST
         LIMIT 1",
    )
    .bind(tenant)
    .fetch_optional(state.pool())
    .await
    .map_err(internal)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let tokens: Vec<i32> = value
        .split(',')
        .filter_map(|s| s.trim().parse::<i32>().ok())
        .collect();
    Ok(if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    })
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
    // If this item is already PUBLISHED, support accrual may have moved its
    // bucketed tier (emerging -> established -> extensive). Refresh the tier
    // stamped on the §7g carve-out chunk so recall's disclosure tracks the
    // current bucket. Derived from the just-recounted distinct_entities; the
    // CASE mirrors SupportTier::from_distinct (buckets, never exact counts).
    sqlx::query(
        "UPDATE chunks c SET support_tier = CASE
             WHEN k.distinct_entities >= 10 THEN 'extensive'
             WHEN k.distinct_entities >= 5  THEN 'established'
             WHEN k.distinct_entities >= 3  THEN 'emerging'
             ELSE NULL END
         FROM knowledge k
         WHERE k.id = $1 AND k.tenant_id = $2 AND k.status = 'published'
           AND c.tenant_id = $2 AND c.document_id = $3 AND c.valid_to IS NULL
           AND c.kind = 'knowledge'",
    )
    .bind(knowledge_id)
    .bind(tenant)
    .bind(format!("knowledge:{knowledge_id}"))
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
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
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
