//! The MATERIALIZER (§4.2 S4 execution, §4.3) — the worker-plane driver that
//! runs the pure deterministic fold for a tenant and WRITES its plan to the
//! three surfaces the read path consumes: `entity_aliases` (via the reused
//! idempotent `upsert_entity_alias`), chunk `entity_tags` (via
//! `chunk_entity_tags_upsert`), and `entity_link_meta` (via
//! `upsert_entity_link_meta`).
//!
//! This is the **sole writer** of the resolution rows the read path reads
//! (§3.1 fence invariant): the read path (`merged_record`, the `entity_tags`
//! pre-filter, the badge) cannot tell an admin-typed alias from a worker-folded
//! one and cannot be tricked into computing a match. It lives here in the
//! server/worker plane and is invoked ONLY by the admin `trigger-fold` endpoint
//! (or a future async worker) — NEVER on `recall`/`get`.
//!
//! The fold itself (`verity_storage::resolve::fold`) is pure: no LLM, no
//! similarity, no DB, no clock. This module is its impure shell — it reads the
//! live evidence, calls `fold`, then executes the returned plan.

use std::sync::Arc;

use uuid::Uuid;
use verity_core::types::{EntityLinkMeta, TenantId};
use verity_storage::resolve::{self, fold_with_known_canonicals, FoldConfig, KnownCanonicals};

use crate::audit::spawn_fold_audit;
use crate::AppState;

/// What a single materialize run did, for the endpoint response + audit.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct MaterializeReport {
    /// Live evidence rows the fold consumed.
    pub evidence_considered: usize,
    /// `entity_aliases` rows upserted.
    pub aliases_written: usize,
    /// Chunk-tag materializations applied (rows the `entity_tags` UPDATE hit).
    pub chunk_tags_written: usize,
    /// `entity_link_meta` badge rows upserted.
    pub link_meta_written: usize,
    /// Components that FAILED CLOSED (surfaced for review, not merged).
    pub review_items: usize,
    /// Distinct canonicals the fold produced.
    pub canonicals: usize,
}

/// What a full resolution run did: how many *new* Tier-1 evidence rows the
/// producer appended, then the fold materializer's report (flattened).
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct RunReport {
    /// New `tier=1` `entity_evidence` rows the producer inserted this run
    /// (idempotent — a repeat run over unchanged L1 facts yields 0).
    pub evidence_produced: usize,
    #[serde(flatten)]
    pub materialize: MaterializeReport,
}

/// **The combined live resolution run (§4.2 S1 → S4).** First populates the
/// ledger from real L1 data (`produce_tier1_evidence`: read current facts, run
/// the S0/S1 producers, idempotently INSERT `tier=1` evidence), THEN runs the
/// existing `run_full_fold` materializer over the now-populated ledger. This is
/// what makes Tier-1 resolution LIVE end-to-end: nothing else populates the
/// ledger from L1.
///
/// Idempotent: the producer's deterministic `evidence_id` + `ON CONFLICT DO
/// NOTHING` means re-running adds no duplicate evidence, and the fold is a pure
/// function of the live ledger — so repeated runs converge.
pub(crate) async fn run_resolution(
    state: &Arc<AppState>,
    tenant: TenantId,
) -> Result<RunReport, (axum::http::StatusCode, String)> {
    let storage = state.storage.inner();
    let evidence_produced = resolve::produce_tier1_evidence(storage, tenant)
        .await
        .map_err(crate::internal)?;
    let materialize = run_full_fold(state, tenant).await?;
    Ok(RunReport {
        evidence_produced,
        materialize,
    })
}

/// Run a full fold for `tenant` and materialize its plan. Errors from any writer
/// abort the run (partial writes are idempotent and re-runnable — the fold is a
/// pure function of the live ledger, so re-running converges).
///
/// `run_full_fold` reads the tenant's whole live ledger + config, folds, and
/// executes the plan. It logs, per canonical link, which evidence justified it
/// (§4.3 audit extension) via `spawn_fold_audit`.
pub(crate) async fn run_full_fold(
    state: &Arc<AppState>,
    tenant: TenantId,
) -> Result<MaterializeReport, (axum::http::StatusCode, String)> {
    let storage = state.storage.inner();

    // 1. Read the whole live ledger + the tenant's key-quality config.
    let live = storage
        .all_live_evidence(tenant)
        .await
        .map_err(crate::internal)?;
    let cfg_rows = storage
        .list_resolution_config(tenant)
        .await
        .map_err(crate::internal)?;
    let fallback = verity_core::types::EntityResolutionConfig::defaults(tenant, "*", "*");
    let config = FoldConfig::new(tenant, cfg_rows, fallback);

    // 1b. §5 precondition (a): the set of canonicals ALREADY FOLDED — present in
    //     `entity_aliases` from a PRIOR fold or an admin crosswalk POST. The pure
    //     fold cannot read the DB, so we read the pre-existing canonical set here
    //     in the worker plane (reusing the existing `list_canonical_entities`
    //     read — no new storage method, `postgres.rs` untouched) and hand it in.
    //     A Tier-3 mention may then tag a chunk with a canonical that exists in
    //     `entity_aliases` even if THIS run did not re-merge it. This read is
    //     worker-plane only; the recall/`get` read path never runs it.
    //
    //     Cap note: `list_canonical_entities` is bounded (≤1000). For tenants
    //     whose folded-canonical count exceeds that, this under-includes prior
    //     canonicals — a fail-closed under-tag (never a wrong tag), and the
    //     freshly-folded set is always included. A future paginated/DISTINCT-only
    //     read would lift the cap without touching the read path (TODO).
    let preexisting: Vec<String> = storage
        .list_canonical_entities(tenant, 1000)
        .await
        .map_err(crate::internal)?
        .into_iter()
        .map(|c| c.canonical_entity)
        .collect();
    let known = KnownCanonicals::new(preexisting.iter().map(String::as_str), std::iter::empty());

    // 2. The PURE fold. No I/O in here. The known-canonical set only satisfies
    //    §5 precondition (a) for Tier-3 chunk tagging — it never forms an edge,
    //    never widens a scope, and does not change alias/component output.
    let plan = fold_with_known_canonicals(&live, &config, &known);

    let mut report = MaterializeReport {
        evidence_considered: live.len(),
        review_items: plan.review.len(),
        canonicals: plan.canonicals.len(),
        ..Default::default()
    };

    // 3. Execute the plan. Every writer is the reused, idempotent storage method
    //    the design names (§4.3) — the materializer invents no new write path.

    // 3a. Canonical membership → entity_aliases (reused upsert_entity_alias).
    for a in &plan.aliases {
        storage
            .upsert_entity_alias(tenant, &a.source, &a.entity_id, &a.canonical_entity)
            .await
            .map_err(crate::internal)?;
        report.aliases_written += 1;
    }

    // 3b. Chunk tags → chunks.entity_tags (chunk_entity_tags_upsert). subject_ref
    //     is `chunk:<source>:<document_id>:<seq>`; parse it back to the key the
    //     upsert needs. A malformed ref is skipped fail-closed (never a wrong tag).
    for ct in &plan.chunk_tags {
        let Some((source, document_id, seq)) = resolve::parse_chunk_ref(&ct.subject_ref) else {
            tracing::warn!(subject_ref = %ct.subject_ref, "fold emitted an unparseable chunk ref; skipping");
            continue;
        };
        let affected = storage
            .chunk_entity_tags_upsert(tenant, &source, &document_id, seq, &ct.tags)
            .await
            .map_err(crate::internal)?;
        report.chunk_tags_written += affected as usize;
    }

    // 3c. Confidence badges + surgical-split back-refs → entity_link_meta.
    for m in &plan.link_meta {
        let meta = EntityLinkMeta {
            tenant_id: tenant,
            subject_kind: m.subject_kind.clone(),
            subject_ref: m.subject_ref.clone(),
            canonical_entity: m.canonical_entity.clone(),
            confidence: m.confidence.clone(),
            strongest_method: m.strongest_method.clone(),
            justifying_evidence: m.justifying_evidence.clone(),
            evidence_count: m.evidence_count,
        };
        storage
            .upsert_entity_link_meta(&meta)
            .await
            .map_err(crate::internal)?;
        report.link_meta_written += 1;

        // §4.3 audit extension: log which evidence justified this link. Only the
        // alias_member links (canonical merges) are logged — the load-bearing
        // security decision — not every chunk tag.
        if m.subject_kind == "alias_member" {
            let evidence: Vec<Uuid> = m.justifying_evidence.clone();
            spawn_fold_audit(state, tenant, &m.canonical_entity, &m.subject_ref, evidence);
        }
    }

    Ok(report)
}
