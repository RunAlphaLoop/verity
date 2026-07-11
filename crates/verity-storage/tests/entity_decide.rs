//! Tier-2 human-gate end-to-end at the storage/fold layer (cross-source
//! entity-resolution §4.2 S4, §6; the Tier-2 opt-in tier of SPEC §7f).
//!
//! Proves the human gate the review screen + decide endpoint depend on:
//!   1. A `tier=2` fuzzy evidence row lands in the review queue and does NOT
//!      auto-merge — the pure fold forms NO edge for it (Tier-2 needs a human).
//!   2. A `decide{confirm}` writes a `human_confirmed` row; after re-folding the
//!      two refs share ONE canonical (the human gate merges).
//!   3. A `decide{reject}` writes a `human_rejected` polarity=-1 anti-link;
//!      after re-folding the two refs are SPLIT (distinct canonicals) and stay
//!      split — a permanent must-not-link no positive evidence overrides (§6).
//!
//! The storage crate cannot call the server's `run_full_fold`, so this test
//! materializes the fold plan itself via the PUBLIC pure `resolve::fold` +
//! the same idempotent `upsert_entity_alias` writer the server materializer
//! uses — no new write path. Requires VERITY_TEST_DSN; skips when absent.

use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::resolve::{fold, split_member_ref, FoldConfig};
use verity_storage::PostgresAdapter;

async fn setup() -> Option<(PostgresAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

/// Write one current L1 fact for (source, entity_id, field)=value.
async fn fact(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    source: &str,
    entity_id: &str,
    field: &str,
    value: serde_json::Value,
) {
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(entity_id.into()),
            kind: EpisodeKind::CdcEvent,
            payload: json!({ "field": field, "value": value }),
            content_hash: format!("h-{source}-{entity_id}-{field}-{value}"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: source.into(),
                entity_id: entity_id.into(),
                field: field.into(),
            },
            value,
            valid_from: chrono::Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .unwrap();
}

/// Re-run the pure fold over the tenant's whole live ledger and materialize its
/// alias plan — exactly the alias-writing step of the server's `run_full_fold`,
/// via the same idempotent `upsert_entity_alias`. Returns the plan's review
/// count so tests can assert "surfaced for review, not merged".
async fn refold(adapter: &PostgresAdapter, tenant: TenantId) -> usize {
    let live = adapter.all_live_evidence(tenant).await.unwrap();
    let cfg_rows = adapter.list_resolution_config(tenant).await.unwrap();
    let fallback = EntityResolutionConfig::defaults(tenant, "*", "*");
    let config = FoldConfig::new(tenant, cfg_rows, fallback);
    let plan = fold(&live, &config);
    for a in &plan.aliases {
        adapter
            .upsert_entity_alias(tenant, &a.source, &a.entity_id, &a.canonical_entity)
            .await
            .unwrap();
    }
    plan.review.len()
}

/// Insert a tier-2 fuzzy evidence row exactly as the Python Tier-2 producer's
/// EMIT does (POST /v1/admin/entity-evidence → insert_evidence).
async fn emit_tier2(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    left: &str,
    right: &str,
) -> EvidenceRow {
    adapter
        .insert_evidence(EvidenceWrite {
            tenant_id: tenant,
            left_ref: left.into(),
            right_ref: right.into(),
            tier: 2,
            method: "name+domain_fuzzy".into(),
            key_value: Some("name+domain_fuzzy; judge: shared domain acme.com".into()),
            key_namespace: None,
            score: Some(0.93),
            evidence_l0_ref: None,
            polarity: 1,
        })
        .await
        .unwrap()
}

/// Insert the human decision exactly as POST .../decide does: `confirm` →
/// method=human_confirmed polarity=+1, `reject` → method=human_rejected
/// polarity=-1.
async fn decide(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    left: &str,
    right: &str,
    confirm: bool,
) {
    let (method, polarity) = if confirm {
        ("human_confirmed", 1i16)
    } else {
        ("human_rejected", -1i16)
    };
    adapter
        .insert_evidence(EvidenceWrite {
            tenant_id: tenant,
            left_ref: left.into(),
            right_ref: right.into(),
            tier: 2,
            method: method.into(),
            key_value: None,
            key_namespace: None,
            score: None,
            evidence_l0_ref: Some("reviewer: verified same account".into()),
            polarity,
        })
        .await
        .unwrap();
}

const LEFT: &str = "salesforce:001xACME";
const RIGHT: &str = "hubspot:4207";

fn member(reff: &str) -> (String, String) {
    let m = split_member_ref(reff).expect("member ref");
    (m.source, m.entity_id)
}

/// Step 1: a tier-2 evidence row is visible in the review queue AND does not
/// auto-merge — the fold forms no edge for a bare Tier-2 pair.
#[tokio::test]
async fn tier2_appears_in_review_queue_and_does_not_auto_merge() {
    let Some((a, t)) = setup().await else {
        return;
    };
    fact(&a, t, "salesforce", "001xACME", "name", json!("Acme, Inc.")).await;
    fact(&a, t, "salesforce", "001xACME", "domain", json!("acme.com")).await;
    fact(&a, t, "hubspot", "4207", "name", json!("Acme")).await;
    fact(&a, t, "hubspot", "4207", "domain", json!("acme.com")).await;

    let emitted = emit_tier2(&a, t, LEFT, RIGHT).await;
    assert_eq!(emitted.tier, 2);
    assert_eq!(emitted.method, "name+domain_fuzzy");

    // It appears in the review queue (newest first, tier IN (2,3)).
    let queue = a.review_queue(t, 100).await.unwrap();
    assert!(
        queue
            .iter()
            .any(|e| e.evidence.evidence_id == emitted.evidence_id),
        "tier-2 evidence must surface in the review queue"
    );

    // It does NOT auto-merge: fold over the live ledger forms no shared canonical.
    refold(&a, t).await;
    let (ls, le) = member(LEFT);
    let (rs, re) = member(RIGHT);
    let left_canon = a.resolve_canonical(t, &ls, &le).await.unwrap();
    let right_canon = a.resolve_canonical(t, &rs, &re).await.unwrap();
    assert!(
        left_canon.is_none() || right_canon.is_none() || left_canon != right_canon,
        "bare Tier-2 must NOT auto-merge without a human_confirmed row; got {left_canon:?} == {right_canon:?}"
    );
}

/// Step 2: POST decide{confirm} → after re-folding the two refs share one
/// canonical (the human gate is what forms the Tier-2 edge).
#[tokio::test]
async fn decide_confirm_merges_the_two_refs() {
    let Some((a, t)) = setup().await else {
        return;
    };
    fact(&a, t, "salesforce", "001xACME", "name", json!("Acme, Inc.")).await;
    fact(&a, t, "salesforce", "001xACME", "domain", json!("acme.com")).await;
    fact(&a, t, "hubspot", "4207", "name", json!("Acme")).await;
    fact(&a, t, "hubspot", "4207", "domain", json!("acme.com")).await;
    emit_tier2(&a, t, LEFT, RIGHT).await;

    // Pre-confirm: not merged.
    refold(&a, t).await;
    let (ls, le) = member(LEFT);
    let (rs, re) = member(RIGHT);
    let before_l = a.resolve_canonical(t, &ls, &le).await.unwrap();
    let before_r = a.resolve_canonical(t, &rs, &re).await.unwrap();
    assert!(
        before_l.is_none() || before_l != before_r,
        "precondition: unmerged before the human confirm"
    );

    // The human gate: confirm.
    decide(&a, t, LEFT, RIGHT, true).await;
    refold(&a, t).await;

    let after_l = a.resolve_canonical(t, &ls, &le).await.unwrap();
    let after_r = a.resolve_canonical(t, &rs, &re).await.unwrap();
    assert!(after_l.is_some(), "left now aliased to a canonical");
    assert_eq!(
        after_l, after_r,
        "decide{{confirm}} must make the two refs share ONE canonical"
    );
}

/// Step 3: POST decide{reject} → a human_rejected/-1 anti-link; the two refs
/// stay split, and re-emitting positive Tier-2 evidence cannot re-merge them
/// (the anti-link is a permanent must-not-link, §6).
#[tokio::test]
async fn decide_reject_writes_anti_link_and_keeps_split() {
    let Some((a, t)) = setup().await else {
        return;
    };
    fact(&a, t, "salesforce", "001xACME", "name", json!("Acme, Inc.")).await;
    fact(&a, t, "salesforce", "001xACME", "domain", json!("acme.com")).await;
    fact(&a, t, "hubspot", "4207", "name", json!("Acme")).await;
    fact(&a, t, "hubspot", "4207", "domain", json!("acme.com")).await;
    emit_tier2(&a, t, LEFT, RIGHT).await;

    // The human gate: reject → anti-link.
    decide(&a, t, LEFT, RIGHT, false).await;
    refold(&a, t).await;

    let (ls, le) = member(LEFT);
    let (rs, re) = member(RIGHT);
    let l = a.resolve_canonical(t, &ls, &le).await.unwrap();
    let r = a.resolve_canonical(t, &rs, &re).await.unwrap();
    assert!(
        l.is_none() || r.is_none() || l != r,
        "decide{{reject}} must keep the two refs SPLIT; got {l:?} == {r:?}"
    );

    // The anti-link is a live -1 evidence row on the pair.
    let live = a.all_live_evidence(t).await.unwrap();
    assert!(
        live.iter()
            .any(|e| e.polarity < 0 && e.method == "human_rejected"),
        "a human_rejected anti-link (-1) must be present in the ledger"
    );

    // Permanence: even a fresh positive human_confirmed cannot override the
    // anti-link — the pair stays split (§6 anti-links win).
    decide(&a, t, LEFT, RIGHT, true).await;
    refold(&a, t).await;
    let l2 = a.resolve_canonical(t, &ls, &le).await.unwrap();
    let r2 = a.resolve_canonical(t, &rs, &re).await.unwrap();
    assert!(
        l2.is_none() || r2.is_none() || l2 != r2,
        "an anti-link is permanent: no positive evidence may re-merge the pair; got {l2:?} == {r2:?}"
    );
}

/// Emit one Tier-3 (never-auto-merge) evidence row on a pair. Distinct method
/// per call so a caller can seed several independent low-value candidates.
async fn emit_tier3(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    left: &str,
    right: &str,
    method: &str,
) -> EvidenceRow {
    adapter
        .insert_evidence(EvidenceWrite {
            tenant_id: tenant,
            left_ref: left.into(),
            right_ref: right.into(),
            tier: 3,
            method: method.into(),
            key_value: None,
            key_namespace: None,
            score: Some(0.5),
            evidence_l0_ref: None,
            polarity: 1,
        })
        .await
        .unwrap()
}

/// Backdate a live evidence row's `valid_from` by `days` — simulates a
/// candidate that has been WAITING in the queue that long. Uses the public pool
/// (no new adapter API); touches only the bi-temporal `valid_from`, which is the
/// SLA clock the priority formula's aging term reads.
async fn age_evidence(adapter: &PostgresAdapter, evidence_id: uuid::Uuid, days: i64) {
    sqlx::query(
        "UPDATE entity_evidence
            SET valid_from = now() - ($2 || ' days')::interval
          WHERE evidence_id = $1",
    )
    .bind(evidence_id)
    .bind(days.to_string())
    .execute(adapter.pool())
    .await
    .unwrap();
}

/// Prioritization + anti-starvation (design §8 Later — review-queue
/// prioritization + SLA). Two properties the queue MUST hold:
///
///   (A) ORDERING: the returned queue is sorted by `priority` DESC — every item's
///       priority is >= the next item's. This is the contract the UI relies on.
///
///   (B) ANTI-STARVATION / AGING FLOOR: a LOW-value candidate that has waited a
///       long time is NOT buried at the bottom beneath a FRESH low-value one. The
///       unbounded linear aging term lifts the aged candidate above its
///       fresh-but-otherwise-identical peer, so nothing starves indefinitely.
#[tokio::test]
async fn review_queue_orders_by_priority_and_ages_out_starved_candidates() {
    let Some((a, t)) = setup().await else {
        return;
    };

    // A FRESH, HIGH-value Tier-2 candidate: it belongs to real clusters (large
    // entity_value) and the pair recurs (frequency), so its INTRINSIC score is
    // high even with zero wait age.
    a.upsert_entity_alias(t, "salesforce", "001HI", "canon-hi-left")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "salesforce", "001HI2", "canon-hi-left")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "hubspot", "HI", "canon-hi-right")
        .await
        .unwrap();
    a.upsert_entity_alias(t, "hubspot", "HI2", "canon-hi-right")
        .await
        .unwrap();
    let hi_left = "salesforce:001HI";
    let hi_right = "hubspot:HI";
    // Recurring pair → frequency > 1 (distinct evidence_ids, same unordered pair).
    emit_tier2(&a, t, hi_left, hi_right).await;
    let high = a
        .insert_evidence(EvidenceWrite {
            tenant_id: t,
            left_ref: hi_left.into(),
            right_ref: hi_right.into(),
            tier: 2,
            method: "email_exact".into(),
            key_value: Some("ceo@acme.com".into()),
            key_namespace: Some("email".into()),
            score: Some(0.99),
            evidence_l0_ref: None,
            polarity: 1,
        })
        .await
        .unwrap();

    // A FRESH, LOW-value Tier-3 candidate: no clusters, single evidence, tier 3.
    let fresh_low = emit_tier3(&a, t, "x:fresh1", "y:fresh2", "cooccur_fresh").await;

    // An AGED, LOW-value Tier-3 candidate: same shape as `fresh_low` but it has
    // been waiting ~400 days. The aging floor must lift it above `fresh_low`.
    let aged_low = emit_tier3(&a, t, "x:aged1", "y:aged2", "cooccur_aged").await;
    age_evidence(&a, aged_low.evidence_id, 400).await;

    let queue = a.review_queue(t, 100).await.unwrap();
    assert!(
        queue.len() >= 3,
        "expected the three seeded candidates in the queue, got {}",
        queue.len()
    );

    // (A) ORDERING: priority is non-increasing down the queue.
    for w in queue.windows(2) {
        assert!(
            w[0].priority >= w[1].priority,
            "queue must be ordered by priority DESC: {} then {}",
            w[0].priority,
            w[1].priority
        );
    }

    let pos = |id: uuid::Uuid| queue.iter().position(|e| e.evidence.evidence_id == id);
    let high_pos = pos(high.evidence_id).expect("high candidate present");
    let fresh_pos = pos(fresh_low.evidence_id).expect("fresh-low candidate present");
    let aged_pos = pos(aged_low.evidence_id).expect("aged-low candidate present");

    // The high-value fresh candidate outranks a low-value fresh one (the whole
    // point of prioritizing at all).
    assert!(
        high_pos < fresh_pos,
        "high-value candidate should rank above a fresh low-value one"
    );

    // (B) ANTI-STARVATION: the AGED low-value candidate is NOT buried below the
    // FRESH low-value candidate — the linear aging term floats it up. Its wait
    // age is reflected in the SLA read-out too.
    let aged = &queue[aged_pos];
    let fresh = &queue[fresh_pos];
    assert!(
        aged.priority > fresh.priority,
        "aged low-value candidate (priority {}) must out-prioritize the fresh \
         low-value one (priority {}) — aging floor / anti-starvation",
        aged.priority,
        fresh.priority
    );
    assert!(
        aged_pos < fresh_pos,
        "aged candidate must sit ABOVE the fresh peer in queue order"
    );
    assert!(
        aged.wait_age_secs > fresh.wait_age_secs,
        "aged candidate's SLA wait-age read-out must exceed the fresh peer's"
    );
    assert!(
        aged.wait_age_secs > 300.0 * 86400.0,
        "aged candidate should report ~400d of wait, got {}s",
        aged.wait_age_secs
    );
}
