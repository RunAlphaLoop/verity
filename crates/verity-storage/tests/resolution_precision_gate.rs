//! CI PRECISION-REGRESSION GATE (≥0.99) over the labeled Tier-2 entity-pair
//! set — design `docs/design/cross-source-entity-resolution.md` §3.2 ("target
//! precision ≥ 0.99, false-merge-rate ≤ target, published with a CI regression
//! gate"), §8 MVP, §9 Group E.
//!
//! This IS the CI precision gate: CI runs `cargo test --workspace`
//! (.github/workflows/ci.yml), so any regression here fails the build. It
//! scores the deciders against the READ-ONLY labeled fixture
//! `ingest/tests/fixtures/entity_resolution/entity_pairs.json`
//! (47 positives / 56 negatives since the 2026-07-11 key-independence
//! expansion — hard negatives heavily represented, including 14
//! domain-shared-but-distinct structural negatives er-0069..er-0082:
//! parent/brand, franchisor, co-tenant, ISP mail domain, ...).
//!
//! 1. The DOMAIN-EQUALITY SIGNAL (S0 canonicalization): "both sides
//!    canonicalize to the SAME clean registrable domain" — free-mail /
//!    placeholder domains fail closed to None inside `canonicalize_domain`.
//!    MEASURED (docs/benchmark/RESULTS-key-independence-2026-07-11.md): this
//!    signal alone false-merges EXACTLY the 14 structural negatives
//!    (FMR 0.2745 on eligible negatives) — which is WHY domain keeps
//!    `min_independent_keys = 2` and domain equality is a candidate signal,
//!    never a lone decider. Gate: the false-merge set is pinned to exactly
//!    those 14 ids (anything new fails the build), recall non-vacuous.
//!
//! 2. The FOLD at `min_independent_keys = 1` for domain (the pre-measurement
//!    "oracle" rule, kept as a documented COUNTEREXAMPLE): through the real
//!    fold, transitivity included, it must false-merge exactly the same
//!    pinned 14 — the measured reason the shipped default is 2.
//!
//! 3. The SHIPPED DEFAULT (min_independent_keys=2) folds the SAME evidence to
//!    ZERO merges — a lone domain never auto-merges in the shipped default
//!    ("annoying, never wrong"). THIS is the §3.2 precision-1.0 decider.
//!
//! The intentional asymmetry (§3.2): under-merge = annoyance, over-merge = a
//! scope leak. Precision is the SECURITY number; the recall floor only proves
//! the gate is not vacuously passing.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use uuid::Uuid;

use verity_core::types::*;
use verity_storage::resolve::{canonicalize_domain, fold, FoldConfig, KeyNamespace};

/// READ-ONLY reference fixture (shared with the Python-side judge evals).
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ingest/tests/fixtures/entity_resolution/entity_pairs.json"
));

struct LabeledPair {
    id: String,
    same: bool,
    left_ref: String,
    right_ref: String,
    left_domain: Option<String>,
    right_domain: Option<String>,
}

fn load_pairs() -> Vec<LabeledPair> {
    let v: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let pairs = v["pairs"].as_array().expect("pairs array");
    assert!(
        pairs.len() >= 60,
        "labeled set unexpectedly small — gate weakened?"
    );
    pairs
        .iter()
        .map(|p| LabeledPair {
            id: p["id"].as_str().unwrap().to_string(),
            same: p["same"].as_bool().unwrap(),
            left_ref: p["left"]["ref"].as_str().unwrap().to_string(),
            right_ref: p["right"]["ref"].as_str().unwrap().to_string(),
            left_domain: p["left"]["domain"].as_str().map(str::to_string),
            right_domain: p["right"]["domain"].as_str().map(str::to_string),
        })
        .collect()
}

/// The deterministic judge's key: the clean registrable domain, or None
/// (fail-closed) for missing / free-mail / placeholder / unparseable values.
/// `canonicalize_domain` handles URL forms, `www.` hosts, and email-shaped
/// values (S0), and applies the built-in denylist floor.
fn clean_domain(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .and_then(|d| canonicalize_domain(d, KeyNamespace::CustomerContact))
        .map(|k| k.value)
}

/// Deterministic domain-equality signal: both sides carry the SAME clean domain.
fn judge_same(p: &LabeledPair) -> bool {
    match (clean_domain(&p.left_domain), clean_domain(&p.right_domain)) {
        (Some(l), Some(r)) => l == r,
        _ => false, // fail closed: no clean key, no merge.
    }
}

/// The 14 domain-shared-but-distinct STRUCTURAL negatives (er-0069..er-0082,
/// added 2026-07-11): parent/brand on one domain, conglomerate brands, holding
/// co/subsidiary, agency-of-record, coworking co-tenants, franchisor/franchisee,
/// .edu spinouts, ISP mail domain (comcast.net — deliberately NOT denylisted),
/// sibling subsidiaries, marketplace sellers, PEO client, distributor, mail
/// migration, conglomerate divisions. Domain equality CANNOT separate these —
/// measured FMR 0.2745 on eligible negatives
/// (docs/benchmark/RESULTS-key-independence-2026-07-11.md) — which is why
/// `min_independent_keys` stays 2 for domain.
fn structural_domain_negatives() -> Vec<String> {
    (69..=82).map(|n| format!("er-{n:04}")).collect()
}

#[test]
fn domain_equality_signal_false_merge_set_is_pinned() {
    let pairs = load_pairs();
    let (mut tp, mut fp, mut tn, mut fn_) = (0u32, 0u32, 0u32, 0u32);
    let mut false_merges: Vec<&str> = Vec::new();
    for p in &pairs {
        match (judge_same(p), p.same) {
            (true, true) => tp += 1,
            (true, false) => {
                fp += 1;
                false_merges.push(&p.id);
            }
            (false, false) => tn += 1,
            (false, true) => fn_ += 1,
        }
    }
    let fmr = fp as f64 / (fp + tn).max(1) as f64;

    // The gate: the signal's false-merge set is EXACTLY the known structural
    // set — one NEW false merge (any id outside the pinned 14) fails the
    // build. This pins the measured domain-alone FMR (14 FP / 0.25 over all
    // 56 negatives) that justifies min_independent_keys=2 for domain.
    assert_eq!(
        false_merges,
        structural_domain_negatives(),
        "domain-equality false-merge set drifted from the measured structural set"
    );
    // Non-vacuous: the signal must still merge the clean-shared-domain
    // positives (38/47 measured at the 2026-07-11 expansion; floor allows
    // benign fixture growth, never silent decay).
    assert!(
        tp >= 25,
        "recall collapsed: only {tp} true merges — the gate is vacuous (fn={fn_})"
    );
    println!(
        "domain-equality signal: tp={tp} fp={fp} (pinned structural set) tn={tn} fn={fn_}, \
         FMR {fmr:.4} over {} labeled pairs",
        pairs.len()
    );
}

#[test]
fn fold_precision_gate_on_labeled_pairs() {
    let pairs = load_pairs();
    let t: TenantId = Uuid::from_u128(0x6A7E_0000_0000_0000_0000_0000_0000_0001);

    // Judge-positive pairs become Tier-1 domain evidence, exactly as the S1
    // producer would emit for a shared clean domain.
    let mut evidence: Vec<EvidenceRow> = Vec::new();
    for (i, p) in pairs.iter().enumerate() {
        let (Some(l), Some(r)) = (clean_domain(&p.left_domain), clean_domain(&p.right_domain))
        else {
            continue;
        };
        if l != r {
            continue;
        }
        evidence.push(EvidenceRow {
            evidence_id: Uuid::from_u128(0xE000_0000_0000_0000_0000_0000_0000_0000 + i as u128),
            tenant_id: t,
            left_ref: p.left_ref.clone(),
            right_ref: p.right_ref.clone(),
            tier: 1,
            method: "domain_match".into(),
            key_value: Some(l),
            key_namespace: Some("customer_contact".into()),
            score: None,
            evidence_l0_ref: Some(format!("l0:{}", p.id)),
            polarity: 1,
            valid_from: Utc.timestamp_opt(1_700_000_000 + i as i64, 0).unwrap(),
            valid_to: None,
            superseded_by: None,
        });
    }

    // --- Operating point A: the pre-measurement "oracle" rule (a clean shared
    // registrable domain merges — min_independent_keys=1 for the domain key).
    // Kept as a documented COUNTEREXAMPLE since 2026-07-11: the expanded
    // fixture proves this rule false-merges the 14 structural negatives
    // (docs/benchmark/RESULTS-key-independence-2026-07-11.md).
    let mut oracle_domain = EntityResolutionConfig::defaults(t, "domain", "customer_contact");
    oracle_domain.min_independent_keys = 1;
    let fallback = EntityResolutionConfig::defaults(t, "*", "*");
    let oracle_cfg = FoldConfig::new(t, vec![oracle_domain], fallback.clone());
    let plan = fold(&evidence, &oracle_cfg);

    let canon_of: BTreeMap<String, String> = plan
        .aliases
        .iter()
        .map(|a| {
            (
                format!("{}:{}", a.source, a.entity_id),
                a.canonical_entity.clone(),
            )
        })
        .collect();
    let merged = |p: &LabeledPair| -> bool {
        match (canon_of.get(&p.left_ref), canon_of.get(&p.right_ref)) {
            (Some(cl), Some(cr)) => cl == cr,
            _ => false,
        }
    };

    let (mut tp, mut fp, mut tn) = (0u32, 0u32, 0u32);
    let mut false_merges: Vec<&str> = Vec::new();
    let mut positives = 0u32;
    for p in &pairs {
        if p.same {
            positives += 1;
            if merged(p) {
                tp += 1;
            }
        } else if merged(p) {
            fp += 1;
            false_merges.push(&p.id);
        } else {
            tn += 1;
        }
    }
    // The counterexample, pinned: through the REAL fold (transitivity, key
    // handling and all), min_independent_keys=1 for domain false-merges
    // EXACTLY the 14 structural negatives — the measured reason the shipped
    // default is 2. A 15th false merge (fixture drift / fold regression)
    // fails the build.
    assert_eq!(fp as usize, false_merges.len());
    assert_eq!(fp + tn, 56, "labeled negative count drifted");
    assert_eq!(
        false_merges,
        structural_domain_negatives(),
        "fold@domain-min=1 false-merge set drifted from the measured structural set"
    );
    let recall = tp as f64 / positives.max(1) as f64;
    // Domain-alone recall measured 0.8085 (38/47) on the expanded fixture —
    // the other 9 positives link only via external_id / email keys.
    assert!(
        recall >= 0.75,
        "fold recall collapsed at the domain-min=1 operating point: {recall:.3} \
         ({tp}/{positives}) — the counterexample is going vacuous"
    );

    // --- Operating point B: the shipped OSS default (min_independent_keys=2,
    // docs/benchmark/RESULTS-tuning-defaults-2026-07-11.md). The SAME
    // lone-domain evidence must merge NOTHING — under-merge is the safe side,
    // and a lone MEDIUM key never auto-merges alone. THIS is the §3.2
    // precision gate on the shipped decider: precision 1.0 / FMR 0.0 by
    // construction (zero merges ⇒ zero false merges).
    let default_cfg = FoldConfig::new(t, Vec::new(), fallback);
    let default_plan = fold(&evidence, &default_cfg);
    assert!(
        default_plan.aliases.is_empty(),
        "OSS default regression: lone-domain evidence auto-merged {} members \
         with min_independent_keys=2",
        default_plan.aliases.len()
    );

    println!(
        "fold gate: domain-min=1 counterexample false-merges exactly the pinned 14 \
         (recall {recall:.3} = {tp}/{positives}); shipped default merged 0 (fail-closed, \
         precision 1.000 / FMR 0.000)"
    );
}
