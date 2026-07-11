//! CI PRECISION-REGRESSION GATE (≥0.99) over the labeled Tier-2 entity-pair
//! set — design `docs/design/cross-source-entity-resolution.md` §3.2 ("target
//! precision ≥ 0.99, false-merge-rate ≤ target, published with a CI regression
//! gate"), §8 MVP, §9 Group E.
//!
//! This IS the CI precision gate: CI runs `cargo test --workspace`
//! (.github/workflows/ci.yml), so any regression here fails the build. It
//! scores TWO deciders against the READ-ONLY labeled fixture
//! `ingest/tests/fixtures/entity_resolution/entity_pairs.json`
//! (33 positives / 35 negatives, hard negatives heavily represented):
//!
//! 1. The DETERMINISTIC JUDGE (S0 canonicalization): "same iff both sides
//!    canonicalize to the SAME clean registrable domain" — free-mail /
//!    placeholder domains fail closed to None inside `canonicalize_domain`, so
//!    they can never match. Gate: precision == 1.0, false-merge-rate == 0.0
//!    (strictly stronger than the ≥0.99 bar), recall non-vacuous.
//!
//! 2. The FOLD at the deterministic-oracle operating point: judge-positive
//!    pairs become `domain_match` ledger evidence and the pure fold
//!    (min_independent_keys=1 for the domain key — modeling the oracle's
//!    "clean shared registrable domain merges" rule) must merge NO labeled
//!    negative pair, transitivity included. Gate: fold precision == 1.0 /
//!    FMR == 0.0 over the labeled pairs.
//!
//! 3. The OSS DEFAULT (min_independent_keys=2) folds the SAME evidence to
//!    ZERO merges — a lone domain never auto-merges in the shipped default
//!    ("annoying, never wrong").
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

/// Deterministic judge: same iff both sides carry the SAME clean domain.
fn judge_same(p: &LabeledPair) -> bool {
    match (clean_domain(&p.left_domain), clean_domain(&p.right_domain)) {
        (Some(l), Some(r)) => l == r,
        _ => false, // fail closed: no clean key, no merge.
    }
}

#[test]
fn deterministic_judge_precision_gate() {
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
    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let fmr = fp as f64 / (fp + tn).max(1) as f64;

    // The gate. ≥0.99 is the published bar; the deterministic judge must hold
    // the cascade's measured 1.000 / 0.000 (a single false merge fails).
    assert_eq!(
        fp, 0,
        "PRECISION REGRESSION: deterministic judge false-merged {false_merges:?}"
    );
    assert!(
        precision >= 0.99,
        "PRECISION REGRESSION: {precision:.4} < 0.99 (tp={tp}, fp={fp})"
    );
    assert_eq!(fmr, 0.0, "false-merge-rate must be 0.0, got {fmr:.4}");
    // Non-vacuous: the judge must actually merge the clean-shared-domain
    // positives (31/33 at fixture authoring; floor set below to allow benign
    // fixture growth, never silent decay to zero).
    assert!(
        tp >= 25,
        "recall collapsed: only {tp} true merges — the gate is vacuous (fn={fn_})"
    );
    println!(
        "deterministic-judge gate: precision {precision:.3}, FMR {fmr:.3}, \
         tp={tp} fp={fp} tn={tn} fn={fn_} over {} labeled pairs",
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

    // --- Operating point A: the deterministic-oracle rule (a clean shared
    // registrable domain merges — min_independent_keys=1 for the domain key).
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
    // The gate: through the REAL fold (transitivity, key handling and all),
    // zero labeled negatives merge. precision == 1.0 / FMR == 0.0 ≥ the 0.99 bar.
    assert_eq!(
        fp, 0,
        "FOLD PRECISION REGRESSION: fold merged labeled negatives {false_merges:?}"
    );
    assert_eq!(fp as f64 / (fp + tn).max(1) as f64, 0.0);
    let recall = tp as f64 / positives.max(1) as f64;
    assert!(
        recall >= 0.85,
        "fold recall collapsed at the oracle operating point: {recall:.3} \
         ({tp}/{positives}) — the gate is going vacuous"
    );

    // --- Operating point B: the shipped OSS default (min_independent_keys=2).
    // The SAME lone-domain evidence must merge NOTHING — under-merge is the
    // safe side, and a lone MEDIUM key never auto-merges alone.
    let default_cfg = FoldConfig::new(t, Vec::new(), fallback);
    let default_plan = fold(&evidence, &default_cfg);
    assert!(
        default_plan.aliases.is_empty(),
        "OSS default regression: lone-domain evidence auto-merged {} members \
         with min_independent_keys=2",
        default_plan.aliases.len()
    );

    println!(
        "fold gate: oracle point precision 1.000 / FMR 0.000, recall {recall:.3} \
         ({tp}/{positives}); OSS default merged 0 (fail-closed)"
    );
}
