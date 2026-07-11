//! CLUSTER-JOIN POLICY MEASUREMENT — the §10 Q3 measured default.
//!
//! `docs/design/cross-source-entity-resolution.md` §4.2 ("Incremental fold …
//! Cluster-drift guards") + §10 Q3: *"Incremental-fold cluster-join policy —
//! exact size floor / tier bar above which 'join two existing components' must
//! route to review rather than auto-join. Needs a measured default."*
//!
//! This harness IS that measurement, and it stays in the tree as the permanent
//! regression gate for the recommended policy. It drives ONLY the public fold
//! API (`refold_incremental`) — no fold internals, no DB, no LLM, no network,
//! no clock: everything is a pure function of seeded inputs, so every number it
//! prints is exactly reproducible.
//!
//! ## What is measured
//!
//! A grid of cluster-join policies over a labeled, synthetic, hand-designed
//! STRESS corpus (NOT a natural distribution — see the RESULTS doc):
//!
//!   size floor S ∈ {2, 3, 5, 8, 12, 20}
//!       (a pre-existing component with `size >= S` is "large"; a join touching
//!        it routes to review — the `large_component_floor` argument of
//!        `refold_incremental`)
//!   × joining-edge tier bar ∈ {tier1-multi-key, tier1-any, human-only}
//!       (tier1-any        = whatever the fold's built-in drift guard already
//!                           lets through: a Tier-1 edge or a human confirm;
//!        tier1-multi-key  = additionally require ≥2 DISTINCT independent
//!                           (key_kind, key_value) on the joining pair, or a
//!                           human confirmation;
//!        human-only       = only a `human_confirmed` join auto-applies)
//!
//! The bar sits ON TOP of the fold's own always-on guards (denylist, §4.4
//! namespace fence, `min_independent_keys` for non-strong keys, Tier-2-without-
//! human / Tier-3 never form an edge). The harness implements the bar as a pure
//! deterministic post-decision over the joining evidence it constructed —
//! label-by-construction, zero inference anywhere.
//!
//! ## Metrics (per grid cell)
//!
//!   bad_auto_joins     — ILLEGITIMATE joins auto-applied. THE LEAK METRIC:
//!                        a false cluster join unions two customers' entity
//!                        scopes (§3.2). Must be 0 at the shipped policy.
//!   legit_review       — LEGITIMATE joins routed to review (friction).
//!   review_volume      — total scenarios routed to review (queue load).
//!
//! Under-merge is annoying, over-merge is a leak: the recommendation is the
//! cell with ZERO bad auto-joins and the least friction.
//!
//! ## Regression gate (asserted every run)
//!
//!   G1  zero bad auto-joins at the RECOMMENDED policy (floor=8,
//!       tier1-multi-key);
//!   G2  human-only never leaks at any floor;
//!   G3  the stress set stays adversarial: tier1-any and tier1-multi-key both
//!       still leak at floor=20 (the vectors the policy exists to stop);
//!   G4  the fold's upstream guards keep blocking the denylist / lone-MEDIUM /
//!       name-only / cross-namespace families outright (never auto-join at ANY
//!       cell);
//!   G5  the computed least-friction zero-leak cell IS the recommended one;
//!   G6  the whole sweep is deterministic (two runs, identical grid).

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use rand::prelude::*;
use rand::rngs::StdRng;
use uuid::Uuid;

use verity_core::types::*;
use verity_storage::resolve::{refold_incremental, FoldConfig, FoldPlan, ReviewReason};

// ---------------------------------------------------------------------------
// The policy grid.
// ---------------------------------------------------------------------------

const FLOORS: &[usize] = &[2, 3, 5, 8, 12, 20];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TierBar {
    /// ≥2 distinct independent (key_kind, key_value) on the joining pair, or a
    /// human confirmation.
    Tier1MultiKey,
    /// Any Tier-1 edge (or human confirm) the fold's built-in guard admits.
    Tier1Any,
    /// Only a human_confirmed join auto-applies.
    HumanOnly,
}
const BARS: &[TierBar] = &[
    TierBar::Tier1MultiKey,
    TierBar::Tier1Any,
    TierBar::HumanOnly,
];

impl TierBar {
    fn name(self) -> &'static str {
        match self {
            TierBar::Tier1MultiKey => "tier1-multi-key",
            TierBar::Tier1Any => "tier1-any",
            TierBar::HumanOnly => "human-only",
        }
    }
}

/// The recommended default this harness gates (G1/G5). If the stress corpus or
/// the fold changes such that another cell wins, this test FAILS and the
/// RESULTS doc must be re-measured and re-published — numbers never drift
/// silently.
///
/// Re-measured 2026-07-11 after the `email_exact` strong-set demotion (see
/// `strong_method` in fold.rs): with email no longer a formally-strong lone
/// bridge, `tier1-any` — now meaning a single crm_fk / external_id /
/// admin_crosswalk bridge, all measured FMR-0 kinds — is leak-free up to
/// floor 8 and roughly halves review friction vs multi-key (114 vs 58 legit
/// auto-joins; review volume 126 vs 182). The prior recommendation
/// (8, tier1-multi-key) was measured against the pre-demotion fold where a
/// lone email bridge counted as strong and leaked 1→87.
const RECOMMENDED_FLOOR: usize = 8;
const RECOMMENDED_BAR: TierBar = TierBar::Tier1Any;

// ---------------------------------------------------------------------------
// Scenario corpus — synthetic, hand-labeled, STRESS composition.
// ---------------------------------------------------------------------------

/// Pre-existing component sizes for most families: deliberately skewed small
/// (most real components are small), with a heavy tail so the floor axis has
/// something to bite on. NOT a natural distribution.
const SIZE_POOL: &[usize] = &[1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 7, 9, 12, 15, 21];

/// Double-coincidence sizes: two independent wrong keys colliding is modeled
/// as a LARGE-component phenomenon (coincidence surface grows with member
/// count: every member contributes contact emails / secondary domains). A
/// hand-labeled stress choice — it upper-bounds the recommendable floor at 8
/// (the smallest double-coincidence side in the set). Stated in the RESULTS
/// doc.
const DOUBLE_SIZE_POOL: &[usize] = &[8, 9, 11, 14, 18, 22];

/// Free-mail domains the tenant denylist DOES catch.
const DENYLIST: &[&str] = &["gmail.com", "hotmail.com", "yahoo.com", "example.com"];
/// Free-mail-ADJACENT domains the denylist does NOT enumerate (the realistic
/// gap: no denylist is exhaustive). These form formally-valid Tier-1
/// email_exact edges — the live leak vector for cluster joins.
const FREEMAIL_ADJACENT: &[&str] = &["gmx.net", "proton.me", "mail.ru", "fastmail.fm"];

const SOURCES: &[&str] = &["salesforce", "hubspot", "gong", "linear"];

fn tenant() -> TenantId {
    Uuid::from_u128(0xC1A5_7E12_0000_0000_0000_0000_0000_0001)
}

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn ev(
    scen_idx: u128,
    seq: u128,
    left: &str,
    right: &str,
    tier: i16,
    method: &str,
    key_value: Option<&str>,
    key_namespace: Option<&str>,
    polarity: i16,
) -> EvidenceRow {
    EvidenceRow {
        evidence_id: Uuid::from_u128(
            0xE000_0000_0000_0000_0000_0000_0000_0000 + (scen_idx << 20) + seq,
        ),
        tenant_id: tenant(),
        left_ref: left.to_string(),
        right_ref: right.to_string(),
        tier,
        method: method.to_string(),
        key_value: key_value.map(str::to_string),
        key_namespace: key_namespace.map(str::to_string),
        score: if tier == 1 { None } else { Some(0.95) },
        evidence_l0_ref: Some(format!("l0:{scen_idx}:{seq}")),
        polarity,
        valid_from: ts(seq as i64),
        valid_to: None,
        superseded_by: None,
    }
}

/// The tenant config for the sweep: the shipped defaults, hardened exactly as
/// the precision fuzzer's adversarial config — denylist on domains, the §4.4
/// internal_directory email fence, `min_independent_keys = 2`. The component
/// size cap is left None so the size-cap guard (measured elsewhere, in
/// `resolution_precision_fuzz`) does not confound the JOIN-policy measurement.
fn sweep_config() -> FoldConfig {
    let mut fallback = EntityResolutionConfig::defaults(tenant(), "*", "*");
    fallback.min_independent_keys = 2;
    fallback.component_size_cap = None;
    fallback.denylist_values = DENYLIST.iter().map(|s| s.to_string()).collect();

    let mut domain_rule = EntityResolutionConfig::defaults(tenant(), "domain", "customer_contact");
    domain_rule.min_independent_keys = 2;
    domain_rule.denylist_values = DENYLIST.iter().map(|s| s.to_string()).collect();

    let mut internal_email =
        EntityResolutionConfig::defaults(tenant(), "email", "internal_directory");
    internal_email.eligible_as_edge = false; // the §4.4 fence.

    FoldConfig::new(tenant(), vec![domain_rule, internal_email], fallback)
}

/// One labeled cluster-join scenario: two PRE-EXISTING folded components
/// (internally chained by strong Tier-1 keys, exactly what a prior fold would
/// have materialized) plus new joining evidence that attempts to fuse them.
struct Scenario {
    family: &'static str,
    /// Label BY CONSTRUCTION: true = the two components are the same real
    /// company (the join SHOULD eventually apply); false = two genuinely
    /// distinct companies (auto-applying the join is a scope leak).
    legit: bool,
    evidence: Vec<EvidenceRow>,
    prior_canonicals: BTreeMap<String, String>,
    prior_sizes: BTreeMap<String, usize>,
    /// Probe members (one per side) used to detect fusion in the plan.
    left_probe: String,
    right_probe: String,
    /// Distinct independent (key_kind, key_value) pairs on the joining edge —
    /// known by construction; the tier-bar scorer reads this, never infers it.
    join_distinct_keys: usize,
    /// A live human_confirmed row exists on the joining pair.
    join_human: bool,
}

/// Build one pre-existing component: `size` members chained by alternating
/// strong Tier-1 keys (crm_fk / external_id), i.e. a cluster a prior fold
/// legitimately produced. Returns the member refs.
#[allow(clippy::too_many_arguments)]
fn build_component(
    scen_idx: u128,
    seq: &mut u128,
    tag: &str,
    side: &str,
    size: usize,
    evidence: &mut Vec<EvidenceRow>,
    prior_canonicals: &mut BTreeMap<String, String>,
    prior_sizes: &mut BTreeMap<String, usize>,
) -> Vec<String> {
    let canonical = format!("canon:prior:{tag}:{side}");
    let mut members = Vec::with_capacity(size);
    for m in 0..size {
        let r = format!("{}:{tag}-{side}{m}", SOURCES[m % SOURCES.len()]);
        prior_canonicals.insert(r.clone(), canonical.clone());
        members.push(r);
    }
    prior_sizes.insert(canonical, size);
    for (m, pair) in members.windows(2).enumerate() {
        *seq += 1;
        let row = if m % 2 == 0 {
            ev(
                scen_idx,
                *seq,
                &pair[0],
                &pair[1],
                1,
                "crm_fk",
                None,
                Some("customer_contact"),
                1,
            )
        } else {
            ev(
                scen_idx,
                *seq,
                &pair[0],
                &pair[1],
                1,
                "external_id",
                Some(&format!("XID-{tag}-{side}-{m}")),
                Some("customer_contact"),
                1,
            )
        };
        evidence.push(row);
    }
    members
}

/// Deterministic corpus generator. Every scenario is seeded from its (family,
/// index), so the corpus is identical on every run and every machine.
fn gen_corpus() -> Vec<Scenario> {
    let mut corpus: Vec<Scenario> = Vec::new();
    let mut scen_idx: u128 = 0;

    // (family, legit, count, size_pool)
    let families: &[(&'static str, bool, usize, &[usize])] = &[
        // -------- LEGITIMATE: same real company, folded separately, bridged
        // by a true key (the join SHOULD apply; routing it to review = friction).
        ("LG-EXT", true, 60, SIZE_POOL), // external_id crosswalk (1 strong key)
        ("LG-FK", true, 40, SIZE_POOL),  // crm_fk bridge (1 strong key)
        ("LG-EMAIL-SINGLE", true, 60, SIZE_POOL), // one exact corporate email (1 strong key)
        ("LG-EMAIL-MULTI", true, 60, SIZE_POOL), // exact email + matching domain (2 keys)
        ("LG-HUMAN", true, 40, SIZE_POOL), // a human confirmed the join
        // -------- ILLEGITIMATE: two genuinely distinct companies bridged by a
        // bad/borderline edge (auto-applying = scope leak).
        ("IL-FREEMAIL-ADJ", false, 70, SIZE_POOL), // shared free-mail-ADJACENT email (1 key)
        ("IL-DOUBLE", false, 40, DOUBLE_SIZE_POOL), // agency email + parked domain (2 keys)
        ("IL-LONE-DOMAIN", false, 50, SIZE_POOL),  // single shared MEDIUM domain
        ("IL-NAME-ONLY", false, 40, SIZE_POOL),    // tier-2 fuzzy name, no human
        ("IL-DENYLIST", false, 30, SIZE_POOL),     // denylisted free-mail domain
        ("IL-CROSSNS", false, 30, SIZE_POOL),      // internal_directory email (§4.4)
    ];

    for (fi, (family, legit, count, pool)) in families.iter().enumerate() {
        for k in 0..*count {
            let mut rng = StdRng::seed_from_u64(((fi as u64) << 32) ^ (k as u64) ^ 0x5EED);
            scen_idx += 1;
            let mut seq: u128 = 0;
            let tag = format!("f{fi}k{k}");

            // Force the smallest case (1 + 1) to exist in every family so the
            // floor axis is probed at its bottom end deterministically.
            let (ls, rs) = if k == 0 {
                (pool[0], pool[0])
            } else {
                (
                    *pool.choose(&mut rng).unwrap(),
                    *pool.choose(&mut rng).unwrap(),
                )
            };

            let mut evidence = Vec::new();
            let mut prior_canonicals = BTreeMap::new();
            let mut prior_sizes = BTreeMap::new();
            let left = build_component(
                scen_idx,
                &mut seq,
                &tag,
                "L",
                ls,
                &mut evidence,
                &mut prior_canonicals,
                &mut prior_sizes,
            );
            let right = build_component(
                scen_idx,
                &mut seq,
                &tag,
                "R",
                rs,
                &mut evidence,
                &mut prior_canonicals,
                &mut prior_sizes,
            );
            let (a, b) = (left[0].clone(), right[0].clone());

            // The NEW joining evidence, per family.
            let join_distinct_keys: usize;
            let mut join_human = false;
            match *family {
                "LG-EXT" => {
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "external_id",
                        Some(&format!("XID-JOIN-{tag}")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "LG-FK" => {
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "crm_fk",
                        None,
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "LG-EMAIL-SINGLE" => {
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "email_exact",
                        Some(&format!("ops@corp-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "LG-EMAIL-MULTI" => {
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "email_exact",
                        Some(&format!("ops@corp-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "domain_match",
                        Some(&format!("corp-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 2;
                }
                "LG-HUMAN" => {
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        2,
                        "human_confirmed",
                        None,
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                    join_human = true;
                }
                "IL-FREEMAIL-ADJ" => {
                    // Two DISTINCT companies whose records share a personal
                    // free-mail-adjacent address the denylist does not
                    // enumerate. Formally a Tier-1 strong email edge.
                    let dom = FREEMAIL_ADJACENT[k % FREEMAIL_ADJACENT.len()];
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "email_exact",
                        Some(&format!("owner-{tag}@{dom}")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "IL-DOUBLE" => {
                    // Double coincidence on two LARGE distinct clusters: a
                    // shared outsourced-agency contact email + a shared parked
                    // secondary domain. Two independent keys — clears
                    // min_independent_keys AND the multi-key bar.
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "email_exact",
                        Some(&format!("billing@agency-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "domain_match",
                        Some(&format!("parked-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 2;
                }
                "IL-LONE-DOMAIN" => {
                    // A single shared MEDIUM key (shared-hosting domain).
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "domain_match",
                        Some(&format!("sharedhost-{tag}.com")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "IL-NAME-ONLY" => {
                    // Tier-2 fuzzy name similarity, NO human confirmation.
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        2,
                        "name+domain_fuzzy",
                        Some(&format!("acme-{tag}")),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "IL-DENYLIST" => {
                    // A denylisted free-mail domain shared by two companies.
                    let dom = DENYLIST[k % DENYLIST.len()];
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "domain_match",
                        Some(dom),
                        Some("customer_contact"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                "IL-CROSSNS" => {
                    // An internal-employee (actor) email coincidentally shared —
                    // the §4.4 wrong-population vector.
                    seq += 1;
                    evidence.push(ev(
                        scen_idx,
                        seq,
                        &a,
                        &b,
                        1,
                        "email_exact",
                        Some(&format!("jane-{tag}@corp-int.dev")),
                        Some("internal_directory"),
                        1,
                    ));
                    join_distinct_keys = 1;
                }
                other => panic!("unknown family {other}"),
            }

            corpus.push(Scenario {
                family,
                legit: *legit,
                evidence,
                prior_canonicals,
                prior_sizes,
                left_probe: a,
                right_probe: b,
                join_distinct_keys,
                join_human,
            });
        }
    }
    corpus
}

// ---------------------------------------------------------------------------
// Policy decision + metrics.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The join auto-applied (the two prior components now share a canonical).
    AutoJoin,
    /// Routed to human review (drift guard or tier bar).
    Review,
    /// The fold's upstream guards refused the edge outright; the components
    /// simply stayed separate (no review item, no join).
    BlockedSeparate,
}

/// Decide the policy outcome for one scenario at (floor, bar) by driving the
/// PUBLIC `refold_incremental` and then applying the tier bar as a pure
/// post-decision over the construction-known joining evidence.
fn decide(s: &Scenario, cfg: &FoldConfig, floor: usize, bar: TierBar) -> Outcome {
    let plan: FoldPlan =
        refold_incremental(&s.evidence, cfg, &s.prior_canonicals, &s.prior_sizes, floor);

    // Did the two prior components fuse into one canonical in the plan?
    let mut canon_of: BTreeMap<String, &str> = BTreeMap::new();
    for a in &plan.aliases {
        canon_of.insert(
            format!("{}:{}", a.source, a.entity_id),
            a.canonical_entity.as_str(),
        );
    }
    let fused = match (canon_of.get(&s.left_probe), canon_of.get(&s.right_probe)) {
        (Some(cl), Some(cr)) => cl == cr,
        _ => false,
    };
    let drift_review = plan
        .review
        .iter()
        .any(|r| matches!(r.reason, ReviewReason::ClusterDrift { .. }));

    if fused {
        // The built-in guard admitted the join at this floor. The tier bar now
        // decides auto vs review.
        match bar {
            TierBar::Tier1Any => Outcome::AutoJoin,
            TierBar::Tier1MultiKey => {
                if s.join_human || s.join_distinct_keys >= 2 {
                    Outcome::AutoJoin
                } else {
                    Outcome::Review
                }
            }
            TierBar::HumanOnly => {
                if s.join_human {
                    Outcome::AutoJoin
                } else {
                    Outcome::Review
                }
            }
        }
    } else if drift_review {
        Outcome::Review
    } else {
        Outcome::BlockedSeparate
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Cell {
    bad_auto: usize,      // ILLEGIT auto-joined — THE LEAK METRIC
    legit_auto: usize,    // LEGIT auto-joined
    legit_review: usize,  // LEGIT routed to review — friction
    legit_blocked: usize, // LEGIT refused outright by upstream guards (a miss)
    illegit_review: usize,
    illegit_blocked: usize,
}

impl Cell {
    fn review_volume(&self) -> usize {
        self.legit_review + self.illegit_review
    }
}

fn run_sweep(corpus: &[Scenario], cfg: &FoldConfig) -> BTreeMap<(usize, TierBar), Cell> {
    let mut grid: BTreeMap<(usize, TierBar), Cell> = BTreeMap::new();
    for &floor in FLOORS {
        for &bar in BARS {
            let cell = grid.entry((floor, bar)).or_default();
            for s in corpus {
                match (decide(s, cfg, floor, bar), s.legit) {
                    (Outcome::AutoJoin, true) => cell.legit_auto += 1,
                    (Outcome::AutoJoin, false) => cell.bad_auto += 1,
                    (Outcome::Review, true) => cell.legit_review += 1,
                    (Outcome::Review, false) => cell.illegit_review += 1,
                    (Outcome::BlockedSeparate, true) => cell.legit_blocked += 1,
                    (Outcome::BlockedSeparate, false) => cell.illegit_blocked += 1,
                }
            }
        }
    }
    grid
}

// ---------------------------------------------------------------------------
// The test: measure, print the grid + JSON, gate the recommended policy.
// ---------------------------------------------------------------------------

#[test]
fn cluster_join_policy_grid_and_regression_gate() {
    let cfg = sweep_config();
    let corpus = gen_corpus();

    let n_legit = corpus.iter().filter(|s| s.legit).count();
    let n_illegit = corpus.len() - n_legit;

    let grid = run_sweep(&corpus, &cfg);

    // ---- G6: determinism — a second full sweep must be byte-identical. ----
    let grid2 = run_sweep(&gen_corpus(), &cfg);
    assert_eq!(grid, grid2, "sweep must be deterministic across runs");

    // ---- G4: upstream-guard families never auto-join at ANY cell. ----
    for &floor in FLOORS {
        for &bar in BARS {
            for s in corpus.iter().filter(|s| {
                matches!(
                    s.family,
                    "IL-LONE-DOMAIN" | "IL-NAME-ONLY" | "IL-DENYLIST" | "IL-CROSSNS"
                )
            }) {
                assert_ne!(
                    decide(s, &cfg, floor, bar),
                    Outcome::AutoJoin,
                    "{} must never auto-join (floor={floor}, bar={})",
                    s.family,
                    bar.name()
                );
            }
        }
    }

    // ---- Per-family outcome breakdown at the recommended cell (for the
    // RESULTS doc; printed below). ----
    let mut family_at_rec: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    for s in &corpus {
        let e = family_at_rec.entry(s.family).or_default();
        match decide(s, &cfg, RECOMMENDED_FLOOR, RECOMMENDED_BAR) {
            Outcome::AutoJoin => e.0 += 1,
            Outcome::Review => e.1 += 1,
            Outcome::BlockedSeparate => e.2 += 1,
        }
    }

    // ---- Print the full grid (markdown) + machine-readable JSON. ----
    println!(
        "\ncorpus: {} scenarios ({n_legit} legitimate joins, {n_illegit} illegitimate joins)",
        corpus.len()
    );
    println!("\n| floor | tier bar | bad auto-joins (LEAK) | legit auto | legit->review (friction) | legit blocked | review volume |");
    println!("|---|---|---|---|---|---|---|");
    for &floor in FLOORS {
        for &bar in BARS {
            let c = &grid[&(floor, bar)];
            println!(
                "| {floor} | {} | {} | {} | {} | {} | {} |",
                bar.name(),
                c.bad_auto,
                c.legit_auto,
                c.legit_review,
                c.legit_blocked,
                c.review_volume()
            );
        }
    }

    let mut cells_json = Vec::new();
    for &floor in FLOORS {
        for &bar in BARS {
            let c = &grid[&(floor, bar)];
            cells_json.push(serde_json::json!({
                "floor": floor,
                "tier_bar": bar.name(),
                "bad_auto_joins": c.bad_auto,
                "legit_auto_joins": c.legit_auto,
                "legit_routed_to_review": c.legit_review,
                "legit_blocked_separate": c.legit_blocked,
                "illegit_routed_to_review": c.illegit_review,
                "illegit_blocked_separate": c.illegit_blocked,
                "review_queue_volume": c.review_volume(),
            }));
        }
    }
    let families_json: Vec<_> = family_at_rec
        .iter()
        .map(|(f, (auto, review, blocked))| {
            serde_json::json!({
                "family": f,
                "auto_join": auto,
                "review": review,
                "blocked_separate": blocked,
            })
        })
        .collect();
    let json = serde_json::json!({
        "benchmark": "cluster-join-policy",
        "design": "docs/design/cross-source-entity-resolution.md §4.2 incremental fold + §10 Q3",
        "corpus": {
            "total_scenarios": corpus.len(),
            "legitimate": n_legit,
            "illegitimate": n_illegit,
            "note": "synthetic, hand-labeled STRESS corpus — adversarial composition, not a natural distribution",
        },
        "grid": cells_json,
        "recommended": {
            "size_floor": RECOMMENDED_FLOOR,
            "tier_bar": RECOMMENDED_BAR.name(),
        },
        "per_family_at_recommended": families_json,
    });
    println!("\nJSON-RESULTS-BEGIN");
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    println!("JSON-RESULTS-END");

    // ---- G1: ZERO bad auto-joins at the recommended policy. ----
    let rec = &grid[&(RECOMMENDED_FLOOR, RECOMMENDED_BAR)];
    assert_eq!(
        rec.bad_auto,
        0,
        "REGRESSION: bad auto-joins at the recommended policy (floor={RECOMMENDED_FLOOR}, bar={})",
        RECOMMENDED_BAR.name()
    );

    // ---- G2: human-only never leaks. ----
    for &floor in FLOORS {
        assert_eq!(
            grid[&(floor, TierBar::HumanOnly)].bad_auto,
            0,
            "human-only bar leaked at floor {floor}"
        );
    }

    // ---- G3: the stress set stays adversarial (the vectors this policy
    // exists to stop must keep firing at the loosest floor). ----
    assert!(
        grid[&(20, TierBar::Tier1Any)].bad_auto > 0,
        "stress set no longer exercises the loose-floor double-coincidence leak vector \
         under tier1-any (post email-demotion, the email bridges never weld; the \
         residual floor-20 leaks are double coincidences)"
    );
    assert!(
        grid[&(20, TierBar::Tier1MultiKey)].bad_auto > 0,
        "stress set no longer exercises the double-coincidence multi-key leak vector"
    );

    // ---- G5: the computed least-friction zero-leak cell IS the recommended
    // one (tie-break: lower friction, then lower review volume, then larger
    // floor — a larger floor reviews less by construction). ----
    let best = grid
        .iter()
        .filter(|(_, c)| c.bad_auto == 0)
        .min_by_key(|((floor, _), c)| (c.legit_review, c.review_volume(), usize::MAX - floor))
        .map(|((floor, bar), _)| (*floor, *bar))
        .expect("at least one zero-leak cell must exist");
    assert_eq!(
        best,
        (RECOMMENDED_FLOOR, RECOMMENDED_BAR),
        "the measured least-friction zero-leak cell moved: re-measure and republish \
         docs/benchmark/RESULTS-cluster-join-*.md before changing the recommendation"
    );
}
