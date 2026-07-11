//! PURE-FOLD PRECISION FUZZER — the load-bearing ER precision gate.
//!
//! `docs/design/cross-source-entity-resolution.md` §6 (five defenses), §8 MVP
//! ("§7e fuzzer: resolution-specific adversarial cases") and §9 Group E. This
//! IS the CI precision gate: it runs under plain `cargo test` (no DB, no DSN,
//! no LLM, no network — the fold is a pure function), so a fold change that
//! introduces ANY false-merge path fails the build unconditionally.
//!
//! Strategy: generate many randomized adversarial evidence ledgers over a known
//! ground truth (each generated ref belongs to exactly one true entity). All
//! intra-entity evidence is legitimately strong; ALL cross-entity evidence is
//! drawn from the §6 attack catalog:
//!   - free-mail / denylisted-domain name collisions,
//!   - cross-namespace actor↔customer email edges (§4.4 fence),
//!   - lone-MEDIUM-key pairs (a single shared domain, `min_independent_keys`),
//!   - near-miss keys (distinct key-nodes that must never connect) and lone
//!     shared key-nodes,
//!   - key-node fan-out (one domain welding 3+ distinct entities),
//!   - anti-linked pairs buried under piles of positive strong evidence,
//!   - Tier-2 evidence WITHOUT human confirmation,
//!   - Tier-3 mentions (never an edge),
//!   - oversized components (`component_size_cap`),
//!   - Tier-3 chunk mentions of never-folded canonicals (must never tag).
//!
//! The security invariants asserted on EVERY iteration:
//!   I1  PRECISION == 1.0 / false-merge-rate == 0.0: no canonical ever contains
//!       members of two different ground-truth entities (a false merge is a
//!       scope leak, §3.2).
//!   I2  Anti-links are never overridden — an anti-linked pair never shares a
//!       canonical, no matter how much positive evidence piles on (§6.1).
//!   I3  `min_independent_keys` is respected — lone-MEDIUM-key pairs never merge.
//!   I4  `component_size_cap` quarantines — no canonical exceeds the cap, and
//!       the oversized component surfaces as `SizeCapExceeded` review.
//!   I5  Tier-3 NEVER forms an edge, and chunk tags only ever name canonicals
//!       that are already folded/known (never a ghost canonical).
//!   I6  The fold is deterministic under input permutation.
//!
//! Seeds vary by loop index (StdRng::seed_from_u64(iter)) — fully
//! deterministic, reproducible failures.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeZone, Utc};
use rand::prelude::*;
use rand::rngs::StdRng;
use uuid::Uuid;

use verity_core::types::*;
use verity_storage::resolve::{
    fold, fold_with_known_canonicals, AliasWrite, FoldConfig, KnownCanonicals, ReviewReason,
};

const ITERS: u64 = 250;
const SIZE_CAP: i32 = 6;
const FREEMAIL: &[&str] = &["gmail.com", "hotmail.com", "yahoo.com", "example.com"];
const SOURCES: &[&str] = &["salesforce", "hubspot", "gong", "linear"];

fn tenant() -> TenantId {
    Uuid::from_u128(0xFEED_FACE_0000_0000_0000_0000_0000_0001)
}

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
}

/// Deterministic evidence-row builder (ids ordered by `seq`).
#[allow(clippy::too_many_arguments)]
fn ev(
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
        evidence_id: Uuid::from_u128(0xE000_0000_0000_0000_0000_0000_0000_0000 + seq),
        tenant_id: tenant(),
        left_ref: left.to_string(),
        right_ref: right.to_string(),
        tier,
        method: method.to_string(),
        key_value: key_value.map(str::to_string),
        key_namespace: key_namespace.map(str::to_string),
        score: if tier == 1 { None } else { Some(0.97) },
        evidence_l0_ref: Some(format!("l0:{seq}")),
        polarity,
        valid_from: ts(seq as i64),
        valid_to: None,
        superseded_by: None,
    }
}

/// The adversarial config: freemail denylisted on the domain key, the §4.4
/// namespace fence on internal_directory emails, min_independent_keys = 2,
/// a component-size cap.
fn adversarial_config() -> FoldConfig {
    let mut fallback = EntityResolutionConfig::defaults(tenant(), "*", "*");
    fallback.min_independent_keys = 2;
    fallback.component_size_cap = Some(SIZE_CAP);
    fallback.denylist_values = FREEMAIL.iter().map(|s| s.to_string()).collect();

    let mut domain_rule = EntityResolutionConfig::defaults(tenant(), "domain", "customer_contact");
    domain_rule.min_independent_keys = 2;
    domain_rule.denylist_values = FREEMAIL.iter().map(|s| s.to_string()).collect();

    let mut internal_email =
        EntityResolutionConfig::defaults(tenant(), "email", "internal_directory");
    internal_email.eligible_as_edge = false; // the §4.4 fence.

    FoldConfig::new(tenant(), vec![domain_rule, internal_email], fallback)
}

/// One generated world: ground truth (ref -> true-entity index) + evidence +
/// the adversarial pair bookkeeping the invariants check against.
#[derive(Default)]
struct World {
    evidence: Vec<EvidenceRow>,
    /// ref -> ground-truth entity index.
    truth: BTreeMap<String, usize>,
    /// pairs a live anti-link forbids (I2).
    anti_pairs: Vec<(String, String)>,
    /// cross-entity pairs joined ONLY by a lone MEDIUM key (I3).
    lone_medium_pairs: Vec<(String, String)>,
    /// cross-entity pairs joined ONLY by tier-2-without-human / tier-3 (I5).
    weak_tier_pairs: Vec<(String, String)>,
    /// members of the oversized ("mega") component, if generated (I4).
    mega_members: Vec<String>,
    /// chunk refs + the ghost canonical that must NEVER become a tag (I5).
    ghost_canonical: String,
}

fn gen_world(seed: u64) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut w = World {
        ghost_canonical: format!("canon:ghost:{seed}"),
        ..Default::default()
    };
    let mut seq: u128 = 1;
    let next = |s: &mut u128| {
        *s += 1;
        *s
    };

    // --- Ground-truth entities, each with 2..=4 member refs across sources. ---
    let n_entities = rng.random_range(4..=9);
    let mut members: Vec<Vec<String>> = Vec::new();
    for e in 0..n_entities {
        let n_members = rng.random_range(2..=4);
        let mut ms = Vec::new();
        for m in 0..n_members {
            let src = SOURCES[(e + m) % SOURCES.len()];
            let r = format!("{src}:s{seed}-e{e}-m{m}");
            w.truth.insert(r.clone(), e);
            ms.push(r);
        }
        members.push(ms);
    }

    // --- Legit intra-entity evidence: strong keys chain the members. ---
    for (e, ms) in members.iter().enumerate() {
        for pair in ms.windows(2) {
            let strong_kind = rng.random_range(0..3);
            let row = match strong_kind {
                0 => ev(
                    next(&mut seq),
                    &pair[0],
                    &pair[1],
                    1,
                    "crm_fk",
                    None,
                    Some("customer_contact"),
                    1,
                ),
                1 => ev(
                    next(&mut seq),
                    &pair[0],
                    &pair[1],
                    1,
                    "external_id",
                    Some(&format!("XID-{seed}-{e}")),
                    Some("customer_contact"),
                    1,
                ),
                _ => ev(
                    next(&mut seq),
                    &pair[0],
                    &pair[1],
                    1,
                    "email_exact",
                    Some(&format!("p{seed}@corp-{e}.com")),
                    Some("customer_contact"),
                    1,
                ),
            };
            w.evidence.push(row);
        }
    }

    // --- Adversarial cross-entity injections (each on a FRESH member pair so
    // two injections can never accidentally corroborate each other into a
    // legitimate 2-key merge). ---
    let mut used_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    let fresh_cross_pair =
        |rng: &mut StdRng, used: &mut BTreeSet<(String, String)>| -> Option<(String, String)> {
            for _ in 0..32 {
                let a = rng.random_range(0..n_entities);
                let b = rng.random_range(0..n_entities);
                if a == b {
                    continue;
                }
                let ra = members[a].choose(rng).unwrap().clone();
                let rb = members[b].choose(rng).unwrap().clone();
                let key = if ra <= rb {
                    (ra.clone(), rb.clone())
                } else {
                    (rb.clone(), ra.clone())
                };
                if used.insert(key) {
                    return Some((ra, rb));
                }
            }
            None
        };

    let n_attacks = rng.random_range(4..=9);
    for k in 0..n_attacks {
        let Some((ra, rb)) = fresh_cross_pair(&mut rng, &mut used_pairs) else {
            break;
        };
        match rng.random_range(0..7) {
            // Free-mail-domain name collision: two distinct companies "share"
            // gmail.com. Denylisted → must never form an edge.
            0 => {
                let dom = FREEMAIL[k % FREEMAIL.len()];
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "domain_match",
                    Some(dom),
                    Some("customer_contact"),
                    1,
                ));
            }
            // Cross-namespace actor/customer email: an internal employee email
            // coincidentally equal to a customer contact email. Fence: the
            // internal_directory email key is not eligible_as_edge.
            1 => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "email_exact",
                    Some(&format!("jane{k}@wrongpop-{seed}.dev")),
                    Some("internal_directory"),
                    1,
                ));
            }
            // Lone MEDIUM key: a single shared (non-denylisted) domain.
            // min_independent_keys=2 → must not auto-merge alone.
            2 => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "domain_match",
                    Some(&format!("collide-{seed}-{k}.com")),
                    Some("customer_contact"),
                    1,
                ));
                w.lone_medium_pairs.push((ra, rb));
            }
            // Near-miss keys: two DIFFERENT key-nodes (acme.com vs acme.net) —
            // no shared node, so no edge may ever form between the entities.
            3 => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &format!("key:domain:near-{seed}-{k}.com"),
                    1,
                    "domain_match",
                    Some(&format!("near-{seed}-{k}.com")),
                    Some("customer_contact"),
                    1,
                ));
                w.evidence.push(ev(
                    next(&mut seq),
                    &rb,
                    &format!("key:domain:near-{seed}-{k}.net"),
                    1,
                    "domain_match",
                    Some(&format!("near-{seed}-{k}.net")),
                    Some("customer_contact"),
                    1,
                ));
            }
            // Anti-linked pair: pile on positive STRONG evidence, then a human
            // anti-link. The anti-link must win, permanently.
            4 => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "crm_fk",
                    None,
                    Some("customer_contact"),
                    1,
                ));
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "external_id",
                    Some(&format!("XID-EVIL-{seed}-{k}")),
                    Some("customer_contact"),
                    1,
                ));
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    1,
                    "human_rejected",
                    None,
                    Some("customer_contact"),
                    -1,
                ));
                w.anti_pairs.push((ra, rb));
            }
            // Tier-2 fuzzy WITHOUT human confirmation: never an edge.
            5 => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    2,
                    "name+domain_fuzzy",
                    Some(&format!("fuzzyname-{k}")),
                    Some("customer_contact"),
                    1,
                ));
                w.weak_tier_pairs.push((ra, rb));
            }
            // Tier-3 mention between two member refs: NEVER an edge.
            _ => {
                w.evidence.push(ev(
                    next(&mut seq),
                    &ra,
                    &rb,
                    3,
                    "llm_mention",
                    Some("Acme"),
                    Some("customer_contact"),
                    1,
                ));
                w.weak_tier_pairs.push((ra, rb));
            }
        }
    }

    // --- Key-node fan-out: one shared MEDIUM domain welding 3+ DISTINCT
    // entities. Must surface as KeyFanOut review, never a weld. ---
    if n_entities >= 3 && rng.random_bool(0.6) {
        let key_ref = format!("key:domain:fanout-{seed}.com");
        for ms in members.iter().take(3) {
            w.evidence.push(ev(
                next(&mut seq),
                &ms[0],
                &key_ref,
                1,
                "domain_match",
                Some(&format!("fanout-{seed}.com")),
                Some("customer_contact"),
                1,
            ));
        }
    }

    // --- Oversized component: ONE true entity with cap+2 members chained by
    // strong keys. Fail-closed: quarantined (SizeCapExceeded), not merged. ---
    if rng.random_bool(0.5) {
        let mega_idx = n_entities; // its own ground-truth entity.
        let n = (SIZE_CAP as usize) + 2;
        let mut prev: Option<String> = None;
        for m in 0..n {
            let r = format!("{}:s{seed}-mega-m{m}", SOURCES[m % SOURCES.len()]);
            w.truth.insert(r.clone(), mega_idx);
            w.mega_members.push(r.clone());
            if let Some(p) = prev {
                w.evidence.push(ev(
                    next(&mut seq),
                    &p,
                    &r,
                    1,
                    "crm_fk",
                    None,
                    Some("customer_contact"),
                    1,
                ));
            }
            prev = Some(r);
        }
    }

    // --- Tier-3 chunk mentions. A mention of a NEVER-FOLDED ghost canonical
    // must never become a tag, cosignal or not, auto_link_tier3 or not
    // (default off here). ---
    let chunk_a = format!("chunk:gdrive:doc-{seed}:0");
    w.evidence.push(ev(
        next(&mut seq),
        &chunk_a,
        &w.ghost_canonical.clone(),
        3,
        "llm_mention",
        Some("Ghost Corp"),
        Some("customer_contact"),
        1,
    ));
    // Sometimes add a deterministic co-signal on the same chunk (a tier-1 edge
    // anchoring the chunk to a real member): the gate may open, but the ghost
    // is STILL not folded, so it must still never be tagged.
    if rng.random_bool(0.5) {
        let anchor = members[0][0].clone();
        w.evidence.push(ev(
            next(&mut seq),
            &chunk_a,
            &anchor,
            1,
            "crm_fk",
            None,
            Some("customer_contact"),
            1,
        ));
    }

    w
}

/// canonical assignments (`ref -> canonical`) from a plan.
fn alias_map(plan_aliases: &[AliasWrite]) -> BTreeMap<String, String> {
    plan_aliases
        .iter()
        .map(|a| {
            (
                format!("{}:{}", a.source, a.entity_id),
                a.canonical_entity.clone(),
            )
        })
        .collect()
}

#[test]
fn pure_fold_precision_fuzzer_no_false_merge_ever() {
    let cfg = adversarial_config();
    let mut total_attacks_survived = 0usize;

    for seed in 0..ITERS {
        let w = gen_world(seed);
        let plan = fold(&w.evidence, &cfg);
        let canon_of = alias_map(&plan.aliases);

        // ---- I1: PRECISION == 1.0 / FMR == 0.0. Every canonical is pure: it
        // contains members of exactly ONE ground-truth entity. ----
        let mut by_canon: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
        let mut size_of: BTreeMap<&str, usize> = BTreeMap::new();
        for a in &plan.aliases {
            let r = format!("{}:{}", a.source, a.entity_id);
            let gt = *w
                .truth
                .get(&r)
                .unwrap_or_else(|| panic!("seed {seed}: alias for unknown ref {r}"));
            by_canon.entry(&a.canonical_entity).or_default().insert(gt);
            *size_of.entry(&a.canonical_entity).or_default() += 1;
        }
        for (canon, gts) in &by_canon {
            assert_eq!(
                gts.len(),
                1,
                "seed {seed}: FALSE MERGE (scope leak): canonical {canon} spans \
                 ground-truth entities {gts:?}\nplan: {plan:#?}"
            );
        }

        // ---- I2: anti-links never overridden. ----
        for (a, b) in &w.anti_pairs {
            let ca = canon_of.get(a);
            let cb = canon_of.get(b);
            assert!(
                ca.is_none() || cb.is_none() || ca != cb,
                "seed {seed}: anti-linked pair ({a}, {b}) shares canonical {ca:?}"
            );
        }

        // ---- I3: lone-MEDIUM-key pairs never merge. ----
        for (a, b) in &w.lone_medium_pairs {
            let ca = canon_of.get(a);
            let cb = canon_of.get(b);
            assert!(
                ca.is_none() || cb.is_none() || ca != cb,
                "seed {seed}: lone shared domain merged ({a}, {b}) — \
                 min_independent_keys violated"
            );
        }

        // ---- I5 (edges): tier-2-without-human / tier-3 pairs never merge. ----
        for (a, b) in &w.weak_tier_pairs {
            let ca = canon_of.get(a);
            let cb = canon_of.get(b);
            assert!(
                ca.is_none() || cb.is_none() || ca != cb,
                "seed {seed}: sub-Tier-1 evidence formed an edge ({a}, {b})"
            );
        }

        // ---- I4: component_size_cap quarantines. ----
        for (canon, size) in &size_of {
            assert!(
                *size as i32 <= SIZE_CAP,
                "seed {seed}: canonical {canon} has {size} members > cap {SIZE_CAP}"
            );
        }
        if !w.mega_members.is_empty() {
            for m in &w.mega_members {
                assert!(
                    !canon_of.contains_key(m),
                    "seed {seed}: member {m} of an oversized component was aliased \
                     instead of quarantined"
                );
            }
            assert!(
                plan.review
                    .iter()
                    .any(|r| matches!(r.reason, ReviewReason::SizeCapExceeded { .. })),
                "seed {seed}: oversized component did not surface as SizeCapExceeded"
            );
        }

        // ---- I5 (tags): chunk tags only name folded/known canonicals; the
        // never-folded ghost canonical is NEVER a tag. ----
        let folded: BTreeSet<&str> = plan.canonicals.iter().map(String::as_str).collect();
        for ct in &plan.chunk_tags {
            for t in &ct.tags {
                assert_ne!(
                    t, &w.ghost_canonical,
                    "seed {seed}: ghost canonical tagged onto {}",
                    ct.subject_ref
                );
                assert!(
                    folded.contains(t.as_str()),
                    "seed {seed}: chunk {} tagged with un-folded canonical {t}",
                    ct.subject_ref
                );
            }
        }

        // ---- I6: determinism under permutation. ----
        let mut rng = StdRng::seed_from_u64(seed ^ 0xDEAD_BEEF);
        let mut permuted = w.evidence.clone();
        permuted.shuffle(&mut rng);
        let plan2 = fold(&permuted, &cfg);
        assert_eq!(
            plan, plan2,
            "seed {seed}: fold output depends on evidence order"
        );

        total_attacks_survived += w.anti_pairs.len()
            + w.lone_medium_pairs.len()
            + w.weak_tier_pairs.len()
            + usize::from(!w.mega_members.is_empty());
    }
    println!(
        "resolution precision fuzz: {ITERS} seeded adversarial ledgers, \
         {total_attacks_survived} tracked attacks, 0 false merges (precision 1.0 / FMR 0.0)"
    );
}

/// Tier-3 mentions of a KNOWN (pre-existing) canonical may tag a chunk when the
/// §5 gate opens — but the known set must never widen membership (no alias/edge
/// effect) and unknown canonicals stay untaggable. Fuzzed alongside the main
/// invariants because `fold_with_known_canonicals` is the production entry
/// point (the worker threads `entity_aliases`'s canonicals in).
#[test]
fn known_canonicals_never_widen_membership_and_gate_stays_closed_for_ghosts() {
    let cfg = adversarial_config();
    for seed in 0..64u64 {
        let w = gen_world(seed);
        let known = KnownCanonicals::new(["canon:prior:known"], []);
        let base = fold(&w.evidence, &cfg);
        let with_known = fold_with_known_canonicals(&w.evidence, &cfg, &known);

        // The known set must not change aliases/canonicals/review — it is a
        // tag-eligibility set ONLY (§5 precondition (a)), never a merge input.
        assert_eq!(base.aliases, with_known.aliases, "seed {seed}");
        assert_eq!(base.canonicals, with_known.canonicals, "seed {seed}");
        assert_eq!(base.review, with_known.review, "seed {seed}");

        // Ghost canonicals remain untaggable even with a non-empty known set.
        for ct in &with_known.chunk_tags {
            for t in &ct.tags {
                assert_ne!(t, &w.ghost_canonical, "seed {seed}: ghost tagged");
            }
        }
    }
}
