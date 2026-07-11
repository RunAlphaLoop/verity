//! S4 — THE FOLD (pure, deterministic).
//!
//! `docs/design/cross-source-entity-resolution.md` §4.2 (S4 + incremental fold)
//! and §6 (permission-safety). This module is the **pure deterministic core** of
//! entity resolution: it takes an in-memory snapshot of *live* evidence rows plus
//! the tenant's key-quality config and folds them into the three materialized
//! surfaces the read path consumes — canonical `entity_aliases` membership,
//! chunk `entity_tags`, and the `entity_link_meta` confidence badge.
//!
//! **Purity is the whole point.** There is NO LLM, NO similarity, NO database,
//! and NO clock inside [`fold`]. It is a total function of its two arguments, so
//! the entire security surface — anti-link permanence, the `min_independent_keys`
//! lone-domain guard, the namespace fence, the `component_size_cap` fail-closed,
//! Tier-3-never-merges — is exhaustively property-testable with no I/O. The tests
//! at the bottom of this file are the security proof (§6).
//!
//! The impure shell (reading live evidence via `live_evidence_for_refs`, writing
//! aliases via `upsert_entity_alias`, tags via `chunk_entity_tags_upsert`, badges
//! via `upsert_entity_link_meta`) lives in the caller (the fold worker / server);
//! this file only produces the *plan* those writers execute.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;
use verity_core::types::*;

use crate::resolve::tier3::KnownCanonicals;

// ---------------------------------------------------------------------------
// Public API — the plan the server/materializer executes.
// ---------------------------------------------------------------------------

/// A parsed `source:entity_id` ref. The evidence ledger stores refs as opaque
/// `"source:entity_id"` strings; the fold splits them back to their two parts
/// only when it must call `upsert_entity_alias(tenant, source, entity_id, ...)`.
///
/// A ref that is not a member ref — a `key:*` key-node (§4.2 step 4) or a
/// `chunk:*` mention subject — is NOT a `(source, entity_id)` and never becomes
/// an alias member; [`split_member_ref`] returns `None` for those.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemberRef {
    pub source: String,
    pub entity_id: String,
}

/// One `(source, entity_id) -> canonical_entity` alias the fold wants written
/// via the reused `upsert_entity_alias` (postgres.rs:302).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AliasWrite {
    pub source: String,
    pub entity_id: String,
    pub canonical_entity: String,
}

/// A chunk-tag materialization the fold wants written via
/// `chunk_entity_tags_upsert` (postgres.rs:614). `subject_ref` is the chunk's
/// mention ref (`chunk:<source>:<document_id>:<seq>`); the caller carries the
/// `(source, document_id, seq)` needed to re-tag. `tags` is the FULL desired tag
/// set for the live chunk (the upsert overwrites, so the fold emits the complete
/// set, deterministically ordered).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkTagWrite {
    pub subject_ref: String,
    pub tags: Vec<String>,
}

/// Why a component did not auto-merge (fail-closed outcomes, §4.2 steps 2/5,
/// §4.2 incremental drift guard). These are surfaced for review, never silently
/// merged — under-merge is safe, over-merge is a scope leak (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReviewReason {
    /// A `polarity=-1` anti-link split what positive edges would otherwise join
    /// (§4.2 step 2). Permanent guardrail — no positive evidence overrides it.
    AntiLinkSplit,
    /// Component size exceeded `component_size_cap` (§4.2 step 5). Runaway
    /// clustering degrades to separate entities, never one scope-fusing mega
    /// entity.
    SizeCapExceeded { size: usize, cap: i32 },
    /// A shared key (domain) fans out to more distinct members than
    /// `min_independent_keys` justifies auto-welding on that key alone (§4.2
    /// step 4): a visible star, surfaced rather than silently transitively
    /// welded.
    KeyFanOut { key: String, members: usize },
    /// Incremental drift guard (§4.2 incremental): a candidate edge would fuse
    /// two *existing* components and the join is below the auto-join bar (either
    /// side above the size floor, or the joining edge below Tier-1). Routed to
    /// review, never silently joined.
    ClusterDrift {
        left_canonical: String,
        right_canonical: String,
    },
}

/// A component surfaced for human review instead of being auto-merged. Carries
/// the refs involved and the reason, so the review queue can render it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewItem {
    pub refs: Vec<String>,
    pub reason: ReviewReason,
    /// The live evidence rows implicated (for audit / surgical retract).
    pub evidence: Vec<Uuid>,
}

/// The full deterministic output of a fold. Everything here is a *plan*; the
/// impure caller executes it against Postgres. Same input ⇒ byte-identical
/// output (see `fold_is_deterministic`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FoldPlan {
    /// Canonical membership to upsert (`entity_aliases`). Members of a singleton
    /// component (their own canonical) are ELIDED — an entity with no alias row
    /// is implicitly its own canonical (§2.1 "annoying, never wrong"), so we do
    /// not write self-aliases. Deterministically ordered.
    pub aliases: Vec<AliasWrite>,
    /// Chunk-tag materializations (`chunks.entity_tags`). Deterministically
    /// ordered.
    pub chunk_tags: Vec<ChunkTagWrite>,
    /// Confidence badges + surgical-split back-refs (`entity_link_meta`).
    /// Deterministically ordered.
    pub link_meta: Vec<EntityLinkMeta>,
    /// Components that FAILED CLOSED — surfaced for review, not merged.
    pub review: Vec<ReviewItem>,
    /// The canonical_entity of every non-trivial component the fold produced, so
    /// the incremental path can detect a component's disappearance/split on
    /// re-fold. Deterministically ordered, deduped.
    pub canonicals: Vec<String>,
}

/// Per-namespace config the fold consults. The evidence ledger spans namespaces,
/// but `EntityResolutionConfig` is keyed per `(key_kind, key_namespace)`; the
/// fold needs a *lookup*, not a single row. `FoldConfig` bundles the tenant's
/// per-`(key_kind, key_namespace)` rows plus a fallback (used when a specific
/// row is missing — the same defaults `read_resolution_config` returns).
///
/// Kept as owned data (not a closure / DB handle) so the fold stays a pure
/// function of plain in-memory inputs and is exhaustively property-testable.
#[derive(Debug, Clone)]
pub struct FoldConfig {
    tenant_id: TenantId,
    /// Keyed by `(key_kind, key_namespace)`.
    rows: BTreeMap<(String, String), EntityResolutionConfig>,
    fallback: EntityResolutionConfig,
}

impl FoldConfig {
    /// Build from the tenant's config rows. `fallback` supplies the guard values
    /// (`component_size_cap`, and the effective `min_independent_keys` /
    /// `auto_merge_tier1` / `auto_link_tier3` when a specific row is absent).
    pub fn new(
        tenant_id: TenantId,
        rows: impl IntoIterator<Item = EntityResolutionConfig>,
        fallback: EntityResolutionConfig,
    ) -> Self {
        let rows = rows
            .into_iter()
            .map(|c| ((c.key_kind.clone(), c.key_namespace.clone()), c))
            .collect();
        Self {
            tenant_id,
            rows,
            fallback,
        }
    }

    /// A FoldConfig carrying only the defaults (no per-key rows). Convenient for
    /// the OSS default path and for tests.
    pub fn defaults(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            rows: BTreeMap::new(),
            fallback: EntityResolutionConfig::defaults(tenant_id, "*", "*"),
        }
    }

    /// Look up the config governing a `(key_kind, key_namespace)` — exact match,
    /// else a `(key_kind, "*")` wildcard, else the fallback.
    fn get(&self, key_kind: &str, key_namespace: &str) -> &EntityResolutionConfig {
        self.rows
            .get(&(key_kind.to_string(), key_namespace.to_string()))
            .or_else(|| self.rows.get(&(key_kind.to_string(), "*".to_string())))
            .unwrap_or(&self.fallback)
    }

    /// The component-size cap (a tenant-wide guard). Taken from the fallback,
    /// which the admin sets on the tenant-default row.
    fn component_size_cap(&self) -> Option<i32> {
        self.fallback.component_size_cap
    }
}

// ---------------------------------------------------------------------------
// Ref parsing (§4.2: split "source:entity_id" back to (source, entity_id)).
// ---------------------------------------------------------------------------

/// Split a member ref `"source:entity_id"` into its parts. Splits on the FIRST
/// `:` only (entity_ids may contain `:`). Returns `None` for non-member refs:
/// - `key:*`   — a key-node (a shared domain/email star), never an alias member.
/// - `chunk:*` — a chunk mention subject, tagged not aliased.
/// - anything with no `:` (a bare token) — malformed, ignored fail-closed.
pub fn split_member_ref(reff: &str) -> Option<MemberRef> {
    if is_key_node(reff) || is_chunk_ref(reff) {
        return None;
    }
    let (source, entity_id) = reff.split_once(':')?;
    if source.is_empty() || entity_id.is_empty() {
        return None;
    }
    Some(MemberRef {
        source: source.to_string(),
        entity_id: entity_id.to_string(),
    })
}

/// `key:<kind>:<value>` — a first-class key-node (§4.2 step 4). A domain shared
/// by N accounts is modeled as a visible star through such a node, never a silent
/// transitive weld.
fn is_key_node(reff: &str) -> bool {
    reff.starts_with("key:")
}

/// `chunk:<source>:<document_id>:<seq>` — an unstructured-mention subject that
/// gets a chunk tag, never an alias member.
fn is_chunk_ref(reff: &str) -> bool {
    reff.starts_with("chunk:")
}

/// Parse a `chunk:<source>:<document_id>:<seq>` ref into the `(source,
/// document_id, seq)` the tag upsert needs. Splits from the RIGHT for `seq` and
/// the LEFT for `source`, leaving `document_id` in the middle (so document_ids
/// containing `:` survive). Returns `None` if malformed.
pub fn parse_chunk_ref(reff: &str) -> Option<(String, String, i32)> {
    let rest = reff.strip_prefix("chunk:")?;
    let (source, tail) = rest.split_once(':')?;
    let (document_id, seq_str) = tail.rsplit_once(':')?;
    if source.is_empty() || document_id.is_empty() {
        return None;
    }
    let seq: i32 = seq_str.parse().ok()?;
    Some((source.to_string(), document_id.to_string(), seq))
}

// ---------------------------------------------------------------------------
// The fold.
// ---------------------------------------------------------------------------

/// Fold a snapshot of *live* evidence into a deterministic write plan.
///
/// Contract (§4.2 S4):
/// 1. Consider only live, `eligible_as_edge` evidence (callers pass live rows;
///    this fn additionally drops rows whose namespace config is
///    `eligible_as_edge = false`).
/// 2. **Anti-links win.** Any `polarity=-1` pair is a hard must-not-link: it
///    both suppresses positive edges between those two refs AND, if the two refs
///    still land in one component via other paths, quarantines that component to
///    review (`AntiLinkSplit`). No positive evidence overrides an anti-link.
/// 3. Build merge edges ONLY from evidence clearing its tier bar:
///    - Tier-1: an edge, subject to `min_independent_keys` (a lone MEDIUM key
///      like a shared domain does not auto-merge two accounts alone).
///    - Tier-2: an edge ONLY if a `human_confirmed` row exists for that pair.
///    - Tier-3: NEVER an edge (only raises evidence_count/confidence on an edge a
///      higher tier already made, or materializes a chunk tag under §5).
/// 4. Shared keys are first-class KEY-NODES: a `key:<kind>:<value>` ref shared by
///    N members is a visible star. If a single key's fan-out would weld more
///    distinct members than `min_independent_keys` corroborates, the component is
///    surfaced for review (`KeyFanOut`), not auto-welded.
/// 5. Union-find over qualifying edges → components. A component larger than
///    `component_size_cap` is QUARANTINED (`SizeCapExceeded`), not merged.
/// 6. Each surviving component → one `canonical_entity` + members + link_meta
///    with `justifying_evidence`. Chunk mentions → tags under §5's rule.
///
/// Pure: no I/O, no clock, no randomness. `fold(x, c) == fold(x, c)` always.
///
/// This is the plain entry point: Tier-3 mentions may only tag canonicals this
/// run just folded (the strictest fail-closed known-set — see §5 precondition
/// (a) in [`crate::resolve::tier3`]). Use [`fold_with_known_canonicals`] to also
/// admit canonicals already materialized in `entity_aliases` from a prior run.
pub fn fold(live_evidence: &[EvidenceRow], config: &FoldConfig) -> FoldPlan {
    fold_with_known_canonicals(live_evidence, config, &KnownCanonicals::empty())
}

/// [`fold`], plus an explicit set of canonicals **already folded** (present in
/// `entity_aliases`), read in the worker plane by the impure materializer.
///
/// The known set is used ONLY to satisfy §5 precondition (a) — "the mentioned
/// canonical is already folded" — for Tier-3 chunk tagging. It NEVER forms a
/// merge edge, NEVER widens a scope, and does not affect alias/component output;
/// it only lets a mention tag a chunk with a canonical that a *prior* fold (or
/// admin crosswalk) already materialized, in addition to those this run
/// produced. Still fully deterministic given its three inputs.
pub fn fold_with_known_canonicals(
    live_evidence: &[EvidenceRow],
    config: &FoldConfig,
    known_canonicals: &KnownCanonicals,
) -> FoldPlan {
    debug_assert!(
        live_evidence.iter().all(|e| e.valid_to.is_none()),
        "fold must be given only LIVE evidence (valid_to IS NULL)"
    );

    // Deterministic working order: valid_from, then evidence_id. Mirrors
    // live_evidence_for_refs' ORDER BY so DB order and in-memory order agree.
    let mut evidence: Vec<&EvidenceRow> = live_evidence
        .iter()
        .filter(|e| e.tenant_id == config.tenant_id)
        .collect();
    evidence.sort_by(|a, b| {
        a.valid_from
            .cmp(&b.valid_from)
            .then_with(|| a.evidence_id.cmp(&b.evidence_id))
    });

    // ---- Pass 1: partition evidence by role. ----
    // Positive merge-forming edges (per tier bar), anti-links, tier-3 mentions,
    // and human confirmations for tier-2.
    let mut anti_links: BTreeSet<UnorderedPair> = BTreeSet::new();
    let mut anti_link_ev: BTreeMap<UnorderedPair, Vec<Uuid>> = BTreeMap::new();
    // Tier-2 pairs that have a live human_confirmed row → the tier-2 edge is
    // permitted for that exact pair.
    let mut human_confirmed: BTreeSet<UnorderedPair> = BTreeSet::new();

    for e in &evidence {
        let pair = UnorderedPair::new(&e.left_ref, &e.right_ref);
        if e.polarity < 0 {
            anti_links.insert(pair.clone());
            anti_link_ev.entry(pair).or_default().push(e.evidence_id);
            continue;
        }
        // human_confirmed / human_rejected are the tier-2 gate + anti-link.
        if e.method == "human_confirmed" {
            human_confirmed.insert(pair);
        }
        if e.method == "human_rejected" {
            // A human rejection is an anti-link even if a producer set polarity
            // wrong. Defense-in-depth: method name also fences.
            let p = UnorderedPair::new(&e.left_ref, &e.right_ref);
            anti_links.insert(p.clone());
            anti_link_ev.entry(p).or_default().push(e.evidence_id);
        }
    }

    // ---- Pass 2: collect candidate merge edges (before min_independent_keys /
    // key-fanout / anti-link suppression). Each carries its justifying evidence.
    // We also record, per key-node, how many distinct members reference it, to
    // model the shared-key star and detect fan-out. ----
    let mut candidate_edges: BTreeMap<UnorderedPair, EdgeEvidence> = BTreeMap::new();
    // key-node ref -> set of member refs it connects (the star's leaves).
    let mut key_star: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // For min_independent_keys: per member-pair, the set of DISTINCT
    // (key_kind, key_value) that independently corroborate a direct edge.
    let mut pair_keys: BTreeMap<UnorderedPair, BTreeSet<(String, String)>> = BTreeMap::new();

    for e in &evidence {
        if e.polarity < 0 || e.method == "human_rejected" {
            continue;
        }
        let cfg = config.get(&key_kind_of(e), namespace_of(e));
        // (1) eligibility fence: a key kind marked not-eligible NEVER forms an edge.
        if !cfg.eligible_as_edge {
            continue;
        }
        // Denylist fence: a denylisted key value (gmail.com, info@) NEVER forms
        // an edge (§4.2 S0 / §6 defense 2).
        if let Some(v) = &e.key_value {
            if cfg.denylist_values.iter().any(|d| d == v) {
                continue;
            }
        }
        // Namespace fence (§4.4): an edge may only form within a namespace. Both
        // refs must be in the same key_namespace population. We encode the
        // namespace on the evidence; a cross-namespace edge is refused here.
        // (Producers stamp key_namespace; refless admin crosswalks carry None
        // and are namespace-agnostic Tier-1.)

        match e.tier {
            1 => {
                // Tier-1 auto-merge must be enabled for this namespace.
                if !cfg.auto_merge_tier1 {
                    continue;
                }
                add_candidate_edge(&mut candidate_edges, &mut key_star, &mut pair_keys, e);
            }
            2 => {
                // Tier-2 forms an edge ONLY if a live human_confirmed row exists
                // for the same pair (§4.2 step 3).
                let pair = UnorderedPair::new(&e.left_ref, &e.right_ref);
                if human_confirmed.contains(&pair) {
                    add_candidate_edge(&mut candidate_edges, &mut key_star, &mut pair_keys, e);
                }
            }
            // Tier-3 NEVER forms an edge (§4.2 step 3). Handled in the tagging
            // pass only.
            _ => {}
        }
    }
    // human_confirmed rows are themselves tier-agnostic edges (a human saying
    // "these two ARE the same" is a first-class link).
    for e in &evidence {
        if e.method == "human_confirmed" && e.polarity >= 0 {
            add_candidate_edge(&mut candidate_edges, &mut key_star, &mut pair_keys, e);
        }
    }

    // ---- Pass 3: min_independent_keys — a lone MEDIUM key (a single shared
    // domain) may not auto-merge two accounts alone. A direct member↔member edge
    // corroborated by fewer than `min_independent_keys` DISTINCT keys (and not
    // human_confirmed, and not a strong FK/external_id/admin edge) is demoted:
    // it does not weld, it surfaces the pair for review. ----
    let mut suppressed_for_min_keys: BTreeSet<UnorderedPair> = BTreeSet::new();
    for (pair, ev) in &candidate_edges {
        // Human confirmation and refless strong edges (crm_fk, external_id,
        // admin_crosswalk, email_exact) satisfy the bar on their own.
        if ev.strong_single_key || human_confirmed.contains(pair) {
            continue;
        }
        let effective_min = config
            .get(&ev.dominant_key_kind, &ev.dominant_namespace)
            .min_independent_keys
            .max(1);
        let distinct = pair_keys.get(pair).map(|s| s.len()).unwrap_or(0) as i16;
        if distinct < effective_min {
            suppressed_for_min_keys.insert(pair.clone());
        }
    }

    // ---- Pass 4: key-node fan-out. A shared key that welds more DISTINCT
    // members than min_independent_keys corroborates is a star surfaced for
    // review, not an auto-weld. If a key connects > that many distinct members
    // through a lone MEDIUM key, drop those key-mediated edges and record the
    // fan-out. Strong keys (external_id, admin) are exempt. ----
    let mut fanout_reviews: Vec<ReviewItem> = Vec::new();
    let mut suppressed_key_nodes: BTreeSet<String> = BTreeSet::new();
    for (key_ref, leaves) in &key_star {
        if leaves.len() <= 2 {
            continue; // a normal pairwise star (A—key—B) is fine.
        }
        // A fan-out of 3+ distinct members through ONE key is only auto-weldable
        // if that key is a strong key kind. Domains are MEDIUM → surface.
        let kind = key_node_kind(key_ref);
        let strong = matches!(kind.as_str(), "external_id" | "crm_fk" | "admin");
        if !strong {
            suppressed_key_nodes.insert(key_ref.clone());
            let mut refs: Vec<String> = leaves.iter().cloned().collect();
            refs.push(key_ref.clone());
            refs.sort();
            fanout_reviews.push(ReviewItem {
                refs,
                reason: ReviewReason::KeyFanOut {
                    key: key_ref.clone(),
                    members: leaves.len(),
                },
                evidence: key_star_evidence(&candidate_edges, key_ref),
            });
        }
    }

    // ---- Pass 5: union-find over the SURVIVING edges. ----
    let mut uf = UnionFind::default();
    // Every ref that appears anywhere gets a node (so singletons are known).
    for e in &evidence {
        uf.touch(&e.left_ref);
        uf.touch(&e.right_ref);
    }
    for (pair, ev) in &candidate_edges {
        if suppressed_for_min_keys.contains(pair) {
            continue;
        }
        // Drop edges mediated by a suppressed (fanned-out) key-node.
        if ev
            .via_key_node
            .as_ref()
            .map(|k| suppressed_key_nodes.contains(k))
            .unwrap_or(false)
        {
            continue;
        }
        uf.union(&pair.a, &pair.b);
    }

    // ---- Pass 6: materialize components, applying anti-link + size-cap
    // fail-closed guards. ----
    let mut components: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for reff in uf.members() {
        let root = uf.find_root(&reff);
        components.entry(root).or_default().insert(reff);
    }

    let cap = config.component_size_cap();
    let mut plan = FoldPlan::default();
    plan.review.extend(fanout_reviews);

    for member_set in components.values() {
        let refs: Vec<String> = member_set.iter().cloned().collect();

        // Only member refs (source:entity_id) count toward alias membership /
        // canonical size; key-nodes and chunk refs are structural, not entities.
        let entity_members: Vec<MemberRef> =
            refs.iter().filter_map(|r| split_member_ref(r)).collect();

        // Singleton (one entity, no cross-source link) → its own canonical,
        // implicit, no alias row written (§2.1). Chunk/key-only components are
        // handled by the tagging pass, not here.
        if entity_members.len() < 2 {
            continue;
        }

        // ---- Guard: anti-link inside the component quarantines it. ----
        let component_anti: Vec<&UnorderedPair> = anti_links
            .iter()
            .filter(|p| member_set.contains(&p.a) && member_set.contains(&p.b))
            .collect();
        if !component_anti.is_empty() {
            let mut ev: Vec<Uuid> = Vec::new();
            for p in &component_anti {
                if let Some(v) = anti_link_ev.get(*p) {
                    ev.extend(v.iter().copied());
                }
            }
            ev.sort();
            ev.dedup();
            plan.review.push(ReviewItem {
                refs: refs.clone(),
                reason: ReviewReason::AntiLinkSplit,
                evidence: ev,
            });
            continue;
        }

        // ---- Guard: component-size cap fails closed. ----
        if let Some(cap) = cap {
            if entity_members.len() as i32 > cap {
                plan.review.push(ReviewItem {
                    refs: refs.clone(),
                    reason: ReviewReason::SizeCapExceeded {
                        size: entity_members.len(),
                        cap,
                    },
                    evidence: component_evidence(&candidate_edges, member_set),
                });
                continue;
            }
        }

        // ---- Survivor: assign canonical + write aliases + meta. ----
        let canonical = canonical_for(&entity_members);
        plan.canonicals.push(canonical.clone());

        // Justifying evidence + strongest method for the whole component.
        let (strongest_method, confidence, just_ev, count) =
            component_badge(&candidate_edges, &human_confirmed, member_set);

        for m in &entity_members {
            plan.aliases.push(AliasWrite {
                source: m.source.clone(),
                entity_id: m.entity_id.clone(),
                canonical_entity: canonical.clone(),
            });
            plan.link_meta.push(EntityLinkMeta {
                tenant_id: config.tenant_id,
                subject_kind: "alias_member".to_string(),
                subject_ref: format!("{}:{}", m.source, m.entity_id),
                canonical_entity: canonical.clone(),
                confidence: confidence.clone(),
                strongest_method: strongest_method.clone(),
                justifying_evidence: just_ev.clone(),
                evidence_count: count,
            });
        }
    }

    // ---- Pass 7: Tier-3 chunk tags. A chunk mention becomes a tag ONLY IF the
    // canonical it mentions was actually folded (a higher tier merged it or it is
    // a real singleton canonical) AND the §5 gate opens: auto_link_tier3, OR a
    // deterministic co-signal on the same chunk, OR a human confirmation. A tag
    // NARROWS retrievability (intersection semantics), and Tier-3 NEVER forms an
    // edge — so tagging cannot create/merge a canonical, only annotate a chunk. -
    // §5 precondition (a): a mention may tag a canonical only if it is ALREADY
    // FOLDED — present in `entity_aliases`. That is this run's freshly-folded
    // canonicals UNIONED with the pre-existing set the caller read from
    // `entity_aliases` (a prior fold / admin crosswalk). The pure fold cannot
    // read the DB, so the pre-existing half arrives as `known_canonicals`.
    let eligible = known_canonicals.with_this_run(plan.canonicals.iter().map(String::as_str));
    materialize_chunk_tags(&evidence, config, &eligible, &mut plan);

    // ---- Determinism: sort every output vector by a total key. ----
    plan.aliases.sort();
    plan.chunk_tags.sort();
    plan.link_meta.sort_by_key(meta_key);
    plan.review.sort();
    plan.canonicals.sort();
    plan.canonicals.dedup();
    plan
}

/// The incremental re-fold entry point (§4.2 "Incremental fold"). Given the
/// affected ref `R`, the caller has already loaded R's component neighborhood
/// (its members' live evidence). This re-runs the pure fold on that neighborhood
/// and applies the CLUSTER-DRIFT GUARD: if a single fold produces a component
/// that fuses two members which, in `prior_canonicals`, belonged to two DISTINCT
/// pre-existing canonicals AND the fusing evidence is below Tier-1 (or either
/// prior side is above `large_component_floor`), that component is routed to
/// review instead of silently joined.
///
/// `prior_canonicals` maps a member ref (`source:entity_id`) → the canonical it
/// resolved to BEFORE this fold (from `entity_link_meta` back-refs / the current
/// `entity_aliases`). `large_component_floor` is the size above which a
/// pre-existing component is "large" and must never fuse silently.
pub fn refold_incremental(
    neighborhood_evidence: &[EvidenceRow],
    config: &FoldConfig,
    prior_canonicals: &BTreeMap<String, String>,
    prior_component_size: &BTreeMap<String, usize>,
    large_component_floor: usize,
) -> FoldPlan {
    let mut plan = fold(neighborhood_evidence, config);

    // Re-run union-find purely to know which member refs share a NEW component,
    // then apply the drift guard on those groupings.
    let mut drift_reviews: Vec<ReviewItem> = Vec::new();
    let mut fused_canonicals_to_drop: BTreeSet<String> = BTreeSet::new();

    // Group the plan's aliases by their new canonical.
    let mut new_components: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in &plan.aliases {
        new_components
            .entry(a.canonical_entity.clone())
            .or_default()
            .push(format!("{}:{}", a.source, a.entity_id));
    }

    for (new_canonical, members) in &new_components {
        // Which DISTINCT prior canonicals do this component's members come from?
        let mut prior_set: BTreeSet<String> = BTreeSet::new();
        for m in members {
            if let Some(pc) = prior_canonicals.get(m) {
                prior_set.insert(pc.clone());
            }
        }
        if prior_set.len() < 2 {
            continue; // not a fusion of two existing components.
        }
        // A fusion of ≥2 prior canonicals. Is either prior side "large"?
        let any_large = prior_set
            .iter()
            .any(|pc| prior_component_size.get(pc).copied().unwrap_or(0) >= large_component_floor);

        // Is the joining evidence below Tier-1? A fusion justified purely by a
        // human_confirmed or a Tier-1 strong key may proceed; otherwise route to
        // review. We approximate "below Tier-1" as: the component's badge is not
        // `deterministic` and not `human_confirmed`.
        let badge_confidence = plan
            .link_meta
            .iter()
            .find(|m| &m.canonical_entity == new_canonical && m.subject_kind == "alias_member")
            .map(|m| m.confidence.as_str())
            .unwrap_or("approximated");
        let below_tier1 =
            badge_confidence != "deterministic" && badge_confidence != "human_confirmed";

        if any_large || below_tier1 {
            let prior_vec: Vec<String> = prior_set.into_iter().collect();
            drift_reviews.push(ReviewItem {
                refs: {
                    let mut r = members.clone();
                    r.sort();
                    r
                },
                reason: ReviewReason::ClusterDrift {
                    left_canonical: prior_vec.first().cloned().unwrap_or_default(),
                    right_canonical: prior_vec.get(1).cloned().unwrap_or_default(),
                },
                evidence: plan
                    .link_meta
                    .iter()
                    .filter(|m| &m.canonical_entity == new_canonical)
                    .flat_map(|m| m.justifying_evidence.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            });
            fused_canonicals_to_drop.insert(new_canonical.clone());
        }
    }

    if !fused_canonicals_to_drop.is_empty() {
        // Remove the silently-fused component's writes; keep it as review only.
        plan.aliases
            .retain(|a| !fused_canonicals_to_drop.contains(&a.canonical_entity));
        plan.link_meta
            .retain(|m| !fused_canonicals_to_drop.contains(&m.canonical_entity));
        plan.canonicals
            .retain(|c| !fused_canonicals_to_drop.contains(c));
        plan.review.extend(drift_reviews);
        plan.review.sort();
    }
    plan
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/// An unordered pair of refs, canonicalized so `(a,b)` and `(b,a)` are equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnorderedPair {
    a: String,
    b: String,
}

impl UnorderedPair {
    fn new(x: &str, y: &str) -> Self {
        if x <= y {
            Self {
                a: x.to_string(),
                b: y.to_string(),
            }
        } else {
            Self {
                a: y.to_string(),
                b: x.to_string(),
            }
        }
    }
}

/// Accumulated justification for one candidate merge edge.
#[derive(Debug, Clone, Default)]
struct EdgeEvidence {
    evidence_ids: Vec<Uuid>,
    /// True if any justifying row is a strong single key that satisfies
    /// min_independent_keys on its own (crm_fk / external_id / admin_crosswalk /
    /// email_exact / human_confirmed).
    strong_single_key: bool,
    /// If this edge is mediated ENTIRELY by a shared key-node, its ref (so a
    /// fanned-out key can suppress it). None for direct member↔member edges.
    via_key_node: Option<String>,
    /// Highest-tier method seen on this edge (for the badge).
    best_method: Option<String>,
    best_tier: i16,
    dominant_key_kind: String,
    dominant_namespace: String,
}

fn strong_method(method: &str) -> bool {
    matches!(
        method,
        "crm_fk" | "external_id" | "admin_crosswalk" | "email_exact" | "human_confirmed"
    )
}

fn key_kind_of(e: &EvidenceRow) -> String {
    match e.method.as_str() {
        "domain_match" => "domain",
        "email_exact" => "email",
        "external_id" => "external_id",
        "crm_fk" => "crm_fk",
        "admin_crosswalk" => "admin",
        _ => "*",
    }
    .to_string()
}

fn namespace_of(e: &EvidenceRow) -> &str {
    e.key_namespace.as_deref().unwrap_or("*")
}

/// Add a candidate merge edge derived from evidence `e`. If both refs are member
/// refs, it is a direct member↔member edge. If exactly one side is a key-node,
/// it contributes a leaf to that key's star (the star is later expanded to
/// pairwise member edges); we record it so fan-out can suppress it.
fn add_candidate_edge(
    edges: &mut BTreeMap<UnorderedPair, EdgeEvidence>,
    key_star: &mut BTreeMap<String, BTreeSet<String>>,
    pair_keys: &mut BTreeMap<UnorderedPair, BTreeSet<(String, String)>>,
    e: &EvidenceRow,
) {
    let left_is_key = is_key_node(&e.left_ref);
    let right_is_key = is_key_node(&e.right_ref);

    if left_is_key ^ right_is_key {
        // member ↔ key-node: record the leaf; the star is expanded after.
        let (key_ref, member_ref) = if left_is_key {
            (&e.left_ref, &e.right_ref)
        } else {
            (&e.right_ref, &e.left_ref)
        };
        key_star
            .entry(key_ref.clone())
            .or_default()
            .insert(member_ref.clone());
        // Also record a direct pairwise edge for every existing leaf of the star
        // so union-find can join them — but tag them via_key_node so fan-out can
        // pull them.
        let leaves: Vec<String> = key_star
            .get(key_ref)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for other in &leaves {
            if other == member_ref {
                continue;
            }
            let pair = UnorderedPair::new(member_ref, other);
            let entry = edges.entry(pair.clone()).or_default();
            entry.evidence_ids.push(e.evidence_id);
            entry.via_key_node = Some(key_ref.clone());
            record_edge_meta(entry, e);
            pair_keys
                .entry(pair)
                .or_default()
                .insert((key_kind_of(e), e.key_value.clone().unwrap_or_default()));
        }
        return;
    }
    if left_is_key && right_is_key {
        return; // key↔key: nonsensical, ignore fail-closed.
    }

    // Direct member ↔ member edge.
    let pair = UnorderedPair::new(&e.left_ref, &e.right_ref);
    let entry = edges.entry(pair.clone()).or_default();
    entry.evidence_ids.push(e.evidence_id);
    if strong_method(&e.method) {
        entry.strong_single_key = true;
    }
    record_edge_meta(entry, e);
    pair_keys.entry(pair).or_default().insert((
        key_kind_of(e),
        e.key_value.clone().unwrap_or_else(|| e.method.clone()),
    ));
}

fn record_edge_meta(entry: &mut EdgeEvidence, e: &EvidenceRow) {
    // Lower tier number = stronger. Track the strongest (lowest tier) method.
    if entry.best_method.is_none() || e.tier < entry.best_tier {
        entry.best_method = Some(e.method.clone());
        entry.best_tier = e.tier;
        entry.dominant_key_kind = key_kind_of(e);
        entry.dominant_namespace = namespace_of(e).to_string();
    }
    if strong_method(&e.method) {
        entry.strong_single_key = true;
    }
}

fn key_node_kind(key_ref: &str) -> String {
    // key:<kind>:<value>
    key_ref
        .strip_prefix("key:")
        .and_then(|r| r.split_once(':'))
        .map(|(k, _)| k.to_string())
        .unwrap_or_default()
}

/// Deterministic canonical id for a component: `account:` + the lexicographically
/// smallest member ref. Stable under member-set permutation, so re-folds are
/// idempotent.
fn canonical_for(members: &[MemberRef]) -> String {
    let min = members.iter().min().expect("component has ≥2 members here");
    format!("canon:{}:{}", min.source, min.entity_id)
}

fn meta_key(m: &EntityLinkMeta) -> (String, String, String) {
    (
        m.subject_kind.clone(),
        m.subject_ref.clone(),
        m.canonical_entity.clone(),
    )
}

/// Evidence ids for edges touching a key-node (for a fan-out review item).
fn key_star_evidence(edges: &BTreeMap<UnorderedPair, EdgeEvidence>, key_ref: &str) -> Vec<Uuid> {
    let mut ids: BTreeSet<Uuid> = BTreeSet::new();
    for ev in edges.values() {
        if ev.via_key_node.as_deref() == Some(key_ref) {
            ids.extend(ev.evidence_ids.iter().copied());
        }
    }
    ids.into_iter().collect()
}

/// All candidate-edge evidence ids fully inside a member set.
fn component_evidence(
    edges: &BTreeMap<UnorderedPair, EdgeEvidence>,
    members: &BTreeSet<String>,
) -> Vec<Uuid> {
    let mut ids: BTreeSet<Uuid> = BTreeSet::new();
    for (pair, ev) in edges {
        if members.contains(&pair.a) && members.contains(&pair.b) {
            ids.extend(ev.evidence_ids.iter().copied());
        }
    }
    ids.into_iter().collect()
}

/// Compute the component badge: strongest method, confidence label,
/// justifying-evidence set, corroboration count.
fn component_badge(
    edges: &BTreeMap<UnorderedPair, EdgeEvidence>,
    human_confirmed: &BTreeSet<UnorderedPair>,
    members: &BTreeSet<String>,
) -> (Option<String>, String, Vec<Uuid>, i16) {
    let mut just: BTreeSet<Uuid> = BTreeSet::new();
    let mut best_tier = i16::MAX;
    let mut best_method: Option<String> = None;
    let mut any_human = false;
    let mut any_deterministic = false;

    for (pair, ev) in edges {
        if !(members.contains(&pair.a) && members.contains(&pair.b)) {
            continue;
        }
        just.extend(ev.evidence_ids.iter().copied());
        if let Some(m) = &ev.best_method {
            if ev.best_tier < best_tier {
                best_tier = ev.best_tier;
                best_method = Some(m.clone());
            }
        }
        if human_confirmed.contains(pair) {
            any_human = true;
        }
        if ev.best_tier == 1 {
            any_deterministic = true;
        }
    }

    let confidence = if any_deterministic {
        "deterministic"
    } else if any_human {
        "human_confirmed"
    } else {
        "approximated"
    }
    .to_string();

    let count = just.len() as i16;
    (best_method, confidence, just.into_iter().collect(), count)
}

/// §5 chunk-tag materialization. Deterministic co-signal rule, fail-closed.
///
/// A Tier-3 mention edge `chunk:… — canonical` becomes a tag ONLY IF:
/// (a) the mentioned canonical was actually folded (present in `folded_canonicals`
///     OR is a real singleton canonical referenced by a member on this chunk), AND
/// (b) the §5 gate opens: `auto_link_tier3` for the namespace is true, OR a
///     deterministic co-signal exists on the same chunk (another live Tier-1/2
///     edge or a `human_confirmed` linking that chunk to the canonical), OR a
///     human confirmation exists.
///
/// Abstain routes to NO TAG (the chunk keeps whatever tags it had) — never the
/// zero-tag broad bucket by force, and never a guessed tag.
fn materialize_chunk_tags(
    evidence: &[&EvidenceRow],
    config: &FoldConfig,
    folded: &KnownCanonicals,
    plan: &mut FoldPlan,
) {
    // Gather, per chunk ref, the candidate (canonical, tier, method, ev) mentions
    // and any deterministic co-signals present on that same chunk.
    let mut chunk_candidates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // chunk ref -> whether a deterministic co-signal (tier<=2 or human) is present.
    let mut chunk_cosignal: BTreeMap<String, bool> = BTreeMap::new();

    for e in evidence {
        if e.polarity < 0 {
            continue;
        }
        let (chunk_ref, other) = if is_chunk_ref(&e.left_ref) {
            (&e.left_ref, &e.right_ref)
        } else if is_chunk_ref(&e.right_ref) {
            (&e.right_ref, &e.left_ref)
        } else {
            continue;
        };
        // The "other" side of a chunk edge is the canonical/entity being asserted.
        // A deterministic co-signal is a tier<=2 or human_confirmed edge on this
        // chunk.
        if e.tier <= 2 || e.method == "human_confirmed" {
            chunk_cosignal.insert(chunk_ref.clone(), true);
        }
        chunk_cosignal.entry(chunk_ref.clone()).or_insert(false);

        // Only Tier-3 (and confirmed) mentions produce a *tag*; the tag value is
        // the asserted canonical/entity ref (`other`).
        chunk_candidates
            .entry(chunk_ref.clone())
            .or_default()
            .insert(other.clone());
    }

    for (chunk_ref, candidates) in &chunk_candidates {
        // Namespace of the chunk mention → its config (governs auto_link_tier3).
        // Chunk mentions carry key_namespace on their evidence; fall back to "*".
        let ns = evidence
            .iter()
            .find(|e| {
                (is_chunk_ref(&e.left_ref) && &e.left_ref == chunk_ref)
                    || (is_chunk_ref(&e.right_ref) && &e.right_ref == chunk_ref)
            })
            .and_then(|e| e.key_namespace.clone())
            .unwrap_or_else(|| "*".to_string());
        let cfg = config.get("*", &ns);

        let cosignal = chunk_cosignal.get(chunk_ref).copied().unwrap_or(false);
        // Gate: auto_link_tier3 OR deterministic co-signal on the same chunk.
        let gate_open = cfg.auto_link_tier3 || cosignal;
        if !gate_open {
            continue; // reviewer-hint only; chunk stays as-is.
        }

        // §5 precondition (a), enforced fail-closed: only tag with canonicals
        // that are ALREADY FOLDED — present in `entity_aliases` (pre-existing or
        // produced this run). A mention NEVER invents a canonical or a merge.
        //   - `folded.contains(cand)`: the mention names a real canonical key
        //     that exists in `entity_aliases`.
        //   - a member ref (`source:entity_id`) whose OWN implicit singleton
        //     canonical is already materialized: eligible ONLY when a
        //     deterministic co-signal anchors it on this chunk (§5's "a real
        //     singleton canonical referenced by a member").
        // A bare `canon:*` the caller never folded is dropped (rule (a)).
        let mut tags: BTreeSet<String> = BTreeSet::new();
        for cand in candidates {
            if folded.contains(cand) {
                tags.insert(cand.clone());
            } else if let Some(m) = split_member_ref(cand) {
                let own = format!("canon:{}:{}", m.source, m.entity_id);
                // Own-canonical tag: allowed only when that singleton canonical
                // is already folded AND a deterministic co-signal is present.
                if cosignal && folded.contains(&own) {
                    tags.insert(own);
                }
            }
        }
        if tags.is_empty() {
            continue; // abstain → no tag (never zero-tag by force).
        }
        let mut tag_vec: Vec<String> = tags.into_iter().collect();
        tag_vec.sort();
        plan.chunk_tags.push(ChunkTagWrite {
            subject_ref: chunk_ref.clone(),
            tags: tag_vec.clone(),
        });
        // A chunk tag also gets an entity_link_meta badge (subject_kind =
        // chunk_tag) so the read path can show provenance.
        for t in &tag_vec {
            plan.link_meta.push(EntityLinkMeta {
                tenant_id: config.tenant_id,
                subject_kind: "chunk_tag".to_string(),
                subject_ref: chunk_ref.clone(),
                canonical_entity: t.clone(),
                confidence: if cfg.auto_link_tier3 && !cosignal {
                    "approximated".to_string()
                } else {
                    "deterministic".to_string()
                },
                strongest_method: Some("llm_mention".to_string()),
                justifying_evidence: chunk_tag_evidence(evidence, chunk_ref),
                evidence_count: 1,
            });
        }
    }
}

fn chunk_tag_evidence(evidence: &[&EvidenceRow], chunk_ref: &str) -> Vec<Uuid> {
    let mut ids: BTreeSet<Uuid> = BTreeSet::new();
    for e in evidence {
        if (is_chunk_ref(&e.left_ref) && e.left_ref == chunk_ref)
            || (is_chunk_ref(&e.right_ref) && e.right_ref == chunk_ref)
        {
            ids.insert(e.evidence_id);
        }
    }
    ids.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Union-find (deterministic; string refs).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct UnionFind {
    parent: BTreeMap<String, String>,
}

impl UnionFind {
    fn touch(&mut self, x: &str) {
        self.parent
            .entry(x.to_string())
            .or_insert_with(|| x.to_string());
    }

    fn find_root(&self, x: &str) -> String {
        let mut cur = x.to_string();
        loop {
            match self.parent.get(&cur) {
                Some(p) if p != &cur => cur = p.clone(),
                _ => return cur,
            }
        }
    }

    fn union(&mut self, x: &str, y: &str) {
        self.touch(x);
        self.touch(y);
        let rx = self.find_root(x);
        let ry = self.find_root(y);
        if rx == ry {
            return;
        }
        // Point the lexicographically LARGER root at the smaller — deterministic,
        // independent of union order, so the component root is canonical.
        let (small, large) = if rx <= ry { (rx, ry) } else { (ry, rx) };
        self.parent.insert(large, small);
    }

    fn members(&self) -> Vec<String> {
        self.parent.keys().cloned().collect()
    }
}

// ===========================================================================
// TESTS — the security proof (§6). All PURE: no DB, no clock, no network.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn tenant() -> TenantId {
        Uuid::from_u128(0x1111_1111_1111_1111_1111_1111_1111_1111)
    }

    /// Build a live evidence row. `ev_seq` makes the evidence_id deterministic
    /// and orderable so tests are reproducible.
    #[allow(clippy::too_many_arguments)]
    fn ev(
        ev_seq: u128,
        left: &str,
        right: &str,
        tier: i16,
        method: &str,
        key_value: Option<&str>,
        key_namespace: Option<&str>,
        polarity: i16,
    ) -> EvidenceRow {
        EvidenceRow {
            evidence_id: Uuid::from_u128(0xE000_0000_0000_0000_0000_0000_0000_0000 + ev_seq),
            tenant_id: tenant(),
            left_ref: left.to_string(),
            right_ref: right.to_string(),
            tier,
            method: method.to_string(),
            key_value: key_value.map(|s| s.to_string()),
            key_namespace: key_namespace.map(|s| s.to_string()),
            score: if tier == 1 { None } else { Some(0.9) },
            evidence_l0_ref: Some(format!("l0:{ev_seq}")),
            polarity,
            valid_from: ts(ev_seq as i64),
            valid_to: None,
            superseded_by: None,
        }
    }

    /// Strong Tier-1 edge (crm_fk) — satisfies min_independent_keys alone.
    fn strong(ev_seq: u128, left: &str, right: &str) -> EvidenceRow {
        ev(
            ev_seq,
            left,
            right,
            1,
            "crm_fk",
            None,
            Some("customer_contact"),
            1,
        )
    }

    /// Lone domain edge (MEDIUM, single key) between two accounts.
    fn domain(ev_seq: u128, left: &str, right: &str, dom: &str) -> EvidenceRow {
        ev(
            ev_seq,
            left,
            right,
            1,
            "domain_match",
            Some(dom),
            Some("customer_contact"),
            1,
        )
    }

    fn cfg_defaults() -> FoldConfig {
        FoldConfig::defaults(tenant())
    }

    /// A config with a cap and explicit per-key rows.
    fn cfg_with(cap: Option<i32>, min_keys: i16, auto_tier3: bool) -> FoldConfig {
        let mut fb = EntityResolutionConfig::defaults(tenant(), "*", "*");
        fb.component_size_cap = cap;
        fb.min_independent_keys = min_keys;
        fb.auto_link_tier3 = auto_tier3;
        let mut domain_rule =
            EntityResolutionConfig::defaults(tenant(), "domain", "customer_contact");
        domain_rule.min_independent_keys = min_keys;
        FoldConfig::new(tenant(), vec![domain_rule], fb)
    }

    // ---- Invariant 1: determinism (same input → identical output). ----
    #[test]
    fn fold_is_deterministic() {
        let evs = vec![
            strong(1, "salesforce:A", "hubspot:B"),
            strong(2, "hubspot:B", "linear:C"),
            domain(3, "salesforce:A", "hubspot:B", "acme.com"),
        ];
        let cfg = cfg_defaults();
        let p1 = fold(&evs, &cfg);
        // Feed a permuted copy: output must be identical.
        let mut permuted = evs.clone();
        permuted.reverse();
        let p2 = fold(&permuted, &cfg);
        assert_eq!(p1, p2, "fold must be order-independent + deterministic");
    }

    // ---- Invariant 2: idempotence (fold∘fold-shaped: re-running is stable). ----
    #[test]
    fn fold_is_idempotent_under_repeat() {
        let evs = vec![strong(1, "salesforce:A", "hubspot:B")];
        let cfg = cfg_defaults();
        let a = fold(&evs, &cfg);
        let b = fold(&evs, &cfg);
        assert_eq!(a, b);
        // Two members merged → one canonical, two alias writes, no review.
        assert_eq!(a.aliases.len(), 2);
        assert!(a.review.is_empty());
        assert_eq!(a.canonicals.len(), 1);
        // Canonical is stable = smallest member.
        assert_eq!(a.aliases[0].canonical_entity, "canon:hubspot:B");
    }

    // ---- Invariant 3: retract-one-row → re-fold SPLITS the component. ----
    #[test]
    fn retract_one_edge_splits_component() {
        // A—B—C chained by two strong edges. Both live → one component of 3.
        let full = vec![
            strong(1, "salesforce:A", "hubspot:B"),
            strong(2, "hubspot:B", "linear:C"),
        ];
        let cfg = cfg_defaults();
        let whole = fold(&full, &cfg);
        assert_eq!(whole.canonicals.len(), 1);
        assert_eq!(whole.aliases.len(), 3);

        // Simulate retraction of the B—C edge: the fold sees only the A—B edge.
        let after = vec![strong(1, "salesforce:A", "hubspot:B")];
        let split = fold(&after, &cfg);
        // C is now its own (implicit) canonical: only A,B written.
        assert_eq!(split.aliases.len(), 2);
        assert!(split
            .aliases
            .iter()
            .all(|a| a.entity_id == "A" || a.entity_id == "B"));
        assert!(!split.aliases.iter().any(|a| a.entity_id == "C"));
    }

    // ---- Invariant 4: anti-links win, permanently. ----
    #[test]
    fn anti_link_blocks_and_quarantines() {
        // Positive strong edge A—B, but a human anti-link says NOT the same.
        let evs = vec![
            strong(1, "salesforce:A", "hubspot:B"),
            ev(
                2,
                "salesforce:A",
                "hubspot:B",
                1,
                "human_rejected",
                None,
                Some("customer_contact"),
                -1,
            ),
        ];
        let cfg = cfg_defaults();
        let p = fold(&evs, &cfg);
        // No merge: the pair is quarantined to review, no alias written.
        assert!(p.aliases.is_empty(), "anti-link must block the merge");
        assert!(p
            .review
            .iter()
            .any(|r| matches!(r.reason, ReviewReason::AntiLinkSplit)));
    }

    #[test]
    fn anti_link_survives_extra_positive_evidence() {
        // Pile positive evidence; the anti-link still wins (permanence).
        let evs = vec![
            strong(1, "salesforce:A", "hubspot:B"),
            strong(2, "salesforce:A", "hubspot:B"),
            domain(3, "salesforce:A", "hubspot:B", "acme.com"),
            ev(
                4,
                "salesforce:A",
                "hubspot:B",
                1,
                "human_rejected",
                None,
                Some("customer_contact"),
                -1,
            ),
        ];
        let p = fold(&evs, &cfg_defaults());
        assert!(p.aliases.is_empty());
        assert!(p
            .review
            .iter()
            .any(|r| matches!(r.reason, ReviewReason::AntiLinkSplit)));
    }

    // ---- Invariant 5: min_independent_keys blocks a lone-domain merge. ----
    #[test]
    fn lone_domain_does_not_auto_merge() {
        // Single shared domain between two accounts, min_independent_keys=2.
        let evs = vec![domain(1, "salesforce:A", "hubspot:B", "acme.com")];
        let cfg = cfg_with(None, 2, false);
        let p = fold(&evs, &cfg);
        assert!(
            p.aliases.is_empty(),
            "a lone MEDIUM domain must NOT auto-merge two accounts"
        );
    }

    #[test]
    fn lone_domain_plus_second_key_merges() {
        // Domain + an independent strong key → clears the bar → merges.
        let evs = vec![
            domain(1, "salesforce:A", "hubspot:B", "acme.com"),
            ev(
                2,
                "salesforce:A",
                "hubspot:B",
                1,
                "external_id",
                Some("XID-1"),
                Some("customer_contact"),
                1,
            ),
        ];
        let cfg = cfg_with(None, 2, false);
        let p = fold(&evs, &cfg);
        assert_eq!(p.aliases.len(), 2, "second independent key clears the bar");
    }

    // ---- Invariant 6: namespace fence (§4.4). ----
    #[test]
    fn namespace_fence_refuses_cross_population_edge() {
        // internal_directory email (an employee) must not weld to a
        // customer_contact account. We model that as a config where the
        // internal_directory email key is NOT eligible_as_edge.
        let mut fb = EntityResolutionConfig::defaults(tenant(), "*", "*");
        let mut internal =
            EntityResolutionConfig::defaults(tenant(), "email", "internal_directory");
        internal.eligible_as_edge = false;
        fb.min_independent_keys = 1;
        let cfg = FoldConfig::new(tenant(), vec![internal], fb);

        let evs = vec![ev(
            1,
            "linear:jane",
            "salesforce:ACME",
            1,
            "email_exact",
            Some("jane@acme.dev"),
            Some("internal_directory"),
            1,
        )];
        let p = fold(&evs, &cfg);
        assert!(
            p.aliases.is_empty(),
            "internal_directory email must not form an edge to a customer account"
        );
    }

    #[test]
    fn same_namespace_email_merges() {
        let mut fb = EntityResolutionConfig::defaults(tenant(), "*", "*");
        fb.min_independent_keys = 1;
        let cfg = FoldConfig::new(tenant(), vec![], fb);
        let evs = vec![ev(
            1,
            "salesforce:P1",
            "hubspot:P2",
            1,
            "email_exact",
            Some("jane@acme.com"),
            Some("customer_contact"),
            1,
        )];
        let p = fold(&evs, &cfg);
        assert_eq!(p.aliases.len(), 2, "same-namespace exact email merges");
    }

    // ---- Invariant 7: component_size_cap quarantines runaway clusters. ----
    #[test]
    fn size_cap_quarantines_mega_cluster() {
        // Chain 5 members with strong edges; cap = 3.
        let evs = vec![
            strong(1, "s:A", "s:B"),
            strong(2, "s:B", "s:C"),
            strong(3, "s:C", "s:D"),
            strong(4, "s:D", "s:E"),
        ];
        let cfg = cfg_with(Some(3), 1, false);
        let p = fold(&evs, &cfg);
        assert!(
            p.aliases.is_empty(),
            "a component over the size cap must not merge"
        );
        assert!(p
            .review
            .iter()
            .any(|r| matches!(r.reason, ReviewReason::SizeCapExceeded { size: 5, cap: 3 })));
    }

    #[test]
    fn under_cap_merges() {
        let evs = vec![strong(1, "s:A", "s:B"), strong(2, "s:B", "s:C")];
        let cfg = cfg_with(Some(3), 1, false);
        let p = fold(&evs, &cfg);
        assert_eq!(p.aliases.len(), 3);
        assert!(p.review.is_empty());
    }

    // ---- Invariant 8: Tier-3 alone NEVER merges. ----
    #[test]
    fn tier3_alone_never_merges() {
        // A Tier-3 mention between two member refs must not weld them.
        let evs = vec![ev(
            1,
            "salesforce:A",
            "hubspot:B",
            3,
            "llm_mention",
            Some("Acme"),
            Some("customer_contact"),
            1,
        )];
        let p = fold(&evs, &cfg_defaults());
        assert!(
            p.aliases.is_empty(),
            "Tier-3 evidence must never on its own form a merge edge"
        );
    }

    #[test]
    fn tier3_mention_tags_only_with_cosignal() {
        // Tier-3 mention on a chunk, PLUS a deterministic co-signal (a tier-1
        // edge on the same chunk to the same canonical). Gate opens → tag.
        let evs = vec![
            // The account itself was folded (two members merge).
            strong(1, "salesforce:A", "hubspot:B"),
            // A chunk mentions the canonical; tier-1 ACL co-signal present.
            ev(
                2,
                "chunk:gdrive:D9:0",
                "canon:hubspot:B",
                1,
                "domain_match",
                Some("acme.com"),
                Some("customer_contact"),
                1,
            ),
            ev(
                3,
                "chunk:gdrive:D9:0",
                "canon:hubspot:B",
                3,
                "llm_mention",
                Some("Acme"),
                Some("customer_contact"),
                1,
            ),
        ];
        let cfg = cfg_with(None, 1, false);
        let p = fold(&evs, &cfg);
        assert!(
            p.chunk_tags
                .iter()
                .any(|t| t.subject_ref == "chunk:gdrive:D9:0"
                    && t.tags.contains(&"canon:hubspot:B".to_string())),
            "co-signal present → chunk tagged"
        );
    }

    #[test]
    fn tier3_mention_abstains_without_cosignal() {
        // Tier-3 mention only, auto_link_tier3=false, no co-signal → no tag.
        let evs = vec![ev(
            1,
            "chunk:linear:ENG-42:0",
            "canon:hubspot:B",
            3,
            "llm_mention",
            Some("Acme"),
            Some("customer_contact"),
            1,
        )];
        let cfg = cfg_with(None, 1, false);
        let p = fold(&evs, &cfg);
        assert!(
            p.chunk_tags.is_empty(),
            "no co-signal + auto_link off → abstain (reviewer-hint only, no tag)"
        );
    }

    // ---- §5 precondition (a): a co-signalled mention of a canonical that is NOT
    // already folded (absent from entity_aliases + not merged this run) must NOT
    // tag — until the caller supplies it as a known/pre-existing canonical. ----
    #[test]
    fn tier3_mention_requires_already_folded_canonical() {
        // A chunk carries BOTH a deterministic co-signal (tier-1 ACL edge) and a
        // Tier-3 mention, all pointing at `canon:hubspot:B` — but nothing folds
        // `canon:hubspot:B` this run (no member↔member merge produces it) and it
        // is not pre-existing. Co-signal alone must not conjure the tag.
        let evs = vec![
            ev(
                1,
                "chunk:gdrive:D9:0",
                "canon:hubspot:B",
                1,
                "domain_match",
                Some("acme.com"),
                Some("customer_contact"),
                1,
            ),
            ev(
                2,
                "chunk:gdrive:D9:0",
                "canon:hubspot:B",
                3,
                "llm_mention",
                Some("Acme"),
                Some("customer_contact"),
                1,
            ),
        ];
        let cfg = cfg_with(None, 1, false);

        // Plain fold: `canon:hubspot:B` is not folded this run and not known →
        // precondition (a) fails → no tag, even with the co-signal.
        let p = fold(&evs, &cfg);
        assert!(
            p.chunk_tags.is_empty(),
            "co-signal without an already-folded canonical must NOT tag (rule a)"
        );

        // Same evidence, but the caller supplies `canon:hubspot:B` as an
        // ALREADY-FOLDED canonical (read from entity_aliases in the worker) →
        // both preconditions met → tag materializes.
        let known = KnownCanonicals::new(["canon:hubspot:B"], std::iter::empty());
        let p2 = fold_with_known_canonicals(&evs, &cfg, &known);
        assert!(
            p2.chunk_tags
                .iter()
                .any(|t| t.subject_ref == "chunk:gdrive:D9:0"
                    && t.tags.contains(&"canon:hubspot:B".to_string())),
            "already-folded (known) canonical + co-signal → tag materializes"
        );
    }

    // ---- Key-node fan-out: a domain shared by 3 accounts surfaces for review. ----
    #[test]
    fn key_fanout_surfaces_for_review() {
        // Three accounts all sharing key-node key:domain:acme.com via MEDIUM keys.
        let evs = vec![
            ev(
                1,
                "key:domain:acme.com",
                "salesforce:A",
                1,
                "domain_match",
                Some("acme.com"),
                Some("customer_contact"),
                1,
            ),
            ev(
                2,
                "key:domain:acme.com",
                "hubspot:B",
                1,
                "domain_match",
                Some("acme.com"),
                Some("customer_contact"),
                1,
            ),
            ev(
                3,
                "key:domain:acme.com",
                "linear:C",
                1,
                "domain_match",
                Some("acme.com"),
                Some("customer_contact"),
                1,
            ),
        ];
        let cfg = cfg_with(None, 2, false);
        let p = fold(&evs, &cfg);
        assert!(
            p.review
                .iter()
                .any(|r| matches!(&r.reason, ReviewReason::KeyFanOut { members: 3, .. })),
            "a domain fanning out to 3 accounts must surface, not silently weld"
        );
        // And it must NOT have auto-merged all three.
        assert!(
            p.aliases.is_empty(),
            "fanned-out key must not weld distinct accounts"
        );
    }

    // ---- Incremental drift guard: fusing two existing large clusters → review. ----
    #[test]
    fn incremental_drift_routes_large_fusion_to_review() {
        // A new fuzzy (below-tier1) human_confirmed-less edge that would fuse two
        // pre-existing canonicals, one of which is "large".
        let evs = vec![domain(1, "salesforce:A", "hubspot:B", "shared.com")];
        let cfg = cfg_with(None, 1, false); // domain alone can merge here.
        let mut prior = BTreeMap::new();
        prior.insert("salesforce:A".to_string(), "canon:old:left".to_string());
        prior.insert("hubspot:B".to_string(), "canon:old:right".to_string());
        let mut sizes = BTreeMap::new();
        sizes.insert("canon:old:left".to_string(), 50usize);
        sizes.insert("canon:old:right".to_string(), 3usize);

        let p = refold_incremental(&evs, &cfg, &prior, &sizes, 10);
        assert!(
            p.review
                .iter()
                .any(|r| matches!(r.reason, ReviewReason::ClusterDrift { .. })),
            "fusing a large pre-existing cluster must route to review"
        );
        assert!(
            p.aliases.is_empty(),
            "the silently-fusing component's writes must be withdrawn"
        );
    }

    #[test]
    fn incremental_strong_fusion_of_small_clusters_proceeds() {
        // A Tier-1 (deterministic) fusion of two SMALL prior clusters proceeds.
        let evs = vec![strong(1, "salesforce:A", "hubspot:B")];
        let cfg = cfg_with(None, 1, false);
        let mut prior = BTreeMap::new();
        prior.insert("salesforce:A".to_string(), "canon:old:left".to_string());
        prior.insert("hubspot:B".to_string(), "canon:old:right".to_string());
        let mut sizes = BTreeMap::new();
        sizes.insert("canon:old:left".to_string(), 1usize);
        sizes.insert("canon:old:right".to_string(), 1usize);
        let p = refold_incremental(&evs, &cfg, &prior, &sizes, 10);
        // Deterministic (Tier-1) + both small → allowed to join.
        assert_eq!(
            p.aliases.len(),
            2,
            "strong fusion of small clusters proceeds"
        );
        assert!(p
            .review
            .iter()
            .all(|r| !matches!(r.reason, ReviewReason::ClusterDrift { .. })));
    }

    // ---- Ref parsing edge cases. ----
    #[test]
    fn ref_parsing_splits_and_rejects() {
        assert_eq!(
            split_member_ref("salesforce:001xACME"),
            Some(MemberRef {
                source: "salesforce".into(),
                entity_id: "001xACME".into()
            })
        );
        // entity_id containing a colon survives (split on first ':').
        assert_eq!(
            split_member_ref("gdrive:folder:file"),
            Some(MemberRef {
                source: "gdrive".into(),
                entity_id: "folder:file".into()
            })
        );
        assert_eq!(split_member_ref("key:domain:acme.com"), None);
        assert_eq!(split_member_ref("chunk:gdrive:D9:0"), None);
        assert_eq!(split_member_ref("bareword"), None);
        assert_eq!(split_member_ref(":empty"), None);
        assert_eq!(
            parse_chunk_ref("chunk:gdrive:D9:0"),
            Some(("gdrive".into(), "D9".into(), 0))
        );
        assert_eq!(
            parse_chunk_ref("chunk:gdrive:a:b:5"),
            Some(("gdrive".into(), "a:b".into(), 5))
        );
        assert_eq!(parse_chunk_ref("chunk:gdrive:D9:notanum"), None);
    }

    // ---- Fuzz-style property test: no anti-linked pair ever ends up merged. ----
    #[test]
    fn property_anti_linked_pairs_never_co_merge() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let refs = ["s:A", "s:B", "s:C", "s:D", "s:E"];
        for seed in 0..500u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut evs: Vec<EvidenceRow> = Vec::new();
            let mut anti: Vec<(usize, usize)> = Vec::new();
            let n = rng.random_range(1..=8);
            for k in 0..n {
                let i = rng.random_range(0..refs.len());
                let mut j = rng.random_range(0..refs.len());
                if i == j {
                    j = (j + 1) % refs.len();
                }
                let polarity = if rng.random_bool(0.25) { -1 } else { 1 };
                if polarity < 0 {
                    anti.push((i.min(j), i.max(j)));
                    evs.push(ev(
                        k as u128,
                        refs[i],
                        refs[j],
                        1,
                        "human_rejected",
                        None,
                        Some("customer_contact"),
                        -1,
                    ));
                } else {
                    evs.push(strong(k as u128, refs[i], refs[j]));
                }
            }
            let cfg = cfg_with(None, 1, false);
            let p = fold(&evs, &cfg);
            // Build canonical->members from the plan; assert no anti-linked pair
            // shares a canonical.
            let mut canon_of: BTreeMap<String, String> = BTreeMap::new();
            for a in &p.aliases {
                canon_of.insert(
                    format!("{}:{}", a.source, a.entity_id),
                    a.canonical_entity.clone(),
                );
            }
            for (i, j) in &anti {
                let ri = refs[*i];
                let rj = refs[*j];
                if let (Some(ci), Some(cj)) = (canon_of.get(ri), canon_of.get(rj)) {
                    assert_ne!(
                        ci, cj,
                        "seed {seed}: anti-linked {ri}/{rj} were co-merged into {ci}"
                    );
                }
            }
        }
    }

    // ---- Determinism property test over random inputs. ----
    #[test]
    fn property_fold_deterministic_over_random_inputs() {
        use rand::rngs::StdRng;
        use rand::seq::SliceRandom;
        use rand::{Rng, SeedableRng};

        let refs = ["s:A", "s:B", "s:C", "hubspot:X", "linear:Y"];
        let methods = ["crm_fk", "domain_match", "external_id", "email_exact"];
        for seed in 0..300u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut evs: Vec<EvidenceRow> = Vec::new();
            let n = rng.random_range(1..=10);
            for k in 0..n {
                let i = rng.random_range(0..refs.len());
                let j = (i + 1 + rng.random_range(0..refs.len() - 1)) % refs.len();
                let m = methods[rng.random_range(0..methods.len())];
                evs.push(ev(
                    k as u128,
                    refs[i],
                    refs[j],
                    1,
                    m,
                    Some("acme.com"),
                    Some("customer_contact"),
                    1,
                ));
            }
            let cfg = cfg_with(Some(4), 1, false);
            let p1 = fold(&evs, &cfg);
            let mut shuffled = evs.clone();
            shuffled.shuffle(&mut rng);
            let p2 = fold(&shuffled, &cfg);
            assert_eq!(p1, p2, "seed {seed}: fold not order-invariant");
        }
    }
}
