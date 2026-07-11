//! Tier-3 mention → chunk-tag eligibility (the co-signal / human rule).
//!
//! `docs/design/cross-source-entity-resolution.md` §5 (the load-bearing rule)
//! and §4.2 step 3 (Tier-3 NEVER forms an edge). This is the *pure* half of the
//! §5 rule that the fold (`fold.rs`) applies; it lives in its own file so the
//! "already folded (exists in `entity_aliases`)" precondition is explicit and
//! independently testable.
//!
//! ## The rule, restated (§5)
//! A Tier-3 mention of `Acme` in a chunk becomes an `entity_tags` value on that
//! chunk **only if**:
//!   (a) the mentioned canonical is **already folded** — i.e. it exists in
//!       `entity_aliases` (a higher tier merged it, in this run or a prior one)
//!       or it is a real, already-materialized singleton canonical — **AND**
//!   (b) either a **deterministic co-signal is present on the same chunk** (a
//!       live Tier-1/Tier-2 or `human_confirmed` edge anchoring that chunk to
//!       the canonical — e.g. the chunk/ACL carries the account's verified
//!       domain) **OR** a human approved it.
//!
//! Neither half alone is enough. Tier-3 never forms a merge edge and never
//! widens a scope; the tag only *narrows* retrievability under §7c intersection
//! semantics. Abstain → **no tag** (never the zero-tag broad bucket by force).
//!
//! ## Why "already folded" needs a DB read, and how purity is preserved
//! The pure [`fold`](crate::resolve::fold) has NO database access, so it cannot
//! by itself know whether a mentioned canonical exists in `entity_aliases` from
//! a *prior* fold or an admin crosswalk POST — it only knows the canonicals it
//! merged in the *current* run (`FoldPlan::canonicals`). "Already folded" is
//! therefore threaded in as an explicit, plain-data input
//! ([`KnownCanonicals`]): the impure materializer (`verity-server`'s
//! `run_full_fold`) reads the pre-existing canonical set via the reused
//! `list_canonical_entities` storage method and hands it to the fold. The read
//! path is untouched and the fold stays a total function of its inputs — the DB
//! read happens in the worker plane, never at recall/`get` time.

use std::collections::BTreeSet;

/// The set of canonicals a Tier-3 mention is allowed to tag: those already
/// materialized in `entity_aliases` (read in the worker plane by the caller),
/// unioned with those the *current* fold run just produced. Plain owned data so
/// the fold stays pure and this stays trivially testable.
#[derive(Debug, Clone, Default)]
pub struct KnownCanonicals {
    set: BTreeSet<String>,
}

impl KnownCanonicals {
    /// Build from the pre-existing `entity_aliases` canonicals (what the caller
    /// read via `list_canonical_entities`) plus this run's freshly-folded
    /// canonicals. Both are canonical keys (`canon:<source>:<entity_id>` /
    /// `account:acme` etc.).
    pub fn new<'a>(
        preexisting: impl IntoIterator<Item = &'a str>,
        this_run: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut set: BTreeSet<String> = BTreeSet::new();
        set.extend(preexisting.into_iter().map(str::to_string));
        set.extend(this_run.into_iter().map(str::to_string));
        Self { set }
    }

    /// An empty known-set: the strictest fail-closed posture. With no known
    /// canonicals, the ONLY canonicals a mention can tag are those the current
    /// fold run produced (the fold adds those itself). Used by the plain
    /// [`fold`](crate::resolve::fold) wrapper so existing callers are unchanged.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Return a copy of this set unioned with the canonicals the *current* fold
    /// run just produced. The fold calls this so a mention may tag a canonical
    /// that is either pre-existing in `entity_aliases` (this set) or freshly
    /// folded this run. Non-mutating so the caller's set is reusable.
    pub fn with_this_run<'a>(&self, this_run: impl IntoIterator<Item = &'a str>) -> Self {
        let mut set = self.set.clone();
        set.extend(this_run.into_iter().map(str::to_string));
        Self { set }
    }

    /// Precondition (a) of the §5 rule: is this canonical already folded — i.e.
    /// does it exist in `entity_aliases` (pre-existing or produced this run)?
    /// Fail-closed: an unknown canonical returns `false`, so a Tier-3 mention of
    /// an un-folded entity can NEVER, on its own, invent a tag for it.
    pub fn contains(&self, canonical: &str) -> bool {
        self.set.contains(canonical)
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_of_preexisting_and_this_run() {
        let k = KnownCanonicals::new(["canon:hubspot:B"], ["account:acme"]);
        assert!(k.contains("canon:hubspot:B"), "pre-existing alias counts");
        assert!(k.contains("account:acme"), "this-run canonical counts");
        assert!(!k.contains("account:other"), "unknown fails closed");
    }

    #[test]
    fn empty_is_fail_closed() {
        let k = KnownCanonicals::empty();
        assert!(k.is_empty());
        assert!(!k.contains("account:acme"));
    }
}
