//! Cross-source entity resolution — S0 (canonicalize) + S1 (Tier-1 exact-key
//! producers). **Deterministic, no LLM, no similarity.** This is the OSS-default
//! cascade's first two stages
//! (`docs/design/cross-source-entity-resolution.md` §4.2 S0/S1).
//!
//! Everything here runs in the **ingestion / worker plane**, never on the read
//! path: it *produces* rows for the append-only `entity_evidence` ledger that
//! the deterministic fold (S4, another crate) reads to materialize
//! `entity_aliases` + chunk `entity_tags` + `entity_link_meta`. Nothing in this
//! module is called at recall/`get` time.
//!
//! ## Layout
//! - [`canon`] — S0. Pure, side-effect-free key/ref canonicalizers (email,
//!   domain, Salesforce `Website` URL, phone, name) + the denylist and the
//!   `key_namespace` stamp (the §4.4 actor-email population fence). Richly
//!   unit-tested inline; no DB, no I/O.
//! - [`producers`] — S1. Given a tenant's current L1 facts (as plain input
//!   records, for testability), emit `tier=1` [`EvidenceWrite`] rows for:
//!   intra-CRM FK (exact), exact email person↔person *within a namespace*, and
//!   exact `external_id` crosswalk. Also a thin storage-backed driver that
//!   consults `read_resolution_config` (denylist / `eligible_as_edge`) before
//!   `insert_evidence`.
//!
//! ## Design posture (§3.2 precision-as-security)
//! A false merge is a *scope leak*, so every canonicalizer **fails closed**: an
//! unparseable / denylisted / role-based / free-mail value returns `None` and
//! never becomes a key, and the namespace fence forbids an edge from ever
//! crossing `internal_directory` ↔ `customer_contact`. Producers emit evidence;
//! whether that evidence *auto-merges* is the fold's decision (subject to
//! `min_independent_keys`), never a producer's.

pub mod canon;
pub mod fold;
pub mod producers;

pub use canon::{
    canonicalize_domain, canonicalize_email, canonicalize_name, canonicalize_phone,
    canonicalize_website_domain, is_denylisted, CanonKey, KeyNamespace,
};
pub use producers::{
    deterministic_evidence_id, produce_tier1_evidence, tier1_crm_fk_evidence,
    tier1_email_within_namespace_evidence, tier1_external_id_evidence, CrmContactFact, EmailFact,
    ExternalIdFact, Tier1Producers,
};

// S4 — the pure deterministic fold (§4.2). Consumes live evidence produced by
// S0/S1 above, materializes canonical membership + chunk tags + badges.
pub use fold::{
    fold, parse_chunk_ref, refold_incremental, split_member_ref, AliasWrite, ChunkTagWrite,
    FoldConfig, FoldPlan, MemberRef, ReviewItem, ReviewReason,
};
