//! Source manifests v1 (SPEC §5e.3): connectors are config.
//!
//! A source manifest is a YAML file executed by the Rust ingest runtime —
//! data, not code: reviewable, diffable, registry-hostable with zero
//! supply-chain code execution. This crate owns the schema, the mapping
//! evaluator, the routing predicates, webhook signature verification, the
//! payload→writes runtime, and the fixture conformance harness that ships
//! WITH the format.
//!
//! # Mapping-language decision (v1): the Verity dot-path subset
//!
//! SPEC §5e.3 names JSONata as the target dialect, evaluated by a pure-Rust
//! engine, with an explicit fallback: "a Verity-defined subset". Surveyed
//! July 2026:
//!
//! - `jsonata-rs` (Stedi): self-described alpha — passes ~800 of the >1,000
//!   reference tests, documented to "panic in unexpected places", unstable
//!   API. A panicking evaluator inside the fail-closed write path is
//!   disqualifying.
//! - `jsonata-core`: full reference-test conformance, but a single-maintainer
//!   dependency of ~183K lines (simd-json, stacker, regex) with no built-in
//!   evaluator resource limits. JSONata permits recursion, so SPEC makes
//!   wall-time/depth/output caps mandatory — they would have to be bolted on
//!   around a foreign evaluator. SPEC schedules validating this crate as its
//!   own spike, off the critical path.
//!
//! v1 therefore ships the documented fallback: a **dot-path subset**
//! (`data.title`, `data.labels[0].name`, `data.team.members[].id`, `$now()`)
//! plus a routing predicate grammar of simple comparisons and `in` over
//! dot-paths. No recursion, no user-defined functions, no eval — every
//! expression is parsed once at manifest validation and evaluated by a
//! bounded interpreter. Hard limits (expression length, path depth, payload
//! depth, output size) are enforced regardless, per SPEC. The `map:` keys are
//! declared per-manifest and the dialect can grow toward JSONata without
//! breaking existing manifests (every dot-path is valid JSONata).
//!
//! # Fail-closed contract
//!
//! - `acl_policy` absent ⇒ parse OK, activation refused, runtime quarantines.
//! - `map`-mode principal extraction failing or empty ⇒ quarantine.
//! - A declared mapping path missing from the payload ⇒ the whole payload
//!   quarantines — never a partial/mis-filed write.
//! - No route matching ⇒ quarantine.
//!
//! # Poll block
//!
//! `poll:` is parse-and-store only in v0: the schema validates it and the
//! server persists it with the manifest, but no poll executor exists yet
//! (SPEC §5e.7 places the reconciliation loop in v0.3+). Webhook delivery is
//! the only execution lane this crate drives today.

pub mod conformance;
pub mod path;
pub mod predicate;
pub mod runtime;
pub mod schema;
pub mod signature;

pub use conformance::{run_manifest_fixtures, FixtureOutcome};
pub use runtime::{AclEnvelope, Applied, EntityWrites, RuntimeOptions};
pub use schema::{AclMode, IdentityNamespace, Manifest, ManifestError, Tier};
pub use signature::{resolve_secret_ref, verify_hmac_sha256_hex};

/// Hard evaluator limits (SPEC §5e.3: "Hard evaluator limits regardless").
pub mod limits {
    /// Maximum manifest YAML size accepted for parsing.
    pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
    /// Maximum entity blocks per manifest.
    pub const MAX_ENTITIES: usize = 64;
    /// Maximum mapped fields per entity.
    pub const MAX_MAP_FIELDS: usize = 128;
    /// Maximum characters in one mapping/predicate expression.
    pub const MAX_EXPR_CHARS: usize = 512;
    /// Maximum dot-path segments per expression.
    pub const MAX_PATH_SEGMENTS: usize = 32;
    /// Maximum literal array index (`[n]`).
    pub const MAX_ARRAY_INDEX: usize = 10_000;
    /// Maximum nesting depth of an inbound payload.
    pub const MAX_PAYLOAD_DEPTH: usize = 64;
    /// Maximum serialized size of one mapped value.
    pub const MAX_VALUE_BYTES: usize = 64 * 1024;
    /// Maximum total serialized output per payload.
    pub const MAX_OUTPUT_BYTES: usize = 512 * 1024;
    /// Maximum principals extracted per payload in `map` mode.
    pub const MAX_PRINCIPALS: usize = 1_024;
}
