//! Verity core: the bi-temporal memory model and the `StorageAdapter` seam.
//!
//! SPEC.md §2 defines the four layers; Milestone A implements L0 (episodes),
//! L1 (facts), and the chunk store. Enforcement invariants (fail-closed
//! visibility, deterministic supersession) are encoded in these types and in
//! the adapter contract — adapters must not weaken them.

pub mod adapter;
pub mod types;

pub use adapter::StorageAdapter;
pub use types::*;
