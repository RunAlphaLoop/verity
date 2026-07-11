//! Postgres profile: pgvector (dense) + pg_search/Tantivy (BM25) behind the
//! `StorageAdapter` trait. SPEC §3 — the default adoption profile, honest
//! ceiling ~5–10M vectors per deployment.

mod cache;
mod crypto;
mod erasure;
mod postgres;
pub mod resolve;

pub use cache::CachedAdapter;
pub use crypto::Kek;
pub use erasure::{CoverageGaps, ErasurePreview, ErasureReport};
pub use postgres::PostgresAdapter;
pub use resolve::{fold, refold_incremental, FoldConfig, FoldPlan, DEFAULT_LARGE_COMPONENT_FLOOR};
