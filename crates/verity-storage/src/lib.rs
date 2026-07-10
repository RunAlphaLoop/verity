//! Postgres profile: pgvector (dense) + pg_search/Tantivy (BM25) behind the
//! `StorageAdapter` trait. SPEC §3 — the default adoption profile, honest
//! ceiling ~5–10M vectors per deployment.

mod cache;
mod postgres;

pub use cache::CachedAdapter;
pub use postgres::PostgresAdapter;
