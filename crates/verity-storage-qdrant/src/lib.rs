//! SCALE profile (SPEC §3): Qdrant behind the `StorageAdapter` trait.
//!
//! This is a **HYBRID profile**, documented as such per SPEC §3's storage-engine
//! split:
//!
//! - **Chunks (the serving-tier retrieval units) live in Qdrant** — one
//!   collection per tenant (`verity_<tenant>`, physical isolation per the §3
//!   tenant model), 384-d cosine vectors, scope metadata (visibility tokens,
//!   entity tags, confidentiality, kind, validity interval, provenance) as
//!   payload with payload indexes, so scope filters are filter-aware-HNSW
//!   pre-filters — never post-hoc truncation.
//! - **Everything else — tenants, the L0 episode log, bi-temporal L1 facts,
//!   action records, and the knowledge lifecycle — delegates to an inner
//!   [`verity_storage::PostgresAdapter`]**. Postgres stays the transactional
//!   system of record (SPEC §3 "durable tier"); Qdrant is the serving index
//!   for dense retrieval at scale.
//! - **Hybrid recall**: the dense leg runs in Qdrant (filtered ANN); the text
//!   leg (BM25) delegates to the inner Postgres adapter's pg_search path; the
//!   two lists are RRF-fused locally. Chunks are therefore dual-written:
//!   Qdrant carries the vector + scope payload, Postgres carries the text for
//!   BM25 (and the durable lineage row).
//!
//! The scope contract (visibility intersection, entity-tag subset semantics
//! with the §7g knowledge carve-out, confidentiality ceiling, fail-closed
//! empty principal sets, invalidate-don't-delete) mirrors the Postgres
//! profile exactly; the scope-soundness fuzzer in `tests/scope_fuzz.rs` probes
//! this profile with the same adversarial corpus.

mod qdrant;

pub use qdrant::{chunk_point, collection_name, point_id, ChunkRow, QdrantAdapter};
