# Verity — agent working notes

Verity is an open-source, permission-aware shared memory plane for enterprise AI agents. **SPEC.md is the build contract** — read the relevant section before implementing; where implementation reality contradicts the spec, the spec gets amended (publicly), not silently ignored.

## Non-negotiables (from SPEC.md)

- **Read path purity:** zero LLM calls, zero live ReBAC-engine calls on `recall`/`get`. Scope filters are materialized into the index and applied as mandatory pre-filters; enforcement lives in ONE shared layer above the `StorageAdapter` trait, never per-adapter.
- **Fail closed, always:** no visibility tokens → invisible; unresolvable subject → empty result; unmappable ACL → quarantine, never permissive indexing.
- **Bi-temporal, deterministic L1:** structured records are keyed upserts `(source, entity_id, field)`; old rows get `valid_to` + `superseded_by`, never UPDATE-in-place, never LLM extraction, never deletion (invalidate-don't-delete; hard purge only via the §8 crypto-shredding pipeline).
- **Every measured number is honest:** benchmarks report p50/p95/p99 at stated corpus size, filter selectivity, and hardware. No vendor-quoted numbers in docs.
- **Rust for the serving core, Python for ingestion only.** Python never appears on the read path.

## Conventions

- Rust 2021, workspace at repo root; `cargo fmt` + `cargo clippy -D warnings` must pass.
- sqlx with runtime queries (no offline macros yet — no DATABASE_URL requirement to build).
- Migrations are plain SQL in `migrations/`, numbered, append-only.
- The dev database is ParadeDB's Postgres 17 image (pgvector + pg_search preinstalled): `docker compose -f deploy/docker-compose.yml up -d`, DSN `postgres://verity:verity@localhost:5433/verity`.

## Current milestone

Milestone A — "the engine is honest": L0/L1 store, chunk store, StorageAdapter + Postgres profile, in-memory current-truth KV, and the filtered-ANN latency benchmark (the week-1 de-risking task; run it before trusting any latency claim in conversation or docs).
