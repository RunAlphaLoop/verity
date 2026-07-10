# Verity measured latency — the honest numbers log

Per SPEC.md §4: every published number comes from `verity-bench`, at a stated
corpus size, filter selectivity, and machine. Append new entries; never edit
old ones.

---

## 2026-07-09 — first curve (Milestone A, week 1)

**Setup:** 100,000 chunks (384-d vectors, HNSW m=16/ef_construction=64), Postgres profile
(ParadeDB pg17: pgvector iterative scans + pg_search BM25) in Docker on Apple M3 Pro / 36 GB.
k=10, 200 queries per case, in-process client (no network hop, no query embedding —
local ONNX encoder not yet built).

| Case | p50 | p95 | p99 |
|---|---|---|---|
| unfiltered ANN (broad token) | 3.30ms | 6.25ms | 10.98ms |
| filtered ANN @ 0.1% selectivity | 1.15ms | 1.82ms | 3.59ms |
| filtered ANN @ 1% selectivity | **25.89ms** | **35.30ms** | 41.53ms |
| filtered ANN @ 10% selectivity | 7.81ms | 17.33ms | 27.97ms |
| filtered ANN @ 50% selectivity | 3.90ms | 7.85ms | 9.56ms |
| BM25 @ 1% selectivity | 29.26ms | 46.94ms | **87.17ms** |
| hybrid (dense+BM25) @ 1% | 35.17ms | 43.07ms | 58.17ms |
| L1 point read (`current_fact`) | 0.33ms | 0.60ms | 0.89ms |

**Findings:**

1. **The `get` path already beats its claim.** L1 point reads are sub-millisecond straight
   from Postgres — the spec's ~2–5ms budget holds with a wide margin before the in-memory
   KV projection even exists.
2. **The filtered-ANN valley is real and now located.** Latency is non-monotonic in
   selectivity: 0.1% is fastest (the planner abandons HNSW for an exact scan over the tiny
   posting set), 50% is near-unfiltered, and **~1% is the worst case** — too selective for
   cheap graph traversal, too large for exact scan. This is precisely the 2–10x degradation
   the research warned about; our mitigation targets (per-scope partial indexes, L3
   projections, roaring-bitmap pre-intersection) should be evaluated against the 1% case.
3. **All dense paths meet <50ms p95 at this corpus size**, but 100k chunks is 1–2 orders of
   magnitude below the Postgres profile's honest ceiling. The next entry must be 1M+ chunks
   before any latency claim leaves this repo.
4. **BM25's p99 (87ms) is the first SLO breach** — pg_search is filtering on the heap after
   the Tantivy match. Candidate fixes: fast fields on filter columns in the bm25 index, or
   tighter LIMIT with pre-intersection.
5. Missing from these numbers: query embedding (local encoder, budgeted 5–15ms), network
   hop, concurrency. Single-query latency only — QPS-under-load is a required follow-up.

---

## 2026-07-09 (later) — BM25 fast-field fix

**Change:** scope-filter columns (tenant_id, visibility, confidentiality) added to the bm25
index as fast fields (migration 0003), letting pg_search filter inside Tantivy instead of
on the heap. Same corpus/machine as the entry above.

| Case | p50 | p95 | p99 | prior p99 |
|---|---|---|---|---|
| BM25 @ 1% selectivity | 23.23ms | 30.46ms | **32.59ms** | 87.17ms |
| hybrid (dense+BM25) @ 1% | 30.70ms | 44.86ms | 55.90ms | 58.17ms |

Finding 4 resolved: **2.7x p99 improvement**, BM25 now inside the 50ms envelope at p95/p99.
Hybrid tail is now dominated by the dense side's 1%-selectivity valley (finding 2), which
remains the top optimization target.

---

## 2026-07-09 (later) — local query encoder measured

**Setup:** all-MiniLM-L6-v2 ONNX (384-d, matching the chunk schema), CPU-only via ONNX
Runtime, single thread, 100 short queries, Apple M3 Pro. Semantic ordering verified by test
(related queries must beat unrelated by >0.2 cosine).

| Case | p50 | p95 | p99 |
|---|---|---|---|
| local query encode (MiniLM-L6 ONNX) | 11.03ms | 12.21ms | 13.61ms |

Inside SPEC §4a's 5–15ms local-encoder budget. Warm-cache encoder load ~190ms; first-run
model download ~4.6s. **End-to-end dense recall including encoding** at 100k/1% selectivity
is therefore ~37ms p50 / ~48ms p95 (encode + filtered ANN, additive worst case) — the
number the <50ms p95 claim must hold against as corpus size grows.
