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

---

## 2026-07-09 (later) — 1M chunks: the valley collapses, then the selectivity router kills it

**Setup:** 1,000,000 chunks, same machine/profile. Bulk-loaded with secondary indexes
dropped (292s load; the incremental path was ~12x slower — bulk loads must drop/rebuild).
Two operational findings on the way: (a) Docker's 64MB default shm fails parallel HNSW
builds silently (`could not resize shared memory segment`) — compose now sets `shm_size: 1gb`;
(b) an accidental run against the index-less table measured the exact-scan curve:
brute-forcing a 1%-filtered subset took **11ms p50** while HNSW iterative scan took
**72.6ms p50** on the same query — the planner picks graph traversal exactly where it loses.

**Fix (this session): adapter-side selectivity router.** Before the dense query, a
sub-millisecond `EXPLAIN` row estimate routes: ≤20k estimated matches → exact top-k over
the filtered subset (perfect recall, no graph); above → HNSW iterative scan. (First
attempt used a capped `count(*)` probe — wrong: GIN builds its full bitmap before LIMIT,
costing ~100ms on broad scopes. Planner estimates are free and order-of-magnitude is all
routing needs.)

| Case | pre-router p50/p95 | **routed p50/p95/p99** |
|---|---|---|
| unfiltered ANN | 9.5 / 53.1ms | 9.8 / 18.6 / 21.1ms |
| filtered ANN @ 0.1% | 1.9 / 2.8ms | 2.2 / 3.7 / 7.2ms |
| filtered ANN @ 1% | **72.6 / 155.1ms** | **15.1 / 25.4 / 49.2ms** |
| filtered ANN @ 10% | 18.8 / 77.3ms | 13.1 / 19.7 / 27.4ms |
| filtered ANN @ 50% | 6.0 / 7.9ms | 5.7 / 10.1 / 13.3ms |
| BM25 @ 1% | — | 282.1 / 329.7 / 359.9ms |
| hybrid @ 1% | — | 284.9 / 330.0 / 381.4ms |
| L1 point read | — | 0.29 / 0.51 / 0.94ms |

**Findings:**

1. **The <50ms p95 claim holds at 1M for scoped dense recall, encoder included.** Worst
   dense case (1% valley) is 25.4ms p95 + ~12ms encode ≈ **~37ms p95 end-to-end**. The
   valley (finding 2 of the 100k entry) is eliminated by routing, not tuning — selective
   scopes get *exact* (perfect-recall) top-k, broad scopes get HNSW.
2. **The `get` path is flat with corpus size:** 0.29ms p50 at 1M vs 0.33ms at 100k.
3. **BM25 at 1M is the new breach: ~280ms p50.** The fast-field fix that held at 100k does
   not carry; pg_search is scoring the full match set before our filters bite. Hybrid
   inherits it. Next steps: push scope filters into the Tantivy query itself
   (`paradedb` filter syntax), or route hybrid's sparse leg through the same
   selectivity router (exact term-match over small filtered subsets). Until fixed, the
   honest hybrid number at 1M is ~330ms p95 — dense-only recall is the fast path.
4. Planner-estimate routing depends on healthy `pg_stats` on the visibility array —
   `ANALYZE` after bulk loads is load-bearing; the real system's roaring-bitmap scope
   masks (SPEC §3) replace the estimate with exact posting-list sizes, making routing
   deterministic.

---

## 2026-07-09 (later) — BM25 pushdown: finding 3 resolved, all paths inside the envelope

**Root cause (pg_search 0.24.1):** the array-overlap operator `&&` is not pushable into
Tantivy, and `valid_to` wasn't indexed — so BM25 queries heap-fetched the *entire* text
match set (~540k rows for a 2-term OR query) to evaluate scope filters before top-k.
The 0003 fast-field change was necessary but not sufficient.

**Fix (migration 0004 + adapter):** visibility expressed as `id @@@
paradedb.term_set('visibility', $principals)` — exact overlap semantics inside the Tantivy
boolean, matches nothing on an empty principal set (fail-closed preserved) — and `valid_to`
added to the bm25 index so `IS NULL` rewrites to a must_not-exists clause. Zero heap_filter
nodes remain in the plan (~1.9k buffers/query vs ~480k).

| Case (1M chunks) | before | **after p50/p95/p99** |
|---|---|---|
| BM25 @ 1% selectivity | 282.1 / 329.7ms | **15.9 / 17.8 / 18.7ms** |
| hybrid (dense+BM25) @ 1% | 284.9 / 330.0ms | **16.0 / 17.9 / 21.8ms** |

**Scoreboard at 1M, worst case per path (p95):** get 0.5ms · dense recall 25.4ms ·
BM25 17.8ms · hybrid 17.9ms · +12ms query encode ⇒ **every retrieval path is inside the
<50ms p95 envelope, encoder included.**

Caveats recorded: term_set's must-clause shifts raw scores by a constant (+1.0) — ranking
identical, RRF unaffected; `entity_tags <@` subset filtering remains a heap filter over the
(now small) pushed-down candidate set — add an entity-bound+broad-visibility bench case
before claiming that combination; one bm25 index per table means the migration briefly
drops search availability during rebuild (~1.6s at 1M).

---

## 2026-07-09 (later) — QPS under load, and the entity-bound BM25 breach

**Setup:** 1,000,000 chunks, same machine/profile (Apple M3 Pro / 36 GB, ParadeDB pg17 in
Docker). Two `verity-bench` additions: a `load` subcommand (the SPEC §4d follow-up flagged
in finding 5 of the first entry) and the entity-bound BM25 case the 0004 entry said to add
before claiming that combination. All numbers are **in-process adapter calls — no HTTP hop,
no query encoder** (dense/hybrid end-to-end adds ~12ms p50 of client CPU per the encoder
entry). One shared adapter, 16-connection pool.

**New latency case** (`run --queries 200`, k=10): principals=[broad token] AND
entity_scope=["account:0"] — broad visibility maximizes the Tantivy-pushed-down candidate
set that the heap-side `entity_tags <@` filter must then chew through.

| Case (1M chunks) | p50 | p95 | p99 |
|---|---|---|---|
| BM25 entity-bound + broad visibility | **542.7ms** | **724.5ms** | 955.4ms |

Same run re-confirmed the existing cases (dense @1% 13.7/17.6ms p50/p95, BM25 @1%
16.3/21.1ms, hybrid @1% 16.7/18.9ms, get 0.30/0.43ms — all consistent with prior entries).

**Load** (`load --sweep --duration-secs 20`): closed loop, zero think time; N tokio tasks
each looping a mixed workload — 70% hybrid recall (random 2-word text + random unit vector,
1%-selectivity token), 20% `current_fact` point reads, 10% `activity()` timeline reads.
Latencies are under-load and include waiting for one of the pool's 16 connections — at N=64
that queueing is the measurement, not an artifact.

| N | overall QPS | hybrid p50/p95/p99 | current_fact p50/p95/p99 | activity p50/p95/p99 |
|---|---|---|---|---|
| 4 | 166 | 32.7 / 48.9 / 60.6ms | 1.2 / 5.4 / 10.5ms | 1.3 / 4.9 / 7.9ms |
| 16 | 167 | 115.1 / 170.4 / 212.4ms | 41.5 / 68.7 / 84.7ms | 42.7 / 68.1 / 84.9ms |
| 64 | 170 | 388.4 / 513.3 / 582.1ms | 317.4 / 428.8 / 508.7ms | 311.0 / 410.1 / 500.7ms |

(Per-type throughput is flat across the sweep: ~117 hybrid ops/s, ~34 get ops/s, ~16
activity ops/s — the 70/20/10 mix at saturation.)

**Findings:**

1. **This box saturates at ~165–170 QPS for this mix, and it saturates by concurrency 4.**
   Tripling and then 16x-ing the offered concurrency buys zero throughput — only queue
   depth; p50 grows ~linearly with N (Little's law behavior, server-side bottleneck in
   Postgres, not the client loop). The honest operating point is N=4: hybrid recall
   48.9ms p95 *excluding* the encoder — with the ~12ms encode added, hybrid under load is
   already outside the 50ms p95 envelope even at low concurrency.
2. **SPEC §4d targets are not met on this setup, with caveats.** Target: ≥300 QPS hybrid
   recall at p95 <50ms per 8-vCPU serving node; measured: ~117 hybrid ops/s inside a
   166-QPS mix, on a laptop running Postgres under a Docker VM — not the reference shape,
   and a recall-heavy 70/20/10 mix rather than §4d's 80/20 get/recall load model. The gap
   (~2.5x) is real enough that it won't be closed by hardware relabeling alone; measuring
   on the reference shape and a get-dominated mix is the required next pass.
3. **Point reads queue behind recall under load:** `current_fact` p95 is 5.4ms at N=4
   (vs 0.43ms idle) and hundreds of ms at N=64 — on a shared pool, 30ms hybrid queries
   head-of-line-block sub-ms gets. The §4d get target (≥5k QPS at p95 <5ms) cannot be met
   from the same undifferentiated pool; the planned L3 in-memory projection (or a
   dedicated fast-path pool) is the designed fix, and a get-only load run should measure
   the ceiling separately.
4. **Entity-bound + broad-visibility BM25 is the worst number ever recorded here: 724ms
   p95, ~14x the envelope.** The 0004 caveat is confirmed, not theoretical: visibility and
   validity are pushed into Tantivy, but with the broad token the pushed-down candidate
   set is essentially the whole text-match set, and `entity_tags <@` heap-filters all of
   it. Dense recall is immune (the selectivity router sends tiny entity-bound subsets to
   exact scan — account:0 covers ~100 chunks at 1M). Candidate fixes, in order: route the
   sparse leg through the same selectivity router (entity-bound scopes are ~0.01%
   selective — exact term matching over ~100 rows is microseconds), or push entity_tags
   into the Tantivy boolean (term_set is exact for the single-tag chunks this corpus has,
   but `<@` subset semantics for multi-tag chunks need care).
5. Honesty notes: the bench tenant's activity timeline holds only 2 rows (~200 table-wide),
   so the activity column measures the scoped timeline query at trivial table size — path
   coverage, not a scale claim. No HTTP hop, no rate limiting, no encoder anywhere in the
   load loop; a served deployment adds all three.

---

## 2026-07-10 — entity-bound BM25 breach fixed: 542.7ms → 12.6ms p50 (43x)

**Fix (migration 0008 + adapter):** `entity_tags` and `kind` join the bm25 index with
**keyword tokenizers** (the default tokenizer splits "account:0", so term_set could never
match raw values — first attempt returned 0 hits), and entity-bound sparse queries become
two stages: a Tantivy boolean pre-filter (`term_set(entity_tags) OR term(kind,'knowledge')`
— any-overlap plus the §7g carve-out) scoring a candidate set bounded by the entity's own
chunks, then the exact `<@` subset residual over the MATERIALIZED candidates.
Filter-then-rank, never truncate-then-authorize; mixing the residual into the `@@@` query
breaks the TopK plan and heap-scans the full match set.

| Case (1M chunks) | before | **after p50/p95/p99** |
|---|---|---|
| BM25 entity-bound + broad visibility | 542.7 / 724.5ms | **12.6 / 16.5 / 19.2ms** |
| BM25 @ 1% (regression check) | 15.9 / 17.8ms | 18.3 / 22.4 / 24.8ms |
| hybrid @ 1% (regression check) | 16.0 / 17.9ms | 17.4 / 21.3 / 32.3ms |

All retrieval paths back inside the <50ms p95 envelope at 1M.

---

## 2026-07-10 — Qdrant SCALE profile lands: first Qdrant-vs-Postgres curve at 100k

**Setup:** `verity-storage-qdrant`'s `qdrant-bench`: 100,000 chunks (384-d unit vectors)
seeded through the hybrid adapter's real dual-write path into BOTH profiles — a dedicated
`verity_qbench` Postgres database (ParadeDB pg17, pgvector HNSW m=16/ef_construction=64,
ANALYZE'd) and one fresh Qdrant collection (v1.18.2, named 384-d cosine vector, payload
indexes on visibility/entity_tags/confidentiality/kind/valid_from, default HNSW, optimizer
green before measuring). Both engines in Docker on Apple M3 Pro / 36 GB. Filtered DENSE
recall through each profile's `StorageAdapter::recall`, k=10, 200 queries per case,
in-process client — no HTTP API hop, no query encoder (+~12ms p50 per the encoder entry).
Selectivity constructed as in `verity-bench`: token 0 on every chunk (broad), token 2 with
p=0.01 (1%).

| Case (100k chunks, dense recall) | p50 | p95 | p99 |
|---|---|---|---|
| Qdrant @ 1% selectivity | **1.09ms** | **1.61ms** | 2.01ms |
| Qdrant broad token (~100%) | 11.18ms | 13.82ms | 15.48ms |
| Postgres @ 1% selectivity | 3.44ms | 4.87ms | 6.29ms |
| Postgres broad token (~100%) | 3.61ms | 7.02ms | 11.75ms |

**Findings:**

1. **At the selective end Qdrant's filter-aware traversal wins** (1.1ms vs 3.4ms p50 at
   1%): no selectivity router needed — cardinality estimation over the payload index picks
   the plan inside the engine. This is the shape the SCALE profile was chosen for.
2. **On the broad token Qdrant is ~3x slower than pgvector here** (11.2ms vs 3.6ms p50):
   every candidate pays a filter check against the payload index plus a gRPC hop, on an
   untuned default HNSW. Not a problem at this corpus size (well inside the envelope), but
   worth rechecking at 1M+ before reading anything into it.
3. **This is NOT the scale claim.** 100k on a dev laptop under Docker says nothing about
   Qdrant's 10M+ regime — the profile exists for corpus sizes past the Postgres profile's
   ~5–10M honest ceiling, and that claim needs 10M+ vectors on server hardware, measured,
   before it appears here. This entry only establishes parity of the trait contract and a
   baseline curve.
4. Caveats: single-query latency only (no QPS-under-load for this profile yet); hybrid
   recall in this profile still runs its BM25 leg in Postgres (pg_search) + local RRF, so
   its sparse numbers are the Postgres profile's; the machine also hosted both containers.

---

## 2026-07-12 — why the playground trace shows ~50–120ms: span composition + dev-DB state, not a regression

**Trigger:** a playground trace line reading "94.3 ms storage" looked like it broke the
<50ms p95 claim. It does not — but only because the two numbers measure different spans
under different conditions, so this entry pins both down.

**What the playground `storage_ms` span actually wraps** (playground.rs `execute_search`,
one `Instant` around the whole in-process read): local ONNX query encode → `scope_for`
(scope compilation incl. revocation-tombstone subtraction, SQL) → `storage.recall`
(HYBRID: dense leg — with its per-call `EXPLAIN` routing probe and `embedding_route`
settings lookup — joined with the BM25 leg, RRF-fused) → `revocation::enforce_restricted`
(restricted-class recheck) → `spawn_audit` (spawn only; the write is async). The
benchmark entries above measure `StorageAdapter::recall` alone, in-process, single-leg,
no encoder (+~12ms separately). The playground span is a strict superset.

**Measured** (HTTP round-trip to `POST /v1/recall`, text query so the server encodes,
k=8, N=50 per cell, dev box under concurrent cargo builds — load avg ~2.2–2.7, dev
Postgres shared with ~100 test tenants):

| Case | build | run1 (cold) | p50 | p95 | max |
|---|---|---|---|---|---|
| bench tenant, 1,000,005 chunks, token-2 (~1%) | debug (7717) | 296.7ms | 84.0ms | 104.5ms | 296.7ms |
| bench tenant, same scope | release (7721) | 183.4ms | 83.0ms | 162.6ms | 190.4ms |
| bench, interleaved re-run (25 ea.) | debug / release | — | 85.0 / 83.7–85.5ms | 106.0 / 103.7–103.9ms | — |
| demo tenant (6 chunks) | debug (7717) | 80.8ms | 18.4ms | 24.4ms | 80.8ms |
| demo tenant (6 chunks) | release (7721) | 77.2ms | 17.8ms | 25.2ms | 77.2ms |

One real playground ask per build (single shot, demo tenant): `storage_ms` 53.3ms
(debug) / 118.3ms (release) — single-shot spread brackets the founder's 94.3ms.

**Findings:**

1. **Debug-vs-release is NOT the story:** interleaved p50s are identical within noise
   (85.0 debug vs 83.7–85.5 release). The span is dominated by Postgres + ONNX native
   code, which compile the same either way.
2. **Cold first shots run 2–4x the p50** (e.g. 296.7ms cold vs 84.0ms p50 on bench). A
   single screenshotted trace number is quite likely a cold shot.
3. **No regression from the L1 fact-visibility change (ba383e4):** its postgres.rs diff
   touches zero recall/chunks query lines (facts only); `EXPLAIN ANALYZE` of the live
   recall SQL shows the same five predicates and no new per-row work on chunks.
4. **What did drift: dev-DB state.** The dense exact-scan leg alone now measures
   ~40–43ms warm at 1% (vs 11–15ms in the 07-09 entries). The shared `visibility` GIN
   index returns 18,565 bitmap rows for token 2 across ALL tenants against 10,028
   in-tenant matches — the ~100 accumulated test tenants pollute the posting list — and
   the box was compiling in parallel. The a529fe1 route cutover also added one settings
   SELECT + an `EXPLAIN` probe per dense call (small, but part of the span).
5. **Conclusion for the claim:** the ~37ms p95 end-to-end number stands as measured on
   its stated conditions (verity-bench, adapter span, quiet box, clean 1M corpus). The
   playground number is a different span (adds scope_for, restricted recheck, BM25 leg,
   HTTP) on a dirty shared dev DB under load — it is *outside the benchmark's stated
   conditions*, which is exactly why the trace shows it. A clean-box re-run of the
   HTTP-path number belongs here before any end-to-end API latency claim ships.
