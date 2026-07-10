# L3 materialized briefs & embedding-model migration (v0.3)

Companion to SPEC §2 (L3 derived views, derived-scope inheritance) and §5c
(embedding-model migration). Describes the v0.3 slice that ships in
`verity-server` / `verity-storage` / `verity-cli` (migration `0015`). Where the
spec promises more than the code does, the gap is stated, not implied away.

---

## Part A — L3 materialized briefs (SPEC §2 L3)

A **brief** is the per-entity "current state in one call": newest memory +
recent agent activity + staleness metadata. v0.3 makes it a **materialized**
derived view with lineage-derived visibility and app-level staleness marking.

### Storage shape (`briefs` table, migration 0015)

One row per `(tenant_id, entity)`:

| column | meaning |
|---|---|
| `body` jsonb | recomputed summary: `{recent_memory, recent_activity, memory_count, activity_count}`, materialized under a **broad** scope |
| `source_visibility` int[] | **intersection** of the visibility arrays of every contributing chunk/action (derived-scope inheritance) |
| `is_stale` bool | app-marked `true` on any contributing write; cleared on refresh |
| `last_synced_at` timestamptz | when the body was last recomputed |
| `source_version` bigint | monotonic, bumped on every stale-marking write |

### The two load-bearing decisions

**1. Derived-scope inheritance = INTERSECTION (fail-closed).**
`source_visibility` is the set intersection of the visibilities of all
contributing sources. Per SPEC §2: *"a brief summarizing three docs is visible
only to principals who can see all three."* Disjoint sources ⇒ empty
intersection ⇒ the brief-level summary is visible to **nobody** — the same
fail-closed posture as an empty chunk visibility. We default to intersection
and do **not** offer a union mode: union would leak the existence/shape of a
source to a principal who cannot see it.

The intersection gates **only the brief-level `summary` block**. It is not used
to serve items (see decision 2).

**2. Re-filtering: the materialized row is metadata + a cached summary, never a
served item set.**
The body is computed under a broad materialization scope, so serving it
verbatim would leak. Instead the read handler (`GET /v1/briefs/{entity}`):

- **serves `recent_memory` / `recent_activity` by re-deriving them under the
  CALLER's scope**, through the exact same scoped `latest_chunks` / `activity`
  paths (plus the `restricted`-class recheck) that `recall` uses. A caller can
  never receive an item their scope excludes — this is the *simplest correct*
  option from the task, and it makes the scope-soundness invariant hold by
  construction.
- uses the materialized row **only** for `is_stale`, `last_synced_at`,
  `source_version`, and the cached `summary` (item counts).
- **gates the `summary`** by derived-scope inheritance: a caller whose
  principals don't intersect `source_visibility` gets `summary: null`, even
  though they may still see the subset of individual items their own scope
  admits.

This is why the scope fuzzer's brief probe (Path 5 in `scope_fuzz.rs`) reduces
to the `latest_chunks` predicate: materializing a broad brief must not change
what the caller-scoped item path returns.

### Staleness lifecycle (app-level, not DB triggers)

Staleness marking lives in Rust (SPEC directive: keep lineage logic out of DB
triggers). On any write, the storage layer marks the affected entities' briefs
stale **synchronously, in the same transaction** as the write (a cheap
`UPDATE ... SET is_stale = true, source_version = source_version + 1`):

- `upsert_chunks` → marks the briefs of every `entity_tag` written.
- `record_action` → marks the briefs of the action's `entities`.
- `upsert_fact` → marks the brief of the fact's source-native `entity_id`
  (only on `Inserted`/`Superseded`; a no-op upsert leaves briefs alone).

Non-existent briefs are ignored — an entity's brief is materialized **lazily on
first read**. Recompute happens two ways:

- **On-read (lazy, debounced):** `GET /v1/briefs/{entity}` refreshes a stale
  brief whose `last_synced_at` is older than `BRIEF_REFRESH_DEBOUNCE_SECS`
  (5s), so a hot entity under write pressure doesn't refresh on every GET.
- **Batch (sleep-time):** `POST /v1/admin/briefs/refresh?tenant=<id>` (admin-
  gated) recomputes every stale brief for a tenant.

### Response shape

```json
GET /v1/briefs/account:acme?scope_handle=<handle>
{
  "entity": "account:acme",
  "recent_memory":   [ ...caller-scoped chunks... ],
  "recent_activity": [ ...caller-scoped actions... ],
  "is_stale": false,
  "last_synced_at": "2026-07-10T19:14:50Z",
  "source_version": 2,
  "summary": { "memory_count": 2, "activity_count": 0 }   // null if caller
                                                          // not in intersection
}
```

### Honest gaps

- The fact→brief lineage keys on the source-native `entity_id`; briefs
  materialized under a matching entity **tag** pick it up. A cross-source
  entity-resolution join (SPEC §7f) that maps `entity_id`→canonical tag is
  future work — until then, fact-driven staleness is exact only when the tag
  equals the entity id.
- The materialized `body` is a cache/summary; L1 record linkage in the brief
  arrives with cross-source entity resolution (§7f).

---

## Part B — Embedding-model migration (SPEC §5c)

The machinery for changing embedding models on a live corpus: a **second named
vector** backfilled alongside the first, then a **query-routing cutover**.

### Storage shape (migration 0015)

- `embedding_models(id, dim, created_at, is_default)` — the named-vector
  registry (SPEC §5c `{model_id, dim, revision}`). Seeded with
  `all-MiniLM-L6-v2` (384-d, the bundled encoder) as default.
- `chunks.embedding_v2 vector(384)` nullable + `chunks.embedding_v2_model` — the
  second named vector and its model marker. HNSW-indexed.
- `settings(tenant_id, key, value)` — runtime routing. `embedding_route ∈
  {v1, v2}`, per-tenant row wins over the global (NULL-tenant) default.

### The procedure

1. **Dual-vector backfill.** `POST /v1/admin/reembed/batch` walks current
   chunks lacking `embedding_v2`, **re-embeds each from its stored canonical
   `content`** (never a re-fetch — SPEC §5c), and fills `embedding_v2` under the
   target model. The encoder lives in the server, so the **CLI drives batches +
   progress** (`verity-cli reembed --model <id> [--tenant] [--batch N]`) while
   the server does the encoding. Ingest keeps writing `embedding` (v1) during
   the window, so freshness is unaffected; v2 is backfilled behind it.
2. **Query-routing cutover.** `POST /v1/admin/reembed/cutover` (or
   `verity-cli reembed cutover --to v2`) flips `embedding_route`. Once active,
   the recall **dense leg searches `embedding_v2`**; chunks not yet backfilled
   (`embedding_v2 IS NULL`) drop out of the dense leg and are covered by
   sparse/BM25 — exactly SPEC §5c's "uncovered chunks fall back to sparse-only
   for the new route."
3. **Coverage gate.** The cutover to v2 **refuses below 100% backfill coverage**
   (HTTP 409) unless `force=true` / `--force`, which acknowledges the
   sparse-only fallback for uncovered chunks. Rollback (`--to v1`) is always
   allowed.

### Honest limit: dims match today

The bundled encoder is 384-d and `embedding_v2` is `vector(384)`, so v0.3 is
**honest plumbing + routing, not a real model swap**: same dimension, same
column width. The registry, per-chunk model marker, dual-vector backfill, and
routing cutover are all real and exercised end-to-end. A **true dimension
change** (e.g. a 768-d model) needs a wider column — add
`embedding_v2 vector(768)` in a new append-only migration and a matching HNSW
index; the rest of the machinery (backfill, coverage gate, routing) is
dimension-agnostic and unchanged.

### Not yet built (SPEC §5c, deferred)

- **Shadow-evaluation mode** (run both routes on sampled traffic, report
  rank-overlap/recall deltas before the flip) — the cutover gate today is
  coverage-based only.
- **Deprecation/drop** of the old vector after a soak window — the old
  `embedding` column is retained; reclaiming it is a manual follow-up.
- The embedding **cache keyed on `(hash, model, params)`** for idempotent,
  restart-safe backfill — v0.3's backfill is idempotent via the `embedding_v2
  IS NULL` guard (already-filled rows are skipped), which is restart-safe but
  re-encodes on a re-run of a partially-failed batch.
