# Verity — Technical & Product Specification (v1.1)

**Name:** Verity (founder-approved 2026-07-09; run trademark/domain clearance before the first public artifact).
**One-liner:** The open-source, permission-aware shared context plane for enterprise AI agents — always fresh from systems of record, provably scoped, fast enough for the inner loop.
**License:** Apache 2.0, permanently. One codebase. Nothing security-critical ever paywalled.

**Changes from v1.0:** this revision resolves the completeness critique in the architecture itself, not in a risks list. Query embedding is now inside the latency budget with a local ONNX query encoder; a first-class Identity Plane (§6) makes source-ACL inheritance actually enforceable; the ReBAC engine decision is made — **SpiceDB**, because its true push Watch API and ZedToken consistency are load-bearing for our materialization design (OpenFGA only offers paginated `ReadChanges` polling); a Deletion, Retention & Compliance plane (§8) reconciles "invalidate-never-delete" with GDPR via crypto-shredding and a lineage-driven hard-purge pipeline; entity-tagging is stated honestly as a deterministic/probabilistic split with quarantine-by-default and a tagger-recall benchmark metric; `memory.remember` is retrievable at launch; MediaObject + retrieve-by-text ships in v0.1; concurrency targets, read-your-writes semantics, backup/restore/DR, tenant-model reconciliation, embedding-model migration, backfill, schema evolution, purpose-policy authoring, audit-log operations, signed-URI lifecycle, cross-source precedence, cost model, and OSS HA posture are all specified. The MVP is re-baselined at 12 weeks with an explicit staffing assumption.

---

## 1. Vision & Positioning

Enterprises run agents across sales, support, marketing, and ops, but each agent is an island: the context they need lives in CRMs, ticketing systems, docs, wikis, and web pages, and no open-source layer today syncs that context live, inherits its permissions, and serves it fast enough to sit inside an agent's inner loop. Verity is that layer — a single Apache-2.0 server that mirrors systems of record into a bi-temporal memory store via CDC/webhooks, inherits source ACLs into a Zanzibar-style permission graph, compiles caller scope into every retrieval as a mandatory pre-filter, and serves scoped hybrid recall with **zero generative-LLM calls and zero live authorization-engine calls on the read path** (the only model on the read path is a ~30M-parameter local query encoder, budgeted at 5–15ms and disclosed as such — see §4), exposed MCP-first to any framework. The category thesis is **trust**: an agent must *never* surface customer B's pricing to customer A, *never* cite a superseded opportunity value, and *never* act on an unprovenanced fact — and the 2026 research proves none of this can be delegated to the model (CIMemories: up to 69% attribute leakage under prompting; MemStrata: embedding similarity is at-chance, 0.59 AUROC, at detecting contradictions). Every guarantee in Verity is therefore architectural and deterministic — and where a guarantee necessarily rests on a probabilistic component (entity tagging over unstructured text), we say so explicitly, quarantine by default, and measure it publicly (§7d). Speed falls out of the correctness architecture rather than fighting it — precomputed scope filters are also the fastest filters.

**How we differ from the incumbents:**

| | Mem0 | Zep/Graphiti | Letta | **Verity** |
|---|---|---|---|---|
| Category | Per-user personalization memory | Temporal KG conversation memory | Agent framework with self-managed context | **Shared enterprise context plane** |
| Fed by | App pushes memories | App pushes episodes | Agent tool calls | **CDC/webhooks from systems of record + agent writes** |
| Permissions | `user_id` namespacing | Namespacing | Agent-bound | **Source-ACL inheritance + directory-synced identity + ReBAC + entity/purpose scoping, enforced in the index** |
| Freshness | N/A (app's problem) | Bi-temporal, LLM ingestion | Sleep-time consolidation | **Two-lane CDC/poll sync; deterministic supersession; published freshness SLOs** |
| Structured records | LLM-extracted to prose | LLM-extracted from JSON episodes | Files | **A CRM row stays a row — deterministic keyed upsert, no LLM in the write path** |
| Read latency (published) | ~0.88s p50 | ~150–200ms p95 | ~300ms p95 | **Target <50ms p95 scoped recall *including local query encoding*; ~5ms pinned-brief/record reads (honest, measured curves; remote-embedder configs excluded and labeled)** |

We do not compete with Mem0/Letta on chat personalization; we interoperate with them. We are "open-source Glean-for-agents": the vendor-neutral layer against Salesforce/Glean/Notion memory silos, and the permission-aware layer that Airbyte's Context Store and Weaviate Engram lack.

**Positioning spine (in this order):** 1) Provable scoping — architectural, injection-proof, benchmarked leakage of zero. 2) Live truth — source change to queryable in seconds, deterministic supersession, published SLOs. 3) Inner-loop speed — sub-50ms p95 server-internal scoped recall including local query encoding, ~5ms entity reads, honest latency curves. The five-minute quickstart is the funnel; trust is the category claim.

---

## 2. Core Concepts & Memory Model

Four hard-separated layers. Every layer above L0 is a derived, rebuildable projection (the evidence-vs-belief split validated by Eywa, Graphiti, and the governed-memory literature). Each layer has a different write path, freshness mechanic, TTL policy, and scoping rule.

### L0 — Evidence Log (immutable, crypto-shreddable)
Append-only raw episodes: CDC events, webhook payloads, document versions, transcripts, web-page snapshots, agent observations. Every episode is stamped with **provenance**: source system, source entity ID, writer principal (user `sub` + agent `azp` + `act` delegation chain from the MCP auth token), trust tier, ingest timestamp, content hash. Nothing here is ever rewritten in the normal course of operation. L0 is the audit log substrate, the poisoning-forensics substrate, and the replay source when extraction pipelines improve.

**Compliance carve-out (v1.1):** "immutable" is an operational property, not a legal impossibility. L0 payloads are envelope-encrypted with per-data-subject and per-source data-encryption keys, so GDPR/CCPA erasure is satisfied by **crypto-shredding** (destroying the key renders the ciphertext — including in every backup — permanently unreadable) plus a lineage-driven hard purge of derived tiers. The full mechanics live in §8. `memory.forget` retains its invalidate-never-delete semantics for *belief management*; erasure is a separate, admin-initiated compliance verb with different machinery.

### L1 — Canonical Records (deterministic, bi-temporal)
Typed, versioned mirrors of system-of-record objects: Account, Contact, Opportunity, Ticket, Page. **A CRM row stays a row.** Updates are deterministic upserts keyed on `(source, entity_id, field)` with bi-temporal versioning:

```
fact_row {
  key:           (source, entity_id, field)
  value:         typed value
  valid_from:    event time (when true in the world)
  valid_to:      NULL if current
  superseded_by: row id | NULL
  recorded_at:   ingestion time
  provenance:    L0 episode id
}
```

"Opportunity stage changed" is one keyed write that structurally retires the old value — no LLM, no embedding, no similarity judgment. This is the load-bearing MemStrata result: deterministic supersession serves stale facts ~0% vs 15–40% for RAG-style stores. Structured data is **never** run through LLM extraction. L1 facts carry no recency decay: they are current until superseded.

When the same real-world entity exists in multiple sources (the Acme account in both HubSpot and Salesforce), L1 rows remain per-source; the merge happens deterministically at the L3 view layer under explicit precedence rules (§7f).

### L2 — Extracted Facts (async, bi-temporal, Graphiti-compatible schema)
`(subject, relation, object)` triples produced by **async** LLM extraction over unstructured sources only (calls, email, docs, chat). Supersession is keyed on normalized `(subject, relation)` — never vector similarity. Contradicting facts set `invalid_at` with `reason ∈ {superseded, forgotten, retracted, poisoned}` — **invalidate, never delete**, preserving as-of-time queries (subject to §8 erasure, which hard-purges). Facts whose subject entity-resolves to an L1 record link to it; **L1 always wins conflicts** (system of record outranks conversational inference). We use Graphiti-compatible concepts (episodes, facts, valid_at/invalid_at) as a schema on our own storage — not a Graphiti or graph-DB dependency.

### L3 — Derived Views (precomputed current truth)
Per-entity **pinned briefs** (Letta-block-style summaries attached to agents, refreshed on CDC change), current-truth projections (including the cross-source merged entity view, §7f), and scope-partitioned indexes — rebuilt asynchronously by sleep-time workers. Every L3 artifact carries lineage back through L2/L1 to L0. On any source change, dependents are **synchronously marked STALE** (cheap lineage walk) and recomputed lazily; staleness metadata (`is_stale`, `last_synced_at`, `source_version`) is returned on every read.

**Enforced invariant:** a derived artifact carries the **intersection** of its lineage's scopes and visibility, and is invalidated whenever any ancestor's scope narrows. A brief summarizing three docs is visible only to principals who can see all three.

### Trust tiers & write-back
- **Tier 1 (authoritative):** CDC-derived L1/L2 content. Agent-immutable.
- **Tier 2 (observations):** agent writes are append-only L0 proposals with mandatory provenance. **New in v1.1 (launch-functional write→read loop):** every Tier-2 observation is *also* deterministically materialized as a retrievable chunk at write time — the raw observation text is embedded (local encoder), tagged with the entity tags inherited from the scope handle it was written under (deterministic, no extraction), stamped `trust_tier = agent_observation`, and indexed into the writer's scope. Asynchronous arbitration (Mem0-style ADD/UPDATE/DELETE/NOOP) into structured L2 facts remains a v0.3 refinement layered on top — but agents can read back what agents wrote from day one, ranked below Tier 1 at recall, quarantinable when originating from low-trust sources (web pages, inbound email).

This is the OWASP ASI06 memory-poisoning defense by construction. Remediation is surgical: one command invalidates everything derived from a poisoned L0 episode via lineage — a demoable security feature.

### Ranking
Composite `similarity × recency-decay × trust-tier × importance` applies to episodic/agent-written memory only. L1 facts: no decay, current-until-superseded.

---

## 3. Architecture

Composed three-tier architecture behind **one narrow retrieval API**, pluggable at exactly one seam (a Rust `StorageAdapter` trait). **No graph database dependency** — Neo4j is GPLv3, FalkorDB SSPL, Memgraph BSL (license-incompatible with an Apache-2.0 core), and KuzuDB's abandonment shows the embedded-graph risk. The graph operations we need at query time (entity scoping, 1–2 hop expansion, permission edges) are cheap adjacency lookups served as rows/payload indexes.

```
                          ┌─────────────────────────────────────────────┐
   SOURCES                │              INGESTION PLANE (Python)       │
  Salesforce ──Pub/Sub──▶ │  ┌──────────┐  ┌─────────┐  ┌────────────┐  │
  HubSpot ────webhooks──▶ │  │Connectors│─▶│ Durable │─▶│ Enrichment │  │
  Drive ──changes.watch─▶ │  │(push+poll│  │workflows│  │ chunk/embed│  │
  Notion/Slack ─────────▶ │  │ + ACLs)  │  │(retry q) │  │ extract    │  │
  Debezium envelope ────▶ │  └──────────┘  └─────────┘  └─────┬──────┘  │
  Web crawl ────────────▶ │        │ ACL tuples                │        │
                          │  ┌─────┴────────────────────┐      │        │
  IDENTITY SOURCES        │  │ IDENTITY PLANE (§6)       │      │        │
  Google Admin SDK ─────▶ │  │ directory sync, principal │      │        │
  MS Graph / SCIM ──────▶ │  │ crosswalk, group closure  │      │        │
                          │  └─────┬────────────────────┘      │        │
                          └────────┼───────────────────────────┼────────┘
                                   ▼                           ▼
                          ┌──────────────┐          ┌────────────────────┐
                          │   SpiceDB    │ Watch    │   DURABLE TIER     │
                          │ (ReBAC truth,│ API      │ Postgres: L0–L3    │
                          │ Go sidecar,  │ (push)   │ rows, lineage,     │
                          │ ZedTokens)   │────┐     │ changelog, keys    │
                          └──────────────┘    │     │ Lance on S3: media,│
                                              │     │ embed lineage      │
                                              ▼     └─────────┬──────────┘
                          ┌─────────────────────────────────────────────┐
                          │        SERVING TIER (Rust, the <50ms path)  │
                          │  local ONNX query encoder (~30M params,     │
                          │    5–15ms CPU) + query-embedding cache      │
                          │  hybrid index: dense ANN + BM25 + payload   │
                          │  scope metadata (visibility tokens, entity  │
                          │  tags, valid_from/to, trust tier)           │
                          │  + RoaringBitmap scope masks                │
                          │  + in-memory L1 current-truth KV (briefs,   │
                          │    records: ~2–5ms point reads)             │
                          │  + revocation tombstone set (fail-closed,   │
                          │    changelog-replicated, ack-confirmed)     │
                          │  + per-scope session write-through buffer   │
                          │    (read-your-writes for remember→recall)   │
                          │  Profiles: pgvector+pg_search │ Qdrant      │
                          └───────────────────┬─────────────────────────┘
                                              │
                          ┌───────────────────▼─────────────────────────┐
                          │        API PLANE (Rust)                     │
                          │  Scope Engine (MemoryScope handles, HMAC)   │
                          │  MCP server (stateless 2026-07-28 spec)     │
                          │  gRPC hot path │ REST │ subscriptions       │
                          └───────────────────┬─────────────────────────┘
                                              ▼
                       Claude / LangGraph / CrewAI / MS Agent Framework /
                       ADK / OpenAI Agents SDK / custom (via adapters)
```

### Storage engines

**Serving tier — two reference profiles behind the `StorageAdapter` trait:**
- **DEFAULT (adoption):** Postgres 17 + pgvector 0.8 (iterative index scans) + pgvectorscale + ParadeDB `pg_search` (Tantivy BM25). One container. Transactional freshness for free; scope filters as indexed WHERE clauses. Honest ceiling: ~5–10M vectors per deployment.
- **SCALE:** Qdrant (Apache 2.0) — filter-aware HNSW with ACORN, tiered multitenancy with zero-downtime tenant promotion, native sparse vectors for hybrid fusion.

Rejected for core: Milvus (ops weight), Chroma (scale ceiling), Turbopuffer-style object-storage serving (cold-start cliff, ~200ms write commit, proprietary), any graph DB (licenses). A native Rust filter-aware index is a **post-v1 experiment behind the adapter trait, never a launch promise**.

**Serving-tier hot structures:**
- **Local query encoder:** a ~30M-parameter embedding model (bge-small / arctic-embed-xs class) shipped in the server binary via ONNX Runtime, executing on CPU in ~5–15ms. Details and the same-model constraint in §4.
- **RoaringBitmap scope masks:** per-principal-token, per-entity-tag, per-confidentiality-class posting bitmaps, intersected in <1ms before/inside index traversal.
- **In-memory L1 current-truth KV projection:** ~2–5ms point reads for records and pinned briefs — the real inner-loop win, cheaper than any ANN work.
- **Revocation tombstones:** an in-memory set of item/principal pairs written **synchronously and fail-closed** on ACL-revocation events, hiding items *immediately*, ahead of asynchronous bitmap/index rebuild. Tombstones are durable (written to the changelog before ack), replicated to all serving replicas with acked delivery, and rebuilt on cold start via changelog replay (§11c) — a revoke is confirmed to the caller only after every live serving replica has acknowledged the tombstone or been fenced out of the query path.
- **Session write-through buffer:** a small per-scope in-memory buffer holding this session's `remember` writes, merged into `recall` results before async consolidation lands in the durable index — this is our read-your-writes guarantee (§4d).

**Durable tier:** Postgres as transactional system of record for L0–L3 rows, tenants, lineage, the key table for crypto-shredding (§8), and the changelog the serving tier tails. **Lance format on object storage** (Apache 2.0, Blob encoding, versioning/time-travel) for multimodal blobs, transcripts, and embedding lineage.

**Optional hot tier:** Valkey for session/working memory and principal-set cache. Never the system of record.

### Tenant model (reconciled, v1.1)

v1.0 claimed "tenant isolation is physical — never a mere filter" while simultaneously citing Qdrant tiered multitenancy, which co-locates small tenants in shared shards behind payload filters. That was a contradiction. The honest model:

- **Definition:** a **tenant** is a distinct legal/organizational trust domain whose data must never be co-queryable with another's — in cloud, a customer organization; in self-host, typically the whole deployment (single-tenant), or a subsidiary/business unit that the operator declares as a hard isolation boundary. Entity scoping (customer A vs customer B *within* one org's CRM) is **not** tenancy — it is Plane-3 scoping (§7c).
- **Large / regulated tenants: physical isolation.** Dedicated schema (Postgres profile) or dedicated collection/shard (Qdrant profile); optionally dedicated serving replicas. This is the default for any tenant that requests it and mandatory above a size/compliance threshold.
- **Small tenants (cloud): tiered co-location, disclosed.** Small tenants may be placed in shared shards separated by a mandatory, first-position `tenant_id` payload filter with tenant-keyed sharding (the Qdrant tiered-multitenancy pattern; Qdrant's own guidance recommends payload partitioning above ~500 tenants). Promotion to physical isolation is zero-downtime and automatic on growth or on request. **This placement policy is disclosed in the trust documentation, not hidden** — the enforcement gate treats `tenant_id` as a non-bypassable filter injected below the API layer, and the scope-soundness fuzz suite (§7e) probes cross-tenant leakage on co-located profiles explicitly.
- **Self-host default:** single-tenant; multi-tenant self-host uses the same tiered policy under operator control.

### Data flow: "opportunity updated"

```
CRM commit ──1-2s──▶ CDC event ──▶ L0 append (provenance stamped)
                                   │
                                   ├─▶ L1 deterministic upsert (keyed; old row
                                   │   gets valid_to + superseded_by)   <1s
                                   │       └─▶ changelog ─▶ serving KV + index
                                   │           upsert; pinned briefs marked
                                   │           stale, recomputed async
                                   ├─▶ lineage walk: dependent L2/L3 marked
                                   │   STALE synchronously (bitmap flip)
                                   └─▶ text fields only: chunk-hash diff ─▶
                                       re-embed changed chunks (seconds)

Agent recall/get sees new value: <5s end-to-end, zero embedding work
for structured fields.
```

---

## 4. Retrieval, Latency & Concurrency

**Non-negotiables on the read path:** zero generative-LLM calls; zero live ReBAC engine calls (materialized visibility + cached principal expansion); zero remote network calls in the default profile (including embedding — see 4a); filters pushed *into* the index (pre-/in-graph filtering only — post-filtering breaks both latency and the permission guarantee, since naive HNSW recall collapses to ~53% under selective filters and truncate-then-authorize under-returns).

### 4a. Query embedding: the honest design (new in v1.1)

v1.0's latency budget silently omitted query embedding. A `recall` needs a dense vector of the query text, and if that requires a round trip to OpenAI (50–300ms), the headline number is dead before the index is touched. Resolution — three coordinated mechanisms:

1. **Sparse-first path needs no dense embedding at all.** BM25 (Tantivy/pg_search) + scope-filter retrieval is fully functional standalone: `recall` with `mode: "sparse"` — or any deployment with no dense embedder configured — serves scoped lexical recall with zero embedding work. This is also the automatic degradation path if the dense encoder is unavailable.
2. **Local ONNX query encoder is the default dense path.** The Rust server ships a small (~30M-parameter, 384-dim class: bge-small-en / snowflake-arctic-embed-xs family, Apache/MIT-licensed weights) embedding model executed via ONNX Runtime on CPU: **~5–15ms per query**, no GPU, no network. In the **default profile, this same local model embeds documents at ingest too**, so query and document vectors live in the same space by construction.
3. **Same-model constraint, stated plainly.** Dense retrieval requires query-side and document-side embeddings from the same model (or a vendor-published asymmetric query/document pair of the same family). Therefore: **BYO remote embeddings for ingest-side document embedding are fully supported, but then queries must be encoded by that same remote model** — the query-side encoder may differ from the document-side embedder *only* when the vendor explicitly ships them as a compatible pair with a local query encoder. There is no magic adapter that lets a local MiniLM query an OpenAI-embedded corpus, and we will not pretend otherwise.
4. **Query-embedding cache:** an LRU cache keyed on `(normalized_query_text, model_id, revision)`. Agent workloads are highly repetitive (templated tool prompts); expected hit rates make the *effective* encoder cost well under the 5–15ms cold figure. Cache entries carry no scope information — scoping applies after embedding, so the cache is safely shared.

**The public claim, restated precisely:** *"sub-50ms p95 server-internal scoped recall, including local query encoding — measured, published, reproducible. Deployments configured with remote (BYO-key) embedders are excluded from this claim and labeled separately on the dashboard, since their recall latency includes a third-party network round trip we do not control."* Marketing never says "sub-50ms" without this qualification available one click away.

### 4b. Read paths, fastest first
1. **`get` / pinned brief** — KV point read from the in-memory L1 projection: **~2–5ms**. No embedding, no ANN. This is the primary inner-loop primitive; most agent turns need "current state of entity X," not search.
2. **`recall` (sparse mode)** — BM25 + scope masks + adjacency expansion: no embedding cost.
3. **`recall` (hybrid, default)** — local query encoding, then parallel filtered ANN + BM25 + 1–2 hop adjacency expansion over precomputed L3 projections, RRF-fused, composite-ranked, merged with the session write-through buffer.

### 4c. Latency budget (recall, hybrid, scale profile, in-region, local encoder)

| Stage | Budget |
|---|---|
| Auth token validation + MemoryScope handle lookup | ~1ms |
| Principal-set cache hit (short-TTL; miss path pre-paid at `open_scope` — see 4e) | 1–2ms |
| **Query embedding — local ONNX encoder (cache miss)** | **5–15ms (cache hit: <0.1ms)** |
| Tombstone + bitmap scope-mask intersection | <1ms |
| Filtered ANN + BM25 (parallel; BM25 overlaps encoder for its leg) | 5–35ms |
| Session write-through buffer merge | <1ms |
| 1-hop adjacency expansion (payload lookup) | 1–3ms |
| RRF fusion + rank + hydrate + staleness metadata | 2–5ms |
| Optional top-k live BatchCheck (`restricted` class, k≤50 — see 4e) | 3–10ms |
| **Total** | **~15–50ms p95 target (server-internal, local-encoder config)** |

Remote-embedder configs add the provider round trip (typically 50–300ms) on encoder-cache misses and are reported on a separate labeled dashboard curve.

### 4d. Concurrency, throughput & read-your-writes (new in v1.1)

Single-query latency is not a serving story. v1.1 commits to explicit load targets, measured in week 1 alongside the filtered-ANN validation:

- **Throughput targets (per serving node, 8 vCPU reference shape):** ≥300 QPS sustained hybrid `recall` at p95 <50ms (local encoder; the encoder is the likely CPU bottleneck — ONNX intra-op threading and the query cache are sized for this); ≥5,000 QPS `get`/pinned-brief point reads at p95 <5ms; linear horizontal scaling across serving replicas (stateless above the changelog).
- **Load model:** the benchmark harness (§13) runs a many-concurrent-agents profile — N agents × mixed 80/20 get/recall traffic with realistic scope-handle diversity — and publishes **p95-under-load**, not just idle p95.
- **Per-tenant rate limits:** token-bucket per tenant and per scope handle, configurable, fail-explicit (429 with retry-after), so one runaway agent fleet cannot starve a co-located tenant.
- **Read-your-writes (session-level, defined):** a `memory.remember` in a scope is **immediately retrievable in that same scope** on subsequent `recall`/`get` calls in the session, *before* async consolidation. Mechanism: the write is acked after L0 append + insertion into the per-scope **session write-through buffer** in the serving tier (embedded on-write with the local encoder; lexical-scanned given buffer sizes of ≤ a few hundred items); every `recall` under that scope handle merges buffer hits into the fused result set. When the async pipeline lands the observation in the durable index, the buffer entry is retired by content hash. Cross-session/cross-agent visibility of the same write follows the normal async path (seconds) and is covered by the freshness SLO, not the read-your-writes guarantee. This is the precise consistency contract: **session-scoped read-your-writes; eventual (SLO-bounded) cross-session.**

### 4e. Cache-miss and edge-case budgets (new in v1.1)

- **Principal-set cache miss** (first query of a principal's session): requires live SpiceDB expansion of the caller's group/relationship closure. This is deliberately **pre-paid at `memory.open_scope`** — scope minting performs the expansion (budget: 10–50ms, ZedToken-consistent) and warms the cache, so the first `recall` is not the slow one. If a recall arrives with a cold cache anyway (e.g., replica failover), the expansion runs inline with a hard 100ms timeout, **fail-closed**: timeout → empty principal set → empty results + explicit `principal_resolution_timeout` error, never a permissive fallback.
- **`restricted`-class truncation semantics (k>50):** the mandatory live BatchCheck is capped at 50 candidates per query. If the scoped candidate set for `restricted` items exceeds 50, the top 50 by pre-rank are checked and the response sets `restricted_truncated: true` with a continuation cursor; unchecked candidates are **never returned unchecked**. Callers needing exhaustive restricted-class sweeps use the paginated path, each page BatchChecked. The 3–10ms BatchCheck figure is a target to be **measured against deep Salesforce role hierarchies in week 1**, not assumed.

### Honest-numbers policy
- The headline commitment is **<50ms p95 server-internal scoped recall including local query encoding** (stretch goal 20–35ms, claimed only when measured). Vendor ACORN numbers (13.9ms at 5M vectors) are best-case; Qdrant's own docs note filter-aware traversal can run **2–10x slower than plain HNSW under restrictive filters** — and every Verity query carries restrictive filters by construction.
- **Week-1 engineering task:** benchmark (a) filtered ANN at our real ACL-token cardinality and selectivity on both profiles, (b) local-encoder throughput under concurrency, (c) BatchCheck latency against a deep role-hierarchy fixture, (d) QPS-under-load per the 4d load model. Published numbers are always measured, never vendor-quoted.
- We publish **latency-vs-corpus-size and latency-vs-QPS curves per profile** (Postgres profile honestly labeled ~30–60ms at its ceiling) — Zep's 150–200ms p95 at 100M nodes is the public bar to beat.
- Marketing framing: **"scoping makes queries faster, not slower"** — a mandatory selective filter shrinks the traversal frontier; the pinned-brief path makes the hottest reads independent of ANN entirely.

If the scale profile misses SLO at target scale, the fallback ladder is: tighter L3 projections → per-scope partial indexes → native Rust filter-aware index experiment behind the adapter trait.

---

## 5. Ingestion & Freshness

**Two-lane, per-connector freshness (the Glean pattern, open-sourced):**

- **PUSH LANE (seconds):** Salesforce CDC via gRPC Pub/Sub (~1–2s delivery, durable replay-ID checkpointing, 72h gap recovery, per-object real-time-vs-polled admin choice given the 5-entity license limit), HubSpot v4 webhooks + journal API, Slack Events, Google Drive `changes.watch` (mandatory channel renewal before 7-day expiry), Notion webhooks (page/property events only — block-level edits require the poll lane), and **Debezium change-event envelopes accepted as a first-class input** (Kafka topic or Debezium Server HTTP sink) so customers inherit 20+ database connectors for free.
- **TRUTH LANE (minutes–days):** cursor-based incremental polling (5–60 min) plus Glean-style full crawls (6h–28d) reconciling dropped webhooks, **deletions** (see §8c — source hard-deletes propagate to tombstone + purge, not merely to invalidation), and **permission drift**. Webhooks are documented-lossy everywhere: push is an optimization, never truth. Per-connector metadata records which entity types are push-capable vs poll-only.

**ACLs ride the same pipeline as content.** Every connector ingests sharing metadata alongside documents and writes ReBAC tuples, targeting seconds-level permission freshness (vs Onyx-style periodic sync cycles). Revocations additionally emit synchronous fail-closed tombstones (§7b). ACL tuples reference **canonical principals** resolved through the Identity Plane (§6) — a connector never writes a raw source-local user ID into the permission graph.

**Incremental re-embedding:** stable chunk IDs, content-hash diffing, embedding cache keyed on `(hash, model, params)`, end-to-end lineage from every index row and derived memory back to `(source, record, version)` — CocoIndex's dataflow-with-lineage design is the reference and a candidate component. Lineage is built day one; it is brutal to retrofit and it powers derived-memory invalidation, poison rollback, and the hard-purge pipeline (§8).

**Structured changes bypass embedding entirely** — the L1 deterministic upsert makes "opportunity updated → agent sees new value" a <5s path.

**Orchestration:** the ingest plane is server-side, horizontally scalable, and runs on durable execution. **v0.1 uses an internal persistent retry queue** (Postgres-backed, replay-ID checkpointed); **Temporal is mandatory before the managed connector fleet ships** (Dust's lesson: freshness pipelines are long-tail failure machines).

**Connector conformance tests are load-bearing infrastructure:** every connector must pass (a) field-mapping conformance (wrong mappings silently corrupt L1), (b) **ACL-mapping conformance** — Drive inherited folder ACLs, Salesforce implicit sharing and territory hierarchies — since silent ACL-mapping errors are the most likely real-world leak, and (c) **identity-mapping conformance** (§6c) — the connector's source-user-ID → canonical-principal crosswalk is exercised against fixture directories, including nested groups.

**Connector portfolio — three tiers (founder decision 2026-07-09; see §5d):**
1. **Native flagship connectors (OSS, few by design):** HubSpot, Google Drive, Salesforce (v0.2), Slack, Debezium/Postgres-CDC, web crawl — the sources where the product's claims live (seconds-level freshness via source push, full ACL fidelity incl. CRM sharing rules, identity crosswalks). We win the flagship-quality war, not the Airbyte quantity war.
2. **Merge.dev as the long-tail provider:** one `merge` connector implementing the standard connector interface unlocks Merge's 240+ integrations (HRIS, ATS, Accounting, Ticketing, File Storage, Knowledge Base) — see §5d for the freshness/ACL envelope and packaging.
3. **Nango (ELv2, self-hostable) as the optional OAuth/credential layer** for community-contributed native connectors, so contributors never handle raw OAuth plumbing.

**Headline metric:** per-connector **freshness SLOs (p50/p95 source-change-to-queryable)** published on a public dashboard next to read latency. Nobody in the market reports this.

### 5a. Initial backfill & cold start (new in v1.1)

First sync of a large Drive/CRM org is days of rate-limited API paging and hours-to-days of embedding — an unscoped cold start is its own incident. The backfill protocol:

1. **Identity first, ACLs before content — always.** Backfill ordering is enforced by the pipeline, not convention: (1) directory sync completes (principals + group closure, §6); (2) the connector's ACL/sharing-metadata crawl runs and tuples land in SpiceDB; (3) content is fetched, and **a content item is indexed only once its ACL is resolvable** — content arriving before its ACL resolves is held in quarantine, never indexed permissively. The fail-closed rule means a partially-backfilled corpus is *under*-visible, never over-visible.
2. **Rate-limit-aware by construction:** per-connector token buckets driven by each API's published quotas, adaptive backoff on 429s, resumable cursors checkpointed in the retry queue — a week-long Drive crawl survives restarts without re-paging.
3. **Progressive availability, visible progress:** entities become queryable as their (ACL, content) pairs complete — no all-or-nothing switchover. The web UI shows per-connector backfill progress (items discovered / ACL-resolved / indexed / quarantined, projected completion, embedding cost-to-date per the §11e cost model).
4. **Airbyte is dropped as the backfill path.** Airbyte carries no ACL metadata, which contradicts the ACL-before-content invariant. If an operator insists on an Airbyte feed, it is gated as **content-only into quarantine**: nothing from it is indexed until a Verity connector (or admin mapping) supplies the ACL and identity resolution for each item. This is documented as a slow-lane escape hatch, not a supported backfill mechanism.

### 5b. Source schema evolution (new in v1.1)

Field-mapping conformance tests are static; production sources drift at runtime — custom fields added/renamed in HubSpot/Salesforce, picklist values changed, objects deprecated.

- **Drift detection at ingest:** every connector validates incoming payloads against its registered schema version. An unknown field, a type change, or a renamed field does not corrupt L1 — the unrecognized values are diverted to a **schema-drift quarantine** (stored in L0 with full fidelity, excluded from L1/index), and an admin notification fires.
- **Admin mapping UI:** the web UI surfaces drifted fields with sampled values; the admin maps them (new L1 field, rename onto existing key, or ignore). Auto-mapping heuristics exist but are **off by default** — a silent wrong mapping is an L1 corruption.
- **Replay on resolution:** because the quarantined payloads live in L0, resolving a mapping triggers deterministic replay — no re-fetch from the source, no data loss for the drift window.
- **Connector upgrades** ship schema-version migrations for L1 with the same replay mechanism; the connector registry records `(connector, schema_version)` per tenant.

### 5c. Embedding-model migration (new in v1.1)

Named vectors record `{model_id, dim, revision}`; here is the actual procedure for changing models on a live 10M-chunk corpus:

1. **Dual named-vector backfill.** The new model is registered as a second named vector on the same chunk rows. A backfill worker walks chunks by lineage (L0/Representation-driven, so it re-embeds from stored canonical text, not from re-fetched sources), populating the new vector alongside the old. Rate/cost-governed (uses the same token-bucket + progress-UI machinery as §5a); the embedding cache keyed on `(hash, model, params)` makes it idempotent and restart-safe. During backfill, all queries route to the old vector — retrieval quality never degrades mid-migration.
2. **Query routing cutover.** Query-side encoding is per-model (§4a's same-model constraint), so cutover is a routing decision: per-tenant (or global) flag flips `recall` to encode queries with the new model and search the new named vector, once backfill coverage crosses a completeness threshold (default 100%; configurable with explicit acknowledgment that uncovered chunks fall back to sparse-only for the new route). A **shadow-evaluation mode** runs both routes on sampled traffic and reports rank-overlap/recall deltas before the flip.
3. **Deprecation.** After a configurable soak window with no rollback, the old named vector is dropped, reclaiming index memory/storage; the model registry retains the historical `(model_id, revision)` record for lineage.
4. Ingest writes **both** vectors during the migration window so freshness is unaffected.

The same procedure covers local-encoder upgrades (e.g., swapping the bundled ONNX model) and local→remote or remote→remote transitions.

### 5d. Merge.dev as the long-tail provider (founder decision, 2026-07-09)

The founder's directive — don't hand-build dozens of OAuth integrations — is served by **Merge.dev as a first-class long-tail provider**, with its role bounded by what we verified (July 2026):

**What Merge gives us (documented):**
- **240+ integrations across nine unified categories** (HRIS, ATS, CRM, Accounting, Ticketing, File Storage, Knowledge Base, Marketing Automation, Chat/Teams) behind one API and one OAuth surface.
- **File Storage ACLs are exactly our ingestion shape:** `File.permissions`/`Folder.permissions` with users/groups/roles, folder-inherited ACLs pre-resolved, a `Group` object with members and child groups, and `file.updated`/`group.updated` webhooks — Merge documents the ACL-aware-RAG pattern natively. ACL polling: 5 min for Drive/Dropbox/SharePoint/OneDrive, 1 h for Box; seconds-level via source webhooks on Drive/Box.
- **Remote Data** returns raw source payloads alongside normalized models (lineage/L0 fidelity preserved); **authenticated passthrough** covers anything unmodeled.

**Hard limits that keep flagships native (verified):**
- Merge is polling ETL at core: **daily sync on the self-serve Launch tier; source-webhook (seconds-level) paths require Professional+ contracts** and exist only for a subset of integrations. SharePoint/OneDrive/Dropbox have **no webhook path** (≈5-min ceiling).
- **CRM record-level visibility is not modeled** — no Salesforce sharing rules, territories, or role hierarchies. CRM ACL inheritance through Merge would mean hand-rolled passthrough Salesforce code, i.e., a native connector wearing a Merge hat.
- **No Slack data sync** (Merge's Slack support is action-execution only, in their Agent Handler product); Chat covers Teams at a 10-min cadence.
- **SaaS-only, no self-host** — all synced content and ACLs transit Merge's cloud.

**Packaging:**
- The `merge` connector ships **in the OSS repo** (the never-paywall covenant applies to code); it participates in the standard conformance suites — File Storage ACL mapping is conformance-tested; categories without ACL models (HRIS, ATS, Accounting, Ticketing) ingest under an **admin-assigned visibility policy** (e.g., "ticketing data → `internal`, support-team principals"), never permissively.
- **Verity Cloud** holds the Merge Professional relationship and resells long-tail connectivity with honest per-source freshness labels on the SLO dashboard (webhook-backed: seconds; polled: cadence-dependent). This is a clean cloud revenue line that never gates OSS features.
- **Self-hosters** bring their own Merge account (free ≤3 linked accounts, daily sync — disclosed in docs) or use native/community connectors. Verity's freshness SLOs are always reported per connector-and-plan, so a Launch-tier Merge source shows its true daily cadence rather than inheriting flagship claims.
- Per-source freshness metadata already exists in the connector registry (§5); Merge sources populate it from their sync/webhook mode. Nothing in the enforcement plane (§6–7) changes: Merge-ingested ACLs resolve through the same Identity Plane crosswalks and fail-closed rules.

---

## 6. Identity Plane (new in v1.1 — first-class)

v1.0's enforcement story had a silent dependency: materialized visibility tokens are expressed over *principals*, but the caller's token carries an IdP `sub`, while every source expresses its ACLs in its own principal vocabulary (Google account IDs and Groups, Salesforce user/role/territory IDs, HubSpot user IDs, Slack member IDs, Notion person IDs). **Without identity stitching, no visibility token can ever match a caller, and every query fail-closes to empty — or someone bodges an email match and creates the real leak surface.** Identity resolution is therefore a first-class plane, not connector plumbing.

### 6a. Canonical principals & directory sync

- **Canonical principal registry:** every human, group, and service/agent identity gets one canonical principal ID in Verity. ReBAC tuples, visibility tokens, bitmaps, tombstones, and audit entries all speak canonical IDs only.
- **Directory sync connectors (a distinct connector surface from content connectors):**
  - **Google Workspace Admin SDK** — the Directory API, *not* the Drive API: user list, and **full nested-group expansion** (Groups can contain Groups; Drive ACLs reference the outer group; correct closure requires recursive membership resolution via the Admin SDK, which is exactly why this cannot be bolted onto the Drive connector).
  - **Microsoft Graph** — users, groups (incl. transitive membership via `transitiveMembers`), Entra ID.
  - **Okta / Entra SCIM** — inbound SCIM provisioning so the customer's IdP pushes joiner/mover/leaver events; SCIM deprovision events feed revocation tombstones directly.
- Directory sync runs on the same two-lane model as content: event/webhook push where available, reconciling poll as truth. **Group-membership freshness is part of the published ACL-sync SLO** — a Drive ACL granting `group:eng-leads` is only as fresh as our closure of `eng-leads`.

### 6b. Per-connector principal mapping

Each content connector ships a **principal crosswalk**: deterministic mapping from source-local principal IDs to canonical principals, populated by directory sync where the source *is* the directory (Google, Microsoft) and by explicit ID-linking where it is not:

- **Preferred: provider-verified joins.** Salesforce `FederationIdentifier`/SSO subject, HubSpot SSO-linked identity, Slack's SSO-bound user profile — cryptographically or administratively asserted links between the source account and the IdP identity.
- **Fallback: email-keyed mapping rules — explicitly risk-labeled.** Where no verified join exists, an admin may enable email-address matching per connector. This is **labeled in the UI and docs as a trust downgrade**: email fields in SaaS user records are frequently mutable and unverified, so an email-keyed match is an attack surface (change your CRM email to the CFO's address, inherit the CFO's visibility). Mitigations when enabled: match only against IdP-verified primary addresses, log every email-derived link distinctly in the audit log, and flag email-mapped principals in the scope inspector. Default: **off**; unmapped source principals resolve to nothing and their grants confer no visibility (fail-closed).
- **Unmappable principals:** an ACL entry naming a principal the crosswalk cannot resolve contributes no visibility. If *all* of an item's ACL entries are unmappable, the item quarantines (never indexed permissively) — same rule as unmappable ACL structures.

### 6c. Identity-mapping conformance tests

Every connector's certification suite includes an identity fixture: a synthetic directory with nested groups (3+ levels), a shared drive with group-inherited ACLs, cross-linked SSO identities, one deliberately unverifiable email-only user, and one deprovisioned user. The connector must produce byte-exact expected canonical tuples — including *denying* visibility for the email-only user when email mapping is off and the deprovisioned user always. **These tests are load-bearing and gate connector release, exactly like ACL-mapping conformance.**

### 6d. Scope & schedule

The Identity Plane — canonical registry, Google Admin SDK directory sync, principal crosswalks for the launch connectors, email-fallback machinery (off by default), and identity conformance fixtures — is **scoped into Milestone B** (§13), because Plane-2 enforcement is untestable without it. Microsoft Graph and SCIM land in v0.2 with the Salesforce connector.

---

## 7. Scoping & Permission Model

Three planes above the Identity Plane. **All in the OSS core, fail-closed everywhere.** Paywalling the security model (the Onyx-EE mistake) is explicitly rejected; this is our differentiation and enterprises won't adopt enforcement they can't inspect.

### 7a. Plane 1 — Authorization (ReBAC source of truth): **SpiceDB** (decided, v1.1)

**Decision:** SpiceDB (Apache 2.0, AuthZed's Zanzibar implementation) is the ReBAC engine. v1.0 chose OpenFGA and cited its "Watch/changelog stream" for visibility materialization — **that stream does not exist as described**: OpenFGA offers only a poll-based, paginated `ReadChanges` API (25 tuples per page, continuation tokens). SpiceDB has a **true push Watch API** plus **ZedTokens** (Zanzibar zookies) for causally-consistent check semantics. Our materialization freshness, grant-propagation SLO, and tombstone triggering are all built on watching the tuple stream, so the engine choice follows the architecture:

- **Watch-driven materialization** (7b) consumes SpiceDB's Watch API directly — grant propagation in seconds without poll-cadence staleness, and the grant-staleness SLO is derived from measured Watch delivery latency rather than a polling interval.
- **ZedTokens** give us at-least-as-fresh check semantics for the `restricted`-class BatchCheck and for `open_scope`-time principal expansion (the expansion is pinned to a ZedToken at or after the latest ACL write we've materialized — no new-enemy anomalies between materialized filters and live checks).
- **Switching-cost logic, recorded:** pre-launch, the switch is cheap (both are Zanzibar-model tuple stores behind a thin client seam; schema languages differ but our tuple vocabulary is small). Post-launch it would be expensive (migration of live permission graphs across customers). Deciding now, on a verified capability difference that our design load-bears on, is exactly when this decision should be made. If SpiceDB's posture changes, the client seam is the insurance — but we design to Watch + ZedTokens and say so.

Connectors write relationship tuples mirroring source sharing models (Drive folders, Salesforce role hierarchies, SharePoint groups) alongside content, through the same CDC pipeline, expressed over canonical principals (§6).

**Packaging:** SpiceDB is a Go service and **cannot be linked into the Rust binary**. Resolution:
- **Production:** SpiceDB runs as a sidecar container (Postgres-backed datastore), deployed and health-checked by our Helm chart / compose file — wired up by default, impossible to accidentally skip.
- **Dev mode:** the `verity dev` binary ships the `spicedb` executable as an embedded resource and supervises it as a child process with its embedded datastore (started/stopped with the server, invisible to the user). If spawn fails, the server refuses to start — never "runs without authz."
- The Rust server talks to it via gRPC only; we do not reimplement the check engine.

### 7b. Plane 2 — Enforcement (materialized, in-index)

The ReBAC engine is **never called on the hot path** (AuthZed's own docs: unbounded LookupResources "will always perform poorly"). Instead:

1. Per-item **visibility tokens** (allowed canonical principals/groups, entity tags, confidentiality class, trust tier) are materialized into the serving index as payload metadata + roaring bitmaps, kept fresh via **SpiceDB's Watch API** (push, not poll).
2. At query time, the subject — cryptographically identified from the **MCP Enterprise-Managed Authorization / ID-JAG token** (spec-stable June 2026): user `sub` + agent `azp` + `act` delegation chain, resolved to a canonical principal via §6 — maps to a short-TTL cached principal set (1–2ms hit; miss path pre-paid at `open_scope`, hard-timeout fail-closed per §4e) attached as a **mandatory pre-filter inside the filtered-ANN query**.
3. **Revocation tombstones (event-driven, fail-closed):** an ACL-revoke event (from the Watch stream, a SCIM deprovision, or truth-lane reconciliation) synchronously writes a tombstone that hides affected items immediately, ahead of the async bitmap rebuild. Tombstones are durable, changelog-broadcast to all serving replicas with **acked delivery before the revoke is confirmed** (§11c). The residual staleness window applies only to *grants*, never revocations — and the grant window is now measured off Watch delivery, published as the ACL-sync SLO.
4. **Confidentiality classes with mandatory live recheck:** items carry a class (`public / internal / confidential / restricted`). For `restricted` — where **pricing, quotes, and negotiation terms land by default** — a top-k live BatchCheck against SpiceDB (~3–10ms target, k≤50, ZedToken-pinned, truncation semantics per §4e) is **mandatory, not optional**, closing the materialization window on exactly the customer-A/customer-B data.

Fail-closed rules: item with no visibility tokens → invisible; query with no resolvable subject → empty; connector that can't map an ACL or a principal → item quarantined, not indexed permissively.

### 7c. Plane 3 — Scope (beyond ACLs: the customer-A/customer-B problem)

Every session opens by minting a **server-side MemoryScope handle** — an HMAC-signed scoped credential (Typesense pattern) binding:

- `tenant_id` → partition selection per the §3 tenant model (physical for large/regulated tenants; mandatory first-position filter for co-located small tenants, disclosed);
- `entity_scope` → mandatory filter over entity tags stamped at write time (see 7d for how tags are derived and what guarantees they carry);
- `purpose` → per AirGapAgent: the declared context (entity + task purpose) is mapped by a deterministic compiled-predicate policy (Cerbos-style) to the retrievable set of provenance/confidentiality classes, **for the whole session**, immune to prompt injection because out-of-scope memory never reaches the model (CIMemories: prompting leaks up to 69%; the model cannot be trusted to withhold).

The handle's filters **cannot be widened by agent-supplied parameters**. Cross-entity analytics requires opening an explicitly different, audited scope. Agents inherit the **intersection** of their data sources' access by default (Dust's rule; admin-overridable).

**Multi-entity content — deny-by-default intersection semantics:** a chunk tagged with multiple entities (a call transcript mentioning customers A and B) is retrievable **only** in a scope covering *all* its entity tags, or in neither. Never union. The extraction pipeline tags conservatively; untaggable sensitive chunks quarantine for review.

**Derived-view scope inheritance:** L3 briefs/summaries carry the intersection of their lineage's visibility and entity scopes, enforced at rebuild time and re-checked when any ancestor's scope narrows (which triggers invalidation).

**Purpose-policy authoring (new in v1.1):** purpose→retrievable-class policies are **YAML policy files** living in the operator's repo, versioned in git like any other config, loaded at boot and hot-reloadable, compiled to predicates at load time with schema validation (an invalid policy file fails the reload, never fails open). Verity ships a starter policy pack (`support_conversation`, `sales_prep`, `analytics_readonly`, `admin_audit`) with documented semantics. Policy files record an owner and a change rationale field; every active policy version is visible in the scope inspector, and the audit log records which policy version governed each scope. A visual admin authoring UI is a later (v0.x/cloud) layer on the same files — the file format is the contract.

### 7d. Entity tagging: the honest split (new in v1.1)

v1.0 implied every guarantee was deterministic; entity-scope soundness over unstructured content is not, and we say so precisely:

- **Deterministic tags (guaranteed):** entity tags on L1 records, on chunks derived from structured objects, and on any content whose provenance names the entity (the transcript attached to the Acme opportunity, the ticket filed against the Acme account, an observation written under an Acme-scoped handle) are **provenance-derived at write time — deterministic, not inferred**. Plane-3 guarantees over these tags are architectural.
- **Probabilistic tags (measured, quarantined):** entity tags *inferred* from unstructured text (an LLM/NER pass noticing that a general-channel Slack thread discusses customer B) are probabilistic. A missed tag is a potential leak that the scope fuzzer cannot catch — the fuzzer probes handle enforcement, not tagger recall. Therefore: (a) **quarantine-by-default** — unstructured content from sources flagged entity-sensitive whose tagger confidence falls below threshold is quarantined for review rather than indexed; (b) tagger behavior is tuned for **recall over precision** (an extra tag narrows retrievability under intersection semantics — safe; a missed tag widens it — unsafe); (c) per-source sensitivity config decides whether zero-confidence content quarantines or falls through to the zero-tag class below.
- **Zero-tag content semantics (defined):** content with no entity tags is retrievable **only in explicitly-broad scopes** (a scope minted with `entity: "*"` / an analytics purpose that a policy explicitly grants zero-tag access) and **never in entity-bound scopes**. An Acme-scoped session cannot retrieve untagged content — not as a fallback, not as filler. This closes the "untagged therefore everywhere" failure mode by inverting it to "untagged therefore almost nowhere."
- **Measured publicly:** **tagger recall is Scoped Recall Benchmark metric #5** (§13) — a labeled corpus of multi-entity unstructured documents, scoring the pipeline on missed-entity rate at the operating threshold, published alongside leakage and latency. Where the guarantee is probabilistic, the number is public.

### 7e. Scope-soundness: a tested invariant, not a principle

Every retrieval path — `recall`, `get`-by-id, adjacency expansion, pinned-brief read, MCP resource read, subscription delivery, session write-through buffer merge, signed-media redemption — passes the same enforcement gate in the storage layer (the documented production leak in the governed-memory literature came through an unguarded get-by-id). **CI gate:** a fuzzer generates adversarial scope handles and probes every read path on every profile — including co-located-tenant configurations — and any cross-scope result fails the build. Every `(subject, scope, results)` tuple is audit-logged.

**Audit-log operations (new in v1.1):** at enterprise QPS the audit log is itself a large, sensitive dataset. It gets: (a) its own **retention policy** (default 400 days, configurable per compliance regime), with aged partitions dropped or exported to the operator's cold store; (b) **access control** — readable only by an explicit audit-reader admin role, itself audited (audit-of-audit reads); (c) **purge participation** — data-subject erasure (§8) redacts content payloads and query text within affected audit entries while preserving the access-event skeleton (who accessed what ref, when, under which scope and policy version) as hashes, keeping the log forensically useful without re-hosting erased PII; (d) storage as append-only partitioned Postgres tables with export to object storage, so audit volume never contends with the serving path.

### 7f. Cross-source entity resolution & precedence (new in v1.1)

L1 keys include `source`, so when HubSpot and Salesforce both hold the Acme account, the single pinned brief needs a merge rule — and it is deterministic:

- **Resolution:** a deterministic resolver links per-source L1 entities into one canonical entity via, in order: explicit admin crosswalk entries; shared strong keys (domain for accounts, verified email for contacts, explicit foreign-key fields like a synced CRM ID); nothing probabilistic in the OSS default. Unresolved candidates surface in the admin UI for manual linking; until linked, they are separate entities with separate briefs (annoying, never wrong).
- **Precedence:** merged L3 views apply **explicit per-field source precedence config** (YAML alongside purpose policies): e.g. `Opportunity.Amount: [salesforce, hubspot]`, `Contact.Phone: [hubspot, salesforce]`. Deterministic: highest-precedence source with a current (non-superseded) value wins; every merged field in a brief carries its winning source and provenance. Fields with no precedence rule and conflicting current values are rendered **side-by-side with provenance** rather than silently picked — conflict made visible beats conflict resolved wrong. L1 rows themselves are never merged or mutated; precedence is a view-time projection, so changing the config just rebuilds L3.

---

## 8. Deletion, Retention & Compliance (new section in v1.1)

"Invalidate, never delete" is the right *belief-management* semantics and the wrong *compliance* posture if it's the only machinery. An enterprise trust product must survive its first DSAR. This section makes L0 immutability and GDPR Article 17 coexist.

### 8a. Crypto-shredding: erasure for immutable and replicated data

- **Envelope encryption at write time:** every L0 episode payload and every Lance blob is encrypted with a **data-encryption key (DEK)** selected by a shred-key policy: per-data-subject DEKs where the payload is attributable to a person (a user's messages, a contact's transcript turns), and per-source(-partition) DEKs otherwise. DEKs live in a Postgres key table, themselves wrapped by a deployment KEK (KMS-backed in cloud/production; file-based in dev).
- **Erasure = key destruction + purge.** Destroying a DEK renders every ciphertext under it permanently unreadable **everywhere it physically exists — including object-storage versions and every backup ever taken** — without rewriting immutable history. This is what makes "L0 is never rewritten" and "the data is gone" simultaneously true.
- Key-table backups are managed separately from data backups with a short retention lag, so a destroyed key cannot be resurrected from an old backup (documented operational requirement; the restore runbook checks key-table recency).

### 8b. The lineage-driven hard-purge pipeline

Crypto-shredding kills the evidence; derived tiers hold plaintext projections and must be physically purged. Because lineage is built day one, purge is a walk, not a search:

```
erasure request (data subject S / episode set E)
  ├─ resolve S → canonical principal + entity links (§6, §7f)
  ├─ enumerate L0 episodes attributable to S (provenance + entity index)
  ├─ lineage walk forward: L1 rows, L2 facts, L3 artifacts, chunks,
  │    embeddings, serving-index entries derived from those episodes
  ├─ synchronous: serving tombstones on every affected item (invisible now)
  ├─ hard-delete derived rows in Postgres; delete chunks/vectors from
  │    serving indexes; compact Lance fragments where blobs held plaintext
  ├─ destroy DEKs for the L0 episodes / blobs (backups now unreadable)
  ├─ redact audit-log payloads referencing S (skeleton preserved, §7e)
  └─ emit signed purge report: refs purged, keys destroyed, timestamps
```

Postgres row deletions age out of PITR backups within the documented backup-retention window; the purge report states this window explicitly (regulator-standard "erasure within X days including backups" language, with X = purge time + backup retention, default 35 days).

### 8c. Source hard-deletes propagate

When a record is hard-deleted in the source system (a GDPR delete in the CRM, a Drive file trashed then purged), Verity must not remain a shadow copy. Push-lane delete events, and truth-lane reconciliation for deletes that webhooks dropped, propagate as: **synchronous serving tombstone (invisible within the freshness SLO) → hard-purge pipeline for the entity's derived data → DEK destruction for its L0 payloads** per the source's configured deletion policy. Per-source config chooses between `mirror-delete` (default for CRM/PII sources: purge as above) and `retain-invalidated` (for sources where the operator has a legal basis to retain history — retention basis recorded, payloads still encrypted and retention-bounded).

### 8d. Retention policies per source

Every connector carries a retention policy: `max_age` for L0 episodes and derived data (e.g., Slack 90 days, web crawl 30 days, CRM indefinite-until-superseded), enforced by a retention worker that runs the same purge pipeline on age-out. Retention interacts correctly with bi-temporality: superseded L1 *values* may outlive retention only if the source policy says so; defaults are conservative.

### 8e. DSAR export

The flip side of erasure: `verity dsar export --subject <principal|email>` produces a machine-readable export of everything attributable to the subject — L0 episodes (decrypted under admin authority, access audited), L1/L2 facts referencing their resolved entities, and the access-event skeleton of who retrieved their data — via the same identity resolution and lineage walk as purge. Ships in OSS (compliance is not paywalled); cloud adds workflow/ticketing around it.

### 8f. `memory.forget` vs erasure — the two verbs, kept distinct

`memory.forget` remains the agent-facing, scope-bound, audited **invalidation** verb: sets `invalid_at`, preserves as-of-time history, reversible in principle. **Erasure/purge is an admin/compliance verb** (`/v1/admin/erasure`, CLI, and web UI), never reachable from an agent scope handle — an injected prompt must not be able to trigger destruction of evidence. The audit log records both, differently.

---

## 9. API Surface

Three layers, one engine, one verb set.

### 9a. MCP server (first-class, stateless 2026-07-28 spec)
No session affinity; server-minted MemoryScope handles for cross-call state; `ttlMs`/`cacheScope` hints on entity reads; `subscriptions/listen` for change notifications; native consumption of EMA/ID-JAG tokens (the `(user, agent, on-behalf-of)` tuple is the authorization subject — never agent-supplied IDs).

Tool surface — six verbs, no sprawl:

```jsonc
// memory.open_scope — start a purpose-bound session
// (pre-pays principal-set expansion, ZedToken-pinned — §4e)
{ "tool": "memory.open_scope",
  "arguments": { "entity": "account:acme-corp", "purpose": "support_conversation" } }
// → { "scope_handle": "vs_9f2...hmac", "retrievable_classes": ["public","internal"],
//     "policy_version": "purpose-pack@a41f2c", "expires_at": "2026-07-09T18:00:00Z" }

// memory.recall — scoped hybrid search (the <50ms path)
{ "tool": "memory.recall",
  "arguments": { "scope_handle": "vs_9f2...", "query": "open renewal risks and last pricing discussion",
                 "k": 8, "mode": "hybrid" } }   // mode: hybrid | sparse (sparse needs no dense encoder)
// → results each carry: content, entity tags (+ tag_derivation: provenance|inferred),
//   trust_tier, valid_from, is_stale, last_synced_at, source_version,
//   citation → L0 episode id; media results carry a scope-bound signed URI (§10);
//   restricted_truncated flag + cursor when the k>50 BatchCheck ceiling applies

// memory.get — point lookup of a record or pinned brief (~2–5ms)
{ "tool": "memory.get",
  "arguments": { "scope_handle": "vs_9f2...", "ref": "record:salesforce/Opportunity/006xx0000012345/Amount" } }
// → { "value": 84000, "valid_from": "2026-07-09T14:02:11Z", "superseded": false }

// memory.remember — fast append to L0 (sub-5ms ack) + immediate retrievability:
// the observation is embedded (local encoder), entity-tagged deterministically from
// the scope handle, indexed as a Tier-2 chunk, and inserted into the session
// write-through buffer — retrievable by this session's next recall, and by other
// sessions within the async freshness SLO (§4d). L2 structured extraction remains async.
{ "tool": "memory.remember",
  "arguments": { "scope_handle": "vs_9f2...",
                 "observation": "Customer confirmed renewal decision moves to their Q4 board meeting.",
                 "entities": ["account:acme-corp"] } }   // entities must ⊆ scope's entity_scope; server-verified
// writer identity, trust tier = agent_observation, provenance chain stamped server-side

// memory.forget — audited invalidation (belief semantics; invalidate-never-delete;
// compliance erasure is a separate admin verb, never agent-reachable — §8f)
{ "tool": "memory.forget",
  "arguments": { "scope_handle": "vs_9f2...", "ref": "fact:l2/8842", "reason": "retracted" } }

// memory.pin / memory.unpin — Letta-style always-in-context entity brief, CDC-live
{ "tool": "memory.pin",
  "arguments": { "scope_handle": "vs_9f2...", "ref": "brief:account:acme-corp" } }

// memory.subscribe — change notifications via subscriptions/listen
{ "tool": "memory.subscribe",
  "arguments": { "scope_handle": "vs_9f2...", "refs": ["entity:account:acme-corp"] } }
```

All scope parameters are required in signatures but **enforced server-side from the token and handle**, never trusted from arguments.

### 9b. REST + gRPC substrate
What the MCP server itself calls. **gRPC** for inner-loop hot-path calls where MCP transport overhead matters (this is where sub-50ms is actually delivered); **REST** for ingestion, admin, bulk ops, connector callbacks; webhooks/SSE mirror subscriptions for non-MCP consumers.

```
POST /v1/scopes                          # mint MemoryScope handle
POST /v1/recall                          # scoped hybrid search
GET  /v1/records/{source}/{entity}/{field}?as_of=...   # bi-temporal point read
POST /v1/episodes                        # remember (L0 append + Tier-2 chunk)
POST /v1/ingest/debezium                 # first-class CDC envelope input
POST /v1/admin/quarantine/{episode_id}/rollback   # surgical poison rollback
POST /v1/admin/erasure                   # crypto-shred + hard-purge (admin-only, §8)
GET  /v1/admin/dsar/export?subject=...   # DSAR export (§8e)
GET  /v1/media/{blob_ref}?sig=...        # scope-bound signed media redemption (§10)
GET  /v1/slo/freshness?connector=hubspot # published freshness SLO data
```

The **wire protocol is separately MIT-licensed** (Airbyte's move) so third parties implement clients freely.

### 9c. Native adapters (the Mem0/Zep distribution playbook)
Thin packages at each framework's documented plug point, all backed by the one server: LangGraph `BaseStore` (hierarchical namespaces map 1:1 to tenant/entity paths), Microsoft Agent Framework `Memory` provider, CrewAI `ExternalMemory`, Google ADK `MemoryService`, OpenAI Agents SDK `Session` backend, Claude Agent SDK memory-tool storage backend. Python + TypeScript SDKs first.

**Standards posture:** build MCP-first; ignore AMP/OMP; monitor the W3C AI Agent Memory Interop CG; agent write identity is A2A signed-Agent-Card compatible.

---

## 10. Multimodal Handling

**Launch: text-canonical, media-aware — and the media path ships in v0.1** (v1.0 deferred it entirely, which quietly dropped a hard requirement; the launch pattern below is cheap — no index changes, no hot-path cost — so it's in). Forced by BYO-key reality (OpenAI, the most common key, still has no multimodal embedder as of mid-2026), native multimodal *embedding* remains a fast-follow.

Schema separates three layers:
- **MediaObject** — immutable blob + content hash in the Lance tier (image, audio, PDF, video), envelope-encrypted per §8a. **In v0.1.**
- **Representation** — versioned derived artifacts: Docling-parsed document text, ASR transcripts (ASR stays *out* of core — we accept transcripts with speaker turns/timestamps as an ingestion format; chunk on speaker turns; store audio URI + ms offsets so agents cite who-said-what-when), VLM descriptions for images, templated serialization for structured records. Each stamped with the pipeline that produced it.
- **Chunk** — the retrieval unit: text surface form, named vectors (each recording `{model_id, dim, revision}` — never mix models/dims in one index; migration between models per §5c), provenance offsets (page, bbox, audio ms range, speaker), and the scoping payload (tenant, entity tags, visibility tokens, confidentiality class) indexed for pre-filtering.

**Launch pattern — retrieve-by-text, answer-from-pixels (in v0.1):** recall returns the chunk plus a scope-checked signed URI to the original media, so a VLM agent answers from the source. Most of the multimodal value, zero index changes, zero hot-path cost.

**Signed media URI lifecycle (new in v1.1):** signed URIs are **scope-bound capabilities, not bare presigned S3 links**. Each URI encodes `(blob_ref, scope_handle_id, expiry)` under the server's HMAC; default TTL **5 minutes** (configurable, capped at scope lifetime). Redemption goes through the server (`GET /v1/media/...`), which re-runs the enforcement gate at redemption time: expired handle, closed scope, revoked visibility, or tombstoned item → 403, regardless of URI validity window. Closing a scope **immediately revokes** its outstanding URIs (the redemption check is live, so no revocation list is needed). Every redemption is audit-logged like any read. Exfiltration-beyond-session is therefore bounded to: an already-fetched blob (out of any system's control) — never a still-live capability.

**Fast-follow (v0.x):** native multimodal single-vector via an embedder capability flag (`text | multimodal | multivector`) — Cohere embed-v4, voyage-multimodal-3.5, Gemini Embedding 2, or **self-hosted Jina v4** for the no-vendor OSS story — as an additional named vector on the same chunk row, introduced via the §5c dual-vector migration machinery (direct visual embedding beats describe-then-embed by ~20–32% on visually rich content; one vector per page, same index, same latency). Note the §4a constraint applies: multimodal document vectors require a compatible query-side encoder; text→image retrieval uses the vendor's paired text tower, which for remote models puts those queries on the labeled remote-latency curve.

**Later (v1+), opt-in only:** late-interaction "high-fidelity documents" mode — dense first-pass + MaxSim rerank over unindexed stored multivectors (Qdrant pattern), or MUVERA fixed-dimensional encodings in the fast index. Never the default: ~1,024 patch vectors/page is irreconcilable with the latency budget. Managed GPU inference for this lives in cloud.

CDC freshness composes cleanly: new source version → new Representations → chunk upserts by stable ID → stale vectors invalidated; the media hash makes re-ingestion idempotent.

---

## 11. Tech Stack & Deployment Shape

**Languages:**
- **Rust** — the server core: serving tier, scope engine, local ONNX query encoder integration, storage adapters, MCP/gRPC/REST surfaces, roaring-bitmap enforcement, embedded Tantivy/usearch for dev mode. Matches the ecosystem we compose (Qdrant, Lance, Tantivy, CocoIndex); allocation-predictable p99; single-static-binary distribution.
- **Python** — the ingestion/enrichment plane only: connector SDK, directory-sync connectors, workflows, LLM extraction, Docling parsing, embedding calls. Never on the read path. This is also the main community-contribution surface (offsetting Rust's smaller contributor pool).

### 11a. Deployment ladder
1. **`verity dev`** — ONE static binary, zero dependencies: embedded storage (SQLite + usearch + Tantivy), bundled ONNX query/document encoder, supervised SpiceDB child process, **bundled web UI**, MCP endpoint exposed on start. Five minutes from download to a Claude/LangGraph/CrewAI agent with persistent scoped memory (the `temporal server start-dev` lesson: docker-compose loses developers).
2. **`docker compose up`** — server + Postgres profile + SpiceDB sidecar + workers: the production self-host.
3. **Helm** — production clusters with the Qdrant scale profile, serving tier horizontally scaled per tenant partition, colocated in-region with the agent runtime (a cross-region hop alone eats the latency budget).

**Dev/prod parity guardrail:** dev and production profiles differ only *below* the `StorageAdapter` trait; the **enforcement gate (scope engine, visibility filtering, tombstones, signed-URI redemption) is one shared Rust layer above the trait**, and the scope-soundness fuzz suite runs against **every profile** in CI.

### 11b. Backup, restore & disaster recovery — self-host, in OSS docs (new in v1.1)

State spans four stores (Postgres durable tier, SpiceDB's datastore, Lance/S3, in-memory serving structures). A naive restore where content is newer than ACLs is permission drift — i.e., a leak. The documented, tooling-enforced protocol:

- **Consistent snapshot ordering:** the backup tool snapshots the **SpiceDB datastore first** (capturing its revision/ZedToken), then the Postgres durable tier (capturing its changelog position), then references the Lance/S3 object versions; the backup manifest records `(spicedb_revision, changelog_position, lance_versions, key_table_version)` as one unit. Because content-visibility depends on ACLs and not vice versa, ACL-older-than-content is the dangerous direction — the ordering plus the restore check below forbids it.
- **Restore is fail-closed until reconciled:** on restore, the serving tier boots in **fail-closed mode** — no queries served — until visibility materialization has been rebuilt from the restored SpiceDB state to a revision at-or-after the restored content changelog position, and the truth lane has run an ACL reconciliation pass against live sources for the gap window. Only then does serving open. The restore runbook also verifies key-table recency (§8a) so destroyed DEKs stay destroyed.
- **Tombstone rebuild-on-cold-start:** tombstones are durable in the changelog, not merely in memory. Every serving replica cold-start is fail-closed: the replica replays the changelog (including the revocation log) from its last checkpoint to head — rebuilding tombstones, bitmaps, and the L1 KV — before it registers for query traffic. A replica can never serve from a state older than the last confirmed revocation.
- **Replica tombstone fan-out (the mechanism, not an assertion):** revocations are broadcast over the changelog stream to all serving replicas; the revoke is **confirmed to the caller only after every live replica acks tombstone application**. A replica that fails to ack within the deadline is fenced out of the load balancer before confirmation proceeds — the invariant is "no replica serving traffic predates any confirmed revocation," enforced by fencing, not hope.
- All of the above ships as `verity backup` / `verity restore` tooling + runbook **in OSS docs** — self-hosters get the same correctness story as cloud, minus the automation. Cloud adds scheduled PITR, cross-region replicas, and tested-restore attestations.

### 11c. Self-host HA posture (new in v1.1)

Single-cluster OSS is not HA-less: the documented posture is **active-standby serving replicas**. Standbys tail the same durable changelog continuously (warm L1 KV, bitmaps, tombstones); failover promotes a standby after replay-to-head, fail-closed during the replay gap (seconds). Postgres HA via standard tooling (Patroni et al.), SpiceDB HA via its own replica support — both referenced, not reinvented. Multi-region active-active remains a cloud feature; single-region resilience is fully self-hostable and documented.

### 11d. Web UI

The bundled web UI is both funnel and security artifact: a **scope inspector** — "show me exactly what this agent can retrieve under this MemoryScope" (including tag derivation, policy version, email-mapped-principal flags) — plus memory browsing, lineage/provenance views, backfill progress, schema-drift queue, and freshness dashboards. It is the single best artifact for passing a security review, for internal red-teaming, and for making the zero-leakage benchmark demonstrable rather than asserted. Ships in OSS. (At v0.1 launch the UI is read-only — inspector and dashboards; admin mutations via CLI/REST until v0.2. See §13.)

### 11e. Cost model note (new in v1.1)

Order-of-magnitude economics buyers and self-hosters ask about first, using defaults (1M documents ≈ 3M chunks ≈ 2B tokens):

- **Embedding (ingest/backfill):** local default encoder — $0 API cost, ~CPU-hours on the ingest fleet (a few hundred CPU-hours per 1M docs; parallelizes trivially). BYO remote: at text-embedding-3-small pricing (~$0.02/1M tokens) ≈ **~$40 per 1M docs**; large-class models (~$0.13/1M) ≈ **~$260 per 1M docs**. Re-embedding cost is incremental thereafter (content-hash diffing); a full model migration (§5c) re-incurs the corpus cost once.
- **Storage:** 3M × 384-dim vectors ≈ ~4.6GB raw (+2–3× HNSW/index overhead); at 1536-dim BYO ≈ ~18GB raw. Postgres L0–L3 for the same corpus: ~20–60GB depending on payload sizes; Lance/S3 blobs at source-media scale. A 1M-doc deployment fits comfortably on one well-provisioned node.
- **LLM extraction (L2, v0.3+):** the dominant marginal cost when enabled — priced per unstructured source at ~$1–5 per 1K documents on current mid-tier models; async, budgetable, and off by default.
- A living cost calculator ships in docs; these are planning numbers, revised against measured pipelines.

**Server, not library.** Shared multi-agent memory, permission enforcement, and the ingestion plane all require a server; the embedded dev mode exists for the funnel, not the architecture.

**Strict API parity** between self-hosted and cloud (the LiveKit promise): conversion is a connection-string change.

**The funnel is designed for AI builders as much as humans:** MCP-native provisioning, `llms.txt`, copy-pasteable docs and MCP config blocks — Supabase (60%+ of new DBs from AI tools) and Neon (80% agent-provisioned) show agents are the largest acquisition channel.

---

## 12. License & Open-Core Split

**Apache 2.0 for everything in the OSS repo, permanently.** Written day-one covenant: the license never changes, and shipped OSS features are never removed (the MinIO anti-pattern). **One codebase** — no OSS/cloud server fork (Zep's Community Edition failure). DCO + trademark strategy, no CLA-heavy control. AGPL/BSL/ELv2 rejected: AGPL blocks enterprise legal approval and framework embedding; Apache 2.0 is the category norm (Mem0/Graphiti/Letta/Cognee); fork-risk is mitigated by a proprietary control plane, not copyleft (the Valkey/OpenTofu lesson).

**Structural bindings for the covenant:** the wire protocol is MIT; **connectors live in a separately-governed repo** so the never-paywall promise is structurally enforced, not a blog post.

**OSS (feature-complete data plane):**
- The engine; both storage profiles; hybrid retrieval; all read paths; the local ONNX query/document encoder.
- The **entire** permission/scoping/enforcement plane: SpiceDB integration, the Identity Plane (directory sync, principal crosswalks, conformance fixtures), visibility materialization, tombstones, scope handles, purpose-policy engine, audit logging, the scope-inspector UI. (Supabase never gated RLS; gating security kills our differentiator.)
- The **entire** compliance plane: crypto-shredding, hard-purge pipeline, retention policies, DSAR export, backup/restore/DR tooling and runbooks. (A trust product that paywalls GDPR compliance is not a trust product.)
- Bi-temporal L0–L3 schema; MCP server; gRPC/REST; all framework adapters and SDKs.
- Connector SDK + flagship OSS connectors; the freshness engine; BYO embedding keys; embedding-model migration tooling.
- The eval/benchmark harness; the dev binary + web UI; single-cluster operation incl. the documented active-standby HA posture.

**Cloud/commercial (monetize operations and multi-tenancy, never withheld features — the Qdrant/Temporal/Supabase template):**
- Managed always-on connector fleet: OAuth credential management, hosted webhook endpoints/verification, contractual **freshness + ACL-sync SLAs**; **long-tail connectivity resold through Verity Cloud's Merge.dev Professional relationship** (240+ integrations without per-customer Merge contracts; per-source freshness honestly labeled per §5d).
- Multi-tenant control plane: tiered tenant placement/promotion (per the §3 disclosed tenant model), zero-downtime upgrades, shard rebalancing, scheduled backups/PITR with tested-restore attestations, autoscaling; multi-region/HA active-active; BYOC/hybrid tier for data-sovereignty buyers.
- Management-plane compliance: SSO/SAML, SCIM *for the control plane itself*, org-level RBAC, audit-log export integrations, SOC 2/HIPAA reporting, turnkey ID-JAG/XAA IdP integration, DSAR workflow/ticketing.
- Managed inference: embeddings/parsing/ASR without keys; late-interaction GPU infrastructure.
- Observability suite (per-agent recall analytics, leakage monitoring, freshness dashboards at fleet scale); memory branching/environments for dev/staging.

---

## 13. MVP Scope (v0.1) & Milestones

Goal: prove the two wedges — **provably scoped recall** and **live supersession** — end to end, with the 5-minute wow.

**Staffing & timeline, stated explicitly (new in v1.1):** the plan assumes **2 engineers plus AI-agent-assisted development, 12 weeks, three overlapping milestones**. v1.0's 10-week plan carried no staffing assumption and had quietly re-inflated scope; this re-baseline both states the assumption and cuts accordingly: benchmark metrics reduced to 1, 2, 4 at launch (leakage, staleness, latency — the freshness dashboard becomes metric-3's v0.2 home; tagger recall, metric 5, lands with probabilistic tagging in v0.3), the web UI is **read-only** at launch (scope inspector + dashboards; admin mutations via CLI/REST), and the identity plane ships with exactly the surface the two launch connectors require. Where reality still contradicts the 12 weeks, scope is cut publicly, not stretched silently.

**MVP connector decision:** **HubSpot** (v4 webhooks + journal: zero license friction for contributors and CI, proves deterministic supersession and freshness) **+ Google Drive** (`changes.watch` + renewal + polling backstop, Docling parsing, **Drive ACL inheritance + Admin SDK nested-group directory sync** — the hard permission proof, testable with a free Google Workspace account) **+ the Debezium envelope input** (nearly free to build, unlocks every database). **Salesforce Pub/Sub moves to v0.2**, funded by a design partner with a dev-org matrix.

### Milestone A — "The engine is honest" (weeks 1–5)
- Rust server on the **Postgres profile only** (pgvector + pg_search, one container); `StorageAdapter` trait defined; Qdrant profile deferred to v0.3.
- **Week 1, before anything else:** the four-part measurement task (§4): filtered-ANN latency at realistic ACL-token cardinality/selectivity; local-encoder throughput under concurrency; BatchCheck latency on a deep role-hierarchy fixture; **QPS-under-load per the §4d load model**. Publish the first measured curves internally. This de-risks every latency and throughput claim in the spec.
- Local ONNX query/document encoder integrated + query-embedding cache; sparse-mode recall functional with no dense encoder.
- L0 evidence log (envelope-encrypted per §8a — the key table and DEK plumbing exist from the first byte written; the purge pipeline itself lands in Milestone C) + L1 deterministic bi-temporal records + chunk store; content-hash incremental re-embedding; lineage from day one.
- In-memory L1 current-truth KV + pinned briefs (`get` at ~2–5ms).
- Internal persistent retry queue for ingestion; backfill protocol skeleton (ACL-before-content gating, resumable cursors).

### Milestone B — "The scope plane, complete and fuzzed" (weeks 4–9, overlapping)
- SpiceDB sidecar/child-process packaging; connector-written tuples; **Watch-API-driven** visibility materialization; ZedToken-pinned principal expansion pre-paid at `open_scope`, fail-closed on miss/timeout.
- **Identity Plane (§6):** canonical principal registry; **Google Admin SDK directory sync with nested-group closure**; HubSpot principal crosswalk; email-fallback machinery present but **off by default**; **identity-mapping conformance fixtures** for both launch connectors.
- MemoryScope HMAC handles; purpose binding via YAML policy files + starter pack; entity-scope filters (provenance-derived deterministic tags only in v0.1 — probabilistic tagging + quarantine thresholds arrive with L2 in v0.3; zero-tag semantics enforced from day one); tenant model per §3; **revocation tombstones with changelog durability, replica ack/fencing, and cold-start replay (§11b)**; **multi-entity intersection semantics**; **derived-scope inheritance**; mandatory BatchCheck on the `restricted` class with k>50 truncation semantics.
- **Session write-through buffer** — read-your-writes for `remember`→`recall` (§4d); `remember` writes materialize as retrievable Tier-2 chunks (deterministic path, §2).
- **Scope-soundness fuzz suite in CI** covering every read path (search, get-by-id, adjacency, brief, MCP resource, buffer merge, media redemption) — the moat, tested.
- Audit log of every `(subject, scope, results)` tuple, with retention/access controls per §7e.

### Milestone C — "The demo and the numbers" (weeks 8–12)
- MCP server (stateless 2026-07-28 spec; open_scope/recall/get/remember/forget/pin) + gRPC/REST; **one** framework adapter (LangGraph BaseStore); others fast-follow in v0.2.
- Connectors: **HubSpot** (webhooks+journal, <5s field-change-to-queryable), **Google Drive** (ACL inheritance + Docling + directory sync), **Debezium envelope** — each with field-mapping, ACL-mapping, *and identity-mapping* conformance tests; backfill with progress UI.
- **MediaObject store + retrieve-by-text/answer-from-pixels** with scope-bound signed URIs (§10) — the v0.1 multimodal commitment, honored.
- **Compliance plane v0:** hard-purge pipeline + DEK destruction (`/v1/admin/erasure`), per-source retention workers, DSAR export CLI; `verity backup`/`restore` with the §11b ordering and fail-closed restore.
- `verity dev` single binary with the **read-only scope-inspector web UI** (+ freshness/backfill dashboards).
- **The "Scoped Recall Benchmark" v0** (branded, open, reproducible) — five metrics defined, **three shipped at launch:** (1) cross-entity/tenant leakage rate under adversarial probes incl. prompt injection — target **0**; (2) stale-fact citation rate after a CDC update — target **~0%**; (4) p95 scoped-read latency vs corpus size *and vs QPS*, local-encoder and remote-embedder curves labeled separately. **(3) per-connector freshness lag ships as the public dashboard in v0.2; (5) entity-tagger recall ships with probabilistic tagging in v0.3.** Whoever defines the metric owns the category conversation; defining all five now and shipping honestly-labeled subsets beats shipping five rushed numbers.

### Launch demo (the whole pitch in one screen)
A CrewAI agent and a Claude agent share memory about the same account. (1) Edit a deal amount in HubSpot → both agents cite the new value in **<5 seconds**, with provenance and `valid_from`. (2) A session scoped to customer A is **actively prompt-injected** to fetch customer B's quote — and provably fails, with the attempt visible in the audit log and the scope inspector showing exactly why. (3) An agent `remember`s an observation and retrieves it in its next turn — then a second agent sees it seconds later. (4) One command rolls back everything derived from a poisoned observation; one admin command crypto-shreds a departed contact's data and prints the signed purge report.

**Explicitly out of v0.1:** Salesforce connector + Microsoft Graph/SCIM directory sync (v0.2), remaining framework adapters (v0.2), freshness public dashboard / benchmark metric 3 (v0.2), admin-mutating web UI incl. schema-drift mapping UI (v0.2; CLI covers it at launch), Temporal (v0.3, before managed fleet), Qdrant scale profile + tiered multitenancy (v0.3), L2 LLM fact extraction + probabilistic entity tagging + benchmark metric 5 + sleep-time consolidation (v0.3), native multimodal embedding (v0.x per §10), `subscriptions/listen` (v0.2), Merge.dev long-tail connector (v0.3 — File Storage category first, per §5d), Nango OAuth layer for community connectors (v0.4), embedding-model migration tooling (v0.2 — the dual-vector schema exists at launch; the orchestrated cutover tool follows).

---

## 14. Risks & Open Decisions Needing the Founder's Call

### Accepted risks (with mitigations)
1. **Filtered-ANN latency at our filter cardinality is unproven.** ACORN can run 2–10x slower under restrictive filters. Mitigation: week-1 measurement task (now including QPS-under-load and encoder throughput); pinned-brief/`get` path (~5ms, ANN-independent) for the inner loop; sparse mode as a no-encoder floor; publish measured curves only; native-index experiment held in reserve behind the adapter trait.
2. **ACL-grant staleness window (seconds).** Revocations are closed synchronously via ack-confirmed tombstones; grants propagate via SpiceDB's Watch API with the SLO derived from measured Watch delivery; `restricted` class gets mandatory ZedToken-pinned live recheck. The window is **disclosed as an SLO** — reviewers forgive bounded, disclosed windows; they fail vendors who claim "instant."
3. **Connector ACL- and identity-mapping fidelity is the real leak surface** (Salesforce implicit sharing, territory hierarchies, Drive inheritance, nested Google Groups, email-keyed fallback links). Mitigation: ACL *and identity* conformance tests as load-bearing, per-connector; email mapping off by default and risk-labeled; quarantine-not-index on unmappable ACLs/principals; the truth lane's full crawl as permission backstop.
4. **Self-host footprint is heavy** (Postgres + SpiceDB + workers + optional Qdrant/Valkey). The dev binary masks this for the funnel; compose/Helm plus the §11b/§11c runbooks make production honest. We will *not* treat friction as a monetization lever — cloud sells operations, not relief from sandbagging.
5. **Unstructured-source correctness is probabilistic** — L2 depends on LLM extraction (5–30% error rates on weak backbones), and inferred entity tags share that character. Trust-tier ranking, quarantine-by-default, zero-tag semantics, and the public tagger-recall metric make this visible rather than pretending to solve it; L1 always outranks L2; deterministic provenance tags carry the architectural guarantee.
6. **Competitive window is 12–18 months** (Airbyte Context Store, Weaviate Engram, Cognee are each one roadmap item from permission-aware retrieval). Our moat is that ACL inheritance + identity stitching + deterministic supersession + scope-soundness + the compliance plane are the hardest things to retrofit; the benchmark defines the terms of comparison. Ship fast.
7. **MCP 2026-07-28 is an RC** (final publication July 28, 2026). Stateless-first is the right bet; the gRPC/REST substrate is the real interface, so spec drift is bounded rework.
8. **Purpose-binding ceremony may frustrate early developers.** Default dev-mode scopes are permissive-single-tenant; strictness ramps with configuration; the starter policy pack lowers authoring cost. Product taste in scope granularity is a first-100-users listening exercise.
9. **Two-language split (Rust core / Python ingestion) taxes a small team** — and the v1.1 staffing assumption (2 engineers + AI-agent-assisted development) makes this sharper. Accepted: Python near the read path forfeits the thesis; Python workers + SDKs remain the community contribution surface; the AI-assisted-development assumption is itself listed as a risk — if velocity misses, the §13 cut order is: Debezium envelope → media path → benchmark metric 4's QPS curve, never the scope plane or compliance plane.
10. **Local-encoder retrieval quality vs. large remote embedders.** A 30M-parameter encoder trades some recall quality for latency sovereignty. Mitigation: hybrid fusion with BM25 recovers much of the gap; BYO remote path exists (honestly labeled slower); the §5c migration machinery means the default can be upgraded without a rebuild-the-world event; retrieval-quality eval runs alongside the latency benchmark.
11. **Crypto-shredding key management is now load-bearing.** A lost KEK is a self-inflicted erasure event. Mitigation: KMS-backed KEK in production, documented key-backup runbook with the recency check, and dev-mode keys clearly labeled non-production.

### Founder decisions required
1. **Name — DECIDED (2026-07-09): Verity.** Repo, binary (`verity`), and docs use it now; trademark/domain clearance still required before any public artifact.
1b. **Long-tail connectors — DECIDED (2026-07-09): Merge.dev** per §5d (flagships stay native for freshness + CRM ACL fidelity; Merge covers the 240+ long tail, held by Verity Cloud; Nango as optional OAuth layer for community connectors). Full evaluation in `docs/research/MERGE-EVALUATION.md`.
2. **Commercial entity vs. connector-repo governance.** How binding do we make the never-paywall covenant (separate foundation-style governance for the connector repo vs. company-owned with a public covenant)? Recommendation in spec: company-owned + MIT protocol + separate repo; founder to ratify.
3. **Design-partner strategy for Salesforce (v0.2).** The Pub/Sub connector needs a funded dev-org matrix and a customer with the CDC add-on license. Pick 1–2 design partners now — ideally one with a deep role-hierarchy org to harden the BatchCheck and identity-crosswalk fixtures against reality.
4. **Cloud timing.** Does the managed service (and therefore Temporal, multi-tenant control plane, SOC 2 track) start in parallel with OSS v0.2, or after OSS traction (e.g., 2k stars / 5 design partners)? Spec assumes the latter; this is a fundraising-dependent call.
5. **Benchmark governance.** Do we seek a neutral co-publisher (academic lab or the W3C CG) for the Scoped Recall Benchmark at launch, trading speed for credibility? Recommendation: launch solo with a fully reproducible harness, invite co-governance in v2.
6. **Latency marketing line.** Approve the exact public claim: "**sub-50ms p95 server-internal scoped recall — including local query encoding — and ~5ms entity reads: measured, published, reproducible. Remote-embedder configurations excluded and labeled.**" Every future number goes on the public dashboard first, marketing second.

*(Resolved since v1.0: the ReBAC engine decision — SpiceDB, §7a — was removed from this list because the Watch-API capability difference made it an architecture question, not a preference question.)*

---

*This document is the build contract. Where implementation reality contradicts a number in this spec, the number changes publicly and the dashboard is the source of truth — that policy is itself the product.*
