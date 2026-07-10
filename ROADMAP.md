# Verity Roadmap — what's built, what's left

> Status as of 2026-07-09. The build contract is [SPEC.md](SPEC.md) (v1.4); measured
> numbers live in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Estimates assume the
> spec's staffing model: 2 engineers + AI-assisted development.

## ✅ Built and verified

**Engine (Milestone A — complete):**
- Bi-temporal L0/L1 store with deterministic supersession; chunk store; `StorageAdapter` seam
- Postgres profile: pgvector HNSW + pg_search BM25, selectivity router, BM25 term_set pushdown
- L1 current-truth cache (invalidate-on-write, coherence-tested)
- Local ONNX query encoder (MiniLM, 11ms p50) wired into recall
- **Measured at 1M chunks: every retrieval path <50ms p95, encoder included**

**Scope plane (Milestone B — started):**
- HMAC MemoryScope handles; all verbs enforce from the signed payload only
- Fail-closed everywhere; entity scoping (deny-by-default intersection); confidentiality ceilings
- Scope-soundness fuzzer in CI (4 read paths, adversarial corpus, independent predicate model)

**Product surface:**
- Action records + scoped activity timeline (cross-agent awareness)
- Entity briefs (one-call current state)
- Knowledge layer, deterministic slice: de-id gate, k-support, publish, §7g carve-out
- Debezium CDC ingestion (31ms POST-to-queryable) + bi-temporal `as_of` reads
- MCP server (9 tools), REST API, launch demo script, CI with live database

---

## 🔨 v0.1 close-out (the founder answer + security spine) — ~6–8 weeks

**Ingestion DX (§5e.7 v0.1 slice):**
- [ ] `verity` CLI: `dev` (embedded server + bundled embeddings), `add <file|dir|url|->` with required `--visibility`, `webhook mint`, `tail`, `query`, `mcp install` (2–3 wks — the 5-minute wow lives here)
- [ ] Minted scoped webhook URLs (static visibility binding; native payload shape; quarantine-preview) (1–1.5 wks)
- [ ] MCP write tools beyond `remember`: `ingest_text`, `ingest_file`, `ingest_url` (2–4 days)
- [ ] ACL provenance tag on every fact (`mirrored|approximated|admin-assigned|quarantined`) (days — retrofit-expensive later)
- [ ] `POST /v1/files` via `unstructured` in the Python plane (1 wk)
- [ ] Connector/admin/ingest auth tokens (the documented trusted-plane seam) (days)

**Scope plane completion (Milestone B):**
- [ ] SpiceDB integration: sidecar/child-process packaging, Watch-driven visibility materialization, principal expansion pre-paid at `open_scope` (2–3 wks)
- [ ] Identity Plane: canonical principal registry, Google Admin SDK directory sync (nested groups), per-connector crosswalks, conformance fixtures (2 wks)
- [ ] Revocation tombstones: changelog durability, replica fencing, cold-start fail-closed replay (1–1.5 wks)
- [ ] Mandatory live BatchCheck on `restricted`-class results (days)
- [ ] Purpose binding via YAML policy packs (1 wk)
- [ ] Audit log of every `(subject, scope, results)` tuple (days)
- [ ] Session write-through buffer — read-your-writes for `remember`→`recall` (1 wk)
- [ ] `memory.forget` (audited invalidation) + knowledge retraction cascade (1 wk)

**Connectors (truth lane):**
- [ ] HubSpot native connector: private-app token, v4 webhooks + journal, field/ACL/identity conformance tests (2 wks)
- [ ] Google Drive native connector: `changes.watch` + poll fallback, Docling/unstructured parsing, **Drive ACL inheritance** (2–3 wks)

**Multimodal v0.1 commitment:**
- [ ] MediaObject store + retrieve-by-text/answer-from-pixels with scope-bound signed URIs (1–1.5 wks)

**Honesty debts (benchmarks):**
- [ ] QPS-under-load + concurrency benchmark (spec has no load numbers yet) (days)
- [ ] Entity-bound + broad-visibility BM25 bench case (heap-filter regression risk noted in 0004) (day)

## 📦 v0.2 — the multiplier (~4–6 weeks)

- [ ] Framework sinks: `VerityVectorStore` (LlamaIndex) + LangChain package — 400+ loaders inherited (2 wks)
- [ ] LangGraph `BaseStore` adapter; others fast-follow (1 wk each)
- [ ] Credential-lifecycle abstraction (4 shapes + expiry telemetry + webhook-health hooks) (1.5–2 wks)
- [ ] Credential wizards: `verity connect slack` (Socket Mode), `verity connect github` (1 wk)
- [ ] Salesforce connector (customer-created Connected App + CDC Pub/Sub; needs design partner) (3+ wks)
- [ ] `subscriptions/listen` + webhook/SSE change notifications (1 wk)
- [ ] Read-only scope-inspector web UI + freshness/backfill dashboards (2–3 wks)
- [ ] Freshness SLO instrumentation (p50/p95 source-change-to-queryable per connector) (1 wk)
- [ ] Compliance plane v0: envelope encryption/DEK plumbing, hard-purge pipeline, DSAR export CLI, `verity backup/restore` with §11b ordering (3 wks)
- [ ] pg_net/Supabase trigger snippet + docs (1–2 days)

## 🏗 v0.3 — the scaling substrate (~6–8 weeks)

- [ ] Source manifests v1: schema + Rust interpreter (JSONata mapping, predicate routing, `acl_policy` tiers, admin approval gate) + conformance harness + community registry repo (5–6 wks)
- [ ] L2 extraction: async LLM fact extraction, `(subject, relation)` supersession, sleep-time consolidation workers (3–4 wks)
- [ ] Knowledge consolidation worker: cross-scope clustering, similarity-merge on propose, support accrual (2 wks)
- [ ] L3 materialized briefs with lineage, staleness metadata, derived-scope inheritance (2 wks)
- [ ] Probabilistic entity tagging + quarantine thresholds + tagger-recall benchmark metric (2 wks)
- [ ] Qdrant scale profile behind the `StorageAdapter` trait (2–3 wks)
- [ ] Temporal for the ingest plane (required before any managed connector fleet) (2 wks)
- [ ] Embedding-model migration tooling (dual-vector cutover orchestration) (1 wk)
- [ ] Scoped Recall Benchmark v0 as a branded, reproducible public harness (2 wks)

## ☁️ Cloud / later (fundraising-dependent)

- Managed connector fleet (Merge relationship, hosted webhook endpoints, freshness SLAs)
- OAuth concierge (verified shared apps + callback relay, Tailscale-style token handoff)
- Multi-tenant control plane, SSO/SCIM, SOC 2 track, managed inference
- LLM manifest-authoring MCP; MCP 2025-11-25 auth for our own server
- Webhook relay for firewalled self-hosters

## Open founder decisions (SPEC §14)

- Cloud timing (parallel with OSS v0.2 vs after traction)
- Salesforce design partners (1–2 needed for the v0.2 connector)
- Benchmark governance (solo launch vs neutral co-publisher)
- Trademark/domain clearance for "Verity" before anything public
