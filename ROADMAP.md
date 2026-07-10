# Verity Roadmap — what's built, what's left

> Status as of 2026-07-10. The build contract is [SPEC.md](SPEC.md) (v1.4); measured
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

## 🔨 v0.1 close-out — ✅ SHIPPED 2026-07-10

Every item landed with tests (37 Rust + 33 Python, scope fuzzer green). As-built notes
mark where the v0.1 slice is narrower than the original line item — those deltas roll
into v0.2/v0.3.

**Ingestion DX (§5e.7 v0.1 slice):**
- [x] `verity-cli`: `dev` / `add <file|dir|url|->` (required `--visibility`, teaching refusal) / `query` / `webhook mint` / `tail` / `mcp install` / `status`. *As built: dev uses docker-compose Postgres; the single-binary embedded mode is future.*
- [x] Minted scoped webhook URLs: narrow-only visibility, native payload → episode+chunk+facts, unknown shapes → quarantine preview, revocation
- [x] MCP write tools: `ingest_text`, `ingest_file`, `ingest_url`, `forget` (13 tools total)
- [x] ACL provenance tag on every fact/chunk (`mirrored|approximated|admin-assigned|quarantined`), surfaced on reads
- [x] `POST /v1/files` multipart + paragraph chunking + embedding. *As built: Rust-native text-like handling; `unstructured`/PDF parsing is v0.2.*
- [x] Admin/ingest bearer auth (constant-time; dev-mode warn when unset)

**Scope plane completion (Milestone B):**
- [x] SpiceDB integration (HTTP gateway seam): schema, nested groups, subject-resolved `open_scope` (422 on self-asserted principals when live). *As built: resolution at mint + windowed re-read subtraction; Watch-driven index materialization is v0.2.*
- [x] Identity: canonical principal registry (`/v1/admin/principals`), group management API, Drive connector principal crosswalk. *As built: Google Admin SDK directory sync not yet — groups arrive via API/connectors.*
- [x] Revocation tombstones: durable-before-delete, windowed subtraction at mint AND read time (cold-start safe by durability). *Replica fan-out is v0.2 with the changelog.*
- [x] Restricted-class live recheck against fresh membership; restricted DROPPED when ReBAC off (fail closed, env override for dev)
- [x] Purpose packs (YAML): confidentiality clamp + entity-scope requirements at mint
- [x] Audit log on every scoped read + admin query endpoint
- [x] Read-your-writes: holds by construction (remember indexes synchronously in-process); the cross-replica write-through buffer arrives with multi-replica serving
- [x] `memory.forget` (chunk/episode) + knowledge retraction cascade (support recount → invalidated below k)

**Connectors (truth lane):**
- [x] HubSpot: BYOT private-app token, search-API cursor polling, v3 webhook payload mapping, Debezium-envelope sink, 12 conformance tests. *Webhook subscriptions are UI-configured (HubSpot limitation).*
- [x] Google Drive: BYOT service account, changes.list cursor, permissions.list → AclEnvelope (Tier A mirroring), ACL-before-content, anyone→quarantine, 21 conformance tests. *Docs export + text download; Docling/PDF parsing is v0.2.*

**Multimodal v0.1 commitment:**
- [x] MediaObject store (sha256, bytea) + HMAC-signed scope-checked media URLs; text-like files chunk+embed on upload. *Lance/S3 blob tier and media-backed recall citations are v0.3.*

**Honesty debts (benchmarks):**
- [x] Load benchmark: ~170 QPS saturation (M3 Pro), queueing curve recorded; §4d cloud-shape run still owed before any public QPS claim
- [x] Entity-bound + broad-visibility BM25: breach found (542ms) and fixed (12.6ms p50) via keyword-tokenized Tantivy pre-filter + materialized residual

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
