# Verity

**The open-source, permission-aware shared context plane for enterprise AI agents** — always fresh from systems of record, provably scoped, fast enough for the inner loop.

Enterprises run agents across sales, support, marketing, and ops, but each agent is an island: the context they need lives in CRMs, ticketing systems, docs, and wikis. Verity mirrors those systems of record into a bi-temporal memory store via CDC/webhooks, inherits source ACLs into a Zanzibar-style permission graph, compiles caller scope into every retrieval as a mandatory pre-filter, and serves scoped hybrid recall — exposed MCP-first to any agent framework.

**Status: pre-alpha.** Milestone A ("the engine is honest") is under construction. See [SPEC.md](SPEC.md) — the build contract — and [docs/research/](docs/research/) for the research that produced it.

## The three claims

1. **Provable scoping** — an agent talking to customer A can never surface customer B's pricing. Enforcement is architectural (in-index pre-filters from a ReBAC permission graph, fail-closed), never delegated to the model.
2. **Live truth** — source change to queryable in seconds. "Opportunity updated" is a deterministic keyed upsert that structurally retires the old value; no LLM in the write path for structured data.
3. **Inner-loop speed** — target <50ms p95 scoped recall (including local query encoding) and ~5ms entity/brief point reads. Every published number is measured, never vendor-quoted.

## Layout

```
crates/verity-core      # types, bi-temporal memory model, StorageAdapter trait
crates/verity-storage   # Postgres profile (pgvector + pg_search) adapter
crates/verity-server    # API plane: REST now; MCP + gRPC to follow
crates/verity-bench     # the week-1 honesty benchmark: filtered-ANN latency at real ACL selectivity
ingest/                 # Python ingestion plane: connectors, enrichment (never on the read path)
migrations/             # SQL migrations (L0 evidence log, L1 bi-temporal facts, chunks)
deploy/                 # docker-compose for the Postgres profile
```

## Quickstart (dev)

```sh
docker compose -f deploy/docker-compose.yml up -d   # Postgres 17 + pgvector + pg_search
cargo run -p verity-bench -- seed --chunks 100000   # synthetic corpus with realistic ACL shape
cargo run -p verity-bench -- run                    # p50/p95/p99 latency: filtered ANN, point reads
```

## License

Apache 2.0, permanently. One codebase. Nothing security-critical ever paywalled.
