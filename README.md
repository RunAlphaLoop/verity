# Verity

**The open-source, permission-aware shared context plane for enterprise AI agents** — always fresh from systems of record, provably scoped, fast enough for the inner loop.

Enterprises run agents across sales, support, marketing, and ops, but each agent is an island: the context they need lives in CRMs, ticketing systems, docs, and wikis. Verity mirrors those systems of record into a bi-temporal memory store via CDC/webhooks, inherits source ACLs into a Zanzibar-style permission graph, compiles caller scope into every retrieval as a mandatory pre-filter, and serves scoped hybrid recall — exposed MCP-first to any agent framework.

**Status: v0.1.** The engine is measured (<50ms p95 every retrieval path at 1M chunks,
query encoding included), the scope plane is fuzzed in CI, identity resolves through
SpiceDB, and the ingestion funnel is live (CLI, MCP, minted webhooks, file drop,
HubSpot + Google Drive connectors, Debezium CDC). See [SPEC.md](SPEC.md) — the build contract — and [docs/research/](docs/research/) for the research that produced it.

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

## Prerequisites

- **Docker**, running — `verity-cli dev` brings up the dev stack (Postgres/ParadeDB + SpiceDB + MinIO) via `docker compose`. Give Docker ~8 GB RAM.
- **Rust**, stable — the toolchain is pinned in `rust-toolchain.toml`, so `rustup` selects it automatically.
- **A C toolchain + build deps** for native crates (`rustup` does not ship a linker). On Debian/Ubuntu: `sudo apt install build-essential pkg-config libssl-dev cmake`. On macOS: `xcode-select --install`.
- ~20 GB free disk for container images and the release build.

## Quickstart (dev)

Run these from the repo checkout. **The first run builds the workspace from source and downloads a small local embedding model — budget ~15 minutes.** Every run after that starts in seconds.

```sh
cargo run --release -p verity-cli -- dev                             # compose up + server + tenant + org-wide scope handle
cargo run --release -p verity-cli -- add ./docs --visibility 1       # ingest a directory (visibility is required, never guessed)
cargo run --release -p verity-cli -- query "what do we know about pricing?"   # scoped hybrid recall with provenance tags
cargo run --release -p verity-cli -- webhook mint my-system --visibility 1    # any system that can POST JSON is now a source
```

Prefer `cargo install --path crates/verity-cli` to shorten `add`/`query`/`webhook` to bare `verity-cli ...` (they only talk to the server over HTTP). Note that `verity-cli dev` must still run from the repo checkout — it discovers the compose file and server binary relative to the source tree.

Benchmarks (`docs/BENCHMARKS.md` is the honesty log — every number measured, never quoted):

```sh
cargo run -p verity-bench -- seed --chunks 100000   # synthetic corpus with realistic ACL shape
cargo run -p verity-bench -- run                    # p50/p95/p99 per path; load --sweep for QPS
```

## Connect an agent (MCP)

`verity-mcp` is a stdio MCP server any MCP-capable agent (Claude Code, LangGraph,
CrewAI, ...) can use. Identity comes from the environment, never from tool arguments:

Use the tenant UUID and principal token that `verity-cli dev` printed (on a fresh `dev` tenant the `user:dev` token is `1`):

```sh
claude mcp add verity \
  -e VERITY_TENANT_ID=<tenant-uuid> -e VERITY_PRINCIPALS=1 \
  -e VERITY_ACTOR_SUB=user:you -e VERITY_ACTOR_AZP=agent:claude-code \
  -- /path/to/target/release/verity-mcp
```

Tools: `memory_open_scope` (mint a session scope), `memory_recall` (scoped hybrid
search), `memory_get` (bi-temporal record read), `memory_remember` (write an
observation), `memory_record_action` / `memory_activity` (the cross-agent activity
timeline — check what other agents did before acting), `memory_whoami`.

## License

Apache 2.0, permanently. One codebase. Nothing security-critical ever paywalled.
