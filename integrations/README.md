# Verity framework integrations

Drop-in, permission-aware memory for the agent frameworks you already use. Each
adapter backs the framework's own memory interface with a Verity server, so
retrieval is filtered by a mandatory pre-filter in the index: a caller only ever
gets back what its scope allows, and a missing scope fails **closed** (empty),
never open.

| Package | Framework | Binds to |
| --- | --- | --- |
| `verity-langchain` | LangChain | `VectorStore` + `Retriever` (+ subject-bound retriever) |
| `verity-langgraph` | LangGraph | `BaseStore` |
| `verity-llamaindex` | LlamaIndex | `VectorStore` |
| `verity-crewai` | CrewAI | storage backend |
| `verity-adk` | Google ADK | memory service |
| `verity-openai-agents` | OpenAI Agents SDK | session |

## The two lanes (read this first)

- **Policy-based (the sink lane, SPEC §5e.4).** Ecosystem loaders strip whatever
  access controls the source system had, so on this lane you assign visibility
  **explicitly at ingest** via a `visibility_policy` (a list of materialized
  principal tokens). This lane does **not** mirror your Google Drive / Salesforce
  ACLs. That is a deliberate limit, and the constructor fails closed if you omit
  the policy.
- **Subject-bound reads (LangChain today).** A retriever can bind to a real
  `subject` (e.g. `user:alice@acme`) and let the server resolve what they may see
  through the permission graph (ReBAC). The agent never holds a token; group
  membership is resolved server-side.

## Quick start (LangChain)

```bash
pip install -e verity-langchain          # from this repo, for now
# a Verity server on :7717 — e.g. `verity dev`
```

```python
from verity_langchain import VerityVectorStore

# Policy-based lane: you assign the visibility tokens at ingest.
store = VerityVectorStore(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant-uuid>",
    visibility_policy=[1],               # required, no default (fails closed)
    admin_token="<admin-token>",         # writes are admin-gated
)

store.add_texts(
    ["Acme renewed for 240 seats on 2026-06-30."],
    metadatas=[{"verity_entities": ["account:acme"]}],
)

# Reads mint a scope from that same policy and pre-filter in the index.
docs = store.as_retriever(search_kwargs={"k": 4}).invoke("Acme renewal seats")
```

### Subject-bound reads (ReBAC inheritance)

Bind a **read-only** retriever to a real person and let the server resolve their
group membership. If `all-staff ⊃ engineering ⊃ alice`, alice inherits what
`all-staff` can see; someone in no group stays dark. Requires the server to be
running with ReBAC (`VERITY_SPICEDB_URL`).

```python
alice = VerityVectorStore.subject_retriever(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant-uuid>",
    subject="user:alice@acme.example",   # a subject, not a token
    k=10,
)
docs = alice.invoke("engineering roadmap")   # only what alice's groups can read
```

There is intentionally no write path on the subject retriever: writes stay
policy-based. A subject read never widens visibility, it resolves the caller's
real, already-granted powers.

## Prove it yourself: the conformance harness

`integrations/e2e/` drives each framework's **real** memory API against a live
server and asserts the isolation boundary: team A writes a secret, team B runs a
query that matches it, and gets nothing of team A's back.

```bash
# real frameworks, real server, real Postgres (dev DB on :5433)
bash integrations/run_e2e.sh
```

Run only the LangChain subject-inheritance test (needs SpiceDB, e.g. `verity dev`):

```bash
VERITY_SPICEDB_URL=http://localhost:8443 VERITY_SPICEDB_KEY=verity-dev-key \
  integrations/run_e2e.sh integrations/e2e/test_langchain_subject_e2e.py
```

Each framework gets a write/read roundtrip, a cross-team isolation check, and a
fail-closed construction check. The harness is a test suite against synthetic
tenants, not a third-party audit. See [HONESTY.md](../HONESTY.md) for what Verity
does not do yet.
