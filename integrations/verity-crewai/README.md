# verity-crewai

Verity [`StorageBackend`](https://docs.crewai.com/en/concepts/memory) for
CrewAI's unified memory: crew memory written through Verity's permission
plane instead of a local LanceDB file.

**Interface note (researched July 2026):** SPEC §9c names CrewAI's
`ExternalMemory` plug point; CrewAI 1.x removed it in the unified-memory
rewrite. The current plug point is the `StorageBackend` protocol
(`crewai.memory.storage.backend`), wired as `Memory(storage=...)` and
`Crew(memory=Memory(...))`. This package implements that protocol; verified
against crewai 1.15.2.

**This is the snapshot-grade convenience lane** (SPEC §5e.4, §9c): this lane
is always policy-based — `visibility_policy` is a **required constructor
argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed.

## How it maps

| CrewAI call | Verity call |
| --- | --- |
| scope path `/crew/research` | entity tag `crew:/crew/research` (exact — Verity entity scoping is subset-semantics over exact tags, so hierarchical `scope_prefix` filters apply client-side; visibility is always the server-side boundary) |
| `save(records)` | `POST /v1/ingest/documents` (admin token) — `document_id = "crewai/<record id>"`, content = JSON envelope |
| `search(query_embedding, ...)` | `POST /v1/scopes` then `POST /v1/recall` with the **query text** (see the embedder shim); `scope_prefix`/`categories`/`metadata_filter`/`min_score` applied client-side |
| `update(record)` | same-document-id re-ingest — bi-temporal supersede, never UPDATE-in-place |
| `delete(record_ids=...)` | `POST /v1/forget` (invalidate-don't-delete); predicate deletes fail closed |
| `reset(scope_prefix)` | `POST /v1/forget` for everything **this instance** wrote in scope — cross-session hard purge is the §8 admin erasure pipeline, deliberately unreachable from a sink |
| `get_scope_info` / `list_scopes` / `list_categories` | not supported in the sink lane (`NotImplementedError`) |

**The embedder shim (required wiring):** CrewAI hands `search()` only an
embedding, never the query text, while Verity encodes queries **server-side**
(read-path purity — a sink cannot inject foreign vectors into the server's
index). `storage.embedder` is a deterministic hash-based pseudo-embedder:
CrewAI treats it as a normal embedding callable, and the storage maps its
vectors back to the original text and forwards the text leg of
`POST /v1/recall`. A foreign embedder's vector fails closed with a teaching
error. Read-backs list at most the server's recall window (k=100).

## Example

```python
from crewai import Agent, Crew, Task
from crewai.memory import Memory
from verity_crewai import VerityStorage

storage = VerityStorage(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",   # write plane
    visibility_policy=[3, 7],             # REQUIRED: materialized principal tokens
)
memory = Memory(storage=storage, embedder=storage.embedder)  # both, always
crew = Crew(agents=[...], tasks=[...], memory=memory)
```

Mint principal tokens with `POST /v1/admin/principals`. Omitting
`visibility_policy` raises a teaching error — bypass is impossible, not
discouraged.

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
