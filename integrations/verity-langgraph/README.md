# verity-langgraph

Verity [`BaseStore`](https://langchain-ai.github.io/langgraph/reference/store/)
adapter for LangGraph: long-term agent memory written through Verity's
permission plane instead of a bare KV store.

**This is the snapshot-grade convenience lane** (SPEC §5e.4): this lane is
always policy-based — `visibility_policy` is a **required constructor
argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed.

## How it maps

| LangGraph call | Verity call |
| --- | --- |
| namespace tuple `("agents", "alice")` | entity tag `ns:agents/alice` |
| `put(ns, key, value)` | `POST /v1/ingest/documents` (admin token) — `document_id = "agents/alice/<key>"`, content = sorted JSON |
| `search(ns, query=...)` | `POST /v1/scopes` (entity-scoped, minted from the policy) then `POST /v1/recall` |
| `search(ns)` / `get(ns, key)` | `GET /v1/briefs/ns:agents/alice` (newest-first listing) |
| `delete(ns, key)` | `POST /v1/forget` (invalidate-don't-delete) |

Embeddings are computed **server-side**; `put(index=...)`, `ttl` and
`search(filter=...)`/`list_namespaces()` are not supported in the sink lane.
Query-less listing and `get` read through the entity brief (newest 10 chunks).

## Example

```python
from verity_langgraph import VerityStore

store = VerityStore(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",          # write plane
    visibility_policy=[3, 7],                     # REQUIRED: materialized principal
)                                                 # tokens allowed to read this data

namespace = ("agents", "alice")
store.put(namespace, "food-preference", {"preference": "vegetarian"})

item = store.get(namespace, "food-preference")
hits = store.search(namespace, query="what does alice eat?", limit=5)

store.delete(namespace, "food-preference")        # invalidate-don't-delete

# Or wire it into a graph: StateGraph(...).compile(store=store)
```

Mint principal tokens with `POST /v1/admin/principals`. Omitting
`visibility_policy` raises a teaching error — bypass is impossible, not
discouraged.

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
