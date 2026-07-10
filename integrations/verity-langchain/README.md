# verity-langchain

Verity sink for [LangChain](https://github.com/langchain-ai/langchain): a
`VectorStore` + `BaseRetriever` pair that turns 100–200+ community loaders
into de-facto Verity connectors.

**This is the snapshot-grade convenience lane** (SPEC §5e.4): no push
freshness, no per-object ACLs. Loaders strip source ACLs by construction, so
this lane is always policy-based — `visibility_policy` is a **required
constructor argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed. Graduate to a native connector for
mirrored per-object ACLs.

## How it maps

| LangChain call | Verity call |
| --- | --- |
| `add_texts()` / `add_documents()` | `POST /v1/ingest/documents` (admin token) — `visibility` = your policy |
| `similarity_search()` / retriever `invoke()` | `POST /v1/scopes` (minted from the same policy, cached) then `POST /v1/recall` |
| `delete(ids=...)` | `POST /v1/forget` (invalidate-don't-delete; session-local episode tracking) |

Embeddings are computed **server-side** by Verity's local encoder — no
`Embeddings` object is needed; recall is hybrid from the query text alone.

## Example

```python
from verity_langchain import VerityVectorStore

store = VerityVectorStore(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",          # write plane
    visibility_policy=[3, 7],                     # REQUIRED: materialized principal
)                                                 # tokens allowed to read this data

# Any LangChain loader output works; plain texts stand in for one.
store.add_texts(
    ["Acme renewed for 240 seats on 2026-06-30."],
    metadatas=[{"verity_entities": ["account:acme"]}],
    ids=["crm-note-881"],
)

docs = store.similarity_search("Acme renewal", k=4)

retriever = store.as_retriever(search_kwargs={"k": 4})   # VerityRetriever
docs = retriever.invoke("Acme renewal")                  # same scoped recall path
```

Mint principal tokens with `POST /v1/admin/principals`; entity tags ride on
document metadata under `verity_entities`. Omitting `visibility_policy`
raises a teaching error — bypass is impossible, not discouraged.

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
