# verity-llamaindex

Verity sink for [LlamaIndex](https://github.com/run-llama/llama_index): one
`VerityVectorStore` class that turns every LlamaHub reader (300+) into a
de-facto Verity connector.

**This is the snapshot-grade convenience lane** (SPEC §5e.4): no push
freshness, no per-object ACLs. Loaders strip source ACLs by construction, so
this lane is always policy-based — `visibility_policy` is a **required
constructor argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed. Graduate to a native connector for
mirrored per-object ACLs.

## How it maps

| LlamaIndex call | Verity call |
| --- | --- |
| `add(nodes)` | `POST /v1/ingest/documents` (admin token) — one document version per node, `visibility` = your policy |
| `query(VectorStoreQuery)` | `POST /v1/scopes` (minted from the same policy, cached) then `POST /v1/recall` |
| `delete(ref_doc_id)` | `POST /v1/forget` (invalidate-don't-delete; session-local episode tracking) |

Embeddings are computed **server-side** by Verity's local encoder — node
embeddings are ignored on write; `query_str` alone gives hybrid recall.

## Example

```python
from llama_index.core import Document
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.vector_stores.types import VectorStoreQuery
from verity_llamaindex import VerityVectorStore

# Any LlamaHub reader works here; a plain Document stands in for one.
docs = [Document(text="Acme renewed for 240 seats on 2026-06-30.",
                 metadata={"verity_entities": ["account:acme"]})]
nodes = SentenceSplitter().get_nodes_from_documents(docs)

store = VerityVectorStore(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",          # write plane
    visibility_policy=[3, 7],                     # REQUIRED: materialized principal
)                                                 # tokens allowed to read this data
store.add(nodes)

result = store.query(VectorStoreQuery(query_str="Acme renewal", similarity_top_k=4))
for node, score in zip(result.nodes, result.similarities):
    print(score, node.text)
```

Mint principal tokens with `POST /v1/admin/principals`; entity tags ride on
node metadata under `verity_entities`. Omitting `visibility_policy` raises a
teaching error — bypass is impossible, not discouraged.

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
