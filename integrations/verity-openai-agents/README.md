# verity-openai-agents

Verity [`Session`](https://openai.github.io/openai-agents-python/ref/memory/session/)
backend for the OpenAI Agents SDK: conversation history written through
Verity's permission plane instead of a bare SQLite file.

**This is the snapshot-grade convenience lane** (SPEC §5e.4, §9c): this lane
is always policy-based — `visibility_policy` is a **required constructor
argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed.

## How it maps

| Session call | Verity call |
| --- | --- |
| item *n* of session `conv-42` | document `session:conv-42/item:<n>`, entity tag `session:conv-42` |
| `add_items(items)` | `POST /v1/ingest/documents` (admin token), one document per item |
| `get_items(limit)` | `POST /v1/scopes` (entity-scoped) then `POST /v1/recall` + client-side `seq` ordering |
| `pop_item()` | `POST /v1/forget` on the newest item's episode (invalidate-don't-delete) |
| `clear_session()` | `POST /v1/forget` per item episode |

**Documented read-back choice:** `get_items` uses `/v1/recall` (query text =
session id, which appears in every stored envelope; the dense leg
independently returns everything inside the entity scope), not
`GET /v1/briefs/{entity}` — the brief caps at the newest 10 chunks, recall
returns the server's full k=100 window. Sessions longer than 100 chunks
exceed that window (documented v0.2 limit).

## Example

```python
from agents import Agent, Runner
from verity_openai_agents import VeritySession

session = VeritySession(
    "conv-42",
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",   # write plane
    visibility_policy=[3, 7],             # REQUIRED: materialized principal tokens
)
agent = Agent(name="assistant", instructions="Reply concisely.")
result = await Runner.run(agent, "What's on my calendar?", session=session)
```

Mint principal tokens with `POST /v1/admin/principals`. Omitting
`visibility_policy` raises a teaching error — bypass is impossible, not
discouraged.

Verified against `openai-agents` 0.18.1 (the `Session` runtime-checkable
protocol: `get_items` / `add_items` / `pop_item` / `clear_session`).

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
