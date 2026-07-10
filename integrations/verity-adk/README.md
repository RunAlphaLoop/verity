# verity-adk

Verity [`BaseMemoryService`](https://google.github.io/adk-docs/sessions/memory/)
for Google ADK: long-term agent memory written through Verity's permission
plane instead of a bare in-memory dict or a Vertex-hosted memory bank.

**This is the snapshot-grade convenience lane** (SPEC §5e.4, §9c): this lane
is always policy-based — `visibility_policy` is a **required constructor
argument with no default**, everything written carries
`acl_provenance="admin-assigned"`, and anything arriving without a policy is
quarantined, never permissively indexed.

## How it maps

| ADK call | Verity call |
| --- | --- |
| memory scope `(app_name, user_id)` | entity tag `adk:<app>/<user>` |
| `add_session_to_memory(session)` | `POST /v1/ingest/documents` (admin token) per text-bearing event — `document_id = "adk/<app>/<user>/<session>/<event>"` |
| `add_events_to_memory(...)` | same, for explicit event deltas (`session_id` optional) |
| `search_memory(app_name=, user_id=, query=)` | `POST /v1/scopes` (entity-scoped) then `POST /v1/recall` → `SearchMemoryResponse` |

Event author, role, and timestamp are preserved in the stored envelope and
returned on `MemoryEntry`. Re-adding a session is idempotent: stable
per-event document ids mean a re-ingest is a bi-temporal supersede, never a
duplicate memory. Embeddings are computed **server-side**;
`custom_metadata` is not supported in the sink lane.

## Example

```python
from google.adk.runners import Runner
from verity_adk import VerityMemoryService

memory_service = VerityMemoryService(
    verity_url="http://127.0.0.1:7717",
    tenant_id="<tenant uuid>",
    admin_token="<VERITY_ADMIN_TOKEN>",   # write plane
    visibility_policy=[3, 7],             # REQUIRED: materialized principal tokens
)
runner = Runner(agent=agent, app_name="calendar",
                session_service=session_service, memory_service=memory_service)

await memory_service.add_session_to_memory(completed_session)
hits = await memory_service.search_memory(
    app_name="calendar", user_id="alice", query="dentist appointment")
```

Mint principal tokens with `POST /v1/admin/principals`. Omitting
`visibility_policy` raises a teaching error — bypass is impossible, not
discouraged.

Verified against `google-adk` 2.4.0 (`BaseMemoryService`:
`add_session_to_memory` / `add_events_to_memory` / `search_memory`).

## Tests

```bash
../.venv/bin/pytest tests/   # mock-based; asserts exact request bodies
```
