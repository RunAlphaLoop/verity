# Salesforce ACL Crosswalk — Work-Item Spec

Status: build contract for branch `salesforce-acl-crosswalk`.
Scope: close the **identity gap** between Salesforce Share rows and Verity's cross-source principal
tokens, and wire the resulting principals into per-record `verity_acl`. **No Rust-core changes.**
Everything on `VerityDebeziumSink` (hubspot.py) is source-agnostic and is reused directly.

The **completeness gap remains open** and is called out explicitly (§5): AccountShare rows are a
*subset* of effective Salesforce visibility (OWD + role hierarchy + sharing rules + implicit
parent→child + territories). Provenance stays `"approximated"`. We over-hide, never under-hide.

---

## 0. Invariants (do not violate)

- **Over-hide, never under-hide.** An unresolvable share id is DROPPED; the record still rides the
  admin `--visibility` fallback. A record never gains visibility from an id we could not resolve.
- **Lowercase exactly like the other connectors.** `005` User → `user:<Email.lower()>`, byte-identical
  to what gdrive/gmail/hubspot emit for the same human. This is the cross-source join key.
- **Provenance is `"approximated"`** — never `"mirrored"`. Share rows are a subset.
- **No Rust-core changes.** `POST /v1/admin/groups` and `POST /v1/admin/principals` already exist and
  are nest-capable; do not touch them.
- **Fail closed.** No roster / 403 / unmappable id → admin policy only, never permissive pass-through.
- **Keep the 15 existing SF tests green**, adjusting only the assertions that legitimately change when
  Share rows stop being inert metadata and become resolved `verity_acl` tokens (§7, itemized).

---

## 1. Identity crosswalk

### 1.1 User `005…` → `user:<email.lower()>`
- New query: `SELECT Id, Email, IsActive FROM User WHERE Id IN (<005 ids>)`.
- **Join key is `Email`, lowercased — NOT `Username`.** `Username` is email-formatted but may differ
  from the real address; inactive/integration users with no human `Email` simply do not join and their
  ids are dropped (fail closed). Lowercasing is the load-bearing step that makes the token identical to
  the other connectors.
- Roster entry: `SalesforceUserInfo(email: str)` (frozen). A `005` with empty/absent `Email` yields no
  roster entry.

### 1.2 Group `00G…` → `group:salesforce-group-<id>` + nested GroupMember edges
- Stable principal: `group_principal(id) -> f"group:salesforce-group-{id}"`. Applies to ALL `Type`
  values (Regular, Queue, **Role**, **RoleAndSubordinates**, …); a Role group is represented as a
  group like any other. Because the token derives from the **id alone**, `Group.Type`/`Name`/`RelatedId`
  are NOT needed — so **no `FROM Group` query is issued**; only `GroupMember` (+ `User`) are queried.
- New query: `SELECT GroupId, UserOrGroupId FROM GroupMember WHERE GroupId IN (<00G ids>)`.
  `UserOrGroupId` may be a `005` User OR another `00G` Group → **SF groups nest**, exactly like Google
  Groups. Edge build:
  - member `005…` → resolve via roster → `user:<email.lower()>` (drop if unresolvable).
  - member `00G…` → `group:salesforce-group-<childid>` (a nested-group edge).
- **Transitive closure, cycle-bounded.** GroupMember only gives direct child ids. We must fetch the
  Group/GroupMember rows for every `00G` reachable from the initial share-group set (child groups
  pulled in by a nested edge may themselves be shared-on), expanding breadth-first. Bound the
  expansion with a visited-set (`seen: set[str]`) so a membership cycle (`A⊃B`, `B⊃A`) terminates, and
  a hard depth/size cap (`GROUP_EXPANSION_MAX = 5000` ids) as a backstop. Only the *token* edges are
  mirrored — SpiceDB itself computes transitivity, so we mirror the direct `group⊃member` edges and
  let the serving core close the graph.

---

## 2. Code changes — `ingest/verity_ingest/connectors/salesforce.py`

### 2.1 New module-level helpers (mirror hubspot.py L142-157, L73)
```python
DEGRADED_ACL_SIGNAL = "verity.backfill.degraded_acl"   # same string value as hubspot (connector-agnostic)

def user_principal(email: str) -> str:
    return f"user:{email.lower()}"

def group_principal(group_id: str) -> str:
    return f"group:salesforce-group-{group_id}"

@dataclass(frozen=True)
class SalesforceUserInfo:
    email: str
```

### 2.2 `SalesforceFactEvent` (L121-130) — grow the two attributes the shared sink reads
The sink's `_stamp_record_visibility`/`envelope` read `record_principals` and `record_visibility` via
`getattr`. Add them; keep `share_principals` as the raw pre-resolution field (or drop it and populate
`record_principals` directly — see §3):
```python
@dataclass
class SalesforceFactEvent(FactEvent):
    object_type: str
    visibility_policy: list[int]
    share_principals: list[str] = field(default_factory=list)      # raw 005/00G ids, pre-resolution
    record_principals: list[str] | None = None                     # resolved principal strings (sink reads)
    record_visibility: list[int] | None = None                     # resolved tokens (sink stamps)
```

### 2.3 `principal_for_share` (L260-275) — no longer mint raw-id tokens here
Change it to a pure classifier that returns the *raw share id* + kind, OR fold it into the resolver
(§3). The old behavior (`user:005…` / `group:00G…` raw strings) is removed — those inert strings were
the identity gap. Keep it returning the raw `UserOrGroupId` string so `_account_share_principals`
still collects the per-account id list; resolution happens in §3.

### 2.4 New connector state + roster fetch (mirror hubspot `_fetch_owners` L461-504)
```python
self.roster_degraded: bool = False                 # set True on 403 (mirror owners_degraded)
self.group_edges: dict[str, set[str]] = {}         # group_str -> {member_str,...} for SpiceDB mirror

async def _fetch_roster(self, user_ids, group_ids) -> tuple[dict[str,SalesforceUserInfo], dict[str,set[str]]]:
    """User + Group + GroupMember queries (reuse _query_pages / _get_json).
    Returns (users_by_id, group_edges). 403 on the User OR Group OR GroupMember query
    sets self.roster_degraded=True, returns ({}, {}), prints the DEGRADED_ACL_SIGNAL block."""
```
- Reuse `_query_pages` (L341-347) and `_get_json` (L369-376) — the existing `/query` + `nextRecordsUrl`
  helpers with the 401-retry-once hook. Do NOT add a new HTTP path.
- 403 block copied from hubspot.py L481-490 (adapt the message to name the missing SF object read):
  set `self.roster_degraded=True`, print to stderr, return empties.
- Group expansion loop is BFS over `00G` ids with the `seen` visited-set + `GROUP_EXPANSION_MAX` cap
  (§1.2). Emits `group_edges[group_principal(parent)] = {user_principal / group_principal(child)…}`.

### 2.5 Resolver (mirror hubspot `record_principals` L258-282, but map from share ids)
```python
@staticmethod
def resolve_share_principals(share_ids, users_by_id) -> list[str] | None:
    """005 -> user:<email.lower()> via roster; 00G -> group:salesforce-group-<id>.
    Unresolvable 005 (no roster email) is DROPPED. Returns [] -> None so unowned/all-dropped
    records fall back to admin policy (fail closed)."""
```
Called per Account event to populate `event.record_principals` from `event.share_principals`.

### 2.6 `poll()` / `run_backfill` wiring (ordering is load-bearing)
- Collect the union of share `005`/`00G` ids across the changed-Account share rows.
- Call `_fetch_roster(user_ids, group_ids)` → `users_by_id`, `self.group_edges`.
- For each Account event: `event.record_principals = resolve_share_principals(event.share_principals, users_by_id)`.
- **Before any `sink.post(...)`**, call the group-edge sync (§4) with `self.group_edges` so SpiceDB has
  the edges before facts land (mirror hubspot lifecycle L819-824 / L956).
- Degraded finish (mirror L841-845): `reporter.finish(error=DEGRADED_ACL_SIGNAL if self.roster_degraded
  else None)`; if degraded, also `print(DEGRADED_ACL_SIGNAL)`.
- Contacts/Opportunities stay share-less today (`record_principals=None` → admin fallback). Not in scope
  to fetch their shares; the completeness caveat (§5) covers this.

### 2.7 Shared-sink generalization
`VerityDebeziumSink.sync_team_edges(team_members)` (hubspot.py L645-664) already accepts a
`{group_str: set[member_str]}` map and already tolerates `member` being a `group:` string (the Rust
endpoint is nest-capable). **No fork.** Only rename/re-doc for source-neutrality:
```python
def sync_group_edges(self, group_members: dict[str, set[str]]) -> int: ...   # was sync_team_edges
```
Keep a thin `sync_team_edges = sync_group_edges` alias (or update hubspot's one call site) so the
HubSpot connector keeps working. `resolve_principals`, `_stamp_record_visibility`, `envelope`,
`_bound_visibility`, `post` are reused UNCHANGED.

---

## 3. `share_principals` → `verity_acl` wiring (the union)

1. `resolve_share_principals` maps raw share ids → principal strings on `event.record_principals`
   (unresolvable `005` dropped).
2. `sink.post()` calls `_stamp_record_visibility(events)` (hubspot.py L666-684): one round-trip
   `resolve_principals` (`POST /v1/admin/principals`) over the distinct principal strings → int tokens;
   stamps `event.record_visibility = resolved or None`. Principals unmapped server-side are dropped
   (fail closed).
3. `envelope()` (hubspot.py L567-596) emits the inline block ONLY when `record_visibility` is set:
   ```json
   {"visibility": [<tokens>], "confidentiality": "internal", "acl_provenance": "approximated"}
   ```
4. **Union with admin fallback:** `post()` also binds `?visibility=<--visibility policy>` via
   `_bound_visibility` (hubspot.py L598-620). Server-side the inline per-record `verity_acl` is UNIONed
   on top of the bound admin policy — the admin floor is never replaced. A record whose every share id
   dropped carries NO inline block and rides the admin `?visibility=` floor alone.

---

## 4. Group-edge mirroring to SpiceDB

`sink.sync_group_edges(self.group_edges)` → sorted `POST /v1/admin/groups {tenant_id, group, member}`,
deterministic (groups sorted, members sorted within each). Members may be `user:<email>` OR
`group:salesforce-group-<child>` — nested edges flow through unchanged. Called FIRST in the poll/
backfill lifecycle (before facts) so `resolve_principals` on the group tokens succeeds.

---

## 5. Provenance & completeness caveat

- `acl_provenance` = `"approximated"` (hardcoded in `envelope`, correct as-is).
- **Identity gap: CLOSED.** A `005`/`00G` on a Share row now resolves to the same cross-source token
  the person/group carries in every other connector.
- **Completeness gap: OPEN.** AccountShare is only a *subset* of effective visibility (OWD, role
  hierarchy, sharing rules, implicit parent→child, territories are not enumerated). We therefore
  over-hide relative to true Salesforce ACLs — acceptable under the fail-closed contract, and the
  reason provenance is `"approximated"` not `"mirrored"`. The connector module docstring states this;
  keep it in sync with the built behavior (raw ids collected → crosswalked → mirrored as SpiceDB group
  edges → stamped inline `verity_acl` UNIONed over the admin `--visibility` floor).
- **Floor-union (write-path REPLACE, not union).** The choke point (`crates/verity-server/src/ingest.rs`,
  `parse_inline_acl(payload).or_else(|| bound_policy.cloned())`) REPLACES the connector-bound admin policy
  with any inline `verity_acl`; it does NOT union server-side. Because AccountShare is a strict subset,
  the connector UNIONs the admin `--visibility` floor INTO the resolved `record_visibility` before stamping
  (`SalesforceFactEvent.union_policy_floor` → `VerityDebeziumSink._stamp_record_visibility`), so the inline
  block is always a superset of the floor. An unresolvable share id is dropped, but the record never loses
  the admin floor.

---

## 6. Join-on-Email-not-Username nuance

`User.Username` is email-formatted but is a distinct field and may diverge from the real address; it is
also globally unique across orgs (often suffixed). Joining on `Username` would mint tokens that do NOT
match gdrive/gmail/hubspot. **Join on `Email`, lowercased.** A `005` with no `Email` (integration/
inactive users) does not join and is dropped (over-hide). Assert this explicitly in tests (§7) with a
mixed-case email fixture proving `Ae@Acme.test` → `user:ae@acme.test`.

---

## 7. Test plan — `ingest/tests/test_salesforce.py`

### New fixtures (`ingest/tests/fixtures/salesforce/`), same query envelope + `attributes` block
- `query_users.json` — `attributes.type:"User"`; fields `Id, Email, IsActive`. Cover
  `005xx000001X8UzAAK` with a **mixed-case** `Email` (e.g. `Ae@Acme.test`) to prove lowercasing;
  include one inactive/no-email user to prove the drop.
- (No `query_groups.json` — no `FROM Group` query is issued; the group token derives from the id.)
- `query_groupmembers.json` — `attributes.type:"GroupMember"`; fields `GroupId, UserOrGroupId`.
  Include at least one `UserOrGroupId` that is another `00G…` (nested edge) and a two-group mutual
  reference (`A⊃B`, `B⊃A`) to prove cycle-safety terminates.

### Mock-transport routing (`make_mock_salesforce`)
Add SOQL substring branches BEFORE `FROM Account`, matching most-specific first:
`FROM GroupMember` → groupmembers; `FROM User` → users. A `roster_fail=True` kwarg returns `403` on
the roster queries (degraded path); a `roster_500=True` kwarg returns a non-403 `500` on the User
query to prove the non-403 error path ALSO degrades to the admin floor + emits the signal.

### Assertions (mirror the four `test_hubspot.py` patterns)
- **(a) User → lowercased token:** `resolve_share_principals(["005xx000001X8UzAAK"], roster)` ==
  `["user:ae@acme.test"]`; unknown-id / no-email / empty-roster → `None` (mirror hubspot L501-528).
- **(b) group edges POSTed sorted, nesting preserved:** after poll, a `/v1/admin/groups` POST carries a
  `member` that is itself `group:salesforce-group-<child>`; emission is sorted (mirror L732-760);
  empty edges → `sync_group_edges({}) == 0`. Cycle fixture must not hang.
- **(c) 403 degraded:** with `roster_fail=True`, `all(e.record_principals is None …)`,
  `connector.roster_degraded is True`, `DEGRADED_ACL_SIGNAL in capsys…out`, backfill reporter
  `progress[-1]["error"] == DEGRADED_ACL_SIGNAL` while `state == "completed"` (mirror L597-622, L871-908).
- **(d) envelope `verity_acl` (approximated):** an Account event with `record_visibility=[t…]` yields
  `env["verity_acl"] == {"visibility":[t…], "confidentiality":"internal", "acl_provenance":"approximated"}`;
  a share-less event has no inline block and rides `?visibility=7,12` (mirror L625-729).
- **Backfill lifecycle:** the SF `_backfill_sink` analog pre-maps the SF principal strings
  (`user:<email>`, `group:salesforce-group-<id>`) in its `/v1/admin/principals` table so resolution
  succeeds; assert a `/v1/admin/groups` POST precedes `/v1/ingest/debezium` (mirror L805-868).

### Existing 15 tests — itemized adjustments (legitimate envelope change)
- The assertion `principal_for_share(...) == "user:005…"/"group:00G…"` (inert raw-id mapping, ~L238-250)
  changes: `principal_for_share` no longer mints tokens (§2.3). Update to assert raw-id passthrough, or
  move the token assertion to `resolve_share_principals`. **Reason:** raw-id strings were the identity
  bug; they are removed.
- Assertions that non-Account events have `share_principals == []` (L232, L319-323) stay valid;
  additionally assert `record_principals is None` on those events.
- Account-event assertions gain `record_principals` / `verity_acl` expectations once shares resolve.
  **Reason:** Share rows are no longer inert — they now produce resolved `verity_acl` tokens.
All other existing tests (token mint, 401-retry, paging, field→event, admin `--visibility`) are
unaffected and MUST stay green.

---

## 8. Build order

1. Module helpers + `SalesforceFactEvent` fields (§2.1-2.2).
2. `_fetch_roster` (User/Group/GroupMember + BFS expansion + 403 degrade) (§2.4).
3. `resolve_share_principals` (§2.5) + `poll`/`run_backfill` wiring + rename `sync_team_edges →
   sync_group_edges` alias (§2.6-2.7).
4. New fixtures + mock routing + the four assertion families; reconcile the 3 itemized existing
   assertions (§7). `cargo` untouched; `pytest ingest/tests/test_salesforce.py` green.
