# Verity Permission Graph — Design Spec (admin/operator plane)

**Status:** design-only. No code changes in this document.
**Author role:** design lead.
**Visual target:** the existing self-contained HTML prototype (two modes, identity/group closure graph, right-panel corpus breakdown by source/confidentiality/provenance, grant-confidence bar, click-a-document → highlight-the-why-path). This spec makes that UX *real* against the codebase.

All file/line references are to `/Users/mattfleming/agent-memory`, verified via Maps A (admin plane), B (data layer), C (UI/CSP).

---

## 1. GOALS / NON-GOALS

### Goals
- **G1.** Answer, on the admin plane, "what does subject X (person or agent) see across all sources?" — the identity/group closure graph plus an aggregate corpus breakdown (by source, confidentiality, provenance) plus a grant-confidence signal.
- **G2.** Answer "who can see object Y (a document/source/entity)?" — the document's materialized visibility tokens resolved to principals, then fanned out to reachable users with the **granting group path** (the "why").
- **G3.** Make the "why" legible: for any reachable person, surface the group-membership path that grants access, and the grant provenance (`mirrored` / `approximated` / `admin-assigned` / `quarantined`) that tells the operator how much to trust the grant.
- **G4.** Stay honest about scope-correctness: the aggregate the panel shows for subject X **must equal** the set `recall` would actually pre-filter to for X — same `visibility && tokens` predicate (Map B §3) **AND the same in-window revocation subtraction the read path performs** (`AppState::scope_for`, `main.rs:471-478` → `RevocationPlane::subtract`, `revocation.rs:92`). Without this subtraction the aggregate over-states real access during a revocation window. The parity is **time-sensitive** (window-scoped: `VERITY_REVOCATION_WINDOW_SECS`): exact equality holds only if both sides read the `revocations` table at the same instant. So the operator view neither over- nor under-states real access, modulo the window read-instant.
- **G5.** Be reusable for a **revocation-preview** ("what breaks if I cut this group edge?") by lifting `admin_group_remove`'s already-computed affected/lost-token logic read-only (Map A §4).

### Non-Goals
- **NG1 — no per-document node rendering at scale.** `my-workspace` has 115,643 chunks; real tenants reach millions. We **never** render one node per document. The graph is the **identity/group closure** (hundreds of nodes — tractable); documents are **aggregated server-side** (`GROUP BY` counts, Map B §3) and only enumerated in a focused, paginated, metadata-only panel.
- **NG2 — no document content exposure.** This is a metadata/counts surface. We show `document_id`, `source`, `confidentiality`, `acl_provenance`, `valid_from`, chunk-counts — **never chunk bodies**. A god-view over bodies would undercut per-principal enforcement; it is explicitly out of scope.
- **NG3 — not the read path.** This is admin/operator tooling. It does **not** live on, call into, or share code with `recall`/`get`. See §2.
- **NG4 — not a mutation surface (MVP/V2).** All endpoints are read-only. The only mutation-adjacent feature is revocation-*preview* (V3), which is a dry-run and writes nothing (Map A §4).
- **NG5 — no external graph library.** CSP forbids CDN/`<script src>` (Map C §1). All rendering is inline SVG / Canvas / CSS bars built in panel JS.

---

## 2. PLANE PLACEMENT & INVARIANTS

### 2.1 This is entirely the admin plane
Every endpoint in this spec is a **new admin handler** mounted under `/v1/admin/…`, gated by `AdminAuth` (Map A §1): each handler takes `headers: HeaderMap` and calls **`state.admin.require(&headers)?`** (the no-dev-open variant — normative, §5) as its first line — NOT `check`, unlike the ~40 existing `check` call sites (`main.rs:610,1142,…,4053`).

The admin plane is *permitted* to do the two things the read path may not:
1. **Live ReBAC / SpiceDB calls** — via the **`pub(crate)` wrappers** `user_groups`/`group_users`/`group_and_ancestors`/`group_direct_members` (`rebac.rs:519/548/530/587`), guarded by `require_rebac(&state)` (`main.rs:3904`) → 503 when ReBAC unset. (`membership_closure`, `rebac.rs:476`, is **private** — not callable from a new handler; the public wrappers already delegate to it, so we call those, never it directly.) `admin_group_remove` already makes exactly these live SpiceDB calls on the admin plane (Map A §4); we follow that precedent.
2. **Rich aggregate SQL** directly against `state.pool()` (`main.rs:4003`), e.g. `GROUP BY source/confidentiality/acl_provenance` (Map B §3). Precedent: `list_principals` (`postgres.rs:2153`) and `debug_recall_candidates` (`postgres.rs:2190`) both carry explicit "Admin plane only; never on the recall/`get` path" contracts.

### 2.2 The read path is never touched or regressed — argument
The read-path non-negotiable (SPEC.md, CLAUDE.md): `recall`/`get` make **no LLM calls**; scope filters are materialized into the index and applied as a **mandatory pre-filter** in ONE shared enforcement layer above `StorageAdapter`.

**Accurate statement of the existing read path (do not misread as ReBAC-free):** the read path today is *not* literally live-ReBAC-free. `recall` (`main.rs:1917`) calls `revocation::enforce_restricted` (`main.rs:1939`), which for `confidentiality=3` (Restricted) hits with ReBAC enabled calls `current_token_set` → `rebac.user_groups(...)` (`revocation.rs:160,232,252`) — a live SpiceDB `LookupResources`. This is a **pre-existing, documented v0.1 approximation** of the SPEC §7b live `BatchCheck` (`revocation.rs:148-159`), NOT something this spec introduces. This spec does not modify `enforce_restricted` and adds **no new** ReBAC to the read path. The load-bearing claim below is therefore the accurate one: **no *new* live-ReBAC call, and no *shared code* with the read path** — not "the read path is ReBAC-free."

This spec preserves read-path purity by **construction**:
- **No shared code path — a hard constraint.** The new handlers are separate functions in `main.rs`, mounted on separate `/v1/admin/*` routes. They **MUST NOT import or call** `enforce_restricted`, `current_token_set`, `scope_for`, or `storage.recall` — the seams where read-path and ReBAC logic are adjacent — and must implement their own closure/token-resolve inline (§3.4/§4.4). They do not wrap or call the recall/get handlers or the shared enforcement layer, and nothing in `recall`/`get` calls the new code. There is therefore no path by which an admin-plane call can execute during a `recall`, and no coupling to the existing read-path Restricted-recheck seam. (The admin plane calls the same *public* `user_groups` wrapper, but never the read-path helper `current_token_set` that wraps it.)
- **Same predicate + same revocation subtraction, different plane — read-only.** The corpus aggregate uses the *same* `visibility && $tokens AND valid_to IS NULL` overlap predicate the read pre-filter uses (`migrations/0026_fact_visibility.sql:3`; Map B §3) **and applies the same in-window revocation subtraction** the read path applies via `scope_for`/`RevocationPlane::subtract` (`main.rs:471`, `revocation.rs:92`) — but re-implemented inline (a `revocations`-table read), NOT by calling `scope_for`. Reusing the *predicate + subtraction logic* is what guarantees scope-correctness (G4). It is not reusing the *read path*: the admin query is a `GROUP BY` count issued from an admin handler, not a `recall` invocation.
- **ReBAC stays off the read path.** Live SpiceDB closure runs only to compute the closure *for the admin request itself* (as `admin_group_remove` already does). The read path continues to consume only the pre-materialized `visibility int[]` tokens; nothing here changes how tokens get materialized or when recall reads them.
- **Fail-closed inheritance.** The admin aggregate inherits fail-closed semantics from the data: `visibility = {}` means invisible (Map B §2). An empty/unresolvable subject yields an empty token set → empty aggregate (§5), never a permissive "show everything."

**Invariant statement:** *The Permission Graph adds **no new** LLM call and **no new** live-ReBAC call to any `recall`/`get` codepath, **shares no code** with the read-path enforcement layer (it does not call `enforce_restricted`/`current_token_set`/`scope_for`/`storage.recall`), and issues its live-ReBAC + aggregate queries exclusively from admin-token-gated `/v1/admin/*` handlers. Read-path purity is preserved because the read path is neither modified nor invoked. (The pre-existing Restricted-hit `enforce_restricted → current_token_set → user_groups` live-ReBAC recheck on `recall`, SPEC §7b v0.1, is unchanged and untouched by this spec.)*

A test asserts this structurally (§9 T7): grep-level assertion that the new handlers are not referenced from recall/get **and** that the new handlers do not reference the shared read-path helpers `enforce_restricted`/`current_token_set`/`scope_for`/`recall`, plus a scope-parity test that the aggregate equals recall's real (post-revocation) filtered set.

---

## 3. ENDPOINT 1 — "what does subject X see"

### 3.1 Method + path
```
GET /v1/admin/access/subject
```
Admin-gated (`state.admin.require` — no-dev-open, §5), tenant-scoped, read-only.

### 3.2 Request params (query string)
| param | type | required | notes |
|---|---|---|---|
| `tenant_id` | uuid | yes | mandatory pre-filter on every query; 404 if tenant unknown (reuse `state.storage.get_tenant` 404 pattern, `main.rs:4054-4065`) |
| `subject` | string | yes | principal string, e.g. `user:alice@x.com` (person or agent). Parsed like `parse_membership` (`main.rs:3880`) |
| `max_confidentiality` | int 0..3 | no (default 3) | confidentiality ceiling; lets the operator ask "what does X see *at internal or below*" |
| `include_facts` | bool | no (default true) | union L1 `facts` into the corpus breakdown (facts mirror chunks' predicate — Map B §2) |
| `as_of` | RFC3339 ts | no (V3 only) | time-travel; see §8. In MVP/V2 this param is rejected/ignored |
| `docs_limit` | int 1..=200 | no (default 50) | page size for the document panel; clamp server-side |
| `docs_after` | keyset cursor | no | `(valid_from, id)` **stored-column** chunk keyset (like `browse_memories` `postgres.rs:1998`); never an aggregate cursor (§3.4 step 6) |

### 3.3 Response JSON schema
```jsonc
{
  "tenant_id": "…",
  "subject": "user:alice@x.com",
  "subject_resolved": true,               // false ⇒ unresolvable ⇒ everything below empty (fail-closed)

  "closure": {                            // the identity/group graph (bounded — §6)
    "nodes": [
      { "id": "user:alice@x.com", "kind": "user",  "label": "alice@x.com", "token": 4711 },
      { "id": "group:eng",        "kind": "group", "label": "eng",         "token": 88,
        "ancestor_depth": 0 },
      { "id": "group:all-staff",  "kind": "group", "label": "all-staff",   "token": 3,
        "ancestor_depth": 1 }
    ],
    "edges": [
      // subject → group and group → ancestor-group membership edges
      { "from": "user:alice@x.com", "to": "group:eng",       "relation": "member" },
      { "from": "group:eng",        "to": "group:all-staff", "relation": "member" }
    ]
  },

  "tokens": [4711, 88, 3],                // the resolved token set used as the visibility filter

  "corpus": {                             // server-side GROUP BY aggregates (§3.4)
    "total": { "chunks": 20431, "docs": 812 },
    "by_source":          [ { "source": "gdrive", "chunks": 15000, "docs": 600 }, … ],
    "by_confidentiality": [ { "level": 0, "chunks": … }, { "level": 1, … }, … ],
    "by_provenance":      [ { "provenance": "mirrored",      "chunks": …, "docs": … },
                            { "provenance": "approximated",  "chunks": …, "docs": … },
                            { "provenance": "admin-assigned","chunks": …, "docs": … },
                            { "provenance": "quarantined",   "chunks": …, "docs": … } ]
  },

  "grant_confidence": {                   // provenance normalized to fractions (grant-confidence bar)
    "mirrored": 0.71, "approximated": 0.18, "admin-assigned": 0.11, "quarantined": 0.00,
    "basis": "chunks"                     // whether fractions are over chunks or docs
  },

  "documents": {                          // focused, paginated, METADATA-ONLY panel (NG2)
    "items": [                            // per-doc rollup is PAGE-LOCAL (§3.4 step 6);
                                          // authoritative per-doc totals come from corpus aggregate
      { "document_id": "d/abc", "source": "gdrive", "min_confidentiality": 1,
        "last_seen": "2026-07-01T…Z", "n_chunks": 12, "page_local": true }
    ],
    "next_after": "1719792000.000|84213" // (valid_from, id) STORED-column keyset, null when exhausted
  },

  "flags": { "approximate_counts": false, "closure_truncated": false,
             "revocation_window_active": false }  // §6 guards + §3.4 step 3
}
```

### 3.4 Exact query / ReBAC-call plan
1. **Gate + tenant check.** `state.admin.require(&headers)?` (no-dev-open, §5); `require_rebac(&state)?` → 503 if ReBAC unset; verify tenant exists (`get_tenant` 404 pattern).
2. **Forward closure (live ReBAC).** For a `user:` subject call `user_groups(tenant, name)` (`rebac.rs:519`) → transitive `group:<name>` closure via `LookupResources(group#membership, subject)`, `fullyConsistent`. Build `closure.nodes/edges`: the subject node + each returned group node; edges from membership. Ancestor depth / group→group edges via `group_and_ancestors` (`rebac.rs:530`) if we want the full internal group DAG rendered.
   - The graph edge set is what the prototype draws. The public wrappers return the *flattened* set; if the prototype wants the *stepwise* path (alice→eng→all-staff, not alice→{eng,all-staff}), reconstruct intermediate edges with `group_and_ancestors` per group (bounded — hundreds of nodes, §6). (Note: `membership_closure` is private; use `user_groups`/`group_and_ancestors` only.)
3. **Resolve closure → tokens, then subtract in-window revocations (SQL).** The subject + every group in the closure is a principal string. Resolve to the i32 token domain:
   ```sql
   SELECT principal, token FROM principals
    WHERE tenant_id = $1 AND principal = ANY($2)   -- $2 = [subject] ∪ closure groups
   ```
   This is the **exact** query `admin_group_remove` already runs (`main.rs:3997-4005`; Map B §1). `PrincipalToken = i32` = `visibility int[]` domain — no casting (Map B header). Principals in the closure that never materialized a token simply don't appear (fail-closed: they contribute no visibility).
   **Then apply the read path's revocation subtraction (parity with G4).** The real read path never enforces on the raw closure tokens: `scope_for` (`main.rs:471-478`) runs `RevocationPlane::subtract` (`revocation.rs:92`) on *every* scoped read, removing any token present in the `revocations` table within `VERITY_REVOCATION_WINDOW_SECS` (`revocation.rs:66-110`; migration `0009_revocations.sql`). We MUST do the same, re-implemented inline (NOT by calling `scope_for`, which is a read-path helper — §2.2):
   ```sql
   -- in-window revoked tokens for this tenant
   SELECT DISTINCT token FROM revocations
    WHERE tenant_id = $1 AND at > now() - make_interval(secs => $window)
   ```
   Subtract this set from the resolved tokens; set `tokens = [resolved tokens] \ [revoked-in-window]`. **Time-sensitivity:** because the window is `now()`-relative, exact parity with a concurrent `recall` only holds when both read `revocations` at the same instant; the response sets `flags.revocation_window_active: true` and the UI surfaces a note when any in-window revocation touched this token set.
4. **Corpus aggregate (SQL GROUP BY ×3).** With the enforcement pre-filter predicate (Map B §3). **This panel represents the visibility-*authorized* set — the exact set recall pre-filters to before its ANN/embedding stage — NOT recall's ANN-returnable set.** So we do NOT filter `kind`, and we do NOT add recall's `{col} IS NOT NULL` embedding-presence filter or entity_scope fence (those shape what ANN can *return*, not what is *authorized*; `postgres.rs:2805-2812`). Parity (G4/T1) is against the **enforcement pre-filter**, defined as:
   ```sql
   WHERE tenant_id = $1
     AND visibility && $2::int[]        -- $2 = post-revocation tokens (step 3); GIN chunks_visibility_idx (0001:74)
     AND confidentiality <= $3          -- max_confidentiality
     AND valid_to IS NULL               -- live only (toggled by as_of in V3)
   ```
   (`kind` may be exposed as an *optional* client filter for operator convenience, but it is not part of the parity baseline.) Run three grouped counts — `GROUP BY source`, `GROUP BY confidentiality`, `GROUP BY acl_provenance` — each `SELECT … count(*) AS chunks, count(DISTINCT document_id) AS docs` (same shape as the production entity-tag aggregate `postgres.rs:1802-1826` and `GROUP BY m.source` at `:2065`). Plus one `total` row. If `include_facts`, union the identical predicate over `facts` (Map B §2). Feasible at 115k (sub-second GROUP BY); see §6 for million-row guards.
5. **Grant-confidence.** Normalize the `by_provenance` counts to fractions (`mirrored` = highest confidence … `quarantined` = lowest). Pure arithmetic over step 4's result.
6. **Documents page (SQL, keyset over STORED columns — never over an aggregate).**
   **Blocker fix (scale):** an earlier draft keyset-paginated on `(max(valid_from), document_id) < $after` over a `GROUP BY document_id`. That is unsound and non-scaling: `max(valid_from)` is an aggregate (illegal in `WHERE`, only `HAVING`), and HAVING-keyset forces a full `GROUP BY` re-scan of the *entire visible corpus* on every page — no index help (there is no `(tenant_id, valid_from)`/`(tenant_id, source)` index on `chunks`; only GIN visibility). For a company-wide token set at 115k+ (far worse at millions) every "load more" re-aggregates the whole corpus. The sanctioned pagination (`browse_memories`, `postgres.rs:1998`) keysets on a **stored** `(recorded_at, id)` column pair precisely because an aggregate keyset cannot narrow the scan.
   **Chosen approach (a): paginate raw chunk rows on the stored `(valid_from, id)` keyset, roll up per-document within the page client-/handler-side.** The GIN `visibility &&` pre-filter is the primary narrowing:
   ```sql
   SELECT id, document_id, source, confidentiality, valid_from
     FROM chunks
    WHERE tenant_id = $1
      AND visibility && $2::int[]                 -- post-revocation tokens
      AND confidentiality <= $3
      AND valid_to IS NULL
      AND (valid_from, id) < ($after_ts, $after_id)   -- keyset over STORED columns
    ORDER BY valid_from DESC, id DESC
    LIMIT $chunk_page                              -- e.g. docs_limit * fan-out headroom
   ```
   Group the returned page's rows by `document_id` in the handler to emit `{ document_id, source, min_confidentiality, last_seen=max(valid_from within page), n_chunks (within page) }`, and return `next_after = (last_row.valid_from, last_row.id)`. Caveat stated in the response/UI: `n_chunks` and `min_confidentiality` are **page-local** (a document's chunks may span pages); the authoritative per-document totals come from the aggregate (step 4), not this panel. `next_after` is a stored-column cursor, monotonic and index-eligible.
   **Alternatives (documented, not chosen for MVP):** (b) paginate distinct `document_id`s via a stored-column keyset with GIN as primary narrowing (needs a distinct-document strategy that still avoids aggregate-keyset); (c) bound the panel to a single non-paginated top-N (`LIMIT N`, no cursor) labelled "most-recent N documents", exactly as the entity-tag directory does (`postgres.rs:1802`, which offers no cursor for the same reason). Whichever is chosen, **the `WHERE`-clause keyset is always over stored columns, never `max(valid_from)`.**
   `docs` visible total is the aggregate's `COUNT(DISTINCT document_id)` (step 4), not this panel. Metadata only — no chunk text selected (NG2).
7. **Respond.** Assemble the JSON above; set `flags` per §6 guards.

**Every column/function cited is real:** `principals(principal,token)` (`0007:36-42`); `chunks.{visibility,confidentiality,source,document_id,acl_provenance,valid_from,valid_to,kind}` (`0001` + `0006` + `0005`); GIN `chunks_visibility_idx` (`0001:74`); `user_groups`/`group_and_ancestors` (`rebac.rs:519/530`); reuse query `main.rs:3997`.

---

## 4. ENDPOINT 2 — "who can see object Y"

### 4.1 Method + path
```
GET /v1/admin/access/object
```
Admin-gated, tenant-scoped, read-only.

### 4.2 Request params
| param | type | required | notes |
|---|---|---|---|
| `tenant_id` | uuid | yes | mandatory pre-filter |
| `document_id` | string | one of these three | the doc whose visibility we decode |
| `source` | string | (alt) | "who can see anything from source S" — aggregate mode |
| `entity` | string | (alt) | an `entity_tags` value (GIN `chunks_entity_tags_idx`, `0001:74`) |
| `as_of` | RFC3339 | no (V3) | time-travel; see §8 honesty note |
| `users_limit` / `users_after` | int / cursor | no | paginate reachable-users when a company-wide group is in play |

Exactly one of `document_id` / `source` / `entity` is required; else 400.

### 4.3 Response JSON schema
```jsonc
{
  "tenant_id": "…",
  "object": { "kind": "document", "id": "d/abc" },

  "visibility_tokens": [88, 3, 4711],     // DISTINCT unnest(visibility) over the object's live chunks
  "confidentiality": 2,                    // min/representative confidentiality of the object
  "provenance": "mirrored",                // acl_provenance of the granting rows (may be a set)

  "principals": [                          // tokens resolved back to strings (Map B §1 reverse)
    { "token": 88,   "principal": "group:eng",       "kind": "group" },
    { "token": 3,    "principal": "group:all-staff", "kind": "group" },
    { "token": 4711, "principal": "user:alice@x.com","kind": "user"  }
  ],

  "reachable_users": [                     // fan-out: every person who can reach the object
    { "user": "user:alice@x.com",
      "via": [ ["group:eng"], ["group:all-staff"] ],   // granting group path(s) — the "why"
      "direct": true },
    { "user": "user:bob@x.com",
      "via": [ ["group:all-staff"] ],
      "direct": false }
  ],
  "reachable_users_next_after": null,

  "flags": { "approximate": false, "fanout_truncated": false }
}
```

### 4.4 Query / ReBAC-call plan — and the HONEST reverse-lookup gap
1. **Gate + tenant + `require_rebac`.**
2. **Object → visibility tokens (SQL).** For `document_id` mode (Map B §3) — cheap, few chunks:
   ```sql
   SELECT DISTINCT unnest(visibility) AS token FROM chunks
    WHERE tenant_id = $1 AND document_id = $2 AND valid_to IS NULL;
   ```
   `source` mode: `WHERE source = $2`; `entity` mode: `WHERE entity_tags @> ARRAY[$2]` (GIN). Also pull `min(confidentiality)` and `array_agg(DISTINCT acl_provenance)` for the object.
   **BLOCKER FIX (scale/security) — `source` and `entity` modes are UNBOUNDED FULL AGGREGATE SCANS.** `source` has **no index** (there is no `(tenant_id, source)`), and `DISTINCT unnest(visibility)` scans every matching row's array even where `entity_tags` uses its GIN. "Who can see anything from source S" over a source spanning most of a 115k (or multi-million) corpus is a guaranteed full-table scan that, unguarded, can hang the admin request and hold a pooled connection (`max_connections=16`). The §6 scale guards must apply **here**, not only to Endpoint 1. State plainly, same honesty as Endpoint 1: **`source`/`entity` mode is a full aggregate scan.** Concretely:
   - Wrap the decode scan in `SET LOCAL statement_timeout = '<ms>'`. **BUILD ITEM: no `statement_timeout` precedent exists in the codebase** — the only `SET LOCAL` usage is the HNSW GUCs at `postgres.rs:2761/2787`; this must be built, not assumed. On timeout, set `flags.approximate = true` and return partial/empty with the flag rather than hang.
   - Either cap the `source`/`entity` token decode (e.g. sample/bounded scan) or **gate those two modes behind a corpus-size ceiling** until a supporting `(tenant_id, source)` (and entity-selective) index exists. `document_id` mode is exempt (few chunks).
   - Fan-out caps (`users_limit`) and the same statement-timeout apply to step 4's `group_users` fan-out as before.
3. **Tokens → principal strings (SQL, reverse of Map B §1).** This helper does **not exist yet** but is trivial and index-backed by `UNIQUE(tenant_id, token)` (Map B §1):
   ```sql
   SELECT token, principal FROM principals
    WHERE tenant_id = $1 AND token = ANY($2)
   ```
   **BUILD ITEM 4a (SQL only, no new SpiceDB wrapper):** add this token→string resolve. Trivial; mirror the existing string→token query at `main.rs:3997`.
4. **Group principals → reachable users (live ReBAC).** For each `group:<name>` in the resolved principals, call `group_users(tenant, group_name)` (`rebac.rs:548`) — **this IS the SpiceDB `LookupSubjects` wrapper** (`/v1/permissions/subjects`, `subjectObjectType: user`, `fullyConsistent`), transitive, sorted/deduped, fail-closed parse (Map A §3). `user:` principals are already terminal users. Union everything into `reachable_users`.
5. **Retain the "why" path.** `group_users` returns the *flattened* user set, not the path. To populate `via` (the granting group path for the highlight-the-why interaction), reconstruct per-user paths from the group DAG: for each reachable user, the granting groups are those closure groups that (a) carry a token on the object AND (b) have the user in their `group_users` result. For stepwise nesting (user→eng→all-staff), use `group_direct_members` (`rebac.rs:587`, `ReadRelationships`) to walk the DAG, or `group_and_ancestors` from the object's granting groups. This composition is the unbuilt part.

**HONEST STATUS of the reverse lookup (Map A §3):**
- The SpiceDB reverse primitive **already exists**: `group_users` (LookupSubjects) + `group_direct_members` (ReadRelationships) cover all graph edges. **No new SpiceDB wrapper is required.**
- What is **NOT built** and must be added:
  - **BUILD ITEM 4a** — token→principal SQL resolve (§4.4 step 3). Pure SQL, index-backed.
  - **BUILD ITEM 4b** — the *composition*: `visibility` token set → principal strings → per-group `group_users` fan-out, **retaining the granting group path** for the why-highlight. This is glue over existing primitives, living entirely in the new admin handler. No new `rebac.rs` function is strictly required, but if we want a named, testable seam, add:
    ```rust
    // rebac.rs — OPTIONAL convenience wrapper (not strictly required; composition can live in the handler)
    pub(crate) async fn users_reachable_via_groups(
        &self, tenant: Uuid, groups: &[String],
    ) -> Result<Vec<(String /*user*/, Vec<String> /*granting groups*/)>, RebacError>
    ```
    Implemented as a fan-out over `group_users` + a path-retention pass. Signature mirrors the existing `pub(crate)` closure fns (`rebac.rs:519/530/548`).

**Bottom line for §4:** the reverse SpiceDB call exists (`group_users`); the missing pieces are one SQL helper (4a) and the path-retaining composition (4b) — both admin-plane glue, no read-path involvement.

---

## 5. SECURITY & AUDIT

- **Admin-token gating (NORMATIVE — MVP requirement, not a recommendation).** Every Permission Graph endpoint MUST gate with **`require(&headers)`** (the no-dev-open, 401-when-unset variant, `main.rs:197`, as `SecretIntakeAuth` does, `main.rs:266-281`) — **NOT `check`** (the dev-open variant, `main.rs:184-186`, used by ~40 existing admin sites). Equivalently, a dedicated no-dev-open extractor modeled on `SecretIntakeAuth`. Rationale: this is a god-view over org structure + access patterns (per-principal closure, who-can-see-what, reachable-user fan-out) — materially more sensitive than existing `check`-gated admin reads. `AdminAuth::check` returns `Ok(())` with no token set on a loopback dev bind (`bind_gate_decision` only forces the token on non-loopback binds, `main.rs:336-350`), so a `check`-gated god-view is fully open on loopback-dev (and via a proxied loopback, an unauthenticated read of the entire org access graph). `require` returns 401 instead. This is settled in this spec (removed from §10 open questions). A test (§9) asserts the endpoints return 401 when `VERITY_ADMIN_TOKEN` is unset, mirroring `SecretIntakeAuth`.
- **Tenant-scoping (mandatory).** `tenant_id` is a required param and the leading predicate on every SQL query and every ReBAC call. Cross-tenant reads are impossible by construction (Map B §2: tenant filter is the mandatory pre-filter). UI passes `tenant_id = Verity.tenant()` on every call and fails closed to `renderNoTenant()` when unset (Map C §2).
- **Metadata-not-content boundary (NG2).** Responses carry `document_id`, `source`, `confidentiality`, `acl_provenance`, `valid_from`, counts — **never** chunk `content`. This is enforced at the SQL projection level (no `content` column is ever selected). A test asserts no endpoint selects chunk bodies (§9).
- **Fail-closed.**
  - Unresolvable subject → `subject_resolved: false`, empty tokens, empty corpus/documents (never permissive).
  - `visibility = {}` on a chunk → invisible; contributes nothing (Map B §2).
  - ReBAC unset → 503 via `require_rebac` (`main.rs:3904`), not a partial/permissive answer.
  - Principal-string with no materialized token → contributes no visibility (silently dropped, matching `admin_group_remove`'s `lost_tokens` subset logic).
- **Per-query audit logging.** Because this surface reveals who-can-see-what, every query is logged.
  - **Proposal:** append-only `admin_access_audit` table (new migration, append-only per repo convention):
    ```sql
    CREATE TABLE admin_access_audit (
      id           bigserial PRIMARY KEY,
      tenant_id    uuid NOT NULL,
      actor        text NOT NULL,          -- admin identity (bearer subject / 'dev-open' when require permits)
      endpoint     text NOT NULL,          -- 'access/subject' | 'access/object' | 'revocation-preview'
      query_target text NOT NULL,          -- the subject/object queried
      params       jsonb NOT NULL,         -- max_confidentiality, as_of, etc.
      result_meta  jsonb NOT NULL,         -- total counts, #nodes, #reachable_users (NOT content)
      queried_at   timestamptz NOT NULL DEFAULT now()
    );
    ```
    This mirrors the existing append-only audit precedent `fact_acl_audit` (`0026:34-53`, Map B §4). Every handler writes one row before responding. `result_meta` records counts only — never document content — so the audit log itself respects NG2.
  - **Alternative (lighter):** structured tracing log line per query if a durable audit table is deemed out-of-MVP-scope; but the god-view sensitivity argues for the durable table. Flag as open question (§10).

---

## 6. SCALE PLAN

- **Identity graph is bounded.** Nodes = subject + its transitive group closure (§3) or the object's granting groups + their transitive user closure (§4). This is hundreds of nodes for a normal principal — tractable to render as inline SVG (Map C §1). We render **this**, not documents (NG1).
  - **Guard:** a **superuser / company-wide closure** can blow up (e.g. `all-staff` reaching thousands of users). Cap `reachable_users` fan-out with `users_limit` pagination and set `flags.fanout_truncated`. Cap closure node rendering (e.g. > N groups → collapse ancestors into a "+K more" node) and set `flags.closure_truncated`.
- **Documents aggregated server-side.** The right-panel breakdown is three `GROUP BY` counts (§3.4 step 4), never a client-side enumeration of 115k rows. Individual documents appear only in the keyset-paginated, metadata-only panel (§3.4 step 6).
- **Index reliance + guards (Map B §3 caveats):**
  - `visibility && $tokens` uses GIN `chunks_visibility_idx` — the intended fast path. **Low-selectivity risk:** a token present in nearly every chunk (company-wide group) makes `&&` low-selectivity → the planner may seqscan 115k. Mitigate: always pair with `tenant_id`, cap page size, accept a full aggregate scan for counts (115k GROUP BY is sub-second).
  - **Million-row tenants:** a huge token set (superuser closure) means the pre-filter doesn't shrink → source/confidentiality/provenance GROUP BYs become full scans. Mitigate with a **statement timeout + `flags.approximate_counts: true`** ("approximate" badge in UI), and note a future option: materialized per-principal counters. There is **no composite `(tenant_id, source)` / `(tenant_id, valid_to)` index** beyond the unique key (Map B §3) — GROUP BYs rely on the GIN pre-filter shrinking the set first.
  - **`statement_timeout` is a BUILD ITEM, not a reuse.** The codebase has no `statement_timeout` precedent (only HNSW `SET LOCAL` GUCs at `postgres.rs:2761/2787`). The guard = a `SET LOCAL statement_timeout` in the same transaction as the aggregate/decode, with the handler catching the timeout error and returning `flags.approximate_counts`/`flags.approximate` set. This applies uniformly to **Endpoint 1's** aggregates/documents scan **AND Endpoint 2's `source`/`entity` decode scan** (§4.4 step 2) — the latter is an equally unbounded full scan and was previously unguarded.
  - **Endpoint 2 `source`/`entity` decode ceiling.** Until a `(tenant_id, source)` / entity-selective index exists, gate `source`/`entity` mode behind a corpus-size ceiling (or bounded/sampled decode); `document_id` mode is exempt (few chunks).
  - `count(DISTINCT document_id)` is a sort/hash aggregate — fine at 115k, watch at millions (same statement-timeout guard).
- **Cold cache.** First query after cold start pays GIN + table warmup; p95 will be worse than warm. The benchmark discipline (CLAUDE.md: report p50/p95/p99 at stated corpus size + selectivity + hardware) applies — the spec's latency claims must be measured on `my-workspace` (115,643 chunks) at both a small-closure and a company-wide-closure selectivity, warm and cold, before any number goes in docs.

---

## 7. UI PANEL

Slots into `crates/verity-server/src/ui/` following the frozen assembler contract (Map C §2). **No changes to `core.js`, `core.css`, `theme.css` (FROZEN — consumed only).** Files touched: two new (`panel_permgraph.html`, `panel_permgraph.js`) + edits to `mod.rs` and `shell.html`.

### 7.1 Wiring steps (Map C §2 "how to add a panel")
1. **`panel_permgraph.html`** —
   ```html
   <section class="panel" id="panel-permgraph">
     <h1>Permission graph</h1>
     <div class="lede">See what a person or agent can reach, or who can reach a document — and why.</div>
     <div id="permgraph-mount"></div>
   </section>
   ```
2. **`panel_permgraph.js`** — IIFE, `var V = window.Verity;`, `V.register({ id:"permgraph", mount, load, onShow })` (`core.js:330`). See §7.2.
3. **`mod.rs`** — add `include_str!("panel_permgraph.html")` + `"\n"` to `PANEL_SECTIONS` (~`mod.rs:81`), `include_str!("panel_permgraph.js")` + `"\n"` to `UI_SCRIPTS` **before** `Verity.boot();` (~`mod.rs:141`, before `:158`), and add `"panel-permgraph"` to the paint-regression test array (`mod.rs:288-305`).
4. **`shell.html`** — one `<div class="navitem" data-nav="permgraph">Permission graph</div>` in `#rail` under the "Prove & inspect" `.group-label` (`shell.html:88-93`).

### 7.2 Panel behavior (matches the prototype UX)
- **`mount(section)`** builds static DOM into `#permgraph-mount` once:
  - A `.toolbar` with a `.seg` segmented control (`core.css:279-288`) — the **exact affordance** for the prototype's two-mode toggle: **"What does a person see?"** / **"Who can see this?"** (`button.on` = active mode).
  - A subject/object picker: reuse `V.principalPicker` (`core.js:2060`) — the ready sectioned who-chooser over `/v1/admin/principals` — for Mode A subject selection; a document/source/entity input for Mode B.
  - No-tenant teach via a local `renderNoTenant()` (pattern `panel_principals.js:217-231`); `onShow` renders it when `!V.tenant()`.
- **`load(section, tenant)`** (autoload, re-runs on tenant change, deduped — `core.js:336`):
  - Mode A: `await V.api("/v1/admin/access/subject?tenant_id=" + encodeURIComponent(tenant) + "&subject=" + …, { admin:true })` (fetch pattern `panel_principals.js:245`; `{admin:true}` attaches the sessionStorage bearer, `core.js:107`).
  - Mode B: `await V.api("/v1/admin/access/object?tenant_id=…&document_id=…", { admin:true })`.
  - Handle `HTTP 401` (admin token required) and `HTTP 503` (ReBAC unconfigured) with verbatim teaching messages, exactly like `panel_principals.js:266-275,344-351`.
- **Render (net-new — no existing SVG/graph helper, Map C §3):**
  - **Identity/group closure graph** — build **inline SVG** as an HTML string (or `document.createElementNS`) inside the nonced panel script block. Inline SVG is CSP-legal (markup, not script; `default-src 'self'` does not gate it, Map C §1). Node labels use `V.entityChip(name, source)` styling (name-first person/group chip, `core.js:2061`). Lay out with a simple deterministic layered layout (subject at left, groups by ancestor_depth) — no layout library.
  - **Right-panel corpus breakdown** (by source / confidentiality / provenance) — pure CSS `<div>` bars in a `.card` (`core.css:152`), widths via inline `style="width:NN%"` (allowed — `style-src 'unsafe-inline'`, Map C §1), colors via the frozen palette (`--green/--blue/--amber/--red`) and the existing `.b-conf-*` confidentiality + `.b-mirrored|approximated|admin-assigned|quarantined` provenance badge lanes — **already the exact four provenance lanes and four confidentiality levels the prototype needs** (Map C §3). Counts via `V.badge`/`V.confBadge`/`V.provenanceBadge` (`core.js:2050s`).
  - **Grant-confidence bar** — a single CSS bar segmenting the `grant_confidence` fractions across the four provenance colors.
  - **Paginated documents panel** — `.tablewrap` + `table` (`core.css:382`), metadata columns only (NG2); "load more" wired to `documents.next_after`.
- **Click-a-document → highlight-the-why-path** (the key interaction):
  - Render each document row and each SVG node with `data-*` attributes (e.g. `data-doc="d/abc"`, `data-node="group:eng"`).
  - Wire clicks with the delegated `wire(host, sel, fn)` helper (`panel_principals.js:75-80,551-572`) — reads `data-*` for args. **No inline `on*` handlers** (CSP nonce-only `script-src` blocks them, Map C §1) — this is the mandated pattern.
  - On document click (Mode A): call `/v1/admin/access/object?document_id=…` to get that doc's granting groups, then toggle a `.highlight` class on the matching SVG group/user nodes + draw the granting-path edges — the "why" highlight. On node click: filter the document panel to docs granted via that node.
  - Optional detail via `V.dialog(id)` (`core.js:460`) and `.kv` dl (`core.css:366`) for the full why-path.
- **Rail count pill:** `V.setCount("permgraph", corpus.total.docs, "docs visible")` (`core.js:438`), derived from the same query the panel shows.

**Prototype fidelity:** two-mode `.seg` toggle, inline-SVG closure graph, CSS-bar corpus breakdown + grant-confidence bar, click-doc→highlight-why — all achievable within CSP with zero external libs (Map C §1/§3).

---

## 8. PHASING

### MVP — Endpoint 1 + closure graph + corpus breakdown
- `GET /v1/admin/access/subject` (§3): `user_groups` closure (`rebac.rs:519`) → token resolve (`main.rs:3997` query) → **in-window revocation subtraction** (BUILD, §3.4 step 3) → 3× GROUP BY corpus (`postgres.rs:1802` shape, enforcement-pre-filter predicate) → stored-column keyset docs page (`browse_memories` `postgres.rs:1998` shape, NOT aggregate-keyset).
- Panel Mode A: inline-SVG closure graph, CSS-bar corpus breakdown (source/confidentiality/provenance), grant-confidence bar, paginated metadata-only docs (page-local rollup).
- Audit table (`admin_access_audit`, §5) + admin **`require`** gating (NORMATIVE, no dev-open).
- **BUILD ITEMS (not reuse):** (i) inline revocation subtraction reading the `revocations` table for parity with `scope_for` (§3.4 step 3; the logic exists in `RevocationPlane::subtract`/`windowed_tokens` `revocation.rs:66-110` but must be re-implemented inline, NOT by calling the read-path `scope_for`); (ii) `SET LOCAL statement_timeout` guard on the aggregate/docs scans (no codebase precedent — §6); (iii) stored-column keyset docs rollup.
- **Reuses (real code):** `user_groups`/`group_and_ancestors` `rebac.rs:519/530` (public wrappers; `membership_closure` is private); string→token query `main.rs:3997`; GROUP BY shape `postgres.rs:1802/2065`; keyset shape `browse_memories` `postgres.rs:1998`; `principalPicker` `core.js:2060`; panel assembler `mod.rs`.

### V2 — Endpoint 2 + provenance confidence + why-highlight
- `GET /v1/admin/access/object` (§4): visibility-token decode → **BUILD ITEM 4a** (token→principal SQL) → `group_users` fan-out (`rebac.rs:548`) → **BUILD ITEM 4b** (path-retaining composition).
- **BUILD ITEM 4c — `source`/`entity` decode-scan guards:** `SET LOCAL statement_timeout` + `flags.approximate` + corpus-size ceiling for the unbounded `DISTINCT unnest(visibility)` full scan (§4.4 step 2, §6). `document_id` mode is exempt.
- Panel Mode B + the click-a-document→highlight-the-why-path interaction (§7.2), showing per-user `via` group paths and `acl_provenance`.
- **Reuses (real code):** `group_users` (LookupSubjects) `rebac.rs:548`; `group_direct_members` (ReadRelationships) `rebac.rs:587` for stepwise DAG walk; distinct-visibility decode query (Map B §3).

### V3 — time-travel + revocation-preview
- **Time-travel (`as_of=T`):** drop `valid_to IS NULL`, apply the window `valid_from <= T AND (valid_to IS NULL OR valid_to > T)` — the **exact predicate `fact_as_of` already uses** (`postgres.rs:3208-3244`, transplantable to chunks, Map B §4).
  - **HONESTY CONSTRAINT (must ship in the UI copy):** `fact_as_of` filters the row's **CURRENT** `visibility`/`confidentiality`, NOT a historical ACL (`postgres.rs:3220-3223`; `0026:47-53` "Visibility is NOT part of the bi-temporal VALUE history"). So `as_of=T` answers *"which value existed at T, gated by NOW's ACL"* — an un-shared principal cannot time-travel to reach an old value. For **true historical-ACL replay** ("who could see it back *then*"), the only source is the append-only **`fact_acl_audit`** log (`0026:34-53`: old/new_visibility, reason, changed_at) — reconstructed by replay, and it exists **for facts only, not chunks**. The time-travel mode must state this asymmetry explicitly: **value-history is bi-temporal; ACL-history is audit-log-replay, facts-only.**
  - **Index reality:** `chunks` has **no as-of index** (only `facts_asof_idx`, `0001:53`) — an as-of scan on chunks is unindexed → slow at scale. Flag a future `chunks_asof_idx` (Map B §3/§4).
- **Revocation-preview** (`GET /v1/admin/groups/revocation-preview`): lift `admin_group_remove` steps 1-3 (`main.rs:3976-4007`) **read-only** — `affected` (`group_users` subtree + inner group), `lost_principals` (`group_and_ancestors`), `lost_tokens` (the `SELECT principal, token FROM principals WHERE … principal = ANY($lost_principals)` at `:3998`). Return `{ affected_members, revoked_principals, lost_tokens }` **without** the tombstone write (`:4010`) or tuple delete (`:4016`). This is the "what breaks if I cut this edge" panel; every affected principal's lost corpus can be shown by feeding `lost_tokens` back through Endpoint 1's aggregate.
  - **Reuses (real code):** `admin_group_remove` `main.rs:3960-4027` (steps 1-3 only, verbatim, no mutation); `fact_as_of` window `postgres.rs:3208`; `fact_acl_audit` replay `0026:34`.

---

## 9. TEST PLAN

### Endpoint unit / integration
- **T1 — Scope-correctness (the load-bearing test, G4).** For a subject X, assert the Endpoint-1 corpus aggregate `total.docs` (and per-source breakdown) **equals** the **enforcement pre-filter** set: `tenant_id` + `visibility && tokens` + `confidentiality <= ceiling` + `valid_to IS NULL`, over the **post-revocation** token set (i.e. after subtracting in-window `revocations`, §3.4 step 3) — NOT recall's ANN-returnable set (so `kind`, `{col} IS NOT NULL`, entity_scope are deliberately NOT in the baseline; align with the real enforcement pre-filter, cf. `postgres.rs:2805-2812`). Method: resolve X's tokens, subtract in-window revocations, run the admin aggregate, then independently run the enforcement-pre-filter query for the same post-revocation tokens read at the same instant and assert equality. **Revocation sub-case:** revoke a token in-window, assert the aggregate drops the corresponding docs (parity would fail without step 3's subtraction). Must hold for `max_confidentiality` variations. Note parity is window-read-instant-sensitive (§3.4 step 3).
- **T2 — Fail-closed subject.** Unknown/unresolvable `subject` → `subject_resolved:false`, empty tokens, empty corpus + empty documents (never permissive). Subject with groups but zero materialized tokens → empty corpus.
- **T3 — Fail-closed ReBAC.** ReBAC unset → 503 (`require_rebac`), not a partial answer.
- **T4 — Tenant isolation.** Same `subject`/`document_id` string in tenant A and tenant B returns disjoint results; a token from tenant A never resolves against tenant B's `principals` (enforced by `tenant_id` predicate). Cross-tenant `document_id` → empty.
- **T5 — Endpoint 2 reverse correctness.** For a document with known `visibility` tokens, assert `principals` = token→string resolve of exactly those tokens (BUILD 4a), and `reachable_users` = union of `group_users` over the group principals + direct users (BUILD 4b). Assert `via` paths are non-empty for every reachable user.
- **T6 — Metadata-not-content (NG2).** Assert no endpoint response contains chunk `content`; assert no SQL in the handlers selects the `content` column (static/grep test).
- **T7 — Read-path non-regression + no shared seam (§2).** Structural assertion that (a) recall/get handlers do not reference the new handlers/queries, AND (b) the new handlers do not reference the shared read-path helpers `enforce_restricted` / `current_token_set` / `scope_for` / `storage.recall` (grep-level) — so the new admin plane never shares the read-path Restricted-recheck seam. The scope-parity test (T1) doubles as behavioral proof the read path is unchanged.
- **T7b — `require` gating (no dev-open).** Assert every Permission Graph endpoint returns **401** when `VERITY_ADMIN_TOKEN` is unset (mirroring `SecretIntakeAuth`), even on a loopback bind — proving `require`, not `check`, gates the god-view.
- **T8 — Scale guards (both endpoints).** With a company-wide token set (Endpoint 1) and a corpus-spanning `source`/`entity` decode (Endpoint 2), assert the `SET LOCAL statement_timeout` fires and the handler returns with `flags.approximate_counts`/`approximate`/`fanout_truncated`/`closure_truncated` set (doesn't hang, doesn't hold a pooled connection). Assert `source`/`entity` mode is refused (or bounded) when the corpus exceeds the ceiling until a supporting index exists.
- **T9 — Audit write.** Every successful query writes exactly one `admin_access_audit` row with `result_meta` counts only (no content).
- **T10 (V3) — Time-travel honesty.** Assert `as_of` uses the current-ACL-gated value window (matches `fact_as_of` semantics), and that the UI/response carries the value-history-vs-ACL-history caveat; assert historical-ACL replay is sourced from `fact_acl_audit` and is facts-only.
- **T11 (V3) — Revocation-preview is non-mutating.** Assert the preview endpoint writes no tombstone and deletes no tuple (DB state unchanged before/after), and its `affected_members`/`lost_tokens` match `admin_group_remove`'s computed values for the same edge.

### UI smoke
- **T12 — Panel loads + CSP-clean.** Panel registers, renders the two-mode `.seg`, autoloads on tenant set, renders inline SVG + CSS bars + doc table; browser console shows **zero CSP violations** (no external script, no inline `on*`). Reuse the existing paint-regression coverage by including `"panel-permgraph"` in the `mod.rs:288-305` array.
- **T13 — Why-highlight interaction.** Clicking a document row highlights the granting group/user nodes and draws the why-path edges (Mode A → Endpoint 2 call); 401/503 render verbatim teach states.

---

## 10. OPEN QUESTIONS / RISKS

1. **Audit durability.** Durable `admin_access_audit` table (§5) vs. tracing-log-only for MVP. The god-view sensitivity argues durable; confirm migration is in-scope for MVP.
2. **Actor identity in the audit.** The bearer is an HMAC-verified opaque token, not a named admin identity (Map A §1). What do we record as `actor`? Options: a configured admin label, the token fingerprint, or `dev-open`. Needs a decision.
3. **Why-path completeness at depth.** `group_users` returns flattened users; reconstructing exact stepwise `via` paths for deeply-nested groups via `group_direct_members` DAG walks (BUILD 4b) could be O(edges) — acceptable at hundreds of groups, but confirm the nesting depth in real tenants.
4. **Company-wide-group selectivity.** Low-selectivity `&&` on an `all-staff` token may seqscan (Map B §3). Do we accept "approximate" counts + statement timeout for MVP, or invest in materialized per-principal counters earlier? Needs a measured decision on `my-workspace` (§6 cold-cache benchmark).
5. **chunks as-of index (V3).** Time-travel on chunks is unindexed (Map B §4). Is a `chunks_asof_idx` in scope for V3, or do we gate time-travel behind a corpus-size limit until then?
6. **Historical-ACL replay for chunks.** `fact_acl_audit` is facts-only (Map B §4). True "who could see this *back then*" for **chunks** has no data source today. Is chunk ACL-audit a future migration, or do we scope V3 time-travel to value-history + facts-only ACL-history and say so plainly?
7. **Cross-source welding gap (from memory).** Known open gap: cross-source identity welding. A person may appear under different principal strings per source; the closure graph reflects the SpiceDB mirror only. Flag that Endpoint-1 "what X sees" is complete *within the mirrored graph* but may miss un-welded cross-source identities — an honesty caveat for the UI.
8. **Facts vs chunks in the corpus total.** `include_facts` unions L1 facts (Map B §2). Confirm the prototype's "total" is chunks-only, facts-only, or both — affects the grant-confidence `basis`.
9. **Approximate badge UX.** When `flags.approximate_counts` is set, the prototype needs a visible "approximate" badge; confirm placement so operators never mistake a timed-out count for ground truth.
