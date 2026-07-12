# FTUE.md — Verity's first hour (build contract)

Status: **contract** — like SPEC.md, implementation follows this document; where reality
disagrees, this file gets amended publicly, not ignored.
Grounding: first-boot reality report (2026-07-11, v0.1.0), prior-art catalog, and the
first-run vocabulary table (§9 below reuses its copy verbatim). Constraints inherited
wholesale from UI-ACTIONS.md §0 (THE LAW) and SPEC.md non-negotiables.

---

## 0. Governing principle

**Denial is the product.** The first hour is engineered so the newcomer's celebrated
moment is a *correct empty result with a visible reason* — not a grant, not a green
dashboard. Every convenience below (picker, wizard, sample data, pre-filled snippets)
exists to assemble the minimum cast for that proof: **one tenant, two keyrings, one
scoped memory, one recall that hits, one recall that provably doesn't.**

Three findings from the first-boot report drive everything here:

1. **Every screen teaches, nothing bootstraps.** All 10 panels have good empty-teach
   cards, but every card's advice is circular ("paste a tenant id" you cannot obtain).
2. **The ghost-tenant trap.** The server mints handles for tenants that were never
   born; a fabricated uuid yields a fully plausible, permanently empty console.
   Fail-closed for data, fail-*silent* for onboarding — this is a server bug, fixed here.
3. **The cheapest win is already built.** `?tenant=<uuid>` deep-linking exists in
   core.js:349 and neither the CLI nor demo.sh uses it.

---

## 1. First-run detection (how the console decides what to show)

Detection is **derived from server truth on every load. Never from localStorage.**

On shell boot, core.js calls the new `GET /v1/admin/tenants` (with the session's admin
token if set; in dev mode it needs none):

| Server answer | Console behavior |
|---|---|
| `200` + empty list | **State A — virgin server.** Home renders the Welcome flow (§3). Every other panel's no-tenant card gains a primary button **"Set up Verity"** that routes to it. The old "paste a tenant id" advice disappears in this state — there is nothing to paste. |
| `200` + non-empty list | **State B — tenants exist.** The session strip's paste-a-uuid box becomes a **tenant picker** (dropdown of names; uuid shown only as dim secondary text). `?tenant=` deep link still wins over the picker. A deep-linked or previously-remembered uuid **not in the list** shows a red session-strip banner: *"This tenant doesn't exist on this server. Pick a real one, or set one up."* — never a green all-clear. |
| `401` | **State C — locked admin plane (prod).** Session strip shows: *"Enter your admin token to list tenants and run setup."* Paste-a-uuid remains available for operators who already know their tenant. No wizard until a token is present. Admin token stays sessionStorage-only per THE LAW. |
| `404`/`405` (old server) | Fall back to today's paste behavior unchanged. |

**Per-tenant checklist detection (State B):** when a tenant is selected and Home loads,
the setup checklist (§4) renders whenever any of its server-derived items is incomplete,
collapses to a single dismissible-per-session row when all are complete. State is
recomputed from endpoints on every Home load — resumable across machines, immune to
cleared browser state, never a stored lie.

---

## 2. Server changes (three, all small — do these first)

1. **NEW `GET /v1/admin/tenants`** → `200 {"tenants":[{"tenant_id":…,"name":…,"created_at":…}]}`,
   admin-gated exactly like `POST` (main.rs:345). Requires a `list_tenants` method on the
   `StorageAdapter` trait + Postgres impl. This is the **only new endpoint** in this
   contract. No setup-status endpoint: checklist state is derived (§4).
2. **Kill the ghost-tenant trap:** `POST /v1/scopes` validates tenant existence and
   returns `404 {"error":"unknown tenant","hint":"create one: POST /v1/admin/tenants, or run verity-cli dev"}`
   for a uuid that was never born. Fail-closed includes fail-*loud* at the front door.
3. **Break the silent boot (Stumble 0):** when `RUST_LOG` is unset, default the tracing
   filter to `info` (main.rs:247 area), and unconditionally print to stdout on bind:
   `verity v0.1.0 listening on http://127.0.0.1:7851 — console: http://127.0.0.1:7851/ui`
   plus one line when migrations run (`applied N migrations`). A bare `./verity` must
   never look like a hung terminal.

Everything else in this contract uses **existing** endpoints:
`POST /v1/admin/tenants` · `GET|POST /v1/admin/principals` · `POST /v1/admin/groups` ·
`POST /v1/scopes` · `POST /v1/ingest/debezium` · `POST /v1/ingest/documents` ·
`POST /v1/episodes` · `POST /v1/knowledge` · `POST /v1/webhooks` + `POST /wh/{token}` ·
`POST /v1/recall` · `POST /v1/admin/debug/recall` · `GET /v1/admin/audit` ·
`GET /v1/activity` · `GET /v1/admin/quarantine` ·
`POST /v1/admin/erasure/preview` + `POST /v1/admin/erasure` · `POST /v1/forget`.

---

## 3. The flow — step by step, exact copy

Delivery vehicle: a **setup panel** (`panel_setup`) mounted where Home's content renders
in State A, and reachable any time from the rail / checklist. It is a page, **not a
modal**; the rail stays live and every panel stays explorable throughout (their empty
states now teach truthfully because §1 removed the circular advice). Steps are shown as
a left-edge progress spine; completed steps collapse to one green line; any step can be
revisited. Ten-second comprehension per screen; every uuid is secondary dim text, never
a field the user authors.

### Step 0 — Welcome (State A only)

> ## Welcome to Verity
> Verity is shared memory for your AI agents — everything they learn, in one place,
> carrying the same sharing rules your company already has.
>
> One thing to know before you start: **when Verity isn't sure someone may see a
> memory, it shows them nothing.** An empty result here is a safety answer, not a bug —
> and by the end of setup you'll see exactly why that's the feature.
>
> **[ Set up Verity — about 5 minutes ]**   [ I already have a tenant id ]

("I already have a tenant id" reveals the classic paste field for operators joining an
existing deployment; it validates against the tenant list, so ghosts are impossible.)

### Step 1 — Your space

> ### Name your space
> **The company that owns this memory space — self-hosting means that's you, and
> there's exactly one.** *(what's this? →)*
>
> Space name: [ Acme Logistics……… ]        **[ Create ]**
>
> ⓘ You are the **tenant**; your customers are **entities** — things memories are
> *about*, scoped inside your space. Customers never get their own tenant.

- `POST /v1/admin/tenants {"name": …}`; on success the console **auto-adopts** the
  returned `tenant_id` (existing `setTenant` path, core.js:542) and shows
  `✓ Acme Logistics created` with the uuid as dim copyable secondary text.
- The name field is the only input. **No uuid is ever typed by a human in this flow.**
- "what's this?" expands the tenant + entity rows from the vocabulary table (§9).
- Kills founder confusions #1, #2, #4, #5 (blank-uuid fields, customers-as-tenants).

### Step 2 — Who can ask

> ### Add the first keys
> A **principal is a key** — one identity that memories can be shared with. A **user
> is the person carrying the keyring**; a **group is a shared key** many people hold
> at once. Sharing rules are written against keys, never against logins. *(what's this? →)*
>
> Add yourself:  Your name [ Matt……… ] → will create the key `user:matt`
> Add a team (optional): [ sales……… ] → will create the key `group:sales`
>
> **[ Create keys ]**       [ skip — I'll use the identity panel later ]

- Create-don't-paste: the user types names; the console derives principal strings
  (`user:<slug>`, `group:<slug>`, editable before create, never blank) and calls
  `POST /v1/admin/principals` (+ `POST /v1/admin/groups` for membership). Materialized
  int tokens are **never** shown as primary text.
- Minimum to proceed: one person. Kills founder confusion #3 (principal ≠ user).

### Step 3 — Open a session

> ### Mint your working handle
> A **scope handle is your signed session pass**: this space + whose keys are asking +
> which customers + how sensitive it may go. Every read is filtered through it — a
> session can narrow it, never widen it. It is not an API token: it's a pre-computed
> answer to *what this session may see*. *(what's this? →)*

- Reuses the **existing global mint dialog** (core.js:446–573) verbatim, pre-filled:
  tenant locked to the space from step 1 (shown by name), principals pre-checked to the
  person from step 2 plus their groups, entities empty ("all your customers"),
  **ceiling defaulted to `internal`** with the four classes listed in order and the
  ceiling one-liner from §9 beside the selector.
- Each of the four fields carries its §9 row as its "what's this?". One-time handle
  display and Scope-Inspector handoff behave exactly as today; auto-adoption makes this
  handle the session's working handle. Kills founder confusion #7 (mint is now the
  front door, not buried behind decode).

### Step 4 — Put memory in (the fork)

Two cards, **equal visual weight**:

> **Explore with sample data**
> Meet **Acme Logistics (sample)** — three people, two teams, one connector, and
> fourteen memories carrying real sharing rules: some org-visible, some team-only, one
> restricted, one field that got superseded, and one item that lands in **quarantine on
> purpose**. Everything is labeled `sample` and removable in one click, using the same
> erasure pipeline you'd use for a real deletion request.
> **[ Seed the sample org ]**

> **Start clean — add your first memory**
> Write one memory yourself. You'll be asked **who can see it** before anything else,
> because Verity never guesses: **leave visibility empty and nobody can see it, ever.**
> *(what's this? →)*
> **[ Open the ingest panel ]**

Sample-data rules (the honest-seeding decision):
- **Mechanism: console-side seeder** (`sample_cast.js`) that replays a trimmed
  demo.sh-shaped cast through the **existing public endpoints** — no new server
  surface, no data baked into the serving binary, ships this week. demo.sh remains the
  full-kitchen-sink CLI demo; the wizard cast is a documented subset of its steps 6–8.
- Cast: principals `user:jordan` (sales), `user:taylor` (support), `group:sales`,
  `group:support`, `agent:acme-crm`, and the guaranteed-blind **`user:sample-blind`**
  ("holds no keys, sees nothing, ever — Verity's `4242 4242`"). Data: CDC upserts via
  `/v1/ingest/debezium` under `source: verity-sample-crm` including one superseded
  field (bi-temporal exemplar visible in record detail), episodes via `/v1/episodes`
  scoped to `group:sales`, one `restricted` pricing note, one org-visible note, one
  webhook item with an unmappable ACL that **quarantines** (via `/v1/webhooks` +
  `/wh/{token}`), and one knowledge candidate via `/v1/knowledge`.
- **Labeled everywhere:** every sample record carries source/tag `verity-sample*`; all
  panels render a `sample` badge on such rows (one shared check in core.js). Sample
  rows are excluded-by-label from any benchmark corpus — "every measured number is
  honest" extends to never letting seed data contaminate a measurement.
- Seeding is idempotent (keyed upserts + fixed ids) — clicking twice doesn't duplicate.
- **Removal is honest:** a "Remove sample data" action (on Home's checklist row and in
  the erasure panel) runs `POST /v1/admin/erasure/preview` scoped to the sample
  subjects, shows the preview, requires the typed confirm, then `POST /v1/admin/erasure`:
  > "This runs Verity's real erasure pipeline — the same crypto-shredding path you'd
  > use for a GDPR request. Sample memories are purged; the audit record of their
  > lifecycle remains."
  If erasure cannot target a subject set in the current build, fall back to
  `POST /v1/forget` with copy that says **invalidated, not erased** — never a
  special-cased delete path, never a silent one.
- Choosing "start clean" routes to panel_ingest's existing first-run teach
  (panel_ingest.js:251–320 — already correct), with the wizard spine still visible.
  Either card satisfies checklist item 4. Kills founder confusion #6: after seeding,
  no panel is empty; without seeding, every empty panel states *why* it's empty.

### Step 5 — The proof (the aha)

A side-by-side compare surface: **same query, two sessions**. Left column runs
`POST /v1/recall` with the step-3 working handle; right column with a handle minted for
`user:sample-blind` (sample path) or for a second principal holding no keys to the
user's first memory (clean path — the wizard mints it, labeled).

> ### Same question. Two sessions.
> [ query: "what's the latest on the Acme renewal?" ]  **[ Run both ]**
>
> **matt's session** — 3 memories        **sample-blind's session** — **0 memories**
> …results…                              This is correct. No memory here carries a key
>                                        this session holds — **an empty result is a
>                                        safety answer, not a bug.** Nothing about
>                                        these memories — not even that they exist —
>                                        reached this session. *(why? →)*
>
> **[ Show the why-trace ]** (admin-only debug recall)
>
> ✓ **Denied — correctly.** This refusal is Verity's whole pitch: scope filters are
> baked into the index as mandatory pre-filters, so out-of-scope memory never reaches
> the model at all. Everything else you build on Verity sits on the guarantee you just
> watched work.

- The compare is **two ordinary recalls composed client-side** — nothing new on the
  read path, no instrumentation inside `recall`, ever.
- "Show the why-trace" calls the existing `POST /v1/admin/debug/recall` — the explain
  oracle is already admin-gated, so explanations can't leak existence to non-operators.
- Copy discipline: the UI says **"provably sees nothing"** only adjacent to the
  expander that states exactly what is guaranteed (materialized mandatory pre-filter,
  one enforcement layer above the StorageAdapter) — claims obey the same honesty rule
  as latency numbers.
- This surface is permanent, not throwaway: it also mounts in the Scope Inspector as
  **"Compare two handles"** and becomes the ongoing audit/debug tool and the README's
  lead screenshot.

### Step 6 — Land

Wizard collapses; Home renders with the checklist fully green plus:

> **Your memory plane is up — and it already told someone "no."**
> Next, when you're ready:
> **[ Connect Claude Code ]** — copy-paste MCP block, pre-filled with *your* url,
> tenant, and principals (the dev.rs:300 block, rendered in-console)
> **[ Connect a real source ]** — mirror the permissions your tools already have
> **[ Run the latency benchmark ]** — *no numbers appear anywhere until your own
> benchmark has run; this slot stays honestly empty until then*
> [ Remove sample data ]  ·  [ Replay setup ]

---

## 4. Checklist mechanics (Home, per tenant)

Six items + one optional, pinned to Home. **Persistent by derivation** — every item's
state is recomputed from server truth on load; there is no stored checklist state to
lie. Skippable (each item is a link, nothing gates anything), resumable (derivation is
machine-independent), never a modal.

| # | Item (copy) | Derived from (existing endpoints) |
|---|---|---|
| 1 | **Space created** — "Acme Logistics exists" | `GET /v1/admin/tenants` (new, §2) |
| 2 | **Keys added** — "at least one person or group holds a key" | `GET /v1/admin/principals?tenant_id=…` count ≥ 1 named principal |
| 3 | **Session open** — "this browser session holds a working handle" | handle present in this session (sessionStorage; honestly labeled *per-session* — re-mint is one click, and the item's link IS the mint dialog) |
| 4 | **Memory in** — "at least one memory is stored (or quarantined — that counts: it means the gate works)" | the counts Home already loads + `GET /v1/activity` / `GET /v1/admin/quarantine` |
| 5 | **First recall hit** — "a scoped recall returned results" | `GET /v1/admin/audit` filtered to recall events for this tenant (recalls are audited; if a build lacks recall audit events, items 5–6 derive from the proof screen having produced both responses this session, labeled per-session — never a fake checkmark) |
| 6 | **Denial verified** ✦ — "a session that holds no matching keys got zero results, with the why-trace to show for it" | `GET /v1/admin/audit`: a zero-result recall by a principal distinct from item 5's |
| ✚ | *(optional, after 6)* **Benchmark run** — "measure YOUR p50/p95/p99 on YOUR corpus" | presence of a benchmark result artifact; until then the card shows no numbers |

Item 6 is the celebrated one (checkmark styled distinct, fires the step-5 "Denied —
correctly" copy). **The checklist ends at verified denial** — granting the blind
principal access is deliberately *not* an item; a checklist that greens-up by opening
things would teach the opposite of the product.

No "mark as done" buttons exist anywhere. If the system can't observe it, it isn't an
item.

---

## 5. CLI alignment (`verity-cli dev` meets the console at the same moment)

Changes to `crates/verity-cli/src/dev.rs` (+ `deploy/demo.sh`):

1. **Print the deep link** — dev.rs:276 becomes
   `kv("console", &format!("{}/ui?tenant={tenant_id}", ctx.url))` (and demo.sh prints
   the same form). Following it lands on a **loaded console showing the checklist with
   items 1–2 already green** — the two entry paths converge on the identical screen.
2. **Name the magic number** — instead of the bare org-wide token `[1]`, dev.rs
   registers the principal string `user:dev` via `POST /v1/admin/principals` and prints:
   `principal      user:dev (token 1) — the org-wide key your dev session holds; see People & groups in the console`
3. **Print the tenant as a named thing** — `tenant         dev (0197f3…)`, one line:
   `the tenant is the company that owns this space — that's you; your customers live inside it as entities`
4. **Expiry honesty** — after the handle line:
   `handle expires in 12h — when verity-cli commands start failing, rerun 'verity-cli dev' to renew`
5. **Keep** the existing closer ("every write needs --visibility: Verity never guesses
   who may see a memory") — it is the same ethos line as Step 0; the two paths must
   speak identical sentences.
6. Next-steps gains one first line: `open the console — your setup checklist is waiting: {url}/ui?tenant={tenant_id}`

With §2.3 (loud boot), the bare-binary path also self-explains: `./verity` prints its
listen line + console URL, and the console handles the rest via State A.

---

## 6. File ownership

| Owner | Files | Work |
|---|---|---|
| **Server (Rust)** | `crates/verity-server/src/main.rs`, storage adapter + Postgres impl, `scope.rs` | §2: `GET /v1/admin/tenants` (route + handler + `StorageAdapter::list_tenants`); tenant-existence 404 in `open_scope`; default `info` tracing + unconditional bind/migration stdout lines |
| **Console — core** | `crates/verity-server/src/ui/core.js` (+ `theme.css` only if a `sample` badge class is missing) | Tenant picker replacing paste-a-uuid in the session strip (States A–C, §1); ghost-uuid banner; shared `sample` badge helper; route hook for `panel_setup` |
| **Console — wizard** | NEW `crates/verity-server/src/ui/panel_setup.{html,js}` | Steps 0–3 + fork + land; reuses the existing mint dialog and `empty-teach` kit; vanilla JS, zero external requests, frozen theme/core classes |
| **Console — sample** | NEW `crates/verity-server/src/ui/sample_cast.js` | The Acme Logistics cast as data + idempotent seeder over existing endpoints; "Remove sample data" via erasure preview→confirm→erasure (forget-fallback with honest copy) |
| **Console — proof** | NEW `crates/verity-server/src/ui/panel_compare.js` (mounted in setup step 5 AND in `panel_scope` as "Compare two handles") | Two client-side recalls side-by-side; fail-closed copy; why-trace via `POST /v1/admin/debug/recall` |
| **Console — home** | `crates/verity-server/src/ui/panel_home.js` | Server-derived checklist (§4) replacing/extending the existing no-tenant teach card; completion state; next-steps cards incl. in-console MCP block and the honestly-empty benchmark slot |
| **Console — copy pass** | all `panel_*.js` touched by §9 | Point-of-use vocabulary lines + "what's this?" expanders at the placements in §9; empty states updated to state *why* empty |
| **CLI** | `crates/verity-cli/src/dev.rs`, `deploy/demo.sh` | §5 items 1–6 |

---

## 7. OUT — explicitly not in the first hour

- **No forced tour, coach marks, or modal welcome wall.** The wizard is a panel; the
  rail never locks; every step is skippable.
- **No self-reported checkmarks**, no localStorage checklist state, no
  "mark as done".
- **No LLM calls anywhere in the FTUE**, and **nothing added to the read path** —
  the proof view is composed client-side from ordinary recalls; explain lives only in
  the admin-gated debug endpoint.
- **No permissive dev-mode semantics.** Dev mode fails closed identically to prod;
  the only bootstrap conveniences are the dev admin plane (already loudly warned) and
  the CLI's 12h handle — both named, printed, and expiring.
- **No silent seeding, no invisible default principal, no implicit "public" scope,
  no default visibility.** Omission refuses, in the wizard exactly as in the API.
- **No "index it anyway" exit from quarantine** — the sample quarantined item teaches
  the two real exits only.
- **No fabricated numbers.** No latency/quality figures anywhere until the user's own
  benchmark runs; the slot stays visibly empty and says so.
- **No tenant auto-creation from a pasted/deep-linked uuid** — unknown tenants are a
  loud error, never a lazily-born space.
- **Deferred past the first hour:** connecting a real ReBAC source, MCP wiring
  (offered as a Step-6 card, not a wizard step), knowledge-lesson review (its vocab
  line appears on first queue item, per §9), entity-resolution weld review, the
  benchmark (optional 7th item), multi-tenant operator workflows, any prod-hardening
  ceremony beyond what exists.

---

## 8. Acceptance criteria

The flow itself — no docs, no source-reading — must answer each founder question at the
stated moment:

1. **"What's a tenant / is it me or my customer?"** (confusions #1/#2/#4) — answered in
   Step 1 by the tenant/entity contrast pair, before any tenant exists.
2. **"Where do I get the uuid?"** (#5) — unanswerable-by-design: no human types a uuid
   anywhere in the flow; picker + deep link + auto-adoption cover every path. Grep the
   wizard for a uuid input field → must be zero.
3. **"Principal vs user?"** (#3) — Step 2's keyring copy, at the field where keys are
   created.
4. **"What is this handle thing?"** (#7) — mint is Step 3, the front door; four fields
   each carry their one-liner.
5. **"Why is this panel empty?"** (#6) — post-fork, either every panel has labeled
   sample data, or its empty state names the reason and offers a working button.
6. **"Is the empty recall a bug?"** — Step 5 attaches the fail-closed line + why-trace
   to the zero at the moment it happens, and the checklist *celebrates* it.

And the first-boot report's dead-ends must be dead:

7. Fresh server + console, zero terminal use → a newcomer reaches the Step-5 proof in
   under 10 minutes with sample data (target: 5), under 20 clean.
8. The Path-B circular chain (mint-needs-tenant-needs-mint) is unreachable: State A
   never advises pasting; the mint dialog in State B offers the picker.
9. Ghost tenant: `POST /v1/scopes` with a never-born uuid returns 404; pasting or
   deep-linking one shows the red banner, never "all clear".
10. `./verity` on a fresh db prints listen line, console URL, and migration count with
    no env vars set.
11. `verity-cli dev` then clicking the printed link lands on a console already scoped
    to the dev tenant with checklist items 1–2 green and `user:dev` visible in People &
    groups.
12. Sample data: every sample row shows the `sample` badge in every panel; seeding
    twice creates nothing new; "Remove sample data" previews, requires typed confirm,
    and the copy truthfully names the mechanism used (erasure vs invalidate).
13. Checklist state survives: complete steps, clear all browser storage, reload → items
    1–2 and 4–6 still green (3 honestly per-session); no item can be checked without
    its server-side evidence existing.
14. Read-path purity audit: `git diff` for the FTUE lands zero changes inside `recall`
    / the enforcement layer; the proof view issues only standard `POST /v1/recall`
    calls.
15. `cargo fmt` + `cargo clippy -D warnings` pass; console remains vanilla JS with zero
    external requests.

---

## 9. Vocabulary placement (copy source: the first-run vocabulary table)

The one-liners and expansions are **verbatim** from the vocabulary table
(docs/design — first-run vocabulary, 2026-07-09/11). Placement, in flow order:

| Concept | Where it appears in this contract |
|---|---|
| Tenant | Step 1 headline; CLI §5.3; tenant picker tooltip |
| Entity | Step 1 contrast pair; mint dialog entity field (Step 3) |
| User / Principal / Group | Step 2, in keyring order (user → principal → group); People & groups panel create actions |
| Scope handle | Step 3 intro; mint dialog header |
| Confidentiality ceiling | Step 3 ceiling selector (default `internal`, four classes in order) |
| Visibility | Step 4 clean-path card + panel_ingest required field (already built) |
| Fail-closed | Step 0 ethos sentence; Step 5 zero-result panel; CLI closer (§5.5) |
| Quarantine | Sample cast's quarantined item inline notice + quarantine queue badge |
| Knowledge lesson | NOT in the wizard — first knowledge review-queue item only |
| Provenance (mirrored/assigned) | `sample` badge neighbor on recall results/record detail; connect-source wizard (post-FTUE) |

---

## 10. Build order (dependency spine)

1. **T1 Server trio (§2)** — unblocks everything; ~1 day.
2. **T2 core.js picker + deep-link + ghost banner (§1)** — makes State B real.
3. **T3 panel_setup steps 0–3** — reuses mint dialog; State A becomes navigable.
4. **T4 sample_cast.js seed + removal** — the fork's left card.
5. **T5 panel_compare + why-trace** — the aha; also mounts in Scope Inspector.
6. **T6 panel_home checklist (§4)** — derivation + celebration + Step-6 cards.
7. **T7 CLI/demo.sh alignment (§5)** — 20 lines; do anytime after T1.
8. **T8 vocabulary copy pass (§9)** — across panels; last, against frozen screens.

T1→T2→T3 are strictly ordered; T4/T5/T7 parallelize after T3; T6 needs T4+T5; T8 last.
