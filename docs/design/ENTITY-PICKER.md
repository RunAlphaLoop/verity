# Verity Console — Entity Picker (v1)

*One shared component for every field that names an entity · the Emptiness Law · the directory endpoint*

**Status:** build contract for the entity-picker system. Subordinate to `UI-SPEC.md`
(chrome, fail-closed gates) and `UI-ACTIONS.md` §0 (ten-second comprehension, plain
language, empty states teach, data auto-loads). Where implementation reality
contradicts this doc, amend the doc publicly — do not silently diverge.

**Grounding:** full inventory of every hand-typed entity reference in
`crates/verity-server/src/ui/` (11 surfaces, exact ids and line numbers cited below);
enforcement queries in `crates/verity-storage/src/postgres.rs` (`entity_scope_predicate`
:1862, BM25 residual :1834, activity containment :2826, de-id lexicon union :2322–2327);
router and scope semantics in `crates/verity-server/src/main.rs` (`resolve_entities`
:227–245, `open_scope` :560, admin routes :316–363).

**Founder evidence (2026-07, verbatim intent):**
(a) screenshot of the mint dialog's *"limit to entities (optional, comma-separated)"*
free-text field — "we need to have a better interface for building lists of entities,
right?"; (b) "during setup, no data has been ingested, so why would we show it?" —
fields must be context-aware. Standing context: **entities are born by usage** — a tag
like `account:acme` comes into existence when data carries it; there is no
create-entity registry, and this design must never introduce one.

---

## 0. The problem, in one table

Eleven console surfaces reference entities. Nine of them are bare free-text inputs
with comma- (or whitespace-, inconsistently) split parsing, no shape check, no
existence check, and no awareness that the tenant may have zero entities. The failure
modes are not symmetric:

| Direction | Surfaces | What a typo does |
|---|---|---|
| **Scope-limiting** (`entity_scope`) | global mint `#mint-entities` (core.js:625), webhook mint `#src-mint-entities` (panel_sources.js:214), derive `#sc-mint-ent-free` (panel_scope.js:910) | Fails closed but **silently**: the handle mints fine, every recall is empty forever — a "mysteriously blind" agent. For webhooks this binds standing infrastructure that cannot be listed or edited afterward. |
| **Tagging** (`entities` / `entity_tags`) | ingest `#ing-ents` (panel_ingest.js:208), quarantine re-ingest `#qr-tags` (panel_quarantine.js:209) | Does **not** fail closed — it fails *creative*: `account:acmee` births a permanent ghost entity and misfiles the memory under it. Invalidate-don't-delete makes the ghost immortal. |
| **Targeting** (erasure/DSAR) | `#er-entity`, `#er-subject` (panel_erasure.js:229–231) | Compliance-grade: exact-string match means a consistent typo yields a silently incomplete erasure, and the typed-confirm ritual re-types the same wrong string — zero protection. |
| **Probing / filtering** | `#sc-brief-e` (panel_scope.js:128), audit filters (panel_audit.js:262, 291) | Probe: the fail-closed teaching copy ("emptiness is a correct answer") actively launders typos into principled zeros. Audit filters: substring, forgiving, harmless. |

Cross-cutting defects: (a) parsing is inconsistent — core.js and `#ing-ents` split on
commas only while quarantine/derive split on `/[\s,]+/`, so `account:acme deal:x` is
one malformed tag on some surfaces and two on others; (b) nothing validates the
`type:name` shape or offers known tags; (c) nothing checks whether the tenant has any
entities at all — the welcome wizard (panel_welcome.js:667–673) opens the mint dialog
at the exact moment zero entities exist.

The one existing picker-shaped affordance — the derive dialog's checkbox list with
refuse-to-widen validation when the source handle already carries a scope
(panel_scope.js:900–926) — is the pattern this contract generalizes.

---

## 1. What "known entities" honestly means

Four candidate vocabularies exist in the store; only one is honest for a picker:

| Set | Where | Enforced against? |
|---|---|---|
| Chunk tags | `chunks.entity_tags text[]` (GIN, `migrations/0001_init.sql`) | **Yes** — recall pre-filter (`<@`, postgres.rs:1862/1834) |
| Action entities | `actions.entities text[]` (GIN, `migrations/0002_actions.sql`) | **Yes** — activity/brief filter (`@>`, postgres.rs:2826) |
| Canonical entities | `entity_aliases.canonical_entity` | No — display/merge layer; lists **merged entities only** (postgres.rs:1115) |
| Fact entity ids | `facts.entity_id` | No — source-native L1 ids (`hs-1`), different vocabulary |

**The picker's directory is `distinct(chunks.entity_tags) ∪ distinct(actions.entities)`
and nothing else.** That union is exactly what scope enforcement filters on; counting
anything else would show entities the scope filter cannot see. (The internal de-id
lexicon query at postgres.rs:2322–2327 already computes a superset of this union — it
additionally includes `facts.entity_id`, which is correct for leak-screening and noise
for a picker.)

Two hard truths the picker must encode, from the enforcement code:

1. **Matching is exact, case-sensitive string equality** (Postgres array containment).
   `account:Acme` silently matches nothing. The picker warns on near-misses; the
   server never will.
2. **"Well-formed" is convention, not law.** The server binds tags verbatim
   (`upsert_chunks`, postgres.rs:2166) and `open_scope` accepts `entity_scope` with
   zero format validation. The convention is `type:name`, lowercase
   (`account:acme-corp`; source-native refs are `source:entity_id` like
   `hubspot:hs-1`). The picker lints against
   `^[a-z0-9_-]+:[a-z0-9._@-]+$` as a **soft warning with explicit
   confirm** — never a hard block, because born-by-usage means an operator may
   legitimately need a shape we didn't predict. Server-side validation stays out (§6).

---

## 2. The component — `Verity.entityPicker(mountEl, opts)`

A reusable core.js builder, vanilla JS against the frozen theme/core kit, zero
external requests. Registered on the exported `Verity` object next to `entityBadges`
(core.js:842).

### 2.1 API

```js
const picker = Verity.entityPicker(mountEl, {
  // --- semantics -----------------------------------------------------------
  mode: "scope" | "tags" | "target" | "probe",
      // wording pack + rules (see 2.4). REQUIRED.
  multiple: true,          // false → single value (erasure target, brief probe)
  allowNew: true,          // false → known-only; typing an unknown tag is refused
                           //   inline ("target" mode default)
  restrictTo: null,        // string[] — closed set; anything outside is refused
                           //   with "refusing to widen" copy (derive-with-scope)
  liveOnly: true,          // directory param; erasure passes false (see §4)
  // --- presentation --------------------------------------------------------
  placeholder: "account:acme",
  explainer: "",           // one plain-language line under the field; per-surface
  emptyBehavior: "hide" | "teach",   // the Emptiness Law (§3). REQUIRED.
  emptyLabel: "",          // override for the collapsed/teaching line (has defaults)
  prefill: [],             // string[] — rendered as chips on mount
  // --- wiring --------------------------------------------------------------
  tenantId: () => Verity.tenant(),   // function, re-read on each directory fetch
  onChange: (values) => {},          // fires on every chip add/remove
});

picker.value();        // → string[] — the chips, and ONLY the chips.
                       //   In-progress typed text is NEVER part of value().
picker.set(values);    // replace chips (used by prefill-from-handle flows)
picker.clear();
picker.refresh();      // re-fetch directory (after an ingest lands, etc.)
picker.collapsed();    // → bool — true when the Emptiness Law hid the field
picker.destroy();
```

**The cardinal rule: `value()` is the only submission path.** Callers must never read
the inner `<input>`. A typo can no longer ride into a POST inside a comma-split
string; a new tag exists in the payload only because the operator explicitly
committed it as a chip and saw the teaching line. This single rule is what converts
"silent ghost/blind" into "explicit, informed act".

### 2.2 Behavior

- **Directory fetch:** on first focus (not on mount — panels must not fan out admin
  calls at load), via `Verity.entityDirectory(tenantId, {q, liveOnly})`, a core.js
  helper wrapping `GET /v1/admin/entity-tags` (§4) with `V.api(path, {admin:true})`
  and a 30-second per-tenant cache shared by all pickers. `emptyBehavior` needs
  `total_distinct` before first paint on some surfaces (§3) — those surfaces call
  `Verity.entityDirectory` once at dialog-open, which is one cheap admin GET.
- **Typeahead:** filters the fetched directory client-side as the operator types
  (substring, case-insensitive, both namespace and name part). Each row renders
  `tag — N memories` where N = `chunk_count + action_count`, e.g.
  `account:acme — 14 memories`, plus a small `merged` badge when
  `canonical_entity` is set (display hint only; never affects the value).
  List is capped by a `max-height` with `overflow-y:auto`; never grows the dialog.
- **Chips:** committed values render as removable chips (`×` button,
  Backspace-on-empty-input removes the last chip). Chips use `V.entityBadges`
  styling for visual continuity with Scope Inspector.
- **Commit gestures:** Enter commits the highlighted suggestion; Enter, comma, or
  space commits typed text as a candidate (this *unifies* the comma-vs-whitespace
  parsing split — tokenization happens uniformly at commit time, in one component).
  Paste of a comma/whitespace-separated list is split and each token goes through
  the same commit pipeline (known → chip; unknown → the new-tag flow, one at a time).
- **Keyboard:** ↑/↓ move the highlight, Enter commits, Esc closes the list,
  Backspace on empty input removes the last chip, Tab leaves the field without
  committing partial text. Fully operable without a mouse.
- **New-tag flow** (`allowNew:true` only): a typed token not in the directory renders
  as a distinct final suggestion row —
  `account:acmee — new · 0 memories carry this tag yet` — that must be explicitly
  selected. On commit the chip gets a dashed "new" treatment and a one-line teaching
  note appears under the field (mode-specific copy, §2.4). Malformed tokens (fail the
  §1 lint) show an inline warning first:
  *"doesn't look like `type:name` — entity tags are lowercase like `account:acme`.
  Add anyway?"* with an explicit *add anyway* action.
- **Near-miss guard:** if a typed token case-insensitively equals a known tag, the
  picker MUST interpose: *"did you mean `account:acme` (14 memories)? Matching is
  exact — `account:Acme` matches nothing."* with one-click replace. If the name part
  is within edit distance ≤ 2 of a known tag in the same namespace, the picker SHOULD
  surface the same suggestion (non-blocking). This is the anti-ghost / anti-blind
  guard and is not optional in `scope`, `tags`, or `target` modes.
- **Namespace hinting:** with an empty input, the suggestion list opens with the
  observed namespaces as group headers (`account: · user: · deal:` — derived from the
  directory, never a hardcoded list) so the operator learns the tenant's actual
  vocabulary, not our examples.
- **Directory unavailable** (401 without admin token, network error): the picker
  degrades to lint-only free entry with a visible honest note —
  *"couldn't load known entities (admin read failed) — typed tags are unchecked."*
  It never blocks the operator and never fabricates counts. Degraded mode still
  enforces chips-only submission and the format lint.
- **`restrictTo`:** when set, the directory is ignored as a source of *additions*;
  suggestions come from the restrict set only, and any token outside it is refused
  inline with *"refusing to widen: `X` is not in the source handle's entity limit"*
  (same words as panel_scope.js:925). `allowNew` is forcibly false.

### 2.3 Honesty rules

1. The picker **offers what exists and never invents**: every suggested tag and every
   count comes from `GET /v1/admin/entity-tags`, which reads the same rows the
   enforcement predicates scan (§4). No client-side synthesis of suggestions.
2. Counts are labeled in memory-speak (`14 memories`), computed as
   `chunk_count + action_count`; hovering (title attr) shows the split and
   `last_seen`. When `liveOnly:false` (erasure), the label distinguishes
   `9 live / 23 total`.
3. Fail-closed semantics are **untouched**: the picker adds no defaults, an empty
   picker submits an absent/empty field exactly as the bare input did, and scope
   copy always says **"limit"**, never "grant" — entity scope narrows
   (SPEC §7c deny-by-default intersection); leaving it empty means *unbound*, not
   *no access*; zero-tag content is invisible in any entity-bound scope (§7d,
   knowledge items excepted).

### 2.4 Mode packs (wording + rules)

| mode | used by | allowNew default | new-tag teaching line | extra rule |
|---|---|---|---|---|
| `scope` | mint, webhook, derive | true | *"new — no memory carries this tag yet. A handle limited to it sees nothing until data arrives tagged `X`."* | new chips additionally get a persistent warning row while present: *"this limit includes a tag with 0 memories — reads through this handle will return nothing for it until data carries it."* |
| `tags` | ingest, quarantine | true | *"new — this entity starts existing when this record lands. 0 memories carry it today."* | when the write scope is entity-bound, tokens outside the scope are refused inline (mirrors the server's `resolve_entities` subset check, main.rs:227) — same rule the ingest hint already teaches (panel_ingest.js:461–464) |
| `target` | erasure entity | **false** | n/a — inventing an entity to erase is never correct | single-value; picking populates the typed-confirm expectation (§5.5); `liveOnly:false` |
| `probe` | brief/activity probe | true | *"not a known tag — the probe will return an honest zero. Checking a boundary? That's the point. Expecting data? Check the spelling."* | single-value; the new-tag flow is deliberately friction-light (probing nonexistent entities is legitimate falsification), but the near-miss guard stays — this is what stops fail-closed copy from laundering typos |

---

## 3. The Emptiness Law

**A field that references not-yet-existing things must never render as a bare input.**
Generalized from founder evidence (b): during setup, zero entities exist, so an entity
limiter is premature noise.

When the directory reports `total_distinct == 0` for the tenant, the picker does not
render its input. It renders one of two collapsed states, chosen per surface via
`emptyBehavior`:

- **`hide`** — for *limiting* surfaces (there is provably nothing to limit to). The
  entire field collapses to one quiet line plus an advanced reveal:

  > No entities yet — nothing to limit to. Entity tags appear as your data carries
  > them (like `account:acme`). <a>limit to a future entity anyway →</a>

  The reveal expands the full picker in new-only mode (directory is empty; every
  entry goes through the new-tag flow with its 0-memories warning). Collapsed
  submits the field as absent — identical to leaving today's input blank.

- **`teach`** — for *tagging* surfaces (typing a tag here is exactly how entities are
  born; hiding it would break entity birth). The picker renders its input immediately
  with the teaching line in place of the suggestion list:

  > No entities yet — tagging is how one is born. Type a tag like `account:acme`
  > and it exists once this record lands.

Decision per surface is fixed in §5 (not left to implementers). When the directory is
unavailable (vs. honestly empty), the Emptiness Law does **not** apply — degraded
free-entry mode renders instead (§2.2); we never hide a field because of our own
fetch failure.

---

## 4. The endpoint — `GET /v1/admin/entity-tags`

No existing endpoint serves this. `GET /v1/admin/entities` (main.rs:320 →
`list_canonical_entities`, postgres.rs:1115) reads `entity_aliases` only and is
explicitly documented as listing **merged** entities — a usage-born tag with no alias
row is invisible to it. It remains a complement (merge/confidence badges), not a
substitute. **New endpoint required.**

```
GET /v1/admin/entity-tags?tenant_id=<uuid>&q=<substring>&live_only=true&limit=100
```

- **Auth:** admin plane (`AdminAuth`, main.rs:81–129) — bearer when
  `VERITY_ADMIN_TOKEN` is set, dev-open otherwise. Console calls it with
  `V.api(path, {admin:true})`. This is worker/admin-plane reading and runs *before*
  any scope exists; it is **never on the recall path** (read-path purity holds: no
  LLM, no ReBAC, and this endpoint isn't consulted by `recall`/`get` at all).
- **Params:** `tenant_id` required; `q` optional case-insensitive substring over the
  tag; `live_only` default `true`; `limit` default 100, max 500.

**Response:**

```json
{
  "total_distinct": 42,
  "truncated": false,
  "tags": [
    {
      "tag": "account:acme-corp",
      "chunk_count": 118,
      "action_count": 9,
      "total_chunk_count": null,
      "last_seen": "2026-07-10T18:02:11Z",
      "canonical_entity": "acct-oid-91",
      "link_confidence": "deterministic"
    }
  ]
}
```

- `total_distinct` — distinct tags for the tenant under `live_only`, **ignoring `q`
  and `limit`** (the Emptiness Law keys off this; a filtered page must not fake
  emptiness).
- `chunk_count` — live chunk rows (`valid_to IS NULL`) carrying the tag: the same
  rows `entity_scope_predicate` can return. `action_count` — action rows.
- `total_chunk_count` — populated only when `live_only=false`: all chunk rows
  including invalidated ones. **Why it exists:** erasure targets physical rows
  (invalidate-don't-delete means superseded rows persist until the §8
  crypto-shredding pipeline runs), so a tag carried only by invalidated rows is a
  legitimate erasure target that a live-only directory would hide. The erasure
  surface queries with `live_only=false`.
- `canonical_entity` / `link_confidence` — LEFT JOIN to
  `entity_aliases` / `entity_link_meta`, display hint only (drives the `merged`
  badge). Null for unmerged tags — the common case.

**Query** (implemented as `StorageAdapter::list_entity_tags` in
`crates/verity-storage`, sqlx runtime query, adjacent to the de-id lexicon union at
postgres.rs:2322):

```sql
SELECT tag,
       sum(chunks)  AS chunk_count,
       sum(actions) AS action_count,
       max(last_seen) AS last_seen
FROM (
  SELECT unnest(entity_tags) AS tag, count(*) AS chunks, 0 AS actions,
         max(valid_from) AS last_seen
    FROM chunks
   WHERE tenant_id = $1 AND ($3 OR valid_to IS NULL)   -- $3 = NOT live_only
   GROUP BY 1
  UNION ALL
  SELECT unnest(entities), 0, count(*), max(occurred_at)
    FROM actions
   WHERE tenant_id = $1
   GROUP BY 1
) t
WHERE ($2::text IS NULL OR tag ILIKE '%' || $2 || '%')
GROUP BY tag
ORDER BY sum(chunks) + sum(actions) DESC, tag
LIMIT $4;
```

Performance honesty: both arrays are GIN-indexed for containment, not
unnest-aggregation — this is a per-tenant seq scan. That is acceptable for an
admin-dialog affordance at current corpus sizes; if it ever hurts, the fix is a
materialized tag summary, **not** counting a different (dishonest) source. Any latency
claim about this endpoint follows the BENCHMARKS.md rules (measured, stated corpus).

**Enforcement-consistency invariant (testable):** for any tag returned with
`live_only=true`, `chunk_count` equals the number of live chunks an unbounded probe
scoped to exactly `[tag]` could match under `entity_scope_predicate`
(postgres.rs:1862), and `action_count` equals rows matched by
`entities @> ARRAY[tag]` (postgres.rs:2826). A Rust integration test seeds a tenant
and asserts both equalities.

---

## 5. Per-surface specification

Every inventoried surface, in severity order. "Copy" strings are contractual — change
them here first.

### 5.1 Ingest — `#ing-ents` (panel_ingest.js:206–210, 488–491, 500) — severity 1

The entity-birth surface; the only one where a typo *creates* rather than blinds.

- **Picker:** `mode:"tags"`, `multiple:true`, `allowNew:true`, `emptyBehavior:"teach"`.
- **Label:** keep *"which customer or account is this about?"*
- **Explainer:** *"tags decide which entity views can find this memory. Known tags
  are suggested with counts; a new tag creates that entity the moment this lands."*
- **Wiring:** POST bodies for `/v1/episodes` and `/v1/files` take
  `picker.value()`; the CLI command builder (:500) emits one `--entity` flag per
  chip. Delete all comma-split parsing.
- **Scope-bound writes:** when the active write pass is entity-bound, construct with
  `restrictTo` = the pass's entity set, replacing the current hint text
  (:461–464) with hard inline refusal that mirrors the server's own subset check.
- After a successful ingest, call `picker.refresh()` on any live pickers (the newly
  born tag should appear with count 1 immediately — the "born by usage" moment made
  visible).

### 5.2 Webhook mint — `#src-mint-entities` (panel_sources.js:213–214, 732–733) — severity 2

Lowest frequency, highest blast radius: mis-scoped standing infrastructure,
near-undiscoverable (console "cannot list webhooks yet", :755–757).

- **Picker:** `mode:"scope"`, `multiple:true`, `allowNew:true`,
  `emptyBehavior:"hide"`.
- **Label:** *"limit to entities (optional)"*.
- **Explainer:** *"every future payload from this source will be limited to these
  entities — for the life of the webhook. There is no edit later; only revoke and
  re-mint."*
- New-tag chips here carry the `scope`-mode standing warning (§2.4) — a webhook
  scoped to a 0-memory tag is the worst silent-blind case in the console.
- **Emptiness:** hidden at zero entities (a scoped webhook during onboarding is
  premature by definition); the advanced reveal exists for the operator wiring
  infrastructure ahead of first data — a legitimate, explicit act.

### 5.3 Erasure — `#er-entity` (panel_erasure.js:228–231, 334–348, 388–413) — severity 3

- **Picker:** `mode:"target"`, `multiple:false`, `allowNew:false`,
  `liveOnly:false`, `emptyBehavior:"hide"`.
- **Label:** keep *"entity"*. **Explainer:** *"pick the exact tag as your data
  carries it — erasure matches strings exactly. Counts include invalidated rows;
  erasure targets those too."*
- Counts render as `9 live / 23 total` in this mode.
- **Typed-confirm interaction (the fix for the re-typed-typo hole):** the confirm
  token the operator must re-type (:406–413) is set from the **picked chip** — now
  guaranteed to be an observed tag. The ritual keeps its deliberateness but can no
  longer confirm a string that matches nothing.
- **Advanced escape hatch (required):** a quiet reveal — *"target an unlisted id
  (exact string match) →"* — opens lint-only free entry for ids that never appear in
  chunk/action tags. Free-entry targets MUST run preview first and the preview's
  existing "0 everywhere — check the id" teaching (:388–393) blocks the confirm
  button until the operator ticks *"I understand nothing matches this id."*
- **`#er-subject` stays free text** in v1 (subjects live partly in L1/facts — a
  vocabulary the directory honestly does not cover; offering chunk-tag suggestions
  for it would be inventing). It gains the format lint and the same preview-gate
  note. Revisit when a subject directory exists.

### 5.4 Global mint — `#mint-entities` (core.js:624–625, 693–694) — severity 4, the founder's screenshot

- **Picker:** `mode:"scope"`, `multiple:true`, `allowNew:true`,
  `emptyBehavior:"hide"`.
- **Label:** *"limit to entities (optional)"* — drop *"comma-separated"*; the
  affordance now shows the mechanism.
- **Explainer:** *"only memories tagged with these entities can come back through
  this handle. Empty = no entity limit."*
- **Wiring:** `body.entity_scope = picker.value()` when non-empty; omit otherwise
  (unchanged fail-closed shape). The dialog's `max-width:600px` stands; the
  suggestion list scrolls internally.
- **Welcome wizard (panel_welcome.js:667–673):** no code change beyond copy — the
  wizard opens this dialog with `entities:""`, and at zero entities the Emptiness Law
  collapses the field automatically. Update the wizard's step-3 note from
  *"entities — which customers (empty = all your customers)"* to:
  *"entity limits appear here once your data carries tags — nothing to limit to
  yet."* Day-zero users no longer see a limiter for a tenant with nothing to limit.

### 5.5 Quarantine re-ingest — `#qr-tags` (panel_quarantine.js:208–209, 119–121, 586–587) — severity 5

- **Picker:** `mode:"tags"`, `multiple:true`, `allowNew:true`,
  `emptyBehavior:"teach"`.
- **Label fix (semantic bug):** the current *"limit to entities"* is wrong — this
  field sets `entity_tags` on the re-ingested record. New label: *"entity tags for
  the corrected record"*. **Explainer:** *"these tag the record — they decide which
  entity views can retrieve it. They do not limit a scope."*
- The audit row immortalizes whatever is committed here; the near-miss guard and
  explicit new-tag flow are the protection inside this "careful correction" flow.

### 5.6 Derive — `#sc-mint-ent-free` (panel_scope.js:907–932) — severity 6

- **Handle already has an entity scope:** keep the existing checkbox-over-known-set
  with refuse-to-widen (:900–906, :922–926) — it is already the correct pattern and
  this contract's ancestor. No change required; optionally restyle checkboxes as
  picker chips later (out of v1).
- **Handle has no entity scope** (the free-text branch): replace with the picker —
  `mode:"scope"`, `multiple:true`, `allowNew:true`, `emptyBehavior:"hide"`. Keep the
  existing note verbatim: *"this handle has no entity limit. Adding one narrows it;
  leave blank to keep it unlimited."*

### 5.7 Brief/activity probe — `#sc-brief-e` (panel_scope.js:128, 227–229, 741–774) — severity 7

- **Picker:** `mode:"probe"`, `multiple:false`, `allowNew:true`,
  `emptyBehavior:"teach"` (with probe-specific empty copy: *"no entities yet — the
  brief of any entity you type will be an honest zero."*).
- Prefill from the handle's `entity_scope[0]` (:227–229) becomes `prefill:[...]`.
- The existing fail-closed empty-state copy (:761–762) stays — the near-miss guard
  now runs *before* the probe, so "emptiness is a correct answer" is no longer doing
  double duty as a typo launderer.

### 5.8 Explicitly unchanged

- **Audit filters `#au-f-q` / `#au-f-entity`** (panel_audit.js:262, 291) — stay free
  text. Client-side substring over fetched rows: forgiving, instantly correctable,
  writes nothing. A picker here would be ceremony.
- **`#mint-subject`** (core.js:618–619) — a principal reference, not an entity tag;
  different resolution plane, out of scope.
- **Entities panel** (panel_entities.js) — no hand-typed entity refs; it remains the
  merge-review surface over `GET /v1/admin/entities` and gains nothing here.

---

## 6. Out of scope (refusals, on the record)

1. **No create-entity registry, no pre-registration** — born-by-usage is product
   philosophy, not a gap. The picker teaches it; it must never gate on it.
2. **No server-side format validation** on `open_scope` / episode `entities` — the
   lint is a console affordance; the API contract stays permissive-verbatim.
3. **No fuzzy search server-side** — `q` is substring only; near-miss logic is
   client-side over the fetched page.
4. **No pagination** beyond `limit` + `truncated` — an admin dialog, not a browser.
5. **No webhook edit/list** — 5.2's blast radius is mitigated at mint time; listing
   webhooks is a separate UI-ACTIONS item.
6. **No subject directory / `#er-subject` picker** — would require honestly covering
   L1 fact subjects; deferred until that vocabulary has a real read.
7. **No picker in CLI/MCP** — console-only; CLI stays flags.
8. **No changes to enforcement** — `resolve_entities`, `entity_scope_predicate`, and
   intersection semantics are untouched. This is UI + one admin read.

---

## 7. Acceptance criteria

1. **The founder's screenshot field is a picker.** `#mint-entities` renders chips +
   typeahead-with-counts; no comma-split free text remains on any of the six
   converted surfaces (grep gate: no `split(",")` or `split(/[\s,]+/)` applied to an
   entity field in `ui/*.js`).
2. **Onboarding shows no premature entity field.** With a fresh tenant
   (`total_distinct == 0`), the wizard's mint step and the global mint dialog show
   the collapsed teaching line, not an input. Verified in the FTUE walkthrough.
3. **A typo can no longer silently narrow a scope or birth a ghost unnoticed.**
   Chips are the only submitted values; an unknown tag reaches a payload only via the
   explicit new-tag flow with its teaching line; a case-variant of a known tag
   triggers the did-you-mean interposition on every `scope`/`tags`/`target` surface.
4. **Erasure cannot confirm an unobserved string** without the operator explicitly
   acknowledging a 0-match preview (advanced path), and the picked path only offers
   observed tags with live/total counts.
5. **Counts are honest.** The integration test of §4's invariant passes: directory
   counts equal enforcement-predicate matches on a seeded tenant, live rows only when
   `live_only=true`.
6. **Emptiness is honest.** Directory-unavailable renders degraded free entry with
   the admin-read failure note — never the "no entities yet" line.
7. **Quarantine's label no longer lies:** "entity tags for the corrected record."
8. **THE LAW holds:** ten-second comprehension per surface (copy above), zero
   external requests, keyboard-complete, data loads on focus without a Load button,
   fail-closed untouched (empty picker ⇒ absent field, "limit" never "grant").
9. **Toolchain:** `cargo fmt` + `cargo clippy -D warnings` pass; endpoint uses sqlx
   runtime queries; no new migration (no schema change).

---

## 8. Build split

| Layer | Files | Work |
|---|---|---|
| **Server (Rust)** | `crates/verity-storage/src/lib.rs` (trait), `crates/verity-storage/src/postgres.rs` (impl near :2322; new `EntityTagRow`/`EntityTagDirectory` types) | `StorageAdapter::list_entity_tags(tenant_id, q, live_only, limit)` with the §4 SQL + `total_distinct` count; unit/integration test for the enforcement-consistency invariant |
| | `crates/verity-server/src/main.rs` | route `GET /v1/admin/entity-tags` (:316 block) + handler behind `AdminAuth`; serde params with defaults |
| **Core kit (JS/CSS)** | `crates/verity-server/src/ui/core.js` | `Verity.entityDirectory` (cached admin fetch) + `Verity.entityPicker` builder (§2) + export at :842; convert `#mint-entities` inside `_buildMintDialog` (:600–711) — the mint dialog lives in core.js, so its conversion ships with the component |
| | `crates/verity-server/src/ui/core.css` / `theme.css` | chip, suggestion-list, new-tag (dashed), warning-row styles reusing `entityBadges` tokens |
| **Panels (JS)** | `panel_ingest.js` (:206–210, :488–500, :461–464) | 5.1 — tags mode, CLI builder from chips, restrictTo on bound passes |
| | `panel_sources.js` (:213–214, :732–733) | 5.2 — scope mode, standing-infra copy |
| | `panel_erasure.js` (:228–231, :334–348, :406–413) | 5.3 — target mode, confirm-token from chip, advanced 0-match gate |
| | `panel_quarantine.js` (:119–121, :208–209, :586–587) | 5.5 — tags mode + label fix |
| | `panel_scope.js` (:128, :227–229, :907–932) | 5.6 free-branch picker + 5.7 probe mode with prefill |
| | `panel_welcome.js` (:460–463, :667–673) | 5.4 — step-3 copy only (collapse is automatic) |

Suggested sequence: server endpoint + test → core builder + mint dialog (proves the
component against the founder's screenshot surface) → ingest (highest-frequency,
entity-birth) → erasure (compliance) → sources/quarantine/scope → wizard copy sweep.
