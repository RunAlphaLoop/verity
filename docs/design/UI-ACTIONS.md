# Verity Console — Action Model (v0.3)

*From evidence room to workbench · what users need to be able to DO*

**Status:** authoritative action model for the Verity web console. `UI-SPEC.md` remains the build contract for chrome, ethos, and the fail-closed gates; **this document is the contract for verbs** — which actions exist, where they live, what unblocks whom, and what stays out.
**Grounding:** live console at `GET /ui` (9 panels, all rail entries live), router `crates/verity-server/src/main.rs` (L299–413), `crates/verity-cli`, `crates/verity-mcp`, and four adversarial journey walkthroughs (day-zero evaluator, operator, reviewer, developer) executed against a live dev server with demo data.
**Rule of evidence:** every claimed gap below cites a real absent verb; every proposed action names its endpoint or says **needs new endpoint**.

---

## 0. The founder verdict (2026-07-11) — the acceptance bar

Delivered verbatim after first real use, this is the standard every tier below must clear:

> "It literally is not a purpose-built UI. It doesn't enable a person to easily
> start/view ingest stats, review entities, review knowledge, create principals
> etc… and even when pieces of that functionality exist, they are incredibly
> hard to interpret — wtf is happening."

Two requirements fall out of it:

1. **The five jobs** — a person, without a terminal, must be able to: start an
   ingest **and watch it flow** (stats/freshness); review entities; review
   knowledge; create **and see** principals/identity; and always know what
   state things are in. The Now tier maps to these (N2/N4→ingest+connect,
   N6→entities, N8/N5→knowledge, N5→principals, N1/N3/N7→orientation).
2. **Interpretability is a shipping gate, not polish.** A verb that exists but
   cannot be understood in ten seconds by a first-time operator does not count
   as shipped. Plain-language labels (no "fold"/"polarity"/raw refs as primary
   text), visible state, and loaded-for-you data are part of each item's
   definition of done — and a full design rebuild (visual + interaction) is the
   committed follow-on to this action model, not an optional extra.

## 1. Thesis

### What the console got right — keep all of it

- **The evidence room works.** Scope Inspector's decode → probe → why-filtered → export-boundary loop is the crown jewel across three personas (evaluator falsification, reviewer proof, developer debug) and it works live. The why-trace correctly stacks drop reasons (`visibility_no_overlap`, `entity_scope_outside`, `stale_superseded`).
- **The human gates are ceremonially correct.** Knowledge publish requires explicit visibility (blank = refusal) with k_min clamped ≥3; erasure has preview → typed-confirm → signed purge report; quarantine has exactly two exits and states three times that "index it anyway" will never exist; group removal warns tombstones-first. These are ahead of most prior art (Temporal/GitHub-class gating).
- **Honest seams instead of fake buttons.** Disabled seams name their target endpoints; empty states say "empty is a valid, on-the-record answer"; coverage bars go striped rather than fabricate a percentage; the tracer admits an ANN miss is invisible to it.
- **The console is a scoped, fail-closed client of the product.** Scope-gated reads go through real handles; there is no god-mode read path. That the console doubles as a live demo of the boundary *is* the sales pitch. This is an invariant, not an implementation detail.

### Where it under-serves — the three deficits

1. **Action verbs.** The server outgrew the UI's self-imposed v0.1 read-only ceiling. Four Sources buttons sit disabled while their endpoints (`POST /v1/webhooks`, `DELETE /v1/webhooks/{id}`, `POST /v1/manifests`, `POST /v1/manifests/{id}/activate`) are live and answer — including manifest activation, which the server code itself calls "THE human gate" and audits the approver for. Raw curl is currently the approval UX for the spec's one mandated human-approval verb. The Audit ribbon still declares live features "routes to CLI/REST until v0.2" — the honesty machinery has doc-rot.
2. **First-run.** The console's default panel demands a scope handle it refuses to mint. `POST /v1/scopes` is public and the mint dialog is already implemented in `panel_scope.js` — but it is only reachable *after* decoding a handle you already have. The CLI never prints `/ui` or the raw handle; the only path in is `cat ~/.verity/config.toml`. There is no home, no rail counts, no tenant pre-fill; the universal first click is a Load button that errors "enter a tenant_id."
3. **Get-data-in.** A memory product with zero console ways to put memory in. No panel calls `POST /v1/episodes` or `POST /v1/files` (verified: no `<input type=file>` exists anywhere in `ui/`). The evaluator cannot run the falsification arc on their own data; the developer's most common fix (re-ingest with corrected visibility) is 100% terminal.

**Target posture** (from the prior-art survey): ~80:20 observe:act, where every act is a **named verb from a closed vocabulary** — never a free-form edit — and every act emits an evidence artifact. Verity's invalidate-don't-delete and quarantine-never-permissive semantics make this a hard requirement, not taste.

---

## 2. Persona × Task map (the demand side)

`[C]` console-appropriate · `[CLI]` CLI/API-appropriate · `[C+CLI]` both. Per UI-SPEC §1/§3, bootstrap, backup/restore, BYOT credential capture, and client-side manifest verification stay CLI **by design**.

| Persona | Phase | Top tasks (ranked) | Surface |
|---|---|---|---|
| **0 · Day-zero evaluator** | first hour | 1. break-the-boundary probe with explained zero · 2. scoped recall with visible provenance · 3. boot + ingest own data · 4. honest latency readout · 5. MCP hookup · 6. see own reads in audit | 1,2,4,6 [C] · 3,5 [CLI] (but *seeing* the ingest land is [C]) |
| | make-or-break | Reach the boundary-falsification moment within ~15 min of `verity-cli dev` — fail-closed looks like a bug in a terminal; only an explain-zero surface converts it into the selling point | [C] |
| **1 · Platform operator** | first week | connect BYOT sources · set per-connector visibility policy · wire identity graph · first backup/restore drill · triage first quarantine | connect/credentials [CLI by design]; visibility *decision*, graph *verification*, quarantine [C] |
| | steady state | 1. connector/credential/freshness health watch · 2. quarantine drain · 3. tag-suggestion review · 4. watch-stream degraded alerting · 5. scheduled backups | 1–4 [C] · 5 [CLI] |
| | incident | revocation-propagation proof ("Jane is gone — prove it *now*") · poisoned-source rollback · restore under KEK discipline | proof + lineage [C]; bulk invalidation + restore [CLI] |
| **2 · Compliance reviewer** (PRIMARY) | all phases | 1. prove-the-boundary live probe · 2. export signed evidence · 3. knowledge publish/reject with full context · 4. audit search/filter/export · 5. erasure + signed purge report · 6. DSAR export · 7. leak reconstruction · 8. trust-vocabulary comprehension in-context | **everything [C]** — this persona has no adequate non-UI path; that is UI-SPEC's founding argument |
| **3 · Agent developer** | integration | 1. why-filtered / explain-zero debugging (their #1 pain — without it they file "search is broken" bugs against correct fail-closed behavior) · 2. scope mint + handle comprehension · 3. recall playground iteration · 4. MCP/adapter wiring · 5. write-path wiring with visibility | 1,3 [C] · 2 [CLI+C] · 4,5 [CLI] |
| | incident | A/B two handles on one query · "my write vanished" (episode → quarantine? → chunk?) · forget bad memory | A/B + trace [C] · forget [CLI/API, agent-reachable by design] |

### Cross-persona conclusions (build-order signal)

1. **One task dominates three personas:** run a probe through an exact handle and get an honest explanation of what came back and why the rest didn't. Scope Inspector is genuinely shared — same mechanism, three framings.
2. **The queues are the steady-state console:** quarantine, knowledge review, tag suggestions, audit tail — all read-inspect-decide loops. Two (knowledge decide-with-context, tag approve) still force terminal exits.
3. **Evidence export is a first-class verb:** boundary evidence, purge report, DSAR bundle, audit export — four artifact-producing tasks, all reviewer-critical, all console-only demand.
4. **The CLI boundary holds:** everything touching the operator's filesystem, secrets, or offline procedures is legitimately CLI. Personas need its **posture visible** in the console (kek_set, watch degraded, auto-publish off, connector staleness), not the verbs themselves.
5. **Incidents are lenses, not screens:** revocation proof, leak reconstruction, poisoning rollback are pivots *within* Scope Inspector / Audit / Quarantine / Knowledge — never a separate incident app.
6. **Frequency×criticality hotspots:** daily-critical = connector/freshness watch [Op] + why-filtered debug [Dev]; weekly-critical = knowledge publish/reject [Rev] + quarantine drain [Op]; once-but-deal-gating = boundary proof + evidence export [Rev/Eval]; per-incident-critical = revocation proof, erasure with signed report.

---

## 3. Action-gap matrix

Legend — Console: **live** · **buried** (reachable only inside another flow) · **seam** (deliberately disabled placeholder) · **absent**. Endpoint: ✓ exists · **NEW** = needs new endpoint.

### A · Read / query path

| Capability | Endpoint | CLI | MCP | Console | Verdict |
|---|---|---|---|---|---|
| Mint scope handle | POST /v1/scopes ✓ (public) | implicit | memory_open_scope | **buried** — only inside decode-first narrow/renew flows | unbury (Now-1) |
| Hybrid recall | POST /v1/recall ✓ | `query` | memory_recall | live | — |
| Point record lookup | GET /v1/records/{src}/{ent}/{field} ✓ | — | memory_get | **absent** | Next — the demo's headline live-truth number is uninspectable |
| Merged entity view | GET /v1/entities/{canonical} ✓ (scope-gated) | — | — | live (drawer) | — |
| Entity brief / activity | GET /v1/briefs/{e}, /v1/activity ✓ | — | memory_brief/activity | live | — |
| Debug recall tracer | POST /v1/admin/debug/recall ✓ | — | — | live | emit `visibility_tokens`, not just count (Now-5) |
| SSE subscribe / poll changes | GET /v1/subscribe ✓ | — | memory_poll_changes | absent | Later (programmatic-first) |

### B · Write / ingest path

| Capability | Endpoint | CLI | MCP | Console | Verdict |
|---|---|---|---|---|---|
| Remember / ingest text | POST /v1/episodes ✓ | `add -` | memory_remember/ingest_text | **absent** | Now-2 |
| Ingest file / URL | POST /v1/files ✓ (multipart, scope-gated) | `add <path/url>` | memory_ingest_file/url | **absent** | Now-2 |
| Record agent action | POST /v1/actions ✓ | — | memory_record_action | absent | OUT — programmatic |
| Batch / CDC / webhook delivery | /v1/ingest/*, /wh/{token} ✓ | — | — | absent | OUT — programmatic |
| Media list / fetch / sign | GET /v1/admin/media, POST /v1/media/{id}/sign ✓ | — | — | **buried** (erasure picker only) | Later — media browser |

### C · Sources, connectors, manifests

| Capability | Endpoint | CLI | Console | Verdict |
|---|---|---|---|---|
| Webhook mint | POST /v1/webhooks ✓ | `webhook mint` | **seam** | Now-4 |
| Webhook revoke | DELETE /v1/webhooks/{id} ✓ | — | **seam** | Now-4 (usable only with list) |
| Webhook list | **NEW** (GET /v1/webhooks) | — | absent | Next — mint+revoke with no enumerate is a broken lifecycle |
| Manifest install (draft) | POST /v1/manifests ✓ | `manifest install` | **seam** | Now-4 |
| Manifest list (server) | GET /v1/manifests ✓ | — | absent | Now-4 (mint validates manifest_id — the dialog needs this read) |
| **Manifest activate** | POST /v1/manifests/{id}/activate ✓ — audits the approver | — (deliberately) | **seam** | Now-4 — the spec's mandated human gate, currently curl-only |
| Connect Slack/GitHub wizards, BYOT creds | (CLI-local) | `connect slack/github` | absent | OUT by design; console owns the Verity side (mint URL, visibility decision, pending row) |
| Connector heartbeat POST / backfill POST | ✓ | — | absent | OUT — programmatic |
| Connector status / freshness / backfill views | ✓ | — | live | fix heartbeat-vs-freshness contradiction (Now-7) |

### D–E · Quarantine & entity resolution

| Capability | Endpoint | Console | Verdict |
|---|---|---|---|
| Quarantine list / reingest / dismiss | ✓ | live | — (keep the two-exits design) |
| Entities browser / review queue / merge decide / precedence | ✓ | live (precedence triple-buried) | unbury via probe-handle mint (Now-1) |
| **Trigger resolution run / fold** | POST /v1/admin/entity-resolution/run, /fold ✓ | **absent** — the panel copy names a verb ("Tier-2 must run to populate it") the console doesn't have | Now-6 |
| Alias upsert / evidence retract / resolution config | ✓ | absent | Later |

### F · Knowledge & consolidation

| Capability | Endpoint | Console | Verdict |
|---|---|---|---|
| Queue list / detail / publish / reject | ✓ | live | publish dialog blocked on principal directory (Now-5); reject reason currently optional — make required (Next) |
| Propose learning | POST /v1/knowledge ✓ | absent | OUT — agent-side by design |
| Un-publish / retract | **NEW** | seam (honest, documented) | Later — design the endpoint |
| Consolidation lease/complete/merge-candidates | ✓ (worker protocol) | absent | OUT; a human "run consolidation now" trigger **needs new endpoint** (Later) |
| Tag-suggestion queue list + approve | GET /v1/admin/tag-suggestions, POST …/approve ✓ | **absent** — a human review queue with zero UI | Next |

### G · Governance, identity, compliance, ops

| Capability | Endpoint | Console | Verdict |
|---|---|---|---|
| Tenant create | POST /v1/admin/tenants ✓ | absent | Next; tenant list **NEW** |
| Principals upsert / group add / remove | ✓ | live | — |
| **Principals/groups read** | **NEW** (GET /v1/admin/principals, GET /v1/admin/groups) | absent — write-only panel | Now-5 — the worst write-without-read asymmetry |
| Audit read / drill / jump | ✓ | live (drill buried; ribbon stale) | copy fix (Now-7) |
| Forget / erasure preview / erasure / DSAR | ✓ | live | move forget out of the admin-gated panel (Next — it is scope-token-authed) |
| Reembed batch / cutover / briefs refresh | ✓ | live | — |
| ReBAC watch status | GET /v1/admin/rebac-watch ✓ | absent | Later — posture readout |
| Backup/restore, dev bootstrap, MCP install | CLI-local | absent | OUT by design |

---

## 4. Journey findings, distilled

Four adversarial walkthroughs against the live server. Full traces in the design log; the load-bearing findings:

### 4.1 Day-zero evaluator — "two live panels behind a config-file scavenger hunt"

- **Dead-end A:** `verity-cli dev` never mentions `/ui` (the string appears nowhere in CLI output) and never prints the raw `vs_…` handle. The only way to obtain a paste-able handle is `cat ~/.verity/config.toml`.
- **Dead-end B:** `/ui` lands on Scope Inspector, which is intake-only — every probe hidden until a decode. **The console can mint handles (`POST /v1/scopes` is public; the dialog is already implemented in `panel_scope.js`); it just refuses to mint the first one.**
- **Dead-end C:** "now let me put MY data in" → hard exit to terminal; zero ingest verbs anywhere in `ui/`.
- **The empty-demo finding (founder-reported, verified and sharpened):** `deploy/demo.sh` never calls `POST /v1/knowledge`, any `/v1/admin/entity-resolution/*` verb, or anything producing quarantine/heartbeats/media. A pure demo tenant leaves Knowledge, Entities (both tabs), Quarantine, Sources-inventory, Backfill, and Media all empty — **five of nine panels dead**, including the flagship human gate. The hand-seeded items observed live are hollow (`distinct_entities:0`, `evidence:[]`, `summary:{name:null,domain:null}`), so the k-support gate demos as vacuous. The demo's single-source records carry no cross-source alias keys, so Entities is empty *forever*, not just until the resolve debounce fires.
- **Sources contradicts itself:** `GET /v1/admin/connector-status` → `[]` seconds after a successful webhook+CDC ingest, while `GET /v1/slo/freshness` on the same tenant shows 4 sources with real percentiles. "No connectors" beside live connector latencies reads as *broken*, not honest.
- **Dev-mode absurdity:** Erasure is client-gated on token *presence* while the dev server requires none; any garbage string unlocks it, and nothing discloses this.

### 4.2 Operator — "three forced terminal exits; only one legitimate"

- The four Sources write-seams point at four **live** endpoints (verified by 405-not-404 method probes). The panel's "no writes in v0.2" framing is a self-imposed ceiling the server outgrew.
- Manifest activation — which `manifests.rs` calls "THE human gate" and audits the approver for — has raw curl as its only human surface.
- No file input exists in any panel while `POST /v1/files` needs only a scope handle.
- BYOT credential entry is the *one* legitimate exit; the console can't even do its honest share (mint intake URL, record the visibility decision, show a pending-first-heartbeat row).
- Probe-handle construction is guesswork: principals are i32 tokens, the Principals panel is write-only, and no read endpoint exists.

### 4.3 Reviewer — "seven interactions to the first decision; two forced exits mid-loop"

- No home, no rail counts: the "what awaits me?" question has no answer; the daily loop starts with three exploratory round-trips.
- **The worst dead-end in the console:** the Publish dialog demands comma-separated i32 principal tokens with no way anywhere to learn what token 1001 means — a psql/curl exit *mid-dialog of the single most consequential act in the product*.
- Merge decisions are made blind: live review-queue candidates render `{name:null, domain:null}` summaries with no link to underlying records (`GET /v1/records/…` exists, console-absent).
- The scope-gated merged view (prerequisite for the admin precedence editor) is unreachable for an admin-token-only session — pure UI burial of a public mint endpoint.
- Reject reason is optional (defaults to "rejected by reviewer") — violates the reason-required house rule Erasure already models. No decision receipt links to the audit row just written. Zero keyboard support; the entities SLA/starvation flag is honest but unactionable and page-scoped; knowledge has no wait-age at all; status-filtered empty states mask work one filter away.

### 4.4 Developer — "five exits in a seven-step loop, on the journey the Scope Inspector was named for"

- SEE-WHY is complete and excellent; **FIX and VERIFY leave the browser at every single branch**: entry (no fresh mint), identification (`visibility_no_overlap` names no token — the server holds `c.visibility` and serializes only its length; no principals read exists), every fix path (no ingest; group-add exists but its required input is undiscoverable), verification (derived handles don't re-resolve the group graph; Renew only after expiry — no path to a post-fix fresh-claims handle), regression (nothing preserves the proof as a re-runnable check).
- **The tracer's blind spot is the case fail-closed is proudest of:** a quarantined payload was never indexed, so it appears as *nothing* — and `explainZero()` never utters the word "quarantine."
- The server's purpose vocabulary lives in `purpose.rs` with no enumeration endpoint; the console's *derive* dialog already embeds the default pack in a datalist, but an API/CLI-first mint attempt 422s with no way to list valid purposes.
- A/B handle comparison — the developer's canonical question — is purely client-side to build and absent.

---

## 5. Prioritized additions — Now / Next / Later

Every item: **the verb · who it unblocks · endpoint · the fail-closed gate it must keep · empty-state/teaching copy requirement.** House rules from the prior-art survey apply to all of them: reason strings appended to audit; preview-first for anything destructive or visibility-widening; typed confirmation scaled to irreversibility; destructive verbs only on detail surfaces, never row-level bulk; per-action admin step-up, never session-level unlock.

### NOW — small, high-leverage; closes every journey's entry dead-ends

**N1 · Mint a probe handle, top-level on Scope Inspector (and reachable from any admin session).**
Unblocks: day-zero dead-end B, developer dead-ends #1/#3 (entry + post-fix verify), reviewer's merged-view/precedence burial. The cheapest, highest-leverage fix in the product — the dialog already exists in `panel_scope.js`; unbury it from the decode-first gate.
Endpoint: `POST /v1/scopes` (exists, public). Purpose dropdown fed by the default pack names (the derive dialog already embeds these in a client-side datalist — reuse it; or trivial **new** `GET /v1/purposes`).
Gate kept: server-side subject resolution and fail-closed clamps unchanged; the *derived*-handle path keeps its narrow-only, no-widen construction; the fresh-mint path is honest that it re-resolves identity (unlike derive/renew — keep that disclosure).
Copy: on success, auto-decode into the panel; intake empty state gains "No handle? Mint a probe handle →" plus the `verity-cli dev` pointer. Disclose the 60s TTL floor (today a `ttl_seconds:1` mint silently outlives its request and makes expiry look broken).

**N2 · Add memory — ingest text / file / URL card.**
Unblocks: day-zero dead-end C (falsify on *own* data — the #2 first-hour task), operator terminal exit #3, developer's re-ingest fix branch.
Endpoints: `POST /v1/episodes` (text), `POST /v1/files` (multipart file/URL; scope-gated, not admin) — both exist.
Gate kept: **visibility is a required field with no default; omission surfaces the server's own 422 refusal verbatim** — the teaching refusal is the point (§5e.8). No permissive shortcut, ever.
Copy: result shows episode/media id + chunk count + a "now recall it under a narrower handle" handoff into Scope Inspector — the first-run arc ends at the boundary, not at ingestion (the demo climax is minute 4, not minute 1).

**N3 · Attention-first home ("Needs decision" strip) + rail count badges.**
Unblocks: reviewer's exploratory round-trips; makes queue age visible from login; gives the console a front door.
Endpoints: all exist — `GET /v1/knowledge?status=candidate|eligible`, `GET /v1/admin/entity-resolution/review-queue`, `GET /v1/admin/quarantine`, freshness SLO. One card per queue: count + oldest-item age + one click into the pre-filtered panel.
Gate kept: **counts must be as-of-stamped and derived from the same query as the target panel** — a badge computed differently than its list is a small lie. The home creates urgency but must never cheapen a gate: publish stays exactly as heavy when the queue reads 47.
Copy: the zero state is affirmative and evidenced — "Nothing needs you — 0 quarantined, 0 pending review, checked 12s ago" — a green build, not a blank page.

**N4 · Un-seam the Sources writes: webhook mint/revoke + manifest install/list/activate.**
Unblocks: operator terminal exits #1 (all four seams point at live endpoints); the spec's mandated human-approval verb gets its human surface.
Endpoints: `POST /v1/webhooks`, `DELETE /v1/webhooks/{id}`, `POST /v1/manifests`, `GET /v1/manifests`, `POST /v1/manifests/{id}/activate` — all exist. (Full lifecycle needs `GET /v1/webhooks` — Next, X4.)
Gates kept: webhook mint mirrors the server's 422 refusal on empty visibility; **show-once secret** with copy-once UI, never re-fetched. Manifest **activate is a separate, explicit, typed-confirm step with the approver recorded in audit** (the server already writes this) — never a flag flip. Install produces a draft only.
Copy: mint result renders the intake URL inside a pre-filled copyable curl/CLI snippet (Pinecone snippet pattern); a client-side "pending first heartbeat" row appears after mint, labeled as client-side, flipping live on the first heartbeat.

**N5 · Principal directory read + named tokens in the why-trace.**
Unblocks: reviewer dead-end #3 (the flagship Publish dialog stops requiring a psql exit), developer dead-end #2 (converts `visibility_no_overlap` from verdict to instruction: "chunk requires #11 = group:sales; your handle has #3 = user:demo"), operator probe-handle guesswork.
Endpoints: **needs new endpoint** `GET /v1/admin/principals` (token ↔ string map; the table the upsert writes already holds it) — the one small new read that unblocks three journeys. Plus one serialization line in `admin_debug_recall`: emit `visibility_tokens: [11]`, not just `visibility_token_count` (the endpoint is already admin-gated and audited; withholding members while disclosing count serves no one).
Gate kept: admin-token only; the token map never renders in any scope-handle context; agent-facing surfaces keep bucketed support and count-only displays (provenance firewall untouched).
Copy: publish dialog becomes a picker with names; the why-card's token row links "resolve this →" to Principals.

**N6 · "Run resolution now" on the Entities panel.**
Unblocks: reviewer's post-clear verification; the day-zero Entities emptiness (with N8's demo fix); the panel's own copy names this verb ("Tier-2 must run to populate it") without having it.
Endpoints: `POST /v1/admin/entity-resolution/run` and `POST …/fold` — exist.
Gate kept: the trigger populates a *human review queue*; it never auto-merges. Confirm dialog states this.
Copy: browser/queue Species-A empty states gain the button: "No candidates awaiting review. Run resolution to scan for cross-source matches →" — and keep the existing "an empty queue means the fold settled everything" line for the post-run state.

**N7 · Empty-state taxonomy pass + honesty copy repairs.**
Unblocks: everyone's first five minutes; protects the honesty brand from its own doc-rot.
Endpoints: none — UI-only. The three-species law: **Species A (nothing ingested yet)** → teach + button (mint webhook, add memory, run resolution, copyable `verity-cli add` line); **Species B (filtered by scope)** → never a fill-it button — the CTA is forensic ("Why filtered?", decode claims), and `explainZero` gains the missing sentence: *"If the write may never have been indexed, check Quarantine →"* with a tenant-seeded jump (the tracer's blind spot, named); **Species C (queue drained)** → celebrate with evidence (count passed, last-checked stamp, audit link). Badge the species visually so "not there" and "not visible to you" are distinguishable at a glance — no competitor makes that distinction; it is Verity's story.
Specific repairs, all verified live: delete the stale Audit ribbon line (drill/jump are live); Erasure locked-state discloses dev-mode ("this server enforces no admin token — dev mode"); Sources renders a reconciling note when freshness has samples but heartbeats are empty ("sources seen by freshness; no heartbeat posted — heartbeats are a connector-side push"), and deletes the stale "emits NO p99" header comment in `panel_sources.html` (the *rendered* disclosure already reports real p99 — the rot is source-comment-only); carry the derive dialog's existing purpose datalist into the N1 fresh-mint dialog; status-filtered empty states report sibling-status counts from the unfiltered call ("0 eligible — 3 candidates exist one filter away").

**N8 · Exit ramps and a demo that exercises its own gates** (CLI/demo-side, zero server work).
Unblocks: day-zero dead-ends A + the empty-demo finding (five dead panels).
Changes: `dev.rs print_summary` and `demo.sh`'s closing lines print the console URL, tenant id, and the raw `vs_…` handle ("paste this into /ui#scope"). Extend `deploy/demo.sh` ~15 lines: propose one knowledge item **with evidence** from the seeded episodes, ingest one second-source record sharing a name/domain alias key, call `POST /v1/admin/entity-resolution/run`, and deliver one deliberately unmappable webhook payload — Knowledge, Entities, and Quarantine light up with honest, non-hollow content and the human gates become witnessable.

### NEXT — completes the loops the Now tier opens

**X1 · A/B handle comparison** (Scope Inspector second handle slot: diff decoded claims + per-chunk drop reasons across two `POST /v1/admin/debug/recall` calls). Unblocks the developer's canonical incident question. Endpoints exist; pure UI. Gate: both traces stay admin+handle-gated and audited.
**X2 · Fix-pivots on why-cards.** Per dropped candidate, a "resolve this" row: `visibility_no_overlap` → Principals pre-seeded (needs N5); `stale_superseded` → show the superseding record via `GET /v1/records/{src}/{ent}/{field}` (exists, console-absent — this also finally surfaces the point-lookup and the demo's live-truth headline number); `entity_scope_untagged` → tag-suggestion queue. Add copy buttons to why-card ids (hit cards have them; why-cards don't).
**X3 · Reviewer clearing loop:** wait-age column + amber threshold on the knowledge queue (port the entities `fmtAge`/starve logic; drop the `rows.length > 1` guard — a single starving item is still starving); "Next undecided →" on every decide/publish/reject success; `j/k/Enter` bindings; **reject reason becomes required** (house rule 1); a **decision receipt** linking to the audit row just written — the evidence product should show you the evidence of your own act. Endpoints exist; UI-only.
**X4 · `GET /v1/webhooks`** — **needs new endpoint** (~30 lines): closes the mint/revoke lifecycle N4 opens; revoke without enumerate requires a remembered UUID.
**X5 · Tag-suggestion review queue** (list + approve) — endpoints exist (`GET /v1/admin/tag-suggestions`, `POST …/approve`). A human review queue with a widening consequence: approve requires a confirm that states what widens, and joins the home strip (N3). Operator-weekly task with zero UI today.
**X6 · Per-ref "current facts" on review-queue cards** (via `GET /v1/records/…`) so merge/anti-link decisions — including the PERMANENT reject — are made on evidence, not on `score 0.91` and null summaries.
**X7 · Tenant create** (`POST /v1/admin/tenants`, exists) + tenant enumeration (**needs new endpoint** `GET /v1/admin/tenants`) — kills the out-of-band UUID paste that precedes every journey.
**X8 · Groups read** (**needs new endpoint** `GET /v1/admin/groups`) — completes N5; the Principals panel stops being write-only; group-membership fixes become verifiable in-console.
**X9 · Heartbeats from the ingest paths** (server change: webhook/CDC ingest calls the existing connector-status write path) or a labeled freshness-derived inventory fallback — removes the Sources self-contradiction at its root. Plus: **relocate `/v1/forget`** out of the admin-gated Erasure panel (it is scope-token-authed; it belongs beside the scope tools, still labeled "invalidate — reversible").

### LATER — durable workbench

- **Probe suites / boundary regression:** save named probes (mint-spec + query + expectation ∈ {must-be-zero, must-hit}); "Run all" re-mints *fresh* handles so group-graph changes are actually re-tested; red/green on drift. Client-side (localStorage) first; a durable, shareable, CI-callable suite **needs a new endpoint**. This is how "is my scoping *still* airtight?" stops being a manual re-walk.
- **Knowledge un-publish/retract** — **needs new endpoint**; today's disabled seam is honest and stays until the endpoint is designed (retraction must cascade support recounts, like erasure does).
- **Human consolidation trigger** ("run consolidation now") — **needs new endpoint**; lease/complete is a worker protocol, not a trigger. Kills the decide-three-identical-candidates pain.
- **Media browser + sign** (`GET /v1/admin/media`, `POST /v1/media/{id}/sign` exist) — unbury from the erasure picker.
- **Entity alias editor + resolution-config editor** (`POST /v1/admin/entity-aliases`, `GET/PUT /v1/admin/entity-resolution-config` exist).
- **Deployment-posture panel:** ReBAC watch status (`GET /v1/admin/rebac-watch`, exists), kek_set, auto-merge flag, dense route (the Migrations "unknown from the UI" seam wants a small **new** GET) — the operator's "what is this deployment's posture" demand; CLI owns the switches, console shows the state.
- **SSE live tails** (`GET /v1/subscribe`, exists) for audit/quarantine, replacing polling.
- **Connect stepper** for first real connector UI: credential *check* (verifies a CLI-registered credential — the console never captures vendor secrets, per §6) → connectivity probe → **non-skippable ACL-mapping conformance check** → visibility fallback → backfill; the wizard's output is an inspectable, replayable config artifact accepted headlessly via API (Grafana-provisioning parity), and each step's pass is stored evidence. A wizard that can't be replayed headlessly would be the only non-reproducible surface in the product; don't ship one.

### Gates that must survive every tier (restated as law)

Fail closed, always; no "index it anyway" affordance, ever. No default visibility anywhere — omission refuses. Scope handles narrow, never widen. Knowledge publish/reject stays human, evidence-first, dialog-gated — never bulk, never keyboard-accelerated *past the dialog*. Erasure stays structurally admin-gated with typed confirm and a signed report. `forget` is always labeled reversible invalidation. Provenance firewall: exact support counts and episode lineage stay admin/audit-scope-only. Read-path purity: nothing in this document adds an LLM or live-ReBAC call to `recall`/`get`; every debugging affordance rides the audited, off-hot-path debug endpoint. Honest numbers or no number. Disabled seams stay honest — and get *removed* the release their endpoint goes live, because a stale seam is a lie in the other direction (the Audit-ribbon lesson).

---

## 6. Explicitly OUT — stays CLI/API by design

Per UI-SPEC §1's boundary, confirmed by the persona analysis ("the CLI boundary holds"):

| Stays out | Why | Console shows instead |
|---|---|---|
| `verity-cli dev` bootstrap, docker compose | operator's laptop/filesystem | health indicator, build hash |
| Backup / restore / drills | shells into the container; DR ordering (SpiceDB-before-Postgres) | last-backup posture (Later) |
| BYOT credential capture (HubSpot token, Drive SA, Slack/GitHub wizards) | **secrets must never transit the server** | the Verity side: mint intake URL, visibility decision, pending row, copyable snippets |
| KEK set/rotation, kill-switch env flips (`VERITY_KNOWLEDGE_AUTO_MERGE=0`) | env/offline procedures | posture readouts (kek_set, auto-merge state) |
| Client-side manifest trust verification (`manifest verify/fetch`) | trust decision belongs on the operator's machine | server-side draft list + the activate gate |
| Temporal orchestration, MCP install, framework adapters | infra + developer toolchain | — |
| Programmatic protocols: `record_action`, `propose_learning`, consolidation lease/complete, connector heartbeat POST, backfill progress POST, Debezium/batch ingest, webhook delivery, poll/SSE client loops | agent- and worker-facing by design | their *outcomes*: activity timeline, knowledge queue, connector status, backfill views, quarantine |
| Free-form record editing of any kind | Retool-class anti-pattern; violates keyed-upsert/bi-temporal L1 | the closed verb vocabulary above |

The console mirrors **decisions and evidence**, not infrastructure orchestration. When in doubt: if it touches a secret, a filesystem, or an env var — CLI; if a human must *see, decide, or prove* — console.
