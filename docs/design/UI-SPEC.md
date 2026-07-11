# Verity Console — UI Specification

*The Evidence Room · UI as a trust-and-compliance surface · v0.1 → v0.2*

**Status:** authoritative build contract for the Verity web console.
**Scope:** extends the embedded read-only inspector at `GET /ui` into a multi-screen evidence room.
**Cross-refs:** `SPEC.md` (§§2, 4–9, 11d, 13, 14), `CLAUDE.md` non-negotiables, `crates/verity-server/src/main.rs` (router), `crates/verity-server/src/ui.html` (today's single-file inspector, 737 lines — the thing we extend), **`UI-ACTIONS.md` (the v0.3 action model — see §9)**.

> **Thesis, one line:** Verity's UI is an evidence room, not a control panel. It exists to let a non-engineer *prove the negative* — that customer A cannot see customer B, that nothing stale or unprovenanced is trusted, that every read is on the record — and to walk out with a signed artifact that says so.

---

## 1. Purpose & the gap

### Why the CLI/API is not enough

Verity's differentiated category claim is **trust**: prove nothing leaks, prove nothing is stale, prove nothing acts on unprovenanced data. That claim has to be *demonstrated to a person* — and the person who gates every enterprise deal is a compliance/security reviewer who **will not read Rust, will not drive `curl`, and will not parse a benchmark log**. Today that persona has *no adequate path at all*:

- The **CLI** (`verity-cli`) is a pure REST client aimed at operators and developers — file ingest, scoped `query`, webhook mint, reembed migration, quarantine `tail`, backup/restore. Every surface assumes a terminal and a mental model of scope handles. It is excellent for the people wiring the plane up; it is unusable as reviewer evidence.
- The **REST API** exposes the full enforcement, compliance, and observability plane, but as JSON over HTTP — not as something a CISO can see, drive, and sign off on.
- The **embedded `/ui`** (`ui.html`) is already the right instinct — a single self-contained page titled *"Verity — scope inspector"*, framing question *"What can this agent see, exactly?"* — but it is a single 737-line file, read-only, with known gaps: **no latency shown on recall** (the one spec-relevant number the milestone is about), **no "why filtered" explanation**, **no scope-handle mint/renew**, **no filtering/search/export on the audit tail**, and a **knowledge review queue whose review action forces you to leave for the CLI**.

### What a UI adds that nothing else can

1. **Converts an architectural guarantee into a viewable, drivable, exportable artifact.** The scope inspector turns "our pre-filter removes every non-A chunk before ranking" from an assertion into a live demonstration a non-engineer runs themselves.
2. **Puts the human gates where humans are.** Knowledge publish/reject, erasure, DSAR, manifest activation — all human-in-the-loop decisions the spec deliberately keeps out of agent reach — get a reviewed surface instead of a raw `POST`.
3. **Makes fail-closed *visible*.** Empty results, quarantine, refusals, and disclosed staleness windows are rendered *with their reasons*, so "under-visible is correct" is shown rather than mistaken for a bug.
4. **Produces the deliverable.** "Export boundary as evidence" and the signed purge report are the literal artifacts a reviewer hands upward to unblock a deal.

The UI does **not** replace the CLI/API. Local plane bootstrap (`dev`), backup/restore (shells into the Docker container), client-side manifest trust verification, and BYOT credential capture remain CLI-only by design — they either touch the operator's laptop/filesystem or capture secrets that must never transit a server. The UI mirrors *decisions*, not infrastructure orchestration.

---

## 2. Personas & primary user

Four personas exist (full detail in discovery). Ranked by who the **first** UI must serve:

1. **Compliance / Trust Reviewer — PRIMARY.** CISO delegate, DPO/privacy, GRC analyst. The persona with **no adequate non-UI path** and the gate that unblocks every enterprise deal. Not deeply technical; needs the mechanism *shown*, not asserted. Jobs: "show me exactly what this agent can see," audit who-saw-what, right-to-erasure + DSAR, knowledge-publish review. **The entire first UI is built for this seat.**
2. **Platform Operator — SECOND.** Infra/SRE who stands Verity up and owns uptime, freshness, DR. Jobs: source health + provenance tier, freshness-vs-SLO, quarantine triage, migrations, backup/DR. Much is CLI-driveable today, so the UI is high-value but not existential. Served by the Operations section (v0.2+).
3. **Agent Developer — THIRD.** Builds agents against MCP/REST. Best-served persona by the *existing* surface (MCP-first, CLI, cookbook). The recall playground + "why filtered" inspector is a strong fast-follow, not the wedge — and it rides the same Scope Inspector screen the reviewer uses.
4. **Security / Incident Responder — FOURTH (fold in, don't build standalone).** Poisoning rollback, revocation-propagation checks, lineage forensics. Narrow, incident-triggered, overlaps heavily with Operator and Reviewer. Surface these as *actions within* the operator/compliance views, never a separate app.

**Design consequence:** the first UI is the **Trust & Compliance console**. Operator dashboards layer in second; incident actions fold into both; the developer playground is the natural third surface (and largely already present as the Scope Inspector's probe loop).

---

## 3. Design principles & SPEC non-negotiables the UI must honor

Every principle below is a promise `SPEC.md`/`CLAUDE.md` already makes. The UI is where those promises become real ("the single best artifact for passing a security review," §11d).

### Honesty by disclosure — what the UI MUST make visible

- **Provenance on every hit.** Each recall/fact result displays its **ACL-provenance tag** (`mirrored | approximated | admin-assigned | quarantined`), **confidentiality class** (`public | internal | confidential | restricted`), **trust tier** (Tier-1 authoritative vs `agent_observation`), and **`tag_derivation: provenance | inferred`** — with deterministic (provenance) tags *visually distinct* from probabilistic (inferred) ones (§5e.6, §7d, §9a).
- **Bi-temporal state per fact.** `valid_from`, `is_stale`, `superseded` (+ supersession chain) surfaced on every read; `as_of` point-in-time reads supported. Superseded values are never silently dropped (§2 L3, §4c, §9a, §9b).
- **Citation to L0.** Every result carries `citation → L0 episode id` (§9a). *Exception:* knowledge-item lineage is **audit-scope-only** and never rendered in a recall/brief context (provenance firewall, §2/§7g).
- **Restricted truncation disclosed, never dropped.** When a `restricted` query hits the k>50 BatchCheck ceiling, surface `restricted_truncated: true` + continuation cursor (§4e, §9a).
- **Honest numbers or no number.** Latency shown as p50/p95/p99 **labeled by config** (local-encoder vs remote-embedder-excluded, one click away); no fabricated percentages (determinate bar only when total known, striped indeterminate otherwise); ETA only when honest; SLO panels show the target line and p99 (§4, §4a, §4c, §13, CLAUDE.md).
- **Email-mapped principals = trust downgrade.** Flagged with a distinct chip wherever they appear — session badge and scope inspector (§6b, §11d).
- **Two lanes, labeled, never blurred.** Convenience lane (`admin-assigned`/`approximated`, no per-object ACL fidelity) vs truth lane (`mirrored`, source-fidelity), with in-product graduation prompts (§5e.4, §5e.6).
- **Active purpose-policy version visible** per scope and recorded per read (§7c).

### What the UI MUST gate or NEVER do

- **Fail closed, always.** No visibility tokens → invisible; unresolvable subject → empty result; unmappable ACL → quarantine. The UI **never offers a permissive-fallback affordance** ("index it anyway") — that shortcut must not exist (§5e.6, §7b, CLAUDE.md).
- **No default visibility, anywhere.** Any write/publish surface **requires** an explicit visibility/policy choice; omission is a refusal, never a silent default (§5e.8).
- **Scope can only NARROW, never widen.** The mint dialog has *no widen affordance by construction* — you may pick a tighter ceiling than your own, never broader. Cross-entity work forces opening a **separate, audited** scope (§5e.6, §7c).
- **Knowledge is human-gated.** `propose_learning` is a proposal, never a publish. Publish grants broad visibility and is the final human gate; **auto-publish is OFF by default** and framed as a high-consequence config choice, never a silent default (§2, §9a).
- **Provenance firewall.** Support counts shown to agents are **BUCKETED** (`several | many | extensive`), exact `distinct_entities`/`writer_count` are admin-surface-only; knowledge lineage back to episodes is audit-scope-only and never in recall/brief (§2, §7g).
- **`forget` = invalidation, not deletion.** Presented as "invalidate (reversible)," preserving as-of history (§8f, CLAUDE.md).
- **Erasure is admin/compliance-only, never agent-reachable.** Hard purge only via the §8 crypto-shred pipeline; no ad-hoc "delete this row." Erasure lives **physically behind the admin token**, structurally unreachable from any scope-handle context (§8, §8b, §8f, CLAUDE.md).
- **Never trust client-supplied identity/scope.** Actor/writer/scope come from the authenticated token, never from arguments — the UI never presents self-reported identity as authoritative (§2, §9a).
- **Read-path purity.** The read screens make **zero LLM calls and zero live ReBAC-engine calls**. Handle decode is client-side; probes are pure reads. Any richer "why filtered" that would need a live enrichment call is deferred to an explicitly OFF-hot-path, admin-gated, audited debug endpoint (not in MVP) — never bolted onto the recall path to make the debugger prettier (§9a, CLAUDE.md).
- **v0.1 web UI is read-only for memory and enforcement.** Admin mutations route to CLI/REST until v0.2. The UI **discloses this ceiling** (per-panel read-only ribbon) rather than faking buttons (§11d, §13).

---

## 4. Information architecture

A single embedded app served at `GET /ui`, organized as an **evidence room** with a fixed left rail. Nav order encodes the reviewer's workflow — *establish the boundary → watch it hold → act at the human gates → produce the artifact* — grouped by the operator's verbs (Prove / Run / Configure), not by API shape.

```
VERITY CONSOLE   ·  tenant switcher  ·  session (scope/admin) badge  ·  build hash

  PROVE  (Evidence — Compliance/Trust Reviewer seat)
   1. Scope Inspector      ← crown jewel; "what can this agent see, exactly?"        [MVP]
   2. Access Audit         ← who saw what, when, under which policy version           [MVP]
   3. Knowledge Review     ← the human gate: publish / reject cross-customer learnings [MVP read-only]
   4. Erasure & DSAR       ← right-to-be-forgotten + subject export, signed reports    [v0.2]

  RUN  (Operations — Operator seat)
   5. Sources & Freshness  ← provenance tier, freshness-vs-SLO, connector health       [v0.2]
   6. Quarantine           ← fail-closed queue: unmappable ACLs sitting invisible      [v0.2]
   7. Migrations           ← re-embed batch + cutover, backfill, brief refresh         [Later]

  CONFIGURE  (Admin — gated, admin-token only)
   8. Principals & Groups  ← identity resolution, ReBAC membership, revocation         [Later]
   9. Entities & Precedence← merge/link, source-of-truth ranking, conflict resolution  [Later]
```

**MVP rail discipline (correction from synthesis):** hold the line at **MVP-3 + global chrome** (screens 1–3). Screens 4–9 appear in the rail as **clearly-labeled "ships in v0.2 / Later" entries that render a placeholder state**, not half-built screens. The rail communicates the full destination while shipping only what is real.

### Global chrome (every screen)

- **Session badge** (top-right): shows *which credential is active*. For a decoded scope handle: principals, entity scope, confidentiality ceiling, expiry countdown. For the admin token: role + *"never persisted to disk."* Email-mapped principals render here with a **red trust-downgrade chip** (§6b). This closes today's "no indication of which token/role is active" gap.
- **Tenant switcher**: one active `tenant_id`; auto-fills from a decoded handle. Feeds every admin panel.
- **Per-panel read-only ribbon** (v0.1): a thin band on each screen that still lacks its v0.2 gate — *"v0.1 · this panel is read-only; the [publish/reject/erase] action routes to CLI/REST — see below."* The ribbon **disappears panel-by-panel as each v0.2 gate lands**, so the disclosure tracks reality screen-by-screen (not one global banner).
- **Build hash** in the header: the served UI is `include_str!`-embedded in the binary, so the hash *is* the version — no UI/server skew possible.

---

## 5. Screen-by-screen spec

For each screen: **what it shows**, the **exact endpoints** behind it (grounded in the real router), and **actions** with their gating.

### Screen 1 · Scope Inspector — *the boundary made concrete*  `[MVP]`

The single highest-leverage screen. Answers the CISO's question — "prove customer A's agent can't see customer B" — live.

**Backing endpoints:**
- Decode: **client-side only** (base64url → JSON via `atob`/`TextDecoder`). No server call. The handle is *"signed, not secret."*
- `POST /v1/recall` (scope-token) — hybrid scoped retrieval.
- `GET /v1/briefs/{entity}` (scope-token) — entity brief.
- `GET /v1/activity` (scope-token) — activity timeline.
- `POST /v1/scopes` (public/scope-mint) — **v0.2** Open/Renew scope.

**Shows:**
- **Handle intake:** `vs_…` textarea + **Decode**. Decoded claims block: `tenant_id`, `principals (tokens)`, `entity_scope`, `max_confidentiality`, `actor (sub · azp)`, `subject`, `retrievable_classes`, **active purpose-policy version** (§7c), `expires_at` with live "Ns left / **EXPIRED**" (red marker).
- **Fail-closed empty-set copy, verbatim from today's `/ui`:** empty principals → *"∅ — this handle sees nothing (fail closed)."*
- **Trust-downgrade flags:** any email-mapped principal badged **trust downgrade** with a one-click "why this is weaker" note (§6b).
- **Three live probes *through the exact handle*** — recall, entity brief, activity — each hit card rendering the full honesty payload: **ACL provenance tag**, **confidentiality class**, **trust tier**, **`tag_derivation`** (provenance = solid badge, inferred = dashed-outline badge — a crisp visual encoding of guaranteed-vs-probabilistic), **`valid_from` / `is_stale` / `superseded`**, **citation → L0 episode id**. Recall auto-fills tenant/entity from the decoded handle.
- **Boundary trace (new, MVP-safe):** a collapsible panel that, for a recall, reports **only what is derivable from the returned payload + handle-vs-query reasoning** — e.g. *"handle `max_confidentiality` is `internal`; a `confidential` filter would be required to match,"* *"`restricted_truncated: true` — continuation cursor shown,"* provenance/tag mix of returned hits. **In-panel honesty note:** *"This trace explains the returned set and the handle's ceiling. It does NOT enumerate every pre-filtered candidate — full per-candidate drop reasons require the audited debug-recall endpoint (not on the read path)."* This keeps the trace itself honest and is the MVP-safe precursor to the deferred debug endpoint.
- **Explain zero (new, pure/zero-backend):** on a zero-hit recall, a diagnostic that reasons from the *decoded handle vs the query params* — *"0 hits. Under this scope, nothing matches — that is the point."* plus the specific clamp when derivable ("your handle's `max_confidentiality` is `internal`; this query needed `confidential`"). Makes fail-closed *demonstrable*, not just empty.
- **Latency, honestly (closes milestone-A tension):** each recall probe shows **p50/p95/p99 measured across N runs of that call**, labeled exactly: *"session-local · N runs · your hardware · not the milestone-A benchmark,"* with a config sub-label (local-encoder vs remote-embedder-excluded, one click away, §4a/§13). This must never be confused with the official benchmark numbers.

**Actions:**
- **Decode** (client-side).
- **Run recall / Load brief / Load activity** (through the handle).
- **Copy handle**; **Copy a hit's `document_id`** (jump to provenance).
- **Export boundary as evidence** → downloads a self-contained HTML/JSON snapshot: decoded claims + probe results + boundary trace + timestamp + build hash. *This is the reviewer's deliverable.*
- **(v0.2) Open scope** → mint dialog (`POST /v1/scopes`) that **only narrows**: entity scope, confidentiality ceiling, purpose, TTL. **No widen affordance by construction** — you cannot select a broader ceiling than your own. **(v0.2) Renew** re-mints an expired handle from the same claims.
- **(Later) A/B two handles** side-by-side on one query ("team handle vs org handle").

**Honors:** read-path purity (client decode, pure probes, no LLM/ReBAC); fail-closed empty-state; provenance/tag-derivation/trust/bi-temporal per hit; email-mapping trust downgrade; scope-only-narrows; restricted-truncation disclosed; honest session-local latency clearly separated from benchmarks.

---

### Screen 2 · Access Audit — *who saw what, on the record*  `[MVP]`

**Backing endpoint:** `GET /v1/admin/audit` (admin-token) — recent audit rows, newest first.

**Shows:**
- Newest-first table of every scoped read (recall, get-by-id, adjacency, brief, subscription delivery, signed-media redemption): `at`, `verb`, `actor (sub · azp)`, `principals`, `confidentiality`, **policy version governing the scope** (§7c), `query summary`, right-aligned `result count`.
- **Blocked-injection rows** with a distinct **defense badge** (§13). Summary strip: *"N adversarial probes in window · 0 leaked items."*
- **Filters (today's `/ui` has none):** by actor, verb, entity, confidentiality, policy version, time range; free-text on query summary.
- Distinct visual treatment for `forget` / `erasure` / `dsar_export` rows so compliance events are findable instantly.
- **Audit-of-audit note:** the panel states that reading it is itself audited and requires the audit-reader role (§7e).

**Actions:**
- **Filter / search**; **auto-refresh** toggle (live tail, ~5s).
- **Export** filtered window as **CSV / JSON** (SIEM-shaped).
- **(v0.2) Drill into a row** → result_ids returned, and **jump-to-Scope-Inspector** with the actor's reconstructed scope claims.

**Honors:** every `(subject, scope, results)` audited across all read paths; policy-version-per-scope visible; blocked injections visible/explainable; audit-reader gating reflected.

---

### Screen 3 · Knowledge Review — *the human gate, with the gate button on the page*  `[MVP read-only]`

The single biggest gap in today's `/ui`: a human-gated review queue whose review action forces you to leave for the CLI. The queue ships live in MVP; the **gate buttons are stubbed behind the per-panel read-only ribbon** until v0.2.

**Backing endpoints:**
- `GET /v1/knowledge` (admin-token) — review queue with admin-exact support/tier/evidence.
- `GET /v1/admin/knowledge/{id}` (admin-token) — full item detail (support, merge_reason, de-id gate, evidence).
- `POST /v1/knowledge/{id}/publish` (admin-token) — **v0.2** publish at broad visibility + `k_min` (clamped ≥3).
- `POST /v1/admin/knowledge/{id}/reject` (admin-token) — **v0.2** reject (remembered so it won't resurrect).

**Shows:**
- Status filter (candidate / eligible / published / quarantined / rejected / invalidated) + queue table: `status` badge (lifecycle-colored), `statement`, category badges, **support as a BUCKET** in any agent-facing preview (`several | many | extensive`) with **exact `distinct_entities` / `writer_count` shown ONLY in this admin surface** (§2 provenance firewall — the buckets/exact split rendered faithfully), `merge_reason` or quarantine `gate` reason, `evidence count`.
- **Item detail drawer** (`GET /v1/admin/knowledge/{id}`): full support, de-id gate result, k-support math (≥3 distinct entities / ≥2 writers / category floor), evidence count. **Lineage-to-episodes is present but explicitly labeled audit-scope-only and never rendered in any recall/brief context** (§2, §7g).

**Actions (v0.2 — ringed by the read-only ribbon in v0.1):**
- **Publish** (`POST /v1/knowledge/{id}/publish`) → dialog that **requires** an explicit visibility + `k_min` (clamped ≥3). **No default visibility — omission refuses** (§5e.8). Confirmation copy states this grants *broad* visibility.
- **Reject** (`POST /v1/admin/knowledge/{id}/reject`).
- **Auto-publish** presented as **OFF** and framed as a high-consequence config toggle, never a silent default (§2 step 5).
- **Retraction note (honest gap):** there is **no un-publish endpoint**; published items link to **Erasure & DSAR / `forget`** as the only retraction path — a **"disabled seam we design but never fake"** (surfaced honestly, not a fake button).

**Honors:** cross-customer generalizations human-gated, never auto-published; bucketed support to agents, exact to admin; provenance firewall (lineage audit-scope-only); no default visibility on publish.

---

### Screen 4 · Erasure & DSAR — *the irreversible admin verb, structurally quarantined from agent scope*  `[v0.2]`

**Structural gating (correction from synthesis):** this screen is **physically reachable only inside the admin-token section** and **cannot be entered from any scope-handle context** — the mount is gated on `admin.check` succeeding, not merely visually hidden. An injected prompt riding a scope handle can never reach it (§8f).

**Backing endpoints:**
- `POST /v1/admin/erasure` (admin-token) — crypto-shred; ReBAC tuples deleted first (§8).
- `GET /v1/admin/dsar/export` (admin-token, audited) — DSAR bundle.
- `GET /v1/admin/media` (admin-token) — list a tenant's media blobs (find named blobs to erase).
- `POST /v1/forget` (scope-token) — item-level invalidation (reversible).

**Shows:**
- Subject lookup (subject id / entity / named `media_ids` via `GET /v1/admin/media`).
- **Erasure preview:** lineage-walk of what *would* be purged (episodes, chunks, actions, keys) **before** anything runs, plus **honest coverage-gap disclosure** — operator-named media, exact-string matching, backup-retention window (§8b). "Disclose the window, don't claim perfection."
- **DSAR bundle preview** (`GET /v1/admin/dsar/export`): episodes (decrypted), chunks, actions, access-event skeleton, proposed knowledge.

**Actions:**
- **Run erasure** (`POST /v1/admin/erasure`) → **strong typed confirm** ("type the subject id to confirm irreversible crypto-shred"). On completion: **per-table purge counts + the signed purge report** (refs purged, keys destroyed, timestamps, retention window) rendered and **downloadable**; plus the **knowledge-retraction cascade** (published items dropped below k-support auto-invalidated) (§8b, §13).
- **Export DSAR** → downloads the bundle; the export writes an audit row (shown as a fresh Access-Audit entry).
- **Item-level "Retract"** (`POST /v1/forget`) — **labeled "invalidate (reversible), not delete"** so `forget` is never mis-presented as deletion (§8f).

**Honors:** erasure admin-only + structurally unreachable from agent scope; hard purge only via §8 crypto-shred (no ad-hoc row delete); `forget` = invalidation; signed purge report surfaced; coverage gaps disclosed.

---

### Screen 5 · Sources & Freshness — *provenance tier + freshness-vs-SLO per source*  `[v0.2]`

**Backing endpoints:**
- `GET /v1/admin/connector-status` (admin-token) — latest heartbeat per source.
- `GET /v1/slo/freshness` (admin-token) — per-source freshness percentiles over window.
- `GET /v1/admin/backfill` (admin-token) — latest backfill run per source.
- **v0.2 writes:** `POST /v1/manifests` → `POST /v1/manifests/{id}/activate`; `POST /v1/webhooks`; `DELETE /v1/webhooks/{id}`.

**Shows:**
- **Source inventory:** per source — **ACL-provenance tier badge** (mirrored / approximated / admin-assigned / quarantined), **lane label** (truth vs convenience, *"labeled everywhere, never blurred,"* §5e.6), `items synced`, cursor, **last-event age** (green <15m / amber <24h / red beyond, honest "no event time" fallback), heartbeat, inline error/last-failure.
- **Freshness SLO table:** per-source **p50 / p95 / p99** source-change-to-queryable over a stated window, with an **SLO target line + breach highlighting** (today's panel shows neither target nor p99 — both fixed). Each source shows its *true cadence* — a daily-sync source reads daily, never inherits a flagship "seconds" claim (§5d).
- **Grant-staleness / ACL-sync window disclosed as an SLO**, not claimed "instant" (§7b, §14).

**Actions:**
- **v0.1 (read):** + **graduation prompt** ("this source is convenience-lane; connect the native Tier-A connector to get `mirrored` ACLs") (§5e.4).
- **v0.2:** **Install manifest (as draft)** (`POST /v1/manifests`) → **Activate** as a *separate, explicit, human-approver-recorded, audited* step (`POST /v1/manifests/{id}/activate`) — never a flag flip (§5e.3). **Mint webhook** (`POST /v1/webhooks`, **show-once secret** with copy-once UI) / **Revoke** (`DELETE /v1/webhooks/{id}`).

**Honors:** two lanes labeled/never blurred; honest per-source freshness incl. p99 + true cadence; ACL-sync window disclosed as SLO; manifest activation is explicit audited human approval.

---

### Screen 6 · Quarantine — *fail-closed, visible, and explained*  `[v0.2]`

**Backing endpoint:** `GET /v1/admin/quarantine` (admin-token) — recent quarantined webhook payloads, newest first.

**Shows:**
- Table of unmappable-ACL / unrecognized-shape events: `at`, `webhook_id`, **reason** (quarantined badge), **full payload view** (today truncates at 240 chars), reason grouping + counts + time-range filter.
- Panel thesis banner: *"These are invisible to recall by design. Nothing ambiguous is indexed permissively."* — the fail-closed non-negotiable made into the panel's identity.

**Actions:**
- **v0.1/v0.2 (read):** filter, group, **export for offline analysis**. The panel **honestly states there is no re-ingest/dismiss endpoint yet** — a flagged gap rendered as a **disabled seam we design but never fake**, not a phantom button.
- **Blocked-on-server-gap (Later):** re-map ACL + re-ingest, dismiss/acknowledge — **needs new WRITE surface** the spec must add first. Crucially, **no "index it anyway" shortcut will ever exist**; re-ingest routes only through a corrected mapping (§7b).

**Honors:** unmappable ACL → quarantine, never permissive indexing; UI offers **no permissive-fallback affordance** by design.

---

### Screen 7 · Migrations — *honest progress, no fabricated percentages*  `[Later]`

**Backing endpoints:**
- `POST /v1/admin/reembed/batch` (admin-token) — re-embed a batch; returns coverage.
- `POST /v1/admin/reembed/cutover` (admin-token) — flip dense route (coverage-gated; `force`; V1 rollback).
- `GET /v1/admin/backfill` (admin-token) — backfill progress (also on Screen 5).
- `POST /v1/admin/briefs/refresh` (admin-token) — recompute stale briefs for a tenant.

**Shows:**
- **Re-embed:** coverage % of `embedding_v2`; **determinate bar when total known, striped indeterminate track when uncountable** — never a fabricated percentage (inherited discipline from today's best panel).
- **Backfill:** per-source state (running/paused/completed/failed), determinate/indeterminate progress, **ETA only when honest** (running + known total + forward progress), inline failure error, **quarantined-count column** (§5a.3).
- **Cutover:** current dense route (v1/v2) + coverage-gate state.

**Actions (Later):**
- **Run re-embed batch** (loop with live coverage).
- **Cut over** → **coverage-gated**; sub-100% requires explicit **`force` acknowledgment**; **V1 rollback** button.
- **Refresh all briefs**.

**Honors:** every measured number honest — no fabricated percentages, ETA only when honest; cutover coverage-gated with explicit force ack.

---

### Screens 8–9 · Principals/Groups & Entities/Precedence — *admin curation*  `[Later]`

**Backing endpoints:**
- `POST /v1/admin/principals` (admin-token) — upsert principal strings → int tokens.
- `POST /v1/admin/groups` (admin-token) — write group-membership tuple; `DELETE /v1/admin/groups` — remove membership (writes revocation tombstones first, fail-closed).
- `POST /v1/admin/entity-aliases` (admin-token) — upsert alias set → canonical.
- `POST /v1/admin/entity-precedence` (admin-token) — per-field source precedence.
- `GET /v1/entities/{canonical}` (scope-token) — merged cross-source view for conflict rendering.

**Shows / Actions:**
- **Principals** (upsert → int tokens). **Groups** (add member; **remove writes revocation tombstones first, fail-closed → strong confirm dialog** with drift-window note: "hidden on the very next read").
- **Entities** (link/merge aliases → canonical; **cross-source merge conflicts rendered side-by-side with provenance when no precedence rule exists** — *"conflict made visible beats conflict resolved wrong,"* §7f — each merged field showing its winning source). **Precedence** (per-field source ranking).
- **Incident-responder actions fold in here and in Screens 1/2:** lineage blast-radius view + poisoning rollback, revocation-tombstone confirmation.

**Honors:** revocation writes tombstones first, fail-closed; merge conflicts made visible, not silently resolved.

---

## 6. MVP / Beyond-MVP / Later — explicit checklists

### MVP (v0.1) — ships first · all read-only · honors §11d/§13 ceiling

- [ ] **Global chrome:** tenant switcher, session badge (with email-mapping red chip), per-panel read-only ribbon, build hash.
- [ ] **Screen 1 · Scope Inspector:** client-side decode; three probes through the handle (`POST /v1/recall`, `GET /v1/briefs/{entity}`, `GET /v1/activity`); full provenance / tag-derivation (solid vs dashed) / trust / bi-temporal per hit; **boundary trace** (payload-derived, with honesty note); **Explain zero**; **session-local p50/p95/p99** clearly labeled "not the benchmark"; **Copy handle / Copy document_id**; **Export boundary as evidence**.
- [ ] **Screen 2 · Access Audit:** `GET /v1/admin/audit`; filter/search (actor/verb/entity/confidentiality/policy-version/time/free-text); blocked-injection defense badges + zero-leak summary; policy-version column; CSV/JSON export; auto-refresh; audit-of-audit note.
- [ ] **Screen 3 · Knowledge Review (read):** `GET /v1/knowledge` + `GET /v1/admin/knowledge/{id}`; queue + detail drawer; bucketed-vs-exact support split; firewall respected (lineage audit-scope-only). Publish/Reject buttons **stubbed behind the read-only ribbon**.

*If only one screen shipped, it is Screen 1 — the deal-unblocking artifact.*

### BEYOND-MVP (v0.2) — the human gates go live

- [ ] **Knowledge Publish / Reject** buttons: `POST /v1/knowledge/{id}/publish` (required visibility + `k_min` ≥3, no default), `POST /v1/admin/knowledge/{id}/reject`. (ribbon lifts on Screen 3.)
- [ ] **Screen 4 · Erasure & DSAR:** structurally admin-gated; erasure preview + coverage-gap disclosure; `POST /v1/admin/erasure` (typed confirm, signed report download, retraction cascade); `GET /v1/admin/dsar/export` (download, self-audits); `GET /v1/admin/media`; item-level `POST /v1/forget` labeled "invalidate, reversible."
- [ ] **Screen 5 · Sources & Freshness (read):** `GET /v1/admin/connector-status`, `GET /v1/slo/freshness` (p50/p95/p99 + target + breach), `GET /v1/admin/backfill`; provenance-tier + lane badges; graduation prompts.
- [ ] **Screen 6 · Quarantine (read/export):** `GET /v1/admin/quarantine`; full payload; grouping/filter/export; honest "no re-ingest endpoint" seam.
- [ ] **Screen 1 · Open scope / Renew** mint dialog (`POST /v1/scopes`, narrow-only, no widen affordance).
- [ ] **Screen 2 · row drill-down** → result_ids + jump-to-inspector.

### LATER

- [ ] **Screen 7 · Migrations:** re-embed batch loop (`POST /v1/admin/reembed/batch`), cutover (`POST /v1/admin/reembed/cutover`, coverage-gated + force ack + V1 rollback), brief refresh (`POST /v1/admin/briefs/refresh`).
- [ ] **Sources v0.2 writes:** manifest install→activate (`POST /v1/manifests`, `POST /v1/manifests/{id}/activate`), webhook mint/revoke (`POST`/`DELETE /v1/webhooks`, show-once secret).
- [ ] **Screens 8–9 · Principals/Groups & Entities/Precedence:** upserts, group add/remove (tombstone confirm), alias/precedence, side-by-side conflict resolution.
- [ ] **Incident actions:** lineage blast-radius + poisoning rollback, revocation-tombstone confirmation.
- [ ] **Debug-recall / "why-out" per-candidate trace:** a **separate, opt-in, admin-gated, audited** endpoint that is **explicitly OFF the pure read path** — the honest way to get full per-candidate drop reasons. *Never* add an LLM/live-ReBAC call to the hot path to make the debugger prettier.
- [ ] **Save-probe / probe-suites** as scoping regression tests (assert expected counts, red/green on drift); **A/B two handles** side-by-side.
- [ ] **Quarantine re-map / re-ingest / dismiss** — *blocked on new server WRITE surface; flagged as a gap the spec must close first.*

---

## 7. Technical approach

### Keep the zero-build, self-contained, embedded page — do not introduce Node/CDN/bundler

This is **load-bearing for the product thesis**, not inertia. An OSS operator runs `cargo run` and gets a working, tamper-evident inspector with **no toolchain, no asset pipeline, and no version skew between UI and server**. For an *evidence room*, "no external hosts, nothing to fetch, nothing that can rot, nothing to CSP-block" is part of the security story — the inspector cannot be silently altered by a compromised CDN. A build step would trade that away for developer convenience. Not worth it.

Constraints preserved from today's `ui.html`:
- **Single served route** (`GET /ui`), assembled at **compile time**, served as one page — no second HTTP request, no static-asset directory to mount.
- **All CSS/JS inline**; system monospace font stack; zero `<link>`, zero `<script src>`, zero web fonts/images.
- **Vanilla JS only**; hand-rolled helpers (`$`, `esc`, `api()`, client-side handle decode via `atob`/`TextDecoder`).

### The one change: split the source so builders parallelize

One 737-line file is already near its ceiling for a 9-screen scope. The fix that preserves **every** constraint: **split the source into per-screen fragments, each `include_str!`-embedded and concatenated at compile time into the single served page.** N files → N builders in parallel; still one binary, one route, zero runtime assets.

**Build mechanism (concrete):** a `build.rs` concatenates the fragments into one generated string that the served route returns (or an equivalent `concat!(include_str!(...), ...)` in a small assembler module). `build.rs` is the explicit build contract: freeze `theme.css` tokens + `core.js` helper signatures **first**, then screen fragments are independent inputs to the concat. Adding a screen is a one-line diff to the assembler order.

**File / asset decomposition** (all under `crates/verity-server/src/ui/`):

```
ui/
  mod.rs                     // serve GET /ui: returns the compile-time-assembled page (one route, unchanged contract)
  build-assembled at compile time via build.rs (or concat! in mod.rs) from the fragments below:
  shell.html                 // doctype-less body: left rail, tenant switcher, session badge, ribbon, <div> mount points
  theme.css                  // DESIGN TOKENS ONLY (palette, type scale, spacing, badge colors) — the shared contract
  core.css                   // layout primitives: cards, .tablewrap (overflow-x), badges, bars, dialogs
  core.js                    // hand-rolled helpers: $, esc, api(), decodeHandle(), badge(), fmtMs(), router, mount registry
  panel_scope.{html,js}      // Screen 1  (crown jewel — senior builder)
  panel_audit.{html,js}      // Screen 2
  panel_knowledge.{html,js}  // Screen 3
  panel_erasure.{html,js}    // Screen 4  (v0.2 — admin-gated mount)
  panel_sources.{html,js}    // Screen 5  (v0.2)
  panel_quarantine.{html,js} // Screen 6  (v0.2)
  panel_migrations.{html,js} // Screen 7  (Later)
  panel_admin.{html,js}      // Screens 8–9 (Later)
```

**Parallelization contract (so builders never collide):**
- **`theme.css` is the single shared design file** — badge colors for provenance/confidentiality/lifecycle, type scale, hue-biased neutrals. **One owner; everyone else imports its classes and never edits it.** This is where the design language lives.
- **`core.js` owns the primitives** (`api()`, `decodeHandle()`, `badge()`, router, mount registry). **One owner.** Panels register against a mount point and never touch each other's DOM.
- **Each `panel_*.{html,js}` pair is fully independent** — a builder owns one screen end-to-end, reading (never writing) `theme.css` and `core.js`. Merge conflicts structurally near-zero.
- **The assembler (`mod.rs` / `build.rs`) is append-only per panel** — one include + one registration line per screen.

### Routing

- `GET /ui` — unchanged single route; serves the assembled page. Unauthenticated (matches today's router; the *page* is public, its *probes* enforce per call).
- No new server routes are required for the MVP-3 — every screen is backed by endpoints that already exist (`/v1/recall`, `/v1/briefs/{entity}`, `/v1/activity`, `/v1/admin/audit`, `/v1/knowledge`, `/v1/admin/knowledge/{id}`).

### Auth handling

- **Scope-token probes** (Screen 1): the caller pastes a `vs_…` handle; the UI sends it on `POST /v1/recall` etc. The handle is *"signed, not secret"* — decoding is client-side and reveals only its own signed claims. Enforcement is server-side from the signed payload; the UI never widens it.
- **Admin-token panels** (Screens 2–9): admin token lives in **`sessionStorage` only, never persisted to disk** (labeled as such in the session badge), sent as `Authorization: Bearer <token>` on admin calls. In dev mode (token unset) the server allows and warns; the UI reflects "dev-mode: admin unset" honestly rather than implying auth.
- **No credential ever transits to an external host** — CSP-clean, single-origin, same binary.

### How mutating calls are made (v0.2+)

- Every mutating action is a plain `fetch` from `core.js`'s `api()` wrapper to the real endpoint with the admin bearer, gated behind: (a) the panel's read-only ribbon being lifted, and (b) the action's confirmation (typed-confirm for erasure, required visibility+`k_min` for publish, tombstone-warning confirm for group removal, force-ack for sub-100% cutover).
- **Show-once secrets** (webhook mint): the raw token is rendered exactly once with a copy-once affordance and never re-fetched.
- **Structural gates** (erasure): the mount only instantiates when `admin.check` succeeds — a scope-handle session can never render the screen.

---

## 8. Build plan — ordered, parallelizable task groups (MVP)

Groups run in dependency order; within the "parallel" groups, tasks touch disjoint files and can be built concurrently by different builders. Each task names the files it touches.

### Group 0 — Foundations (SERIAL · must land first · one owner each) — *blocks everything*

- **T0.1 — Assembler + routing skeleton.** Create `ui/mod.rs` and the `build.rs` concat (or `concat!` assembler); wire `GET /ui` to serve the assembled page; stub empty fragment includes so it compiles. **Files:** `crates/verity-server/src/ui/mod.rs`, `crates/verity-server/build.rs`, `crates/verity-server/src/main.rs` (route swap only). **Owner:** infra builder.
- **T0.2 — Design tokens (frozen contract).** `theme.css`: palette (blue-slate biased dark ground, accent held distinct from semantic green/amber/red/blue), type scale, spacing, and the badge color vocabulary (provenance mirrored-green / approximated-amber / admin-blue / quarantined-red; confidentiality 4-level; knowledge lifecycle; trust/tier/entity; **dashed-outline = inferred, solid = provenance**). **Files:** `crates/verity-server/src/ui/theme.css`. **Owner:** design owner. **Frozen after this task — no later edits.**
- **T0.3 — Core primitives (frozen signatures).** `core.js` helpers (`$`, `esc`, `api()`, `decodeHandle()`, `badge()`, `fmtMs()`, router, mount registry) and `core.css` layout primitives (cards, `.tablewrap` overflow-x, badges, bars, dialogs). Publish helper signatures. **Files:** `crates/verity-server/src/ui/core.js`, `crates/verity-server/src/ui/core.css`. **Owner:** core owner. **Signatures frozen after this task.**
- **T0.4 — Shell + global chrome.** `shell.html`: left rail (with v0.2/Later placeholder entries), tenant switcher, session badge (email-mapping red chip), per-panel read-only ribbon component, build-hash header, mount `<div>`s. **Files:** `crates/verity-server/src/ui/shell.html`. **Owner:** core owner (after T0.3).

### Group A — MVP screens (PARALLEL · disjoint files · after Group 0)

- **TA.1 — Screen 1 · Scope Inspector.** Client-side decode + claims block + fail-closed copy + trust-downgrade flag; three probes (`POST /v1/recall`, `GET /v1/briefs/{entity}`, `GET /v1/activity`) with full honesty payload per hit; boundary trace (payload-derived + honesty note); Explain-zero; session-local p50/p95/p99 (labeled "not the benchmark"); Copy handle / Copy document_id; Export boundary as evidence. **Files:** `crates/verity-server/src/ui/panel_scope.html`, `panel_scope.js`. **Owner:** senior builder.
- **TA.2 — Screen 2 · Access Audit.** `GET /v1/admin/audit`; filter/search bar; blocked-injection defense badges + zero-leak summary; policy-version column; compliance-event row styling; CSV/JSON export; auto-refresh; audit-of-audit note. **Files:** `crates/verity-server/src/ui/panel_audit.html`, `panel_audit.js`. **Owner:** builder B.
- **TA.3 — Screen 3 · Knowledge Review (read).** `GET /v1/knowledge` + `GET /v1/admin/knowledge/{id}`; status filter + queue table with bucketed/exact support split; detail drawer with de-id gate + k-support math + audit-scope-only lineage label; Publish/Reject **stubbed behind read-only ribbon**. **Files:** `crates/verity-server/src/ui/panel_knowledge.html`, `panel_knowledge.js`. **Owner:** builder C.

### Group B — Integration & evidence (SERIAL · after Group A)

- **TB.1 — Rail registration + placeholders.** Register the 3 live panels; render v0.2/Later rail entries as labeled placeholder states. **Files:** `crates/verity-server/src/ui/mod.rs` (append includes), `shell.html` (rail entries). **Owner:** core owner.
- **TB.2 — "Export boundary as evidence" hardening.** Self-contained HTML/JSON snapshot (claims + probes + trace + timestamp + build hash), no external refs. **Files:** `crates/verity-server/src/ui/panel_scope.js`, `core.js` (export helper only). **Owner:** senior builder.
- **TB.3 — Read-path-purity + honesty audit.** Verify zero LLM/live-ReBAC on read; latency label wording ("session-local, not benchmark"); boundary-trace honesty note present; no permissive-fallback affordance anywhere; admin token in `sessionStorage` only. **Files:** review across `ui/`. **Owner:** senior builder + design owner.

**Critical path:** T0.1 → T0.2/T0.3 (parallel) → T0.4 → {TA.1, TA.2, TA.3 parallel} → TB.*. The three MVP screens require **no new server endpoints**.

---

## 9. v0.3 direction: from evidence room to workbench

**Pointer:** the authoritative action model for v0.3 is **`UI-ACTIONS.md`** (same directory). This spec remains the contract for chrome, panel structure, and the fail-closed gates; UI-ACTIONS.md is the contract for *verbs* — what users must be able to DO, grounded in a full action-gap matrix (REST/CLI/MCP/console), a persona×task demand analysis, and four adversarial journey walkthroughs run against the live console.

**What v0.3 changes.** The v0.1/v0.2 build shipped the evidence room and it works — but the journeys show the server outgrew the UI's read-only ceiling: live endpoints sit behind disabled seams (webhook mint, manifest install/**activate** — the spec's one mandated human-approval verb), the default panel demands a scope handle the console refuses to mint (`POST /v1/scopes` is public and the dialog already exists), and a memory product has zero in-console ways to put memory in. v0.3 adds a small closed vocabulary of **named action verbs** — mint a probe handle, add memory (explicit visibility, refusal on omission), an attention-first "needs decision" home, un-seamed source writes, a principal directory read, a run-resolution trigger, and empty states that teach the verb that fills them — per the Now/Next/Later ladder in UI-ACTIONS.md.

**What does not change — the evidence-room ethos and every gate, restated as law:**
- Fail closed, always; **no "index it anyway" affordance will ever exist**; quarantine keeps exactly its two exits.
- **No default visibility anywhere** — omission is a refusal, never a silent default.
- Scope handles **narrow, never widen**; cross-entity work still opens a separate, audited scope.
- Knowledge stays **human-gated**: publish/reject remain evidence-first, dialog-gated, never bulk; auto-publish stays OFF; the provenance firewall (bucketed support to agents, exact counts + lineage admin/audit-scope-only) is untouched.
- Erasure stays **structurally admin-gated** (typed confirm, preview-first, signed purge report); `forget` is always "invalidate — reversible."
- **Read-path purity:** no v0.3 verb adds an LLM or live-ReBAC call to `recall`/`get`; debugging rides the audited, off-hot-path debug endpoint.
- **Honest numbers or no number**; identity never client-supplied; the console remains a scoped, fail-closed client of the product with no god-mode read path.
- Disabled seams stay honest in both directions: designed-not-faked while the endpoint is missing, and **removed the release the endpoint goes live** — a stale seam (the Audit-ribbon lesson) is a lie in the other direction.

Every act v0.3 adds must emit or link its evidence (audit row, show-once secret, signed report, decision receipt). The console stays an evidence room; it just stops making you leave the room to act on the evidence.
