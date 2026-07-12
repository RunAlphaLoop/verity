# Playground — "Ask your memory" (build contract, v1)

**Status:** authoritative build contract for the playground panel + endpoint. Synthesized 2026-07-12 from three concept sketches (demo-first, latency-workbench, operator-first); the judgment is recorded in §1 so future edits know what was traded away and why.

**Founder's ask (verbatim):** *"a 'playground', so users can pick a scope and use an agent to ask questions of the data and see what comes back. We can measure speed etc..."*

**Panel id:** `playground` · **Rail:** `Playground`, in **Prove & inspect**, directly after `Scope Inspector` · **Endpoint:** `POST /v1/playground/ask` + `GET /v1/playground/status` · **State:** none — no migrations, no new tables, nothing persisted beyond the ordinary audit rows the underlying scoped reads already write.

---

## 0. Read-path purity — the law, stated first

> **Read-path purity is NOT violated by this feature.** `POST /v1/recall` and `GET /v1/records/{source}/{entity}/{field}` remain exactly as they are: zero LLM calls, zero live ReBAC-engine calls, scope filters materialized into the index and applied as mandatory pre-filters, enforcement in the ONE shared layer above `StorageAdapter`. The playground is a **consumer** of the read path: the LLM sits *above* it, in `POST /v1/playground/ask`, calling recall/get as tools. Each tool execution invokes the same internal pipeline the public handlers use — `verify_scope → (encode) → scope_for → storage.recall → revocation::enforce_restricted → spawn_audit` for search, `verify_scope → current_fact/fact_as_of → spawn_audit` for point reads — so every tool read is enforced, fail-closed, and audited identically to a normal agent read. Nothing in `recall`/`get` changes; nothing in the loop can widen a handle; Python appears nowhere (the loop is Rust in `playground.rs`, calling the Anthropic Messages API directly with the workspace `reqwest` + rustls).

This paragraph is reproduced (condensed) in the panel lede and in the module docs of `playground.rs`. It is not decoration; it is the answer to the first question every evaluator asks.

**Fail-closed corollary:** the agent's only source of facts is tool results returned through the chosen scope handle. There is no fallback scope, no admin bypass, no server-side default principal, and no "retry wider." A handle that can see nothing produces an agent that says so — and the UI enforces that structurally (§5), not by trusting the model's prose.

---

## 1. The judgment (why this shape)

Scored against (1) THE LAW (UI-ACTIONS §0), (2) the founder's ask, (3) honest measurement, (4) one-pass buildability with no migrations:

| Concept | THE LAW | Founder's ask | Honest numbers | One-pass build | Verdict |
|---|---|---|---|---|---|
| demo-first | ★★★ denial-as-hero; structural visibility stamping | ★★ (two lanes ≠ "pick a scope") | ★★ | ★★ (two-lane state machine, verdict strip) | **graft:** denial enforcement, status/error contract, disclosed system prompt |
| latency-workbench | ★★ (engineer-dense §4/§7) | ★★★ ("measure speed etc") | ★★★ span rules, cache disclosure, benchmark firewall | ★★ (bucket machinery) | **graft:** measurement rules, runs table, verify-before-spend |
| operator-first | ★★★ three moments, keyring teaching, plain trace | ★★★ | ★★ | ★★ (3 tools; embedded quick-mint forks the mint dialog) | **winner (skeleton)** |

**Synthesis:** operator-first's single-lane "Who is asking → Ask → What happened" skeleton; scope picking is **adopt, never mint** (the embedded quick-mint is cut — `Verity.openMint()` is the one mint ceremony and the playground subscribes to it instead); demo-first's server-stamped `visibility` field and denial hero; latency-workbench's measurement discipline, session runs table, and fail-before-spend ordering; sequential A/B via "recently asked as" chips replaces both the two-lane grid (too much UI) and the embedded picker (forked ceremony). Two tools, not one and not three: `search_memory` (recall) and `get_fact` (the bi-temporal L1 point read) — the second is cheap, teaches the L0/L1 split in the trace, and the trace stays legible.

---

## 2. Panel layout

```
┌ Playground ──────────────────────────────────────────────────────────────────┐
│ h1  Playground — ask the memory, through one key                             │
│ lede Pick a scope handle — the signed key an agent reads with — ask in       │
│      plain language, and a model answers using ONLY what that key can see.   │
│      Every number below is measured, never estimated. A zero here is         │
│      enforcement working, not a bug. Recall itself never calls a model —     │
│      the model sits above the read path, calling it as a tool.               │
│                                                                              │
│ ┌ 1 · WHO IS ASKING?  (a principal is a key; a person carries a keyring) ──┐ │
│ │ (•) This tab's working handle    [ok: live — expires in 42m]             │ │
│ │      reads as  Priya Shah #1001 · sales (shared key) #1002               │ │
│ │      limited to any entity · ceiling internal          [inspect →]       │ │
│ │ ( ) Paste a handle  [ vs_… ______________________________ ]              │ │
│ │ ( ) Mint a handle → (opens the one mint dialog; the fresh handle lands   │ │
│ │      here automatically)                                                 │ │
│ │                                                                          │ │
│ │ recently asked as:  [Priya + sales ×] [support only ×]                   │ │
│ │   this tab only — click to re-ask the same question as a different key.  │ │
│ │   That two-click swap IS the boundary demo.                              │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌ 2 · ASK ─────────────────────────────────────────────────────────────────┐ │
│ │ [ what's the renewal risk at Acme?                          ]  [Ask]     │ │
│ │ model [Haiku 4.5 — fast, cheap (default) ▾]  repeat [1 ▾ 3 5]            │ │
│ │ up to 8 tool turns · each ask starts fresh — nothing is remembered       │ │
│ │ between questions · repeats run one after another, never in parallel     │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌ 3 · WHAT CAME BACK (latest run) ─────────────────────────────────────────┐ │
│ │ [ok: answered from 6 memories visible to this key]                       │ │
│ │ Acme's renewal is at risk: their champion left in May [1] and support    │ │
│ │ ticket volume doubled in Q2 [2]. …                                       │ │
│ │ ──────────────────────────────────────────────────────────────           │ │
│ │ server total 2,412.7 ms · model 2,406.4 ms across 2 calls (incl. network │ │
│ │ to Anthropic) · memory reads 6.3 ms across 1 scoped read · 2,190 tokens  │ │
│ │ in / 285 out (from the API's usage block) · round-trip in this browser   │ │
│ │ 2,541 ms                                                                 │ │
│ │ every number measured this run — nothing estimated · session-local,      │ │
│ │ this hardware — NOT the milestone-A benchmark                            │ │
│ │                                                                          │ │
│ │ WHAT THE AGENT DID                                                       │ │
│ │  1  model read the question, decided to search   812.4 ms · 903/71 tok   │ │
│ │  2  searched memory for "acme renewal risk" (k=8)                        │ │
│ │        → 6 results came back through this key        6.3 ms storage      │ │
│ │        ▸ show the 6 results (content-first hit cards)                    │ │
│ │  3  model wrote the answer                       1,594.0 ms · 1,287/214  │ │
│ │  ▸ the agent's instructions (the fixed system prompt, verbatim)          │ │
│ │  the model is instructed to answer only from these results; this trace   │ │
│ │  is how you check it kept its word. [prove this boundary → Scope Insp.]  │ │
│ │                                                                          │ │
│ │ EVIDENCE — what this key let through (the agent saw nothing else)        │ │
│ │  [1] slack · "champion Dana G left for Initech…" · doc a91f… seq 2 ·     │ │
│ │      score 12.31   [sample data]                                         │ │
│ │  [2] zendesk · "ticket volume doubled…" · doc 77c0… seq 5 · score 11.02  │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌ 4 · THIS SESSION ────────────────────────────────────────────────────────┐ │
│ │ comparable runs (same key · question · model · k)              n = 5     │ │
│ │   memory reads   p50 6.1 ms    p95 8.9 ms   (per scoped read)            │ │
│ │   model call     p50 1,102 ms  p95 1,710 ms (per Anthropic round-trip)   │ │
│ │   whole answer   p50 2,390 ms  p95 2,801 ms (server total)               │ │
│ │ runs: # · model · turns · reads · hits · server ms · in/out tok · when   │ │
│ │ session-local · this hardware · model time includes Anthropic network ·  │ │
│ │ repeats sequential · dies with this tab · NOT the milestone-A benchmark  │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

Sections 3 and 4 do not render until there is a run. Every uuid/token renders `refSpan` mono-small behind a plain-language name (THE LAW #1). Every number carries a label and a provenance ("measured this run", "from the API's usage block", "elapsed in this browser").

---

## 3. Scope-picking UX (adopt, never mint)

The playground owns **no** mint form, no ceiling/TTL/entity/purpose controls, and no principal picker. Three ways to adopt a scope, in ceremony order:

1. **This tab's working handle** — default-selected when `Verity.workingHandle()` is non-empty; subscribes `Verity.onWorkingHandle` so it appears/disappears live. Claims render via `Verity.decodeHandle()` using `panel_scope.js` conventions exactly: `entityChip(name, "#token")` per principal (names via the admin principal-directory cache; a 401 degrades honestly to `token #1001 · name unknown`), `confBadge` ceiling, entity limit or "any entity", `fmtAge` expiry countdown. An expired working handle flips to `stateChip("fail","expired")` and the radio falls through to paste — never a silent ask with a dead key.
2. **Paste a handle** — decode-as-you-type, 250 ms debounce (the `panel_scope.js` pattern); malformed input shows the decoder's own human message inline. A handle whose `principals` array is empty gets `stateChip("attn","sees nothing — no keys on this handle")` in the claims strip *before* any ask; Ask stays **enabled** — the denial is the demo.
3. **Mint a handle →** — calls `Verity.openMint()` (the one global mint dialog, UI-ACTIONS N1). The panel subscribes once via `Verity.onMint(({handle}) => adopt(handle))`; a mint completed while this panel is open lands as the active scope automatically.

**Recently asked as** — up to three chips in `sessionStorage` (same lifetime discipline as the working handle: this tab only, gone on close, labeled as such). Each stores `{label, handle}` where label is the human claims summary at adopt time ("Priya + sales"). Click → that scope becomes active → press Ask again. Two clicks from grounded answer to honest denial: the A/B demo without a second lane.

The active scope is summarized in one line above the Ask box — *asking as **Priya Shah** + **sales** (shared key) · ceiling internal · any entity · expires in 14m* — never the raw `vs_…` string, never a uuid as primary text. `[inspect →]` jumps via `Verity.show("scope", { handle })`. Handles live in panel JS memory + the sessionStorage chips only; never localStorage, never disk, never logged.

---

## 4. The agentic loop (server, `playground.rs`)

### Order of operations (fail before spend)

1. Read env `VERITY_ANTHROPIC_KEY_FILE`; unset/unreadable → **503** (§6). The key is read from the file **per request** (rotation works without restart), trimmed, held in a newtype whose `Debug`/`Display` print `«redacted»`, used only to build the `x-api-key` header. Never logged, never in any response, never in panel JS.
2. `verify_scope(&req.scope_handle)` — an invalid/expired handle fails the whole ask **before any LLM call**: fail closed, and no tokens spent on a dead key (the 401 body says so).
3. Validate `model` against the allowlist, `question` (non-empty, ≤ 2,000 chars), clamp `max_turns` to 1..=8 (server default 8).
4. Loop: Anthropic Messages API via workspace `reqwest` (rustls) — `anthropic-version: 2023-06-01`, `max_tokens: 1024`, the system prompt below, the two tools below. Execute every `tool_use` block server-side against the pinned handle; append `tool_result`; repeat until `end_turn` or the turn cap.
5. Timeouts: 60 s per model call (reqwest timeout); 120 s whole-ask budget → **504** with all completed, measured turns attached. Measured work is never thrown away.

### Timing capture (the honesty contract)

- Every await gets exactly one `std::time::Instant::now()`/`elapsed()` pair, **on the server**: one span per model call (`llm_ms`), one per tool execution (`storage_ms`, which includes the local `encode()` dense leg — it is part of the read the public handler also performs), one around the whole handler (`wall_ms`). Raw `f64` ms, one decimal; never "~2s".
- Token counts are copied from each Anthropic response's `usage` block — input, output, and `cache_read_input_tokens` — never estimated by a tokenizer. Top-level totals are sums of per-turn blocks, each addend visible in `turns[]`, so the sum is checkable.
- The browser adds exactly one number of its own — `performance.now()` around the fetch — always rendered *beside* the server total and labeled "round-trip in this browser", so network overhead is visible instead of smeared into the product's numbers.
- A turn whose usage reports `cache_read_input_tokens > 0` gets a `cache read: N tok` chip in the trace — a repeat that got faster from provider-side prompt caching is disclosed, not pocketed as a speedup.
- Standing disclosure everywhere numbers appear: *"session-local · this hardware · model time includes Anthropic network — NOT the milestone-A benchmark."* No playground number is ever quotable as a product latency claim.
- **No dollar figures anywhere.** Cost = vendor-quoted price × tokens; vendor-quoted numbers are banned from surfaces. Tokens only.

### Tool executions = the public read path, internally

- `search_memory` runs the recall pipeline verbatim (same functions the `POST /v1/recall` handler calls): `verify_scope → encode(text) → scope_for → storage.recall → revocation::enforce_restricted → spawn_audit("recall", …)`. Tool `k` is clamped 1..=20; `text` required.
- `get_fact` runs the get pipeline verbatim: `verify_scope → current_fact / fact_as_of → spawn_audit("get", …)`. A missing key returns a normal `tool_result` saying "no value for that key/time" — not an error, and rendered as such in the trace.
- A `tool_use` block naming any other tool gets a `tool_result` error block (`"unknown tool"`) and is **never executed**.
- Every tool read writes the standard audit row through `spawn_audit`, carrying the handle's own mint-time actor identity — the playground's reads land in Access audit exactly as if an agent had called `/v1/recall` with this handle. That is a demo beat, not new code.

### The system prompt (fixed, server-side constant, disclosed verbatim in the response and the trace)

> You are an agent answering questions from an enterprise memory store. You are reading through a permission scope: whatever the tools return is everything you are allowed to see. Answer ONLY from tool results in this conversation — never use outside knowledge, never guess, never fill gaps. Always search before answering. If your searches return nothing, say plainly that nothing is visible to this scope and stop; an empty answer is a correct answer here. When you do answer, cite the memories supporting each claim by their bracketed evidence number. Be concise.

Honesty about the limit of instruction: the prompt forbids parametric answers; the **trace is how you verify compliance**, and the `visibility` stamp (§5) makes the denial case model-proof. We instruct; the trace proves; the server enforces.

### Tool definitions (sent to the model)

```json
[
  { "name": "search_memory",
    "description": "Search this company's shared memory THROUGH the caller's permission scope. Returns only memories this scope is allowed to see, each with a bracketed evidence number. An empty result means nothing is visible — that is a true answer, not an error.",
    "input_schema": { "type": "object",
      "properties": {
        "text": { "type": "string", "description": "what to search for" },
        "k":    { "type": "integer", "minimum": 1, "maximum": 20, "description": "max results (default 8)" } },
      "required": ["text"] } },
  { "name": "get_fact",
    "description": "Point-read one structured fact by exact key (source, entity_id, field), as visible to your scope — e.g. the current DUNS number on record. Optionally as of a past moment (RFC3339). Use search_memory first to discover keys; use this to pin an exact current or historical value.",
    "input_schema": { "type": "object",
      "properties": {
        "source":    { "type": "string" },
        "entity_id": { "type": "string" },
        "field":     { "type": "string" },
        "as_of":     { "type": "string", "description": "optional RFC3339 timestamp; absent = current value" } },
      "required": ["source", "entity_id", "field"] } }
]
```

`tool_result` content for `search_memory` is a JSON array of hits, each prefixed with its assigned evidence number `n` (stable across the whole ask — the dedup table lives in the loop). For `get_fact`, the `FactRow` JSON or the plain not-found sentence.

---

## 5. Visibility stamping — denial is enforced, not requested

The server tracks, across the whole ask:
- `storage_calls` — number of tool executions,
- `visible_hits_total` — sum of `search_memory` hit counts plus `get_fact` hits (found = 1).

It stamps the response with exactly one of:

| `visibility` | condition | UI treatment |
|---|---|---|
| `"grounded"` | ≥ 1 tool call and `visible_hits_total ≥ 1` | `stateChip("ok", "answered from N memories visible to this key")` |
| `"nothing_visible"` | ≥ 1 tool call and `visible_hits_total == 0` | **the denial hero** (§7C) renders *regardless of the model's prose*; the model's text renders beneath it, quoted and dimmed, as "the model's own words" |
| `"no_reads"` | zero tool calls | `stateChip("attn", "answered without reading")` + warning (§7F) |

A hallucinating model cannot fake an answer past the UI, and a lazy model cannot pass off parametric knowledge as memory. The counts shown in the denial copy are the measured totals, never canned.

---

## 6. API contract

### `GET /v1/playground/status`

Always **200** — absence of a key is a state, not an error. The panel calls this on show; the model picker is populated from `models` (the UI never invents model ids).

```json
{ "ready": true,
  "models": [
    { "id": "claude-haiku-4-5-20251001", "label": "Haiku 4.5 — fast, cheap",     "default": true  },
    { "id": "claude-sonnet-4-6",          "label": "Sonnet 4.6 — smarter, slower", "default": false } ],
  "max_turns": 8 }
```

```json
{ "ready": false,
  "reason": "VERITY_ANTHROPIC_KEY_FILE is not set",
  "env_var": "VERITY_ANTHROPIC_KEY_FILE" }
```

`reason` (string) is one of: `"VERITY_ANTHROPIC_KEY_FILE is not set"` / `"key file not found"` / `"key file unreadable"`. The filesystem path never appears in any response. The status check confirms existence/readability only; the file contents are read solely at ask time to build the `x-api-key` header.

### `POST /v1/playground/ask`

Auth: `scope_handle` in the body **is** the read authorization, exactly like `/v1/recall`. No admin bypass, no default scope. Stateless.

Request:

| field | type | rules |
|---|---|---|
| `scope_handle` | string | required; verified before any model call |
| `question` | string | required; non-empty; ≤ 2,000 chars → 422 |
| `model` | string | optional; default `claude-haiku-4-5-20251001`; allowlist `["claude-haiku-4-5-20251001","claude-sonnet-4-6"]` → 422 naming both allowed ids |
| `max_turns` | integer | optional; server clamps to 1..=8 |

Response **200**:

```json
{
  "answer": "Acme's renewal is at risk: their champion left in May [1] and support ticket volume doubled in Q2 [2].",
  "visibility": "grounded",
  "stop": "end_turn",
  "model": "claude-haiku-4-5-20251001",
  "system_prompt": "You are an agent answering questions from an enterprise memory store. …",
  "evidence": [
    { "n": 1,
      "chunk_id": 4711, "document_id": "a91f2c…", "seq": 2,
      "content": "champion Dana G left for Initech…", "score": 12.31,
      "kind": "content", "entity_tags": ["account:acme"],
      "trust_tier": "authoritative", "acl_provenance": "mirrored",
      "valid_from": "2026-05-14T09:12:00Z", "provenance": 88123 }
  ],
  "turns": [
    { "n": 1, "llm_ms": 812.4, "stop_reason": "tool_use", "text": "",
      "usage": { "input_tokens": 903, "output_tokens": 71, "cache_read_input_tokens": 0 },
      "tool_calls": [
        { "tool": "search_memory",
          "input": { "text": "acme renewal risk", "k": 8 },
          "storage_ms": 6.3, "hits": 6, "evidence_ns": [1, 2, 3, 4, 5, 6],
          "fact": null, "error": null } ] },
    { "n": 2, "llm_ms": 1594.0, "stop_reason": "end_turn",
      "text": "Acme's renewal is at risk: …",
      "usage": { "input_tokens": 1287, "output_tokens": 214, "cache_read_input_tokens": 0 },
      "tool_calls": [] }
  ],
  "totals": {
    "wall_ms": 2412.7,
    "llm_ms": 2406.4,  "llm_calls": 2,
    "storage_ms": 6.3, "storage_calls": 1,
    "visible_hits_total": 6,
    "input_tokens": 2190, "output_tokens": 285, "cache_read_input_tokens": 0
  }
}
```

Field types, exhaustively:

- `answer` string — the final assistant text (may be empty if the model produced none; the UI never invents one).
- `visibility` string enum — `"grounded" | "nothing_visible" | "no_reads"` (§5). Server-computed from measured hit counts; the UI trusts this field, not the prose.
- `stop` string enum — `"end_turn" | "turn_cap"`.
- `model` string — the model actually used.
- `system_prompt` string — the fixed prompt, disclosed verbatim; renders in the trace fold.
- `evidence[]` — deduped union of every `search_memory` hit across all tool calls, numbered in first-seen order; each entry is the exact `RecallHit` serialization the model received (same wire shape as `POST /v1/recall`) plus `n` (integer ≥ 1). "Show what the model saw" is the wire truth, not a retelling.
- `turns[]` — one entry per model call, wall order: `n` int; `llm_ms` f64 (measured server-side around the Anthropic round-trip, includes network); `stop_reason` string (Anthropic's, verbatim); `text` string (the turn's prose, may be `""`); `usage` object of three integers copied from the API response; `tool_calls[]` with `tool` string, `input` object (the model's input, verbatim), `storage_ms` f64, `hits` int, `evidence_ns` int[] (empty for `get_fact`), `fact` FactRow|null (`get_fact` only), `error` string|null (`"unknown tool"`, or the not-found sentence).
- `totals` — `wall_ms` f64 (whole handler); `llm_ms` f64 + `llm_calls` int; `storage_ms` f64 + `storage_calls` int; `visible_hits_total` int; three token integers, each the checkable sum of the per-turn `usage` blocks.

### Errors (plain-language bodies, surfaced verbatim by the panel via `Verity.err`)

| status | body | notes |
|---|---|---|
| **503** | `{ "error": "playground_unavailable", "detail": "This server has no Anthropic key configured. Set VERITY_ANTHROPIC_KEY_FILE to the path of a file containing an API key (e.g. ~/.verity-anthropic-key, chmod 600), then restart. The key is read server-side only and never logged. Recall itself needs no key — this gates only the model on top." }` | env unset / file missing / unreadable |
| **401** | `{ "error": "scope_refused", "detail": "<verify_scope's own refusal, verbatim> — the model was never called; no tokens were spent." }` | fail closed, before any spend |
| **422** | `{ "error": "bad_request", "detail": "unknown model \"…\" — allowed: claude-haiku-4-5-20251001, claude-sonnet-4-6" }` (or empty/oversize question) | |
| **502** | `{ "error": "model_call_failed", "detail": "Anthropic API returned HTTP 529 (overloaded) on turn 2. Verity's read path was unaffected.", "partial": { "turns": […], "totals": {…} } }` | provider body truncated to 300 chars; the key never appears in any error path |
| **504** | `{ "error": "ask_timed_out", "detail": "the 120 s ask budget elapsed on turn 5; every completed turn below is measured", "partial": { … } }` | measured work is never discarded |

The **deny outcome is not an error**: a scope that sees nothing returns **200** with `visibility: "nothing_visible"`. Denial is the product working.

---

## 7. All states, exact copy

**A · No tenant** — standard no-tenant teach (panel_memories wording): *"No space selected yet — pick a space in the bar above; this screen loads itself the moment one is set."*

**B · No key** (`status.ready === false`) — teaching empty state replaces sections 2–4; section 1 still works for handle inspection:
> **The playground needs a model key on the server**
> This screen drives a real agent, so the server needs an Anthropic API key. Set **`VERITY_ANTHROPIC_KEY_FILE`** to the path of a file containing the key (for example `~/.verity-anthropic-key`, permissions `0600`) and restart the server. The key stays server-side — it never reaches this browser, the logs, or the audit trail. Everything else here works now; **recall itself is LLM-free** — the key gates only the model on top. Meanwhile: probe this scope directly in **Scope Inspector →**.
> *(the `reason` string from status renders beneath, dim mono)* `[Retry]`

**C · THE DENIAL (the hero)** — whenever `visibility === "nothing_visible"`; counts are the measured totals, never canned; forensic CTAs only, never a widen button:
> `stateChip("attn", "nothing visible to this key")` **Nothing visible to this key — and that's the demo.**
> The agent searched **3 times** through this handle and got **0 results**. It answered from nothing because it *has* nothing: Verity's read path filters by permission **before** ranking, and it fails closed — no key, no memory, no exceptions, and no way for a clever question to widen a scope. The data may well exist; these keys cannot see it.
> *the model's own words:* "I found no memories visible to this scope about Acme's renewal." *(dim, quoted)*
> measured all the same: `model 2.1 s · memory reads 3.4 ms · 3 turns · 1,204 tok in / 41 out`
> **[Prove why, item by item → Scope Inspector]** *(via `Verity.show("scope",{handle})`)* · **[Ask as a different key]** *(focuses the recently-asked-as chips)*
> If a write you expected is invisible to *every* key, it may never have been indexed — check **Quarantine →**.

**D · No handle yet** (Ask pressed, or on first paint with no working handle):
> **Pick who is asking first.** The agent reads with a scope handle — the signed key an agent reads with — and there is no default. An unscoped ask does not exist; Verity fails closed. **[Mint a handle →]** or paste one above (`verity-cli dev` prints one at bootstrap).

**E · Handle expired mid-session** — claims strip flips to `stateChip("fail","expired")`, Ask disables:
> This handle expired — the server will refuse it, and refuses it *before* spending any tokens. Handles expire on purpose; re-mint from the top bar — renewal never widens anything. Runs already in the session table keep their numbers.

**F · Answered without reading** (`visibility === "no_reads"`):
> `stateChip("attn","answered without reading")` The model never called a tool, so nothing below is grounded in this scope's memory. Treat it as the model's own invention, or ask again.

**G · Turn cap hit** (`stop === "turn_cap"`) — amber line above the answer:
> Stopped at the **8-turn cap**. The answer may be incomplete — the trace shows everything it did get to, measured.

**H · Model call failed** (502/504) — `stateChip("fail","the model call failed — memory was fine")`:
> Anthropic API: HTTP 529 (overloaded) on turn 2. The memory reads before the failure are shown below with their measured timings, labeled *partial*. Verity's read path was not involved; your handle is still good — ask again.

**I · In flight** — Ask disables; `stateChip("wait", "asking — model turns can take seconds")` plus a ticking counter labeled **"elapsed in this browser"** (the only number on screen not server-measured, and it says so). No fake progress bars. Not streamed in v1: the trace arrives whole (§9).

**Answer-state chips (labels):** `answered from N memories visible to this key` / `nothing visible to this key` / `answered without reading`. **Timing labels:** `server total` · `model … across N calls (incl. network to Anthropic)` · `memory reads … across N scoped reads` · `N tokens in / N out (from the API's usage block)` · `round-trip in this browser`. **Section headers:** `Who is asking?` · `Ask` · `What came back` · `What the agent did` · `Evidence — what this key let through (the agent saw nothing else)` · `This session`.

---

## 8. Trace, evidence, and session table (frontend rules)

- **Trace:** one plain-language line per step in wall order. Model steps: *"model read the question, decided to search · 812.4 ms · 903 in / 71 out tok"* (fold: the turn's text + stop_reason; `cache read: N tok` chip when nonzero). Tool steps: *"searched memory for "…" (k=8) → 6 results came back through this key · 6.3 ms storage"* (fold: hit cards reusing panel_scope conventions — content first, chips second, ids mono-small via `refSpan`, `sampleBadge` on verity-sample sources, rank + raw score, never a fake percent). A zero-hit step renders `→ 0 results — nothing visible to this key for that search` in the attention color: in a denied run the trace is a column of amber zeros, which *is* the visual story. First fold: the disclosed system prompt. Footnote on storage ms: *"the same in-process read the public POST /v1/recall performs, measured without HTTP framing."*
- **Evidence list:** the response's `evidence[]`, numbered to match the model's `[n]` citations.
- **Split attribution line** under the strip, computed from the same measured spans: *"model 99.7% of the time · permission-filtered reads 0.3%"* — the sales point (the boundary is not the slow part) is computed, not asserted.
- **Repeat ×N** (1/3/5): sequential re-POSTs of the identical request, fresh conversation each — disclosed as sequential so nobody mistakes it for a load test. **Session table** (panel JS memory only; dies with the tab and says so): comparable runs = same `(handle claims payload, question, model)`; changing any starts a new bucket rather than contaminating the old. p50/p95 rows (nearest-rank, the panel_scope algorithm) render only at n ≥ 5; below that, the raw list — a p95 of two samples is a small lie.

---

## 9. Explicitly OUT of scope for v1

1. **Streaming/SSE** — one honest whole response beats a fancy partial one, and it keeps timing spans unambiguous. The wait chip + labeled browser ticker carry the suspense. Revisit if asks routinely exceed ~15 s.
2. **Multi-turn chat / conversation memory** — every ask is a fresh, stateless conversation; comparability dies the moment context accumulates.
3. **Two parallel lanes / side-by-side diff** — the recently-asked-as chips make the A/B demo two clicks; a true diff view belongs with Scope Inspector's comparison work.
4. **More tools** (entity briefs, activity, write verbs) — two read tools keep the trace legible. **Write tools are a separate gate, never smuggled in**: the playground reads only.
5. **Dollar-cost display** — price × tokens uses vendor-quoted numbers, which are banned. Tokens only.
6. **Prompt/temperature/max_tokens knobs, custom system prompts** — knobs make runs incomparable; the disclosed fixed prompt is part of the honesty.
7. **Persisted or shareable run history** — stateless by mandate; the session table dies with the tab and says so. Scope Inspector's evidence export remains the proof artifact.
8. **Benchmark aggregation** — no playground number ever feeds docs or latency claims; the milestone-A bench remains the only citable number.
9. **Concurrency/load testing** — repeats are sequential and disclosed as such.
10. **Other providers / arbitrary model ids** — the two-entry allowlist is the whole surface.
11. **Key management UI** — the env-var/file contract is the whole surface; the console never displays, tests, or edits the key.
12. **A playground-specific audit verb** — the underlying reads carry recall/get's existing audit rows; whether an *ask* is itself auditable is a follow-on design question.
13. **Any Python** — the loop is Rust in `playground.rs`, full stop.

---

## 10. Files & wiring (build checklist)

**Backend (Rust):**

| file | change |
|---|---|
| `crates/verity-server/src/playground.rs` | **new** — redacted-key newtype + file loading, Messages-API client (workspace reqwest/rustls), two tool executors calling the same internal pipeline as the public handlers, the agentic loop with `Instant` spans, visibility stamping, `status` + `ask` handlers |
| `crates/verity-server/src/main.rs` | `mod playground;` + `.route("/v1/playground/status", get(playground::status))` + `.route("/v1/playground/ask", post(playground::ask))` |

**Frontend (UI fragments + wiring):**

| file | change |
|---|---|
| `crates/verity-server/src/ui/panel_playground.html` | **new** body fragment — `<section class="panel" id="panel-playground">` with h1 + lede + mount div; no doctype/head/body |
| `crates/verity-server/src/ui/panel_playground.js` | **new** — `Verity.register({id:"playground",…})`; adopt-handle flow (workingHandle/paste/onMint), recently-asked-as chips, ask/repeat, visibility-stamped rendering, trace + evidence + session table. Reuses `Verity.api/esc/decodeHandle/fmtMs/fmtAge/stateChip/entityChip/refSpan/confBadge/sampleBadge/openMint/onMint/workingHandle/onWorkingHandle/tenant/onTenant/show/err` — no forked patterns |
| `crates/verity-server/src/ui/mod.rs` | two `include_str!` lines (one in `PANEL_SECTIONS` after `panel_scope.html` to match rail order, one in `UI_SCRIPTS`) + `"panel-playground"` added to the id array in `panels_are_spliced_inside_the_content_pane` — the splice pin must keep passing |
| `crates/verity-server/src/ui/shell.html` | one rail entry in **Prove & inspect**, after Scope Inspector: `<div class="navitem" data-nav="playground">Playground</div>` |

**Gates:** `cargo fmt` + `cargo clippy -D warnings` clean; Rust 2021; no new dependencies; no migrations; no Python; the splice test passes with the new id; the key string appears in zero log lines, zero responses, zero JS.
