# Cross-Source Entity Resolution — Design (SPEC §7f, extended)

**Status:** proposal. **Milestone:** A ("the engine is honest"). **Owner:** memory-plane.
**Amends:** SPEC §7f and §7d (see §3 and §8 — turning on the probabilistic tiers is a *public* spec amendment, per CLAUDE.md "where implementation reality contradicts the spec, the spec gets amended publicly, not silently ignored").

This document specifies how Verity links per-source L1 entities (the Acme account in Salesforce *and* HubSpot, a Linear ticket "about Acme", a Drive doc mentioning "Acme") into one **canonical entity**, and how the resulting canonical ids and chunk **entity tags** reach the read path. The guiding model: **resolution decisions are evidence, not edits.** A canonical entity is not a row an operator edits; it is a *cluster that a pure deterministic function folds out of an append-only, provenance-tagged evidence ledger.* Because a canonical is a fold, an unmerge is just retracting an edge and re-folding — reversibility is structural, not bolted on.

---

## 1. Problem, and why the three-source case is hard

An enterprise agent's context for "Acme" is scattered across systems that expose *radically different identity material*. Verity ingests three source shapes today (grounded in the real connectors: `ingest/verity_ingest/connectors/{salesforce,hubspot,gdrive}.py`, `registry/manifests/linear.yaml`, `ingest/verity_ingest/connector.py`):

| Source shape | Identity material in the record | The hard part |
|---|---|---|
| **CRM** (Salesforce, HubSpot) — structured, id-rich | Native PK (`001…`/`hs_object_id`), intra-source FKs (`Contact.AccountId`), **email**, **domain** (HubSpot `domain`; SF only `Website`, a URL), name | Two CRMs share **no** id. Company-level cross-CRM linking degrades to domain (SF domain must be *parsed* out of `Website`) or fuzzy name ("Acme, Inc." vs "Acme"). Domain is not identity (free-mail, subsidiaries, conglomerates). Each field supersedes independently (`(source, entity_id, field)` bi-temporal upserts), so the *matching key itself is bi-temporal*. |
| **Ticketing** (Linear) — structured facts + free-text bodies, **id-poor** | Issue UUID, `identifier` ("ENG-42"), `team.key`, `organizationId`, **actor email** in the raw payload (`jane@acme.dev`) | `organizationId` is a **false friend** — it is *your own workspace*, a tenancy boundary, not a customer entity; keying on it collapses all tickets into one node. The customer lives **only in prose** (comment body). Actor email is an **internal employee**, so joining it to a CRM *customer* contact by email is almost always the wrong population. |
| **Unstructured docs** (Google Drive) — content bytes, **id-less** | Drive `fileId` (the file, not a business entity), ACL principals (`user:`/`group:`/`domain:` emails), and `entity_tags` that **ships empty from the connector** | **No business entity id at all.** Detection must precede linking: an NER/gazetteer pass over free text produces candidate spans, then disambiguation ("which Acme?") with no key to anchor on. ACL emails/domains are *who can see it*, only associatively "what it is about". Quarantined docs (`resolvable=False` ACL) never index, so resolution coverage over docs is bounded by ACL mirrorability, not content. |

**The through-line.** The only STRONG cross-source keys in the codebase are **exact email** (person identity) and **intra-CRM FKs** (`Contact.AccountId`). Company-level cross-source linking is already MEDIUM (domain). The moment either side is ticketing-customer-context or a document, the join collapses to *detect-a-name-or-domain-in-free-text-then-disambiguate* — the highest-false-positive cell in the matrix. And **a false positive here is not a data-quality nit — it is a scope leak** (§3.2). That asymmetry governs every threshold in this design.

---

## 2. What §7f ships today, and how this extends (not rewrites) it

### 2.1 Shipped today (verified against code)

Migration `migrations/0020_entity_resolution.sql` defines two tenant-scoped, admin-driven config tables:

- **`entity_aliases`** — `(tenant_id, source, entity_id) → canonical_entity`. PK `(tenant_id, source, entity_id)` (one canonical per source entity); index `entity_aliases_canonical_idx` on `(tenant_id, canonical_entity)` for forward member lookup. A source entity with **no** alias row is implicitly its own canonical ("annoying, never wrong").
- **`entity_precedence`** — `(tenant_id, canonical_entity, field) → source_order[]`, with `'*'` wildcards for entity-default and global-default.

The whole merge is `PostgresAdapter::merged_record` (`crates/verity-storage/src/postgres.rs:416`), served through `GET /v1/entities/{canonical}` (`crates/verity-server/src/main.rs:676`): resolve members (`list_entity_aliases`, postgres.rs:354) → gather only current facts (`valid_to IS NULL`, joined on UNNEST-zipped `(source, entity_id)` arrays so source A/entity X never picks up source B/entity X) → load precedence (`load_precedence`, postgres.rs:517) → resolve each field most-specific-wins with a fully deterministic total order (precedence rank → `valid_from` → source → entity_id). Winner + `superseded_alternatives`, every field self-describing its winning source and provenance. **Zero LLM, zero live ReBAC — a pure L1 read.** Admin writes go through `admin_entity_aliases` (main.rs:609, idempotent `upsert_entity_alias` at postgres.rs:302) and `admin_entity_precedence` (main.rs:648), both admin-token gated. `get_merged_entity` is scope-handle gated exactly like `get_record` (fails closed 401 on a bad handle).

**Three things §7f does NOT do today** (the gaps this design closes):

1. The **"shared strong keys"** tier that §7f line 730 *names* ("domain for accounts, verified email for contacts, explicit foreign-key fields") is **unimplemented** — the migration header calls `entity_aliases` "the table the resolver writes," but the only writer is an admin POST.
2. The **candidate-review surface** §7f promises ("unresolved candidates surface in the admin UI for manual linking") has **no queue, no candidate table, no endpoint**.
3. **Unstructured mentions are not handled at all.** Chunk `entity_tags` are bound **verbatim** as supplied by the ingestion caller (`postgres.rs:987`, `.bind(&c.entity_tags)`) and are never rewritten by the resolver. There is **no code path from `entity_aliases` to `entity_tags`** — an alias `hubspot/hs-1 → account:acme` does not re-tag chunks tagged `hubspot:hs-1`. The reverse-lookup helper `resolve_canonical` (postgres.rs:382) that *could* drive such materialization has **zero non-test callers**.

### 2.2 How this extends it

This design sits **upstream** of the shipped resolver. `merged_record`, `entity_aliases`, `entity_precedence`, and the `entity_tags` `<@`/`term_set` read-time pre-filter are **unchanged**. We add a new *producer* of the rows the read path already consumes:

```
              old world:  admin POST ──────────────────────────► entity_aliases ──► merged_record (§7f)
              new world:  admin POST ─┐
                          strong keys ├─► entity_evidence (ledger) ─► FOLD ─► entity_aliases ──► merged_record (§7f, UNCHANGED)
                          fuzzy+human ─┤       (append-only)          (pure     + entity_link_badge
                          text mentions┘                              det.)      + chunk entity_tags (materialized)
```

The **shape consumed by `merged_record` is identical**, so the read path and the precedence engine never learn anything changed. The gaps close directly: strong-key producers fill §7f's unbuilt tier; a materialized view over the ledger *is* the review queue; and the fold is finally a production caller for `resolve_canonical`, closing the documented alias→tag gap.

**The OSS default stays deterministic.** "Nothing probabilistic in the OSS default" (§7f) remains literally true: the default fold uses **Tier-1 (exact keys) only**. Tier-2 (fuzzy → human) and Tier-3 (text mentions) are **opt-in, per-tenant, kill-switchable**, and turning them on is a **public §7f/§7d amendment** (§8).

---

## 3. Non-negotiables the design obeys

### 3.1 Deterministic, LLM-free read path

Zero LLM inference and zero live ReBAC calls on `recall`/`get`/`GET /v1/entities/{canonical}` (CLAUDE.md "Read path purity"; §7b). **All** similarity/embedding/NER/LLM work runs in the **ingestion or async worker plane only** — "Rust for the serving core, Python for ingestion only… Python never appears on the read path." Resolution output is **materialized** into the serving index exactly as ACLs and knowledge-merge results are: the read path *reads* precomputed canonical ids and entity tags; it never *computes* a match. **Testable fence invariant:** the fold (Stage S4) is the *sole writer* of the two rows the read path consumes for resolution — `entity_aliases` and chunk `entity_tags` — so the read path cannot tell an admin-typed alias from a worker-folded one, and cannot be tricked into computing one. Structured L1 is never LLM-extracted and L1 rows are never merged or mutated; resolution is a view-time/index-tag projection, never an L1 rewrite (§2 L1, §7f).

### 3.2 Precision-as-security: a false merge is a scope leak

Entity tags are the **mandatory Plane-3 `entity_scope` pre-filter** (§7c/§7d). If customer A's entity is falsely merged with customer B's, their scopes **union** and A's data becomes retrievable in a B-bound session — the exact customer-A/customer-B leak §7c exists to prevent. Therefore, as a **security invariant, not a data-quality preference: precision dominates recall.** The governing asymmetry, stated once and applied everywhere: **under-merge = two separate briefs = annoying but never wrong; over-merge = a leak.** This is the identical asymmetry the knowledge-merge cascade holds to (`docs/design/knowledge-merge-tuning.md` §1). The operating point transfers: **target precision ≥ 0.99, false-merge-rate ≤ target, published with a CI regression gate**, holding the cascade's measured bar (precision 1.000 / FMR 0.000 across 112 negatives at the shipped opus-4-8 judge, `docs/benchmark/RESULTS-anthropic-judge-2026-07-10.md`; cosine-only baseline was precision 1.000 / recall ~0.11 at the ≥99%-precision frontier, `RESULTS-2026-07-11.md`). Honesty framing: **"engineered precision with auditable gates + a human backstop," never "cannot mis-merge."**

### 3.3 Provenance + reversibility

Every canonical link records its **method/confidence** (deterministic strong-key / probabilistic-approximated / admin-crosswalk / human-confirmed) and retains **lineage back to L0** (§2 lineage-day-one). Reversibility is total: **invalidate-don't-delete** — a superseded link gets `valid_to`/`superseded_by`, never UPDATE-in-place or DELETE (§2 L1). Re-linking or splitting rebuilds derived views without data loss (§7f "changing the config just rebuilds L3"). Hard deletion happens **only** via the §8 crypto-shred / lineage hard-purge pipeline, where entity resolution is itself a *step* (§8b: "resolve S → canonical principal + entity links"), never as a resolution operation. Conflicts with no precedence rule are rendered **side-by-side with provenance** (§7f "conflict made visible beats conflict resolved wrong"). Derived-view scope is the **intersection** of constituents' scopes (§2, §7c).

### 3.4 Fail-closed on ambiguity

Ambiguity resolves to the safe side, always (CLAUDE.md; §7b). Unresolved/ambiguous candidates → **stay separate**, surfaced for manual linking. Low-confidence inferred tag → **quarantine for review**, never index permissively (§7d(a)). Resolver/LLM unavailable or uncertain → **no merge**, degrade to separate entities. Multi-entity chunks are **deny-by-default intersection** (retrievable only in a scope covering *all* tags); zero-tag content is retrievable only in explicitly-broad scopes, so a resolver failing to tag must **never** dump content into the zero-tag broad bucket.

---

## 4. The design

### 4.1 Data model (migration `0022_entity_evidence.sql`, append-only, tenant-scoped)

> Numbered after the current head (`0021_backfill_runs.sql`).

**`entity_evidence` — the ledger. Append-only. Source of truth; everything else is derived.**

| column | type | notes |
|---|---|---|
| `evidence_id` | uuid PK | |
| `tenant_id` | uuid FK → tenants | |
| `left_ref` | text | canonicalized ref, e.g. `salesforce:001xACME` |
| `right_ref` | text | e.g. `hubspot:4207` — the two refs this evidence links |
| `tier` | smallint | 1 = deterministic strong key, 2 = strong-but-fuzzy, 3 = unstructured mention |
| `method` | text | `admin_crosswalk` / `crm_fk` / `email_exact` / `domain_match` / `external_id` / `name+domain_fuzzy` / `llm_mention` / `human_confirmed` / `human_rejected` |
| `key_value` | text | the actual matched value (`jane@acme.dev`, `acme.com`) — load-bearing for denylist + audit |
| `key_namespace` | text | **e.g. `customer_contact` vs `internal_directory`** — the actor-email-population fence (§4.4) |
| `score` | real NULL | null for Tier-1; blocker/judge score for 2/3 |
| `evidence_l0_ref` | text | lineage pointer to the L0 record/chunk that produced it |
| `polarity` | smallint | +1 = link, −1 = **anti-link** (a human "these are NOT the same" / must-not-link) |
| `valid_from` | timestamptz | |
| `valid_to` | timestamptz NULL | **invalidate-don't-delete**: retraction stamps `valid_to`, never DELETE |
| `superseded_by` | uuid NULL | bi-temporal chain (§2 L1) |

Indexes: `(tenant_id, left_ref)`, `(tenant_id, right_ref)` for fold traversal; `(tenant_id, tier, valid_to)` for the review-queue view. A row is *live* iff `valid_to IS NULL`; the fold reads only live rows.

**`entity_resolution_config` — key-quality allowlist + denylist + merge guards** (the over-merge control; a *security* control, mandatory even in MVP). Tenant-scoped, admin-driven, versioned.

| column | type | notes |
|---|---|---|
| `tenant_id` | uuid | |
| `key_kind` | text | `email` / `domain` / `phone` / `external_id` |
| `key_namespace` | text | e.g. `customer_contact`, `internal_directory` — an edge may only form *within* a namespace |
| `eligible_as_edge` | bool | may this key kind ever *form* a merge edge |
| `denylist_values` | text[] | free-mail (`gmail.com`), role locals (`info@`,`sales@`), placeholders (`example.com`) — **never** an edge |
| `min_independent_keys` | smallint | **default 2; per-kind exception `external_id` = 1** — a single MEDIUM key (e.g. shared domain) may not auto-merge alone (grafted from P0); measured, see §10 Q2 |
| `auto_merge_tier1` | bool | OSS default true |
| `auto_link_tier3` | bool | **default FALSE** — the Tier-3 auto-link kill switch (`VERITY_ENTITY_AUTO_LINK=0` analog) |
| `tau_nil` | real | Tier-3 NIL threshold (§5) — **default 0.70**, measured, see §10 Q6 |
| `margin_delta` | real | Tier-3 top1−top2 abstain margin (§5) — **default 0.15**, measured, see §10 Q6 |
| `component_size_cap` | int | union-find components exceeding this are **quarantined, not merged** |

**`entity_link_meta` — materialized fold output the read path is allowed to see.** One row per live canonical link, *and* per materialized chunk tag (folds P2's confidence badge and P1's per-tag provenance sidecar into one surface, so "which evidence added which tag/link" is explicit for the scope inspector and for surgical audit).

| column | type | notes |
|---|---|---|
| `tenant_id` | uuid | |
| `subject_kind` | text | `alias_member` (a `(source,entity_id)`) or `chunk_tag` (a `(chunk_id, tag)`) |
| `subject_ref` | text | the member ref or `chunk_id` |
| `canonical_entity` / `tag` | text | the link target |
| `confidence` | text | `deterministic` / `human_confirmed` / `approximated` |
| `strongest_method` | text | highest-tier method that justified it |
| `justifying_evidence` | uuid[] | the live `entity_evidence` rows that produced it — enables surgical per-tag removal on split |
| `evidence_count` | smallint | corroboration depth |

`entity_aliases` and `entity_precedence` (from `0020`) are **unchanged**. The fold writes `entity_aliases` (idempotent `upsert_entity_alias`, postgres.rs:302), chunk `entity_tags`, and `entity_link_meta`.

### 4.2 The offline resolution pipeline, stage by stage

```
   ─────────── INGESTION / WORKER PLANE  (similarity + LLM + NER ALLOWED, off every hot path) ───────────
   connectors ─► S0 canonicalize refs & keys  (DETERMINISTIC)
                     │
                     ├─► S1 Tier-1 exact-key producer            (DETERMINISTIC, no LLM)      ─┐
                     ├─► S2 Tier-2 blocker + LLM judge  (SIMILARITY blocker + LLM; → HUMAN)    ├─► entity_evidence
                     └─► S3 Tier-3 mention EL           (NER/LLM; NIL/abstain; non-authoritative)┘   (ledger)
                                                                                                     │
                                                                        S4 FOLD (PURE DETERMINISTIC) ◄┘
                                                              reads live evidence + config; union-find + anti-links
                                                                                                     │
       writes ───────────────────────────────────────────────────────────────────────────────────────┤
                                                                                                     ▼
                 entity_aliases  +  chunk entity_tags  +  entity_link_meta   (materialized)
   ══════════════════════════════════════════════════════════════════════════════════════════════════
   ─────────────────────── READ PLANE (Rust serving core; ZERO LLM, ZERO live ReBAC) ───────────────────
   recall / get / GET /v1/entities/{canonical}  ─► merged_record (§7f, UNCHANGED) reads entity_aliases;
                                                   scope filter reads materialized entity_tags (`<@`/term_set);
                                                   response carries the entity_link_meta confidence badge.
```

| Stage | Plane | Nature | Auto-merge power |
|---|---|---|---|
| **S0** canonicalize refs & keys | ingestion | **deterministic** | — |
| **S1** Tier-1 exact keys | ingestion | **deterministic, no LLM** | **auto-merge-eligible** |
| **S2** Tier-2 blocker + judge | async worker | **similarity** blocker (recall-only) + **LLM judge** | forms an edge **only after `human_confirmed`** |
| **S3** Tier-3 mention EL | async worker | **NER/LLM** | **never forms an edge** (corroboration / reviewer-hint only) |
| **S4** the fold | worker | **pure deterministic** (no LLM, no similarity) | applies the above; anti-links + caps |

**S0 — Canonicalize refs & keys (deterministic).** Normalize every ref to `source:entity_id`. Normalize keys: email lowercase + strip `+tag`; domain → registrable eTLD+1 via the Public Suffix List, strip `www`; SF `Account.Website` URL → parsed domain (SF exposes no clean domain field); phone → E.164; name → NFKC + case-fold + strip legal suffixes. **Apply the denylist immediately** — a `gmail.com` domain or `info@` local never becomes a key. **Stamp `key_namespace`** (an actor email from Linear → `internal_directory`; a CRM contact email → `customer_contact`).

**S1 — Tier-1 exact-key producer (deterministic, no LLM).** For each surviving strong key emit `tier=1` evidence: intra-CRM FK (`Contact.AccountId`, exact), exact email person↔person *within a namespace*, exact `external_id` crosswalk, admin crosswalk POSTs. This is the OSS-default cascade's stage-1. Auto-merge-eligible — subject to `min_independent_keys` (a lone shared domain does not auto-merge two accounts; §4.4).

**S2 — Tier-2 blocker + judge (similarity + LLM ALLOWED).** A cheap bi-encoder / trigram **blocker** over names+domains bounds the candidate set (recall-only — a miss here is unrecoverable, so high recall is the design goal). Each surviving pair goes to the **LLM judge** (opus-4-8, the shipped judge) with the strict fail-closed **"ties/uncertain → NO"** prompt reused verbatim from the knowledge-merge cascade. Emits `tier=2` evidence with `score` + rationale (stored on the audit row). **Never auto-merges — queues for human review.**

**S3 — Tier-3 mention EL (NER/LLM ALLOWED).** See §5. Emits `tier=3` evidence. **Never alone creates a merge or widens a scope.**

**S4 — The Fold (PURE DETERMINISTIC).** `fold(live_evidence, config) → aliases + tags + meta`:
1. Read only live (`valid_to IS NULL`), `eligible_as_edge` evidence.
2. **Anti-links win:** any live `polarity=−1` between two refs is a hard **must-not-link** that no positive evidence can override, and it splits a component (correlation-clustering constraint).
3. Build merge edges **only** from evidence clearing its tier's bar: Tier-1 edges (subject to `min_independent_keys`); Tier-2 edges **only if a `human_confirmed` row exists**; Tier-3 **never forms an edge** — it only raises `evidence_count`/confidence on an edge a higher tier already formed, or materializes a chunk tag under §5's co-signal rule.
4. **Model shared keys as first-class key-nodes** (grafted from P0): `salesforce:X —[verified_domain]— key:domain:acme.com —[verified_domain]— hubspot:Y`. A domain shared by *N* accounts becomes a visible star, not a silent transitive weld — if the star's fan-out implies merging distinct accounts, the component **surfaces for review** rather than auto-welding.
5. Union-find over qualifying edges → components. A component exceeding `component_size_cap` is **quarantined, not merged** (runaway clustering degrades to separate entities, never one mega-entity).
6. Each component → one `canonical_entity`; write `entity_aliases` members, chunk `entity_tags`, and `entity_link_meta` (with `justifying_evidence`).
7. **Idempotent + reversible:** the fold is a pure function of the live ledger, so retract-one-row + re-fold is the entire unmerge mechanism.

**Incremental fold (not a full re-cluster every ingestion).** A full re-fold does not scale. New evidence for `ref R` re-folds only R's affected component(s): load R's component members (via `entity_link_meta` back-refs), pull their live evidence, re-run union-find on that neighborhood, and re-materialize only its aliases/tags/meta. **Cluster-drift guards:** if a new edge would *merge two existing components*, do not silently join — route to review if either component is above a size floor (measured default: 8, §10 Q3) or if the joining edge is below Tier-1 (this is where two large customer clusters would fuse; it must never happen silently). Anti-links and the `component_size_cap` apply identically in the incremental path. A periodic full re-fold runs as a consistency backstop.

### 4.3 Exactly what the read path sees

Only three materialized things, all precomputed in the worker plane:
1. **`entity_aliases`** (canonical membership) — `merged_record` (§7f) runs exactly as today.
2. **Chunk `entity_tags`** — consumed only as the `<@` / `paradedb.term_set` **pre-filter** (postgres.rs:665) under §7c intersection semantics.
3. **`entity_link_meta`** — the confidence badge surfaced on the merged-entity response and in briefs ("canonical: `account:acme` — *deterministic*, won on domain_match" vs "*approximated* — 1 human confirmation, 2 corroborating mentions").

**Zero** ledger traversal, **zero** fold, **zero** LLM, **zero** live ReBAC at read time. `spawn_audit` (main.rs:688) logs the read with field provenance, as today; we extend it so each *fold* also logs which evidence justified each link (mirroring how knowledge merges store the judge's yes/no + rationale — auditable, reversible).

---

## 5. Unstructured text: detection → retrieval → disambiguation → ABSTAIN

This is Tier-3, the one irreducibly probabilistic surface, and the subtle part. The reality (§1): Drive and Linear bodies carry **no business entity id**; `entity_tags` ships empty. The posture (from the prior-art survey and §7d): **liberal about attaching *a* tag, conservative about *which* entity, quarantine when ambiguous.** The two decisions are deliberately split.

**Detection (worker).** Build a per-tenant **gazetteer** from L1: every Account/company name + alias + domain, every Contact email/domain. Run **high-precision gazetteer + fuzzy match first** (a closed, alias-rich catalog beats generic NER), NER/LLM as backstop for spans the gazetteer misses. Output: candidate mention spans + the L0 chunk ref.

**Candidate retrieval + disambiguation (worker).** For each mention, retrieve catalog candidates (alias dict + fuzzy + optional bi-encoder). Score by context similarity + intra-doc mention coherence + a **domain co-signal** (if the doc body or ACL also carries `acme.com`, it corroborates an `Acme` mention). Emit **Tier-3 evidence**, `method=llm_mention`, with `score`.

**The two-decision rule and the explicit ABSTAIN / NIL gates** (thresholds adopted verbatim from P1; configured via `tau_nil`/`margin_delta`):

- **Decision A — attach *a* tag at all? Recall over precision (safe).** Under §7c/§7d deny-by-default **intersection** semantics, an extra tag *narrows* retrievability, so over-attaching a plausible tag is safe. Lean in — as *non-authoritative Tier-3 evidence*.
- **Decision B — *which* entity? Precision; ABSTAIN if unsure.** Linking `Acme` to the *wrong* Acme mis-files content into a real customer's scope. So disambiguation emits **NIL** (no evidence; chunk → quarantine, **not** the zero-tag bucket) whenever **any** gate fires:
  1. **NIL threshold:** top-candidate score `< tau_nil` → no catalog entity is a real match → abstain.
  2. **Margin test:** `top1 − top2 < margin_delta` (two plausible Acmes) → abstain rather than guess.
  3. **Judge/kill-switch:** `auto_link_tier3 = false` (default) → Tier-3 never auto-creates/strengthens a link; the mention is a **reviewer hint** only. (When the LLM judge is invoked, ties/uncertain → NO.)

**The load-bearing rule: Tier-3 NEVER, on its own, creates a canonical merge or widens a scope.** A confident, unambiguous mention only *corroborates* an edge a higher tier already made, or becomes a **review-queue candidate**. Concretely, a Tier-3 mention of `Acme` in a Drive doc becomes an `entity_tags` value on that chunk **only if** `account:acme` is already a folded canonical **and** either (a) a **deterministic co-signal exists on the same chunk** or (b) a human approves. **The ACL-vs-content boundary, pinned:** ACL emails/domains (`domain:acme.com`, `group:sales-acme@x`) are **associative corroboration only** ("who can see it," not "what it is about"); entity tags and ACL visibility remain **orthogonal**. An ACL co-signal *raises confidence enough to permit the tag*, but the tag still **narrows** retrievability under §7c intersection — it never grants visibility. Abstain routes to **quarantine, never zero-tag** (zero-tag content is broad-scope-visible, so "abstain → untagged → leaks into broad scope" is itself the failure mode §7d closes).

**The fuzzer can't catch tagger misses (§7d, §7e), so we publish a number.** The scope-soundness fuzzer probes *handle enforcement*, not *tagger recall*. Tier-3 tagger recall is therefore a **published Scoped Recall Benchmark metric (#5, §7d/§13)** with a CI regression gate. **Precision is the guarantee; recall is the capability; both on the record.**

---

## 6. Permission-safety: why a wrong merge can't leak scope, and how it's split

**The threat (§3.2):** falsely merging customer A's entity with customer B's unions their `entity_scope` filters; A's data becomes retrievable in a B-bound session. **False merge = security incident; missed merge = UX annoyance.**

**Five defenses, defense-in-depth:**

1. **Only two tiers can *form* an edge, both precision-bounded.** Tier-1 deterministic strong keys (auto, subject to `min_independent_keys`), and Tier-2 **only after `human_confirmed`**. Tier-3 can never form an edge. There is no "the LLM was 0.8 sure so we merged" path — **by construction**, not by a threshold that might drift.
2. **Key-quality allowlist + denylist + `min_independent_keys` kills transitive over-merge** — the single biggest real-world identity-graph leak. `gmail.com`, `info@`, `example.com` are never edges; and a lone shared domain (MEDIUM) can't auto-merge two accounts on its own. The key-node model surfaces N-account domain collisions for human inspection instead of silently welding them.
3. **Namespace fence on actor-email edges** (§4.4) — the easiest real false-merge vector, first-class in config.
4. **Component-size cap fails closed** — runaway clusters quarantine, never form one scope-fusing mega-entity.
5. **Derived-view scope is the intersection of constituents (§2/§7c)** — even a *correct* merge doesn't leak: the canonical is visible only to principals who can see **all** constituents, and the read still runs the materialized `entity_tags` pre-filter per §7c. **Fuzzable (§7e):** add resolution-specific adversarial cases — a mis-linked entity surfacing across scope handles **fails the build**.

**Detecting and splitting a wrong merge (invalidate-don't-delete):** stamp `valid_to` on the offending evidence row; if a human asserts non-identity, append a `polarity=−1` **anti-link**. Re-fold. Union-find splits the component; `entity_aliases`, chunk `entity_tags`, and `entity_link_meta` rebuild — and `entity_link_meta.justifying_evidence` makes removing exactly the tags that edge added **surgical**. **Nothing is DELETEd**; the retracted row stays with `valid_to` set, preserving the audit trail of *what we once believed and why we stopped*. The anti-link is a **permanent guardrail** — the same bad auto-merge cannot re-form on the next ingestion. Hard deletion of an entity's data happens **only** via the §8 crypto-shred pipeline, never as a resolution op.

### 4.4 The actor-email population fence (Source 3's sharpest finding, made first-class)

Linear's `jane@acme.dev` is an **internal employee**, not a customer contact. Joining it to a CRM *customer* contact by email is almost always the **wrong population** — and a scope leak. This is not handled in prose; it is a config rule: every key carries a **`key_namespace`**, and an edge may form **only within a namespace**. Actor emails are stamped `internal_directory`; CRM contact emails `customer_contact`. An `internal_directory` email therefore **cannot** form an edge to a `customer_contact` entity. (Independently, `acme.dev` ≠ `acme.com` — different registrable domains — so even the domain would not match; but the namespace fence is the *primary* defense and does not rely on the TLD differing.)

---

## 7. Worked example: SF "Acme" + HubSpot "Acme" + a Linear ticket + a Drive doc

**Inputs.**
- **Salesforce:** `Account 001xACME`, `Name="Acme, Inc."`, `Website="https://www.acme.com"`.
- **HubSpot:** `company 4207`, `name="Acme"`, `domain="acme.com"`.
- **Linear:** org `0a2f…`, issue `ENG-42`, `assignee.email="jane@acme.dev"`, comment: *"Repro confirmed for Acme's timeout."* ("Acme" appears **only in the body**; `organizationId` is your own workspace.)
- **Google Drive:** doc `fileId=D9`, body mentions "Acme", ACL includes `domain:acme.com`, `group:sales-acme@x`. `entity_tags` ships **empty**.

**Trace.**

- **S0 canonicalize.** SF `Website` → domain `acme.com`. HubSpot `domain=acme.com` clean. `jane@acme.dev` → domain `acme.dev`, `key_namespace=internal_directory`. `acme.com` not free-mail → eligible.
- **S1 Tier-1.** SF `acme.com` ↔ HubSpot `acme.com` → `tier=1, method=domain_match, key_value=acme.com` linking `salesforce:001xACME` ↔ `hubspot:4207`. With `min_independent_keys=2`, the domain alone would *queue for review*; if a second independent key co-signs (e.g. a synced external_id, or an exact contact-email match within `customer_contact`), it **auto-merges**. Linear `jane@acme.dev`: attempted edge is `internal_directory` → **refused** an edge to the `customer_contact`/account namespace. Correctly no link.
- **S2 Tier-2 (if enabled).** Blocker pairs "Acme, Inc." with "Acme" — but they already merged on domain, so no fuzzy adjudication of the legal-vs-DBA name drift was ever needed. Clean.
- **S3 Tier-3 (if enabled).**
  - **Drive D9:** gazetteer matches "Acme" → candidate `account:acme`. Single confident candidate, wide margin → **not NIL**. A **deterministic co-signal on the same chunk** — ACL `domain:acme.com` = the account's verified domain — is present, so the chunk **may be tagged `account:acme`** (narrowing D9's retrievability to Acme-scope; safe under intersection). Absent the co-signal with `auto_link_tier3=false` (default): **reviewer hint only**, D9 stays as-is — not force-linked, not dumped into zero-tag.
  - **Linear "Acme's timeout":** gazetteer matches "Acme", but **no deterministic co-signal** (org id = workspace; actor = wrong population). Single candidate, zero corroboration, auto-link off → **abstain / reviewer-hint only.** Ticket stays a separate entity, surfaced in the review queue: "ENG-42 possibly concerns `account:acme` (mention-only, unconfirmed)." A human confirm → `human_confirmed` evidence (which *does* let the fold link it); a reject → `polarity=−1` anti-link, permanent.
- **S4 fold.** Merged: `salesforce:001xACME` + `hubspot:4207` → `account:acme`, meta `confidence=deterministic, strongest_method=domain_match`. Not merged (correctly): the Linear ticket (until a human confirms); `jane@acme.dev` never joined the customer account.

**Read path at recall time:** the serving core reads materialized `entity_aliases` (Acme = SF+HubSpot), materialized chunk `entity_tags` (D9 tagged iff the co-signal fired), and the badge. **No LLM, no NER, no fold, no live ReBAC.**

**Payoff:** at no point did an LLM's "Acme" guess auto-widen a scope. The one auto-merge was an exact shared domain (with the second-key guard). The internal-employee email was refused the customer edge. The mention-only ticket stayed separate. If D9's "Acme" later turns out to be "Acme Freight" (a *different* customer), an admin stamps `valid_to` on that Tier-3 evidence (+ an anti-link), re-folds, and D9's tag vanishes — no row deleted, full audit intact.

---

## 8. MVP vs beyond-MVP vs later

### MVP — ships the honest engine, OSS default, **no spec amendment needed** (S0 + S1 + S4)
- [ ] `0022_entity_evidence.sql`: `entity_evidence`, `entity_resolution_config`, `entity_link_meta`.
- [ ] **S0** canonicalize refs + keys (PSL domains, SF `Website` parse, E.164, name normalize, denylist, `key_namespace` stamping).
- [ ] **S1** Tier-1 exact-key producer (intra-CRM FK, exact email *within namespace*, external_id, admin crosswalk).
- [ ] **S4** deterministic fold: anti-links, key-node modeling, `min_independent_keys`, `component_size_cap`, union-find → `entity_aliases` + chunk `entity_tags` + `entity_link_meta`. **Finally a production caller for `resolve_canonical` (postgres.rs:382)**, closing the documented alias→`entity_tags` gap.
- [ ] Key-quality allowlist + denylist + **namespace fence** (a *security* control — non-negotiable even in MVP).
- [ ] `entity_link_meta` confidence badge surfaced in `get_merged_entity` (main.rs:676) and briefs.
- [ ] Extend `spawn_audit` so the fold logs justifying evidence per link.
- [ ] §7e fuzzer: resolution-specific adversarial cases (mis-linked entity across scope handles **fails the build**).
- [ ] CI precision-regression gate at **≥0.99 / FMR ≤ target**, holding the cascade's 1.000-across-112-negatives bar.

**MVP outcome:** §7f finally has real strong-key resolution (not just admin POSTs), the review queue's data substrate exists, and every link is provenance-badged — all deterministic, all read-path-pure. **"Nothing probabilistic in the OSS default" stays literally true.**

### Beyond-MVP — opt-in, per-tenant, kill-switchable; **each a public spec amendment**
- [ ] **S2 (Tier-2 fuzzy + human review)** — blocker + LLM judge → review queue (materialized view over `tier=2, valid_to IS NULL`) → the admin UI §7f promised. Reuse the knowledge-merge prompt + candidate→quarantined→published machinery (§126/§155). **Amends §7f** (adds the probabilistic-propose / human-confirm tier).
- [ ] **S3 (Tier-3 unstructured mentions)** — gazetteer + NER/LLM EL with `tau_nil`/`margin_delta` NIL gates → non-authoritative corroboration + reviewer hints; drives chunk `entity_tags` materialization only under the co-signal/human rule. Publish tagger recall as §7d metric #5. **Amends §7d** (the probabilistic-tag path). `VERITY_ENTITY_AUTO_LINK=0` defaults off.

### Later
- [ ] Review-queue prioritization + SLA (starvation risk — surface high-value/high-frequency entities first).
- [ ] Permission-aware review UI (the reviewer acts cross-scope; the surface is **audit-class**, per §149's provenance-firewall pattern — the review UI must not itself become a cross-scope read).
- [ ] Splink-style calibrated F-S scores as a Tier-2 producer (opt-in cloud tier, trust-downgrade-labeled per §6b).
- [ ] Full incremental-fold optimization + cluster-drift dashboards.

---

## 9. Build plan (parallelizable task groups)

**Group A — Migration & storage (foundation; blocks B/C/D).**
- `migrations/0022_entity_evidence.sql` (three tables + indexes).
- `crates/verity-storage/src/postgres.rs`: `insert_evidence`, `retract_evidence` (stamp `valid_to`), `live_evidence_for_refs`, `upsert_entity_link_meta`, `chunk_entity_tags_upsert`. Reuse `upsert_entity_alias` (:302), `resolve_canonical` (:382), `list_entity_aliases` (:354). **Leave `merged_record` (:416), `load_precedence` (:517), the `entity_tags` pre-filter (:665) untouched.**

**Group B — S0/S1 producers (depends on A).**
- `crates/verity-ingest` (or `ingest/verity_ingest`): key canonicalizers (PSL domain, SF `Website` parse, E.164, name normalize), denylist + namespace stamping, Tier-1 emitters over the SF/HubSpot/Linear connectors.

**Group C — S4 fold worker (depends on A; parallel to B).**
- `crates/verity-storage` (or a new `crates/verity-resolver`): the pure `fold(live_evidence, config)` — union-find, anti-links, key-node modeling, `min_independent_keys`, `component_size_cap`, incremental re-fold + drift guards. Property tests: fold determinism, idempotence, retract→re-fold split.

**Group D — Server surface (depends on A).**
- `crates/verity-server/src/main.rs`: badge in `get_merged_entity` (:676); new admin endpoints — evidence insert/retract, `entity_resolution_config` CRUD, review-queue read (view over `tier=2/3` live evidence). Extend `spawn_audit` (:688) for fold provenance.
- `crates/verity-server/src/entity_resolution_tests.rs`: fold + badge + fail-closed tests alongside the existing `merged_entity_*` cases.

**Group E — Safety gates (depends on C/D).**
- §7e fuzzer resolution cases (mis-link across scope handles → build fails).
- CI precision-regression gate (≥0.99 / FMR ≤ target) reusing the knowledge-merge benchmark harness; Scoped-Recall metric #5 wiring for Tier-3.

**Group F — Probabilistic tiers (beyond-MVP; depends on B/C; each gated behind a per-tenant flag + a public spec amendment).**
- S2 blocker + LLM judge (reuse `docs/design/knowledge-merge-tuning.md` cascade + prompt).
- S3 gazetteer/NER/LLM EL + NIL gates + co-signal tagging.
- SPEC.md §7f / §7d amendments.

---

## 10. Open questions

1. **Where does the fold worker live** — extend an existing sleep-time consolidation worker, or a new `verity-resolver` crate? (Leaning: new crate, since the fold is a distinct pure function with its own property-test surface.)
2. **ANSWERED (2026-07-11): `min_independent_keys` is per-`key_kind` — external_id = 1, domain = 2, email = 2.** Measured on the 103-pair hand-labeled stress corpus (`docs/benchmark/RESULTS-key-independence-2026-07-11.md`; synthetic, adversarial — NOT a natural distribution): external_id-alone false-merge rate **0/3 eligible negatives** (exact namespaced equality refused both constructed confusables), domain-alone FMR **0.2745** (14 FP — parents, franchises, co-tenants, `comcast.net`-style ISP domains: structural and un-denylistable), email-alone FMR **3/4 eligible** (shared humans: fractional CFO, serial founder, agency contact). The `{ext=1, dom=2, email=2}` policy measures FMR 0.0000 / precision 1.0 at auto-merge recall 0.1277 (6/47); the 36/47 forgone domain-only auto-merges are the deliberate price, paid as review latency, not lost links — the deterministic Tier-2 judge holds precision 1.0 / recall 0.7872 on the same corpus. So Q2's "too conservative?" answer is: yes for external_id (now 1), no for domain (the collisions are real). Codified in `EntityResolutionConfig::defaults` (verity-core `types.rs`) and migration `0024`. Caveats: the stress set cannot model a factually wrong same-namespace crosswalk (anti-link/review territory), and it measures account↔account edges, not person↔person. **Amended same day:** `fold.rs`'s `strong_method` no longer lets a lone `email_exact` weld — the measured leak (email-alone FMR 3/4 eligible; a lone `email_exact` bridge was also the cluster-join grid's worst offender, never leak-free at any floor) outweighed the unmeasured §4.2 S1 person↔person convenience. Email edges remain Tier-1 but now clear the per-kind `min_independent_keys` bar (email = 2 by default); person↔person lone-email welds stay available as an explicit per-namespace tenant opt-in (config email → `min_independent_keys = 1`). Fail-closed by default, recoverable by config — under-merge is review latency, over-merge is a leak.
3. **ANSWERED (2026-07-11, re-measured same day after the `email_exact` amendment): size floor = 8, joining-edge bar = tier1-any (a single crm_fk / external_id / admin_crosswalk bridge, or better).** Measured on the 520-scenario cluster-join stress corpus (`docs/benchmark/RESULTS-cluster-join-2026-07-11.md`; synthetic, adversarial — NOT a natural distribution), driving the public `refold_incremental` API over a floor × bar grid. The FIRST measurement (email still in the strong set) found `tier1-any` never leak-free (1→87 leaks from lone free-mail-adjacent `email_exact` bridges) and recommended (8, tier1-multi-key). That finding drove the `strong_method` amendment (Q2 above); the RE-MEASURED grid against the amended fold shows the email vector dead upstream, making tier1-any — now meaning only the measured-FMR-0 strong kinds — **leak-free at every floor ≤ 8**: at (8, tier1-any), 0 bad auto-joins, 114/260 legitimate joins auto-applied, 86 routed to review, review volume 126 (vs 58/142/182 under multi-key). Floors 12/20 leak double-coincidence clusters (10/27) under both tier1 bars; `human-only` never leaks but reviews 165–199 legit joins. Codified as `DEFAULT_LARGE_COMPONENT_FLOOR = 8` in `fold.rs`. Caveats: double-coincidence sides were constructed ≥8 members, upper-bounding the recommendable floor by design; tier1-any's safety rests on crosswalk trustworthiness (a factually wrong crosswalk is anti-link territory); and min-keys-suppressed pairs are dropped fail-closed by the fold AND discoverable: the review queue (closed follow-up, same day) surfaces all live positive evidence whose pair is still undecided — not welded, not anti-linked — so deferred Tier-1 pairs reach a reviewer, drop out on weld, and never resurface after an anti-link.
4. **Key-node collision UX** — when one domain fans out to N accounts (subsidiaries, conglomerates), what is the reviewer's default action, and can we auto-suggest a split by a secondary key?
5. **Tier-3 co-signal taxonomy** — beyond "ACL domain == account verified domain," which co-signals count as deterministic enough to permit a tag (a Linear ticket filed against an object with a resolvable FK; an observation written under an entity-scoped handle — the §7d provenance-derived tags, which are deterministic and preferred over EL)?
6. **ANSWERED (2026-07-11): measured fresh — `tau_nil = 0.70`, `margin_delta = 0.15`.** Neither bootstrapped nor guessed: a 9×9 = 81-point deterministic grid sweep over the 106-case hand-labeled mention corpus (`docs/benchmark/RESULTS-tier3-gates-2026-07-11.md`; synthetic stress set — NOT a natural distribution; no LLM calls). (0.70, 0.15) is the max-recall point among those with precision ≥ 0.99 and zero false links: link-precision **1.0000**, link-recall **0.7812** (50/64), **0 false links**, 38/38 correct abstains, 14/64 over-abstains (8 co-signal-cap ties + 6 partial names numerically inseparable from the wrong-org traps). The prior 0.55 default admits **10 false links** on this corpus (all in the fuzzy-backstop regime; identical to 0.70 on today's pure-gazetteer path where every mention scores 1.0), and `margin_delta = 0` is unsafe at every tau (21+ false links from alphabetical tie-break guesses). Codified in `Tier3Config` (ingest `resolve_tier3.py`), `EntityResolutionConfig::defaults` (verity-core `types.rs`), and migration `0024`. Caveats: score quantization (the scorer emits few discrete levels, so tau only bites in the backstop regime) and co-signal boost saturation at 1.0 (margin cannot separate two exact-name candidates even when one is co-signed — a measured scorer limitation, band b4). Consolidated with Q2/Q3 in `docs/benchmark/RESULTS-tuning-defaults-2026-07-11.md`.
7. **Review-queue starvation** — default-to-separate accumulates candidates; what SLA/prioritization makes the deterministic-only default *livable* rather than fragmenting every brief?
