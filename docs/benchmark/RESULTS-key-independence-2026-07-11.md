# Key-independence sweep — is `min_independent_keys = 2` right, per key kind?

Corpus: `ingest/tests/fixtures/entity_resolution/entity_pairs.json` — **103 labeled entity pairs** (47 positives, 52 hard negatives, 4 easy negatives). **This is a synthetic, hand-labeled STRESS set, not a natural distribution** — negatives are adversarially composed (domain-shared-but-distinct parents/franchises/co-tenants, shared-consultant emails), so the measured rates bound behavior on adversarial cases; the zero/nonzero distinction carries the decision weight, the magnitudes do not generalize to field data.

Question (design doc §4.1 `min_independent_keys`, §10 Q2): may a SINGLE exact key of kind K auto-merge two entities alone, per kind? All scorers are deterministic (no LLM, no network); the simulator mirrors the fold's Pass-3 arithmetic (`crates/verity-storage/src/resolve/fold.rs`). Precision-first: a false merge unions two customers' scopes — a leak (§3.2) — so the **false-merge rate (FMR) is the load-bearing number**; a forgone auto-merge is NOT a loss, it falls through to the Tier-2 blocker→judge→human review path.

## Per-kind: what if a single K-key could auto-merge alone?

| key kind | FP (false merges) | eligible negs | FMR (eligible) | FMR (all negs) | recall alone | lone-K positives (auto-merges forgone by K=2) |
|---|---|---|---|---|---|---|
| `external_id` | **0** | 3 | **0.0000** | 0.0000 | 0.1064 | 4 |
| `domain` | **14** | 51 | **0.2745** | 0.2500 | 0.8085 | 36 |
| `email` | **3** | 4 | **0.7500** | 0.0536 | 0.1064 | 4 |

"Eligible" = both sides carry a non-denylisted key of that kind. "Lone-K positives" = true pairs whose ONLY matching key is kind K: exactly the auto-merges a 2-key bar on K forgoes (its recall cost, paid as Tier-2 review latency, not as a miss).

### `domain`-alone false merges (14) — the leaks

- `er-0069` ['Procter & Gamble', 'pg.com'] == ['Gillette', 'pg.com'] — DOMAIN-SHARED-BUT-DISTINCT: parent (P&G) and a consumer brand it owns, BOTH carrying the parent's domain pg.com in CRM. Distinct entities, distinct deal scopes. A domain-alone auto-merge fuses them — exactly the leak min_independent_keys exists to stop. Must stay apart.
- `er-0070` ['Unilever', 'unilever.com'] == ["Ben & Jerry's Homemade", 'unilever.com'] — DOMAIN-SHARED-BUT-DISTINCT: conglomerate vs one of its brands; the brand's CRM record was enriched with the parent's corporate domain. Two entities, one domain. Domain alone must not merge. Must stay apart.
- `er-0071` ['Berkshire Hathaway', 'berkshirehathaway.com'] == ['GEICO', 'berkshirehathaway.com'] — DOMAIN-SHARED-BUT-DISTINCT: holding company vs a wholly-owned subsidiary whose record carries the holding domain. Separate legal entities, separate data scopes. Must stay apart.
- `er-0072` ['Redwood Dental', 'brightsidemarketing.com'] == ['Harbor Plumbing', 'brightsidemarketing.com'] — DOMAIN-SHARED-BUT-DISTINCT: two unrelated small businesses whose CRM domain field holds their shared marketing AGENCY's domain (agency-managed email/website). The domain identifies the agency, not either client. Must stay apart.
- `er-0073` ['Lumen Bio', 'members.thehive.work'] == ['Quartz Legal', 'members.thehive.work'] — DOMAIN-SHARED-BUT-DISTINCT: two coworking-space members using the space's shared member domain. Shared infrastructure, not shared identity — the co-tenancy failure on a domain that is NOT in any free-mail denylist. Must stay apart.
- `er-0074` ['Marriott International', 'marriott.com'] == ['Desert Springs Hospitality', 'marriott.com'] — DOMAIN-SHARED-BUT-DISTINCT: franchisor vs an independent franchise operator whose contacts use brand-domain email. The franchisee is its own company with its own contracts and scope. Must stay apart.
- `er-0075` ['Crick Therapeutics', 'stanford.edu'] == ['Turing Robotics', 'stanford.edu'] — DOMAIN-SHARED-BUT-DISTINCT: two unrelated university spinouts whose records inherited the founders' .edu domain from contact enrichment. Institutional domains are co-tenant domains. Must stay apart.
- `er-0076` ["Hartley's Hardware", 'comcast.net'] == ['Bayside Florist', 'comcast.net'] — DOMAIN-SHARED-BUT-DISTINCT: two small businesses on an ISP mail domain (comcast.net) that is deliberately NOT in the free-mail denylist — proves the denylist cannot enumerate every shared-infrastructure domain, so the structural min_independent_keys guard must exist independently. Must stay apart.
- `er-0077` ['Meridian Battery', 'heliosgroup.com'] == ['Solward Grid', 'heliosgroup.com'] — DOMAIN-SHARED-BUT-DISTINCT: two SIBLING subsidiaries of one holding group (Helios Group), both on the parent's domain. Merging siblings through the parent domain unions two unrelated books of business. Must stay apart.
- `er-0078` ['Maple Crafts', 'etsy.com'] == ['Cedar Woodworks', 'etsy.com'] — DOMAIN-SHARED-BUT-DISTINCT: two marketplace sellers whose 'website' field holds the marketplace's domain. Platform domain, not company identity. Must stay apart.
- `er-0079` ['Oakfield Robotics', 'trinetclients.com'] == ['Pinehurst Media', 'trinetclients.com'] — DOMAIN-SHARED-BUT-DISTINCT: two companies using the same PEO/employer-of-record, whose HR-sourced contacts share the PEO's client mail domain. Shared back office, distinct companies. Must stay apart.
- `er-0080` ['Northstar Distribution', 'vulcantools.com'] == ['Vulcan Tools', 'vulcantools.com'] — DOMAIN-SHARED-BUT-DISTINCT: a distributor whose record carries its MANUFACTURER's domain (rep works from the vendor's portal/email) vs the manufacturer itself. Supply-chain adjacency, not identity. Must stay apart.
- `er-0081` ['Nimbus Software', 'vectorsystems.com'] == ['Vector Systems', 'vectorsystems.com'] — DOMAIN-SHARED-BUT-DISTINCT: a recently ACQUIRED company whose mailboxes migrated to the acquirer's domain vs the acquirer. Their pre-acquisition data scopes remain distinct; fusing them is a human decision (admin crosswalk), never a domain-alone auto-merge. Must stay apart.
- `er-0082` ['Kite Aerospace', 'thornegroup.com'] == ['Fenwick Marine', 'thornegroup.com'] — DOMAIN-SHARED-BUT-DISTINCT: two divisions of a conglomerate (Thorne Group) sharing the group domain. Divisions transact independently; a shared group domain must not weld their scopes. Must stay apart.

### `email`-alone false merges (3) — the leaks

- `er-0083` ['Alpine Physio', 'alpinephysio.com'] == ['Basalt Brewing', 'basaltbrewing.com'] — SHARED-EMAIL-BUT-DISTINCT: one fractional CFO (m.tran@ledgerpartners.co) is the billing contact for TWO unrelated companies. An exact shared customer-contact email between two ACCOUNT records is one shared human, not one company — email alone must not auto-merge accounts. Must stay apart.
- `er-0084` ['Peregrine Labs', 'peregrinelabs.com'] == ['Copperline Coffee', 'copperlinecoffee.com'] — SHARED-EMAIL-BUT-DISTINCT: a serial founder's personal gmail is the contact on both of their (distinct) companies. The free-mail DOMAIN is denylisted upstream, but the exact ADDRESS still matches — one person owning two companies does not make them one entity. Must stay apart.
- `er-0085` ['Orchid Skincare', 'orchidskincare.com'] == ['Truss Construction', 'trussconstruction.com'] — SHARED-EMAIL-BUT-DISTINCT: an agency-of-record account manager is the listed contact on two client accounts. Shared vendor human, distinct customers. Must stay apart.

## Policy sweep

| policy | external_id | domain | email | precision | recall | **FMR** | TP/FP/TN/FN |
|---|---|---|---|---|---|---|---|
| `uniform_min1` | 1 | 1 | 1 | 0.7302 | 0.9787 | **0.3036** | 46/17/39/1 |
| `uniform_min2` | 2 | 2 | 2 | 1.0000 | 0.0426 | **0.0000** | 2/0/56/45 |
| `per_kind_email1` | 1 | 2 | 1 | 0.7692 | 0.2128 | **0.0536** | 10/3/53/37 |
| `per_kind_email2` | 1 | 2 | 2 | 1.0000 | 0.1277 | **0.0000** | 6/0/56/41 |

Recall here is AUTO-MERGE recall only. On this same corpus the deterministic Tier-2 judge (name+domain, human-review path) holds precision 1.0 — see `RESULTS-resolve-tier2-deterministic-*.md` — so pairs a policy refuses are recoverable through review.

## Recommendation (data-decided, precision-first)

- **`external_id` → `min_independent_keys = 1`.** Measured 0 false merges over 3 eligible stress negatives (FMR 0.0000), including a cross-namespace value collision (er-0087) and a same-namespace near-miss (er-0088), both correctly refused by exact namespaced equality. An exact crosswalk is an intentional identity assertion by an integration; requiring a second key would forgo 4 clean crosswalk-only true positives for zero measured precision gain.
- **`domain` → `min_independent_keys = 2` (keep the default).** A lone shared domain false-merges **14 of 51** eligible stress negatives (FMR 0.2745): parents/subsidiaries, conglomerate brands, franchises, agencies-of-record, coworking/PEO/marketplace/ISP/university co-tenants. These are STRUCTURAL — a denylist cannot enumerate them (er-0076's comcast.net is deliberately not denylisted). The cost: 36 of 47 true pairs are domain-only and fall to Tier-2 review instead of auto-merging — the deliberate, measured price of the §3.2 posture.
- **`email` → `min_independent_keys = 2` for account↔account edges.** A lone shared contact email false-merges **3 of 4** eligible stress negatives (FMR 0.7500): a fractional CFO, a serial founder, an agency contact — one human serving two companies. **Finding:** `fold.rs` currently lists `email_exact` in `strong_method`, letting it weld alone (the `per_kind_email1` row) — measured FMR 0.0536 vs 0.0000 for `per_kind_email2`. The §4.2 S1 intent ("exact email person↔person within a namespace") is fine for PERSON entities; for ACCOUNT merges the exemption should be dropped (a config/spec amendment, flagged for §10 Q2 — this corpus does not measure person↔person resolution).

## Honesty notes

- Synthetic hand-labeled STRESS corpus (103 pairs at this writing); composition stated above. Not a natural distribution; per-kind FMR magnitudes are properties of this set's composition.
- Every number above was produced by `python -m verity_ingest.resolve_keys_sweep` on the checked-in fixture; nothing is quoted from elsewhere. `ingest/tests/test_resolve_keys_sweep.py` pins the per-kind FMR/FP counts as a regression gate.
- Key-independence caveat: in er-0098/er-0102 the contact email lives ON the shared domain, so email+domain are CORRELATED keys; the fold counts them as 2 distinct keys. A future refinement could refuse to count an email key whose domain equals an already-counted domain key.
- `external_id` FMR 0 means: exact NAMESPACED equality refused every confusable we could construct. The set does not model an integration writing a factually wrong crosswalk into the SAME namespace with exact-match values — that failure is real but unmeasurable by a key rule (it is what anti-links/review and invalidate-don't-delete are for).
- No LLM or API call anywhere in this sweep; all scorers are deterministic and offline.

