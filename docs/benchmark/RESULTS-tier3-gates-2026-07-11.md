# ER Tier-3 abstain gates (tau_nil, margin_delta) — measured sweep

Eval set: `/Users/mattfleming/agent-memory/ingest/tests/fixtures/entity_resolution/mention_sweep_cases.json` — **102 graded labeled mentions** (64 gold-link, 38 gold-abstain) + 4 annex cases reported separately below. **Synthetic, hand-labeled STRESS set — not a natural mention distribution**: bands were designed to sit on the deterministic scorer's decision boundaries so the grid has measurable cliffs. Every number below was produced by running the shipped pipeline over this corpus; no number is quoted from elsewhere.

Pipeline: `resolve_tier3.plan_tier3` (detect -> retrieve -> disambiguate), deterministic end-to-end — the NER-backstop seam is exercised by a scripted detector replaying hand-authored fixture spans (`detector_spans`); **no LLM or network call anywhere**. Answers design §10 Q6 (cross-source-entity-resolution.md): measure `tau_nil`/`margin_delta` fresh on a tenant-catalog EL benchmark rather than bootstrapping from the knowledge-merge judge's operating point.

## Grading

Each case carries a config-independent gold label: `gold: account:x` (the mention truly refers to that catalog entity; correct decision = RESOLVE) or `gold: null` (correct decision = ABSTAIN). A case counts as a **link** when Decision B resolved to one canonical (outcome `tag` **or** `reviewer_hint` — the §5 tag gate is orthogonal to the abstain gates and is not what this sweep tunes), and as an **abstain** on NIL / margin-abstain / no detection. Per point: link-precision = correct/emitted links; link-recall = correct links / gold-link cases; false-link rate = false links / graded cases; over-abstain = gold-link cases abstained; correct-abstain = gold-abstain cases abstained.

## Corpus composition

| band | cases | gold-link | gold-abstain | what it stresses |
|---|---|---|---|---|
| `b10_short_low_context` | 10 | 4 | 6 | short/low-context docs (link, ambiguous, and unknown variants) |
| `b1_exact_cosignal` | 12 | 12 | 0 | unambiguous exact name + domain co-signal (strong context) |
| `b2_exact_no_cosignal` | 12 | 12 | 0 | unambiguous exact name, no co-signal (resolves as reviewer_hint) |
| `b3_ambiguous_two_exact` | 12 | 0 | 12 | two exact same-surface candidates, no co-signal (the two Acmes) — MUST abstain |
| `b4_ambiguous_cosignal_capped` | 8 | 8 | 0 | two exact candidates + co-signal on one; boost caps at 1.0 so margin stays 0 (scorer limitation, measured) |
| `b5_separable_two_candidates` | 10 | 10 | 0 | exact top + fuzzy sibling (margins 0.25 / 0.3333) — prices margin_delta set too high |
| `b6_partial_name_backstop` | 12 | 12 | 0 | near-miss partial names via the scripted backstop (0.75 / 0.6667) — the tau_nil recall frontier |
| `b7_fuzzy_with_cosignal` | 6 | 6 | 0 | fuzzy partial name + co-signal (saturates to 1.0) — the sanctioned sub-exact link path |
| `b8_wrong_org_trap` | 10 | 0 | 10 | distinct near-miss orgs scoring 0.6667 / 0.6000 — sets the tau_nil floor; must abstain |
| `b9_gold_nil_generic_scatter` | 4 | 0 | 4 | catalog name tokens scattered as common words (gold NIL) |
| `b9_gold_nil_unknown_org` | 6 | 0 | 6 | orgs matching nothing in the catalog (gold NIL) |
| **total (graded)** | **102** | **64** | **38** | |

## The grid — link-recall per point (false links flagged)

Cell = link-recall at that point; `(n FL)` marks points with n **false links** (any such point is disqualified). Link-precision is 1.0 at every unflagged point on this corpus (zero false links).

| tau_nil \ margin_delta | 0.00 | 0.05 | 0.10 | 0.15 | 0.20 | 0.25 | 0.30 | 0.40 | 0.50 |
|---|---|---|---|---|---|---|---|---|---|
| **0.50** | 0.906 (31 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.797 (10 FL) | 0.719 (10 FL) | 0.719 (10 FL) |
| **0.55** | 0.906 (31 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.797 (10 FL) | 0.719 (10 FL) | 0.719 (10 FL) |
| **0.60** | 0.906 (31 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.875 (10 FL) | 0.797 (10 FL) | 0.719 (10 FL) | 0.719 (10 FL) |
| **0.65** | 0.906 (27 FL) | 0.875 (6 FL) | 0.875 (6 FL) | 0.875 (6 FL) | 0.875 (6 FL) | 0.875 (6 FL) | 0.797 (6 FL) | 0.719 (6 FL) | 0.719 (6 FL) |
| **0.70** | 0.812 (21 FL) | 0.781 | 0.781 | **0.781** ← | 0.781 | 0.781 | 0.703 | 0.625 | 0.625 |
| **0.75** | 0.812 (21 FL) | 0.781 | 0.781 | 0.781 | 0.781 | 0.781 | 0.703 | 0.625 | 0.625 |
| **0.80** | 0.719 (21 FL) | 0.688 | 0.688 | 0.688 | 0.688 | 0.688 | 0.609 | 0.531 | 0.531 |
| **0.90** | 0.719 (21 FL) | 0.688 | 0.688 | 0.688 | 0.688 | 0.688 | 0.609 | 0.531 | 0.531 |
| **1.00** | 0.719 (21 FL) | 0.688 | 0.688 | 0.688 | 0.688 | 0.688 | 0.609 | 0.531 | 0.531 |

Reading the cliffs (all measured):

- **margin_delta = 0.00 is unsafe at every tau**: exact-exact ties (two Acmes) fall through to the deterministic alphabetical tie-break — a guess — producing false links (bands b3/b4/b10).
- **tau_nil <= 0.60** additionally admits the 0.6000-scored wrong-org traps; **tau_nil <= 0.6667 (grid 0.65)** admits the 0.6667 traps (band b8). The margin gate cannot help — those traps are single-candidate.
- **tau_nil >= 0.80** drops the legitimate 0.75-scored partial-name mentions (band b6): recall falls with no precision gain.
- **margin_delta >= 0.30** starts eating the separable two-candidate band (b5: margins 0.25, then 0.3333 at >= 0.40): recall falls with no precision gain.

## Recommended operating point

Selection rule: among points with link-precision >= 0.99 **and zero false links**, take maximal link-recall; resolve ties to the (lower-)median tau and delta of the tied region — the interior of the safe plateau (tau in {0.70, 0.75} x delta in {0.05..0.25}), deliberately not a boundary point (0.6667 and 0.75 are exact score levels; 0.25 is an exact margin level).

### `tau_nil = 0.70`, `margin_delta = 0.15`

| metric | value |
|---|---|
| link-precision | **1.0000** |
| link-recall | **0.7812** (50/64) |
| **false links** | **0** (rate 0.0000) |
| correct-abstain | 38/38 (1.0000) |
| over-abstain | 14/64 (0.2188) |
| abstain rate (overall) | 0.5098 |

### What it abstains on (the price of precision, itemized)

- **b4_ambiguous_cosignal_capped** (8): `s3-0037-b4_ambiguous_cosignal_capped`, `s3-0038-b4_ambiguous_cosignal_capped`, `s3-0039-b4_ambiguous_cosignal_capped`, `s3-0040-b4_ambiguous_cosignal_capped`, `s3-0041-b4_ambiguous_cosignal_capped`, `s3-0042-b4_ambiguous_cosignal_capped`, `s3-0043-b4_ambiguous_cosignal_capped`, `s3-0044-b4_ambiguous_cosignal_capped`
- **b6_partial_name_backstop** (6): `s3-0061-b6_partial_name_backstop`, `s3-0062-b6_partial_name_backstop`, `s3-0063-b6_partial_name_backstop`, `s3-0064-b6_partial_name_backstop`, `s3-0065-b6_partial_name_backstop`, `s3-0066-b6_partial_name_backstop`

- The **b4** over-abstains are a measured scorer limitation, not a gate mistuning: the co-signal boost caps at 1.0, so it cannot separate two exact-surface candidates even when it deterministically corroborates one. Fixing that is a scorer change (e.g. rank co-signal above tie, or boost multiplicatively below the cap) — flagged for a follow-up, not silently absorbed here.
- The **b6** 0.6667 over-abstains are deliberate: those scores are numerically identical to the b8 wrong-org traps, so no tau separates them; the sanctioned path for such mentions is a co-signal (b7, which saturates to 1.0 and links at every tau).

## Shipped default vs recommended

| point | precision | recall | false links | over-abstain |
|---|---|---|---|---|
| shipped default `tau=0.55, delta=0.15` | 0.8485 | 0.8750 | **10** | 8 |
| **recommended `tau=0.70, delta=0.15`** | **1.0000** | 0.7812 | **0** | 14 |

The shipped default `tau_nil=0.55` admits **10 false links** on this corpus — all from the b8 wrong-org traps, which only exist in the NER-backstop regime (fuzzy scores). Raising to 0.70 costs measured recall (0.8750 -> 0.7812: the six b6 0.6667 partial-name links, numerically inseparable from the traps) and buys the elimination of ALL false links — the precision-first trade (a false link is a scope leak; a miss is a review-queue entry). On the pure gazetteer path (the shipped `NullMentionDetector` default) every detected mention scores exactly 1.0, so 0.55 and 0.70 behave identically TODAY; the raise hardens the gate for the backstop era. `Tier3Config` defaults should be amended accordingly (spec-amendment path, per the design doc's conventions).

## Annex — containment failures the gates CANNOT block (reported, not hidden)

4 fixture cases put a catalog surface form as a contiguous sub-span of a longer, distinct org name ('Acme' inside 'Acme Analytics'). The window pass exact-matches them at 1.000 with no second candidate, so **every grid point false-links all 4** — the failure is in DETECTION, upstream of the gates, and would be dishonest to average into the grid. Standing detection-level limitation; candidate fixes (longest-span-wins suppression, NER-span containment checks) are follow-up work: `s3-0103-annex_containment_detection_gap`, `s3-0104-annex_containment_detection_gap`, `s3-0105-annex_containment_detection_gap`, `s3-0106-annex_containment_detection_gap`.

## Honesty notes

- **Corpus**: 102 graded synthetic hand-labeled mentions (+4 annex), composition above. STRESS set engineered onto the scorer's decision boundaries — precision/recall here do NOT predict natural-corpus rates; they bound gate behavior at the boundaries.
- **tau_nil is only exercisable in the backstop regime**: the gazetteer window pass yields exact 1.0 matches only, so with the shipped `NullMentionDetector` the NIL gate never fires on a detected mention. The scripted spans deterministically stand in for a live NER backstop; a live-backstop measurement on real text remains future work.
- **Score quantization**: the deterministic scorer emits a small set of levels (1.0, 0.75, 0.6667, 0.6 on this corpus; fuzzy retrieval floors at 0.6). Grid cells between levels are flat by construction; the recommended tau=0.70 sits between the 0.6667 trap level and the 0.75 legitimate level with slack on both sides.
- **Known scorer saturations, measured here**: (a) the +0.4 co-signal boost caps at 1.0 and cannot break an exact-exact tie (b4 over-abstains); (b) a WRONG fuzzy candidate >= 0.6 with a co-signal would also saturate to 1.0 and be ungateable — such cases are excluded from this corpus (they need a scorer fix, not a threshold) and noted here so the exclusion is explicit.
- Every reported number was measured by this module over the named fixture on this machine; the sweep is pure Python over an in-memory corpus (no DB, no network), so no latency numbers are claimed.

