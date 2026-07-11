# The tagger-recall eval set — methodology (SRB metric 5)

**Status:** srb-v0, Phase 0 (measurement first). Spec: SPEC.md §7d
(probabilistic entity tagging; "tagger recall" listed as SRB metric #5).

SRB metric 5 measures the **entity-tagging** step of consolidation — the point
where the worker looks at a chunk of unstructured content and decides which of the
tenant's known entities the chunk is *about*, attaching each as a suggested tag.
Tagging is **probabilistic**: content mentions accounts by name, by abbreviation,
by pronoun, or not at all, and the tagger has to decide. The decision is
load-bearing because a tag **widens a memory's scope**: it attaches the memory to
that entity, so the memory surfaces on that account's recall. A **wrong** tag
leaks a memory into an account it does not concern — the tagging analogue of a
false merge in metric #6. Per the SRB precision-first contract, **a false tag is
worse than a missed tag: precision dominates recall.**

You cannot tune what you cannot measure. Until now metric #5 was
*defined-not-reported*. This eval set and harness are the yardstick; this run is
the baseline.

## What is measured

The harness (`ingest/verity_ingest/tagger_eval.py`, run `python -m
verity_ingest.tagger_eval`) **mirrors the shipped tag decision** in
`ingest/verity_ingest/consolidation.py` — the `DeterministicExtractor`'s
entity-name **echo** (consolidation.py lines 525–536): for each entity in the
episode's provenance lexicon it takes the bare name (after the last `:`), skips
names shorter than 3 chars, and suggests the tag for any chunk whose content
contains that bare name as a **case-insensitive substring**, at confidence 0.95.

The harness does **not** reimplement the echo. For each example it builds the
smallest `LeasedEpisode` the extractor accepts — one `LeasedChunk` holding the
content, the tenant lexicon supplied as the provenance `entities` — and calls
`DeterministicExtractor().extract`, the same public seam the consolidation worker
uses in production. The predicted tag set is exactly the `tag_suggestions` the
real extractor emits. The tenant lexicon per example is the **union of the
expected tags and the distractor entities**, so the tagger is always choosing
among real candidates, some of which it must reject.

For each example we compute, over the *set* of tags:

- **precision** — of the suggested tags, how many were in `expected_tags`. The
  costly error (a false tag = scope-widening).
- **recall** — of the `expected_tags`, how many were suggested.
- **F1** — harmonic mean.
- **distractor false-positive rate** — of the `distractor_entities` (in the
  lexicon but NOT in the content), how many were wrongly tagged. This is the
  confusion the hard categories are built to stress.

Metric numbers are reported by category too, so the precision holes and the
recall gap are attributable to specific failure modes rather than averaged away.

## Construction of the labeled corpus

Full corpus: [`tagger-eval.jsonl`](tagger-eval.jsonl) — one JSON object per line:
`{id, category, content, expected_tags, distractor_entities}`. **118 examples.**
`content` is a realistic sales/support snippet; `expected_tags` are the entity
tags that *should* be suggested (empty when the content mentions no entity);
`distractor_entities` are entities present in the tenant lexicon but **not** in
this content, which must **not** be tagged. Entity tags use the shipped
`account:<slug>` shape, and the echo keys on the bare slug after the last `:`.

The corpus is stratified into seven categories, chosen to exercise the honest
failure modes of an exact-name matcher:

| category | n | what it tests |
|---|---|---|
| `single_entity` | 44 | one account named verbatim — the clean case |
| `multi_entity` | 18 | two or more accounts genuinely named in one snippet |
| `none` | 23 | NO entity in the content — the tagger must not hallucinate |
| `common_word` | 10 | account name is also a common word (`Box`, `Apple`, `Summit`), used in its **common sense** — must NOT be tagged (precision stress) |
| `partial_name` | 12 | content uses an **abbreviation** (`IBM`, `GE`, `JPMC`) for a full-name entity — the echo MISSES it (recall gap) |
| `pronoun_only` | 7 | the account is referred to **only by pronoun/role** ("they", "their security team") and never named — must NOT be tagged |
| `substring_collision` | 4 | a short entity name is a **substring** of a common word (`meta`/`data` inside "metadata") and only one/none is really present |

Design intent per category:

- **`common_word` / `substring_collision`** are the **precision-stressing** cases.
  A naive substring matcher has no word-sense: it tags `account:box` on "the box
  turned green in CI" and `account:meta` on "metadata pipeline". These are the
  realistic false-tag failures, and the corpus surfaces them rather than hiding
  them. (A few `common_word` rows — `Oracle` running an `oracle` database,
  `Square` asking for square-footage pricing — are labeled as a **true** tag
  because the account IS genuinely named; they document that the echo gets the
  right answer for the wrong reason, blind to sense.)

- **`partial_name`** is the **recall-gap** case. The exact-name echo cannot expand
  `IBM` → `international-business-machines`, so it misses every abbreviation. This
  is the acceptable failure under the precision-first contract, and the primary
  thing the probabilistic (LLM) tagger is meant to recover.

- **`pronoun_only`** is a precision case that the echo happens to pass *for the
  right reason*: with no name in the text, the echo suggests nothing, which is
  correct. The entity is listed as a distractor (it is the real account behind
  the pronoun, but the content never names it) so a tagger that hallucinated a tag
  from provenance would be penalized.

- **`none`** anchors the no-hallucination end: content with a real lexicon but no
  entity present. Expected tags empty; any suggestion is a false positive.

## Sample rows

```json
{"id":"tg-0000","category":"single_entity","content":"Acme signed the order form this morning; kickoff is next Tuesday.","expected_tags":["account:acme"],"distractor_entities":["account:umbrella","account:wayne"]}
{"id":"tg-0030","category":"none","content":"The prospect wants a demo next week but hasn't shared the company name yet.","expected_tags":[],"distractor_entities":["account:acme","account:vandelay"]}
{"id":"tg-0045","category":"common_word","content":"We shipped the fix on Monday and the box turned green in CI.","expected_tags":[],"distractor_entities":["account:box","account:acme"]}
{"id":"tg-0053","category":"partial_name","content":"IBM's procurement team wants a volume discount for 10k seats.","expected_tags":["account:international-business-machines"],"distractor_entities":["account:acme","account:hooli"]}
{"id":"tg-0061","category":"pronoun_only","content":"They want the enterprise tier but haven't approved budget yet.","expected_tags":[],"distractor_entities":["account:acme"]}
{"id":"tg-0068","category":"substring_collision","content":"Metadata pipeline is healthy; no issues to report this week.","expected_tags":[],"distractor_entities":["account:meta","account:data"]}
```

## Governance (per SPEC §14)

Following the benchmark-governance decision used for metric #6: **publish the
methodology and a representative sample; the full set grows with real usage.**
This file is the published methodology; the checked-in `.jsonl` is the current
harness input and is expected to expand as real extractor output and new hard
cases accrue. The precision-stressing categories (`common_word`,
`substring_collision`) are the sensitive part — new ones should be added whenever
a real false-tag risk is discovered in the field.

## Reproducing

```sh
# Score the corpus with the CURRENT (deterministic) tagger, print the table,
# and write the dated report. Needs no database and no API key.
python -m verity_ingest.tagger_eval
# -> docs/benchmark/RESULTS-tagger-<date>.{json,md}
```

## The Phase-0 baseline finding

See [`RESULTS-tagger-2026-07-10.md`](RESULTS-tagger-2026-07-10.md). At v0 the
deterministic echo scores **precision 0.85, recall 0.79, F1 0.82** over 118
examples, with a **distractor false-positive rate of 0.074**. The number decomposes
cleanly by category and tells the honest story:

- On realistically-named accounts the echo is **precision 1.0**:
  `single_entity`, `multi_entity`, `none`, and `pronoun_only` all tag zero false
  positives. The precision-first contract holds where entity names are
  distinctive.
- The precision loss is **entirely** in the word-sense categories:
  `common_word` (P 0.18) and `substring_collision` (P 0.29). A substring matcher
  cannot tell the `Box` account from a shipping box, so it emits scope-widening
  false tags. This is the echo's real precision hole and motivates a tagger with
  word-sense — the probabilistic one.
- The recall loss is **entirely** in `partial_name` (R 0.0): the echo misses
  every abbreviation (`IBM`, `GE`, `HP`, `JPMC`). This is the recall gap the
  probabilistic tagger is meant to close.

So the v0 baseline is not a bland "P=1.0, low recall" — it is *precision 1.0 on
distinctive names, with two named precision holes (word-sense) and one named
recall gap (abbreviations)*. Both gaps point at the same fix.

## The AnthropicExtractor tagger (defined, not run here)

The `AnthropicExtractor` (consolidation.py, active only behind
`ANTHROPIC_API_KEY`) is the **probabilistic** tagger. Its extraction prompt asks
the model to suggest a tag "for each chunk whose content clearly discusses one of
the known entities but is not yet tagged with it … prefer recall over precision".
A model tagger would (a) expand abbreviations, recovering the `partial_name`
recall gap, and (b) apply word-sense, closing the `common_word` /
`substring_collision` precision holes — lifting **both** numbers the deterministic
echo leaves on the table, at the same precision-first posture. It is **shape-only
here** (no key), so this run is the *deterministic* baseline.

With this run, metric #5 is **defined AND baseline-reported**, closing the
'defined-not-reported' gap.
