# The consolidation eval set — methodology (SRB metric 6)

**Status:** srb-v0, Phase 0 (measurement first). Spec:
[`docs/design/knowledge-merge-tuning.md`](../design/knowledge-merge-tuning.md) §4.

SRB metric 6 measures the knowledge-statement **merge decision** — the step where
the consolidation worker decides whether an incoming generalization is *the same
generalization* as one already on file (and so accrues cross-entity support) or a
*new* one (and so mints a fresh candidate). Merging across distinct entities is the
only way k-distinct-entity support is reached, so this decision is load-bearing for
whether any org-level knowledge can ever publish — and a **wrong** merge fabricates
cross-customer support for an unsupported claim. Per §1's governing asymmetry, **a
false merge is far worse than a missed merge**: precision dominates recall.

You cannot tune what you cannot measure. This eval set is the yardstick.

## What is measured

The harness (`verity-bench`, `crates/verity-bench/src/consolidation.rs`) **mirrors the
shipped merge decision** in `crates/verity-server/src/consolidation.rs`
(`propose_or_merge`, lines 373–405). That decision merges an incoming statement into an
existing one when either:

1. **normalized-exact:** `lower(collapse_whitespace(a)) == lower(collapse_whitespace(b))`
   (consolidation.rs `normalize_term`, lines 56–61), or
2. **cosine ≥ threshold:** `1 - (embedding_a <=> embedding_b) >= VERITY_KNOWLEDGE_MERGE_THRESHOLD`
   (default **0.85**, consolidation.rs line 52), where `<=>` is pgvector cosine distance and
   embeddings come from the server's encoder (all-MiniLM-L6-v2, 384-d).

The harness reproduces both legs exactly: the same normalization, and the same encoder
(`verity_encoder::QueryEncoder` — the crate the server calls) with cosine similarity =
dot product of the L2-normalized vectors. No database round-trip is needed; the decision
is encoder+cosine only. The encoder and threshold are **self-labeled** into the emitted
JSON per the SRB honesty policy.

For each pair we compute the merge score (1.0 if normalized-exact, else cosine), predict
`merge` iff `score >= threshold`, and compare to the label. We report the confusion matrix
(TP/FP/TN/FN), precision, recall, F1, the **false-merge rate FP/(FP+TN)**, and a full **PR
curve** by sweeping the threshold — so the operating point where precision reaches ≥ 0.99
(false-merge rate ≤ 1%) is visible together with the recall it buys.

## Construction of the labeled pairs

Full corpus: [`consolidation-pairs.jsonl`](consolidation-pairs.jsonl) — one JSON object
per line: `{id, domain, kind, a, b, same_generalization}`. **206 pairs: 94 positives, 90
hard negatives, 22 easy negatives.** Five domains: security/DPA, pricing/discount behavior,
procurement cycles, integration objections, renewal timing.

The corpus is built from **generalization clusters**. Each cluster is one generalization;
its members are realistic paraphrases (varied word order, synonyms, voice, hedging), authored
to look like independent LLM re-extractions of the same pattern across different customers —
deliberately **not** byte-identical. (The deterministic extractor's cosine-1.0 case — which
made the old tests pass while real model output never merged — is intentionally absent.)

- **POSITIVES (`same_generalization: true`)** — every within-cluster unordered pair. The
  seed cluster is the live-smoke finding itself: *"enterprise security teams require a signed
  DPA before a security review"* / *"accounts require a Data Processing Agreement before any
  security assessment"* / *"procurement blocks the security review until the DPA is executed"*
  — all the SAME generalization.

- **HARD NEGATIVES (`same_generalization: false`, `kind: hard_negative`)** — the pairs where
  precision is won or lost. Two **distinct** generalizations in the **same domain** that share
  surface vocabulary: same subject/segment or same relation, different predication. Examples:
  - *requires a signed **DPA** before security review* vs *requires a **SOC 2** report before
    security review* (same slot, different artifact);
  - *healthcare buyers **negotiate hard on price*** vs *healthcare buyers **require a DPA***
    (same segment, different claim);
  - *deepest discounts at **quarter-end*** vs *deepest discounts for **volume commitments***.

  These are generated both by pairing cluster representatives within a domain and by a set of
  hand-authored cross-topic pairs, so the negatives cluster right up against the positives in
  embedding space — the realistic failure mode for a short-text bi-encoder.

- **EASY NEGATIVES (`kind: easy_negative`)** — statements from unrelated domains (e.g. a
  renewal-timing claim vs a security-questionnaire claim). These anchor the low-similarity end
  of the curve.

## Governance (per §7.4 / SPEC §14)

Following the benchmark-governance decision: **publish the methodology and a representative
sample; the full set grows with real usage.** This file is the published methodology. The
sample pairs quoted above are illustrative; the checked-in `.jsonl` is the current harness
input and is expected to expand as real extractor output and new hard negatives accrue. Hard
negatives are where precision is decided, so their curation is the sensitive part — new ones
should be added whenever a real false-merge risk is discovered.

## Sample rows

```json
{"domain":"security_dpa","kind":"positive","a":"enterprise security teams require a signed DPA before they will begin a security review","b":"procurement teams block the security review until the data processing agreement is executed","same_generalization":true}
{"domain":"security_dpa","kind":"hard_negative","a":"requires a signed DPA before the security review can start","b":"requires a SOC 2 report before the security review can start","same_generalization":false}
{"domain":"cross_domain","kind":"easy_negative","a":"SMB buyers are highly price-sensitive","b":"prospects stall without a native Salesforce integration","same_generalization":false}
```

## Reproducing

```sh
# Score the eval set with the CURRENT merge decision, emit the dated report,
# and enforce the CI gate (false-merge rate <= 1%). Needs no database.
cargo run --release -p verity-bench -- consolidation-gate \
  --threshold 0.85 --max-false-merge-rate 0.01 --out docs/benchmark
```

Metric 6 is also emitted as part of the full `verity-bench srb` run (into
`RESULTS-<date>.{json,md}` alongside metrics 1, 2, 4). The stand-alone
`consolidation-gate` subcommand is the CI entry point and requires no Postgres.

## The Phase-0 baseline finding

At the shipped **0.85** threshold the decision has **precision 1.0, recall 0.0** — it merges
**none** of the 94 true paraphrase pairs (the deterministic-extractor tests passed only because
their statements were byte-identical). The ≥99%-precision frontier sits at threshold ≈ **0.75**,
buying only **~11% recall**. Lowering the threshold to recover paraphrase (e.g. 0.50 → ~66%
recall) drives the false-merge rate to ~13%, unacceptable under the precision-first contract.
This quantifies the design doc's finding and is the baseline the cascade (§2) must beat. See
[`RESULTS-consolidation-2026-07-10.md`](RESULTS-consolidation-2026-07-10.md).

## Phase-2 result — the DeterministicJudge cascade

Phase 2 replaced the bare cosine decision with the three-stage cascade (design §2):
the deterministic **canonical-exact fast path**, then the low-τ **blocker**
(`/v1/admin/consolidation/merge-candidates`, τ_block ≈ 0.45 + shared-category
pre-filter, capped) feeding a worker-side **judge**, then the unchanged human gate.
**The server-side τ=0.85 cosine auto-merge is REMOVED** (migration `0017`): the server
no longer merges on cosine alone — merges come only from canonical-exact or a
worker-supplied, validated, *judged* decision (`merge_into` + recorded `judge_reason`).

The `verity-bench` metric above still measures the **cosine baseline** (it is Phase-0's
instrument and mirrors the old decision, unchanged). The **cascade decision** is measured
separately, LLM-free, by the `DeterministicJudge` over the same 206 pairs
(`ingest/verity_ingest/consolidation_eval.py`; run `python -m
verity_ingest.consolidation_eval`):

| decision | precision | recall | false-merge-rate |
|---|---|---|---|
| cosine @ 0.85 (baseline) | 1.00 | **0.00** | 0.00 |
| cosine @ ≥0.99-precision frontier (τ≈0.73) | 1.00 | **~0.11** | 0.00 |
| **DeterministicJudge cascade** | **1.00** | **0.30** (28/94) | **0.00** |

The DeterministicJudge (canonical-exact OR same controlled-artifact rule) holds
**precision 1.0 / zero false merges** — DPA vs SOC 2 vs pen-test vs BAA stay separate on
the hard negatives — while ~3× the cosine frontier's recall on true paraphrase, via
canonicalization plus the artifact-set rule. The **AnthropicJudge** (behind
`ANTHROPIC_API_KEY`, not runnable here without a key) would extend recall further at the
same precision, since it catches paraphrases outside the artifact family that the
deterministic rule misses.
