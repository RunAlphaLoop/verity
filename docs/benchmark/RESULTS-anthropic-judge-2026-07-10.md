# Anthropic judge — live measurement (consolidation metric #6)

**Date:** 2026-07-10. **Model:** claude-opus-4-8. **Eval set:** the same 206 labeled
statement pairs as [RESULTS-consolidation-2026-07-10.md](RESULTS-consolidation-2026-07-10.md)
(94 positives / 90 hard negatives / 22 easy negatives). **Method:** each pair run through
the shipped `AnthropicJudge` (`ingest/verity_ingest/consolidation.py`) exactly as the
Phase-2 cascade calls it — pairwise "same generalization?", strict, fail-closed — and scored
against the label, identical to the deterministic harness. Directly comparable.

This closes the "LLM judge recall not yet measured" gap in
[docs/design/knowledge-merge-tuning.md](../design/knowledge-merge-tuning.md).

## Result

| judge | precision | recall | F1 | false-merge rate | false merges |
|---|---|---|---|---|---|
| cosine @ 0.85 (shipped baseline) | 1.000 | 0.000 | 0.000 | 0.000 | 0 |
| cosine @ ≥99%-precision frontier (0.75) | 1.000 | ~0.11 | — | 0.000 | 0 |
| DeterministicJudge cascade | 1.000 | 0.298 | 0.459 | 0.000 | 0 |
| **AnthropicJudge cascade (opus-4-8)** | **1.000** | **0.862** | **0.926** | **0.000** | **0 / 112** |

Confusion (AnthropicJudge): TP 81 · FP 0 · TN 112 · FN 13. Zero errors.

## Reading it

- **Precision is perfect and the false-merge rate is zero across all 112 negatives** — including
  every hard negative the design worried about (DPA-before-review vs SOC 2-before-review,
  healthcare-price vs healthcare-DPA, etc.). Not one distinct generalization was fused. This is
  the load-bearing property: a false merge fabricates cross-customer support and would surface a
  wrong generalization org-wide, so precision dominates. It held.
- **Recall 0.862 vs the deterministic judge's 0.298** — the LLM judge catches ~2.9× more true
  paraphrase, so far more real generalizations actually reach k-support and become eligible for
  review, without any precision cost.
- **13 misses (FN)** are true paraphrases the judge called "different" — the acceptable failure
  (a real generalization that fails to publish, not a wrong one that does). The remaining recall
  gap is where a stronger prompt or a second-opinion pass could push further; precision is the
  guarantee, recall is the capability, and both are now on the record.

## Honesty notes

- One run, 206 pairs, opus-4-8, temperature per the shipped judge config. LLM decisions are not
  perfectly deterministic run-to-run; the precision result (0 false merges) is the number that
  must hold and did, but re-run before quoting a recall figure to the decimal.
- Measured as the direct pairwise judge decision (no blocker gating), same as the deterministic
  harness — so the comparison is apples-to-apples. In production the blocker only *reduces* what
  reaches the judge, so end-to-end precision is ≥ this.
- API key was read from an operator file outside the repo and never entered the codebase, git
  history, or the harness source.
