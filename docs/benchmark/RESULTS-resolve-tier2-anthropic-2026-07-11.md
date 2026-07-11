# ER Tier-2 entity-resolution judge — live measurement

**Date:** 2026-07-11. **Model:** claude-opus-4-8 (the shipped `AnthropicJudge`).
**Eval set:** `ingest/tests/fixtures/entity_resolution/entity_pairs.json` — **68 labeled
entity pairs** (33 positives / 32 hard negatives / 3 easy negatives). **Method:** each
pair run through the shipped `EntityAnthropicJudge` (`ingest/verity_ingest/resolve_tier2.py`)
exactly as the Tier-2 producer's blocker→judge cascade decides a pair — pairwise "same
entity?", strict, fail-closed — and scored against the label, identical to the
knowledge-merge harness (`consolidation_eval.py`). Directly comparable.

Run **twice**; both runs were **identical** (below), so the result is stable, not
single-run noise.

## Result

| judge | precision | recall | F1 | false-merge rate | false merges |
|---|---|---|---|---|---|
| deterministic (domain-required oracle) | **1.0000** | 0.9394 | 0.9688 | **0.0000** | 0 / 35 |
| **AnthropicJudge (opus-4-8)** | 0.9412 | **0.9697** | 0.9552 | **0.0571** | **2 / 35** |

Confusion (AnthropicJudge): TP 32 · FP 2 · TN 33 · FN 1. Both runs.

## Reading it

- **The LLM judge buys recall but does NOT hold precision on its own.** It lifts recall
  0.9394 → 0.9697 (catching the no-shared-domain true dup `Globex Corporation` ⇄
  `Globex`/globex.io that the deterministic oracle misses) — but it makes **2 false
  merges** the deterministic judge does not. In entity resolution a false merge unions
  two customers' data scopes: it is a **scope leak, not a data-quality nit**
  (cross-source-entity-resolution.md §3.2). So the **false-merge rate (0.0571) is the
  load-bearing number**, and here it is non-zero.
- **Both false merges are the same failure mode:** an identical company *name* paired
  with a **free-mail contact domain** on one side —
  `Oracle`/oracle.com ⇄ `Oracle`/yahoo.com, and `Acme`/hotmail.com ⇄ `Acme`/acme.com.
  The model over-trusts the name match and fuses across a domain that carries no company
  identity. This reproduced on both runs.
- **This is exactly why the design never lets the judge auto-merge.** The measurement
  *validates* the defense-in-depth, precision-as-security posture:
  1. **Free-mail / role / placeholder domains are denylisted keys** (§4.1, §4.4) — in
     production `yahoo.com`/`hotmail.com` are not eligible edge keys, so these two pairs
     never become an auto-merge candidate in the first place.
  2. **Tier-2 never forms an edge without a `human_confirmed` row** (§4.2 S4) — the fold
     structurally refuses to merge a Tier-2 pair until a human approves it in the review
     queue. The judge is a **recall booster that proposes review candidates**, never a
     merge authority.
  A reviewer looking at "`Oracle`/oracle.com vs `Oracle`/yahoo.com" rejects it in one
  click (writing a permanent anti-link); the LLM's over-merge is caught by the gate the
  spec requires precisely for this class of error.
- **Contrast with the knowledge-merge judge** (RESULTS-anthropic-judge-2026-07-10.md:
  precision 1.000 across 112 negatives). There the same model held precision perfectly;
  here, on entity pairs engineered to be name-confusable, it does not. The lesson is
  not "the judge is bad" — it is "**for entity resolution, precision cannot rest on the
  LLM; it rests on the deterministic denylist + the human gate**, with the LLM supplying
  recall." Both numbers are now on the record.

## Honesty notes

- Two runs, 68 pairs, opus-4-8, at the shipped judge's temperature. LLM decisions are
  not perfectly deterministic run-to-run; here the two runs matched to the pair, but
  re-run before quoting a figure to the decimal.
- This is the **raw pairwise judge** decision (as the harness scores it), the same
  apples-to-apples method as the knowledge-merge eval. It measures the judge's own error
  rate, not the end-to-end system's — end-to-end, the free-mail denylist removes those
  candidate pairs and the `human_confirmed` gate removes any survivor, so the shipped
  false-merge rate into `entity_aliases` is bounded far below this 0.0571.
- The eval set is precision-adversarial by construction (32/35 negatives are hard: same
  name / different company, parent vs distinct subsidiary, same name / different domain,
  free-mail collisions). It is a stress test, not a natural-distribution sample.
- API key was read from an operator file outside the repo and never entered the
  codebase, git history, this document, or the harness output.
