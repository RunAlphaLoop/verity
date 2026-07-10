# Knowledge-merge tuning: firing on LLM paraphrase without fabricating support

**Status:** design, 2026-07-10. Follows the live-Anthropic smoke finding (task #39).
**Owner decision required:** §7. **Ships against:** the consolidation plane (SPEC §2, `crates/verity-server/src/consolidation.rs`, `ingest/verity_ingest/consolidation.py`).

---

## 1. The problem

Verity's knowledge layer is the mechanism by which the organization *learns across
customers without the customers' specifics crossing streams*. Agents in scoped
sessions hypothesize (n=1); a trusted server-side worker generalizes by clustering
similar hypotheses across **distinct entities** and accruing **support**; a candidate
publishes only after passing the de-identification gate, **k-distinct-entity support**
(default k=3), a category-size floor, corroboration, and human/policy review.

The clustering step is a similarity **merge**: when a candidate is proposed, the server
embeds its statement (MiniLM-L6, 384-d) and, if cosine to an existing candidate exceeds
`VERITY_KNOWLEDGE_MERGE_THRESHOLD` (default **0.85**), merges — adding the new entity as
evidence instead of minting a duplicate. Merging across distinct entities is *the only
way k-support is reached*.

**A live smoke against real Claude Opus 4.8 (not the deterministic test extractor) showed
the merge never fires on real model output.** Three semantically-identical generalizations
of one pattern (DPA-before-security-review), extracted from three different customers, came
back paraphrased:

| statement (abbreviated) | — |
|---|---|
| "…enterprise security teams require a signed DPA before they will begin a security review." | A |
| "…enterprise accounts require a Data Processing Agreement to be signed before any security assessment can proceed." | B |
| "…procurement teams block the security review until the data processing agreement (DPA) is executed." | C |

Measured pairwise MiniLM cosine: **A·B 0.62, A·C 0.68, B·C 0.49** — all far below 0.85. So
each stayed a separate candidate at `distinct_entities=1`; k-support never accrues; **the
generalization can never publish.** The deterministic extractor passed tests only because
its statements were byte-identical (cosine 1.0). Related finding: the LLM's L2 relation
keys are non-canonical (`requires` vs `requires_before_security_assessment`), so
`(subject, relation)` supersession also won't align across re-extractions — the same
canonicalization problem.

### Why the obvious fix is dangerous

Lowering the threshold to ~0.5 would merge A/B/C — **and also merge genuinely different
generalizations.** MiniLM-L6 has poor separation on short text: paraphrases sit at
0.49–0.68, but *unrelated* statements can also land in that band. A **false merge** fuses
two distinct patterns into one item and fabricates support for it — and that item, once it
crosses k=3, becomes **broadly visible to every customer's agents** via the §7g carve-out.

> **The governing asymmetry: a false merge is far worse than a missed merge.** A missed
> merge means a real generalization fails to publish (a capability gap). A false merge means
> a *wrong or unsupported* generalization is surfaced org-wide as trusted, cross-customer
> truth. Precision dominates recall. Any tuning must be evaluated as a precision problem
> first, a recall problem second.

---

## 2. The merge mechanism we will adopt

**A three-stage cascade: cheap bi-encoder *blocker* → LLM *judge* → human *gate before
publish*.** Each stage can only *reduce* what merges; none can force a merge past the human
gate for anything that would reach k-support. This keeps the precision-first contract while
actually catching paraphrase.

```
candidate C proposed
      │
  (1) BLOCKER  — bi-encoder, cheap, server-side
      │  embed C.statement; find existing candidates with cosine >= τ_block (LOW, ~0.45)
      │  → the CANDIDATE SET for C (bounds how many LLM calls stage 2 makes)
      │  cosine < τ_block against everything → fresh candidate, no merge. Done.
      ▼
  (2) JUDGE    — LLM-as-judge, worker-side (the worker already has the LLM + cross-scope read)
      │  "Is C the SAME generalization as any of these? Answer per-item yes/no + reason."
      │  strict prompt, precision-tuned; ties/uncertain → NO (fail closed).
      │  yes → propose the merge (accrue evidence). no across all → fresh candidate.
      ▼
  (3) HUMAN GATE — existing review queue, before PUBLISH (not before merge)
         a merged item still must pass k-support + de-id gate + reviewer approval.
```

**Placement and why:**
- The **blocker is a bi-encoder** (bge/gte/e5-small-class or the current MiniLM, tuned
  low) purely to *shrink the search space* — it is allowed high recall / low precision
  because stage 2 is the real decision. Its only job is to keep the judge's LLM-call count
  bounded (candidates share categories, so also pre-filter by category overlap — see below).
- The **judge is the LLM already in the worker.** This is canonical to the spec's "the
  worker generalizes" design (SPEC §2, "who generalizes"): the component with cross-scope
  read makes the semantic call, and its *only* outflow is a merge proposal that still faces
  the de-identification gate and human review. Cross-scope reading stays safe because the
  outflow is gated. An LLM judging "same generalization?" is dramatically more reliable than
  a 384-d cosine and is auditable (it returns a reason, stored on the merge record).
- The **human gate is unchanged** — merging only accrues *candidate* support; nothing
  auto-publishes (see §5).

**Category signal (graft into the blocker):** the smoke's three candidates all carried
overlapping categories (`security`, `compliance`, `sales-process`). Require the blocker's
candidate set to also share ≥1 category (Jaccard > 0) before the judge is consulted. Cheap,
and it both bounds LLM calls and raises precision of the pre-filter.

**Fail-closed everywhere:** blocker finds nothing → fresh candidate (safe). Judge uncertain
or errors → NO merge (safe — a missed merge, the acceptable failure). LLM unavailable →
degrade to *no auto-merge*, candidates queue for human clustering (§5), never to a bare
low-threshold cosine merge.

---

## 3. Canonicalization (fixes both findings)

Paraphrase collapses best **at extraction time**. Extend the extractor prompt (deterministic
and Anthropic) to emit, alongside the human-readable statement:

- a **canonical statement**: a normalized, lowercased, article-stripped predication of the
  generalization (e.g. all three DPA statements → `segment_buyer requires signed_dpa before
  security_review`);
- a **canonical predicate** for L2 facts: a controlled-vocabulary relation
  (`requires_before`) instead of free-text (`requires` / `requires_before_security_assessment`),
  fixing the `(subject, relation)` supersession-alignment finding.

The canonical statement becomes the blocker's embedding target and an exact-match fast path
(identical canonical form → merge with no LLM call). The human statement stays for display.
Canonicalization is a **recall aid, never a merge authority** — two different generalizations
must not be forced together by an over-aggressive normalization, so the judge still rules on
anything that isn't an exact canonical match.

---

## 4. Measurement: make the operating point defensible

You cannot tune what you cannot measure, and "trust us, we lowered a threshold" fails a
security review. Add **Scoped Recall Benchmark metric #6 — consolidation precision/recall.**

- **Eval set:** a labeled corpus of statement *pairs* tagged same-generalization vs
  different, built from (a) real extractor output over seeded multi-entity scenarios and (b)
  hard negatives — statements that are *topically close but genuinely distinct* (e.g. "requires
  DPA before security review" vs "requires SOC 2 report before security review"). ~200 pairs
  to start; grows with real usage. Checked into `docs/benchmark/`.
- **Metric:** report the full confusion matrix and the **PR curve** for the merge decision,
  and choose the operating point at a **target precision ≥ 0.99** (false-merge rate ≤ 1%),
  reporting whatever recall that buys. The number we publish is "at ≥99% precision we catch
  X% of true paraphrase merges" — recall is a capability disclosure, precision is the
  guarantee.
- **Harness:** `verity-bench srb` gains the metric; the cascade (blocker+judge) is evaluated
  end-to-end, so the reported precision is of the *shipped* decision, not the bi-encoder in
  isolation. Self-labels model + threshold used, per the honesty policy.
- **Regression gate:** CI check that the false-merge rate on the eval set stays ≤ target;
  any tuning that raises it fails the build.

---

## 5. User acceptability — the buyer-facing stance

Auto-derived, cross-customer knowledge is the most trust-sensitive thing Verity does. The
stance that makes it acceptable to an enterprise security/trust review:

**What is *never* automatic (the load-bearing promise):**
1. **Publishing is never automatic.** Merging only accrues *candidate* support. Crossing
   k-support makes an item *eligible for review*, not published. A human (or an explicitly
   configured policy the customer sets) approves every publish. Auto-publish is **off by
   default and opt-in per tenant.**
2. **Cross-customer learning is opt-in.** A tenant chooses whether their scoped interactions
   contribute to org-level generalizations at all. Default posture is configurable at
   deploy; the OSS default ships **conservative** (consolidation runs, publishing gated).
3. **No merge is authoritative without the judge's recorded reason.** Every merge stores
   the LLM's yes/no + rationale and the blocker score — auditable, reversible.

**Controls and transparency:**
- **Review queue** (already exists) shows candidates with their evidence (which entities,
  bucketed counts — never exact, to blunt membership inference, per SPEC §2), the merge
  history with reasons, and the de-identification gate result. A reviewer approves, edits, or
  rejects; rejection is remembered so the same candidate doesn't re-surface.
- **Confidence to agents:** published knowledge carries a **support tier** (e.g. `emerging`
  3–4 entities / `established` 5+), so a consuming agent can weight it. Never a false
  precision — buckets, not exact counts.
- **Correction/retraction UX:** the existing `memory.forget` + retraction cascade already
  recounts support and auto-invalidates a published item if support drops below k when a
  source is forgotten/erased. Merge reasons make "why did these combine?" answerable.
- **Kill switch:** `VERITY_KNOWLEDGE_AUTO_MERGE=0` disables auto-merge entirely; candidates
  then cluster only via human review in the queue. Consolidation degrades to assisted, never
  silent.

**The one-paragraph pitch for a security review:** *Verity learns patterns across your
customers but never lets one customer's specifics reach another. Generalizations are
de-identified deterministically, must be independently supported by ≥3 distinct customers,
are judged for sameness by a model whose reasoning is recorded and auditable, and are never
published without human approval — which is off by default. A wrong generalization is
structurally harder to publish than a real one is, and both are fully reversible.*

---

## 6. Rollout — phased, for a 2-person team

**Phase 0 — measurement first (½–1 wk).** Build the labeled pair eval set (real + hard
negatives) and metric #6 in `verity-bench srb`. *No behavior change yet* — this instruments
the current 0.85 threshold so every later change is measured, not asserted. Ship the CI
regression gate against a placeholder target.

**Phase 1 — canonicalization + exact-match merge (1 wk).** Extend both extractors to emit
canonical statement + canonical predicate. Add the exact-canonical-match fast-path merge
(no LLM). Fixes the L2 relation-key finding immediately. Tests: paraphrase set collapses to
fewer canonical forms; supersession aligns across re-extractions.

**Phase 2 — the cascade (1.5–2 wks).** Blocker (low-τ bi-encoder + category-Jaccard
pre-filter) → LLM judge in the worker (strict, fail-closed, reason recorded) → merge
proposal. Deterministic judge stub for tests (rule-based "same" oracle) so the test suite
stays LLM-free; live path behind the existing `ANTHROPIC_API_KEY` seam. Tune τ_block and the
judge prompt against metric #6 to the ≥99%-precision operating point. Re-run the original
live smoke: the three DPA candidates must now reach `distinct_entities=3`.

**Phase 3 — acceptability surface (1 wk).** Auto-publish opt-in flag (default off); support
tiers on published items; merge-reason + evidence display in the review queue and `/ui`;
`VERITY_KNOWLEDGE_AUTO_MERGE` kill switch. Document the buyer stance (§5) in
`docs/OPERATIONS.md` and the trust section of the site.

**Sequencing note:** Phase 0 before everything — never tune blind. Phases 1–3 are
independently shippable; 1 is pure win (fixes a bug, no risk), 2 is the core, 3 is the trust
wrapper that makes 2 sellable.

---

## 7. Risks & open decisions for the founder

1. **LLM-judge cost/latency on the write path.** Mitigated: the judge runs in the async
   sleep-time worker (never the read path), the blocker + category pre-filter bound how many
   candidate comparisons hit the LLM, and the exact-canonical fast-path skips it entirely for
   true duplicates. Still: at scale, budget it. **Decision:** acceptable per-candidate LLM
   cost ceiling, and whether a cheaper judge model (Haiku-class) suffices for the sameness
   call (likely yes — it's a constrained yes/no).
2. **Bi-encoder choice.** Keep MiniLM as the low-τ blocker (recall-only, cheap) or adopt a
   stronger 2026 small embedder? For the *blocker* MiniLM is probably fine since the judge
   decides; a stronger encoder mainly helps if we ever want a judge-free fast path at higher
   τ. **Decision:** defer; measure both in Phase 0.
3. **Default posture on cross-customer learning.** OSS ships conservative (consolidation on,
   publish gated, auto-publish off). Cloud/enterprise may want a managed default. **Decision:
   founder call on the shipped default and how loudly to document it.**
4. **Eval-set governance.** Hard negatives are where precision is won or lost; who curates
   them, and do we publish the eval set (transparency) or hold it (prevent gaming)?
   **Recommendation:** publish the methodology + a sample, hold the full set — matches the
   benchmark-governance open decision (SPEC §14).
5. **This is engineered precision, not a proof.** We say "≥99% precision on our eval set with
   human approval before publish," never "cannot produce a wrong generalization." The human
   gate is the real backstop; the cascade makes the reviewer's job rare and easy, it does not
   replace them. State this honestly — it's the same posture as the de-identification gate
   ("auditable gates, not differential privacy").
