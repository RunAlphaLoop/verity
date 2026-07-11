# RESULTS — entity-resolution tuning defaults (consolidated), 2026-07-11

This note consolidates the three measurements that set Verity's entity-resolution
tuning defaults, closing design §10 Q2 / Q3 / Q6
(`docs/design/cross-source-entity-resolution.md`). Each default below is chosen
FROM a measurement — no number here is guessed or vendor-quoted. All sweeps ran
on deterministic scorers only (zero LLM/API calls) and are pinned by regression
tests.

**Honesty note (applies to every number below):** all three corpora are
**synthetic, hand-labeled STRESS sets** — adversarially composed to
concentrate the failure modes, **NOT natural data distributions**. Measured
rates bound behavior on the constructed traps; they are not field-rate
estimates. Precision-first throughout: a false merge/link is a scope leak,
strictly worse than a miss (a miss is a review-queue entry).

## The chosen defaults

| default | old → new | load-bearing number | where codified |
|---|---|---|---|
| `tau_nil` | 0.55 (Python) / unset (Rust) → **0.70** | link-precision **1.0000**, **0 false links**, recall 0.7812 (50/64) at (0.70, 0.15) on the 106-case mention sweep; 0.55 admits **10 false links** (all b8 wrong-org traps, fuzzy-backstop regime) | `Tier3Config` (`ingest/verity_ingest/resolve_tier3.py`), `EntityResolutionConfig::defaults` (`crates/verity-core/src/types.rs`), migration `0024` |
| `margin_delta` | 0.15 (Python) / unset (Rust) → **0.15** (confirmed + codified) | `delta = 0` is unsafe at **every** tau (21+ false links from alphabetical tie-break guesses); any delta in {0.05..0.25} at tau 0.70 measures identically (safe plateau; 0.15 is the plateau's lower-median pick) | same three places |
| `min_independent_keys` (external_id) | 2 → **1** | external_id-alone false-merge rate **0/3 eligible negatives** (0.0000) on the 103-pair key-independence corpus; recall-alone 0.1064 — 4 crosswalk-only true positives unlocked | `EntityResolutionConfig::defaults` per-`key_kind` match |
| `min_independent_keys` (domain) | 2 → **2** (kept, now measured) | domain-alone FMR **0.2745** eligible (14 FP: parents, franchises, co-tenants, ISP mail domains — structural, un-denylistable) | unchanged default, column default `0022` stands |
| `min_independent_keys` (email, account↔account) | 2 → **2** (kept, now measured) | email-alone FMR **3/4 eligible** (shared humans: fractional CFO, serial founder, agency contact); policy `{ext=1, dom=2, email=2}` measures FMR **0.0000** overall | unchanged default; see flagged `strong_method` caveat below |
| cluster-join size floor | unset (caller-supplied) → **`DEFAULT_LARGE_COMPONENT_FLOOR = 8`** | re-measured post-amendment: **0 bad auto-joins** at (floor 8, tier1-any) on 520 scenarios; 114/260 legit joins auto-applied, 86 → review (volume 126); floors 12/20 leak double coincidences (10/27) under both tier1 bars | `crates/verity-storage/src/resolve/fold.rs` |
| cluster-join tier bar | below-Tier-1 (built-in) → **tier1-any (post-amendment: crm_fk / external_id / admin only)** | first measurement (email strong): tier1-any leaked 1→87 → drove the `email_exact` demotion; RE-MEASURED against the amended fold: tier1-any is **leak-free at every floor ≤ 8** and halves review friction vs multi-key | the built-in bar is now the measured-safe default; superseded (8, tier1-multi-key) noted in the RESULTS doc |

## The three detailed measurements

1. **Tier-3 abstain gates** — `RESULTS-tier3-gates-2026-07-11.md` / `.json`.
   106 hand-labeled mention cases (102 graded: 64 gold-link / 38 gold-abstain,
   + 4 ungateable containment-annex cases), 9×9 = 81-point (tau, delta) grid.
   Regression gate: `ingest/tests/test_resolve_tier3_sweep.py`.
2. **Key independence** — `RESULTS-key-independence-2026-07-11.md` / `.json`.
   103 labeled pairs (47 positive / 52 hard-negative / 4 easy-negative),
   per-kind K-alone FMR + policy sweep. Regression gate:
   `ingest/tests/test_resolve_keys_sweep.py`.
3. **Cluster-join policy** — `RESULTS-cluster-join-2026-07-11.md` / `.json`.
   520 scenarios (260 legitimate / 260 illegitimate joins), floor × bar grid
   over the public `refold_incremental` API. Regression gate:
   `crates/verity-storage/tests/cluster_join_measurement.rs`.

## Remaining caveats (measured limitations, not hidden)

- **Stress sets, not field rates** — see the honesty note above; re-measure on
  tenant data before quoting any of these numbers as production rates.
- **Scorer quantization / co-signal saturation (Q6):** tau only bites in the
  NER-backstop regime — on today's pure-gazetteer path every detected mention
  scores exactly 1.0, so 0.55 and 0.70 behave identically; and the co-signal
  boost caps at 1.0, so two exact-name candidates cannot be separated by a
  co-signal on one of them (band b4: 8 forced over-abstains).
- **Flagged, then FIXED same day:** `fold.rs` `strong_method` no longer lets a
  lone `email_exact` weld. The measured leak (email-alone FMR 3/4 eligible
  negatives; the cluster-join grid's worst offender — a lone `email_exact`
  bridge is never leak-free at any floor) outweighed the unmeasured §4.2 S1
  person↔person convenience. Email edges stay Tier-1 but now clear the
  per-kind `min_independent_keys` bar (email = 2 by default); person↔person
  lone-email welds remain available as an explicit per-namespace tenant opt-in
  (config email → `min_independent_keys = 1`). Fail-closed by default,
  recoverable by config.
- **Cluster-join bar enforcement (re-measured):** after the `email_exact`
  demotion, the built-in drift-guard bar (`tier1-any` — now only crm_fk /
  external_id / admin_crosswalk, the measured-FMR-0 kinds) is itself leak-free
  at every floor ≤ 8, so no caller-side multi-key enforcement is required by
  measurement. Residual follow-up: min-keys-suppressed pairs (lone domain, and
  lone email post-amendment) are dropped fail-closed but not yet persisted to
  the review queue.
- **Floor upper bound by construction:** the double-coincidence scenarios were
  built with sides ≥ 8 members, which upper-bounds the recommendable floor at 8
  by design.
- The Tier-3 fixture rationales quote scores measured against the pipeline at
  generation time; a scorer change that moves them fails the generator
  calibration and the pinned sweep tests — regenerate the corpus and re-run the
  sweep before trusting the numbers again.
