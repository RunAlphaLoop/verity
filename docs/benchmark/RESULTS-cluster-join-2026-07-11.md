# Incremental-fold CLUSTER-JOIN policy — measured default (§10 Q3)

**Question** (`docs/design/cross-source-entity-resolution.md` §4.2 "Incremental fold … Cluster-drift guards" + §10 Q3): when new evidence would **join two existing components**, above which size floor / below which joining-edge tier bar must the join **route to review** instead of auto-applying?

**Harness:** `crates/verity-storage/tests/cluster_join_measurement.rs` — a permanent regression test (`cargo test -p verity-storage --test cluster_join_measurement`). It drives ONLY the public fold API (`refold_incremental`); **zero LLM, zero network, zero DB, zero clock** — every number below is the deterministic output of seeded scenario generation + the pure fold, exactly reproducible on any machine. Machine-readable copy: `RESULTS-cluster-join-2026-07-11.json`.

## Corpus — synthetic, hand-labeled STRESS set (NOT a natural distribution)

**520 scenarios: 260 legitimate joins, 260 illegitimate joins**, labeled **by construction** (the generator knows which pairs of components are the same real company). Each scenario is two pre-existing components (internally chained by strong Tier-1 keys, i.e. clusters a prior fold legitimately produced) plus new joining evidence. Component sizes are drawn from a deliberately small-skewed pool with a heavy tail (`[1,1,2,2,2,3,3,4,4,5,5,7,9,12,15,21]`); the composition is **adversarial** — the illegitimate half over-represents exactly the attack vectors §6 catalogs, so absolute rates here do NOT transfer to production traffic. What transfers is the *ordering* of policies and which cells are leak-free on these vectors.

| family | n | label | joining edge |
|---|---|---|---|
| LG-EXT | 60 | legit | one `external_id` crosswalk (1 strong key) |
| LG-FK | 40 | legit | one `crm_fk` bridge (1 strong key) |
| LG-EMAIL-SINGLE | 60 | legit | one exact corporate email (1 strong key) |
| LG-EMAIL-MULTI | 60 | legit | exact email + matching domain (2 independent keys) |
| LG-HUMAN | 40 | legit | `human_confirmed` |
| IL-FREEMAIL-ADJ | 70 | illegit | shared **free-mail-adjacent** email (`gmx.net`, `proton.me`, … — NOT in the denylist; formally a valid Tier-1 `email_exact` edge) |
| IL-DOUBLE | 40 | illegit | **double coincidence**: shared agency contact email + shared parked domain (2 independent keys) between two LARGE clusters (sides drawn from `[8,9,11,14,18,22]`) |
| IL-LONE-DOMAIN | 50 | illegit | single shared MEDIUM domain |
| IL-NAME-ONLY | 40 | illegit | Tier-2 fuzzy name, no human confirmation |
| IL-DENYLIST | 30 | illegit | denylisted free-mail domain (`gmail.com`, …) |
| IL-CROSSNS | 30 | illegit | `internal_directory` actor email (§4.4 wrong population) |

Two hand-labeled modeling choices are load-bearing and stated here honestly:

1. **"Free-mail-adjacent"** models the reality that no denylist is exhaustive: a shared personal email at a domain the denylist misses is formally exact `email_exact` evidence. In the FIRST measurement (same day, superseded) `email_exact` was a strong single key in the fold and this vector made `tier1-any` unshippable (1→87 leaks). That finding drove the `strong_method` amendment — `email_exact` no longer lone-welds (see `fold.rs`) — and this doc's grid is the RE-MEASUREMENT against the amended fold, where the vector is stopped upstream by the per-kind `min_independent_keys` bar (email = 2).
2. **Double coincidences are modeled as a large-cluster phenomenon** (coincidence surface grows with member count — every member contributes contact emails and secondary domains). The smallest double-coincidence side in the set is **8**, which is what upper-bounds the recommendable floor at 8. If you believe 2-key coincidences occur between smaller clusters in your data, lower the floor (or run human-only), and re-run this harness with your composition.

Config under test: shipped defaults hardened as in `resolution_precision_fuzz.rs` — `min_independent_keys=2`, free-mail denylist, §4.4 `internal_directory` email fence, `component_size_cap=None` (the cap is measured separately; leaving it off isolates the join policy).

## Policy semantics measured

- **Size floor S:** a pre-existing component with `size >= S` is "large"; a join touching it routes to review (`refold_incremental`'s `large_component_floor`, applied to **all** joins including human-confirmed ones — as implemented).
- **Tier bar** (applied on top of the fold's always-on guards):
  - `tier1-any` — whatever the built-in drift guard admits (any Tier-1 edge or human confirm). This is the currently-shipped behavior.
  - `tier1-multi-key` — additionally require ≥2 **distinct independent** `(key_kind, key_value)` on the joining pair, or a human confirmation.
  - `human-only` — only a `human_confirmed` join auto-applies.

## The grid (520 scenarios; 260 legit / 260 illegit per cell) — RE-MEASURED after the email_exact demotion

| floor | tier bar | **bad auto-joins (LEAK)** | legit auto | legit→review (friction) | legit blocked | review volume |
|---|---|---|---|---|---|---|
| 2 | tier1-multi-key | **0** | 2 | 198 | 60 | 238 |
| 2 | tier1-any | **0** | 6 | 194 | 60 | 234 |
| 2 | human-only | **0** | 1 | 199 | 60 | 239 |
| 3 | tier1-multi-key | **0** | 8 | 192 | 60 | 232 |
| 3 | tier1-any | **0** | 20 | 180 | 60 | 220 |
| 3 | human-only | **0** | 2 | 198 | 60 | 238 |
| 5 | tier1-multi-key | **0** | 32 | 168 | 60 | 208 |
| 5 | tier1-any | **0** | 69 | 131 | 60 | 171 |
| 5 | human-only | **0** | 14 | 186 | 60 | 226 |
| **8** | **tier1-any** | **0** | **114** | **86** | **60** | **126** |
| 8 | tier1-multi-key | **0** | 58 | 142 | 60 | 182 |
| 8 | human-only | **0** | 20 | 180 | 60 | 220 |
| 12 | tier1-multi-key | 10 | 72 | 128 | 60 | 158 |
| 12 | tier1-any | 10 | 136 | 64 | 60 | 94 |
| 12 | human-only | **0** | 27 | 173 | 60 | 213 |
| 20 | tier1-multi-key | 27 | 87 | 113 | 60 | 126 |
| 20 | tier1-any | 27 | 176 | 24 | 60 | 37 |
| 20 | human-only | **0** | 35 | 165 | 60 | 205 |

("legit blocked" = 60 everywhere: the LG-EMAIL-SINGLE family. Under the amended fold a lone shared email is min-keys-suppressed BEFORE the join decision — fail-closed, no leak — and discoverable: see the honesty note below, closed same day.)

## Recommendation — floor **8**, bar **tier1-any** (post-amendment)

With `email_exact` demoted, `tier1-any` now means "any single remaining formally-strong key": `crm_fk` / `external_id` / `admin_crosswalk` — exactly the kinds the key-independence measurement found FMR 0 (`RESULTS-key-independence-2026-07-11.md`). On the re-measured grid it is **leak-free at every floor ≤ 8** and strictly dominates multi-key on friction: at floor 8, **0 bad auto-joins, 114/260 legitimate joins auto-applied, 86 routed to review, review volume 126** (vs 58/142/182 under multi-key). The prior recommendation (8, tier1-multi-key) was correct for the pre-amendment fold and is superseded.

Why the axes land there, in the re-measured data:

- **The free-mail-adjacent email vector is dead upstream.** IL-FREEMAIL-ADJ (70 scenarios) never reaches the join decision — the per-kind min-keys bar (email = 2) blocks the lone-email bridge for illegitimate AND legitimate pairs alike. This is what turned tier1-any leak-free at small floors.
- **Floors 12/20 still leak double coincidences under BOTH tier1 bars** (10/27 leaks) — the IL-DOUBLE sides (8–11) slip under larger floors, and a 2-key coincidence satisfies multi-key too. 8 remains the largest safe floor, exactly as the corpus's construction bounds it.
- **`human-only` never leaks but pays maximal friction** (165–199 legit joins reviewed) — the §10 Q7 starvation risk made concrete.

**Precision-first caveats:**

- The leak column is the load-bearing number; friction rankings are sensitive to family composition. When in doubt, lower the floor — every tier1 cell at floor ≤ 8 is leak-free here.
- `tier1-any`'s safety rests on the trustworthiness of `external_id`/`crm_fk`/`admin_crosswalk` values. This corpus cannot model a factually WRONG same-namespace crosswalk (the same Q2 caveat); a poisoned crosswalk is anti-link/review territory, not a threshold problem.
- **Honesty gap — CLOSED same day:** min-keys-suppressed direct pairs (lone domain; lone email post-amendment) are dropped fail-closed by the fold, and the review queue now surfaces them: it reads *live positive evidence whose pair is still undecided* (not welded into one canonical, not anti-linked), so every deferred Tier-1 pair is discoverable, self-heals out of the queue on weld, and is excluded permanently on anti-link. Derived from state, never by re-duplicating fold logic in SQL. DSN-gated proof: `deferred_tier1_pair_surfaces_until_decided` (crates/verity-storage/tests/entity_decide.rs).

Defense-in-depth confirmed along the way (asserted at **every** grid cell, gate G4): the denylist, lone-MEDIUM-key, Tier-2-without-human, and §4.4 cross-namespace families **never** auto-join under any policy.

## Per-family outcomes at the recommended policy (floor=8, tier1-any)

| family | auto-join | review | blocked separate |
|---|---|---|---|
| LG-EXT | 37 | 23 | 0 |
| LG-FK | 19 | 21 | 0 |
| LG-EMAIL-SINGLE | 0 | 0 | 60 |
| LG-EMAIL-MULTI | 38 | 22 | 0 |
| LG-HUMAN | 20 | 20 | 0 |
| IL-FREEMAIL-ADJ | 0 | 0 | 70 |
| IL-DOUBLE | 0 | 40 | 0 |
| IL-LONE-DOMAIN | 0 | 0 | 50 |
| IL-NAME-ONLY | 0 | 0 | 40 |
| IL-DENYLIST | 0 | 0 | 30 |
| IL-CROSSNS | 0 | 0 | 30 |

The friction shape after the amendment: single-strong-key legitimate bridges (EXT/FK) now auto-apply when both sides are under the floor and queue when large — while lone-email legitimate bridges pay the full min-keys price (deferred to the review queue, which now surfaces undecided Tier-1 pairs — see the closed honesty note above). Human-confirmed joins of large clusters also queue at this floor — as `refold_incremental` implements today; whether a human confirm should override the size floor is a possible follow-up amendment.

## Regression gate (runs in CI under plain `cargo test`)

The harness asserts on every run: **G1** zero bad auto-joins at (8, tier1-any); **G2** human-only never leaks; **G3** the stress set still exercises the loose-floor leak vectors (both tier1 bars must still leak at floor=20 — the corpus staying adversarial is itself gated); **G4** the four upstream-guard families never auto-join anywhere; **G5** the computed least-friction zero-leak cell IS the recommended one (if the fold or corpus changes the winner, the build fails and this doc must be re-measured — exactly the mechanism that caught the email_exact amendment and forced this re-measurement); **G6** the full sweep is deterministic across runs.
