"""Tests for the Tier-3 abstain-gate sweep (resolve_tier3_sweep.py) — including
the REGRESSION GATE that pins the recommended operating point's measured
numbers on the sweep corpus (docs/benchmark/RESULTS-tier3-gates-2026-07-11.md).

Entirely LLM-FREE and deterministic: the NER-backstop seam is exercised only by
the ScriptedMentionDetector replaying fixture spans. No key is set, read, or
asserted on anywhere in this file.

The corpus is a synthetic hand-labeled STRESS set (see the fixture's `_about`);
the pinned numbers are stress-set numbers, not natural-distribution claims.
"""

from __future__ import annotations

from verity_ingest.resolve_tier3 import Tier3Config
from verity_ingest.resolve_tier3_sweep import (
    RECOMMENDED_MARGIN_DELTA,
    RECOMMENDED_TAU_NIL,
    choose_operating_point,
    grade_case,
    load_sweep_cases,
    measure_annex,
    measure_point,
    sweep,
)


def _graded(cases):
    return [c for c in cases if not c.get("annex")]


# ---------------------------------------------------------------------------
# THE REGRESSION GATE — pins the recommended operating point on the corpus.
# If a scorer/normalizer/fixture change moves ANY of these, the RESULTS doc is
# stale and must be re-measured + republished (never silently drift).
# ---------------------------------------------------------------------------


def test_recommended_point_regression_gate() -> None:
    cases = load_sweep_cases()
    graded = _graded(cases)
    gold_link_total = sum(1 for c in graded if c.get("gold"))
    p = measure_point(graded, RECOMMENDED_TAU_NIL, RECOMMENDED_MARGIN_DELTA)

    # The load-bearing pair: zero false links, perfect link-precision.
    assert p.false_links == 0, p.false_link_cases
    assert p.link_precision == 1.0

    # The full measured operating point (published in RESULTS-tier3-gates-2026-07-11):
    # 102 graded mentions = 64 gold-link + 38 gold-abstain.
    assert len(graded) == 102
    assert gold_link_total == 64
    assert p.correct_links == 50
    assert p.over_abstain == 14
    assert p.correct_abstain == 38
    assert p.link_recall(gold_link_total) == 50 / 64


def test_selection_rule_returns_recommended_point() -> None:
    cases = load_sweep_cases()
    graded = _graded(cases)
    gold_link_total = sum(1 for c in graded if c.get("gold"))
    chosen = choose_operating_point(sweep(cases), gold_link_total)
    assert (chosen.tau_nil, chosen.margin_delta) == (
        RECOMMENDED_TAU_NIL,
        RECOMMENDED_MARGIN_DELTA,
    )


# ---------------------------------------------------------------------------
# The measured cliffs the RESULTS doc narrates — kept true by construction.
# ---------------------------------------------------------------------------


def test_margin_delta_zero_is_unsafe() -> None:
    # delta=0 falls through exact-exact ties to the alphabetical tie-break — a
    # guess — so the ambiguous bands false-link. Any delta > 0 must not.
    cases = _graded(load_sweep_cases())
    p0 = measure_point(cases, RECOMMENDED_TAU_NIL, 0.0)
    assert p0.false_links > 0
    assert any("b3_ambiguous_two_exact" in cid for cid in p0.false_link_cases)
    p_small = measure_point(cases, RECOMMENDED_TAU_NIL, 0.05)
    assert p_small.false_links == 0


def test_pre_amendment_default_tau_admits_backstop_traps() -> None:
    # Documents WHY the sweep recommended raising tau_nil: at the
    # pre-amendment default (0.55 — shipped before the 2026-07-11 tuning
    # amendment) every b8 wrong-org trap (fuzzy 0.6 / 0.6667, single
    # candidate) false-links. Only meaningful in the backstop regime — on the
    # pure gazetteer path all detected mentions score 1.0.
    cases = _graded(load_sweep_cases())
    p = measure_point(cases, 0.55, 0.15)
    assert p.false_links > 0
    assert all("b8_wrong_org_trap" in cid for cid in p.false_link_cases)
    # The recommended tau clears them all.
    p_rec = measure_point(cases, RECOMMENDED_TAU_NIL, RECOMMENDED_MARGIN_DELTA)
    assert p_rec.false_links == 0


def test_shipped_default_is_the_recommended_operating_point() -> None:
    # The 2026-07-11 amendment landed: Tier3Config now ships the measured
    # recommendation (RESULTS-tuning-defaults-2026-07-11.md).
    cfg = Tier3Config()
    assert cfg.tau_nil == RECOMMENDED_TAU_NIL
    assert cfg.margin_delta == RECOMMENDED_MARGIN_DELTA
    p = measure_point(_graded(load_sweep_cases()), cfg.tau_nil, cfg.margin_delta)
    assert p.false_links == 0
    assert p.link_precision == 1.0


def test_high_gates_cost_recall_without_precision_gain() -> None:
    cases = _graded(load_sweep_cases())
    gold_link_total = sum(1 for c in cases if c.get("gold"))
    rec = measure_point(cases, RECOMMENDED_TAU_NIL, RECOMMENDED_MARGIN_DELTA)
    high_tau = measure_point(cases, 0.80, RECOMMENDED_MARGIN_DELTA)
    high_delta = measure_point(cases, RECOMMENDED_TAU_NIL, 0.40)
    assert high_tau.false_links == 0 and high_delta.false_links == 0
    assert high_tau.link_recall(gold_link_total) < rec.link_recall(gold_link_total)
    assert high_delta.link_recall(gold_link_total) < rec.link_recall(gold_link_total)


# ---------------------------------------------------------------------------
# Corpus composition — the published size/mix stays what the doc says it is.
# ---------------------------------------------------------------------------


def test_corpus_size_and_composition() -> None:
    cases = load_sweep_cases()
    graded = _graded(cases)
    annex = [c for c in cases if c.get("annex")]
    assert len(graded) == 102
    assert len(annex) == 4
    bands = {}
    for c in graded:
        bands[c["band"]] = bands.get(c["band"], 0) + 1
    assert bands == {
        "b1_exact_cosignal": 12,
        "b2_exact_no_cosignal": 12,
        "b3_ambiguous_two_exact": 12,
        "b4_ambiguous_cosignal_capped": 8,
        "b5_separable_two_candidates": 10,
        "b6_partial_name_backstop": 12,
        "b7_fuzzy_with_cosignal": 6,
        "b8_wrong_org_trap": 10,
        "b9_gold_nil_unknown_org": 6,
        "b9_gold_nil_generic_scatter": 4,
        "b10_short_low_context": 10,
    }
    # Every case documents its label.
    assert all(c.get("rationale") for c in cases)
    # Gold labels are config-independent link-or-NIL.
    assert sum(1 for c in graded if c.get("gold")) == 64


def test_annex_containment_is_ungateable_and_reported_separately() -> None:
    # The 4 containment cases false-link at the recommended point AND at the
    # strictest grid point — the failure is in detection, upstream of the
    # gates. They must never be averaged into grid metrics.
    cases = load_sweep_cases()
    rec = measure_annex(
        cases, Tier3Config(tau_nil=RECOMMENDED_TAU_NIL, margin_delta=RECOMMENDED_MARGIN_DELTA)
    )
    strict = measure_annex(cases, Tier3Config(tau_nil=1.0, margin_delta=0.5))
    assert rec["annex_cases"] == 4
    assert rec["annex_false_links"] == 4
    assert strict["annex_false_links"] == 4


# ---------------------------------------------------------------------------
# Grading arithmetic on tiny hand-verified cases.
# ---------------------------------------------------------------------------

_TINY_CATALOG = [
    {"canonical": "account:acme", "name": "Acme, Inc.", "aliases": ["Acme"],
     "domains": ["acme.com"], "is_canonical": True}
]


def test_grade_case_correct_link_and_over_abstain() -> None:
    case = {
        "id": "t1",
        "gold": "account:acme",
        "catalog": _TINY_CATALOG,
        "chunk": {"chunk_ref": "chunk:gdrive:T1:0", "text": "Acme renewal notes.",
                  "chunk_domains": [], "acl_domains": []},
        "detector_spans": [],
    }
    assert grade_case(case, Tier3Config(tau_nil=0.7, margin_delta=0.15)) == "correct_link"
    # An impossible tau (> any score) forces NIL -> over-abstain on a gold link.
    assert grade_case(case, Tier3Config(tau_nil=1.01, margin_delta=0.15)) == "over_abstain"


def test_grade_case_false_link_and_correct_abstain() -> None:
    case = {
        "id": "t2",
        "gold": None,  # distinct near-miss org: correct decision is ABSTAIN
        "catalog": [{"canonical": "account:url", "name": "Umbrella Research Labs",
                     "aliases": [], "domains": ["urlabs.com"], "is_canonical": True}],
        "chunk": {"chunk_ref": "chunk:gdrive:T2:0",
                  "text": "Umbrella Labs, the unrelated startup, pinged us.",
                  "chunk_domains": [], "acl_domains": []},
        "detector_spans": ["Umbrella Labs"],  # fuzzy 0.6667 vs the catalog name
    }
    # tau below the trap score -> the wrong org links -> false_link.
    assert grade_case(case, Tier3Config(tau_nil=0.55, margin_delta=0.15)) == "false_link"
    # the recommended tau abstains -> correct_abstain.
    assert grade_case(case, Tier3Config(tau_nil=0.70, margin_delta=0.15)) == "correct_abstain"
