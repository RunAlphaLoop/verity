"""Tests for the ER Tier-2 entity-resolution judge eval harness.

Entirely LLM-FREE. Runs ``evaluate(EntityDeterministicJudge(), labeled_set)`` over
the checked-in fixture (NO API key), asserting the load-bearing property — the
deterministic oracle NEVER fuses a negative, so precision == 1.0 and
false_merge_rate == 0.0 — plus a recall floor (recall is expected to be lower;
the live judge closes that gap). Also checks the harness metric arithmetic on a
tiny hand-verified set, mirroring the tagger/consolidation eval tests.

No real key is set, read, or asserted on anywhere in this file.
"""

from __future__ import annotations

from verity_ingest.resolve_tier2 import Entity, EntityDeterministicJudge
from verity_ingest.resolve_tier2_eval import (
    Confusion,
    decide_same,
    evaluate,
    is_freemail,
    load_pairs,
)


# ---------------------------------------------------------------------------
# The load-bearing property: deterministic oracle holds precision 1.0 / FMR 0.0
# on the whole labeled set (never fuses a hard negative).
# ---------------------------------------------------------------------------


def test_deterministic_judge_holds_precision_and_zero_false_merges() -> None:
    pairs = load_pairs()
    r = evaluate(EntityDeterministicJudge(), pairs)

    # Precision-as-security: a false merge is a scope leak. The deterministic
    # oracle must never produce one.
    assert r["confusion"]["fp"] == 0, r["false_merges"]
    assert r["precision"] == 1.0
    assert r["false_merge_rate"] == 0.0


def test_recall_has_a_reasonable_floor() -> None:
    # Recall is EXPECTED to be lower than precision (the deterministic oracle
    # misses same-company pairs without a clean shared domain — the acceptable
    # failure the live judge fixes). Assert only a floor so the test documents the
    # baseline without over-fitting to an exact value.
    pairs = load_pairs()
    r = evaluate(EntityDeterministicJudge(), pairs)
    assert r["recall"] >= 0.5
    # And it does catch real dups (not a degenerate all-negative predictor).
    assert r["confusion"]["tp"] > 0


def test_corpus_breakdown_is_balanced_with_hard_negatives_well_represented() -> None:
    pairs = load_pairs()
    r = evaluate(EntityDeterministicJudge(), pairs)
    c = r["corpus"]
    assert c["total"] == len(pairs)
    assert c["positives"] + c["negatives"] == c["total"]
    # Hard negatives are the point of a precision-first set: well represented.
    assert c["hard_negatives"] >= 20
    # Roughly balanced positives vs negatives (neither side trivial).
    assert c["positives"] >= 15
    assert c["negatives"] >= 15


# ---------------------------------------------------------------------------
# Free-mail denylist pre-filter: a shared co-tenant domain never fuses.
# ---------------------------------------------------------------------------


def test_freemail_shared_domain_does_not_fuse() -> None:
    # Identical placeholder name on a shared free-mail domain: co-tenants, NOT one
    # company. The upstream denylist blanks the domain, so the judge abstains.
    left = Entity(ref="sf:1", name="Consulting", domain="outlook.com")
    right = Entity(ref="hs:2", name="Consulting", domain="outlook.com")
    assert is_freemail("outlook.com")
    assert decide_same(EntityDeterministicJudge(), left, right) is False


def test_corporate_shared_domain_still_fuses() -> None:
    # Control: a real corporate shared domain is NOT denylisted, so a legitimate
    # cross-source dup still fuses.
    left = Entity(ref="sf:1", name="Acme, Inc.", domain="acme.com")
    right = Entity(ref="hs:2", name="Acme", domain="acme.com")
    assert not is_freemail("acme.com")
    assert decide_same(EntityDeterministicJudge(), left, right) is True


# ---------------------------------------------------------------------------
# Harness metric arithmetic on a tiny hand-verified set.
# ---------------------------------------------------------------------------


def test_confusion_metric_math_hand_checked() -> None:
    # 3 TP, 1 FP, 4 TN, 2 FN.
    c = Confusion()
    for _ in range(3):
        c.observe(predicted_merge=True, truth_same=True)  # TP
    c.observe(predicted_merge=True, truth_same=False)  # FP
    for _ in range(4):
        c.observe(predicted_merge=False, truth_same=False)  # TN
    for _ in range(2):
        c.observe(predicted_merge=False, truth_same=True)  # FN

    assert (c.tp, c.fp, c.tn, c.fn) == (3, 1, 4, 2)
    assert c.precision == 3 / 4  # TP/(TP+FP)
    assert c.recall == 3 / 5  # TP/(TP+FN)
    assert c.false_merge_rate == 1 / 5  # FP/(FP+TN)
    # F1 = 2PR/(P+R)
    p, r = 3 / 4, 3 / 5
    assert abs(c.f1 - (2 * p * r) / (p + r)) < 1e-12


def test_confusion_empty_predictions_defaults() -> None:
    # No positives predicted => precision defined as 1.0 (vacuous), recall 0.0,
    # false-merge rate 0.0. Matches consolidation_eval.Confusion exactly.
    c = Confusion()
    c.observe(predicted_merge=False, truth_same=True)  # FN
    c.observe(predicted_merge=False, truth_same=False)  # TN
    assert c.precision == 1.0
    assert c.recall == 0.0
    assert c.false_merge_rate == 0.0


def test_evaluate_metric_math_on_tiny_set() -> None:
    # A tiny inline set the deterministic judge decides predictably:
    #  - shared corporate domain + agreeing name  -> predicted SAME
    #  - distinct corporate domains               -> predicted NOT SAME
    tiny = [
        # TP: same company, shared domain, labeled same.
        {
            "id": "t1",
            "kind": "positive",
            "same": True,
            "left": {"ref": "a:1", "name": "Acme, Inc.", "domain": "acme.com"},
            "right": {"ref": "b:1", "name": "Acme", "domain": "acme.com"},
        },
        # TN: distinct domains, labeled not-same.
        {
            "id": "t2",
            "kind": "hard_negative",
            "same": False,
            "left": {"ref": "a:2", "name": "Acme Corp", "domain": "acmecorp.com"},
            "right": {"ref": "b:2", "name": "Acme Freight", "domain": "acmefreight.com"},
        },
        # FN: same company but no clean shared domain -> oracle abstains.
        {
            "id": "t3",
            "kind": "positive",
            "same": True,
            "left": {"ref": "a:3", "name": "Globex", "domain": ""},
            "right": {"ref": "b:3", "name": "Globex", "domain": "globex.io"},
        },
    ]
    r = evaluate(EntityDeterministicJudge(), tiny)
    assert r["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 1}
    assert r["precision"] == 1.0
    assert r["recall"] == 0.5
    assert r["false_merge_rate"] == 0.0
    assert r["corpus"] == {
        "total": 3,
        "positives": 2,
        "hard_negatives": 1,
        "easy_negatives": 0,
        "negatives": 1,
    }
    assert [m["id"] for m in r["missed_examples"]] == ["t3"]
    assert r["false_merges"] == []
