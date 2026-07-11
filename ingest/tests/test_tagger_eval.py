"""Metric #5 (tagger recall) harness tests.

Asserts the metric arithmetic on a tiny hand-built fixture (perfect-tag, false-tag,
missed-tag), that the harness reuses the SHIPPED echo (not a reimplementation),
and that it scores the full checked-in corpus without error.
"""

from __future__ import annotations

import json
from pathlib import Path

from verity_ingest.tagger_eval import (
    Confusion,
    ExampleResult,
    evaluate,
    predict_tags,
)


# --------------------------------------------------------------------------
# predict_tags reuses the real DeterministicExtractor echo
# --------------------------------------------------------------------------


def test_predict_tags_uses_real_echo() -> None:
    # Named account tagged; distractor absent from content is not; pronoun-only
    # is not tagged (no name in the text).
    tags = predict_tags(
        "Acme wants a demo. They asked about pricing.",
        ["account:acme", "account:globex"],
    )
    assert tags == {"account:acme"}


def test_predict_tags_short_bare_name_skipped() -> None:
    # bare name < 3 chars is dropped as noise by the shipped echo.
    tags = predict_tags("Bo joined the call.", ["x:bo"])
    assert tags == set()


def test_predict_tags_common_word_false_positive() -> None:
    # The echo has no word-sense: 'box' the word triggers account:box.
    tags = predict_tags("The box turned green in CI.", ["account:box"])
    assert tags == {"account:box"}


# --------------------------------------------------------------------------
# Metric arithmetic on a tiny fixture
# --------------------------------------------------------------------------


def _write_corpus(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "tiny.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


def test_perfect_tag_case(tmp_path: Path) -> None:
    corpus = _write_corpus(
        tmp_path,
        [
            {
                "id": "t0",
                "category": "single_entity",
                "content": "Acme signed today.",
                "expected_tags": ["account:acme"],
                "distractor_entities": ["account:globex"],
            }
        ],
    )
    r = evaluate(corpus)
    assert r["confusion"] == {"tp": 1, "fp": 0, "fn": 0}
    assert r["precision"] == 1.0
    assert r["recall"] == 1.0
    assert r["f1"] == 1.0
    assert r["distractor_fp_rate"] == 0.0
    assert r["exact_examples"] == 1
    assert r["false_tag_examples"] == []
    assert r["missed_examples"] == []


def test_false_tag_case(tmp_path: Path) -> None:
    # 'box' the common word is present but no account is meant: a false tag.
    corpus = _write_corpus(
        tmp_path,
        [
            {
                "id": "t0",
                "category": "common_word",
                "content": "The box turned green in CI.",
                "expected_tags": [],
                "distractor_entities": ["account:box"],
            }
        ],
    )
    r = evaluate(corpus)
    assert r["confusion"] == {"tp": 0, "fp": 1, "fn": 0}
    # precision over a false tag with no true positives -> 0.0
    assert r["precision"] == 0.0
    # no expected tags at all -> recall is vacuously 1.0
    assert r["recall"] == 1.0
    assert r["distractor_fp_rate"] == 1.0  # 1 of 1 distractor wrongly tagged
    assert r["distractor_tagged"] == 1
    assert len(r["false_tag_examples"]) == 1
    assert r["false_tag_examples"][0]["false_tags"] == ["account:box"]
    assert r["exact_examples"] == 0


def test_missed_tag_case(tmp_path: Path) -> None:
    # Abbreviation the exact-name echo cannot reach: a missed tag.
    corpus = _write_corpus(
        tmp_path,
        [
            {
                "id": "t0",
                "category": "partial_name",
                "content": "IBM wants a volume discount.",
                "expected_tags": ["account:international-business-machines"],
                "distractor_entities": ["account:acme"],
            }
        ],
    )
    r = evaluate(corpus)
    assert r["confusion"] == {"tp": 0, "fp": 0, "fn": 1}
    # no tags suggested at all -> precision vacuously 1.0
    assert r["precision"] == 1.0
    assert r["recall"] == 0.0
    assert r["f1"] == 0.0
    assert r["distractor_fp_rate"] == 0.0
    assert len(r["missed_examples"]) == 1
    assert r["missed_examples"][0]["missed_tags"] == [
        "account:international-business-machines"
    ]


def test_mixed_corpus_aggregates(tmp_path: Path) -> None:
    # perfect + false + missed together: tp=1, fp=1, fn=1.
    corpus = _write_corpus(
        tmp_path,
        [
            {
                "id": "perfect",
                "category": "single_entity",
                "content": "Acme signed today.",
                "expected_tags": ["account:acme"],
                "distractor_entities": ["account:globex"],
            },
            {
                "id": "false",
                "category": "common_word",
                "content": "The box turned green in CI.",
                "expected_tags": [],
                "distractor_entities": ["account:box"],
            },
            {
                "id": "missed",
                "category": "partial_name",
                "content": "IBM wants a discount.",
                "expected_tags": ["account:international-business-machines"],
                "distractor_entities": ["account:acme"],
            },
        ],
    )
    r = evaluate(corpus)
    assert r["confusion"] == {"tp": 1, "fp": 1, "fn": 1}
    assert r["precision"] == 0.5  # 1 / (1+1)
    assert r["recall"] == 0.5  # 1 / (1+1)
    assert abs(r["f1"] - 0.5) < 1e-9
    assert r["corpus"]["total"] == 3
    assert r["corpus"]["examples_with_no_expected_tag"] == 1
    assert r["distractor_tagged"] == 1


# --------------------------------------------------------------------------
# Confusion unit behavior
# --------------------------------------------------------------------------


def test_confusion_set_arithmetic() -> None:
    c = Confusion()
    c.observe(
        predicted={"account:acme", "account:box"},
        expected={"account:acme"},
        distractors={"account:box", "account:globex"},
    )
    assert (c.tp, c.fp, c.fn) == (1, 1, 0)
    assert c.distractor_total == 2
    assert c.distractor_tagged == 1
    assert c.distractor_fp_rate == 0.5
    assert c.precision == 0.5
    assert c.recall == 1.0


def test_confusion_vacuous_precision_recall() -> None:
    # Nothing predicted, nothing expected: both vacuously perfect.
    c = Confusion()
    c.observe(predicted=set(), expected=set(), distractors={"account:acme"})
    assert c.precision == 1.0
    assert c.recall == 1.0
    assert c.distractor_fp_rate == 0.0


def test_example_result_exact_flag() -> None:
    ok = ExampleResult("i", "c", "x", ["a"], ["a"])
    assert ok.exact
    bad = ExampleResult("i", "c", "x", ["a"], ["a", "b"], false_tags=["b"])
    assert not bad.exact


# --------------------------------------------------------------------------
# The checked-in corpus scores without error and stays precision-first
# --------------------------------------------------------------------------


def test_full_corpus_scores() -> None:
    r = evaluate()  # default corpus path
    assert r["corpus"]["total"] >= 100
    # baseline invariant: precision-first — false tags stay bounded, and the
    # deterministic echo never tags a pronoun-only or clean 'none' snippet.
    assert 0.0 <= r["precision"] <= 1.0
    assert 0.0 <= r["recall"] <= 1.0
    assert r["confusion"]["tp"] > 0
    # per-category sanity: the 'none' and 'pronoun_only' categories are
    # zero-false-positive by construction of the echo.
    by_cat = r["corpus"]["by_category"]
    assert by_cat["none"]["fp"] == 0
    assert by_cat["pronoun_only"]["fp"] == 0
