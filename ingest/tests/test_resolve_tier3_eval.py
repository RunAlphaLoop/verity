"""Tests for the ER Tier-3 mention producer eval harness (resolve_tier3_eval.py).

Entirely LLM-FREE. Runs ``evaluate(cases)`` with the deterministic (gazetteer-only)
detector over the checked-in fixture (NO API key), asserting the load-bearing
property — an AMBIGUOUS mention is NEVER tagged (``ambiguous_tags == 0``) — plus
overall decision accuracy on the labeled set. Also checks the harness arithmetic
on a tiny hand-verified set, mirroring the tier-2 eval test.

No real key is set, read, or asserted on anywhere in this file.
"""

from __future__ import annotations

from verity_ingest.resolve_tier3_eval import evaluate, load_cases


# ---------------------------------------------------------------------------
# The load-bearing property: NO ambiguous mention is ever tagged, on the whole set.
# ---------------------------------------------------------------------------


def test_no_ambiguous_mention_is_ever_tagged() -> None:
    cases = load_cases()
    rep = evaluate(cases)
    # Abstain-as-security: tagging the wrong 'Acme' mis-files content into a real
    # customer's scope. The ambiguous case (two candidates) must abstain, never tag.
    assert rep.ambiguous_tags == 0, [
        (m.case_id, m.canonical, m.predicted) for m in rep.per_mention if m.ambiguous
    ]


def test_shipped_pipeline_matches_all_labels() -> None:
    cases = load_cases()
    rep = evaluate(cases)
    wrong = [(m.case_id, m.canonical, m.expected, m.predicted) for m in rep.per_mention if not m.correct]
    assert rep.accuracy == 1.0, wrong
    assert rep.cases_all_correct == rep.total_cases, wrong


def test_no_tag_false_positives() -> None:
    # Every emitted `tag` in the labeled set was expected to be a tag (no chunk
    # tagged for a wrong-outcome entity).
    cases = load_cases()
    rep = evaluate(cases)
    assert rep.tag_false_positives == 0


def test_corpus_covers_every_outcome() -> None:
    # The fixture must exercise ALL FOUR two-decision outcomes (nil, abstain,
    # reviewer_hint, tag) so the gates are all under test.
    cases = load_cases()
    rep = evaluate(cases)
    oc = rep.outcome_counts
    assert oc.get("tag", 0) > 0
    assert oc.get("reviewer_hint", 0) > 0
    assert oc.get("abstain_margin", 0) > 0
    # NIL is exercised via the empty-expect cases (unknown org / below-tau); those
    # emit nothing, so assert those cases exist and stayed empty.
    empty_cases = [c for c in cases if not c.get("expect")]
    assert len(empty_cases) >= 2


# ---------------------------------------------------------------------------
# Harness arithmetic on a tiny hand-verified set.
# ---------------------------------------------------------------------------


def test_evaluate_tiny_confident_cosignal_tag() -> None:
    tiny = [
        {
            "id": "t1",
            "kind": "tag_with_cosignal",
            "catalog": [
                {"canonical": "account:acme", "name": "Acme, Inc.", "aliases": ["Acme"],
                 "domains": ["acme.com"], "is_canonical": True}
            ],
            "chunk": {
                "chunk_ref": "chunk:gdrive:D9:0",
                "text": "Acme timeout repro.",
                "acl_domains": ["acme.com"],
            },
            "expect": {"account:acme": "tag"},
        }
    ]
    rep = evaluate(tiny)
    assert rep.total_mentions == 1
    assert rep.correct == 1
    assert rep.accuracy == 1.0
    assert rep.ambiguous_tags == 0
    assert rep.outcome_counts.get("tag") == 1


def test_evaluate_tiny_ambiguous_abstains() -> None:
    tiny = [
        {
            "id": "t2",
            "kind": "margin_abstain",
            "catalog": [
                {"canonical": "account:acme-corp", "name": "Acme", "domains": ["acmecorp.com"],
                 "is_canonical": True},
                {"canonical": "account:acme-freight", "name": "Acme", "domains": ["acmefreight.com"],
                 "is_canonical": True},
            ],
            "chunk": {"chunk_ref": "chunk:gdrive:D10:0", "text": "Kickoff with Acme."},
            "expect": {"account:acme-corp": "abstain_margin", "account:acme-freight": "abstain_margin"},
        }
    ]
    rep = evaluate(tiny)
    assert rep.ambiguous_tags == 0
    assert rep.outcome_counts.get("abstain_margin") == 2
    assert rep.accuracy == 1.0


def test_evaluate_tiny_unknown_org_is_empty() -> None:
    tiny = [
        {
            "id": "t3",
            "kind": "nil_no_candidate",
            "catalog": [
                {"canonical": "account:acme", "name": "Acme", "domains": ["acme.com"],
                 "is_canonical": True}
            ],
            "chunk": {"chunk_ref": "chunk:gdrive:D13:0", "text": "Zorp Robotics onboarding."},
            "expect": {},
        }
    ]
    rep = evaluate(tiny)
    # No mention detected -> no graded mention -> case counted correct (empty & no emit).
    assert rep.cases_all_correct == 1
    assert rep.total_mentions == 0
