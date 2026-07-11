"""Regression gate for the key-independence sweep (resolve_keys_sweep) — pins
the per-kind single-key false-merge numbers measured on the checked-in stress
corpus, so a fixture or scorer change that silently alters the §10 Q2 answer
fails loudly.

Entirely LLM-FREE and offline (deterministic scorers only, no key, no network).
The pinned numbers were produced by running
``python -m verity_ingest.resolve_keys_sweep`` on the 103-pair fixture
(47 positives / 52 hard negatives / 4 easy negatives) — a SYNTHETIC,
HAND-LABELED STRESS SET, not a natural distribution. The pins are exact on
purpose: this corpus is versioned test data, and the zero/nonzero FMR
distinction per key kind IS the design decision (external_id=1, domain=2,
email=2 for account edges).
"""

from __future__ import annotations

import pytest

from verity_ingest.resolve_keys_sweep import (
    POLICIES,
    domain_key,
    email_key,
    evaluate_kind_alone,
    evaluate_policy,
    external_id_key,
    matching_kinds,
    merges_under,
    run_sweep,
)
from verity_ingest.resolve_tier2_eval import load_pairs


@pytest.fixture(scope="module")
def sweep() -> dict:
    return run_sweep(load_pairs())


# ---------------------------------------------------------------------------
# THE regression gate: per-kind single-key-alone FMR pins.
# ---------------------------------------------------------------------------


def test_external_id_alone_has_zero_false_merges(sweep: dict) -> None:
    # The load-bearing zero: exact NAMESPACED external_id equality fused no
    # stress negative (cross-namespace collision er-0087 and same-namespace
    # near-miss er-0088 both refused). This is what justifies
    # min_independent_keys=1 for external_id.
    k = sweep["per_kind_alone"]["external_id"]
    assert k["confusion"]["fp"] == 0, k["false_merges"]
    assert k["false_merge_rate_eligible"] == 0.0
    assert k["false_merge_rate_all_negatives"] == 0.0
    # And it is not vacuous: eligible negatives exist and were refused.
    assert k["eligible_negatives"] == 3


def test_domain_alone_false_merge_pins(sweep: dict) -> None:
    # A lone shared domain fuses every domain-shared-but-distinct stress
    # negative (er-0069..er-0082): parents/subsidiaries, brands, franchise,
    # agency, coworking, PEO, marketplace, ISP, university, acquisition. This
    # nonzero FMR is what justifies keeping min_independent_keys=2 for domain.
    k = sweep["per_kind_alone"]["domain"]
    assert k["confusion"]["fp"] == 14
    assert {e["id"] for e in k["false_merges"]} == {f"er-{n:04d}" for n in range(69, 83)}
    assert k["eligible_negatives"] == 51
    assert k["false_merge_rate_eligible"] == pytest.approx(14 / 51)
    assert k["false_merge_rate_all_negatives"] == pytest.approx(14 / 56)


def test_email_alone_false_merge_pins(sweep: dict) -> None:
    # A lone shared customer-contact email fuses the shared-human negatives
    # (fractional CFO er-0083, serial founder er-0084, agency contact er-0085)
    # — but NOT the role-local er-0086, which the denylist refuses as a key.
    # This nonzero FMR is why email needs a second key for ACCOUNT merges,
    # contra fold.rs's current email_exact strong-key exemption.
    k = sweep["per_kind_alone"]["email"]
    assert k["confusion"]["fp"] == 3
    assert {e["id"] for e in k["false_merges"]} == {"er-0083", "er-0084", "er-0085"}
    assert k["eligible_negatives"] == 4  # er-0086 excluded: role local ⇒ no key
    assert k["false_merge_rate_eligible"] == pytest.approx(3 / 4)
    assert k["false_merge_rate_all_negatives"] == pytest.approx(3 / 56)


# ---------------------------------------------------------------------------
# Recall-cost pins: what a 2-key bar forgoes, per kind (deferred to review).
# ---------------------------------------------------------------------------


def test_lone_key_positive_counts(sweep: dict) -> None:
    per = sweep["per_kind_alone"]
    # 36 true pairs are domain-only (the 32 legacy shared-domain positives that
    # carry a usable domain, minus none, plus er-0094..er-0097).
    assert per["domain"]["lone_key_positive_count"] == 36
    # 4 crosswalk-only true positives (er-0090..er-0093).
    assert per["external_id"]["lone_key_positives"] == [
        "er-0090",
        "er-0091",
        "er-0092",
        "er-0093",
    ]
    # 4 contact-email-only true positives (er-0098..er-0101).
    assert per["email"]["lone_key_positives"] == [
        "er-0098",
        "er-0099",
        "er-0100",
        "er-0101",
    ]


# ---------------------------------------------------------------------------
# Policy sweep pins: the recommended per-kind policy holds FMR 0; the email=1
# variant (fold.rs's current strong_method behavior) leaks.
# ---------------------------------------------------------------------------


def test_recommended_policy_has_zero_false_merges_and_measured_recall(sweep: dict) -> None:
    r = sweep["policies"]["per_kind_email2"]  # external_id=1, domain=2, email=2
    assert r["confusion"]["fp"] == 0, r["false_merges"]
    assert r["precision"] == 1.0
    assert r["false_merge_rate"] == 0.0
    # Auto-merge recall is deliberately low (6/47): external_id-only ×4 plus
    # the two-key pairs er-0102/er-0103. Everything else defers to review.
    assert r["confusion"]["tp"] == 6
    assert r["recall"] == pytest.approx(6 / 47)


def test_email_strong_exemption_would_leak(sweep: dict) -> None:
    # per_kind_email1 mirrors fold.rs's current email_exact strong-key
    # exemption applied to account↔account edges: it admits the 3 shared-human
    # false merges. The measured reason to amend the exemption.
    r = sweep["policies"]["per_kind_email1"]
    assert r["confusion"]["fp"] == 3
    assert r["false_merge_rate"] == pytest.approx(3 / 56)


def test_uniform_policies_bracket_the_tradeoff(sweep: dict) -> None:
    lo = sweep["policies"]["uniform_min1"]
    hi = sweep["policies"]["uniform_min2"]
    # min1 everywhere: high recall, leaks 17 scope merges (14 domain + 3 email).
    assert lo["confusion"]["fp"] == 17
    assert lo["false_merge_rate"] == pytest.approx(17 / 56)
    assert lo["recall"] == pytest.approx(46 / 47)
    # min2 everywhere: zero leaks, but forgoes even clean external_id
    # crosswalks (only the two-key pairs merge).
    assert hi["confusion"]["fp"] == 0
    assert hi["confusion"]["tp"] == 2
    assert hi["false_merge_rate"] == 0.0


# ---------------------------------------------------------------------------
# Scorer unit behavior (the fences the numbers depend on).
# ---------------------------------------------------------------------------


def test_domain_key_refuses_freemail_and_empty() -> None:
    assert domain_key({"domain": "acme.com"}) == "acme.com"
    assert domain_key({"domain": "https://www.acme.com/x"}) == "acme.com"
    assert domain_key({"domain": "gmail.com"}) is None  # free-mail denylist
    assert domain_key({"domain": ""}) is None
    assert domain_key({}) is None
    # ISP/shared-infra domains are NOT denylisted — the structural guard, not
    # the denylist, must catch those (er-0076).
    assert domain_key({"domain": "comcast.net"}) == "comcast.net"


def test_email_key_refuses_role_locals_but_keeps_freemail_addresses() -> None:
    assert email_key({"email": "Jane.Doe@Acme.com"}) == "jane.doe@acme.com"
    assert email_key({"email": "info@sharedspaces.com"}) is None  # role local
    assert email_key({"email": "sales@x.com"}) is None
    # A free-mail ADDRESS names one person (unlike the bare domain) — kept as a
    # key; er-0084 then shows why it still may not weld alone.
    assert email_key({"email": "jsmith.builds@gmail.com"}) == "jsmith.builds@gmail.com"
    assert email_key({"email": "not-an-email"}) is None
    assert email_key({}) is None


def test_external_id_key_is_namespaced_exact() -> None:
    a = {"external_id": {"namespace": "hubspot_company_id", "value": "88213"}}
    b = {"external_id": {"namespace": "netsuite_customer_id", "value": "88213"}}
    assert external_id_key(a) == ("hubspot_company_id", "88213")
    assert external_id_key(a) != external_id_key(b)  # er-0087: ns fences value
    assert external_id_key({"external_id": {"namespace": "x", "value": ""}}) is None
    assert external_id_key({}) is None


def test_matching_kinds_and_merges_under_arithmetic() -> None:
    pair = {
        "left": {
            "domain": "ashgrove.com",
            "email": "t@ashgrove.com",
            "external_id": {"namespace": "n", "value": "1"},
        },
        "right": {
            "domain": "ashgrove.com",
            "email": "t@ashgrove.com",
            "external_id": {"namespace": "n", "value": "2"},
        },
    }
    assert matching_kinds(pair) == frozenset({"domain", "email"})
    # Two distinct kinds satisfy a min-2 policy; a lone min-2 kind does not.
    assert merges_under(frozenset({"domain", "email"}), POLICIES["uniform_min2"]) is True
    assert merges_under(frozenset({"domain"}), POLICIES["uniform_min2"]) is False
    assert merges_under(frozenset({"external_id"}), POLICIES["per_kind_email2"]) is True
    assert merges_under(frozenset(), POLICIES["uniform_min1"]) is False  # fail closed


def test_kind_alone_and_policy_math_on_tiny_hand_checked_set() -> None:
    tiny = [
        {  # TP under domain-alone.
            "id": "t1",
            "kind": "positive",
            "same": True,
            "left": {"name": "A", "domain": "a.com"},
            "right": {"name": "A Inc", "domain": "a.com"},
        },
        {  # FP under domain-alone (shared domain, distinct entities).
            "id": "t2",
            "kind": "hard_negative",
            "same": False,
            "left": {"name": "B", "domain": "shared.com"},
            "right": {"name": "C", "domain": "shared.com"},
        },
        {  # TN under domain-alone (distinct domains).
            "id": "t3",
            "kind": "hard_negative",
            "same": False,
            "left": {"name": "D", "domain": "d.com"},
            "right": {"name": "E", "domain": "e.com"},
        },
        {  # FN under domain-alone (no domain), TP under external_id-alone.
            "id": "t4",
            "kind": "positive",
            "same": True,
            "left": {"name": "F", "external_id": {"namespace": "n", "value": "9"}},
            "right": {"name": "F", "external_id": {"namespace": "n", "value": "9"}},
        },
    ]
    dom = evaluate_kind_alone(tiny, "domain")
    assert dom["confusion"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert dom["eligible_negatives"] == 2
    assert dom["false_merge_rate_eligible"] == 0.5
    assert dom["lone_key_positives"] == ["t1"]

    ext = evaluate_kind_alone(tiny, "external_id")
    assert ext["confusion"] == {"tp": 1, "fp": 0, "tn": 2, "fn": 1}
    assert ext["lone_key_positives"] == ["t4"]

    rec = evaluate_policy(tiny, {"external_id": 1, "domain": 2, "email": 2})
    assert rec["confusion"] == {"tp": 1, "fp": 0, "tn": 2, "fn": 1}
    assert rec["forgone_true_pairs"] == ["t1"]
