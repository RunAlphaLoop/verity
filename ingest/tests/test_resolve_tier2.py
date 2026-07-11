"""Tests for the ER Tier-2 candidate producer (resolve_tier2.py).

Entirely LLM-FREE: the default ``EntityDeterministicJudge`` needs no API key, so
the blocker -> judge -> emit cascade is exercised fully offline. The live
``EntityAnthropicJudge`` is only shape-checked against a respx mock (and is
skipped without a key) — no real key is ever set, read, or asserted on.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from verity_ingest.consolidation import AnthropicJudge, JudgeVerdict
from verity_ingest.resolve_tier2 import (
    ANTHROPIC_API_URL,
    CandidatePair,
    Entity,
    EntityAnthropicJudge,
    EntityDeterministicJudge,
    EntityJudge,
    Tier2Client,
    Tier2Evidence,
    block_candidates,
    block_score,
    build_entity_judge,
    normalize_domain,
    normalize_name,
    plan_tier2,
    run_tier2,
)

BASE_URL = "http://verity.test"
TENANT = "11111111-1111-1111-1111-111111111111"


# A small fixture population: SF Acme + HubSpot Acme (same, share acme.com),
# an internal-ish acme.dev record (different domain), and an unrelated Globex.
ACME_SF = Entity(ref="salesforce:001xACME", name="Acme, Inc.", domain="https://www.acme.com")
ACME_HS = Entity(ref="hubspot:4207", name="Acme", domain="acme.com")
ACME_DEV = Entity(ref="linear:org-0a2f", name="Acme", domain="acme.dev")
GLOBEX = Entity(ref="hubspot:9001", name="Globex Corporation", domain="globex.io")


# ---------- normalizers ----------


def test_normalize_name_strips_legal_suffix_and_punct() -> None:
    assert normalize_name("Acme, Inc.") == "acme"
    assert normalize_name("Acme") == "acme"
    assert normalize_name("Globex Corporation") == "globex"


def test_normalize_domain_from_url_and_email() -> None:
    assert normalize_domain("https://www.acme.com/path?x=1") == "acme.com"
    assert normalize_domain("jane@acme.dev") == "acme.dev"
    assert normalize_domain("ACME.com:443") == "acme.com"
    assert normalize_domain("") == ""


# ---------- (1) BLOCKER ----------


def test_blocker_finds_fuzzy_name_and_domain_pairs() -> None:
    cands = block_candidates([ACME_SF, ACME_HS, GLOBEX])
    keys = {c.pair_key for c in cands}
    # Acme SF <-> Acme HS block (shared domain + name); neither blocks Globex.
    assert (min(ACME_SF.ref, ACME_HS.ref), max(ACME_SF.ref, ACME_HS.ref)) in keys
    assert all("hubspot:9001" not in k for k in keys)


def test_blocker_exact_shared_domain_floors_score_high() -> None:
    assert block_score(ACME_SF, ACME_HS) >= 0.90


def test_blocker_pairs_are_ordered_and_deterministic() -> None:
    a = block_candidates([ACME_SF, ACME_HS, ACME_DEV, GLOBEX])
    b = block_candidates([GLOBEX, ACME_DEV, ACME_HS, ACME_SF])
    assert [c.pair_key for c in a] == [c.pair_key for c in b]
    for c in a:
        assert c.left.ref <= c.right.ref


def test_blocker_excludes_already_merged_pairs() -> None:
    merged = [(ACME_SF.ref, ACME_HS.ref)]  # fold already merged these Tier-1
    cands = block_candidates([ACME_SF, ACME_HS, ACME_DEV], already_merged=merged)
    keys = {c.pair_key for c in cands}
    assert (min(ACME_SF.ref, ACME_HS.ref), max(ACME_SF.ref, ACME_HS.ref)) not in keys


def test_blocker_excludes_anti_linked_pairs_either_order() -> None:
    # Human said acme.com and acme.dev are NOT the same -> never re-propose,
    # passed in either ref order.
    anti = [(ACME_DEV.ref, ACME_HS.ref)]
    cands = block_candidates([ACME_HS, ACME_DEV], anti_linked=anti)
    assert cands == []


# ---------- (2) JUDGE (deterministic, no key) ----------


def test_deterministic_judge_same_on_shared_domain_and_name() -> None:
    v = EntityDeterministicJudge().judge(ACME_SF, ACME_HS)
    assert v.same is True
    assert "acme.com" in v.reason


def test_deterministic_judge_not_same_on_distinct_domains() -> None:
    # acme.com vs acme.dev -> different registrable domains -> NOT SAME (§7).
    v = EntityDeterministicJudge().judge(ACME_HS, ACME_DEV)
    assert v.same is False


def test_deterministic_judge_abstains_without_shared_domain() -> None:
    # Names fuzz-match but no clean shared domain -> ambiguous -> abstain.
    left = Entity(ref="drive:D9", name="Acme", domain="")
    v = EntityDeterministicJudge().judge(left, ACME_HS)
    assert v.same is False


def test_judge_is_pluggable_via_factory_no_key_needed() -> None:
    judge = build_entity_judge("deterministic")
    assert isinstance(judge, EntityDeterministicJudge)
    # Structurally satisfies the EntityJudge Protocol (identical to the
    # knowledge-merge Judge seam): a judge(...) -> JudgeVerdict method.
    assert isinstance(judge, EntityJudge)
    assert isinstance(judge.judge(ACME_SF, ACME_HS), JudgeVerdict)


# ---------- (3) plan/emit: precision-first gating ----------


def test_plan_emits_tier2_for_judged_same_with_correct_shape() -> None:
    result = plan_tier2(TENANT, [ACME_SF, ACME_HS, GLOBEX], EntityDeterministicJudge())
    assert len(result.to_emit) == 1
    ev = result.to_emit[0]
    body = ev.to_json()
    assert body["tenant_id"] == TENANT
    assert body["tier"] == 2
    assert body["method"] == "name+domain_fuzzy"
    assert body["left_ref"] <= body["right_ref"]
    assert {body["left_ref"], body["right_ref"]} == {ACME_SF.ref, ACME_HS.ref}
    assert isinstance(body["score"], float) and body["score"] >= 0.90
    assert "judge:" in body["key_value"]
    # No polarity/anti-link, and no api key ever appears on the wire body.
    assert "polarity" not in body  # default +1 server-side
    assert "api_key" not in body and "x-api-key" not in body


def test_uncertain_pair_produces_no_emit() -> None:
    # A name-fuzzy pair with NO shared clean domain: judge abstains -> no emit,
    # but the abstention is recorded in verdicts (audit of the no-emit).
    d9 = Entity(ref="drive:D9", name="Acme", domain="")
    result = plan_tier2(TENANT, [d9, ACME_HS], EntityDeterministicJudge())
    assert result.candidates  # blocker DID surface the fuzzy pair
    assert result.to_emit == []  # precision-first: abstain => nothing emitted
    assert result.verdicts and all(v.same is False for _, v in result.verdicts)


def test_distinct_domain_pair_blocks_but_judge_gates_it_out() -> None:
    # acme.com vs acme.dev: names identical so the blocker MAY surface them,
    # but the judge gates on distinct domains -> no emit.
    result = plan_tier2(TENANT, [ACME_HS, ACME_DEV], EntityDeterministicJudge())
    assert result.to_emit == []


def test_already_merged_pair_is_never_re_emitted() -> None:
    result = plan_tier2(
        TENANT,
        [ACME_SF, ACME_HS],
        EntityDeterministicJudge(),
        already_merged=[(ACME_SF.ref, ACME_HS.ref)],
    )
    assert result.candidates == []
    assert result.to_emit == []


# ---------- run_tier2: EMIT over a mocked admin plane ----------


@respx.mock
def test_run_tier2_posts_tier2_evidence_to_admin_plane() -> None:
    route = respx.post(f"{BASE_URL}/v1/admin/entity-evidence").mock(
        return_value=httpx.Response(200, json={"evidence_id": "ev-1"})
    )
    client = Tier2Client(BASE_URL, admin_token="secret-admin")
    result = run_tier2(client, TENANT, [ACME_SF, ACME_HS, GLOBEX], EntityDeterministicJudge())

    assert len(result.to_emit) == 1
    assert route.called
    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer secret-admin"
    import json

    sent = json.loads(request.content)
    assert sent["tier"] == 2
    assert sent["method"] == "name+domain_fuzzy"
    assert {sent["left_ref"], sent["right_ref"]} == {ACME_SF.ref, ACME_HS.ref}


@respx.mock
def test_run_tier2_emits_nothing_when_all_pairs_abstain() -> None:
    route = respx.post(f"{BASE_URL}/v1/admin/entity-evidence").mock(
        return_value=httpx.Response(200, json={"evidence_id": "x"})
    )
    client = Tier2Client(BASE_URL, admin_token="t")
    # acme.com vs acme.dev only: judge gates it out -> zero POSTs.
    result = run_tier2(client, TENANT, [ACME_HS, ACME_DEV], EntityDeterministicJudge())
    assert result.to_emit == []
    assert not route.called


# ---------- live judge seam: reuses AnthropicJudge, no key handled ----------


def test_entity_anthropic_judge_subclasses_reused_judge() -> None:
    # Structural proof of REUSE: the live entity judge IS an AnthropicJudge, so
    # it inherits the parent's ANTHROPIC_API_KEY loading verbatim.
    assert issubclass(EntityAnthropicJudge, AnthropicJudge)


def test_entity_anthropic_judge_requires_key_via_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    # No key in the environment -> parent __init__ raises. We never embed one.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        EntityAnthropicJudge()
    with pytest.raises(RuntimeError):
        build_entity_judge("anthropic")


@respx.mock
def test_entity_anthropic_judge_shape_and_fail_closed() -> None:
    # Inject a dummy key via constructor arg (NOT a real key, NOT from env) to
    # exercise the wire shape against a mock. Same fail-closed contract as the
    # knowledge judge: a SAME response merges, a malformed body fails closed.
    api = respx.post("https://api.anthropic.com/v1/messages")
    api.mock(
        return_value=httpx.Response(
            200,
            json={
                "stop_reason": "end_turn",
                "content": [
                    {
                        "type": "text",
                        "text": '{"same_generalization": true, "reason": "shared domain acme.com"}',
                    }
                ],
            },
        )
    )
    judge = EntityAnthropicJudge(api_key="test-not-a-real-key")
    verdict = judge.judge(ACME_SF, ACME_HS)
    assert isinstance(verdict, JudgeVerdict)
    assert verdict.same is True
    # It hit the reused Anthropic endpoint URL.
    assert api.called

    # Fail-closed: a garbage body -> NOT SAME, never a merge.
    api.mock(return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "{"}]}))
    v2 = EntityAnthropicJudge(api_key="test-not-a-real-key").judge(ACME_SF, ACME_HS)
    assert v2.same is False


def test_anthropic_judge_url_constant_matches_reused_module() -> None:
    # The live path reuses the knowledge module's endpoint constant.
    assert ANTHROPIC_API_URL == "https://api.anthropic.com/v1/messages"


def test_candidate_pair_key_is_order_independent() -> None:
    p1 = CandidatePair(left=ACME_SF, right=ACME_HS, score=0.9)
    assert p1.pair_key == (min(ACME_SF.ref, ACME_HS.ref), max(ACME_SF.ref, ACME_HS.ref))


def test_tier2_evidence_omits_l0_ref_when_absent() -> None:
    ev = Tier2Evidence(
        tenant_id=TENANT, left_ref="a:1", right_ref="b:2", score=0.9, key_value="k"
    )
    assert "evidence_l0_ref" not in ev.to_json()
    ev2 = Tier2Evidence(
        tenant_id=TENANT,
        left_ref="a:1",
        right_ref="b:2",
        score=0.9,
        key_value="k",
        evidence_l0_ref="l0:xyz",
    )
    assert ev2.to_json()["evidence_l0_ref"] == "l0:xyz"
