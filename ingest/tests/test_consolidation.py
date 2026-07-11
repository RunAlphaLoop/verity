"""Consolidation worker tests (SPEC §2 L2 / knowledge, §7d — v0.3 task 33).

Fixture-driven: recorded lease payloads map to EXACT expected complete()
bodies under the DeterministicExtractor (the honest v0 every test uses).
Lease/complete HTTP is exercised through respx mocks, including the
re-lease-after-expiry idempotency path. The AnthropicExtractor's request
shape is verified against a respx mock of the Messages API; a live smoke
runs only when ANTHROPIC_API_KEY is present in the environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
import respx

from verity_ingest.consolidation import (
    ANTHROPIC_API_URL,
    ANTHROPIC_JUDGE_SCHEMA,
    ANTHROPIC_MODEL,
    AnthropicExtractor,
    AnthropicJudge,
    ConsolidationClient,
    DeterministicExtractor,
    DeterministicJudge,
    Extraction,
    JudgeExisting,
    KnowledgeCandidate,
    L2Fact,
    LeasedEpisode,
    TagSuggestion,
    build_extractor,
    build_judge,
    canonical_predicate,
    canonical_statement,
    decide_merges,
    run_once,
)
from verity_ingest.consolidation_eval import evaluate as evaluate_cascade

FIXTURES = Path(__file__).parent / "fixtures" / "consolidation"
BASE_URL = "http://verity.test:7717"
TENANT = "018f6b7a-aaaa-7000-8000-000000000000"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


def leased(name: str) -> LeasedEpisode:
    return LeasedEpisode.from_json(fixture(name)["episodes"][0])


# ---------- DeterministicExtractor: recorded payload -> exact complete body ----------


def test_observation_extracts_exact_complete_body() -> None:
    episode = leased("lease_observation.json")
    extraction = DeterministicExtractor().extract(episode)
    body = extraction.to_complete_body(TENANT, episode.episode_id)
    assert body == fixture("expected_complete_observation.json")


def test_doc_version_extracts_exact_complete_body() -> None:
    """No observation payload: text comes from the indexed chunks; the
    entity-tag echo stays silent when no known entity names the content."""
    episode = leased("lease_doc_version.json")
    extraction = DeterministicExtractor().extract(episode)
    body = extraction.to_complete_body(TENANT, episode.episode_id)
    assert body == fixture("expected_complete_doc_version.json")


def make_episode(text: str, entities: list[str] | None = None) -> LeasedEpisode:
    return LeasedEpisode(
        episode_id="018f6b7a-0000-7000-8000-0000000000ff",
        source="agent",
        source_entity=(entities or [None])[0],
        kind="observation",
        payload={"observation": text, "entities": entities or []},
        chunks=[],
    )


def test_no_generalization_marker_means_no_knowledge_candidate() -> None:
    extraction = DeterministicExtractor().extract(
        make_episode("Acme wants a demo next week.", ["account:acme"])
    )
    assert extraction.knowledge_candidates == []


def test_marker_sentences_dedupe_and_carry_episode_evidence() -> None:
    episode = make_episode(
        "Enterprise buyers always ask for SSO. Enterprise buyers always ask for SSO.",
        ["account:acme"],
    )
    extraction = DeterministicExtractor().extract(episode)
    assert len(extraction.knowledge_candidates) == 1
    cand = extraction.knowledge_candidates[0]
    assert cand.statement == "Enterprise buyers always ask for SSO."
    assert cand.evidence == [episode.episode_id]


def test_tag_echo_skips_already_tagged_and_short_names() -> None:
    episode = LeasedEpisode(
        episode_id="e",
        source="agent",
        source_entity=None,
        kind="observation",
        payload={"observation": "Acme and Bo met.", "entities": ["account:acme", "x:bo"]},
        chunks=[
            LeasedEpisode.from_json(
                {
                    "episode_id": "e",
                    "source": "agent",
                    "source_entity": None,
                    "kind": "observation",
                    "payload": None,
                    "chunks": [
                        {
                            "chunk_id": "c-tagged",
                            "content": "Acme and Bo met.",
                            "entity_tags": ["account:acme"],
                        },
                        {"chunk_id": "c-bare", "content": "Acme and Bo met.", "entity_tags": []},
                    ],
                }
            ).chunks[i]
            for i in range(2)
        ],
    )
    extraction = DeterministicExtractor().extract(episode)
    # account:acme suggested only for the untagged chunk; "bo" (< 3 chars
    # bare name) is skipped as false-positive noise.
    assert [(t.chunk_id, t.tag, t.confidence) for t in extraction.tag_suggestions] == [
        ("c-bare", "account:acme", 0.95)
    ]


# ---------- lease/complete client against respx mocks ----------


@respx.mock
def test_run_once_leases_extracts_and_completes_exactly() -> None:
    lease_route = respx.post(f"{BASE_URL}/v1/admin/consolidation/lease").mock(
        return_value=httpx.Response(200, json=fixture("lease_observation.json"))
    )
    complete_route = respx.post(f"{BASE_URL}/v1/admin/consolidation/complete").mock(
        return_value=httpx.Response(
            200,
            json={
                "episode_id": "018f6b7a-0000-7000-8000-000000000001",
                "l2_facts": {"inserted": 2, "superseded": 0, "unchanged": 0},
                "tag_suggestions": {"suggested": 1, "auto_applied": 0},
                "knowledge": [{"knowledge_id": "k", "merged": False, "status": "candidate"}],
            },
        )
    )
    client = ConsolidationClient(BASE_URL)

    completed = run_once(client, TENANT, DeterministicExtractor(), limit=8)

    assert completed == 1
    lease_body = json.loads(lease_route.calls.last.request.content)
    assert lease_body == {"tenant_id": TENANT, "limit": 8, "worker": "verity-ingest"}
    complete_body = json.loads(complete_route.calls.last.request.content)
    assert complete_body == fixture("expected_complete_observation.json")


@respx.mock
def test_release_after_expiry_is_idempotent() -> None:
    """A worker that crashed after complete() can be handed the same episode
    again once its lease expires; the server acknowledges the replay with
    already_processed and the worker treats it as done."""
    respx.post(f"{BASE_URL}/v1/admin/consolidation/lease").mock(
        side_effect=[
            httpx.Response(200, json=fixture("lease_observation.json")),
            # Re-lease after expiry: same episode handed out again.
            httpx.Response(200, json=fixture("lease_observation.json")),
        ]
    )
    complete_route = respx.post(f"{BASE_URL}/v1/admin/consolidation/complete").mock(
        side_effect=[
            httpx.Response(200, json={"episode_id": "e", "knowledge": []}),
            httpx.Response(200, json={"already_processed": True}),
        ]
    )
    client = ConsolidationClient(BASE_URL)
    extractor = DeterministicExtractor()

    assert run_once(client, TENANT, extractor) == 1
    assert run_once(client, TENANT, extractor) == 1  # replay: no error, no dupes

    first = json.loads(complete_route.calls[0].request.content)
    second = json.loads(complete_route.calls[1].request.content)
    assert first == second, "the replayed complete body must be identical"


@respx.mock
def test_admin_token_rides_as_bearer() -> None:
    route = respx.post(f"{BASE_URL}/v1/admin/consolidation/lease").mock(
        return_value=httpx.Response(200, json={"episodes": []})
    )
    client = ConsolidationClient(BASE_URL, admin_token="sekrit")
    assert client.lease(TENANT) == []
    assert route.calls.last.request.headers["authorization"] == "Bearer sekrit"


@respx.mock
def test_complete_error_bubbles() -> None:
    respx.post(f"{BASE_URL}/v1/admin/consolidation/complete").mock(
        return_value=httpx.Response(422, text="episode was never leased")
    )
    client = ConsolidationClient(BASE_URL)
    with pytest.raises(httpx.HTTPStatusError):
        client.complete(TENANT, "nope", Extraction())


# ---------- serialization details ----------


def test_complete_body_shapes() -> None:
    extraction = Extraction(
        l2_facts=[L2Fact("s", "r", "o"), L2Fact("s", "r", "o2", valid_from="2026-01-01T00:00:00Z")],
        tag_suggestions=[TagSuggestion("c", "t", 0.5)],
        knowledge_candidates=[KnowledgeCandidate("stmt", ["cat"], ["ep"])],
    )
    body = extraction.to_complete_body("t", "e")
    assert body["l2_facts"][0] == {
        "subject": "s",
        "relation": "r",
        "object": "o",
        "canonical_predicate": "r",
    }
    assert body["l2_facts"][1]["valid_from"] == "2026-01-01T00:00:00Z"
    assert body["l2_facts"][1]["canonical_predicate"] == "r"
    assert body["tag_suggestions"] == [{"chunk_id": "c", "tag": "t", "confidence": 0.5}]
    assert body["knowledge_candidates"] == [
        {
            "statement": "stmt",
            "categories": ["cat"],
            "evidence": ["ep"],
            "canonical_statement": "stmt",
        }
    ]


# ---------- canonicalization (knowledge-merge-tuning.md §3) ----------

# The DPA trio from the live-smoke finding: three paraphrases of ONE
# generalization (DPA-before-security-review) that MiniLM cosine could not
# merge (A·B 0.62, A·C 0.68, B·C 0.49). Canonicalization must collapse them.
DPA_TRIO = [
    "Enterprise security teams always require a signed DPA before they will begin a security review.",
    "Enterprise accounts consistently require a Data Processing Agreement to be signed before any security assessment can proceed.",
    "Procurement teams consistently block the security review until the data processing agreement (DPA) is executed.",
]


def test_dpa_trio_collapses_to_one_canonical_form() -> None:
    forms = {canonical_statement(s) for s in DPA_TRIO}
    assert len(forms) == 1, f"DPA paraphrases must share a canonical form, got {forms}"
    (form,) = forms
    # Sanity: the collapsed form is the expected stable predication.
    assert form == "segment_buyer requires signed_dpa before security_review"


def test_distinct_generalizations_do_not_over_normalize() -> None:
    """DON'T fuse "requires DPA" and "requires SOC 2" — a false merge is the
    failure the design forbids (knowledge-merge-tuning.md §1)."""
    dpa = canonical_statement("Enterprise customers always require a DPA before security review.")
    soc2 = canonical_statement(
        "Enterprise customers always require a SOC 2 report before security review."
    )
    assert dpa != soc2, "distinct required artifacts must stay distinct"
    assert "signed_dpa" in dpa
    assert "soc" in soc2


def test_canonical_statement_is_deterministic_and_order_insensitive() -> None:
    a = canonical_statement("Enterprise buyers require a signed DPA before security review.")
    b = canonical_statement("Enterprise buyers require a signed DPA before security review.")
    assert a == b
    # Whitespace/case/article variants collapse identically.
    c = canonical_statement("enterprise   buyers require   the signed dpa before   the security review")
    assert a == c


def test_canonical_predicate_aligns_requires_variants() -> None:
    """The finding: "requires" and "requires_before_security_assessment" must
    both key to the SAME canonical predicate so L2 supersession aligns."""
    assert canonical_predicate("requires") == "requires"
    assert canonical_predicate("requires_before_security_assessment") == "requires_before"
    assert canonical_predicate("require a DPA before the security review") == "requires_before"
    assert canonical_predicate("blocks until") == "blocks_until"
    assert canonical_predicate("is") == "is"


def test_canonical_predicate_slugs_unknown_relations_deterministically() -> None:
    assert canonical_predicate("Renewal Stage") == "renewal_stage"
    # Never lost: an unmappable relation still produces a stable key.
    assert canonical_predicate("!!!") == "relates_to"


def test_dataclasses_autofill_canonical_fields() -> None:
    """Constructing without canonical fields derives them deterministically."""
    fact = L2Fact("Acme", "requires a DPA before security review", "yes")
    assert fact.canonical_predicate == "requires_before"
    cand = KnowledgeCandidate("Enterprise buyers always require a DPA before security review.")
    assert cand.canonical_statement == "segment_buyer requires signed_dpa before security_review"
    # Explicit values are respected (the model's own canonical form wins).
    fact2 = L2Fact("Acme", "stage", "renewal", canonical_predicate="is")
    assert fact2.canonical_predicate == "is"


# ---------- AnthropicExtractor (seam; live call only when the key exists) ----------


def test_anthropic_extractor_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_extractor("anthropic")
    # Deterministic path needs no key.
    assert isinstance(build_extractor("deterministic"), DeterministicExtractor)


@respx.mock
def test_anthropic_extractor_request_shape_and_mapping() -> None:
    structured = {
        "l2_facts": [
            {
                "subject": "Acme Corp",
                "relation": "stage",
                "object": "renewal",
                "canonical_predicate": "is",
            }
        ],
        "tag_suggestions": [
            {"chunk_id": "018f6b7a-0000-7000-8000-00000000000a", "tag": "account:acme", "confidence": 0.9},
            # An invented chunk id must be dropped, never forwarded.
            {"chunk_id": "made-up", "tag": "account:acme", "confidence": 0.9},
        ],
        "knowledge_candidates": [
            {
                "statement": "Healthcare customers consistently need DPAs.",
                "categories": ["industry:healthcare"],
                "canonical_statement": "segment_buyer requires signed_dpa",
            }
        ],
    }
    route = respx.post(ANTHROPIC_API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": json.dumps(structured)}],
                "stop_reason": "end_turn",
            },
        )
    )
    episode = leased("lease_observation.json")
    extractor = AnthropicExtractor(api_key="test-key")

    extraction = extractor.extract(episode)

    request = route.calls.last.request
    assert request.headers["x-api-key"] == "test-key"
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(request.content)
    assert body["model"] == ANTHROPIC_MODEL
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["messages"][0]["role"] == "user"
    # The schema ALSO requires the canonical fields — assert the request shape.
    schema = body["output_config"]["format"]["schema"]
    l2_props = schema["properties"]["l2_facts"]["items"]
    assert "canonical_predicate" in l2_props["properties"]
    assert "canonical_predicate" in l2_props["required"]
    kc_props = schema["properties"]["knowledge_candidates"]["items"]
    assert "canonical_statement" in kc_props["properties"]
    assert "canonical_statement" in kc_props["required"]

    assert [(f.subject, f.relation, f.object) for f in extraction.l2_facts] == [
        ("Acme Corp", "stage", "renewal")
    ]
    # The model's canonical_predicate rides through unchanged.
    assert extraction.l2_facts[0].canonical_predicate == "is"
    assert [t.chunk_id for t in extraction.tag_suggestions] == [
        "018f6b7a-0000-7000-8000-00000000000a"
    ]
    cand = extraction.knowledge_candidates[0]
    assert cand.evidence == [episode.episode_id], "evidence is attributed client-side"
    assert cand.canonical_statement == "segment_buyer requires signed_dpa"


@respx.mock
def test_anthropic_refusal_yields_empty_extraction() -> None:
    respx.post(ANTHROPIC_API_URL).mock(
        return_value=httpx.Response(200, json={"content": [], "stop_reason": "refusal"})
    )
    extraction = AnthropicExtractor(api_key="test-key").extract(leased("lease_observation.json"))
    assert extraction.to_complete_body(TENANT, "e")["l2_facts"] == []


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set; skipping live Messages API smoke",
)
def test_anthropic_extractor_live_smoke() -> None:
    episode = leased("lease_observation.json")
    extraction = AnthropicExtractor().extract(episode)
    # Loose assertions: a live model is not deterministic, the seam is.
    body = extraction.to_complete_body(TENANT, episode.episode_id)
    assert set(body) == {"tenant_id", "episode_id", "l2_facts", "tag_suggestions", "knowledge_candidates"}


# ---------- the JUDGE (knowledge-merge-tuning.md §2, stage 2) ----------


def _existing(statement: str) -> JudgeExisting:
    return JudgeExisting(knowledge_id="k-existing", statement=statement)


def test_deterministic_judge_merges_dpa_paraphrases() -> None:
    """The DPA trio: three paraphrases of ONE generalization the cosine blocker
    could not merge. The DeterministicJudge says SAME on all pairs."""
    j = DeterministicJudge()
    a, b, c = DPA_TRIO
    assert j.judge(KnowledgeCandidate(b), _existing(a)).same
    assert j.judge(KnowledgeCandidate(c), _existing(a)).same
    assert j.judge(KnowledgeCandidate(c), _existing(b)).same
    verdict = j.judge(KnowledgeCandidate(b), _existing(a))
    assert verdict.reason  # a reason is always recorded


def test_deterministic_judge_keeps_distinct_artifacts_apart() -> None:
    """The precision guard: DPA vs SOC 2 vs pen-test vs BAA are DIFFERENT
    generalizations — the judge must say NOT SAME. A false merge here fabricates
    cross-customer support (knowledge-merge-tuning.md §1)."""
    j = DeterministicJudge()
    dpa = "enterprise buyers require a signed DPA before a security review"
    soc2 = "enterprise buyers require a current SOC 2 report before security review"
    pentest = "enterprise buyers require an annual third-party penetration test"
    baa = "healthcare accounts require a signed Business Associate Agreement before sharing patient data"
    for other in (soc2, pentest, baa):
        assert not j.judge(KnowledgeCandidate(dpa), _existing(other)).same
    # SOC2 vs pentest also distinct.
    assert not j.judge(KnowledgeCandidate(soc2), _existing(pentest)).same


def test_deterministic_judge_no_artifact_is_not_same() -> None:
    """Two statements with no controlled artifact don't merge on the rule leg
    (they'd need byte-identical canonical forms). Fail closed, not a guess."""
    j = DeterministicJudge()
    a = "SMB buyers are highly price-sensitive and churn on any price increase"
    b = "small businesses cancel quickly when prices are raised"
    # Distinct canonical forms, no artifact tokens → NOT SAME (a missed merge).
    assert not j.judge(KnowledgeCandidate(a), _existing(b)).same


@respx.mock
def test_decide_merges_sets_merge_into_on_judge_yes() -> None:
    """The worker flow: blocker returns a candidate set, the DeterministicJudge
    rules SAME on a true paraphrase, and decide_merges tags the candidate with
    merge_into + judge_reason."""
    existing_id = "018f6b7a-1111-7000-8000-000000000001"
    respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "knowledge_id": existing_id,
                        "statement": DPA_TRIO[0],
                        "categories": ["security"],
                        "cosine": 0.62,
                    }
                ]
            },
        )
    )
    client = ConsolidationClient(BASE_URL)
    cand = KnowledgeCandidate(DPA_TRIO[1], categories=["security"], evidence=["ep"])
    decide_merges(client, TENANT, DeterministicJudge(), [cand])
    assert cand.merge_into == existing_id
    assert cand.judge_reason
    # The judged fields ride through to the wire body.
    body = cand.to_json()
    assert body["merge_into"] == existing_id
    assert "judge_reason" in body


@respx.mock
def test_decide_merges_fails_closed_on_judge_no() -> None:
    """Blocker surfaces a topically-close but DISTINCT item (SOC 2 vs DPA); the
    judge says NO, so no merge_into is set (fresh candidate)."""
    respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "knowledge_id": "018f6b7a-2222-7000-8000-000000000002",
                        "statement": "enterprise buyers require a current SOC 2 report before security review",
                        "categories": ["security"],
                        "cosine": 0.55,
                    }
                ]
            },
        )
    )
    client = ConsolidationClient(BASE_URL)
    cand = KnowledgeCandidate(
        "enterprise buyers require a signed DPA before a security review",
        categories=["security"],
    )
    decide_merges(client, TENANT, DeterministicJudge(), [cand])
    assert cand.merge_into is None
    assert cand.to_json().get("merge_into") is None


@respx.mock
def test_decide_merges_empty_blocker_is_fresh() -> None:
    """Empty blocker set → no LLM call needed, no merge (fresh candidate)."""
    respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(200, json={"candidates": []})
    )
    client = ConsolidationClient(BASE_URL)
    cand = KnowledgeCandidate(DPA_TRIO[0], categories=["security"])
    decide_merges(client, TENANT, DeterministicJudge(), [cand])
    assert cand.merge_into is None


@respx.mock
def test_decide_merges_degrades_when_blocker_unavailable() -> None:
    """LLM/blocker unavailable (server error) → no auto-merge, never a bare
    low-threshold merge. The candidate stays fresh; the worker does not raise."""
    respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(503, text="down")
    )
    client = ConsolidationClient(BASE_URL)
    cand = KnowledgeCandidate(DPA_TRIO[0], categories=["security"])
    decide_merges(client, TENANT, DeterministicJudge(), [cand])  # must not raise
    assert cand.merge_into is None


@respx.mock
def test_run_once_with_judge_wires_the_cascade() -> None:
    """run_once(..., judge=) calls merge-candidates between extract and complete
    and forwards the judged merge in the complete body."""
    existing_id = "018f6b7a-3333-7000-8000-000000000003"
    respx.post(f"{BASE_URL}/v1/admin/consolidation/lease").mock(
        return_value=httpx.Response(
            200,
            json={
                "episodes": [
                    {
                        "episode_id": "018f6b7a-0000-7000-8000-000000000009",
                        "source": "agent",
                        "source_entity": "cust-b",
                        "kind": "observation",
                        "payload": {
                            "observation": (
                                "Enterprise accounts consistently require a Data Processing "
                                "Agreement to be signed before any security assessment can proceed."
                            ),
                            "entities": ["cust-b"],
                        },
                        "chunks": [],
                    }
                ]
            },
        )
    )
    mc = respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(
            200,
            json={"candidates": [{"knowledge_id": existing_id, "statement": DPA_TRIO[0]}]},
        )
    )
    complete_route = respx.post(f"{BASE_URL}/v1/admin/consolidation/complete").mock(
        return_value=httpx.Response(200, json={"episode_id": "e", "knowledge": []})
    )
    client = ConsolidationClient(BASE_URL)
    completed = run_once(client, TENANT, DeterministicExtractor(), judge=DeterministicJudge())
    assert completed == 1
    assert mc.called
    body = json.loads(complete_route.calls.last.request.content)
    assert body["knowledge_candidates"][0]["merge_into"] == existing_id
    assert body["knowledge_candidates"][0]["judge_reason"]


@respx.mock
def test_run_once_without_judge_proposes_no_merge() -> None:
    """No judge → no blocker call, no merge_into (the server still runs its own
    deterministic canonical-exact fast path)."""
    respx.post(f"{BASE_URL}/v1/admin/consolidation/lease").mock(
        return_value=httpx.Response(200, json=fixture("lease_observation.json"))
    )
    mc = respx.post(f"{BASE_URL}/v1/admin/consolidation/merge-candidates").mock(
        return_value=httpx.Response(200, json={"candidates": []})
    )
    respx.post(f"{BASE_URL}/v1/admin/consolidation/complete").mock(
        return_value=httpx.Response(200, json={"episode_id": "e", "knowledge": []})
    )
    client = ConsolidationClient(BASE_URL)
    run_once(client, TENANT, DeterministicExtractor())  # judge defaults to None
    assert not mc.called


def test_build_judge_selects_and_none_is_llm_free() -> None:
    assert isinstance(build_judge("deterministic"), DeterministicJudge)
    with pytest.raises(ValueError):
        build_judge("bogus")


def test_anthropic_judge_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_judge("anthropic")


@respx.mock
def test_anthropic_judge_request_shape_and_parse() -> None:
    route = respx.post(ANTHROPIC_API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": json.dumps({"same_generalization": True, "reason": "same DPA gate"})}
                ],
                "stop_reason": "end_turn",
            },
        )
    )
    j = AnthropicJudge(api_key="test-key")
    verdict = j.judge(KnowledgeCandidate(DPA_TRIO[1]), _existing(DPA_TRIO[0]))
    assert verdict.same and verdict.reason == "same DPA gate"
    body = json.loads(route.calls.last.request.content)
    assert body["model"] == ANTHROPIC_MODEL
    assert body["output_config"]["format"]["schema"] == ANTHROPIC_JUDGE_SCHEMA
    assert route.calls.last.request.headers["x-api-key"] == "test-key"


@respx.mock
def test_anthropic_judge_fails_closed_on_error() -> None:
    """Any transport/parse error or a refusal → NOT SAME (never a merge)."""
    respx.post(ANTHROPIC_API_URL).mock(return_value=httpx.Response(500, text="boom"))
    assert not AnthropicJudge(api_key="k").judge(KnowledgeCandidate("a"), _existing("b")).same
    respx.post(ANTHROPIC_API_URL).mock(
        return_value=httpx.Response(200, json={"content": [], "stop_reason": "refusal"})
    )
    assert not AnthropicJudge(api_key="k").judge(KnowledgeCandidate("a"), _existing("b")).same


# ---------- metric #6: the DeterministicJudge cascade beats the cosine baseline ----------


def test_deterministic_judge_cascade_metric6_precision_and_recall() -> None:
    """Run the cascade decision over the 206-pair eval set. The trust contract:
    precision 1.0 (zero false merges — DPA vs SOC2 etc. stay separate) and recall
    materially above the ~11% cosine baseline at the precision-preserving
    frontier (knowledge-merge-tuning.md §4)."""
    r = evaluate_cascade()
    assert r["confusion"]["fp"] == 0, f"false merges: {r['false_merges']}"
    assert r["precision"] == 1.0
    assert r["false_merge_rate"] == 0.0
    # Materially beats the 11% cosine recall. (Measured ~0.30 for this judge.)
    assert r["recall"] > 0.11, f"recall {r['recall']:.4f} must beat the cosine baseline"
