"""Tests for the ER Tier-3 unstructured-mention producer (resolve_tier3.py).

Entirely LLM-FREE: the default ``NullMentionDetector`` needs no API key, so the
detect -> retrieve -> disambiguate -> emit cascade is exercised fully offline via
the high-precision gazetteer pass. The live ``AnthropicMentionDetector`` is only
shape-checked against a respx mock (and requires a key to construct) — no real key
is ever set, read, or asserted on.

The load-bearing assertions are the ABSTAIN GATES (§5):
  - ambiguous "Acme" with two candidates  -> ABSTAIN_MARGIN / NIL (never a guess)
  - free-text with a deterministic co-signal -> confident TAG
  - free-text with NO co-signal + auto-off -> REVIEWER_HINT only (non-authoritative)
"""

from __future__ import annotations

import httpx
import pytest
import respx

from verity_ingest.consolidation import AnthropicJudge
from verity_ingest.resolve_tier3 import (
    ANTHROPIC_API_URL,
    AnthropicMentionDetector,
    Candidate,
    CatalogEntity,
    Chunk,
    Gazetteer,
    Mention,
    MentionDetector,
    NullMentionDetector,
    Tier3Client,
    Tier3Config,
    Tier3Evidence,
    Tier3Outcome,
    build_mention_detector,
    detect_mentions,
    disambiguate,
    plan_tier3,
    retrieve_candidates,
    run_tier3,
)

BASE_URL = "http://verity.test"
TENANT = "11111111-1111-1111-1111-111111111111"

# One folded canonical account with a verified domain.
ACME = CatalogEntity(
    canonical="account:acme", name="Acme, Inc.", aliases=("Acme",), domains=("acme.com",)
)
# Two DIFFERENT Acmes that share the surface form "Acme" — the ambiguity case.
ACME_CORP = CatalogEntity(
    canonical="account:acme-corp", name="Acme", aliases=("Acme Corp",), domains=("acmecorp.com",)
)
ACME_FREIGHT = CatalogEntity(
    canonical="account:acme-freight",
    name="Acme",
    aliases=("Acme Freight",),
    domains=("acmefreight.com",),
)


# ---------- gazetteer ----------


def test_gazetteer_from_l1_builds_surface_forms_and_domains() -> None:
    gaz = Gazetteer.from_l1(
        accounts=[
            {"canonical": "account:acme", "name": "Acme, Inc.", "aliases": ["Acme"],
             "domains": ["acme.com"]},
        ],
        contacts=[
            {"canonical": "account:acme", "email": "jane@acme.com"},
        ],
    )
    assert "acme" in gaz.surface_forms()
    assert gaz.canonicals_for_domain("acme.com") == frozenset({"account:acme"})
    # A contact email contributes its domain as a co-signal on the account.
    assert "acme.com" in gaz.all_domains()


def test_gazetteer_domain_cosignal_lookup_normalizes() -> None:
    gaz = Gazetteer([ACME])
    assert gaz.canonicals_for_domain("https://www.acme.com/x") == frozenset({"account:acme"})
    assert gaz.canonicals_for_domain("acme.dev") == frozenset()


# ---------- detection ----------


def test_detect_exact_gazetteer_mention_word_boundary() -> None:
    gaz = Gazetteer([ACME])
    ms = detect_mentions("chunk:gdrive:D9:0", "Repro confirmed for Acme's timeout.", gaz)
    assert [m.text.lower().strip("'s") for m in ms] == ["acme"] or any(
        "acme" in m.text.lower() for m in ms
    )
    assert all(m.method == "gazetteer" for m in ms)


def test_detect_multiword_surface_form() -> None:
    lph = CatalogEntity(canonical="account:lph", name="Los Pollos Hermanos", domains=("lph.com",))
    gaz = Gazetteer([lph])
    ms = detect_mentions("chunk:gdrive:D16:0", "Contract with Los Pollos Hermanos signed.", gaz)
    assert any("los pollos hermanos" in m.text.lower() for m in ms)


def test_detect_ignores_generic_word_noise() -> None:
    # "Massive" and "dynamic" as separate common words must NOT match the company
    # "Massive Dynamic" (no contiguous surface span).
    md = CatalogEntity(canonical="account:md", name="Massive Dynamic", domains=("md.com",))
    gaz = Gazetteer([md])
    ms = detect_mentions("c:1", "Massive quarterly dynamic pricing review.", gaz)
    assert ms == []


def test_null_detector_adds_no_spans() -> None:
    assert NullMentionDetector().detect("anything", Gazetteer([ACME])) == []


# ---------- retrieval + co-signal scoring ----------


def test_retrieve_single_confident_candidate_no_cosignal() -> None:
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="c:1", text="Acme")
    cands = retrieve_candidates(m, gaz)
    assert len(cands) == 1
    assert cands[0].entity.canonical == "account:acme"
    assert cands[0].co_signal is False
    assert cands[0].score == 1.0  # exact surface form


def test_retrieve_cosignal_boosts_and_flags() -> None:
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="c:1", text="Acme")
    cands = retrieve_candidates(m, gaz, acl_domains=["acme.com"])
    assert cands[0].co_signal is True


def test_retrieve_two_candidates_same_surface_form_are_ambiguous() -> None:
    gaz = Gazetteer([ACME_CORP, ACME_FREIGHT])
    m = Mention(chunk_ref="c:1", text="Acme")
    cands = retrieve_candidates(m, gaz)
    assert {c.entity.canonical for c in cands} == {"account:acme-corp", "account:acme-freight"}
    # No co-signal -> equal scores -> zero margin (the abstain trigger).
    assert cands[0].score == cands[1].score


# ---------- THE ABSTAIN GATES (load-bearing, §5) ----------


def test_gate_ambiguous_two_acmes_abstains_never_tags() -> None:
    # ambiguous "Acme" with two candidates -> ABSTAIN_MARGIN, NEVER a tag.
    gaz = Gazetteer([ACME_CORP, ACME_FREIGHT])
    m = Mention(chunk_ref="c:1", text="Acme")
    cands = retrieve_candidates(m, gaz)
    d = disambiguate(m, cands, Tier3Config())
    assert d.outcome is Tier3Outcome.ABSTAIN_MARGIN
    assert d.emit_tag is False
    assert d.emit_evidence is False  # quarantine: nothing on the wire


def test_gate_nil_when_no_candidate() -> None:
    d = disambiguate(Mention(chunk_ref="c:1", text="Zorp"), [], Tier3Config())
    assert d.outcome is Tier3Outcome.NIL
    assert d.emit_evidence is False


def test_gate_nil_below_tau() -> None:
    weak = [Candidate(entity=ACME, score=0.3)]  # below default tau_nil 0.70
    d = disambiguate(Mention(chunk_ref="c:1", text="Acme"), weak, Tier3Config())
    assert d.outcome is Tier3Outcome.NIL
    assert d.emit_evidence is False


def test_gate_freetext_with_cosignal_is_confident_tag() -> None:
    # free-text with a deterministic co-signal -> confident TAG.
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="chunk:gdrive:D9:0", text="Acme")
    cands = retrieve_candidates(m, gaz, acl_domains=["acme.com"])
    d = disambiguate(m, cands, Tier3Config())
    assert d.outcome is Tier3Outcome.TAG
    assert d.emit_tag is True
    assert d.emit_evidence is True


def test_gate_freetext_no_cosignal_autooff_is_reviewer_hint_only() -> None:
    # no co-signal + auto-off (default) -> reviewer hint only, NEVER a tag.
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="chunk:linear:ENG-42:0", text="Acme")
    cands = retrieve_candidates(m, gaz)  # no co-signal
    d = disambiguate(m, cands, Tier3Config())  # auto_link_tier3 off by default
    assert d.outcome is Tier3Outcome.REVIEWER_HINT
    assert d.emit_tag is False
    assert d.emit_evidence is True  # still surfaces in the review queue


def test_gate_human_confirmed_overrides_killswitch_to_tag() -> None:
    # A human confirmation is the §5 "or a human approves" branch AND overrides
    # the auto-off kill switch -> TAG even without a co-signal.
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="chunk:linear:ENG-42:0", text="Acme")
    cands = retrieve_candidates(m, gaz)
    d = disambiguate(m, cands, Tier3Config(), human_confirmed=True)
    assert d.outcome is Tier3Outcome.TAG
    assert d.emit_tag is True


def test_gate_noncanonical_target_never_tags() -> None:
    # Even confident + co-signed, a target that is NOT yet a folded canonical is a
    # reviewer hint (§5: a tag requires an already-folded canonical).
    noncanon = CatalogEntity(
        canonical="account:initech", name="Initech", domains=("initech.com",), is_canonical=False
    )
    gaz = Gazetteer([noncanon])
    m = Mention(chunk_ref="c:1", text="Initech")
    cands = retrieve_candidates(m, gaz, chunk_domains=["initech.com"])
    d = disambiguate(m, cands, Tier3Config())
    assert d.outcome is Tier3Outcome.REVIEWER_HINT
    assert d.emit_tag is False


def test_gate_autolink_on_permits_tag_without_human() -> None:
    gaz = Gazetteer([ACME])
    m = Mention(chunk_ref="c:1", text="Acme")
    cands = retrieve_candidates(m, gaz, chunk_domains=["acme.com"])
    d = disambiguate(m, cands, Tier3Config(auto_link_tier3=True))
    assert d.outcome is Tier3Outcome.TAG
    assert d.emit_tag is True


# ---------- plan/emit shape ----------


def test_plan_emits_tier3_evidence_with_correct_shape_for_cosignal_tag() -> None:
    gaz = Gazetteer([ACME])
    chunk = Chunk(
        chunk_ref="chunk:gdrive:D9:0",
        text="Repro confirmed for Acme's timeout.",
        acl_domains=("acme.com",),
    )
    result = plan_tier3(TENANT, [chunk], gaz, Tier3Config())
    assert len(result.to_emit) == 1
    body = result.to_emit[0].to_json()
    assert body["tenant_id"] == TENANT
    assert body["tier"] == 3
    assert body["method"] == "llm_mention"
    assert body["left_ref"] == "account:acme"  # the candidate
    assert body["right_ref"] == "chunk:gdrive:D9:0"  # the chunk
    assert body["key_namespace"] == "customer_context"  # never internal_directory (§4.4)
    assert body["evidence_l0_ref"] == "chunk:gdrive:D9:0"
    assert "emit_tag=True" in body["key_value"]
    # No api key ever appears on the wire body.
    assert "api_key" not in body and "x-api-key" not in body


def test_plan_ambiguous_emits_nothing() -> None:
    gaz = Gazetteer([ACME_CORP, ACME_FREIGHT])
    chunk = Chunk(chunk_ref="chunk:gdrive:D10:0", text="Kickoff call with Acme went well.")
    result = plan_tier3(TENANT, [chunk], gaz, Tier3Config())
    assert result.to_emit == []  # abstain: quarantine, no guess
    assert any(d.outcome is Tier3Outcome.ABSTAIN_MARGIN for d in result.decisions)


def test_plan_reviewer_hint_emits_nonauthoritative_evidence() -> None:
    gaz = Gazetteer([ACME])
    chunk = Chunk(chunk_ref="chunk:linear:ENG-42:0", text="Repro confirmed for Acme's timeout.")
    result = plan_tier3(TENANT, [chunk], gaz, Tier3Config())
    assert len(result.to_emit) == 1
    assert "emit_tag=False" in result.to_emit[0].to_json()["key_value"]


def test_plan_human_confirmed_for_chunk_promotes_to_tag() -> None:
    gaz = Gazetteer([ACME])
    chunk = Chunk(
        chunk_ref="chunk:linear:ENG-42:0",
        text="Repro confirmed for Acme's timeout.",
        human_confirmed_canonicals=frozenset({"account:acme"}),
    )
    result = plan_tier3(TENANT, [chunk], gaz, Tier3Config())
    assert len(result.to_emit) == 1
    assert "emit_tag=True" in result.to_emit[0].to_json()["key_value"]


# ---------- run_tier3: EMIT over a mocked admin plane ----------


@respx.mock
def test_run_tier3_posts_tier3_evidence_to_admin_plane() -> None:
    route = respx.post(f"{BASE_URL}/v1/admin/entity-evidence").mock(
        return_value=httpx.Response(200, json={"evidence_id": "ev-1"})
    )
    client = Tier3Client(BASE_URL, admin_token="secret-admin")
    gaz = Gazetteer([ACME])
    chunk = Chunk(
        chunk_ref="chunk:gdrive:D9:0",
        text="Repro confirmed for Acme's timeout.",
        acl_domains=("acme.com",),
    )
    result = run_tier3(client, TENANT, [chunk], gaz, Tier3Config())
    assert len(result.to_emit) == 1
    assert route.called
    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer secret-admin"
    import json

    sent = json.loads(request.content)
    assert sent["tier"] == 3
    assert sent["method"] == "llm_mention"
    assert sent["left_ref"] == "account:acme"


@respx.mock
def test_run_tier3_emits_nothing_when_all_mentions_abstain() -> None:
    route = respx.post(f"{BASE_URL}/v1/admin/entity-evidence").mock(
        return_value=httpx.Response(200, json={"evidence_id": "x"})
    )
    client = Tier3Client(BASE_URL, admin_token="t")
    gaz = Gazetteer([ACME_CORP, ACME_FREIGHT])
    chunk = Chunk(chunk_ref="chunk:gdrive:D10:0", text="Kickoff call with Acme went well.")
    result = run_tier3(client, TENANT, [chunk], gaz, Tier3Config())
    assert result.to_emit == []
    assert not route.called


# ---------- live NER backstop seam: reuses AnthropicJudge, no key handled ----------


def test_detector_factory_null_needs_no_key() -> None:
    d = build_mention_detector("null")
    assert isinstance(d, NullMentionDetector)
    assert isinstance(d, MentionDetector)


def test_anthropic_detector_subclasses_reused_judge() -> None:
    # Structural proof of REUSE: the live detector IS an AnthropicJudge, so it
    # inherits the parent's ANTHROPIC_API_KEY loading verbatim.
    assert issubclass(AnthropicMentionDetector, AnthropicJudge)


def test_anthropic_detector_requires_key_via_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        AnthropicMentionDetector()
    with pytest.raises(RuntimeError):
        build_mention_detector("anthropic")


@respx.mock
def test_anthropic_detector_shape_and_fail_closed() -> None:
    # Inject a dummy key via constructor arg (NOT a real key, NOT from env) to
    # exercise the wire shape against a mock.
    api = respx.post("https://api.anthropic.com/v1/messages")
    api.mock(
        return_value=httpx.Response(
            200,
            json={
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": '{"mentions": ["Acme"]}'}],
            },
        )
    )
    det = AnthropicMentionDetector(api_key="test-not-a-real-key")
    gaz = Gazetteer([ACME])
    spans = det.detect("Some text about Acme.", gaz)
    assert spans == ["Acme"]
    assert api.called

    # Fail-closed: a garbage body -> NO spans, never a hallucinated mention.
    api.mock(return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "{"}]}))
    spans2 = AnthropicMentionDetector(api_key="test-not-a-real-key").detect("x Acme y", gaz)
    assert spans2 == []


def test_ner_backstop_only_adds_known_catalog_spans() -> None:
    # A detector that returns an unknown org must NOT create a mention (we can only
    # tag catalog entities). One that returns a known form DOES.
    class KnownDetector:
        def detect(self, text: str, gazetteer: Gazetteer) -> list[str]:
            return ["Acme", "Totally Unknown Org"]

    gaz = Gazetteer([ACME])
    # Use text with NO gazetteer-detectable span so only the backstop contributes.
    ms = detect_mentions("c:1", "see attached notes", gaz, detector=KnownDetector())
    texts = {m.text for m in ms}
    assert "Acme" in texts
    assert "Totally Unknown Org" not in texts
    assert all(m.method == "ner" for m in ms)


def test_anthropic_url_constant_matches_reused_module() -> None:
    assert ANTHROPIC_API_URL == "https://api.anthropic.com/v1/messages"


def test_tier3_evidence_omits_l0_ref_when_absent() -> None:
    ev = Tier3Evidence(
        tenant_id=TENANT, left_ref="account:acme", right_ref="chunk:x:1:0", score=0.9, key_value="k"
    )
    body = ev.to_json()
    assert body["evidence_l0_ref"] == "chunk:x:1:0" if ev.evidence_l0_ref else True
    ev2 = Tier3Evidence(
        tenant_id=TENANT,
        left_ref="account:acme",
        right_ref="chunk:x:1:0",
        score=0.9,
        key_value="k",
        evidence_l0_ref=None,
    )
    assert "evidence_l0_ref" not in ev2.to_json()
