"""ER Tier-2 candidate PRODUCER — the probabilistic tier that populates the
review queue (cross-source-entity-resolution.md §4.2 S2, §5, §8; the
precision-first blocker→judge cascade of knowledge-merge-tuning.md).

The pipeline, three stages, mirrors the knowledge-merge cascade exactly:

    (1) BLOCKER  — cheap trigram/token-set similarity over normalized
        name+domain generates candidate PAIRS (recall-oriented; a miss here is
        unrecoverable so we lean liberal). Pairs that are ALREADY Tier-1 merged
        or ALREADY anti-linked are excluded — the fold has already decided them.
    (2) JUDGE    — each surviving pair goes to a PLUGGABLE judge whose interface
        is IDENTICAL to the knowledge-merge judge (``JudgeVerdict judge(...)``):
          - ``EntityDeterministicJudge`` — LLM-FREE, the honest oracle every
            test uses (NO API key). Precision-first: exact-domain + strong-name
            agreement => SAME; anything softer / ambiguous => NOT SAME.
          - ``EntityAnthropicJudge`` — the live seam. It SUBCLASSES the existing
            ``consolidation.AnthropicJudge`` so it REUSES that class's key
            loading (``ANTHROPIC_API_KEY`` from the operator's environment at
            runtime), httpx Messages-API call, structured-output parse, and
            fail-closed error handling VERBATIM — only the prompt is swapped for
            an entity-sameness prompt that keeps the identical strict
            "ties/uncertain => NO" posture. NO api key is embedded, printed, or
            handled here; the reused class reads it at construction time.
    (3) EMIT     — each judged-SAME pair POSTs tier=2 evidence to
        POST /v1/admin/entity-evidence with method="name+domain_fuzzy", the
        judge score, and the rationale. These land in the review queue and
        NEVER auto-merge: the fold requires a ``human_confirmed`` row before a
        Tier-2 edge forms (§4.2 S4, §6 defense 1). This producer only PROPOSES.

Precision-as-security (§3.2): a false merge unions two customers' scopes — a
leak, not a data nit. So under-emit is safe (a missed review candidate); an
uncertain judge emits NOTHING. That asymmetry governs every gate here.

Python is ingestion-only and never on the read path (CLAUDE.md); this producer
writes solely through the admin plane.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

import httpx

# REUSE the knowledge-merge judge machinery verbatim — do NOT reinvent it. The
# Tier-2 judge seam IS the knowledge-merge Judge seam: same JudgeVerdict, same
# strict fail-closed AnthropicJudge (whose key loading we inherit untouched).
from verity_ingest.consolidation import (
    ANTHROPIC_JUDGE_SCHEMA,
    ANTHROPIC_API_URL,
    ANTHROPIC_VERSION,
    AnthropicJudge,
    JudgeVerdict,
)

# ---------------------------------------------------------------------------
# S0-lite: normalize name + domain (deterministic).
#
# Entity resolution's blocker keys on normalized name+domain. This is a
# deliberately small, deterministic normalizer — NFKC-ish casefold, strip legal
# suffixes off names, registrable-ish domain off a URL/email — enough for cheap
# trigram/token-set blocking. It is a RECALL aid; the judge makes the decision.
# ---------------------------------------------------------------------------

# Legal suffixes stripped from company names before token-set comparison, so
# "Acme, Inc." and "Acme" block together. Never discriminative for identity.
_LEGAL_SUFFIXES = frozenset(
    {
        "inc",
        "incorporated",
        "llc",
        "llp",
        "ltd",
        "limited",
        "corp",
        "corporation",
        "co",
        "company",
        "plc",
        "gmbh",
        "sa",
        "ag",
        "nv",
        "bv",
        "srl",
        "spa",
        "pty",
        "group",
        "holdings",
        "the",
    }
)

_WWW = re.compile(r"^www\d*\.", re.IGNORECASE)


def normalize_name(name: str) -> str:
    """Casefold, strip punctuation and legal suffixes, collapse whitespace."""
    s = (name or "").casefold()
    s = re.sub(r"[^a-z0-9\s]+", " ", s)
    toks = [t for t in s.split() if t and t not in _LEGAL_SUFFIXES]
    return " ".join(toks)


def name_tokens(name: str) -> frozenset[str]:
    return frozenset(normalize_name(name).split())


def normalize_domain(domain: str) -> str:
    """Best-effort registrable domain from a raw domain / URL / email.

    Deterministic and dependency-free: strip scheme/path, take the host, drop a
    leading ``www``. Not a full Public Suffix List — the live S0 (Rust) owns
    PSL-correct eTLD+1; this is the blocker's cheap normalizer only."""
    d = (domain or "").strip().casefold()
    if not d:
        return ""
    if "@" in d:  # an email -> its domain
        d = d.rsplit("@", 1)[-1]
    d = re.sub(r"^[a-z]+://", "", d)  # strip scheme
    d = d.split("/", 1)[0]  # strip path
    d = d.split("?", 1)[0].split("#", 1)[0]
    d = d.split(":", 1)[0]  # strip port
    d = _WWW.sub("", d)
    return d.strip(".")


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """One per-source L1 entity to resolve. ``ref`` is the ledger ref shape
    ``source:entity_id`` (e.g. ``salesforce:001xACME``). ``name`` and
    ``domain`` are the identity material the blocker keys on; sourced from L1
    (via the API in production) or passed in for testability."""

    ref: str
    name: str = ""
    domain: str = ""


def _ordered(a: str, b: str) -> tuple[str, str]:
    """Canonical (left_ref, right_ref) ordering so a pair has ONE identity
    regardless of iteration order — matches the Rust producers' ``ordered``."""
    return (a, b) if a <= b else (b, a)


@dataclass(frozen=True)
class CandidatePair:
    """A blocker-proposed pair, ordered. ``score`` is the blocker similarity
    (0..1) carried onto the emitted evidence for audit."""

    left: Entity
    right: Entity
    score: float

    @property
    def pair_key(self) -> tuple[str, str]:
        return _ordered(self.left.ref, self.right.ref)


# ---------------------------------------------------------------------------
# (1) BLOCKER — trigram + token-set similarity over normalized name+domain.
# ---------------------------------------------------------------------------


def _trigrams(s: str) -> frozenset[str]:
    s = f"  {s} "
    return frozenset(s[i : i + 3] for i in range(len(s) - 2)) if len(s) >= 3 else frozenset({s})


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def block_score(left: Entity, right: Entity) -> float:
    """Cheap recall-oriented similarity of two entities on name+domain.

    max( token-set Jaccard on names, trigram Jaccard on names ) with a domain
    BOOST: an exact normalized-domain match is the strongest cheap signal, so it
    floors the score high (still recall-only — the judge decides). Distinct
    non-empty domains do NOT veto here (blocker is liberal); the judge weighs
    them. Returns 0..1."""
    ln, rn = normalize_name(left.name), normalize_name(right.name)
    name_sim = 0.0
    if ln and rn:
        name_sim = max(
            _jaccard(name_tokens(left.name), name_tokens(right.name)),
            _jaccard(_trigrams(ln), _trigrams(rn)),
        )
    ld, rd = normalize_domain(left.domain), normalize_domain(right.domain)
    if ld and rd and ld == rd:
        # Exact shared domain: floor high so the pair always blocks. MEDIUM key
        # per §1 — it BLOCKS the pair for the judge, it does not merge it.
        return max(name_sim, 0.90)
    return name_sim


def block_candidates(
    entities: Iterable[Entity],
    *,
    threshold: float = 0.45,
    already_merged: Iterable[tuple[str, str]] = (),
    anti_linked: Iterable[tuple[str, str]] = (),
) -> list[CandidatePair]:
    """Generate candidate PAIRS above ``threshold`` (recall-oriented, low bar),
    EXCLUDING pairs already Tier-1 merged or already anti-linked.

    ``already_merged`` / ``anti_linked`` are collections of ref pairs (either
    order). In production a caller sources them from the fold's current state
    (``entity_aliases`` membership + live ``polarity=-1`` evidence); passed in
    here for testability. Excluding them is not just efficiency — re-proposing a
    human "NOT the same" (anti-link) would churn the review queue on a decision
    already made (§6).
    """
    ents = list(entities)
    exclude = {_ordered(a, b) for a, b in already_merged}
    exclude |= {_ordered(a, b) for a, b in anti_linked}

    out: list[CandidatePair] = []
    for i in range(len(ents)):
        for j in range(i + 1, len(ents)):
            a, b = ents[i], ents[j]
            if a.ref == b.ref:
                continue
            if _ordered(a.ref, b.ref) in exclude:
                continue
            score = block_score(a, b)
            if score >= threshold:
                left, right = (a, b) if a.ref <= b.ref else (b, a)
                out.append(CandidatePair(left=left, right=right, score=round(score, 4)))
    # Deterministic order: strongest first, then by ref pair.
    out.sort(key=lambda c: (-c.score, c.pair_key))
    return out


# ---------------------------------------------------------------------------
# (2) JUDGE — pluggable, interface IDENTICAL to the knowledge-merge judge.
#
# The knowledge Judge is ``judge(proposed, existing) -> JudgeVerdict``. The
# entity judge is the SAME shape, ``judge(left, right) -> JudgeVerdict``, over
# two Entities. JudgeVerdict is REUSED verbatim from consolidation.
# ---------------------------------------------------------------------------


@runtime_checkable
class EntityJudge(Protocol):
    def judge(self, left: Entity, right: Entity) -> JudgeVerdict: ...


class EntityDeterministicJudge:
    """LLM-FREE entity judge — the honest oracle every test uses (NO API key).

    Precision-first, mirroring ``DeterministicJudge``'s posture:
      - SAME iff the two entities share an EXACT normalized domain AND their
        names are non-trivially compatible (token-set overlap OR one name-token
        set is a subset of the other — "Acme" ⊂ "Acme, Inc."). An exact shared
        registrable domain plus agreeing names is the strongest cheap
        deterministic signal of one company.
      - Distinct non-empty domains => NOT SAME (different registrable domains
        are different companies — the §7 ``acme.com`` vs ``acme.dev`` guard).
      - Missing a domain on either side, or names that merely fuzz-match without
        a shared domain => NOT SAME (ambiguous => abstain => no emit).
    It WILL miss same-company pairs that lack a shared clean domain (recall gap,
    the acceptable failure); the live EntityAnthropicJudge closes that without
    lowering precision."""

    def judge(self, left: Entity, right: Entity) -> JudgeVerdict:
        ld, rd = normalize_domain(left.domain), normalize_domain(right.domain)
        lt, rt = name_tokens(left.name), name_tokens(right.name)

        if ld and rd:
            if ld != rd:
                return JudgeVerdict(False, f"distinct domains {ld} vs {rd}")
            # Same domain. Require compatible names to guard free-mail-style
            # co-tenancy (though free-mail domains are denylisted upstream).
            if lt and rt and (lt & rt or lt <= rt or rt <= lt):
                return JudgeVerdict(True, f"exact shared domain {ld} + agreeing name")
            return JudgeVerdict(
                False, f"shared domain {ld} but names disagree; abstain (fail closed)"
            )
        # No clean domain on at least one side: names alone never merge here.
        return JudgeVerdict(
            False, "no exact shared domain; name-only match is ambiguous, abstain"
        )


# The entity-sameness prompt: same STRICT, precision-first, "ties/uncertain =>
# NO" posture as _JUDGE_PROMPT, retargeted from generalizations to entities.
_ENTITY_JUDGE_PROMPT = """\
You are a STRICT precision-first entity-resolution judge for an enterprise \
memory system. You are given two records, each a business entity (a company/ \
account) with a name and optional domain, drawn from different source systems. \
Decide whether they are THE SAME real-world entity — i.e. whether they should \
be proposed for merging into one canonical entity.

Rules:
- Answer SAME only if the evidence is strong: an exact shared registrable \
domain with compatible names, or names that unambiguously denote the same \
company. Legal-suffix and word-order differences ("Acme, Inc." vs "Acme") do \
NOT matter.
- Different registrable domains (e.g. acme.com vs acme.dev) usually mean \
DIFFERENT entities — answer NOT SAME unless the names make identity certain.
- A false merge unions two customers' data scopes — a security leak. So if you \
are uncertain, or it is a tie, answer NOT SAME. A missed merge is acceptable; a \
wrong merge is not.

Left entity:  name={left_name!r} domain={left_domain!r}
Right entity: name={right_name!r} domain={right_domain!r}

Return JSON {{"same_generalization": bool, "reason": "<one line>"}}."""


class EntityAnthropicJudge(AnthropicJudge):
    """Live entity judge — SUBCLASSES ``consolidation.AnthropicJudge`` so it
    REUSES that class's runtime key loading (``ANTHROPIC_API_KEY`` from the
    operator's environment; constructing WITHOUT a key raises, exactly as the
    parent does), its httpx Messages-API transport, structured-output schema,
    and fail-closed parse/error handling VERBATIM. This class adds ONLY the
    entity-sameness prompt — no key is embedded, printed, read from a literal,
    or handled here beyond the parent's env seam.

    The wire schema and fail-closed contract are the knowledge judge's: any
    parse/transport error or refusal => NOT SAME (never a merge)."""

    def judge(self, left: Entity, right: Entity) -> JudgeVerdict:
        prompt = _ENTITY_JUDGE_PROMPT.format(
            left_name=left.name,
            left_domain=left.domain,
            right_name=right.name,
            right_domain=right.domain,
        )
        try:
            response = self._client.post(
                ANTHROPIC_API_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 512,
                    "messages": [{"role": "user", "content": prompt}],
                    "output_config": {
                        "format": {"type": "json_schema", "schema": ANTHROPIC_JUDGE_SCHEMA}
                    },
                },
            )
            response.raise_for_status()
            body = response.json()
            if body.get("stop_reason") == "refusal":
                return JudgeVerdict(False, "judge refused; failing closed (no merge)")
            import json as _json

            text = next(b["text"] for b in body["content"] if b["type"] == "text")
            parsed = _json.loads(text)
            same = bool(parsed["same_generalization"])
            reason = str(parsed.get("reason", "")).strip() or "no reason given"
        except (httpx.HTTPError, KeyError, ValueError, StopIteration) as exc:
            return JudgeVerdict(False, f"judge error, failing closed: {exc}")
        return JudgeVerdict(same, reason)


def build_entity_judge(name: str) -> EntityJudge:
    """Judge factory, mirroring ``consolidation.build_judge``. ``deterministic``
    needs NO api key (the default/test path); ``anthropic`` constructs the live
    judge, which reads ``ANTHROPIC_API_KEY`` from the operator's environment."""
    if name == "deterministic":
        return EntityDeterministicJudge()
    if name == "anthropic":
        return EntityAnthropicJudge()
    raise ValueError(f"unknown entity judge {name!r}")


# ---------------------------------------------------------------------------
# (3) EMIT — POST tier=2 evidence to the admin plane.
# ---------------------------------------------------------------------------


@dataclass
class Tier2Evidence:
    """One tier=2 evidence row the producer will POST. Shape matches
    POST /v1/admin/entity-evidence exactly (§4.1/§8): tier=2,
    method="name+domain_fuzzy", the blocker ``score``, and the ``key_value``
    carrying the judge rationale for the audit row. ``polarity`` defaults to +1
    (a link proposal) — it still cannot merge without ``human_confirmed``."""

    tenant_id: str
    left_ref: str
    right_ref: str
    score: float
    key_value: str
    tier: int = 2
    method: str = "name+domain_fuzzy"
    evidence_l0_ref: str | None = None

    def to_json(self) -> dict:
        body: dict = {
            "tenant_id": self.tenant_id,
            "left_ref": self.left_ref,
            "right_ref": self.right_ref,
            "tier": self.tier,
            "method": self.method,
            "score": self.score,
            "key_value": self.key_value,
        }
        if self.evidence_l0_ref is not None:
            body["evidence_l0_ref"] = self.evidence_l0_ref
        return body


class Tier2Client:
    """Thin admin-plane client — POSTs tier=2 evidence to the review queue.

    Bearer admin token rides the header exactly like ``ConsolidationClient``.
    Does not touch any Anthropic key: the judge owns that seam."""

    def __init__(
        self,
        base_url: str,
        admin_token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        headers = {"authorization": f"Bearer {admin_token}"} if admin_token else {}
        self._client = client or httpx.Client(base_url=base_url, headers=headers, timeout=60.0)

    def emit(self, evidence: Tier2Evidence) -> dict:
        response = self._client.post("/v1/admin/entity-evidence", json=evidence.to_json())
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Public entrypoint: blocker -> judge -> (evidence). Pure planning is separated
# from the network EMIT so the whole cascade is testable offline.
# ---------------------------------------------------------------------------


@dataclass
class ProducerResult:
    """What one Tier-2 producer pass decided (before/without emitting)."""

    candidates: list[CandidatePair] = field(default_factory=list)
    to_emit: list[Tier2Evidence] = field(default_factory=list)
    # (pair_key, verdict) for every judged candidate — audit of no-emit too.
    verdicts: list[tuple[tuple[str, str], JudgeVerdict]] = field(default_factory=list)


def plan_tier2(
    tenant_id: str,
    entities: Iterable[Entity],
    judge: EntityJudge,
    *,
    threshold: float = 0.45,
    already_merged: Iterable[tuple[str, str]] = (),
    anti_linked: Iterable[tuple[str, str]] = (),
) -> ProducerResult:
    """Run BLOCKER -> JUDGE and PLAN the tier=2 evidence to emit (no network).

    Precision-first: only judged-SAME pairs become evidence. Uncertain / NO
    verdicts are recorded in ``verdicts`` for audit but produce NO evidence —
    the review queue is never polluted with a guess."""
    result = ProducerResult()
    result.candidates = block_candidates(
        entities,
        threshold=threshold,
        already_merged=already_merged,
        anti_linked=anti_linked,
    )
    for pair in result.candidates:
        verdict = judge.judge(pair.left, pair.right)
        result.verdicts.append((pair.pair_key, verdict))
        if not verdict.same:
            continue  # abstain / NOT SAME => no emit (safe under-merge)
        left, right = pair.pair_key  # ordered
        result.to_emit.append(
            Tier2Evidence(
                tenant_id=tenant_id,
                left_ref=left,
                right_ref=right,
                score=pair.score,
                key_value=f"name+domain_fuzzy; judge: {verdict.reason}",
            )
        )
    return result


def run_tier2(
    client: Tier2Client,
    tenant_id: str,
    entities: Iterable[Entity],
    judge: EntityJudge,
    *,
    threshold: float = 0.45,
    already_merged: Iterable[tuple[str, str]] = (),
    anti_linked: Iterable[tuple[str, str]] = (),
) -> ProducerResult:
    """The full producer pass: plan, then EMIT each judged-SAME pair as tier=2
    evidence to the review queue. Returns the plan (with what was emitted).

    Nothing here auto-merges: tier=2 evidence only surfaces for human review;
    the fold requires a ``human_confirmed`` row before an edge forms."""
    result = plan_tier2(
        tenant_id,
        entities,
        judge,
        threshold=threshold,
        already_merged=already_merged,
        anti_linked=anti_linked,
    )
    for evidence in result.to_emit:
        client.emit(evidence)
    return result
