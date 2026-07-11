"""ER Tier-3 unstructured-mention PRODUCER — the one irreducibly probabilistic
surface (cross-source-entity-resolution.md §4.2 S3, §5). It reads FREE TEXT
(Drive/Linear bodies) that carry NO business entity id and `entity_tags` that
ship EMPTY, and emits **non-authoritative** `tier=3` evidence
(``method="llm_mention"``) that the deterministic fold treats as corroboration /
a reviewer hint — it NEVER, on its own, forms a canonical edge or widens a scope
(§4.2 S4, §5, §6).

The pipeline, four stages, mirrors resolve_tier2's block/judge/emit spine:

    (1) GAZETTEER — per-tenant, built from L1: every Account/company name +
        alias + domain, and every Contact email/domain (§5 "Detection"). A
        closed, alias-rich catalog beats generic NER on a known tenant.
    (2) DETECTION — over unstructured text. HIGH-PRECISION gazetteer + fuzzy
        FIRST (name/alias surface forms, word-boundary matched, casefolded),
        NER/LLM as a BACKSTOP only for spans the gazetteer misses. The backstop
        is a PLUGGABLE seam whose default is DETERMINISTIC (so tests need no key);
        the live seam REUSES ``consolidation.AnthropicJudge``'s key loading
        lazily (``EntityAnthropicMentionDetector``), embedding NO key here.
    (3) RETRIEVAL + DISAMBIGUATION — for each mention span, retrieve gazetteer
        candidates, score by surface-match strength + a DOMAIN/ACL CO-SIGNAL (a
        domain on the same chunk / in the ACL that matches a candidate's verified
        domain is deterministic corroboration), and rank.
    (4) ABSTAIN / NIL gates + the TWO-DECISION rule, then EMIT.

The TWO-DECISION rule (§5):
    - Decision A — attach *a* tag at all? RECALL-lean (safe): under §7c/§7d
      deny-by-default INTERSECTION semantics an extra tag NARROWS retrievability,
      so over-attaching a plausible tag can never leak. We lean in — as
      non-authoritative Tier-3 evidence.
    - Decision B — *which* entity? PRECISION; ABSTAIN if unsure. Linking the
      WRONG "Acme" mis-files content into a real customer's scope. Disambiguation
      emits NIL (quarantine, NEVER the zero-tag broad bucket) whenever any gate
      fires:
        1. NIL threshold:  top-candidate score < ``tau_nil``  -> no real match.
        2. Margin test:    ``top1 - top2 < margin_delta``     -> two plausible
           entities -> abstain rather than guess.
        3. Kill switch:    ``auto_link_tier3 == False`` (DEFAULT) -> Tier-3 never
           auto-creates/strengthens a link; the mention is a REVIEWER HINT only.

The load-bearing rule (§5): **a Tier-3 mention becomes a chunk `entity_tags`
value only if the candidate is already a folded canonical AND either (a) a
deterministic CO-SIGNAL exists on the same chunk, or (b) a human approves.** An
ACL email/domain is ASSOCIATIVE corroboration only ("who can see it," never
"what it is about"): a co-signal RAISES confidence enough to permit the tag, but
the tag still NARROWS retrievability under §7c intersection — it never grants
visibility. Abstain routes to QUARANTINE, never to the zero-tag broad bucket.

Emission is via the EXISTING POST /v1/admin/entity-evidence with ``tier=3`` and
``method="llm_mention"`` — the SAME admin plane resolve_tier2 uses. This producer
only PROPOSES; the fold (Rust, read path never) decides.

Python is ingestion-only and never on the read path (CLAUDE.md).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Protocol, runtime_checkable

import httpx

# REUSE the Tier-2 deterministic normalizers verbatim — the gazetteer keys on the
# SAME normalized name+domain shapes the Tier-1/Tier-2 producers do, so a mention
# and a catalog entity compare apples-to-apples. Do NOT reinvent them.
from verity_ingest.resolve_tier2 import (
    normalize_domain,
    normalize_name,
    name_tokens,
)

# REUSE the knowledge-merge / Tier-2 judge machinery for the LLM backstop seam.
# The Tier-3 detector backstop IS the AnthropicJudge seam: we inherit its runtime
# ANTHROPIC_API_KEY loading, httpx transport, and fail-closed handling verbatim,
# swapping only the prompt for span detection. NO key is embedded or handled here.
from verity_ingest.consolidation import (
    ANTHROPIC_API_URL,
    ANTHROPIC_VERSION,
    AnthropicJudge,
)


# ---------------------------------------------------------------------------
# Config: the Tier-3 NIL / margin / kill-switch gates (§4.1 entity_resolution_config).
# These mirror the server-side `entity_resolution_config` columns the fold reads;
# passed in here so the producer's abstain behavior matches the tenant's config.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tier3Config:
    """The Tier-3 disambiguation gates (§5), sourced from `entity_resolution_config`.

    Defaults are the SAFE, precision-first operating point: ``auto_link_tier3``
    OFF (the ``VERITY_ENTITY_AUTO_LINK=0`` analog), a high ``tau_nil`` so weak
    matches abstain, and a real ``margin_delta`` so two plausible candidates
    abstain rather than guess."""

    tau_nil: float = 0.55
    margin_delta: float = 0.15
    auto_link_tier3: bool = False


# ---------------------------------------------------------------------------
# (1) GAZETTEER — per-tenant catalog built from L1.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatalogEntity:
    """One catalog entry the gazetteer can resolve a mention TO. A folded
    canonical (``account:acme``) plus its identity material from L1: the display
    name, every alias/surface form, and every verified domain. ``is_canonical``
    records whether this entity is ALREADY a folded canonical — the load-bearing
    gate for tagging (a Tier-3 mention may only tag a chunk if the target is
    already a folded canonical; §5)."""

    canonical: str  # e.g. "account:acme" — the tag/link target
    name: str = ""
    aliases: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()  # verified registrable domains
    is_canonical: bool = True

    @property
    def surface_forms(self) -> tuple[str, ...]:
        """Every name/alias the detector may match, normalized-nonempty."""
        forms = [self.name, *self.aliases]
        seen: dict[str, None] = {}
        for f in forms:
            n = normalize_name(f)
            if n:
                seen.setdefault(n, None)
        return tuple(seen)

    @property
    def norm_domains(self) -> frozenset[str]:
        return frozenset(d for d in (normalize_domain(x) for x in self.domains) if d)


class Gazetteer:
    """Per-tenant mention catalog (§5 "Detection"). Built from L1 accounts/companies
    (name + aliases + domains) and contacts (email/domain). Indexes surface forms
    for exact + fuzzy lookup and domains for the co-signal.

    Fail-closed: entities with NO usable surface form are dropped (they can never
    be matched anyway); a canonical with only a domain still contributes that
    domain to the co-signal index."""

    def __init__(self, entities: Iterable[CatalogEntity]) -> None:
        self._entities: list[CatalogEntity] = list(entities)
        # exact surface form -> list of catalog entities (a form may be shared,
        # e.g. two "Acme" catalog rows — the ambiguity the margin test guards).
        self._by_form: dict[str, list[CatalogEntity]] = {}
        # normalized domain -> canonical (co-signal lookup).
        self._by_domain: dict[str, set[str]] = {}
        for e in self._entities:
            for form in e.surface_forms:
                self._by_form.setdefault(form, []).append(e)
            for d in e.norm_domains:
                self._by_domain.setdefault(d, set()).add(e.canonical)

    @classmethod
    def from_l1(
        cls,
        accounts: Iterable[dict],
        contacts: Iterable[dict] = (),
    ) -> "Gazetteer":
        """Build a gazetteer from L1-shaped rows (as the API/connectors expose
        them). ``accounts``: dicts with ``canonical`` (or ``ref``), ``name``,
        optional ``aliases`` and ``domains``/``domain``. ``contacts``: dicts with
        an ``email`` (or ``domain``) and the ``canonical`` account they belong to
        — every contact email/domain becomes a co-signal domain on its account.

        In production a caller sources these from L1 via the read API; passed in
        as plain dicts here for testability (mirrors resolve_tier2.Entity)."""
        by_canonical: dict[str, dict] = {}

        def _slot(canonical: str) -> dict:
            return by_canonical.setdefault(
                canonical,
                {"name": "", "aliases": [], "domains": [], "is_canonical": True},
            )

        for a in accounts:
            canonical = a.get("canonical") or a.get("ref") or ""
            if not canonical:
                continue
            s = _slot(canonical)
            if a.get("name") and not s["name"]:
                s["name"] = a["name"]
            s["aliases"].extend(a.get("aliases", []) or [])
            doms = list(a.get("domains", []) or [])
            if a.get("domain"):
                doms.append(a["domain"])
            s["domains"].extend(doms)
            if "is_canonical" in a:
                s["is_canonical"] = bool(a["is_canonical"])

        for c in contacts:
            canonical = c.get("canonical") or c.get("account") or ""
            if not canonical:
                continue
            s = _slot(canonical)
            dom = c.get("domain") or c.get("email") or ""
            if dom:
                s["domains"].append(dom)

        return cls(
            CatalogEntity(
                canonical=canonical,
                name=s["name"],
                aliases=tuple(s["aliases"]),
                domains=tuple(s["domains"]),
                is_canonical=s["is_canonical"],
            )
            for canonical, s in by_canonical.items()
        )

    @property
    def entities(self) -> list[CatalogEntity]:
        return list(self._entities)

    def all_domains(self) -> frozenset[str]:
        return frozenset(self._by_domain)

    def canonicals_for_domain(self, domain: str) -> frozenset[str]:
        """Which folded canonicals a (normalized) domain corroborates."""
        return frozenset(self._by_domain.get(normalize_domain(domain), ()))

    def surface_forms(self) -> frozenset[str]:
        return frozenset(self._by_form)

    def lookup_exact(self, form: str) -> list[CatalogEntity]:
        return list(self._by_form.get(normalize_name(form), ()))

    def lookup_fuzzy(self, form: str, *, min_sim: float = 0.6) -> list[CatalogEntity]:
        """Candidate entities whose surface form fuzzily matches ``form`` (token-set
        Jaccard). Recall aid for detection — precision is the disambiguation
        gates' job, not the retrieval step's."""
        q = name_tokens(form)
        if not q:
            return []
        out: list[CatalogEntity] = []
        for cat_form, ents in self._by_form.items():
            cf = frozenset(cat_form.split())
            if not cf:
                continue
            sim = len(q & cf) / len(q | cf)
            if sim >= min_sim:
                out.extend(ents)
        # dedup preserving order.
        seen: dict[str, None] = {}
        uniq = []
        for e in out:
            if e.canonical not in seen:
                seen[e.canonical] = None
                uniq.append(e)
        return uniq


# ---------------------------------------------------------------------------
# (2) DETECTION — gazetteer + fuzzy first, NER/LLM backstop.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mention:
    """A detected mention span in one unstructured chunk. ``chunk_ref`` is the L0
    chunk pointer (``chunk:<source>:<document_id>:<seq>`` — the same shape the
    fold's ``parse_chunk_ref`` expects). ``text`` is the matched surface span;
    ``method`` records how it was found (``gazetteer`` / ``fuzzy`` / ``ner``)."""

    chunk_ref: str
    text: str
    method: str = "gazetteer"


@runtime_checkable
class MentionDetector(Protocol):
    """The NER/LLM BACKSTOP seam. Same shape as the Tier-2 judge seam: a single
    method the deterministic default and the live Anthropic seam both satisfy."""

    def detect(self, text: str, gazetteer: Gazetteer) -> list[str]: ...


class NullMentionDetector:
    """The deterministic default backstop: NO extra spans. Detection then relies
    ENTIRELY on the high-precision gazetteer pass — the safe default that needs no
    key and never hallucinates a span. Tests use this."""

    def detect(self, text: str, gazetteer: Gazetteer) -> list[str]:
        return []


_ENTITY_MENTION_PROMPT = """\
You extract ORGANIZATION/COMPANY name mentions from a short business text \
(a document or ticket body) for an enterprise memory system. Return ONLY the \
verbatim organization surface forms you are confident appear as named companies \
in the text — no people, no products, no generic words. If none, return an empty \
list. When uncertain whether a span is a company, LEAVE IT OUT (precision-first: \
a spurious span can only mis-tag).

Text:
{text!r}

Return JSON {{"mentions": ["<surface form>", ...]}}."""


class AnthropicMentionDetector(AnthropicJudge):
    """LIVE NER backstop — SUBCLASSES ``consolidation.AnthropicJudge`` so it REUSES
    that class's runtime ``ANTHROPIC_API_KEY`` loading (constructing WITHOUT a key
    raises, exactly as the parent does), httpx transport, and fail-closed handling
    VERBATIM. It adds ONLY the mention-extraction prompt — no key is embedded,
    printed, or read from a literal here.

    Fail-closed: any parse/transport error or refusal => NO extra spans (never a
    hallucinated mention). The gazetteer pass still ran, so detection degrades to
    high-precision-only, never to zero — and never to a guess."""

    _MENTION_SCHEMA = {
        "type": "object",
        "properties": {"mentions": {"type": "array", "items": {"type": "string"}}},
        "required": ["mentions"],
        "additionalProperties": False,
    }

    def detect(self, text: str, gazetteer: Gazetteer) -> list[str]:
        prompt = _ENTITY_MENTION_PROMPT.format(text=text)
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
                        "format": {"type": "json_schema", "schema": self._MENTION_SCHEMA}
                    },
                },
            )
            response.raise_for_status()
            body = response.json()
            if body.get("stop_reason") == "refusal":
                return []
            import json as _json

            payload = next(b["text"] for b in body["content"] if b["type"] == "text")
            parsed = _json.loads(payload)
            return [str(m) for m in parsed.get("mentions", []) if str(m).strip()]
        except (httpx.HTTPError, KeyError, ValueError, StopIteration):
            return []  # fail closed: no hallucinated span


_POSSESSIVE = re.compile(r"['’]s$", re.IGNORECASE)


def _iter_windows(text: str, max_len: int) -> Iterable[str]:
    """Contiguous word windows up to ``max_len`` tokens, for multi-word surface
    forms ("Los Pollos Hermanos"). Word-boundary matching only — no substring
    inside a longer word. Trailing possessive ``'s`` is stripped per token so
    "Acme's" matches the catalog form "Acme" (``normalize_name`` would otherwise
    split the apostrophe into a spurious "s" token)."""
    raw = re.findall(r"[A-Za-z0-9&'’./-]+", text)
    words = [_POSSESSIVE.sub("", w) for w in raw]
    n = len(words)
    for i in range(n):
        for j in range(i + 1, min(i + max_len, n) + 1):
            yield " ".join(words[i:j])


def detect_mentions(
    chunk_ref: str,
    text: str,
    gazetteer: Gazetteer,
    *,
    detector: MentionDetector | None = None,
    max_form_len: int = 5,
) -> list[Mention]:
    """Detect mentions in one chunk. HIGH-PRECISION gazetteer + fuzzy first
    (word-boundary windows matched against the catalog's surface forms), then the
    pluggable NER/LLM backstop for spans the gazetteer missed. Deduped by matched
    surface form.

    Precision-first: gazetteer hits are exact normalized-form matches (never a
    substring inside a word). The backstop only ADDS spans that themselves resolve
    to a gazetteer entity — a backstop span naming an unknown org is dropped (we
    can only tag things in the catalog)."""
    detector = detector or NullMentionDetector()
    forms = gazetteer.surface_forms()
    found: dict[str, Mention] = {}

    # (a) gazetteer pass: exact normalized surface-form windows.
    for window in _iter_windows(text, max_form_len):
        nf = normalize_name(window)
        if nf and nf in forms:
            found.setdefault(nf, Mention(chunk_ref=chunk_ref, text=window, method="gazetteer"))

    # (b) NER/LLM backstop: only for forms the gazetteer pass missed, and only if
    #     the span resolves to a known catalog entity (exact or fuzzy).
    for span in detector.detect(text, gazetteer):
        nf = normalize_name(span)
        if not nf or nf in found:
            continue
        if gazetteer.lookup_exact(span) or gazetteer.lookup_fuzzy(span):
            found[nf] = Mention(chunk_ref=chunk_ref, text=span, method="ner")

    return list(found.values())


# ---------------------------------------------------------------------------
# (3) RETRIEVAL + DISAMBIGUATION — score candidates with the domain/ACL co-signal.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """A scored disambiguation candidate for one mention. ``score`` in 0..1;
    ``co_signal`` is True iff a deterministic domain/ACL co-signal on the SAME
    chunk corroborates this candidate (the load-bearing tagging gate, §5)."""

    entity: CatalogEntity
    score: float
    co_signal: bool = False


def _surface_score(mention_text: str, entity: CatalogEntity) -> float:
    """Base match strength of a mention span against a catalog entity's surface
    forms: 1.0 for an exact normalized-form match, else the best token-set
    Jaccard. Deterministic, recall-tolerant; the gates decide precision."""
    m = normalize_name(mention_text)
    mt = frozenset(m.split())
    best = 0.0
    for form in entity.surface_forms:
        if m == form:
            return 1.0
        ft = frozenset(form.split())
        if mt and ft:
            best = max(best, len(mt & ft) / len(mt | ft))
    return best


def retrieve_candidates(
    mention: Mention,
    gazetteer: Gazetteer,
    *,
    chunk_domains: Iterable[str] = (),
    acl_domains: Iterable[str] = (),
) -> list[Candidate]:
    """Retrieve + score catalog candidates for one mention. Score = surface-match
    strength, BOOSTED when a deterministic domain co-signal corroborates the
    candidate (a domain in the chunk body OR its ACL matching the candidate's
    verified domain). Both chunk-body and ACL domains corroborate — but note the
    ACL boundary (§5): an ACL co-signal only RAISES confidence enough to permit a
    tag; it never grants visibility (tags NARROW retrievability under intersection).

    Deterministic order: strongest first, then canonical id (stable)."""
    cosig_canonicals: set[str] = set()
    for d in list(chunk_domains) + list(acl_domains):
        cosig_canonicals |= set(gazetteer.canonicals_for_domain(d))

    ents = {e.canonical: e for e in gazetteer.lookup_exact(mention.text)}
    for e in gazetteer.lookup_fuzzy(mention.text):
        ents.setdefault(e.canonical, e)

    out: list[Candidate] = []
    for e in ents.values():
        base = _surface_score(mention.text, e)
        if base <= 0.0:
            continue
        has_cosig = e.canonical in cosig_canonicals
        # Co-signal boosts toward 1.0 (deterministic corroboration), so a
        # co-signed candidate clears tau_nil and separates from a bare one.
        score = min(1.0, base + 0.4) if has_cosig else base
        out.append(Candidate(entity=e, score=round(score, 4), co_signal=has_cosig))
    out.sort(key=lambda c: (-c.score, c.entity.canonical))
    return out


# ---------------------------------------------------------------------------
# (4) ABSTAIN / NIL gates + two-decision rule -> Decision.
# ---------------------------------------------------------------------------


class Tier3Outcome(str, Enum):
    """What the two-decision rule decided for one mention (§5)."""

    NIL = "nil"  # no candidate is a real match (top < tau_nil) -> quarantine
    ABSTAIN_MARGIN = "abstain_margin"  # two plausible candidates -> quarantine
    REVIEWER_HINT = "reviewer_hint"  # confident but no co-signal / auto-off -> hint only
    TAG = "tag"  # confident + co-signal (or human) -> emit a tag-eligible mention


@dataclass(frozen=True)
class Tier3Decision:
    """The full, auditable outcome for one mention: the ranked candidates, the
    chosen top (if any), the outcome, and WHY. ``emit_tag`` is the load-bearing
    bit: True only when the mention is BOTH confident/unambiguous AND corroborated
    (co-signal on an already-folded canonical) — i.e. Decision B resolved AND the
    §5 tagging gate cleared. A REVIEWER_HINT still emits Tier-3 evidence (so the
    review queue sees it) but with ``emit_tag=False`` — non-authoritative."""

    mention: Mention
    candidates: tuple[Candidate, ...]
    outcome: Tier3Outcome
    reason: str
    top: Candidate | None = None
    emit_tag: bool = False

    @property
    def emit_evidence(self) -> bool:
        """Whether ANY tier=3 evidence is emitted. NIL / margin-abstain emit
        NOTHING (quarantine, no guess on the wire). A confident single candidate
        emits evidence — as a reviewer hint at minimum."""
        return self.outcome in (Tier3Outcome.REVIEWER_HINT, Tier3Outcome.TAG)


def disambiguate(
    mention: Mention,
    candidates: list[Candidate],
    config: Tier3Config,
    *,
    human_confirmed: bool = False,
) -> Tier3Decision:
    """Apply the TWO-DECISION rule + the explicit ABSTAIN/NIL gates (§5).

    Decision A (attach a tag at all) is recall-lean and implicit: we lean toward
    emitting SOME evidence for a confident, unambiguous mention. Decision B (which
    entity) is precision-first and gated:

      1. NIL:    top score < tau_nil               -> Tier3Outcome.NIL (no emit)
      2. margin: top1 - top2 < margin_delta        -> ABSTAIN_MARGIN (no emit)
      3. tag gate: TAG only if the top is an already-folded canonical AND
         (a co-signal is present OR a human approved) AND auto_link_tier3 permits
         (or the human overrides the kill switch). Otherwise REVIEWER_HINT.
    """
    if not candidates:
        return Tier3Decision(
            mention=mention,
            candidates=(),
            outcome=Tier3Outcome.NIL,
            reason="no catalog candidate for mention",
        )

    top = candidates[0]
    second = candidates[1] if len(candidates) > 1 else None

    # Gate 1 — NIL threshold: nothing in the catalog is a real match.
    if top.score < config.tau_nil:
        return Tier3Decision(
            mention=mention,
            candidates=tuple(candidates),
            outcome=Tier3Outcome.NIL,
            reason=f"top score {top.score:.3f} < tau_nil {config.tau_nil:.3f}",
            top=top,
        )

    # Gate 2 — margin test: two plausible candidates -> abstain rather than guess.
    if second is not None and (top.score - second.score) < config.margin_delta:
        return Tier3Decision(
            mention=mention,
            candidates=tuple(candidates),
            outcome=Tier3Outcome.ABSTAIN_MARGIN,
            reason=(
                f"margin {top.score - second.score:.3f} < margin_delta "
                f"{config.margin_delta:.3f} ({top.entity.canonical} vs "
                f"{second.entity.canonical})"
            ),
            top=top,
        )

    # Decision B resolved to a single confident candidate. Now the §5 TAG gate.
    # A tag may materialize only if the target is ALREADY a folded canonical AND
    # one of the three permit conditions holds:
    #   (a) a deterministic CO-SIGNAL exists on the chunk  (the §5 worked-example
    #       default: a co-signed mention tags even with the kill switch off), or
    #   (b) a HUMAN approved this chunk↔canonical            (§5 "or a human
    #       approves"; also overrides the kill switch), or
    #   (c) the tenant opted INTO auto_link_tier3            (the kill switch ON —
    #       a public §8 spec amendment; permits an uncorroborated confident tag).
    if top.entity.is_canonical and (top.co_signal or human_confirmed or config.auto_link_tier3):
        if human_confirmed:
            why = "human_confirmed"
        elif top.co_signal:
            why = "deterministic co-signal on chunk"
        else:
            why = "auto_link_tier3 opt-in"
        return Tier3Decision(
            mention=mention,
            candidates=tuple(candidates),
            outcome=Tier3Outcome.TAG,
            reason=f"confident, unambiguous, {why}; target is a folded canonical",
            top=top,
            emit_tag=True,
        )

    # Confident + unambiguous but NOT corroborated (no co-signal, no human, and
    # auto-link off) — or the target is not yet a folded canonical: reviewer hint
    # only. Emits non-authoritative evidence; NEVER a tag, NEVER a scope-widening
    # edge. The chunk stays as-is (NOT dumped into the zero-tag broad bucket).
    reason_bits = []
    if not top.entity.is_canonical:
        reason_bits.append("target not yet a folded canonical")
    if not top.co_signal:
        reason_bits.append("no deterministic co-signal")
    if not config.auto_link_tier3:
        reason_bits.append("auto_link_tier3 off")
    return Tier3Decision(
        mention=mention,
        candidates=tuple(candidates),
        outcome=Tier3Outcome.REVIEWER_HINT,
        reason="reviewer hint only: " + ", ".join(reason_bits),
        top=top,
    )


# ---------------------------------------------------------------------------
# EMIT — POST tier=3 evidence to the admin plane (the SAME endpoint as Tier-2).
# ---------------------------------------------------------------------------


@dataclass
class Tier3Evidence:
    """One tier=3 evidence row the producer POSTs. Shape matches
    POST /v1/admin/entity-evidence (§4.1/§8): ``tier=3``, ``method="llm_mention"``,
    the disambiguation ``score``, the matched ``key_value``, ``key_namespace``
    (mentions are ``customer_context`` — associative, never an internal-directory
    edge; §4.4), and ``evidence_l0_ref`` = the chunk that produced it.

    ``polarity`` is always +1 (a positive mention). Even a TAG-eligible mention is
    NON-AUTHORITATIVE: the fold never forms an edge from tier=3 — it only raises
    confidence on an existing edge or materializes a tag under the co-signal rule
    (§4.2 S4). ``emit_tag`` rides ``key_value`` for the audit row so the fold /
    reviewer can tell a tag-eligible mention from a bare reviewer hint."""

    tenant_id: str
    left_ref: str  # the mention's canonical candidate, e.g. "account:acme"
    right_ref: str  # the chunk ref, e.g. "chunk:gdrive:D9:0"
    score: float
    key_value: str
    evidence_l0_ref: str | None = None
    tier: int = 3
    method: str = "llm_mention"
    key_namespace: str = "customer_context"

    def to_json(self) -> dict:
        body: dict = {
            "tenant_id": self.tenant_id,
            "left_ref": self.left_ref,
            "right_ref": self.right_ref,
            "tier": self.tier,
            "method": self.method,
            "score": self.score,
            "key_value": self.key_value,
            "key_namespace": self.key_namespace,
        }
        if self.evidence_l0_ref is not None:
            body["evidence_l0_ref"] = self.evidence_l0_ref
        return body


class Tier3Client:
    """Thin admin-plane client — POSTs tier=3 evidence. Bearer admin token rides
    the header exactly like ``Tier2Client``. Touches no Anthropic key: the
    detector owns that seam."""

    def __init__(
        self,
        base_url: str,
        admin_token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        headers = {"authorization": f"Bearer {admin_token}"} if admin_token else {}
        self._client = client or httpx.Client(base_url=base_url, headers=headers, timeout=60.0)

    def emit(self, evidence: Tier3Evidence) -> dict:
        response = self._client.post("/v1/admin/entity-evidence", json=evidence.to_json())
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Public entrypoint: detect -> retrieve -> disambiguate -> plan (-> emit).
# Pure planning is separated from the network EMIT so the whole cascade is
# testable offline with NO key (mirrors resolve_tier2.plan_tier2 / run_tier2).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Chunk:
    """One unstructured chunk to resolve (a Drive/Linear body). ``chunk_ref`` is
    the L0 pointer ``chunk:<source>:<document_id>:<seq>``. ``chunk_domains`` are
    domains found in the body; ``acl_domains`` are ACL principals' domains
    (associative co-signal only — §5). ``human_confirmed_canonicals`` are targets
    a reviewer already approved for THIS chunk (overrides the kill switch)."""

    chunk_ref: str
    text: str
    chunk_domains: tuple[str, ...] = ()
    acl_domains: tuple[str, ...] = ()
    human_confirmed_canonicals: frozenset[str] = frozenset()


@dataclass
class ProducerResult:
    """What one Tier-3 producer pass decided (before/without emitting)."""

    decisions: list[Tier3Decision] = field(default_factory=list)
    to_emit: list[Tier3Evidence] = field(default_factory=list)


def plan_tier3(
    tenant_id: str,
    chunks: Iterable[Chunk],
    gazetteer: Gazetteer,
    config: Tier3Config,
    *,
    detector: MentionDetector | None = None,
) -> ProducerResult:
    """Run DETECT -> RETRIEVE -> DISAMBIGUATE and PLAN the tier=3 evidence (no
    network). NIL / margin-abstain mentions produce NO evidence (quarantine, no
    guess on the wire); REVIEWER_HINT and TAG mentions produce non-authoritative
    tier=3 evidence, with ``emit_tag`` recorded in the audit ``key_value``."""
    result = ProducerResult()
    for chunk in chunks:
        mentions = detect_mentions(chunk.chunk_ref, chunk.text, gazetteer, detector=detector)
        for mention in mentions:
            candidates = retrieve_candidates(
                mention,
                gazetteer,
                chunk_domains=chunk.chunk_domains,
                acl_domains=chunk.acl_domains,
            )
            # A human pre-approval applies iff it targets the mention's top candidate.
            top_canonical = candidates[0].entity.canonical if candidates else None
            human = top_canonical in chunk.human_confirmed_canonicals if top_canonical else False
            decision = disambiguate(mention, candidates, config, human_confirmed=human)
            result.decisions.append(decision)
            if not decision.emit_evidence or decision.top is None:
                continue  # NIL / margin-abstain: nothing emitted
            result.to_emit.append(
                Tier3Evidence(
                    tenant_id=tenant_id,
                    left_ref=decision.top.entity.canonical,
                    right_ref=mention.chunk_ref,
                    score=decision.top.score,
                    key_value=(
                        f"llm_mention text={mention.text!r} "
                        f"emit_tag={decision.emit_tag} ({decision.reason})"
                    ),
                    evidence_l0_ref=mention.chunk_ref,
                )
            )
    return result


def run_tier3(
    client: Tier3Client,
    tenant_id: str,
    chunks: Iterable[Chunk],
    gazetteer: Gazetteer,
    config: Tier3Config,
    *,
    detector: MentionDetector | None = None,
) -> ProducerResult:
    """The full producer pass: plan, then EMIT each non-abstaining mention as
    tier=3 evidence. Returns the plan (with what was emitted).

    Nothing here auto-merges or widens a scope: tier=3 evidence is
    non-authoritative — the fold never forms an edge from it, and a chunk tag
    materializes only under the §5 co-signal/human rule at fold time."""
    result = plan_tier3(tenant_id, chunks, gazetteer, config, detector=detector)
    for evidence in result.to_emit:
        client.emit(evidence)
    return result


def build_mention_detector(name: str) -> MentionDetector:
    """Detector factory, mirroring ``resolve_tier2.build_entity_judge``.
    ``null`` (the default/test path) needs NO api key; ``anthropic`` constructs
    the live NER backstop, which reads ``ANTHROPIC_API_KEY`` from the operator's
    environment at construction time (inherited from ``AnthropicJudge``)."""
    if name == "null":
        return NullMentionDetector()
    if name == "anthropic":
        return AnthropicMentionDetector()
    raise ValueError(f"unknown mention detector {name!r}")
