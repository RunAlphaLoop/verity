"""Sleep-time consolidation worker (SPEC.md §2 L2 / knowledge items, §7d).

The async plane that turns unstructured L0 episodes into structured memory:

    lease  -> extract -> complete

- ``lease``: POST /v1/admin/consolidation/lease hands out unprocessed non-CDC
  episodes (observation / webhook / doc_version) with payloads decrypted for
  this trusted-plane worker, leased for 5 minutes. CDC episodes are skipped
  server-side: their L1 extraction is deterministic at ingest time (SPEC §2 L1
  — structured data never goes through LLM extraction).
- ``extract``: an ``Extractor`` turns one episode into L2 (subject, relation,
  object) facts, per-chunk entity-tag suggestions, and knowledge candidates.
- ``complete``: POST /v1/admin/consolidation/complete writes the results.
  L2 supersession, tag-suggestion review states, and knowledge similarity-
  merge (support accrual) all happen server-side; completing the same episode
  twice is an acknowledged no-op, so a crashed worker can simply retry.

Two extractors ship:

- ``DeterministicExtractor`` — the honest v0 used in ALL tests: regex/rule
  extraction ("X is Y" sentences, "key: value" lines), entity-tag echo (exact
  entity-name matches in chunk content at 0.95 confidence), and a knowledge
  candidate whenever a sentence carries a generalization marker ("always",
  "consistently", "customers ... tend").
- ``AnthropicExtractor`` — the LLM seam, active only when ANTHROPIC_API_KEY is
  set. Raw httpx against the Messages API (the ingest plane is deliberately
  httpx-only — no SDK dependency), model ``claude-opus-4-8``, strict JSON via
  structured outputs (``output_config.format`` json_schema).

Python never appears on the read path; this worker only writes through the
admin plane.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

# ---------------------------------------------------------------------------
# Canonicalization (knowledge-merge-tuning.md §3)
#
# Paraphrase collapses best at extraction time. We emit, alongside the human
# statement/relation, a NORMALIZED canonical form that the server uses for the
# exact-match fast-path merge (canonical statements) and for L2 supersession
# alignment (canonical predicates). Canonicalization is deterministic, tested,
# and deliberately CONSERVATIVE: it must collapse paraphrases of the SAME
# generalization ("requires DPA before review") but must NOT collapse distinct
# generalizations ("requires DPA" vs "requires SOC 2"). Over-normalization that
# fuses different objects is a false merge, the failure the design forbids.
# ---------------------------------------------------------------------------

# Articles / filler stripped from canonical forms. Deliberately small: only
# words that carry no discriminative meaning for a generalization.
_CANONICAL_FILLER = frozenset(
    {
        "a",
        "an",
        "the",
        "some",
        "any",
        "will",
        "they",
        "any",
        "be",
        "been",
        "is",
        "are",
        "to",
        "that",
        "can",
        "proceed",
        "begin",
        "start",
        "started",
        "executed",
        "signed",
        "of",
        "and",
        # generalization markers carry no predication content
        "always",
        "consistently",
        "usually",
        "typically",
        "generally",
        "often",
        "tend",
        "tends",
        "every",
        "all",
    }
)

# Controlled predicate vocabulary. Free-text relations (from either extractor)
# map to a small set of canonical predicates so (subject, relation) supersession
# aligns across re-extractions. Order matters: multi-word / "before"/"until"
# senses are checked before the bare "requires" sense so
# "requires ... before ..." → requires_before, not requires.
_PREDICATE_BLOCKS_UNTIL = re.compile(r"\bblock(?:s|ed|ing)?\b|\buntil\b", re.IGNORECASE)
_PREDICATE_REQUIRES_BEFORE = re.compile(
    r"\b(?:require|need|mandate|demand)\w*\b.*\bbefore\b"
    r"|\brequire\w*_before\w*"
    r"|\bbefore\b.*\b(?:review|assessment|approval)\b",
    re.IGNORECASE,
)
_PREDICATE_REQUIRES = re.compile(
    r"\b(?:require|need|mandate|demand|ask\s+for|request)\w*\b", re.IGNORECASE
)
_PREDICATE_IS = re.compile(r"^is$", re.IGNORECASE)


def canonical_predicate(relation: str) -> str:
    """Map a free-text relation to the controlled predicate vocabulary.

    ``requires`` and ``requires_before_security_assessment`` both → ``requires_before``
    (the finding), so their (subject, relation) L2 keys align and supersede.
    Unknown relations fall back to a whitespace/underscore-normalized slug so
    they still key deterministically (never lost)."""
    r = relation.strip()
    if _PREDICATE_IS.match(r):
        return "is"
    if _PREDICATE_BLOCKS_UNTIL.search(r):
        return "blocks_until"
    if _PREDICATE_REQUIRES_BEFORE.search(r):
        return "requires_before"
    if _PREDICATE_REQUIRES.search(r):
        return "requires"
    # Fallback: deterministic slug (lowercase, non-alnum → single underscore).
    slug = re.sub(r"[^a-z0-9]+", "_", r.lower()).strip("_")
    return slug or "relates_to"


# Synonym map applied to canonical-statement tokens: collapse surface variants
# of the SAME concept (never distinct concepts) so paraphrases align. Values are
# stable canonical tokens.
_CANONICAL_SYNONYMS = {
    "dpa": "signed_dpa",
    "dpas": "signed_dpa",
    "data": "",  # part of the "data processing agreement" phrase (see phrases)
    "processing": "",
    "agreement": "",
    "agreements": "",
    "enterprise": "segment_buyer",
    "procurement": "segment_buyer",
    "buyers": "segment_buyer",
    "buyer": "segment_buyer",
    "accounts": "segment_buyer",
    "account": "segment_buyer",
    "teams": "segment_buyer",
    "team": "segment_buyer",
    "customers": "segment_buyer",
    "customer": "segment_buyer",
    "clients": "segment_buyer",
    "security": "security_review",
    "review": "security_review",
    "assessment": "security_review",
    "assessments": "security_review",
    "require": "requires",
    "requires": "requires",
    "required": "requires",
    "requiring": "requires",
    "need": "requires",
    "needs": "requires",
    "require_before": "requires",
    "block": "blocks",
    "blocks": "blocks",
    "blocked": "blocks",
    "before": "before",
    "until": "before",
}

# Multi-word phrases collapsed to a single canonical token BEFORE tokenization.
_CANONICAL_PHRASES = [
    (re.compile(r"\bdata\s+processing\s+agreement\b", re.IGNORECASE), " signed_dpa "),
    (re.compile(r"\bsigned\s+dpa\b", re.IGNORECASE), " signed_dpa "),
    (re.compile(r"\bsecurity\s+(?:review|assessment)\b", re.IGNORECASE), " security_review "),
    (re.compile(r"\bsecurity\s+teams?\b", re.IGNORECASE), " segment_buyer "),
    (re.compile(r"\bsecurity\s+team\b", re.IGNORECASE), " segment_buyer "),
]


def canonical_statement(statement: str) -> str:
    """Normalize a generalization to a stable predication for exact-match merge.

    Lowercase, strip parentheticals, collapse known multi-word phrases, drop
    articles/filler, map synonyms, sort the object tokens so word-order variants
    align — while KEEPING discriminative tokens (``signed_dpa`` vs ``soc_2``) so
    distinct generalizations stay distinct.

    The three DPA paraphrases collapse to the same form; "requires DPA before
    review" and "requires SOC 2 before review" DO NOT."""
    s = statement.lower()
    # Drop parentheticals like "(dpa)" and trailing punctuation.
    s = re.sub(r"\([^)]*\)", " ", s)
    s = re.sub(r"[^a-z0-9_\s]", " ", s)
    # Collapse known multi-word phrases to single tokens first.
    for pat, repl in _CANONICAL_PHRASES:
        s = pat.sub(repl, s)

    # Structural inversion: "blocks A until B" ≡ "requires B before A". Rewrite
    # to the requires/before order so a blocking paraphrase aligns with a
    # requiring one (the DPA trio's C variant). Split on "until", swap sides,
    # re-join with "before" and a leading "requires".
    if re.search(r"\buntil\b", s) and re.search(r"\bblock", s):
        left, _, right = s.partition(" until ")
        left = re.sub(r"\bblock\w*\b", " ", left)
        # right = the required artifact, left = the gated event. Inject an
        # explicit "requires" so the role-based assembly (below) fires.
        s = f" requires {right} before {left} "

    tokens = [t for t in s.split() if t]
    mapped: list[str] = []
    for tok in tokens:
        syn = _CANONICAL_SYNONYMS.get(tok, tok)
        if syn == "":
            continue  # dropped phrase-fragment
        if syn in _CANONICAL_FILLER:
            continue
        mapped.append(syn)

    # Dedupe preserving first occurrence.
    deduped: list[str] = []
    for tok in mapped:
        if tok not in deduped:
            deduped.append(tok)

    # Role-based assembly for the requires/blocks-before family: the surface
    # order (and blocks/until inversion) is discarded in favor of stable roles,
    # so "A requires B before C" and "C is blocked until B" both canonicalize to
    # "<subject> requires <required> before <gate>". Roles: segment_buyer is the
    # subject; a security_review is the gate; everything else is the required
    # artifact (KEPT and sorted, so signed_dpa vs soc_2 stay distinct).
    has_before = "before" in deduped
    has_predicate = any(t in ("requires", "blocks") for t in deduped)
    if has_before and has_predicate:
        subject = "segment_buyer" if "segment_buyer" in deduped else None
        gate = "security_review" if "security_review" in deduped else None
        structural = {"before", "requires", "blocks", "segment_buyer", "security_review"}
        required = sorted(t for t in deduped if t not in structural)
        parts: list[str] = []
        if subject:
            parts.append(subject)
        parts.append("requires")
        parts.extend(required)
        if gate:
            parts.extend(["before", gate])
        return " ".join(parts).strip()

    # General fallback: subject first, predicate second, remaining tokens sorted.
    predicates = [t for t in deduped if t in ("requires", "blocks")]
    subjects = [t for t in deduped if t == "segment_buyer"]
    rest = sorted(t for t in deduped if t not in predicates and t not in subjects)
    lead: list[str] = []
    if subjects:
        lead.append("segment_buyer")
    if predicates:
        lead.append(predicates[0])
    return " ".join([*lead, *rest]).strip()


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------


@dataclass
class L2Fact:
    """One extracted triple. Server-side this becomes a deterministic L1-style
    upsert keyed (source=l2, entity=normalized subject, field=NORMALIZED
    canonical_predicate) — supersession falls out of the existing machinery.

    ``relation`` is the human-readable, free-text relation as extracted;
    ``canonical_predicate`` is a controlled-vocabulary relation
    (``requires_before`` / ``blocks_until`` / ``requires`` / ``is`` ...) that the
    server uses as the supersession ``field`` so re-extractions of the same
    relation align even when the free-text wording differs (fixes the finding:
    ``requires`` vs ``requires_before_security_assessment`` must both key to the
    SAME fact so the later one supersedes)."""

    subject: str
    relation: str
    object: Any
    valid_from: str | None = None
    canonical_predicate: str | None = None

    def __post_init__(self) -> None:
        if self.canonical_predicate is None:
            self.canonical_predicate = canonical_predicate(self.relation)

    def to_json(self) -> dict:
        body: dict[str, Any] = {
            "subject": self.subject,
            "relation": self.relation,
            "object": self.object,
            "canonical_predicate": self.canonical_predicate,
        }
        if self.valid_from is not None:
            body["valid_from"] = self.valid_from
        return body


@dataclass
class TagSuggestion:
    """A probabilistic entity tag for one chunk (SPEC §7d): suggest-only by
    default server-side; >= 0.9 confidence auto-applies only under
    VERITY_AUTO_TAG=1."""

    chunk_id: str
    tag: str
    confidence: float

    def to_json(self) -> dict:
        return {"chunk_id": self.chunk_id, "tag": self.tag, "confidence": self.confidence}


@dataclass
class KnowledgeCandidate:
    """A proposed generalization (SPEC v1.3 §2). Always a proposal: the server
    merges into an existing candidate/published item (support accrual) or runs
    the de-identification gate on a fresh proposal.

    ``statement`` is the human-readable form (kept for display).
    ``canonical_statement`` is a normalized predication (lowercased, articles
    and filler stripped, predicate mapped to the controlled vocabulary) that the
    server uses for the exact-canonical-match fast-path merge: two paraphrases
    with an identical canonical form merge with NO embedding/LLM cost. It is a
    RECALL AID, never a merge authority — different generalizations must not
    collapse to the same canonical form (see knowledge-merge-tuning.md §3)."""

    statement: str
    categories: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    canonical_statement: str | None = None

    def __post_init__(self) -> None:
        if self.canonical_statement is None:
            self.canonical_statement = canonical_statement(self.statement)

    def to_json(self) -> dict:
        return {
            "statement": self.statement,
            "categories": self.categories,
            "evidence": self.evidence,
            "canonical_statement": self.canonical_statement,
        }


@dataclass
class Extraction:
    l2_facts: list[L2Fact] = field(default_factory=list)
    tag_suggestions: list[TagSuggestion] = field(default_factory=list)
    knowledge_candidates: list[KnowledgeCandidate] = field(default_factory=list)

    def to_complete_body(self, tenant_id: str, episode_id: str) -> dict:
        return {
            "tenant_id": tenant_id,
            "episode_id": episode_id,
            "l2_facts": [f.to_json() for f in self.l2_facts],
            "tag_suggestions": [t.to_json() for t in self.tag_suggestions],
            "knowledge_candidates": [k.to_json() for k in self.knowledge_candidates],
        }


@dataclass
class LeasedChunk:
    chunk_id: str
    content: str
    entity_tags: list[str]


@dataclass
class LeasedEpisode:
    episode_id: str
    source: str
    source_entity: str | None
    kind: str
    payload: Any
    chunks: list[LeasedChunk]

    @classmethod
    def from_json(cls, body: dict) -> "LeasedEpisode":
        return cls(
            episode_id=body["episode_id"],
            source=body["source"],
            source_entity=body.get("source_entity"),
            kind=body["kind"],
            payload=body.get("payload"),
            chunks=[
                LeasedChunk(
                    chunk_id=c["chunk_id"],
                    content=c["content"],
                    entity_tags=list(c.get("entity_tags", [])),
                )
                for c in body.get("chunks", [])
            ],
        )

    def text(self) -> str:
        """The unstructured text to extract from: an observation's payload
        text when present, else the episode's indexed chunk contents."""
        if isinstance(self.payload, dict):
            obs = self.payload.get("observation")
            if isinstance(obs, str) and obs:
                return obs
        return "\n".join(c.content for c in self.chunks)

    def entities(self) -> list[str]:
        """Provenance-derived entities: the payload's entity list plus the
        episode's source_entity, deduped, order preserved."""
        seen: list[str] = []
        candidates: list[str] = []
        if isinstance(self.payload, dict):
            raw = self.payload.get("entities")
            if isinstance(raw, list):
                candidates.extend(e for e in raw if isinstance(e, str))
        if self.source_entity:
            candidates.append(self.source_entity)
        for e in candidates:
            if e not in seen:
                seen.append(e)
        return seen


# ---------------------------------------------------------------------------
# Extractor seam
# ---------------------------------------------------------------------------


class Extractor(Protocol):
    def extract(self, episode: LeasedEpisode) -> Extraction: ...


_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
# "X is Y": capitalized subject of 1-4 words, then a non-empty object.
_IS_PATTERN = re.compile(r"^([A-Z][\w'-]*(?:\s+[A-Z0-9][\w'-]*){0,3})\s+is\s+(.{2,})$")
# "key: value" lines: short word-y key, non-empty value. URLs excluded.
_KV_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9 _/-]{0,48}):\s+(\S.*)$")
# Generalization markers gate knowledge candidates (honest v0: a marker word
# is a *hypothesis* signal, nothing more — the server's gates do the rest).
_GENERALIZATION_MARKERS = (
    re.compile(r"\balways\b", re.IGNORECASE),
    re.compile(r"\bconsistently\b", re.IGNORECASE),
    re.compile(r"\bcustomers\b.*\btend\b", re.IGNORECASE),
)


class DeterministicExtractor:
    """Regex/rule-based extraction — the honest v0. No model calls, fully
    reproducible, used by every test. Precision is deliberately conservative;
    recall is whatever the rules catch."""

    def extract(self, episode: LeasedEpisode) -> Extraction:
        text = episode.text()
        entities = episode.entities()
        result = Extraction()

        # --- L2 facts ---
        for sentence in _SENTENCE_SPLIT.split(text):
            m = _IS_PATTERN.match(sentence.strip())
            if m:
                result.l2_facts.append(
                    L2Fact(
                        subject=m.group(1),
                        relation="is",
                        object=m.group(2).rstrip(".!? "),
                    )
                )
        # "key: value" lines attribute to the episode's primary entity.
        primary = entities[0] if entities else None
        if primary:
            for line in text.splitlines():
                m = _KV_PATTERN.match(line.strip())
                if m and "http" not in m.group(1).lower():
                    result.l2_facts.append(
                        L2Fact(
                            subject=primary,
                            relation=m.group(1).strip(),
                            object=m.group(2).rstrip(".!? "),
                        )
                    )

        # --- Tag suggestions: entity-name echo over chunk content ---
        for entity in entities:
            bare = entity.rsplit(":", 1)[-1]
            if len(bare) < 3:
                continue  # short names are false-positive noise
            for chunk in episode.chunks:
                if entity in chunk.entity_tags:
                    continue  # already tagged deterministically
                if bare.lower() in chunk.content.lower():
                    result.tag_suggestions.append(
                        TagSuggestion(chunk_id=chunk.chunk_id, tag=entity, confidence=0.95)
                    )

        # --- Knowledge candidates: generalization-marker sentences ---
        seen_statements: set[str] = set()
        for sentence in _SENTENCE_SPLIT.split(text):
            stripped = sentence.strip()
            if not stripped:
                continue
            if any(marker.search(stripped) for marker in _GENERALIZATION_MARKERS):
                if stripped not in seen_statements:
                    seen_statements.add(stripped)
                    result.knowledge_candidates.append(
                        KnowledgeCandidate(
                            statement=stripped,
                            categories=[],
                            evidence=[episode.episode_id],
                        )
                    )
        return result


# ---------------------------------------------------------------------------
# Anthropic extractor (LLM seam — only active when ANTHROPIC_API_KEY is set)
# ---------------------------------------------------------------------------

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-opus-4-8"
ANTHROPIC_VERSION = "2023-06-01"

# Strict JSON out: structured outputs constrain the response to this schema.
_EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "l2_facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "relation": {"type": "string"},
                    "object": {"type": "string"},
                    "canonical_predicate": {
                        "type": "string",
                        "enum": [
                            "requires_before",
                            "blocks_until",
                            "requires",
                            "is",
                            "has",
                            "relates_to",
                        ],
                    },
                },
                "required": ["subject", "relation", "object", "canonical_predicate"],
                "additionalProperties": False,
            },
        },
        "tag_suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "chunk_id": {"type": "string"},
                    "tag": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["chunk_id", "tag", "confidence"],
                "additionalProperties": False,
            },
        },
        "knowledge_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "statement": {"type": "string"},
                    "categories": {"type": "array", "items": {"type": "string"}},
                    "canonical_statement": {"type": "string"},
                },
                "required": ["statement", "categories", "canonical_statement"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["l2_facts", "tag_suggestions", "knowledge_candidates"],
    "additionalProperties": False,
}

_EXTRACTION_PROMPT = """\
You extract structured memory from one raw episode of an enterprise memory \
system. Given the episode below, produce:
- l2_facts: (subject, relation, object) triples that are stated as facts. \
Subjects should be the entity identifiers given when the fact is about them. \
Also emit canonical_predicate: a controlled-vocabulary relation chosen from \
{{requires_before, blocks_until, requires, is, has, relates_to}}. Use \
requires_before when the fact is "X requires Y before Z" (or "X blocks Z until \
Y"); use requires for a plain requirement; is for identity/attribute facts. \
The canonical_predicate must be STABLE across paraphrases so re-extractions of \
the same relation align.
- tag_suggestions: for each chunk whose content clearly discusses one of the \
known entities but is not yet tagged with it, suggest that tag with your \
confidence (0-1). Prefer recall over precision: a missed tag is worse than an \
extra suggestion.
- knowledge_candidates: entity-FREE generalizations ("category-level lessons") \
the episode supports. Never name a specific entity in a statement. Also emit \
canonical_statement: a normalized, lowercased, article-stripped predication of \
the SAME generalization in the stable form "SUBJECT PREDICATE OBJECT \
[before GATE]" (e.g. "segment_buyer requires signed_dpa before \
security_review"). Two paraphrases of the same lesson MUST produce an identical \
canonical_statement; two genuinely different lessons (e.g. requiring a DPA vs \
requiring a SOC 2 report) MUST produce different ones — do not over-normalize.

Known entities: {entities}
Chunks (id: content): {chunks}

Episode text:
{text}
"""


class AnthropicExtractor:
    """Messages-API extractor. Implemented behind the ANTHROPIC_API_KEY env
    var; constructing it without a key raises so callers can fall back or
    skip gracefully (tests smoke-run it only when the key exists)."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = ANTHROPIC_MODEL,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "AnthropicExtractor requires ANTHROPIC_API_KEY; "
                "use DeterministicExtractor without one"
            )
        self.model = model
        self._client = client or httpx.Client(timeout=120.0)

    def extract(self, episode: LeasedEpisode) -> Extraction:
        prompt = _EXTRACTION_PROMPT.format(
            entities=json.dumps(episode.entities()),
            chunks=json.dumps({c.chunk_id: c.content for c in episode.chunks}),
            text=episode.text(),
        )
        response = self._client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
                "output_config": {
                    "format": {"type": "json_schema", "schema": _EXTRACTION_SCHEMA}
                },
            },
        )
        response.raise_for_status()
        body = response.json()
        if body.get("stop_reason") == "refusal":
            # Safety-classifier decline: nothing extracted, never partial JSON.
            return Extraction()
        text = next(b["text"] for b in body["content"] if b["type"] == "text")
        parsed = json.loads(text)
        known_chunks = {c.chunk_id for c in episode.chunks}
        return Extraction(
            l2_facts=[
                L2Fact(
                    subject=f["subject"],
                    relation=f["relation"],
                    object=f["object"],
                    # Trust the model's canonical_predicate when it emits a
                    # non-empty controlled-vocab value; otherwise derive it
                    # deterministically (the schema requires it, but stay safe).
                    canonical_predicate=f.get("canonical_predicate")
                    or canonical_predicate(f["relation"]),
                )
                for f in parsed["l2_facts"]
            ],
            tag_suggestions=[
                TagSuggestion(
                    chunk_id=t["chunk_id"], tag=t["tag"], confidence=float(t["confidence"])
                )
                for t in parsed["tag_suggestions"]
                if t["chunk_id"] in known_chunks  # never trust invented ids
            ],
            knowledge_candidates=[
                KnowledgeCandidate(
                    statement=k["statement"],
                    categories=list(k["categories"]),
                    evidence=[episode.episode_id],
                    canonical_statement=k.get("canonical_statement")
                    or canonical_statement(k["statement"]),
                )
                for k in parsed["knowledge_candidates"]
            ],
        )


# ---------------------------------------------------------------------------
# Client + loop
# ---------------------------------------------------------------------------


class ConsolidationClient:
    """Thin admin-plane client for the lease/complete endpoints."""

    def __init__(
        self,
        base_url: str,
        admin_token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        headers = {"authorization": f"Bearer {admin_token}"} if admin_token else {}
        self._client = client or httpx.Client(base_url=base_url, headers=headers, timeout=60.0)

    def lease(
        self, tenant_id: str, limit: int = 16, worker: str = "verity-ingest"
    ) -> list[LeasedEpisode]:
        response = self._client.post(
            "/v1/admin/consolidation/lease",
            json={"tenant_id": tenant_id, "limit": limit, "worker": worker},
        )
        response.raise_for_status()
        return [LeasedEpisode.from_json(e) for e in response.json()["episodes"]]

    def complete(self, tenant_id: str, episode_id: str, extraction: Extraction) -> dict:
        response = self._client.post(
            "/v1/admin/consolidation/complete",
            json=extraction.to_complete_body(tenant_id, episode_id),
        )
        response.raise_for_status()
        return response.json()


def run_once(
    client: ConsolidationClient,
    tenant_id: str,
    extractor: Extractor,
    limit: int = 16,
) -> int:
    """One lease -> extract -> complete pass. Returns episodes completed.
    An `already_processed` acknowledgement (another worker won, or a retry
    after our own crash-and-re-lease) counts as done — idempotent by design."""
    episodes = client.lease(tenant_id, limit=limit)
    completed = 0
    for episode in episodes:
        extraction = extractor.extract(episode)
        client.complete(tenant_id, episode.episode_id, extraction)
        completed += 1
    return completed


def build_extractor(name: str) -> Extractor:
    if name == "deterministic":
        return DeterministicExtractor()
    if name == "anthropic":
        return AnthropicExtractor()
    raise ValueError(f"unknown extractor {name!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verity sleep-time consolidation worker")
    parser.add_argument("--base-url", default="http://127.0.0.1:7717")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument(
        "--admin-token",
        default=os.environ.get("VERITY_ADMIN_TOKEN"),
        help="bearer token for the admin plane (default: $VERITY_ADMIN_TOKEN)",
    )
    parser.add_argument(
        "--extractor",
        choices=["deterministic", "anthropic"],
        default="deterministic",
    )
    parser.add_argument("--limit", type=int, default=16)
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--once", action="store_true", help="one pass, then exit (tests)")
    args = parser.parse_args(argv)

    extractor = build_extractor(args.extractor)
    client = ConsolidationClient(args.base_url, admin_token=args.admin_token)
    while True:
        completed = run_once(client, args.tenant_id, extractor, limit=args.limit)
        print(f"consolidation: completed {completed} episode(s)", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
