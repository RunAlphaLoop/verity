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
# Wire types
# ---------------------------------------------------------------------------


@dataclass
class L2Fact:
    """One extracted triple. Server-side this becomes a deterministic L1-style
    upsert keyed (source=l2, entity=normalized subject, field=normalized
    relation) — supersession falls out of the existing machinery."""

    subject: str
    relation: str
    object: Any
    valid_from: str | None = None

    def to_json(self) -> dict:
        body: dict[str, Any] = {
            "subject": self.subject,
            "relation": self.relation,
            "object": self.object,
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
    similarity-merges into an existing candidate/published item (support
    accrual) or runs the de-identification gate on a fresh proposal."""

    statement: str
    categories: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "statement": self.statement,
            "categories": self.categories,
            "evidence": self.evidence,
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
                },
                "required": ["subject", "relation", "object"],
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
                },
                "required": ["statement", "categories"],
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
Subjects should be the entity identifiers given when the fact is about them.
- tag_suggestions: for each chunk whose content clearly discusses one of the \
known entities but is not yet tagged with it, suggest that tag with your \
confidence (0-1). Prefer recall over precision: a missed tag is worse than an \
extra suggestion.
- knowledge_candidates: entity-FREE generalizations ("category-level lessons") \
the episode supports. Never name a specific entity in a statement.

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
                L2Fact(subject=f["subject"], relation=f["relation"], object=f["object"])
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
