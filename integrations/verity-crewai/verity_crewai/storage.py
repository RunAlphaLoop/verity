"""``VerityStorage`` — CrewAI ``StorageBackend`` for Verity (SPEC §9c).

Crew memory written through Verity's permission plane instead of a local
LanceDB file. CrewAI scope paths become Verity entity tags (``"/crew/research"``
-> ``"crew:/crew/research"``, one exact tag per record — Verity entity scoping
is subset-semantics over exact tags, SPEC §7d), and every write carries an
explicit visibility policy. ``scope_prefix`` filters are applied client-side
over the parsed envelopes (hierarchical prefixes cannot be expressed as an
exact-tag entity scope); the server-side enforcement boundary is always the
visibility policy.

Snapshot-grade convenience lane: ``visibility_policy`` is REQUIRED with no
default — omitting it raises the teaching error. Bypass is impossible, not
discouraged.

**Interface note (researched July 2026):** CrewAI 1.x replaced the old
``ExternalMemory`` plug point (SPEC §9c names it; it was removed in the 1.0
unified-memory rewrite) with the ``StorageBackend`` protocol in
``crewai.memory.storage.backend``, wired as ``Memory(storage=...)`` and
``Crew(memory=Memory(...))``. This class implements that current protocol;
verified against crewai 1.15.2.

**The embedder shim (required wiring):** CrewAI hands ``search()`` only a
``query_embedding`` — never the query text — while Verity encodes queries
server-side (read-path purity: the sink cannot inject foreign vectors into
an index built by the server's encoder). ``VerityStorage.embedder`` bridges
the two: a deterministic hash-based pseudo-embedder that CrewAI treats as a
normal embedding callable, whose vectors this storage maps back to the
original text and forwards as the ``text`` leg of ``POST /v1/recall``.
Construct ``Memory(storage=storage, embedder=storage.embedder)`` — search
fails with a teaching error if a foreign embedder's vector arrives.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx
from crewai.memory.types import MemoryRecord

from ._client import VerityClient, require_visibility_policy

#: Marker baked into every stored envelope (BM25-matchable for listing).
RECORD_KIND = "crewai-memory-record"

#: Pseudo-embedding dimension: 16 two-byte lanes from one SHA-256 digest.
#: Distinct texts get near-orthogonal vectors, so CrewAI's client-side
#: intra-batch cosine dedup only ever collapses *identical* texts (cos=1).
EMBEDDER_DIM = 16

#: The server caps recall at k=100 — the listing window of the sink lane.
RECALL_WINDOW = 100

#: How many (vector -> text) mappings the embedder shim retains.
STASH_CAPACITY = 4096

FOREIGN_EMBEDDING_TEACHING = (
    "VerityStorage.search received an embedding it did not produce. Verity "
    "encodes queries server-side (read-path purity), so CrewAI must be wired "
    "with this storage's own embedder shim: "
    "Memory(storage=storage, embedder=storage.embedder). The shim maps its "
    "deterministic pseudo-embeddings back to the query text and forwards the "
    "text to POST /v1/recall."
)


def normalize_scope(scope: Optional[str]) -> str:
    """``None``/``""`` -> ``"/"``; ensure exactly one leading, no trailing ``/``."""
    if not scope:
        return "/"
    path = "/" + scope.strip("/")
    return path


def scope_tag(scope: Optional[str]) -> str:
    """``"/crew/research"`` -> ``"crew:/crew/research"``."""
    return "crew:" + normalize_scope(scope)


def in_scope(scope: str, prefix: Optional[str]) -> bool:
    """Hierarchical prefix match: ``"/crew"`` covers ``"/crew/research"``."""
    path = normalize_scope(prefix)
    if path == "/":
        return True
    return scope == path or scope.startswith(path + "/")


def _pseudo_embedding(text: str) -> List[float]:
    """Deterministic unit-scale vector from SHA-256: 16 lanes in [-1, 1]."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [
        int.from_bytes(digest[2 * i : 2 * i + 2], "big") / 32767.5 - 1.0
        for i in range(EMBEDDER_DIM)
    ]


class VerityStorage:
    """CrewAI ``StorageBackend`` (structural protocol) backed by a Verity server.

    - ``save()`` posts each record's JSON envelope to
      ``POST /v1/ingest/documents`` (admin token), tagged with the record's
      exact scope tag, with ``visibility`` from the required
      ``visibility_policy`` and ``acl_provenance="admin-assigned"``.
    - ``search()`` maps the shim's pseudo-embedding back to the query text,
      mints a handle from that same policy, and calls ``POST /v1/recall``
      (server-side hybrid encoding). ``scope_prefix`` / ``categories`` /
      ``metadata_filter`` / ``min_score`` are applied client-side.
    - ``update()`` re-ingests the same document id — a bi-temporal supersede.
    - ``delete(record_ids=...)`` / ``reset()`` retire episodes via
      ``POST /v1/forget`` (invalidate-don't-delete). ``reset`` retires what
      this instance wrote (per-scope); a cross-session hard purge is the §8
      admin erasure pipeline, deliberately not reachable from a sink.
    - Hierarchy enumeration (``get_scope_info`` / ``list_scopes`` /
      ``list_categories``) is not supported in the sink lane and fails
      closed with ``NotImplementedError``.
    """

    def __init__(
        self,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "crewai-memory",
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.visibility_policy = require_visibility_policy(
            visibility_policy, "VerityStorage"
        )
        self.tenant_id = tenant_id
        self.source = source
        self._client = VerityClient(
            verity_url,
            tenant_id,
            admin_token=admin_token,
            timeout=timeout,
            transport=transport,
        )
        #: record_id -> (episode_id, normalized scope) for writes this session.
        self._episodes: Dict[str, Tuple[str, str]] = {}
        #: pseudo-embedding key -> source text (bounded, thread-safe).
        self._stash: OrderedDict[Tuple[float, ...], str] = OrderedDict()
        self._stash_lock = threading.Lock()

    @property
    def client(self) -> VerityClient:
        return self._client

    # ---------- the embedder shim ----------

    def embedder(self, texts: List[str]) -> List[List[float]]:
        """Deterministic pseudo-embedder for ``Memory(embedder=...)``.

        Verity never sees these vectors: they exist so CrewAI's plumbing can
        hand ``search()`` something that maps back to the query text.
        """
        vectors: List[List[float]] = []
        with self._stash_lock:
            for text in texts:
                vector = _pseudo_embedding(text)
                key = tuple(vector)
                self._stash[key] = text
                self._stash.move_to_end(key)
                while len(self._stash) > STASH_CAPACITY:
                    self._stash.popitem(last=False)
                vectors.append(vector)
        return vectors

    def _query_text(self, query_embedding: List[float]) -> str:
        with self._stash_lock:
            text = self._stash.get(tuple(float(x) for x in query_embedding))
        if text is None:
            raise ValueError(f"VerityStorage: {FOREIGN_EMBEDDING_TEACHING}")
        return text

    # ---------- envelope codec ----------

    @staticmethod
    def _document_id(record_id: str) -> str:
        return f"crewai/{record_id}"

    @staticmethod
    def _envelope(record: MemoryRecord) -> str:
        return json.dumps(
            {
                "kind": RECORD_KIND,
                "id": record.id,
                "content": record.content,
                "scope": normalize_scope(record.scope),
                "categories": record.categories,
                "metadata": record.metadata,
                "importance": record.importance,
                "created_at": record.created_at.isoformat(),
                "last_accessed": record.last_accessed.isoformat(),
                "source": record.source,
                "private": record.private,
            },
            sort_keys=True,
        )

    @staticmethod
    def _record_from(envelope: dict) -> MemoryRecord:
        return MemoryRecord(
            id=envelope["id"],
            content=envelope["content"],
            scope=envelope["scope"],
            categories=envelope.get("categories") or [],
            metadata=envelope.get("metadata") or {},
            importance=envelope.get("importance", 0.5),
            created_at=datetime.fromisoformat(envelope["created_at"]),
            last_accessed=datetime.fromisoformat(envelope["last_accessed"]),
            source=envelope.get("source"),
            private=envelope.get("private", False),
        )

    def _parse_hits(
        self, hits: List[dict], scope_prefix: Optional[str]
    ) -> List[Tuple[MemoryRecord, float, str]]:
        """Recall hits -> ``[(record, score, episode_id)]``; multi-chunk
        documents re-joined by chunk seq, foreign/partial/out-of-scope
        documents skipped."""
        by_doc: Dict[str, Dict[str, Any]] = {}
        for hit in hits:
            doc = by_doc.setdefault(
                hit["document_id"],
                {"chunks": {}, "episode": hit["provenance"], "score": hit["score"]},
            )
            doc["chunks"][hit["seq"]] = hit["content"]
            doc["score"] = max(doc["score"], hit["score"])
        results: List[Tuple[MemoryRecord, float, str]] = []
        for doc in by_doc.values():
            content = "".join(c for _, c in sorted(doc["chunks"].items()))
            try:
                envelope = json.loads(content)
            except ValueError:
                continue
            if envelope.get("kind") != RECORD_KIND:
                continue
            record = self._record_from(envelope)
            if not in_scope(record.scope, scope_prefix):
                continue
            results.append((record, doc["score"], doc["episode"]))
        return results

    def _recall(
        self, text: str, scope_prefix: Optional[str]
    ) -> List[Tuple[MemoryRecord, float, str]]:
        """One recall over the policy's whole visibility (no entity scope —
        Verity entity scoping is exact-tag subset semantics, so hierarchical
        prefixes filter client-side), capped at the server's k=100 window."""
        handle = self._client.mint_scope(self.visibility_policy)
        hits = self._client.recall(scope_handle=handle, k=RECALL_WINDOW, text=text)
        return self._parse_hits(hits, scope_prefix)

    @staticmethod
    def _matches(
        record: MemoryRecord,
        categories: Optional[List[str]],
        metadata_filter: Optional[Dict[str, Any]],
    ) -> bool:
        if categories and not set(categories) & set(record.categories):
            return False
        if metadata_filter:
            for key, value in metadata_filter.items():
                if record.metadata.get(key) != value:
                    return False
        return True

    # ---------- StorageBackend contract: write plane ----------

    def save(self, records: List[MemoryRecord]) -> None:
        for record in records:
            scope = normalize_scope(record.scope)
            result = self._client.ingest_document(
                source=self.source,
                document_id=self._document_id(record.id),
                content=self._envelope(record),
                entities=[scope_tag(scope)],
                visibility=self.visibility_policy,
            )
            self._episodes[record.id] = (result["episode_id"], scope)

    def update(self, record: MemoryRecord) -> None:
        """Same document id, new version — bi-temporal supersede, never
        UPDATE-in-place."""
        self.save([record])

    def delete(
        self,
        scope_prefix: Optional[str] = None,
        categories: Optional[List[str]] = None,
        record_ids: Optional[List[str]] = None,
        older_than: Optional[datetime] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Retire records by id (``POST /v1/forget``). Only the id criterion
        is supported in the sink lane — predicate deletes over content the
        sink cannot enumerate would be a silent no-op, so they fail closed."""
        if record_ids is None or categories or older_than or metadata_filter:
            raise NotImplementedError(
                "VerityStorage.delete supports record_ids only (sink lane); "
                "scope-wide retirement is reset(scope_prefix); hard purge is "
                "the Verity §8 admin erasure pipeline"
            )
        deleted = 0
        for record_id in record_ids:
            tracked = self._episodes.pop(record_id, None)
            if tracked is not None:
                episode_id = tracked[0]
            else:  # cross-session: the id is in the envelope, BM25 finds it
                found = [
                    episode
                    for record, _, episode in self._recall(record_id, scope_prefix)
                    if record.id == record_id
                ]
                if not found:
                    continue
                episode_id = found[0]
            handle = self._client.mint_scope(self.visibility_policy)
            self._client.forget(
                scope_handle=handle,
                kind="episode",
                id=episode_id,
                reason=f"crewai-memory delete {self._document_id(record_id)}",
            )
            deleted += 1
        return deleted

    def reset(self, scope_prefix: Optional[str] = None) -> None:
        """Retire everything this instance wrote under ``scope_prefix``
        (invalidate-don't-delete). Records written by other sessions are NOT
        touched: a cross-session hard purge is the §8 admin erasure pipeline,
        deliberately not reachable from a sink credential."""
        prefix = normalize_scope(scope_prefix)
        for record_id, (episode_id, scope) in list(self._episodes.items()):
            if not in_scope(scope, prefix):
                continue
            handle = self._client.mint_scope(self.visibility_policy)
            self._client.forget(
                scope_handle=handle,
                kind="episode",
                id=episode_id,
                reason=f"crewai-memory reset {prefix}",
            )
            del self._episodes[record_id]

    # ---------- StorageBackend contract: read plane ----------

    def search(
        self,
        query_embedding: List[float],
        scope_prefix: Optional[str] = None,
        categories: Optional[List[str]] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        min_score: float = 0.0,
    ) -> List[Tuple[MemoryRecord, float]]:
        text = self._query_text(query_embedding)
        parsed = self._recall(text, scope_prefix)
        results = [
            (record, score)
            for record, score, _ in parsed
            if score >= min_score and self._matches(record, categories, metadata_filter)
        ]
        results.sort(key=lambda pair: pair[1], reverse=True)
        return results[:limit]

    def get_record(self, record_id: str) -> Optional[MemoryRecord]:
        for record, _, _ in self._recall(record_id, None):
            if record.id == record_id:
                return record
        return None

    def list_records(
        self,
        scope_prefix: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        """Newest first, via a marker-token recall. The server caps recall at
        k=100, so this lists at most the sink lane's recall window."""
        parsed = self._recall(RECORD_KIND, scope_prefix)
        records = [record for record, _, _ in parsed]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[offset : offset + limit]

    def count(self, scope_prefix: Optional[str] = None) -> int:
        """Records visible inside the recall window (≤100 — documented cap)."""
        return len(self.list_records(scope_prefix, limit=RECALL_WINDOW))

    # ---------- hierarchy enumeration: fail closed in the sink lane ----------

    def get_scope_info(self, scope: str) -> Any:
        raise NotImplementedError(
            "VerityStorage does not enumerate scope hierarchies (sink lane); "
            "search or list_records per scope instead"
        )

    def list_scopes(self, parent: str = "/") -> List[str]:
        raise NotImplementedError(
            "VerityStorage does not enumerate scope hierarchies (sink lane); "
            "search or list_records per scope instead"
        )

    def list_categories(self, scope_prefix: Optional[str] = None) -> Dict[str, int]:
        raise NotImplementedError(
            "VerityStorage does not enumerate categories (sink lane); "
            "filter search(categories=...) instead"
        )

    # ---------- async variants (thread-offloaded) ----------

    async def asave(self, records: List[MemoryRecord]) -> None:
        await asyncio.to_thread(self.save, list(records))

    async def asearch(
        self,
        query_embedding: List[float],
        scope_prefix: Optional[str] = None,
        categories: Optional[List[str]] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        min_score: float = 0.0,
    ) -> List[Tuple[MemoryRecord, float]]:
        return await asyncio.to_thread(
            self.search,
            query_embedding,
            scope_prefix,
            categories,
            metadata_filter,
            limit,
            min_score,
        )

    async def adelete(
        self,
        scope_prefix: Optional[str] = None,
        categories: Optional[List[str]] = None,
        record_ids: Optional[List[str]] = None,
        older_than: Optional[datetime] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> int:
        return await asyncio.to_thread(
            self.delete, scope_prefix, categories, record_ids, older_than,
            metadata_filter,
        )

    def close(self) -> None:
        self._client.close()
