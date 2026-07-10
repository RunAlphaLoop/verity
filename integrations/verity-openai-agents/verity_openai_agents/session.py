"""``VeritySession`` — OpenAI Agents SDK ``Session`` backend for Verity (SPEC §9c).

Conversation history stored through Verity's permission plane instead of a
bare SQLite file. Each conversation item is one Verity document
(``document_id = "session:<id>/item:<n>"``) tagged with the session entity
tag ``"session:<id>"``, so every read is entity-scoped and every write
carries an explicit visibility policy.

Snapshot-grade convenience lane: ``visibility_policy`` is REQUIRED with no
default — omitting it raises the teaching error. Bypass is impossible, not
discouraged.

Read-back design (documented choice): ``get_items`` uses ``POST /v1/recall``
with the session entity tag as the scope filter plus client-side ``seq``
ordering — NOT ``GET /v1/briefs/{entity}``, because the brief caps at the
newest 10 chunks while recall returns up to the server's k=100 window. The
query text is the session id (it appears in every stored envelope, so the
BM25 leg matches every item; the dense leg independently returns everything
inside the entity scope). Sessions longer than 100 chunks exceed the recall
window — that cap is a documented v0.2 limit of the sink lane.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import httpx

from ._client import VerityClient, require_visibility_policy

if TYPE_CHECKING:  # structural Session protocol — no runtime import needed
    from agents.items import TResponseInputItem
else:  # pragma: no cover — typing alias only
    TResponseInputItem = Any

#: Marker baked into every stored envelope (BM25-matchable, greppable).
ITEM_KIND = "openai-agents-session-item"

#: The server caps recall at k=100; sessions beyond that exceed the window.
RECALL_WINDOW = 100


def session_tag(session_id: str) -> str:
    """``"s-123"`` -> ``"session:s-123"`` — the entity tag every item carries."""
    if not session_id or not isinstance(session_id, str):
        raise ValueError("VeritySession: session_id must be a non-empty string")
    return f"session:{session_id}"


class VeritySession:
    """OpenAI Agents SDK ``Session`` protocol implementation backed by Verity.

    - ``add_items()`` posts each item to ``POST /v1/ingest/documents`` (admin
      token) as ``document_id = "session:<id>/item:<n>"`` with the session
      entity tag, ``visibility`` from the required ``visibility_policy`` and
      ``acl_provenance="admin-assigned"``.
    - ``get_items()`` mints an entity-scoped handle from that same policy and
      calls ``POST /v1/recall``, then orders client-side by item ``seq``.
    - ``pop_item()`` / ``clear_session()`` retire item episodes via
      ``POST /v1/forget`` (invalidate-don't-delete).
    """

    session_settings = None  # Session protocol attribute (no per-session overrides)

    def __init__(
        self,
        session_id: str,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "openai-agents-session",
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.visibility_policy = require_visibility_policy(
            visibility_policy, "VeritySession"
        )
        self.session_id = session_id
        self._tag = session_tag(session_id)
        self.tenant_id = tenant_id
        self.source = source
        self._client = VerityClient(
            verity_url,
            tenant_id,
            admin_token=admin_token,
            timeout=timeout,
            transport=transport,
        )
        #: Next item seq; lazily initialized from read-back (max seen + 1) so
        #: a fresh VeritySession can append to an existing conversation.
        self._next_seq: Optional[int] = None

    @property
    def client(self) -> VerityClient:
        return self._client

    # ---------- internal sync plumbing ----------

    def _document_id(self, seq: int) -> str:
        return f"session:{self.session_id}/item:{seq}"

    def _fetch(self) -> List[Tuple[int, Any, str]]:
        """All live items, ordered by seq: ``[(seq, item, episode_id), ...]``.

        One recall (query text = session id) inside the session entity scope;
        multi-chunk documents are re-joined by chunk seq before JSON parsing.
        """
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[self._tag])
        hits = self._client.recall(
            scope_handle=handle, k=RECALL_WINDOW, text=self.session_id
        )
        by_doc: Dict[str, Dict[str, Any]] = {}
        for hit in hits:
            doc = by_doc.setdefault(
                hit["document_id"], {"chunks": {}, "episode": hit["provenance"]}
            )
            doc["chunks"][hit["seq"]] = hit["content"]
        items: List[Tuple[int, Any, str]] = []
        for doc in by_doc.values():
            content = "".join(c for _, c in sorted(doc["chunks"].items()))
            try:
                envelope = json.loads(content)
            except ValueError:
                continue  # partial multi-chunk read-back (item > recall window)
            if envelope.get("kind") != ITEM_KIND:
                continue
            items.append((envelope["seq"], envelope["item"], doc["episode"]))
        items.sort(key=lambda t: t[0])
        return items

    def _ensure_seq(self) -> int:
        if self._next_seq is None:
            existing = self._fetch()
            self._next_seq = existing[-1][0] + 1 if existing else 0
        return self._next_seq

    def _add_items(self, items: List[TResponseInputItem]) -> None:
        seq = self._ensure_seq()
        for item in items:
            envelope = {
                "kind": ITEM_KIND,
                "session": self.session_id,
                "seq": seq,
                "item": item,
            }
            self._client.ingest_document(
                source=self.source,
                document_id=self._document_id(seq),
                content=json.dumps(envelope, sort_keys=True),
                entities=[self._tag],
                visibility=self.visibility_policy,
            )
            seq += 1
        self._next_seq = seq

    def _forget_episode(self, episode_id: str, reason: str) -> None:
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[self._tag])
        self._client.forget(
            scope_handle=handle, kind="episode", id=episode_id, reason=reason
        )

    def _get_items(self, limit: Optional[int]) -> List[TResponseInputItem]:
        items = [item for _, item, _ in self._fetch()]
        if limit is not None:
            items = items[-limit:] if limit > 0 else []
        return items

    def _pop_item(self) -> Optional[TResponseInputItem]:
        items = self._fetch()
        if not items:
            return None
        seq, item, episode_id = items[-1]
        self._forget_episode(
            episode_id, f"openai-agents pop_item {self._document_id(seq)}"
        )
        self._next_seq = seq  # the popped seq is free again
        return item

    def _clear_session(self) -> None:
        seen: set = set()
        for seq, _, episode_id in self._fetch():
            if episode_id in seen:
                continue
            seen.add(episode_id)
            self._forget_episode(
                episode_id, f"openai-agents clear_session {self._document_id(seq)}"
            )

    # ---------- Session protocol (async) ----------

    async def get_items(self, limit: Optional[int] = None) -> List[TResponseInputItem]:
        """Conversation history, oldest first; ``limit`` = latest N items."""
        return await asyncio.to_thread(self._get_items, limit)

    async def add_items(self, items: List[TResponseInputItem]) -> None:
        """Append items in order, one Verity document per item."""
        await asyncio.to_thread(self._add_items, list(items))

    async def pop_item(self) -> Optional[TResponseInputItem]:
        """Retire and return the newest item (``POST /v1/forget``)."""
        return await asyncio.to_thread(self._pop_item)

    async def clear_session(self) -> None:
        """Retire every item in the session (invalidate-don't-delete)."""
        await asyncio.to_thread(self._clear_session)

    def close(self) -> None:
        self._client.close()
