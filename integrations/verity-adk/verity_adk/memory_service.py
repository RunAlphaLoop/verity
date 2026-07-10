"""``VerityMemoryService`` — Google ADK ``BaseMemoryService`` for Verity (SPEC §9c).

Long-term agent memory written through Verity's permission plane instead of a
bare in-memory dict or a Vertex-hosted memory bank. Every event is one Verity
document (``document_id = "adk/<app>/<user>/<session>/<event>"``) tagged with
the user entity tag ``"adk:<app>/<user>"``, so every read is entity-scoped
and every write carries an explicit visibility policy.

Snapshot-grade convenience lane: ``visibility_policy`` is REQUIRED with no
default — omitting it raises the teaching error. Bypass is impossible, not
discouraged.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Mapping, Optional, Sequence

import httpx
from google.adk.memory import BaseMemoryService
from google.adk.memory.base_memory_service import SearchMemoryResponse
from google.adk.memory.memory_entry import MemoryEntry
from google.genai import types as genai_types

from ._client import VerityClient, require_visibility_policy

if TYPE_CHECKING:
    from google.adk.events import Event
    from google.adk.sessions import Session

#: Marker baked into every stored envelope (BM25-greppable provenance).
MEMORY_KIND = "adk-memory-event"

#: Doc-id bucket for delta writes that arrive without a session id.
UNKNOWN_SESSION_ID = "unknown-session"


def user_tag(app_name: str, user_id: str) -> str:
    """``("calendar", "alice")`` -> ``"adk:calendar/alice"`` — the memory
    scope ADK defines (per app, per user)."""
    for part in (app_name, user_id):
        if not part or not isinstance(part, str) or "/" in part:
            raise ValueError(
                f"VerityMemoryService: app_name/user_id must be non-empty strings "
                f"without '/', got ({app_name!r}, {user_id!r})"
            )
    return f"adk:{app_name}/{user_id}"


def _event_text(event: Event) -> str:
    return " ".join(
        part.text for part in event.content.parts if getattr(part, "text", None)
    )


def _format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class VerityMemoryService(BaseMemoryService):
    """Google ADK memory service backed by a Verity server.

    - ``add_session_to_memory(session)`` posts each text-bearing event to
      ``POST /v1/ingest/documents`` (admin token) under the user entity tag,
      with ``visibility`` from the required ``visibility_policy`` and
      ``acl_provenance="admin-assigned"``. Stable document ids make
      re-adding a session idempotent (one new version per re-ingest, same
      document identity — bi-temporal supersede, never duplicate memories).
    - ``add_events_to_memory(...)`` ingests an explicit event delta the same
      way (``session_id`` optional per the interface contract).
    - ``search_memory(...)`` mints an entity-scoped handle from that same
      policy and calls ``POST /v1/recall`` (hybrid, server-side encoding),
      returning ``MemoryEntry`` items with author/timestamp preserved.
    """

    def __init__(
        self,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "adk-memory",
        search_k: int = 10,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.visibility_policy = require_visibility_policy(
            visibility_policy, "VerityMemoryService"
        )
        self.tenant_id = tenant_id
        self.source = source
        self.search_k = search_k
        self._client = VerityClient(
            verity_url,
            tenant_id,
            admin_token=admin_token,
            timeout=timeout,
            transport=transport,
        )

    @property
    def client(self) -> VerityClient:
        return self._client

    # ---------- internal sync plumbing ----------

    def _ingest_events(
        self,
        app_name: str,
        user_id: str,
        session_id: str,
        events: Sequence[Event],
    ) -> None:
        tag = user_tag(app_name, user_id)
        for event in events:
            if not event.content or not event.content.parts:
                continue
            text = _event_text(event)
            if not text:
                continue
            envelope = {
                "kind": MEMORY_KIND,
                "author": event.author,
                "role": event.content.role,
                "timestamp": _format_timestamp(event.timestamp),
                "text": text,
            }
            self._client.ingest_document(
                source=self.source,
                document_id=f"adk/{app_name}/{user_id}/{session_id}/{event.id}",
                content=json.dumps(envelope, sort_keys=True),
                entities=[tag],
                visibility=self.visibility_policy,
            )

    def _search(self, app_name: str, user_id: str, query: str) -> SearchMemoryResponse:
        tag = user_tag(app_name, user_id)
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[tag])
        hits = self._client.recall(scope_handle=handle, k=self.search_k, text=query)
        response = SearchMemoryResponse()
        for hit in hits:
            try:
                envelope = json.loads(hit["content"])
            except ValueError:
                continue  # partial multi-chunk read-back of an oversized event
            if envelope.get("kind") != MEMORY_KIND:
                continue
            response.memories.append(
                MemoryEntry(
                    content=genai_types.Content(
                        role=envelope.get("role") or "user",
                        parts=[genai_types.Part(text=envelope["text"])],
                    ),
                    author=envelope.get("author"),
                    timestamp=envelope.get("timestamp"),
                )
            )
        return response

    # ---------- BaseMemoryService contract (async) ----------

    async def add_session_to_memory(self, session: Session) -> None:
        """Ingest every text-bearing event of the session (idempotent —
        stable per-event document ids)."""
        await asyncio.to_thread(
            self._ingest_events,
            session.app_name,
            session.user_id,
            session.id,
            list(session.events),
        )

    async def add_events_to_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        events: Sequence[Event],
        session_id: Optional[str] = None,
        custom_metadata: Optional[Mapping[str, object]] = None,
    ) -> None:
        """Ingest an explicit event delta (incremental update, per the
        interface contract). ``custom_metadata`` is not supported in the
        sink lane and is ignored."""
        _ = custom_metadata
        await asyncio.to_thread(
            self._ingest_events,
            app_name,
            user_id,
            session_id or UNKNOWN_SESSION_ID,
            list(events),
        )

    async def search_memory(
        self, *, app_name: str, user_id: str, query: str
    ) -> SearchMemoryResponse:
        """Scoped hybrid recall over this app/user's memory."""
        return await asyncio.to_thread(self._search, app_name, user_id, query)

    def close(self) -> None:
        self._client.close()


# Explicit re-export for typing convenience.
__all__ = [
    "MEMORY_KIND",
    "MemoryEntry",
    "SearchMemoryResponse",
    "UNKNOWN_SESSION_ID",
    "VerityMemoryService",
    "user_tag",
]
