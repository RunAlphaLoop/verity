"""``VerityStore`` — LangGraph ``BaseStore`` adapter for Verity (SPEC §5e.4).

Long-term agent memory written through Verity's permission plane instead of a
bare KV store. Namespace tuples become Verity entity tags (``("agents",
"alice")`` -> ``"ns:agents/alice"``), so every read is entity-scoped and every
write carries an explicit visibility policy.

Snapshot-grade convenience lane: ``visibility_policy`` is REQUIRED with no
default — omitting it raises the teaching error. Bypass is impossible, not
discouraged.
"""

from __future__ import annotations

import asyncio
import json
from typing import Dict, Iterable, List, Optional, Tuple

import httpx
from langgraph.store.base import (
    BaseStore,
    GetOp,
    Item,
    ListNamespacesOp,
    Op,
    PutOp,
    Result,
    SearchItem,
    SearchOp,
)

from ._client import VerityClient, parse_timestamp, require_visibility_policy


def namespace_tag(namespace: Tuple[str, ...]) -> str:
    """``("agents", "alice")`` -> ``"ns:agents/alice"``."""
    if not namespace:
        raise ValueError("VerityStore: namespace tuple must be non-empty")
    for part in namespace:
        if not isinstance(part, str) or not part or "/" in part:
            raise ValueError(
                f"VerityStore: namespace parts must be non-empty strings without "
                f"'/', got {namespace!r}"
            )
    return "ns:" + "/".join(namespace)


class VerityStore(BaseStore):
    """LangGraph ``BaseStore`` backed by a Verity server.

    - ``put()`` posts the JSON value to ``POST /v1/ingest/documents`` under
      the admin token, tagged with the namespace entity tag, with
      ``visibility`` from the required ``visibility_policy`` and
      ``acl_provenance="admin-assigned"``.
    - ``search()`` mints an entity-scoped handle from that same policy and
      calls ``POST /v1/recall`` (query-less search lists newest items via the
      entity brief).
    - ``get()`` reads the newest version through ``GET /v1/briefs/{entity}``.
    - ``delete()`` retires the item's episode via ``POST /v1/forget``
      (invalidate-don't-delete).

    ``list_namespaces`` is not supported in the sink lane.
    """

    def __init__(
        self,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "langgraph-store",
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.visibility_policy = require_visibility_policy(
            visibility_policy, "VerityStore"
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
        #: (namespace, key) -> latest episode id written this session.
        self._episodes: Dict[Tuple[Tuple[str, ...], str], str] = {}

    @property
    def client(self) -> VerityClient:
        return self._client

    # ---------- BaseStore contract ----------

    def batch(self, ops: Iterable[Op]) -> List[Result]:
        results: List[Result] = []
        for op in ops:
            if isinstance(op, PutOp):
                results.append(self._apply_put(op))
            elif isinstance(op, GetOp):
                results.append(self._apply_get(op))
            elif isinstance(op, SearchOp):
                results.append(self._apply_search(op))
            elif isinstance(op, ListNamespacesOp):
                raise NotImplementedError(
                    "VerityStore does not enumerate namespaces (sink lane); "
                    "query per namespace instead"
                )
            else:  # pragma: no cover — future op types fail closed
                raise NotImplementedError(f"unsupported op: {op!r}")
        return results

    async def abatch(self, ops: Iterable[Op]) -> List[Result]:
        return await asyncio.to_thread(self.batch, list(ops))

    # ---------- op handlers ----------

    @staticmethod
    def _document_id(namespace: Tuple[str, ...], key: str) -> str:
        return "/".join(namespace) + "/" + key

    def _apply_put(self, op: PutOp) -> None:
        if op.value is None:  # BaseStore.delete() arrives as PutOp(value=None)
            self._forget(op.namespace, op.key)
            return None
        tag = namespace_tag(op.namespace)
        result = self._client.ingest_document(
            source=self.source,
            document_id=self._document_id(op.namespace, op.key),
            content=json.dumps(op.value, sort_keys=True),
            entities=[tag],
            visibility=self.visibility_policy,
        )
        self._episodes[(tuple(op.namespace), op.key)] = result["episode_id"]
        return None

    def _newest_hit(self, namespace: Tuple[str, ...], key: str) -> Optional[dict]:
        """Newest live chunk for one item, via the entity brief (recency-
        ordered, no query leg needed)."""
        tag = namespace_tag(namespace)
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[tag])
        brief = self._client.brief(scope_handle=handle, entity=tag)
        document_id = self._document_id(namespace, key)
        for hit in brief["recent_memory"]:  # newest first
            if hit["document_id"] == document_id:
                return hit
        return None

    def _apply_get(self, op: GetOp) -> Optional[Item]:
        hit = self._newest_hit(op.namespace, op.key)
        if hit is None:
            return None
        written_at = parse_timestamp(hit["valid_from"])
        return Item(
            value=json.loads(hit["content"]),
            key=op.key,
            namespace=tuple(op.namespace),
            created_at=written_at,
            updated_at=written_at,
        )

    def _apply_search(self, op: SearchOp) -> List[SearchItem]:
        if op.filter:
            raise NotImplementedError(
                "VerityStore.search does not support value filters (sink lane)"
            )
        tag = namespace_tag(op.namespace_prefix)
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[tag])
        if op.query is not None:
            hits = self._client.recall(
                scope_handle=handle, k=op.limit + op.offset, text=op.query
            )
        else:  # query-less listing: newest items from the entity brief
            hits = self._client.brief(scope_handle=handle, entity=tag)["recent_memory"]
        prefix = "/".join(op.namespace_prefix) + "/"
        items: List[SearchItem] = []
        seen: set = set()
        for hit in hits:
            document_id = hit["document_id"]
            if not document_id.startswith(prefix) or document_id in seen:
                continue  # one SearchItem per item, newest/best chunk wins
            seen.add(document_id)
            written_at = parse_timestamp(hit["valid_from"])
            items.append(
                SearchItem(
                    namespace=tuple(op.namespace_prefix),
                    key=document_id[len(prefix):],
                    value=json.loads(hit["content"]),
                    created_at=written_at,
                    updated_at=written_at,
                    score=hit["score"] if op.query is not None else None,
                )
            )
        return items[op.offset : op.offset + op.limit]

    def _forget(self, namespace: Tuple[str, ...], key: str) -> None:
        """Retire the item's episode. Falls back to a brief lookup for items
        written by other sessions; deleting a missing item is a no-op
        (matching ``BaseStore.delete`` semantics)."""
        episode_id = self._episodes.pop((tuple(namespace), key), None)
        if episode_id is None:
            hit = self._newest_hit(namespace, key)
            if hit is None:
                return
            episode_id = hit["provenance"]
        tag = namespace_tag(namespace)
        handle = self._client.mint_scope(self.visibility_policy, entity_scope=[tag])
        self._client.forget(
            scope_handle=handle,
            kind="episode",
            id=episode_id,
            reason=f"langgraph-store delete {self._document_id(namespace, key)}",
        )
