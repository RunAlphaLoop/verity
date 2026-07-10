"""``VerityVectorStore`` — LlamaIndex sink for Verity (SPEC §5e.4).

Snapshot-grade convenience lane: every LlamaHub reader becomes a de-facto
Verity connector, but loaders strip source ACLs by construction, so this
lane is always policy-based. The ``visibility_policy`` constructor argument
is REQUIRED and has no default — omitting it raises the teaching error, and
bypass is impossible, not discouraged.

No push freshness, no per-object ACLs. Graduate to a native connector
(mirrored ACL provenance) for the truth lane.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

import httpx
from llama_index.core.schema import BaseNode, MetadataMode, TextNode
from llama_index.core.vector_stores.types import (
    BasePydanticVectorStore,
    VectorStoreQuery,
    VectorStoreQueryResult,
)

try:  # pydantic v2 (what llama-index-core >= 0.11 uses)
    from pydantic import PrivateAttr
except ImportError:  # pragma: no cover
    from llama_index.core.bridge.pydantic import PrivateAttr

from ._client import VerityClient, require_visibility_policy

#: Node metadata key that carries Verity entity tags (e.g. ``account:acme``).
ENTITIES_METADATA_KEY = "verity_entities"


class VerityVectorStore(BasePydanticVectorStore):
    """LlamaIndex vector store backed by a Verity server.

    - ``add()`` posts each node to ``POST /v1/ingest/documents`` under the
      admin token, with ``visibility`` taken from the required
      ``visibility_policy`` and ``acl_provenance="admin-assigned"``.
    - ``query()`` mints a scope handle from that same policy and calls
      ``POST /v1/recall`` — the mandatory pre-filtered read path. The policy
      the constructor demanded is the ceiling of everything this sink can
      write and read.

    Embeddings are computed server-side by Verity's local encoder; node/query
    embeddings supplied by LlamaIndex are ignored on write and optional on
    read (``query_str`` alone gives hybrid recall).
    """

    stores_text: bool = True

    verity_url: str
    tenant_id: str
    source: str = "llamaindex"
    visibility_policy: List[int]

    _client: VerityClient = PrivateAttr()
    #: ref_doc_id -> episode ids ingested this session (for ``delete``).
    _episodes: Dict[str, List[str]] = PrivateAttr(default_factory=dict)

    def __init__(
        self,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "llamaindex",
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
        **kwargs: Any,
    ) -> None:
        tokens = require_visibility_policy(visibility_policy, "VerityVectorStore")
        super().__init__(
            verity_url=verity_url,
            tenant_id=tenant_id,
            source=source,
            visibility_policy=tokens,
            **kwargs,
        )
        self._client = VerityClient(
            verity_url,
            tenant_id,
            admin_token=admin_token,
            timeout=timeout,
            transport=transport,
        )

    @classmethod
    def class_name(cls) -> str:
        return "VerityVectorStore"

    @property
    def client(self) -> VerityClient:
        return self._client

    # ---------- write plane ----------

    def add(self, nodes: Sequence[BaseNode], **kwargs: Any) -> List[str]:
        """Ingest one document version per node. Entity tags ride on node
        metadata under ``verity_entities``."""
        ids: List[str] = []
        for node in nodes:
            content = node.get_content(metadata_mode=MetadataMode.NONE)
            entities = list(node.metadata.get(ENTITIES_METADATA_KEY) or [])
            result = self._client.ingest_document(
                source=self.source,
                document_id=node.node_id,
                content=content,
                entities=entities,
                visibility=self.visibility_policy,
            )
            ref = node.ref_doc_id or node.node_id
            self._episodes.setdefault(ref, []).append(result["episode_id"])
            ids.append(node.node_id)
        return ids

    def delete(self, ref_doc_id: str, **delete_kwargs: Any) -> None:
        """Retire (invalidate-don't-delete) everything ingested for
        ``ref_doc_id`` in this session via ``POST /v1/forget``.

        Snapshot-lane limitation: episode tracking is session-local. Deleting
        a document ingested by another process raises — re-ingest or use the
        Verity API directly (never a silent no-op on the permission plane).
        """
        episodes = self._episodes.pop(ref_doc_id, None)
        if not episodes:
            raise ValueError(
                f"VerityVectorStore.delete: no episodes recorded for {ref_doc_id!r} "
                "in this session. Sink-lane deletes are session-local (snapshot-grade "
                "convenience lane, SPEC §5e.4); use POST /v1/forget with the episode "
                "id for anything ingested elsewhere."
            )
        handle = self._client.mint_scope(self.visibility_policy)
        for episode_id in episodes:
            self._client.forget(
                scope_handle=handle,
                kind="episode",
                id=episode_id,
                reason=f"llamaindex delete ref_doc_id={ref_doc_id}",
            )

    # ---------- read plane ----------

    def query(self, query: VectorStoreQuery, **kwargs: Any) -> VectorStoreQueryResult:
        if query.query_str is None and query.query_embedding is None:
            raise ValueError(
                "VerityVectorStore.query needs query_str and/or query_embedding"
            )
        if query.filters is not None:
            raise ValueError(
                "VerityVectorStore does not support LlamaIndex metadata filters; "
                "visibility filtering is structural (scope handle), not per-query"
            )
        handle = self._client.mint_scope(self.visibility_policy)
        hits = self._client.recall(
            scope_handle=handle,
            k=query.similarity_top_k,
            text=query.query_str,
            embedding=query.query_embedding,
        )
        nodes: List[TextNode] = []
        similarities: List[float] = []
        ids: List[str] = []
        for hit in hits:
            nodes.append(
                TextNode(
                    id_=hit["chunk_id"],
                    text=hit["content"],
                    metadata={
                        "document_id": hit["document_id"],
                        "entity_tags": hit["entity_tags"],
                        "acl_provenance": hit["acl_provenance"],
                        "trust_tier": hit["trust_tier"],
                        "valid_from": hit["valid_from"],
                        "provenance": hit["provenance"],
                    },
                )
            )
            similarities.append(hit["score"])
            ids.append(hit["chunk_id"])
        return VectorStoreQueryResult(nodes=nodes, similarities=similarities, ids=ids)
