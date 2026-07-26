"""``VerityVectorStore`` + ``VerityRetriever`` — LangChain sink for Verity
(SPEC §5e.4).

Snapshot-grade convenience lane: 100–200+ community loaders inherited, but
loaders strip source ACLs by construction, so this lane is always
policy-based. ``visibility_policy`` is REQUIRED with no default — omitting it
raises the teaching error. Bypass is impossible, not discouraged.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.retrievers import BaseRetriever
from langchain_core.vectorstores import VectorStore
from pydantic import ConfigDict

from ._client import VerityClient, require_visibility_policy

#: Document metadata key that carries Verity entity tags (e.g. ``account:acme``).
ENTITIES_METADATA_KEY = "verity_entities"


def _document_from_hit(hit: dict) -> Document:
    """Shared hit->Document projection for both the policy and subject read
    lanes (identical recall response shape)."""
    return Document(
        id=hit["chunk_id"],
        page_content=hit["content"],
        metadata={
            "document_id": hit["document_id"],
            "entity_tags": hit["entity_tags"],
            "acl_provenance": hit["acl_provenance"],
            "trust_tier": hit["trust_tier"],
            "valid_from": hit["valid_from"],
            "provenance": hit["provenance"],
        },
    )


class VerityVectorStore(VectorStore):
    """LangChain vector store backed by a Verity server.

    - ``add_texts()`` posts each text to ``POST /v1/ingest/documents`` under
      the admin token, with ``visibility`` taken from the required
      ``visibility_policy`` and ``acl_provenance="admin-assigned"``.
    - ``similarity_search()`` mints a scope handle from that same policy and
      calls ``POST /v1/recall`` — the mandatory pre-filtered read path. The
      policy the constructor demanded is the ceiling of everything this sink
      can write and read.

    Embeddings are computed server-side by Verity's local encoder; no
    LangChain ``Embeddings`` object is required (or used).
    """

    def __init__(
        self,
        *,
        verity_url: str,
        tenant_id: str,
        visibility_policy: Optional[List[int]] = None,
        admin_token: Optional[str] = None,
        source: str = "langchain",
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.visibility_policy = require_visibility_policy(
            visibility_policy, "VerityVectorStore"
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
        #: document_id -> episode ids ingested this session (for ``delete``).
        self._episodes: Dict[str, List[str]] = {}

    @property
    def client(self) -> VerityClient:
        return self._client

    @property
    def embeddings(self) -> Optional[Embeddings]:
        return None  # encoding is server-side, on purpose

    # ---------- write plane ----------

    def add_texts(
        self,
        texts: Iterable[str],
        metadatas: Optional[List[dict]] = None,
        *,
        ids: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[str]:
        """Ingest one document version per text. Entity tags ride on metadata
        under ``verity_entities``."""
        texts = list(texts)
        metadatas = metadatas or [{} for _ in texts]
        ids = ids or [uuid.uuid4().hex for _ in texts]
        written: List[str] = []
        for text, metadata, document_id in zip(texts, metadatas, ids):
            entities = list((metadata or {}).get(ENTITIES_METADATA_KEY) or [])
            result = self._client.ingest_document(
                source=self.source,
                document_id=document_id,
                content=text,
                entities=entities,
                visibility=self.visibility_policy,
            )
            self._episodes.setdefault(document_id, []).append(result["episode_id"])
            written.append(document_id)
        return written

    def delete(self, ids: Optional[List[str]] = None, **kwargs: Any) -> Optional[bool]:
        """Retire (invalidate-don't-delete) via ``POST /v1/forget``.

        Snapshot-lane limitation: episode tracking is session-local. Deleting
        ids ingested by another process raises — never a silent no-op on the
        permission plane.
        """
        if not ids:
            raise ValueError("VerityVectorStore.delete requires explicit ids")
        unknown = [i for i in ids if i not in self._episodes]
        if unknown:
            raise ValueError(
                f"VerityVectorStore.delete: no episodes recorded for {unknown!r} in "
                "this session. Sink-lane deletes are session-local (snapshot-grade "
                "convenience lane, SPEC §5e.4); use POST /v1/forget with the episode "
                "id for anything ingested elsewhere."
            )
        handle = self._client.mint_scope(self.visibility_policy)
        for document_id in ids:
            for episode_id in self._episodes.pop(document_id):
                self._client.forget(
                    scope_handle=handle,
                    kind="episode",
                    id=episode_id,
                    reason=f"langchain delete id={document_id}",
                )
        return True

    # ---------- read plane ----------

    def similarity_search_with_score(
        self, query: str, k: int = 4, **kwargs: Any
    ) -> List[Tuple[Document, float]]:
        handle = self._client.mint_scope(self.visibility_policy)
        hits = self._client.recall(scope_handle=handle, k=k, text=query)
        return [(_document_from_hit(hit), hit["score"]) for hit in hits]

    def similarity_search(self, query: str, k: int = 4, **kwargs: Any) -> List[Document]:
        return [doc for doc, _ in self.similarity_search_with_score(query, k=k)]

    def as_retriever(self, **kwargs: Any) -> "VerityRetriever":
        """A ``BaseRetriever`` bound to this store's visibility policy."""
        search_kwargs = kwargs.pop("search_kwargs", {})
        k = search_kwargs.get("k", 4)
        return VerityRetriever(vectorstore=self, k=k, **kwargs)

    @classmethod
    def subject_retriever(
        cls,
        *,
        verity_url: str,
        tenant_id: str,
        subject: str,
        k: int = 4,
        entity_scope: Optional[List[str]] = None,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> "VeritySubjectRetriever":
        """Build a READ-ONLY retriever bound to a real ``subject`` (e.g.
        ``"user:alice@acme.example"``).

        Every read mints a subject-bound scope (``POST /v1/scopes`` with
        ``subject=``, resolved server-side via ReBAC — the caller's own token
        plus its transitive group closure, SPEC §6/§9a) and calls recall. This
        is deliberately NOT a ``VerityVectorStore``: there is no write path
        under a subject — writes stay policy-based/admin-assigned (SPEC §5e.4).
        No ``admin_token`` and no ``visibility_policy`` are accepted here.

        Requires ReBAC on the server (``VERITY_SPICEDB_URL``); without it the
        server rejects subject scopes 422.
        """
        client = VerityClient(
            verity_url,
            tenant_id,
            admin_token=None,
            timeout=timeout,
            transport=transport,
        )
        return VeritySubjectRetriever(
            client=client,
            subject=subject,
            k=k,
            entity_scope=list(entity_scope) if entity_scope else None,
        )

    # ---------- constructors ----------

    @classmethod
    def from_texts(
        cls,
        texts: List[str],
        embedding: Optional[Embeddings] = None,
        metadatas: Optional[List[dict]] = None,
        *,
        ids: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> "VerityVectorStore":
        """``embedding`` is accepted for interface compatibility and ignored:
        Verity encodes server-side. ``visibility_policy`` is still required."""
        store = cls(**kwargs)
        store.add_texts(texts, metadatas, ids=ids)
        return store


class VerityRetriever(BaseRetriever):
    """Scoped retriever: every ``invoke()`` reads through ``POST /v1/recall``
    under a scope minted from the store's required visibility policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    vectorstore: VerityVectorStore
    k: int = 4

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        return self.vectorstore.similarity_search(query, k=self.k)


class VeritySubjectRetriever(BaseRetriever):
    """READ-ONLY retriever bound to a real ``subject``.

    Every ``invoke()`` mints a subject-bound scope (``POST /v1/scopes`` with
    ``subject=``, resolved server-side via ReBAC into the caller's own token
    plus its transitive group closure) and reads through ``POST /v1/recall``.
    There is intentionally NO write path here: writes stay policy-based /
    admin-assigned (SPEC §5e.4). A subject read never widens visibility — it
    resolves the caller's real, already-granted powers.

    Construct via :meth:`VerityVectorStore.subject_retriever`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client: VerityClient
    subject: str
    k: int = 4
    entity_scope: Optional[List[str]] = None

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        handle = self.client.mint_subject_scope(
            self.subject, entity_scope=self.entity_scope
        )
        hits = self.client.recall(scope_handle=handle, k=self.k, text=query)
        return [_document_from_hit(hit) for hit in hits]
