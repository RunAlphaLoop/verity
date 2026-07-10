"""LlamaIndex conformance: REAL ``VectorStoreIndex`` machinery against a live
Verity server — ``VectorStoreIndex.from_vector_store`` + ``retriever.retrieve``,
not our client directly."""

from __future__ import annotations

import pytest
from llama_index.core import MockEmbedding, VectorStoreIndex
from llama_index.core.schema import TextNode

from verity_llamaindex import VerityVectorStore

pytestmark = pytest.mark.e2e

#: Must match the server's MiniLM chunk index (384-d): LlamaIndex insists on a
#: local embed model and passes its query vector through to ``/v1/recall``.
#: MockEmbedding satisfies the machinery; retrieval quality comes from the
#: server's hybrid recall (BM25 + server-side query encoding).
EMBED_DIM = 384

SENTINEL = "TEAM-A-ONLY llamaindex secret: the kite-9 launch is 2026-09-01."


def store_for(tenant, policy):
    return VerityVectorStore(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )


def index_for(store):
    return VectorStoreIndex.from_vector_store(store, embed_model=MockEmbedding(embed_dim=EMBED_DIM))


def test_native_write_native_read_roundtrip(tenant):
    index = index_for(store_for(tenant, tenant.team_a))
    index.insert_nodes(
        [
            TextNode(
                text="Acme renewed for 240 seats on 2026-06-30.",
                metadata={"verity_entities": ["account:acme"]},
            ),
            TextNode(
                text="Globex churned after the Q2 downtime.",
                metadata={"verity_entities": ["account:globex"]},
            ),
        ]
    )
    results = index.as_retriever(similarity_top_k=4).retrieve("Acme renewal seats")
    assert results, "retriever found nothing for content just written"
    assert any("240 seats" in r.node.get_content() for r in results)


def test_team_b_retriever_sees_nothing_of_team_a(tenant):
    index_for(store_for(tenant, tenant.team_a)).insert_nodes([TextNode(text=SENTINEL)])
    index_b = index_for(store_for(tenant, tenant.team_b))
    retriever_b = index_b.as_retriever(similarity_top_k=10)

    # Nothing visible at all under team B's policy...
    assert retriever_b.retrieve("kite-9 launch secret") == []

    # ...and after team B writes its own note the read path demonstrably
    # works, yet still returns nothing of team A's.
    index_b.insert_nodes([TextNode(text="Team B llamaindex note: umbrella-7 retro held.")])
    results = retriever_b.retrieve("kite-9 launch secret umbrella-7")
    assert results, "team B cannot read its own writes"
    assert all("TEAM-A-ONLY" not in r.node.get_content() for r in results)


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityVectorStore(
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
