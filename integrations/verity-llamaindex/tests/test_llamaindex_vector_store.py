"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response
from llama_index.core.schema import TextNode
from llama_index.core.vector_stores.types import (
    MetadataFilter,
    MetadataFilters,
    VectorStoreQuery,
)

from verity_llamaindex import VerityVectorStore

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}
HIT = {
    "chunk_id": "019f0000-0000-7000-8000-00000000c001",
    "document_id": "doc-1",
    "seq": 0,
    "content": "Acme renewed for 240 seats.",
    "score": 0.42,
    "entity_tags": ["account:acme"],
    "kind": "content",
    "acl_provenance": "admin-assigned",
    "trust_tier": "Authoritative",
    "valid_from": "2026-07-01T00:00:00Z",
    "provenance": "019f0000-0000-7000-8000-00000000e001",
}


def make_store(**overrides):
    kwargs = dict(
        verity_url=VERITY_URL,
        tenant_id=TENANT,
        visibility_policy=[3, 7],
        admin_token="test-admin-token",
    )
    kwargs.update(overrides)
    return VerityVectorStore(**kwargs)


def body(route, call=-1) -> dict:
    return json.loads(route.calls[call].request.content)


# ---------- the visibility_policy doctrine (SPEC §5e.4) ----------

def test_visibility_policy_is_required_and_teaches():
    with pytest.raises(ValueError) as err:
        VerityVectorStore(verity_url=VERITY_URL, tenant_id=TENANT)
    message = str(err.value)
    assert "SPEC §5e.4" in message
    assert "quarantined" in message
    assert "admin-assigned" in message


@pytest.mark.parametrize("bad", [[], (), "3,7", [3, "7"], [True], 3])
def test_visibility_policy_rejects_non_token_lists(bad):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityVectorStore(
            verity_url=VERITY_URL, tenant_id=TENANT, visibility_policy=bad
        )


# ---------- add() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_add_posts_exact_ingest_body(respx_mock):
    route = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(
            200, json={"episode_id": "ep-1", "chunks_indexed": 1}
        )
    )
    store = make_store()
    node = TextNode(
        id_="node-1",
        text="Acme renewed for 240 seats.",
        metadata={"verity_entities": ["account:acme"]},
    )
    ids = store.add([node])

    assert ids == ["node-1"]
    assert body(route) == {
        "tenant_id": TENANT,
        "source": "llamaindex",
        "document_id": "node-1",
        "content": "Acme renewed for 240 seats.",
        "entities": ["account:acme"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    assert route.calls.last.request.headers["authorization"] == "Bearer test-admin-token"


@respx.mock(base_url=VERITY_URL)
def test_add_without_entity_metadata_sends_empty_entities(respx_mock):
    route = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-2", "chunks_indexed": 1})
    )
    make_store(source="my-loader").add([TextNode(id_="node-2", text="hello")])
    assert body(route)["entities"] == []
    assert body(route)["source"] == "my-loader"


# ---------- query() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_query_mints_scope_from_policy_then_recalls(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[HIT]))

    result = make_store().query(
        VectorStoreQuery(query_str="Acme renewal", similarity_top_k=4)
    )

    assert body(scopes) == {
        "tenant_id": TENANT,
        "principals": [3, 7],
        "ttl_seconds": 3600,
    }
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 4,
        "text": "Acme renewal",
    }
    assert result.ids == [HIT["chunk_id"]]
    assert result.similarities == [pytest.approx(0.42)]
    assert result.nodes[0].text == "Acme renewed for 240 seats."
    assert result.nodes[0].metadata["acl_provenance"] == "admin-assigned"
    assert result.nodes[0].metadata["entity_tags"] == ["account:acme"]


@respx.mock(base_url=VERITY_URL)
def test_query_with_embedding_sends_embedding_leg(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    recall = respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))

    make_store().query(
        VectorStoreQuery(query_embedding=[0.1, 0.2], similarity_top_k=2)
    )
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 2,
        "embedding": [0.1, 0.2],
    }


@respx.mock(base_url=VERITY_URL)
def test_query_reuses_cached_scope_until_expiry(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))
    store = make_store()
    store.query(VectorStoreQuery(query_str="one", similarity_top_k=1))
    store.query(VectorStoreQuery(query_str="two", similarity_top_k=1))
    assert scopes.call_count == 1


def test_query_requires_a_query_leg():
    with pytest.raises(ValueError, match="query_str and/or query_embedding"):
        make_store().query(VectorStoreQuery(similarity_top_k=3))


def test_query_rejects_metadata_filters():
    filters = MetadataFilters(filters=[MetadataFilter(key="a", value="b")])
    with pytest.raises(ValueError, match="metadata filters"):
        make_store().query(
            VectorStoreQuery(query_str="x", similarity_top_k=1, filters=filters)
        )


# ---------- delete() -> POST /v1/forget ----------

@respx.mock(base_url=VERITY_URL)
def test_delete_forgets_session_episodes(respx_mock):
    respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-9", "chunks_indexed": 1})
    )
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    store = make_store()
    store.add([TextNode(id_="node-9", text="ephemeral")])
    store.delete("node-9")

    assert body(forget) == {
        "scope_handle": "vs_test-handle",
        "ref": {"kind": "episode", "id": "ep-9"},
        "reason": "llamaindex delete ref_doc_id=node-9",
    }


def test_delete_unknown_ref_doc_raises_not_noop():
    with pytest.raises(ValueError, match="session-local"):
        make_store().delete("never-ingested")
