"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response
from langchain_core.documents import Document

from verity_langchain import VerityRetriever, VerityVectorStore

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}
HIT = {
    "chunk_id": "019f0000-0000-7000-8000-00000000c001",
    "document_id": "crm-note-881",
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


def test_from_texts_requires_visibility_policy_too():
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityVectorStore.from_texts(
            ["hello"], verity_url=VERITY_URL, tenant_id=TENANT
        )


# ---------- add_texts() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_add_texts_posts_exact_ingest_body(respx_mock):
    route = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    ids = make_store().add_texts(
        ["Acme renewed for 240 seats."],
        metadatas=[{"verity_entities": ["account:acme"]}],
        ids=["crm-note-881"],
    )
    assert ids == ["crm-note-881"]
    assert body(route) == {
        "tenant_id": TENANT,
        "source": "langchain",
        "document_id": "crm-note-881",
        "content": "Acme renewed for 240 seats.",
        "entities": ["account:acme"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    assert route.calls.last.request.headers["authorization"] == "Bearer test-admin-token"


@respx.mock(base_url=VERITY_URL)
def test_add_documents_inherits_the_same_body(respx_mock):
    route = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-2", "chunks_indexed": 1})
    )
    make_store(source="my-loader").add_documents(
        [Document(page_content="hello", metadata={})], ids=["doc-2"]
    )
    assert body(route) == {
        "tenant_id": TENANT,
        "source": "my-loader",
        "document_id": "doc-2",
        "content": "hello",
        "entities": [],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }


# ---------- similarity_search() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_similarity_search_mints_scope_from_policy_then_recalls(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[HIT]))

    docs = make_store().similarity_search("Acme renewal", k=4)

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
    assert len(docs) == 1
    assert docs[0].id == HIT["chunk_id"]
    assert docs[0].page_content == "Acme renewed for 240 seats."
    assert docs[0].metadata["acl_provenance"] == "admin-assigned"
    assert docs[0].metadata["entity_tags"] == ["account:acme"]


@respx.mock(base_url=VERITY_URL)
def test_similarity_search_with_score_returns_server_scores(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[HIT]))
    [(doc, score)] = make_store().similarity_search_with_score("Acme renewal", k=1)
    assert score == pytest.approx(0.42)
    assert doc.metadata["document_id"] == "crm-note-881"


@respx.mock(base_url=VERITY_URL)
def test_scope_is_cached_across_searches(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))
    store = make_store()
    store.similarity_search("one")
    store.similarity_search("two")
    assert scopes.call_count == 1


# ---------- retriever ----------

@respx.mock(base_url=VERITY_URL)
def test_retriever_invoke_uses_the_scoped_recall_path(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    recall = respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[HIT]))

    retriever = make_store().as_retriever(search_kwargs={"k": 2})
    assert isinstance(retriever, VerityRetriever)
    docs = retriever.invoke("Acme renewal")

    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 2,
        "text": "Acme renewal",
    }
    assert docs[0].page_content == "Acme renewed for 240 seats."


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
    store.add_texts(["ephemeral"], ids=["doc-9"])
    assert store.delete(["doc-9"]) is True

    assert body(forget) == {
        "scope_handle": "vs_test-handle",
        "ref": {"kind": "episode", "id": "ep-9"},
        "reason": "langchain delete id=doc-9",
    }


def test_delete_unknown_ids_raises_not_noop():
    with pytest.raises(ValueError, match="session-local"):
        make_store().delete(["never-ingested"])
