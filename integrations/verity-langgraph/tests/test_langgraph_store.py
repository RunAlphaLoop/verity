"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import json
from urllib.parse import unquote

import pytest
import respx
from httpx import Response

from verity_langgraph import VerityStore, namespace_tag

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
NS = ("agents", "alice")
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}


def hit(document_id: str, content: str, score: float = 0.42) -> dict:
    return {
        "chunk_id": "019f0000-0000-7000-8000-00000000c001",
        "document_id": document_id,
        "seq": 0,
        "content": content,
        "score": score,
        "entity_tags": ["ns:agents/alice"],
        "kind": "content",
        "acl_provenance": "admin-assigned",
        "trust_tier": "Authoritative",
        "valid_from": "2026-07-01T00:00:00Z",
        "provenance": "019f0000-0000-7000-8000-00000000e001",
    }


def brief_response(*hits: dict) -> dict:
    return {
        "entity": "ns:agents/alice",
        "generated_at": "2026-07-01T00:00:01Z",
        "recent_memory": list(hits),
        "recent_activity": [],
    }


def make_store(**overrides):
    kwargs = dict(
        verity_url=VERITY_URL,
        tenant_id=TENANT,
        visibility_policy=[3, 7],
        admin_token="test-admin-token",
    )
    kwargs.update(overrides)
    return VerityStore(**kwargs)


def body(route, call=-1) -> dict:
    return json.loads(route.calls[call].request.content)


# ---------- the visibility_policy doctrine (SPEC §5e.4) ----------

def test_visibility_policy_is_required_and_teaches():
    with pytest.raises(ValueError) as err:
        VerityStore(verity_url=VERITY_URL, tenant_id=TENANT)
    message = str(err.value)
    assert "SPEC §5e.4" in message
    assert "quarantined" in message
    assert "admin-assigned" in message


@pytest.mark.parametrize("bad", [[], (), "3,7", [3, "7"], [True], 3])
def test_visibility_policy_rejects_non_token_lists(bad):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityStore(verity_url=VERITY_URL, tenant_id=TENANT, visibility_policy=bad)


# ---------- namespace mapping ----------

def test_namespace_tuple_becomes_entity_tag():
    assert namespace_tag(("agents", "alice")) == "ns:agents/alice"
    assert namespace_tag(("memories",)) == "ns:memories"


@pytest.mark.parametrize("bad_ns", [(), ("",), ("a/b",), ("a", 1)])
def test_namespace_tag_rejects_malformed_tuples(bad_ns):
    with pytest.raises(ValueError):
        namespace_tag(bad_ns)


# ---------- put() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_put_posts_exact_ingest_body(respx_mock):
    route = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    make_store().put(NS, "food-preference", {"preference": "vegetarian"})

    assert body(route) == {
        "tenant_id": TENANT,
        "source": "langgraph-store",
        "document_id": "agents/alice/food-preference",
        "content": '{"preference": "vegetarian"}',
        "entities": ["ns:agents/alice"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    assert route.calls.last.request.headers["authorization"] == "Bearer test-admin-token"


# ---------- search() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_search_mints_entity_scoped_handle_then_recalls(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[hit("agents/alice/food-preference", '{"preference": "vegetarian"}')],
        )
    )
    items = make_store().search(NS, query="what does alice eat?", limit=5)

    assert body(scopes) == {
        "tenant_id": TENANT,
        "principals": [3, 7],
        "ttl_seconds": 3600,
        "entity_scope": ["ns:agents/alice"],
    }
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 5,
        "text": "what does alice eat?",
    }
    assert len(items) == 1
    assert items[0].namespace == NS
    assert items[0].key == "food-preference"
    assert items[0].value == {"preference": "vegetarian"}
    assert items[0].score == pytest.approx(0.42)


@respx.mock(base_url=VERITY_URL)
def test_search_dedupes_chunks_and_applies_offset(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit("agents/alice/a", '{"n": 1}', 0.9),
                hit("agents/alice/a", '{"n": 1}', 0.8),  # second chunk, same item
                hit("agents/alice/b", '{"n": 2}', 0.7),
                hit("other/ns/c", '{"n": 3}', 0.6),  # outside the prefix
            ],
        )
    )
    items = make_store().search(NS, query="n", limit=1, offset=1)
    assert body(recall)["k"] == 2  # limit + offset
    assert [i.key for i in items] == ["b"]


@respx.mock(base_url=VERITY_URL)
def test_queryless_search_lists_newest_via_brief(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    briefs = respx_mock.get(path__startswith="/v1/briefs/").mock(
        return_value=Response(
            200, json=brief_response(hit("agents/alice/a", '{"n": 1}'))
        )
    )
    items = make_store().search(NS)
    request = briefs.calls.last.request
    assert unquote(request.url.path) == "/v1/briefs/ns:agents/alice"
    assert request.url.params["scope_handle"] == "vs_test-handle"
    assert [i.key for i in items] == ["a"]
    assert items[0].score is None


def test_search_value_filters_are_rejected():
    with pytest.raises(NotImplementedError, match="filter"):
        make_store().search(NS, filter={"preference": "vegetarian"})


# ---------- get() -> GET /v1/briefs/{entity} ----------

@respx.mock(base_url=VERITY_URL)
def test_get_returns_newest_version_from_brief(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.get(path__startswith="/v1/briefs/").mock(
        return_value=Response(
            200,
            json=brief_response(
                hit("agents/alice/other-key", '{"x": 0}'),
                hit("agents/alice/food-preference", '{"preference": "vegetarian"}'),
            ),
        )
    )
    item = make_store().get(NS, "food-preference")
    assert item is not None
    assert item.key == "food-preference"
    assert item.namespace == NS
    assert item.value == {"preference": "vegetarian"}


@respx.mock(base_url=VERITY_URL)
def test_get_missing_key_returns_none(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.get(path__startswith="/v1/briefs/").mock(
        return_value=Response(200, json=brief_response())
    )
    assert make_store().get(NS, "nope") is None


# ---------- delete() -> POST /v1/forget ----------

@respx.mock(base_url=VERITY_URL)
def test_delete_forgets_the_session_episode(respx_mock):
    respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-9", "chunks_indexed": 1})
    )
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    store = make_store()
    store.put(NS, "food-preference", {"preference": "vegetarian"})
    store.delete(NS, "food-preference")

    assert body(forget) == {
        "scope_handle": "vs_test-handle",
        "ref": {"kind": "episode", "id": "ep-9"},
        "reason": "langgraph-store delete agents/alice/food-preference",
    }


@respx.mock(base_url=VERITY_URL)
def test_delete_cross_session_item_looks_up_provenance(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.get(path__startswith="/v1/briefs/").mock(
        return_value=Response(
            200, json=brief_response(hit("agents/alice/food-preference", "{}"))
        )
    )
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    make_store().delete(NS, "food-preference")
    assert body(forget)["ref"] == {
        "kind": "episode",
        "id": "019f0000-0000-7000-8000-00000000e001",
    }


@respx.mock(base_url=VERITY_URL, assert_all_called=False)
def test_delete_missing_item_is_a_noop(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.get(path__startswith="/v1/briefs/").mock(
        return_value=Response(200, json=brief_response())
    )
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 0})
    )
    make_store().delete(NS, "never-written")
    assert forget.call_count == 0


# ---------- list_namespaces is fail-closed ----------

def test_list_namespaces_is_not_supported():
    with pytest.raises(NotImplementedError, match="namespaces"):
        make_store().list_namespaces()
