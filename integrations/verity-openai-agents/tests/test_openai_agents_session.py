"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import asyncio
import json

import pytest
import respx
from httpx import Response

from verity_openai_agents import VeritySession, session_tag

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
SESSION = "conv-42"
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}


def envelope(seq: int, item: dict) -> str:
    return json.dumps(
        {
            "kind": "openai-agents-session-item",
            "session": SESSION,
            "seq": seq,
            "item": item,
        },
        sort_keys=True,
    )


def hit(seq: int, item: dict, *, chunk_seq: int = 0, content: str | None = None) -> dict:
    return {
        "chunk_id": f"019f0000-0000-7000-8000-00000000c0{seq:02x}",
        "document_id": f"session:{SESSION}/item:{seq}",
        "seq": chunk_seq,
        "content": content if content is not None else envelope(seq, item),
        "score": 0.5,
        "entity_tags": [f"session:{SESSION}"],
        "kind": "content",
        "acl_provenance": "admin-assigned",
        "trust_tier": "Authoritative",
        "valid_from": "2026-07-01T00:00:00Z",
        "provenance": f"019f0000-0000-7000-8000-00000000e0{seq:02x}",
    }


def make_session(**overrides) -> VeritySession:
    kwargs = dict(
        verity_url=VERITY_URL,
        tenant_id=TENANT,
        visibility_policy=[3, 7],
        admin_token="test-admin-token",
    )
    kwargs.update(overrides)
    return VeritySession(SESSION, **kwargs)


def body(route, call=-1) -> dict:
    return json.loads(route.calls[call].request.content)


def run(coro):
    return asyncio.run(coro)


USER_MSG = {"role": "user", "content": "what's on my calendar?"}
ASSISTANT_MSG = {"role": "assistant", "content": "Standup at 10."}


# ---------- the visibility_policy doctrine (SPEC §5e.4) ----------

def test_visibility_policy_is_required_and_teaches():
    with pytest.raises(ValueError) as err:
        VeritySession(SESSION, verity_url=VERITY_URL, tenant_id=TENANT)
    message = str(err.value)
    assert "SPEC §5e.4" in message
    assert "quarantined" in message
    assert "admin-assigned" in message


@pytest.mark.parametrize("bad", [[], (), "3,7", [3, "7"], [True], 3])
def test_visibility_policy_rejects_non_token_lists(bad):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VeritySession(
            SESSION, verity_url=VERITY_URL, tenant_id=TENANT, visibility_policy=bad
        )


# ---------- session tag / protocol shape ----------

def test_session_tag():
    assert session_tag("conv-42") == "session:conv-42"
    with pytest.raises(ValueError):
        session_tag("")


def test_satisfies_the_session_protocol():
    from agents.memory.session import Session

    assert isinstance(make_session(), Session)


# ---------- add_items() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_add_items_posts_exact_ingest_bodies(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    run(make_session().add_items([USER_MSG, ASSISTANT_MSG]))

    assert body(ingest, 0) == {
        "tenant_id": TENANT,
        "source": "openai-agents-session",
        "document_id": f"session:{SESSION}/item:0",
        "content": envelope(0, USER_MSG),
        "entities": [f"session:{SESSION}"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    assert body(ingest, 1)["document_id"] == f"session:{SESSION}/item:1"
    assert json.loads(body(ingest, 1)["content"])["seq"] == 1
    auth = ingest.calls.last.request.headers["authorization"]
    assert auth == "Bearer test-admin-token"


@respx.mock(base_url=VERITY_URL)
def test_add_items_resumes_seq_from_existing_conversation(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(0, USER_MSG), hit(1, ASSISTANT_MSG)])
    )
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-2", "chunks_indexed": 1})
    )
    run(make_session().add_items([{"role": "user", "content": "and tomorrow?"}]))
    assert body(ingest)["document_id"] == f"session:{SESSION}/item:2"


# ---------- get_items() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_get_items_mints_entity_scope_and_recalls_by_session_id(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(
        # server returns hits in arbitrary (score) order — seq 1 first
        return_value=Response(200, json=[hit(1, ASSISTANT_MSG), hit(0, USER_MSG)])
    )
    items = run(make_session().get_items())

    assert body(scopes) == {
        "tenant_id": TENANT,
        "principals": [3, 7],
        "ttl_seconds": 3600,
        "entity_scope": [f"session:{SESSION}"],
    }
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 100,
        "text": SESSION,
    }
    assert items == [USER_MSG, ASSISTANT_MSG]  # client-side seq order


@respx.mock(base_url=VERITY_URL)
def test_get_items_limit_returns_latest_n_in_chronological_order(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[hit(0, {"n": 0}), hit(1, {"n": 1}), hit(2, {"n": 2})],
        )
    )
    assert run(make_session().get_items(limit=2)) == [{"n": 1}, {"n": 2}]


@respx.mock(base_url=VERITY_URL)
def test_get_items_rejoins_multi_chunk_documents(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    long_item = {"role": "user", "content": "x" * 3000}
    full = envelope(0, long_item)
    respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit(0, long_item, chunk_seq=1, content=full[2000:]),
                hit(0, long_item, chunk_seq=0, content=full[:2000]),
            ],
        )
    )
    assert run(make_session().get_items()) == [long_item]


@respx.mock(base_url=VERITY_URL)
def test_get_items_skips_foreign_and_partial_documents(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit(0, USER_MSG),
                hit(1, {}, content='{"kind": "something-else"}'),
                hit(2, {}, content="{truncated json"),
            ],
        )
    )
    assert run(make_session().get_items()) == [USER_MSG]


# ---------- pop_item() -> POST /v1/forget ----------

@respx.mock(base_url=VERITY_URL)
def test_pop_item_forgets_newest_episode_and_returns_item(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(0, USER_MSG), hit(1, ASSISTANT_MSG)])
    )
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    popped = run(make_session().pop_item())

    assert popped == ASSISTANT_MSG
    assert body(forget) == {
        "scope_handle": "vs_test-handle",
        "ref": {"kind": "episode", "id": "019f0000-0000-7000-8000-00000000e001"},
        "reason": f"openai-agents pop_item session:{SESSION}/item:1",
    }


@respx.mock(base_url=VERITY_URL)
def test_pop_item_frees_the_seq_for_reuse(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(0, USER_MSG), hit(1, ASSISTANT_MSG)])
    )
    respx_mock.post("/v1/forget").mock(return_value=Response(200, json={"retired": 1}))
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-3", "chunks_indexed": 1})
    )
    session = make_session()
    run(session.pop_item())
    run(session.add_items([{"role": "assistant", "content": "corrected answer"}]))
    assert body(ingest)["document_id"] == f"session:{SESSION}/item:1"


@respx.mock(base_url=VERITY_URL, assert_all_called=False)
def test_pop_item_on_empty_session_returns_none(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 0})
    )
    assert run(make_session().pop_item()) is None
    assert forget.call_count == 0


# ---------- clear_session() -> POST /v1/forget per episode ----------

@respx.mock(base_url=VERITY_URL)
def test_clear_session_forgets_every_episode_once(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(0, USER_MSG), hit(1, ASSISTANT_MSG)])
    )
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    run(make_session().clear_session())
    assert forget.call_count == 2
    ids = {body(forget, i)["ref"]["id"] for i in range(2)}
    assert ids == {
        "019f0000-0000-7000-8000-00000000e000",
        "019f0000-0000-7000-8000-00000000e001",
    }
