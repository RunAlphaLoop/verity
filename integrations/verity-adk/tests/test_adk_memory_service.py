"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import asyncio
import json

import pytest
import respx
from google.adk.events import Event
from google.adk.sessions import Session
from google.genai import types as genai_types
from httpx import Response

from verity_adk import VerityMemoryService, user_tag

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
APP = "calendar"
USER = "alice"
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}


def event(event_id: str, text: str, *, author: str = "user", role: str = "user") -> Event:
    return Event(
        id=event_id,
        author=author,
        timestamp=1751328000.0,  # 2025-07-01T00:00:00+00:00
        content=genai_types.Content(role=role, parts=[genai_types.Part(text=text)]),
    )


def envelope(text: str, *, author: str = "user", role: str = "user") -> str:
    return json.dumps(
        {
            "kind": "adk-memory-event",
            "author": author,
            "role": role,
            "timestamp": "2025-07-01T00:00:00+00:00",
            "text": text,
        },
        sort_keys=True,
    )


def hit(document_id: str, content: str, score: float = 0.42) -> dict:
    return {
        "chunk_id": "019f0000-0000-7000-8000-00000000c001",
        "document_id": document_id,
        "seq": 0,
        "content": content,
        "score": score,
        "entity_tags": [f"adk:{APP}/{USER}"],
        "kind": "content",
        "acl_provenance": "admin-assigned",
        "trust_tier": "Authoritative",
        "valid_from": "2026-07-01T00:00:00Z",
        "provenance": "019f0000-0000-7000-8000-00000000e001",
    }


def make_service(**overrides) -> VerityMemoryService:
    kwargs = dict(
        verity_url=VERITY_URL,
        tenant_id=TENANT,
        visibility_policy=[3, 7],
        admin_token="test-admin-token",
    )
    kwargs.update(overrides)
    return VerityMemoryService(**kwargs)


def body(route, call=-1) -> dict:
    return json.loads(route.calls[call].request.content)


def run(coro):
    return asyncio.run(coro)


# ---------- the visibility_policy doctrine (SPEC §5e.4) ----------

def test_visibility_policy_is_required_and_teaches():
    with pytest.raises(ValueError) as err:
        VerityMemoryService(verity_url=VERITY_URL, tenant_id=TENANT)
    message = str(err.value)
    assert "SPEC §5e.4" in message
    assert "quarantined" in message
    assert "admin-assigned" in message


@pytest.mark.parametrize("bad", [[], (), "3,7", [3, "7"], [True], 3])
def test_visibility_policy_rejects_non_token_lists(bad):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityMemoryService(
            verity_url=VERITY_URL, tenant_id=TENANT, visibility_policy=bad
        )


# ---------- scope mapping ----------

def test_user_tag_is_app_and_user_scoped():
    assert user_tag("calendar", "alice") == "adk:calendar/alice"


@pytest.mark.parametrize("bad", [("", "alice"), ("a/b", "alice"), ("calendar", "")])
def test_user_tag_rejects_malformed_parts(bad):
    with pytest.raises(ValueError):
        user_tag(*bad)


def test_is_a_base_memory_service():
    from google.adk.memory import BaseMemoryService

    assert isinstance(make_service(), BaseMemoryService)


# ---------- add_session_to_memory() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_add_session_posts_exact_ingest_body_per_event(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    session = Session(
        app_name=APP,
        user_id=USER,
        id="sess-9",
        events=[
            event("ev-1", "book a dentist appointment"),
            event("ev-2", "Booked for Tuesday 9am.", author="assistant", role="model"),
        ],
    )
    run(make_service().add_session_to_memory(session))

    assert ingest.call_count == 2
    assert body(ingest, 0) == {
        "tenant_id": TENANT,
        "source": "adk-memory",
        "document_id": f"adk/{APP}/{USER}/sess-9/ev-1",
        "content": envelope("book a dentist appointment"),
        "entities": [f"adk:{APP}/{USER}"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    assert body(ingest, 1)["document_id"] == f"adk/{APP}/{USER}/sess-9/ev-2"
    assert json.loads(body(ingest, 1)["content"])["author"] == "assistant"
    auth = ingest.calls.last.request.headers["authorization"]
    assert auth == "Bearer test-admin-token"


@respx.mock(base_url=VERITY_URL, assert_all_called=False)
def test_add_session_skips_events_without_text(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    silent = Event(id="ev-3", author="user", timestamp=1751328000.0, content=None)
    empty = Event(
        id="ev-4",
        author="user",
        timestamp=1751328000.0,
        content=genai_types.Content(role="user", parts=[]),
    )
    session = Session(app_name=APP, user_id=USER, id="sess-9", events=[silent, empty])
    run(make_service().add_session_to_memory(session))
    assert ingest.call_count == 0


# ---------- add_events_to_memory() (delta writes) ----------

@respx.mock(base_url=VERITY_URL)
def test_add_events_delta_uses_session_bucket(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-2", "chunks_indexed": 1})
    )
    service = make_service()
    run(
        service.add_events_to_memory(
            app_name=APP, user_id=USER, events=[event("ev-9", "latest turn")],
            session_id="sess-9",
        )
    )
    assert body(ingest)["document_id"] == f"adk/{APP}/{USER}/sess-9/ev-9"

    run(
        service.add_events_to_memory(
            app_name=APP, user_id=USER, events=[event("ev-10", "no session")]
        )
    )
    assert body(ingest)["document_id"] == f"adk/{APP}/{USER}/unknown-session/ev-10"


# ---------- search_memory() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_search_memory_mints_entity_scope_then_recalls(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit(
                    f"adk/{APP}/{USER}/sess-9/ev-2",
                    envelope("Booked for Tuesday 9am.", author="assistant", role="model"),
                )
            ],
        )
    )
    response = run(
        make_service().search_memory(app_name=APP, user_id=USER, query="dentist?")
    )

    assert body(scopes) == {
        "tenant_id": TENANT,
        "principals": [3, 7],
        "ttl_seconds": 3600,
        "entity_scope": [f"adk:{APP}/{USER}"],
    }
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 10,
        "text": "dentist?",
    }
    assert len(response.memories) == 1
    entry = response.memories[0]
    assert entry.author == "assistant"
    assert entry.timestamp == "2025-07-01T00:00:00+00:00"
    assert entry.content.role == "model"
    assert entry.content.parts[0].text == "Booked for Tuesday 9am."


@respx.mock(base_url=VERITY_URL)
def test_search_memory_honours_search_k(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    recall = respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[]))
    run(
        make_service(search_k=3).search_memory(
            app_name=APP, user_id=USER, query="anything"
        )
    )
    assert body(recall)["k"] == 3


@respx.mock(base_url=VERITY_URL)
def test_search_memory_skips_foreign_and_partial_chunks(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit("adk/x", '{"kind": "something-else"}'),
                hit("adk/y", "{not json"),
                hit(f"adk/{APP}/{USER}/s/e", envelope("real memory")),
            ],
        )
    )
    response = run(
        make_service().search_memory(app_name=APP, user_id=USER, query="q")
    )
    assert [m.content.parts[0].text for m in response.memories] == ["real memory"]
