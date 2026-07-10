"""Google ADK conformance: REAL ``BaseMemoryService`` machinery against a live
Verity server — ``add_session_to_memory`` / ``search_memory`` with real
``Session`` / ``Event`` / ``google.genai`` content objects, not our client
directly."""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from google.adk.events import Event
from google.adk.sessions import Session
from google.genai import types as genai_types

from verity_adk import VerityMemoryService

pytestmark = pytest.mark.e2e

APP = "calendar"
USER = "alice"
SENTINEL = "TEAM-A-ONLY adk secret: the swift-8 audit lands next week."


def run(coro):
    return asyncio.run(coro)


def service_for(tenant, policy) -> VerityMemoryService:
    return VerityMemoryService(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )


def event(text: str, *, author: str = "user", role: str = "user") -> Event:
    return Event(
        id=f"ev-{uuid.uuid4().hex[:8]}",
        author=author,
        timestamp=time.time(),
        content=genai_types.Content(role=role, parts=[genai_types.Part(text=text)]),
    )


def session(*events: Event) -> Session:
    return Session(
        app_name=APP,
        user_id=USER,
        id=f"sess-{uuid.uuid4().hex[:8]}",
        events=list(events),
    )


def texts(response) -> list[str]:
    return [part.text for entry in response.memories for part in entry.content.parts if part.text]


def test_native_write_native_read_roundtrip(tenant):
    service = service_for(tenant, tenant.team_a)
    run(
        service.add_session_to_memory(
            session(
                event("book a dentist appointment for next tuesday"),
                event("Booked for Tuesday 9am.", author="assistant", role="model"),
            )
        )
    )
    response = run(service.search_memory(app_name=APP, user_id=USER, query="dentist appointment"))
    assert response.memories, "search_memory found nothing for a session just added"
    assert any("dentist" in text for text in texts(response))
    assert any(entry.author == "assistant" for entry in response.memories)


def test_team_b_service_sees_nothing_of_team_a(tenant):
    run(service_for(tenant, tenant.team_a).add_session_to_memory(session(event(SENTINEL))))
    service_b = service_for(tenant, tenant.team_b)

    # Same app/user through team B's policy: invisible.
    empty = run(service_b.search_memory(app_name=APP, user_id=USER, query="swift-8 audit secret"))
    assert empty.memories == []

    # Team B's own session proves the read path works, still no leakage.
    run(service_b.add_session_to_memory(session(event("Team B adk note: the crane-1 sync moved."))))
    response = run(
        service_b.search_memory(app_name=APP, user_id=USER, query="swift-8 audit secret crane-1")
    )
    assert response.memories, "team B cannot search its own memories"
    assert all("TEAM-A-ONLY" not in text for text in texts(response))


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityMemoryService(
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
