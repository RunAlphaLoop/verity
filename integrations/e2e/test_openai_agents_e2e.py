"""OpenAI Agents SDK conformance: REAL ``Session`` protocol usage against a
live Verity server — ``get_items`` / ``add_items`` / ``pop_item`` /
``clear_session`` with real protocol items (``EasyInputMessageParam`` /
response-output-message shapes), not our client directly."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from openai.types.responses import EasyInputMessageParam

from verity_openai_agents import VeritySession

pytestmark = pytest.mark.e2e

SENTINEL = "TEAM-A-ONLY openai-agents secret: the merlin-2 postmortem draft."


def run(coro):
    return asyncio.run(coro)


def session_for(tenant, policy, session_id: str) -> VeritySession:
    return VeritySession(
        session_id,
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )


def test_native_write_native_read_roundtrip(tenant):
    session_id = f"thread-{uuid.uuid4().hex[:8]}"
    session = session_for(tenant, tenant.team_a, session_id)
    items = [
        dict(EasyInputMessageParam(role="user", content="What is on the roadmap this week?")),
        dict(EasyInputMessageParam(role="assistant", content="Milestone A: the engine is honest.")),
    ]
    run(session.add_items(items))

    # A FRESH session object (no local state) must read the history back.
    fresh = session_for(tenant, tenant.team_a, session_id)
    assert run(fresh.get_items()) == items
    assert run(fresh.get_items(limit=1)) == items[-1:]

    popped = run(fresh.pop_item())
    assert popped == items[-1]
    assert run(fresh.get_items()) == items[:-1]

    run(fresh.clear_session())
    assert run(fresh.get_items()) == []


def test_team_b_session_sees_nothing_of_team_a(tenant):
    session_id = f"thread-{uuid.uuid4().hex[:8]}"
    session_a = session_for(tenant, tenant.team_a, session_id)
    run(session_a.add_items([dict(EasyInputMessageParam(role="user", content=SENTINEL))]))

    # The SAME session id through team B's policy: empty history, empty pop.
    session_b = session_for(tenant, tenant.team_b, session_id)
    assert run(session_b.get_items()) == []
    assert run(session_b.pop_item()) is None

    # Team B's own thread proves the read path works under policy [2].
    own = session_for(tenant, tenant.team_b, f"thread-{uuid.uuid4().hex[:8]}")
    own_items = [dict(EasyInputMessageParam(role="user", content="team B: plan the crow-3 demo"))]
    run(own.add_items(own_items))
    assert run(own.get_items()) == own_items

    # And team A's history is untouched by team B's probing.
    assert len(run(session_a.get_items())) == 1


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VeritySession(
            "thread-doctrine",
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
