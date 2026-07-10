"""CrewAI conformance: REAL unified-``Memory`` machinery against a live Verity
server — ``Memory(storage=..., embedder=storage.embedder)`` driving
``remember()`` (the save path: EncodingFlow -> ``storage.save``) and
``recall(depth="shallow")`` (the search path: embedder shim -> ``storage.search``),
not our storage class directly.

``remember`` is called with explicit scope/categories/importance so the
EncodingFlow takes its zero-LLM fast path (fields provided, no consolidation
candidates above threshold) — no API keys, no network beyond Verity.
"""

from __future__ import annotations

import pytest
from crewai.memory import Memory

from verity_crewai import VerityStorage

pytestmark = pytest.mark.e2e

SENTINEL = "TEAM-A-ONLY crewai secret: the puffin-4 demo is on thursday."
SCOPE = "/crew/research"


def memory_for(tenant, policy) -> Memory:
    storage = VerityStorage(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )
    return Memory(storage=storage, embedder=storage.embedder)


def remember(memory: Memory, content: str):
    record = memory.remember(
        content,
        scope=SCOPE,
        categories=["e2e"],
        importance=0.8,
    )
    assert record is not None, "Memory.remember() dropped the record"
    return record


def test_native_write_native_read_roundtrip(tenant):
    memory = memory_for(tenant, tenant.team_a)
    remember(memory, "Alice prefers vegetarian catering for crew events.")
    remember(memory, "The retro is scheduled in the large meeting room.")

    matches = memory.recall("vegetarian catering", depth="shallow", limit=5)
    assert matches, "recall found nothing for content just remembered"
    assert any("vegetarian" in match.record.content for match in matches)
    assert all(match.record.scope == SCOPE for match in matches)


def test_team_b_memory_sees_nothing_of_team_a(tenant):
    remember(memory_for(tenant, tenant.team_a), SENTINEL)
    memory_b = memory_for(tenant, tenant.team_b)

    # Nothing visible at all under team B's policy...
    assert memory_b.recall("puffin-4 demo secret", depth="shallow", limit=10) == []

    # ...and team B's own memories prove the read path works, still no leakage.
    remember(memory_b, "Team B crewai note: the wren-6 pilot shipped.")
    matches = memory_b.recall("puffin-4 demo secret wren-6", depth="shallow", limit=10)
    assert matches, "team B cannot recall its own memories"
    assert all("TEAM-A-ONLY" not in match.record.content for match in matches)


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityStorage(
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
