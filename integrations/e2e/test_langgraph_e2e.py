"""LangGraph conformance: REAL ``BaseStore`` API against a live Verity server —
``store.put`` / ``store.search`` / ``store.get`` (the BaseStore front doors,
which route through ``batch``), not our client directly."""

from __future__ import annotations

import pytest

from verity_langgraph import VerityStore

pytestmark = pytest.mark.e2e

NAMESPACE = ("agents", "alice")
SENTINEL_VALUE = {"note": "TEAM-A-ONLY langgraph secret: heron-5 migration friday"}


def store_for(tenant, policy):
    return VerityStore(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )


def test_native_write_native_read_roundtrip(tenant):
    store = store_for(tenant, tenant.team_a)
    store.put(NAMESPACE, "diet", {"preference": "vegetarian catering"})

    found = store.search(NAMESPACE, query="vegetarian catering")
    assert found, "search found nothing for an item just put()"
    assert any(item.value == {"preference": "vegetarian catering"} for item in found)

    item = store.get(NAMESPACE, "diet")
    assert item is not None
    assert item.value == {"preference": "vegetarian catering"}
    assert item.namespace == NAMESPACE and item.key == "diet"


def test_team_b_store_sees_nothing_of_team_a(tenant):
    store_for(tenant, tenant.team_a).put(NAMESPACE, "secret", SENTINEL_VALUE)
    store_b = store_for(tenant, tenant.team_b)

    # The same namespace + key through team B's policy: invisible.
    assert store_b.get(NAMESPACE, "secret") is None
    assert store_b.search(NAMESPACE, query="heron-5 migration secret") == []

    # Team B's own writes prove the read path works, and still no leakage.
    store_b.put(NAMESPACE, "own", {"note": "team B stand-up moved to 10am"})
    results = store_b.search(NAMESPACE, query="heron-5 migration stand-up")
    assert results, "team B cannot read its own writes"
    assert all("TEAM-A-ONLY" not in str(item.value) for item in results)


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityStore(
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
