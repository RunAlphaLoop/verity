"""LangChain conformance: REAL retriever machinery against a live Verity
server — ``vector_store.as_retriever().invoke(...)``, not our client directly."""

from __future__ import annotations

import pytest

from verity_langchain import VerityVectorStore

pytestmark = pytest.mark.e2e

SENTINEL = "TEAM-A-ONLY langchain secret: the falcon-3 budget is 1.2M."


def store_for(tenant, policy):
    return VerityVectorStore(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        visibility_policy=policy,
        admin_token=tenant.admin_token,
    )


def test_native_write_native_read_roundtrip(tenant):
    store = store_for(tenant, tenant.team_a)
    store.add_texts(
        [
            "Acme renewed for 240 seats on 2026-06-30.",
            "Globex churned after the Q2 downtime.",
        ],
        metadatas=[
            {"verity_entities": ["account:acme"]},
            {"verity_entities": ["account:globex"]},
        ],
    )
    docs = store.as_retriever(search_kwargs={"k": 4}).invoke("Acme renewal seats")
    assert docs, "retriever found nothing for content just written"
    assert any("240 seats" in doc.page_content for doc in docs)


def test_team_b_retriever_sees_nothing_of_team_a(tenant):
    store_for(tenant, tenant.team_a).add_texts([SENTINEL])
    store_b = store_for(tenant, tenant.team_b)
    retriever_b = store_b.as_retriever(search_kwargs={"k": 10})

    # Nothing visible at all under team B's policy...
    assert retriever_b.invoke("falcon-3 budget secret") == []

    # ...and once team B has its own data the read path demonstrably works,
    # yet still returns nothing of team A's.
    store_b.add_texts(["Team B langchain note: osprey-2 kickoff done."])
    docs = retriever_b.invoke("falcon-3 budget secret osprey-2")
    assert docs, "team B cannot read its own writes"
    assert all("TEAM-A-ONLY" not in doc.page_content for doc in docs)


def test_constructing_without_visibility_policy_teaches(tenant):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityVectorStore(
            verity_url=tenant.url,
            tenant_id=tenant.tenant_id,
            admin_token=tenant.admin_token,
        )
