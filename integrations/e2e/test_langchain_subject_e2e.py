"""LangChain SUBJECT-BOUND read conformance (group-membership inheritance).

Proves the inheritance story through a FRAMEWORK ADAPTER, not just MCP: a
retriever constructed for a real subject (``user:alice@acme.example``) mints its
scope with ``subject=`` and the server resolves it via ReBAC (SPEC §6/§9a) into
alice's transitive group closure. Because ``all-staff ⊃ engineering ⊃ alice``,
alice's retriever sees a doc shared with the ``all-staff`` group token; bob,
who is in no group, stays dark.

This test requires ReBAC/SpiceDB. It self-gates on ``VERITY_SPICEDB_URL`` — the
SAME env var that (inherited by the session server, conftest.py:74) turns ReBAC
on. A normal no-SpiceDB run SKIPS it cleanly and leaves every other e2e green.
Run it with (SpiceDB up via ``verity dev``)::

    VERITY_SPICEDB_URL=http://localhost:8443 VERITY_SPICEDB_KEY=verity-dev-key \
        integrations/run_e2e.sh integrations/e2e/test_langchain_subject_e2e.py

Writes stay policy-based (SPEC §5e.4): the group-visible doc is ingested with an
explicit visibility int token + ``acl_provenance=mirrored`` through the admin
API. Only the READ lane is subject-bound.
"""

from __future__ import annotations

import os

import httpx
import pytest

from verity_langchain import VerityVectorStore
from verity_langchain.vector_store import VeritySubjectRetriever

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not os.environ.get("VERITY_SPICEDB_URL"),
        reason=(
            "subject-bound ReBAC read path requires SpiceDB "
            "(set VERITY_SPICEDB_URL; run `verity dev`)"
        ),
    ),
]

# Directory + doc shapes reused verbatim from demo/two_agent_trust.py.
G_ALL = "group:all-staff@acme.example"
G_ENG = "group:engineering@acme.example"
U_ALICE = "user:alice@acme.example"
U_BOB = "user:bob@acme.example"
MARKER = "falcon-release-q3"  # unique term; only the group-visible doc carries it


def _admin_client(tenant) -> httpx.Client:
    return httpx.Client(
        base_url=tenant.url,
        headers={"Authorization": f"Bearer {tenant.admin_token}"},
        timeout=30.0,
    )


@pytest.fixture
def inheritance_dir(tenant):
    """Build ``all-staff ⊃ engineering ⊃ alice`` (bob excluded) and ingest one
    doc visible to the all-staff group token. Returns the tenant namespace.

    Group management + subject resolution require ReBAC; if the server was NOT
    started with SpiceDB this fails loudly (503 group-management / 422 subject),
    which is correct — the skipif above keeps the default run green.
    """
    with _admin_client(tenant) as admin:
        # (1) membership tuples — nested group closure. Bob gets no tuple.
        for group, member in ((G_ALL, G_ENG), (G_ENG, U_ALICE)):
            resp = admin.post(
                "/v1/admin/groups",
                json={"tenant_id": tenant.tenant_id, "group": group, "member": member},
            )
            resp.raise_for_status()

        # (2) resolve the all-staff group string -> its materialized int token.
        resp = admin.post(
            "/v1/admin/principals",
            json={"tenant_id": tenant.tenant_id, "principals": [G_ALL]},
        )
        resp.raise_for_status()
        all_staff_token = resp.json()["mappings"][G_ALL]

        # (3) ingest a doc visible ONLY to the all-staff group token.
        #     Write lane stays policy-based: explicit visibility + mirrored ACL.
        resp = admin.post(
            "/v1/ingest/documents",
            json={
                "tenant_id": tenant.tenant_id,
                "source": "e2e-subject",
                "document_id": "eng-roadmap",
                "content": (
                    "CONFIDENTIAL -- the Q3 engineering roadmap: "
                    f"shipping the {MARKER}."
                ),
                "visibility": [all_staff_token],
                "acl_provenance": "mirrored",
            },
        )
        resp.raise_for_status()
    return tenant


def _subject_retriever(tenant, subject: str, k: int = 10) -> VeritySubjectRetriever:
    retriever = VerityVectorStore.subject_retriever(
        verity_url=tenant.url,
        tenant_id=tenant.tenant_id,
        subject=subject,
        k=k,
    )
    # A subject retriever is READ-only by construction — no write surface.
    assert isinstance(retriever, VeritySubjectRetriever)
    assert not hasattr(retriever, "add_texts")
    return retriever


def test_alice_inherits_all_staff_and_sees_group_doc(inheritance_dir):
    tenant = inheritance_dir
    alice = _subject_retriever(tenant, U_ALICE)

    # Query matches the hidden doc's unique marker term — a strong assertion.
    docs = alice.invoke(f"engineering roadmap {MARKER}")
    assert docs, "alice's subject retriever found nothing for a doc her groups can read"
    assert any(MARKER in doc.page_content for doc in docs), (
        "alice should inherit all-staff (alice -> engineering -> all-staff) and "
        f"see the {MARKER} doc"
    )


def test_bob_is_dark_no_group_membership(inheritance_dir):
    tenant = inheritance_dir
    bob = _subject_retriever(tenant, U_BOB)

    # Same marker-matching query; bob is in no group so his closure is empty.
    docs = bob.invoke(f"engineering roadmap {MARKER}")
    assert all(MARKER not in doc.page_content for doc in docs), (
        "bob has no group membership and MUST NOT see the all-staff-only doc"
    )
    # Strongest form: bob sees nothing at all from this tenant's group doc.
    assert docs == [], "bob's subject retriever must be fully dark"
