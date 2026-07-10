"""Mock-based contract tests: exact request bodies for every Verity call."""

from __future__ import annotations

import json
import math
from datetime import datetime

import pytest
import respx
from crewai.memory.types import MemoryRecord
from httpx import Response

from verity_crewai import VerityStorage, in_scope, scope_tag

VERITY_URL = "http://verity.test"
TENANT = "019f0000-0000-7000-8000-000000000001"
SCOPE_RESPONSE = {
    "scope_handle": "vs_test-handle",
    "expires_at": "2099-01-01T00:00:00Z",
}
CREATED = datetime(2026, 7, 1, 0, 0, 0)


def record(record_id: str = "rec-1", **overrides) -> MemoryRecord:
    kwargs = dict(
        id=record_id,
        content="Alice prefers vegetarian catering",
        scope="/crew/research",
        categories=["preferences"],
        metadata={"agent": "planner"},
        importance=0.8,
        created_at=CREATED,
        last_accessed=CREATED,
        source="task-1",
        private=False,
    )
    kwargs.update(overrides)
    return MemoryRecord(**kwargs)


def envelope(rec: MemoryRecord) -> str:
    return json.dumps(
        {
            "kind": "crewai-memory-record",
            "id": rec.id,
            "content": rec.content,
            "scope": rec.scope,
            "categories": rec.categories,
            "metadata": rec.metadata,
            "importance": rec.importance,
            "created_at": rec.created_at.isoformat(),
            "last_accessed": rec.last_accessed.isoformat(),
            "source": rec.source,
            "private": rec.private,
        },
        sort_keys=True,
    )


def hit(rec: MemoryRecord, score: float = 0.42) -> dict:
    return {
        "chunk_id": "019f0000-0000-7000-8000-00000000c001",
        "document_id": f"crewai/{rec.id}",
        "seq": 0,
        "content": envelope(rec),
        "score": score,
        "entity_tags": [scope_tag(rec.scope)],
        "kind": "content",
        "acl_provenance": "admin-assigned",
        "trust_tier": "Authoritative",
        "valid_from": "2026-07-01T00:00:00Z",
        "provenance": f"019f0000-0000-7000-8000-00000000e0{abs(hash(rec.id)) % 16:02x}",
    }


def make_storage(**overrides) -> VerityStorage:
    kwargs = dict(
        verity_url=VERITY_URL,
        tenant_id=TENANT,
        visibility_policy=[3, 7],
        admin_token="test-admin-token",
    )
    kwargs.update(overrides)
    return VerityStorage(**kwargs)


def body(route, call=-1) -> dict:
    return json.loads(route.calls[call].request.content)


# ---------- the visibility_policy doctrine (SPEC §5e.4) ----------

def test_visibility_policy_is_required_and_teaches():
    with pytest.raises(ValueError) as err:
        VerityStorage(verity_url=VERITY_URL, tenant_id=TENANT)
    message = str(err.value)
    assert "SPEC §5e.4" in message
    assert "quarantined" in message
    assert "admin-assigned" in message


@pytest.mark.parametrize("bad", [[], (), "3,7", [3, "7"], [True], 3])
def test_visibility_policy_rejects_non_token_lists(bad):
    with pytest.raises(ValueError, match="SPEC §5e.4"):
        VerityStorage(verity_url=VERITY_URL, tenant_id=TENANT, visibility_policy=bad)


# ---------- protocol conformance + scope mapping ----------

def test_satisfies_the_storage_backend_protocol():
    from crewai.memory.storage.backend import StorageBackend

    assert isinstance(make_storage(), StorageBackend)


def test_scope_paths_become_exact_entity_tags():
    assert scope_tag("/crew/research") == "crew:/crew/research"
    assert scope_tag("crew/research/") == "crew:/crew/research"
    assert scope_tag(None) == "crew:/"


def test_in_scope_is_hierarchical_prefix_match():
    assert in_scope("/crew/research", "/crew")
    assert in_scope("/crew/research", None)
    assert in_scope("/crew", "/crew")
    assert not in_scope("/crewmates", "/crew")
    assert not in_scope("/other", "/crew")


# ---------- the embedder shim ----------

def test_embedder_is_deterministic_and_distinct_texts_diverge():
    storage = make_storage()
    [a1], [a2] = storage.embedder(["alpha"]), storage.embedder(["alpha"])
    [b] = storage.embedder(["beta"])
    assert a1 == a2  # identical text -> identical vector (dedup-safe)
    assert len(a1) == 16
    cos = sum(x * y for x, y in zip(a1, b)) / (
        math.sqrt(sum(x * x for x in a1)) * math.sqrt(sum(x * x for x in b))
    )
    assert abs(cos) < 0.9  # distinct texts never look like duplicates


def test_search_with_foreign_embedding_fails_closed_and_teaches():
    with pytest.raises(ValueError, match="embedder=storage.embedder"):
        make_storage().search([0.1] * 1536)


# ---------- save() -> POST /v1/ingest/documents ----------

@respx.mock(base_url=VERITY_URL)
def test_save_posts_exact_ingest_body(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-1", "chunks_indexed": 1})
    )
    rec = record()
    make_storage().save([rec])

    assert body(ingest) == {
        "tenant_id": TENANT,
        "source": "crewai-memory",
        "document_id": "crewai/rec-1",
        "content": envelope(rec),
        "entities": ["crew:/crew/research"],
        "visibility": [3, 7],
        "acl_provenance": "admin-assigned",
    }
    auth = ingest.calls.last.request.headers["authorization"]
    assert auth == "Bearer test-admin-token"


@respx.mock(base_url=VERITY_URL)
def test_update_reingests_same_document_id(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-2", "chunks_indexed": 1})
    )
    storage = make_storage()
    storage.save([record()])
    storage.update(record(content="Alice now prefers vegan catering"))
    assert ingest.call_count == 2
    assert body(ingest, 0)["document_id"] == body(ingest, 1)["document_id"]


# ---------- search() -> POST /v1/scopes + POST /v1/recall ----------

@respx.mock(base_url=VERITY_URL)
def test_search_maps_embedding_back_to_text_and_recalls(respx_mock):
    scopes = respx_mock.post("/v1/scopes").mock(
        return_value=Response(200, json=SCOPE_RESPONSE)
    )
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(record())])
    )
    storage = make_storage()
    [query_vec] = storage.embedder(["what catering does alice want?"])
    results = storage.search(query_vec, scope_prefix="/crew", limit=5)

    # No entity_scope: Verity entity scoping is exact-tag subset semantics,
    # so hierarchical scope_prefix filtering happens client-side.
    assert body(scopes) == {
        "tenant_id": TENANT,
        "principals": [3, 7],
        "ttl_seconds": 3600,
    }
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 100,
        "text": "what catering does alice want?",
    }
    assert len(results) == 1
    rec, score = results[0]
    assert isinstance(rec, MemoryRecord)
    assert rec.id == "rec-1"
    assert rec.content == "Alice prefers vegetarian catering"
    assert rec.metadata == {"agent": "planner"}
    assert score == pytest.approx(0.42)


@respx.mock(base_url=VERITY_URL)
def test_search_applies_client_side_filters(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    respx_mock.post("/v1/recall").mock(
        return_value=Response(
            200,
            json=[
                hit(record("rec-1", categories=["preferences"]), 0.9),
                hit(record("rec-2", categories=["logistics"]), 0.8),
                hit(record("rec-3", categories=["preferences"]), 0.1),
                hit(record("rec-4", metadata={"agent": "other"}), 0.7),
                hit(record("rec-5", scope="/other"), 0.95),  # outside the prefix
            ],
        )
    )
    storage = make_storage()
    [vec] = storage.embedder(["q"])
    results = storage.search(
        vec,
        scope_prefix="/crew",
        categories=["preferences"],
        metadata_filter={"agent": "planner"},
        min_score=0.2,
    )
    assert [rec.id for rec, _ in results] == ["rec-1"]


# ---------- delete() / reset() -> POST /v1/forget ----------

@respx.mock(base_url=VERITY_URL)
def test_delete_by_id_forgets_the_session_episode(respx_mock):
    respx_mock.post("/v1/ingest/documents").mock(
        return_value=Response(200, json={"episode_id": "ep-9", "chunks_indexed": 1})
    )
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    storage = make_storage()
    storage.save([record()])
    assert storage.delete(record_ids=["rec-1"]) == 1

    assert body(forget) == {
        "scope_handle": "vs_test-handle",
        "ref": {"kind": "episode", "id": "ep-9"},
        "reason": "crewai-memory delete crewai/rec-1",
    }


@respx.mock(base_url=VERITY_URL)
def test_delete_cross_session_id_looks_up_provenance(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    rec = record("rec-7")
    respx_mock.post("/v1/recall").mock(return_value=Response(200, json=[hit(rec)]))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    assert make_storage().delete(record_ids=["rec-7"]) == 1
    assert body(forget)["ref"]["id"] == hit(rec)["provenance"]


def test_predicate_deletes_fail_closed():
    with pytest.raises(NotImplementedError, match="record_ids"):
        make_storage().delete(categories=["preferences"])
    with pytest.raises(NotImplementedError, match="record_ids"):
        make_storage().delete()


@respx.mock(base_url=VERITY_URL)
def test_reset_retires_this_sessions_scope_matches_only(respx_mock):
    ingest = respx_mock.post("/v1/ingest/documents").mock(
        side_effect=[
            Response(200, json={"episode_id": "ep-a", "chunks_indexed": 1}),
            Response(200, json={"episode_id": "ep-b", "chunks_indexed": 1}),
        ]
    )
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    forget = respx_mock.post("/v1/forget").mock(
        return_value=Response(200, json={"retired": 1})
    )
    storage = make_storage()
    storage.save([record("rec-a", scope="/crew/research")])
    storage.save([record("rec-b", scope="/other")])
    storage.reset("/crew")

    assert ingest.call_count == 2
    assert forget.call_count == 1
    assert body(forget)["ref"] == {"kind": "episode", "id": "ep-a"}
    assert body(forget)["reason"] == "crewai-memory reset /crew"


# ---------- read-backs and fail-closed enumeration ----------

@respx.mock(base_url=VERITY_URL)
def test_get_record_finds_by_id_via_recall(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(record("rec-5"))])
    )
    found = make_storage().get_record("rec-5")
    assert body(recall)["text"] == "rec-5"
    assert found is not None and found.id == "rec-5"


@respx.mock(base_url=VERITY_URL)
def test_list_records_uses_marker_recall_newest_first(respx_mock):
    respx_mock.post("/v1/scopes").mock(return_value=Response(200, json=SCOPE_RESPONSE))
    older = record("rec-old", created_at=datetime(2026, 1, 1))
    newer = record("rec-new", created_at=datetime(2026, 7, 1))
    recall = respx_mock.post("/v1/recall").mock(
        return_value=Response(200, json=[hit(older), hit(newer)])
    )
    records = make_storage().list_records("/crew")
    assert body(recall) == {
        "scope_handle": "vs_test-handle",
        "k": 100,
        "text": "crewai-memory-record",
    }
    assert [r.id for r in records] == ["rec-new", "rec-old"]


def test_hierarchy_enumeration_fails_closed():
    storage = make_storage()
    with pytest.raises(NotImplementedError, match="sink lane"):
        storage.get_scope_info("/crew")
    with pytest.raises(NotImplementedError, match="sink lane"):
        storage.list_scopes()
    with pytest.raises(NotImplementedError, match="sink lane"):
        storage.list_categories()
