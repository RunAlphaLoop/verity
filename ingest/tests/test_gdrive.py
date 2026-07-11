"""Google Drive connector conformance tests (SPEC.md §5: ACL-mapping
conformance is load-bearing and gates release).

All Drive API payloads are recorded fixtures authored from Google's
documented resource shapes (developers.google.com, Drive API v3:
changes.list / changes.getStartPageToken / files.get / permissions.list).
No live API calls anywhere in this file.
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import httpx
import pytest

from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gdrive import (
    DOCUMENTS_PATH,
    PRINCIPALS_PATH,
    DryRunSink,
    GDriveConfig,
    GDriveConnector,
    GDriveDocumentEvent,
    HttpRegistry,
    StaticRegistry,
    VerityDocumentSink,
    build_document_request,
    map_permissions,
    run_once,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gdrive"

DOC_ID = "1QplanDocAAAAAAAAAAAAAAAAAAAAAAAA"
GONE_ID = "1GoneFileBBBBBBBBBBBBBBBBBBBBBBBB"
TXT_ID = "1OncallTxtCCCCCCCCCCCCCCCCCCCCCC"
PDF_ID = "1PricingPdfDDDDDDDDDDDDDDDDDDDDD"
TRASHED_ID = "1OldNotesTrashEEEEEEEEEEEEEEEEEE"

_FILE_FIXTURES = {
    DOC_ID: "file_doc.json",
    TXT_ID: "file_notes.json",
    PDF_ID: "file_pricing.json",
    TRASHED_ID: "file_trashed.json",
}
_PERM_FIXTURES = {
    DOC_ID: "perms_doc.json",
    TXT_ID: "perms_notes.json",
    PDF_ID: "perms_pricing.json",
}
_CHANGES_PAGES = {
    "387": "changes_page1.json",
    "387-page-2": "changes_page2.json",
}

REGISTRY_MAP = {
    "user:alice@corp.example": 101,
    "group:eng-leads@corp.example": 202,
    "domain:corp.example": 303,
}

TENANT = "t-acme"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FixtureTransport:
    """DriveTransport backed by recorded JSON/bytes fixtures."""

    def __init__(self) -> None:
        self.json_calls: list[tuple[str, dict]] = []
        self.bytes_calls: list[tuple[str, dict]] = []

    def get_json(self, path: str, params: dict) -> dict:
        self.json_calls.append((path, dict(params)))
        if path == "changes/startPageToken":
            return _load("start_page_token.json")
        if path == "changes":
            return _load(_CHANGES_PAGES[params["pageToken"]])
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "files" and parts[2] == "permissions":
            return _load(_PERM_FIXTURES[parts[1]])
        if len(parts) == 2 and parts[0] == "files":
            return _load(_FILE_FIXTURES[parts[1]])
        raise AssertionError(f"unexpected Drive call: GET {path} {params}")

    def get_bytes(self, path: str, params: dict) -> bytes:
        self.bytes_calls.append((path, dict(params)))
        if path == f"files/{DOC_ID}/export" and params.get("mimeType") == "text/plain":
            return (FIXTURES / "doc_export.txt").read_bytes()
        if path == f"files/{TXT_ID}" and params.get("alt") == "media":
            return (FIXTURES / "oncall_notes.txt").read_bytes()
        raise AssertionError(f"unexpected content fetch: GET {path} {params}")


def _poll(cursor, config: GDriveConfig | None = None):
    transport = FixtureTransport()
    connector = GDriveConnector(transport, config or GDriveConfig(tenant_id=TENANT))
    events, next_cursor = asyncio.run(connector.poll(cursor))
    return transport, events, next_cursor


# ---------------------------------------------------------------------------
# ACL mapping conformance (SPEC fail-closed rules)
# ---------------------------------------------------------------------------


def test_map_user_and_group_permissions():
    envelope = map_permissions(_load("perms_doc.json")["permissions"])
    assert envelope == AclEnvelope(
        resolvable=True,
        principals=["user:alice@corp.example"],
        groups=["group:eng-leads@corp.example"],
    )


def test_map_domain_permission():
    envelope = map_permissions(_load("perms_notes.json")["permissions"])
    assert envelope == AclEnvelope(
        resolvable=True,
        principals=["user:alice@corp.example"],
        groups=["domain:corp.example"],
    )


def test_anyone_link_quarantines_by_default():
    envelope = map_permissions(_load("perms_pricing.json")["permissions"])
    assert envelope == AclEnvelope(resolvable=False, principals=[], groups=[])


def test_anyone_link_maps_only_with_explicit_config():
    envelope = map_permissions(
        _load("perms_pricing.json")["permissions"], anyone_maps_to="org:everyone"
    )
    assert envelope == AclEnvelope(
        resolvable=True,
        principals=["user:bob@corp.example"],
        groups=["org:everyone"],
    )


def test_unknown_permission_type_quarantines():
    perms = [{"type": "sharePointGroup", "id": "x", "role": "reader"}]
    assert map_permissions(perms) == AclEnvelope(resolvable=False)


def test_user_permission_without_email_quarantines():
    perms = [{"type": "user", "id": "x", "role": "reader"}]
    assert map_permissions(perms) == AclEnvelope(resolvable=False)


def test_deleted_permission_confers_nothing():
    perms = [
        {"type": "user", "emailAddress": "alice@corp.example", "role": "owner"},
        {"type": "user", "emailAddress": "gone@corp.example", "role": "reader", "deleted": True},
    ]
    assert map_permissions(perms) == AclEnvelope(
        resolvable=True, principals=["user:alice@corp.example"], groups=[]
    )


# ---------------------------------------------------------------------------
# Truth lane: changes.list polling
# ---------------------------------------------------------------------------


def test_first_poll_returns_start_page_token_and_no_events():
    transport, events, cursor = _poll(None)
    assert events == []
    assert cursor == "387"
    assert transport.json_calls[0][0] == "changes/startPageToken"


def test_poll_paginates_and_advances_cursor():
    _, events, cursor = _poll("387")
    assert cursor == "412"
    # doc, removed file, text file, anyone-pdf, trashed file; the
    # changeType="drive" entry is skipped (identity plane's job, not ours).
    assert [e.document_id for e in events] == [DOC_ID, GONE_ID, TXT_ID, PDF_ID, TRASHED_ID]
    assert all(isinstance(e, GDriveDocumentEvent) for e in events)


def test_google_doc_exports_text_and_mirrors_acl():
    _, events, _ = _poll("387")
    doc = events[0]
    assert doc.mime_type == "application/vnd.google-apps.document"
    assert doc.content == (FIXTURES / "doc_export.txt").read_bytes()
    assert doc.version == "42"
    assert doc.modified_time == "2026-07-09T09:59:31.000Z"
    assert doc.acl == AclEnvelope(
        resolvable=True,
        principals=["user:alice@corp.example"],
        groups=["group:eng-leads@corp.example"],
    )


def test_plain_text_file_downloads_directly():
    _, events, _ = _poll("387")
    txt = events[2]
    assert txt.mime_type == "text/plain"
    assert txt.content == (FIXTURES / "oncall_notes.txt").read_bytes()
    assert txt.acl == AclEnvelope(
        resolvable=True,
        principals=["user:alice@corp.example"],
        groups=["domain:corp.example"],
    )


def test_anyone_shared_file_quarantines_and_content_is_never_fetched():
    transport, events, _ = _poll("387")
    pdf = events[3]
    assert pdf.acl == AclEnvelope(resolvable=False, principals=[], groups=[])
    assert pdf.content == b""
    # ACL-before-content (§5a): no bytes were pulled for the quarantined item,
    # and none for the non-extractable PDF mimetype either way.
    assert all(not path.startswith(f"files/{PDF_ID}") for path, _ in transport.bytes_calls)


def test_removed_and_trashed_files_emit_removal_markers():
    transport, events, _ = _poll("387")
    gone, trashed = events[1], events[4]
    assert gone.removed and gone.modified_time == "2026-07-09T10:02:41.000Z"
    assert trashed.removed and trashed.modified_time == "2026-07-09T10:09:01.000Z"
    # A hard-removed change never triggers files.get.
    assert all(path != f"files/{GONE_ID}" for path, _ in transport.json_calls)


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------


def test_static_registry_resolves_known_and_skips_unknown():
    registry = StaticRegistry(REGISTRY_MAP)
    resolved = registry.resolve(["user:alice@corp.example", "user:nobody@corp.example"])
    assert resolved == {"user:alice@corp.example": 101}


def test_http_registry_contract():
    """POST /v1/admin/principals {"tenant_id", "principals"} — server as
    built returns tokens nested under "mappings"."""
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "mappings": {
                    "user:alice@corp.example": 101,
                    "group:eng-leads@corp.example": 202,
                    "user:nobody@corp.example": None,
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    registry = HttpRegistry(
        "http://verity.local:8080",
        tenant_id="8b1c8d7e-0a63-4a1a-9d1e-000000000001",
        client=client,
    )
    resolved = registry.resolve(
        ["user:alice@corp.example", "group:eng-leads@corp.example", "user:nobody@corp.example"]
    )
    assert seen == {
        "method": "POST",
        "path": PRINCIPALS_PATH,
        "body": {
            "tenant_id": "8b1c8d7e-0a63-4a1a-9d1e-000000000001",
            "principals": [
                "user:alice@corp.example",
                "group:eng-leads@corp.example",
                "user:nobody@corp.example",
            ],
        },
    }
    # Null token = unresolved: contributes no visibility (fail-closed).
    assert resolved == {"user:alice@corp.example": 101, "group:eng-leads@corp.example": 202}


# ---------------------------------------------------------------------------
# Sink request bodies (POST /v1/ingest/documents contract)
# ---------------------------------------------------------------------------


def _delivered_requests(config: GDriveConfig | None = None) -> list[dict]:
    _, events, _ = _poll("387", config)
    registry = StaticRegistry(REGISTRY_MAP)
    sink = DryRunSink(stream=io.StringIO())
    for event in events:
        sink.deliver(build_document_request(event, registry, TENANT))
    return sink.requests


def test_sink_request_bodies_exact():
    assert _delivered_requests() == [
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": DOC_ID,
            "content": (FIXTURES / "doc_export.txt").read_text(),
            "entities": [],
            "valid_from": "2026-07-09T09:59:31.000Z",
            "visibility": [101, 202],
            "acl_provenance": "mirrored",
        },
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": GONE_ID,
            "removed": True,
            "valid_from": "2026-07-09T10:02:41.000Z",
        },
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": TXT_ID,
            "content": (FIXTURES / "oncall_notes.txt").read_text(),
            "entities": [],
            "valid_from": "2026-07-09T10:04:58.000Z",
            "visibility": [101, 303],
            "acl_provenance": "mirrored",
        },
        {
            # anyone-link: quarantined — no visibility field, no content.
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": PDF_ID,
            "content": None,
            "entities": [],
            "valid_from": "2026-07-09T10:07:02.000Z",
            "acl_provenance": "quarantined",
        },
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": TRASHED_ID,
            "removed": True,
            "valid_from": "2026-07-09T10:09:01.000Z",
        },
    ]


def test_unresolved_principal_confers_no_visibility():
    registry = StaticRegistry({"user:alice@corp.example": 101})  # group missing
    _, events, _ = _poll("387")
    body = build_document_request(events[0], registry, TENANT)
    assert body["visibility"] == [101]
    assert body["acl_provenance"] == "mirrored"


def test_all_principals_unresolvable_quarantines():
    _, events, _ = _poll("387")
    body = build_document_request(events[0], registry=StaticRegistry({}), tenant_id=TENANT)
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"


def test_verity_sink_posts_to_documents_endpoint():
    posted: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(202, json={"status": "accepted"})

    sink = VerityDocumentSink(
        "http://verity.local:8080", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    body = {"tenant_id": TENANT, "source": "gdrive", "document_id": DOC_ID}
    sink.deliver(body)
    assert posted == [("POST", DOCUMENTS_PATH, body)]


def test_verity_sink_heartbeat_reports_batch_then_resets():
    posted: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"recorded": True})

    sink = VerityDocumentSink(
        "http://verity.local:8080", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    sink.deliver(
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": DOC_ID,
            "valid_from": "2026-02-03T10:00:00.000Z",
        }
    )
    sink.deliver(
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": TXT_ID,
            "valid_from": "2026-02-01T09:00:00.000Z",  # older: never wins
        }
    )
    sink.heartbeat(cursor="412")
    assert posted[-1] == (
        "/v1/admin/connector-status",
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "items_synced": 2,
            "cursor": "412",
            "last_event_at": "2026-02-03T10:00:00.000Z",
        },
    )
    # Accumulators reset: a heartbeat with nothing delivered posts nothing.
    calls_before = len(posted)
    sink.heartbeat(cursor="413")
    assert len(posted) == calls_before


def test_verity_sink_raises_on_rejection():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "visibility-or-acl required"})

    sink = VerityDocumentSink(
        "http://verity.local:8080", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(httpx.HTTPStatusError):
        sink.deliver({"tenant_id": TENANT})


# ---------------------------------------------------------------------------
# Runner: cursor checkpointing
# ---------------------------------------------------------------------------


def test_run_once_establishes_then_advances_cursor(tmp_path):
    state_file = tmp_path / "gdrive_cursor.json"
    registry = StaticRegistry(REGISTRY_MAP)

    # First run: no cursor -> getStartPageToken, nothing delivered.
    connector = GDriveConnector(FixtureTransport(), GDriveConfig(tenant_id=TENANT))
    sink = DryRunSink(stream=io.StringIO())
    assert run_once(connector, registry, sink, state_file) == 0
    assert json.loads(state_file.read_text()) == {"cursor": "387"}

    # Second run: polls from 387, delivers all five requests, advances to 412.
    connector = GDriveConnector(FixtureTransport(), GDriveConfig(tenant_id=TENANT))
    sink = DryRunSink(stream=io.StringIO())
    assert run_once(connector, registry, sink, state_file) == 5
    assert json.loads(state_file.read_text()) == {"cursor": "412"}
    assert [r["document_id"] for r in sink.requests] == [
        DOC_ID,
        GONE_ID,
        TXT_ID,
        PDF_ID,
        TRASHED_ID,
    ]
