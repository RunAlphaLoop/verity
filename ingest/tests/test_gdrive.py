"""Google Drive connector conformance tests (SPEC.md §5: ACL-mapping
conformance is load-bearing and gates release).

All Drive API payloads are recorded fixtures authored from Google's
documented resource shapes (developers.google.com, Drive API v3:
changes.list / changes.getStartPageToken / files.get / permissions.list).
No live API calls anywhere in this file.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
from pathlib import Path

import httpx
import pytest

from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gdrive import (
    DOCUMENTS_PATH,
    PRINCIPALS_PATH,
    DryRunFactSink,
    DryRunSink,
    GDriveConfig,
    GDriveConnector,
    GDriveDocumentEvent,
    HttpRegistry,
    StaticRegistry,
    VerityDocumentSink,
    build_document_request,
    deliver_facts,
    is_binary_extractable,
    map_permissions,
    run_once,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gdrive"

DOC_ID = "1QplanDocAAAAAAAAAAAAAAAAAAAAAAAA"
GONE_ID = "1GoneFileBBBBBBBBBBBBBBBBBBBBBBBB"
TXT_ID = "1OncallTxtCCCCCCCCCCCCCCCCCCCCCC"
PDF_ID = "1PricingPdfDDDDDDDDDDDDDDDDDDDDD"
TRASHED_ID = "1OldNotesTrashEEEEEEEEEEEEEEEEEE"
XLSX_ID = "1PipelineXlsxFFFFFFFFFFFFFFFFFFF"

# The binary lane treats file bytes as opaque (extraction is server-side), so
# the fixture bytes only need to LOOK like an office file — generated inline,
# no binary fixture files in the repo.
XLSX_BYTES = b"PK\x03\x04 tiny xlsx stand-in bytes \x00\x01\x02"

_FILE_FIXTURES = {
    DOC_ID: "file_doc.json",
    TXT_ID: "file_notes.json",
    PDF_ID: "file_pricing.json",
    TRASHED_ID: "file_trashed.json",
    XLSX_ID: "file_pipeline.json",
}
_PERM_FIXTURES = {
    DOC_ID: "perms_doc.json",
    TXT_ID: "perms_notes.json",
    PDF_ID: "perms_pricing.json",
    XLSX_ID: "perms_pipeline.json",
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
        if path == f"files/{XLSX_ID}" and params.get("alt") == "media":
            return XLSX_BYTES
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
    # doc, removed file, text file, anyone-pdf, trashed file, xlsx; the
    # changeType="drive" entry is skipped (identity plane's job, not ours).
    assert [e.document_id for e in events] == [
        DOC_ID,
        GONE_ID,
        TXT_ID,
        PDF_ID,
        TRASHED_ID,
        XLSX_ID,
    ]
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
    # ACL-before-content (§5a): PDFs ARE binary-extractable now, so the ONLY
    # thing keeping these bytes unfetched is the quarantine — which is
    # exactly the ordering guarantee this test pins.
    assert is_binary_extractable("application/pdf")
    assert all(not path.startswith(f"files/{PDF_ID}") for path, _ in transport.bytes_calls)


def test_office_file_downloads_bytes_for_server_side_extraction():
    _, events, _ = _poll("387")
    xlsx = events[5]
    assert xlsx.mime_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert xlsx.content == XLSX_BYTES
    assert xlsx.name == "q3-pipeline.xlsx"
    assert xlsx.acl == AclEnvelope(
        resolvable=True,
        principals=["user:alice@corp.example"],
        groups=["group:eng-leads@corp.example"],
    )


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
        {
            # binary lane: raw bytes for server-side Tier-1 extraction —
            # content_base64 + filename INSTEAD of "content", same mirrored
            # visibility mapping as text deliveries.
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": XLSX_ID,
            "content_base64": base64.b64encode(XLSX_BYTES).decode("ascii"),
            "filename": "q3-pipeline.xlsx",
            "entities": [],
            "valid_from": "2026-07-09T10:11:12.000Z",
            "visibility": [101, 202],
            "acl_provenance": "mirrored",
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


def test_binary_lane_with_unresolvable_principals_also_quarantines():
    _, events, _ = _poll("387")
    body = build_document_request(events[5], registry=StaticRegistry({}), tenant_id=TENANT)
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"
    # The bytes still ride along (the server's choke point holds quarantined
    # items un-indexed) and "content" is never doubled up next to base64.
    assert body["content_base64"] == base64.b64encode(XLSX_BYTES).decode("ascii")
    assert "content" not in body


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

    # Second run: polls from 387. Only the three SCOPABLE files are delivered
    # to /v1/ingest/documents — the two removals (GONE_ID, TRASHED_ID) and the
    # anyone-shared quarantine (PDF_ID) are skipped fail-closed: the server's
    # documents endpoint accepts only mirrored/approximated/admin-assigned
    # writes (it has no `removed` field and rejects `quarantined`), so
    # delivering them would 422 and, worse, one such file would abort a whole
    # crawl. Skipped files are counted and reported, never indexed. Cursor
    # still advances to 412 (the whole window was processed).
    connector = GDriveConnector(FixtureTransport(), GDriveConfig(tenant_id=TENANT))
    sink = DryRunSink(stream=io.StringIO())
    assert run_once(connector, registry, sink, state_file) == 3
    assert json.loads(state_file.read_text()) == {"cursor": "412"}
    assert [r["document_id"] for r in sink.requests] == [DOC_ID, TXT_ID, XLSX_ID]


# --- M1 connector ACL-diff lane (build #5): document-target retraction ------


class _CollectingClient:
    """Minimal POST-only client that records acl-change bodies."""

    def __init__(self) -> None:
        self.posts: list[dict] = []

    def post(self, url, json):  # noqa: A002 — httpx kwarg name
        self.posts.append({"url": url, "body": json})

        class _Resp:
            def raise_for_status(self_inner):
                return None

        return _Resp()


def test_gdrive_acl_diff_lane_emits_document_retraction_on_tightening(tmp_path):
    from verity_ingest.acl_diff import AclDiffLane, AclState

    # A Drive file whose sharing tightens between two syncs: bob (a writer)
    # loses access. The lane emits ONE acl-change targeting the DOCUMENT lineage
    # (object.document_id → correct_chunk_acl), carrying the NEW FULL resolved
    # token set (alice only) and bob in the removed set.
    registry = StaticRegistry(
        {"user:alice@corp.example": 101, "user:bob@corp.example": 202}
    )
    client = _CollectingClient()
    state = AclState(tmp_path / "gdrive.acl.json")
    lane = AclDiffLane(
        state,
        tenant_id=TENANT,
        registry=registry,
        client=client,
        base_url="http://verity.local:7717",
    )
    doc = "1PlanDocXYZ"

    # Sync 1: alice + bob share the file — baseline, no emit.
    assert (
        lane.observe(
            doc,
            ["user:alice@corp.example", "user:bob@corp.example"],
            source="gdrive",
            document_id=doc,
        )
        is None
    )
    assert client.posts == []

    # Sync 2: bob un-shared → exactly one document-target acl-change.
    change = lane.observe(
        doc, ["user:alice@corp.example"], source="gdrive", document_id=doc
    )
    assert change is not None
    assert change.removed_principals == ["user:bob@corp.example"]
    lane.flush()

    assert len(client.posts) == 1
    body = client.posts[0]["body"]
    assert client.posts[0]["url"].endswith("/v1/ingest/acl-change")
    assert body["source"] == "gdrive"
    assert body["object"] == {"document_id": doc}
    assert "fact" not in body
    # REPLACE: the new full resolved set is alice only (bob=202 gone).
    assert body["verity_acl"]["visibility"] == [101]
    assert body["reason"] == "source_unshare"
    assert lane.emitted == 1


# ---------------------------------------------------------------------------
# Fact lane: selective identity-keyed org/person envelopes (§4.2, the weld)
# ---------------------------------------------------------------------------
#
# These drive the accumulator directly via _observe_permissions (no new
# fixtures needed) and then deliver_facts into a DryRunFactSink, asserting
# selectivity (only real users become people; groups/domain/anyone/service-
# accounts/freemail/role-locals do not), the weld shape (bare `email` under
# source gdrive:contacts.person), owner-only visibility, and fail-closed.

ALICE = "alice@corp.example"  # file owner in perms_doc/perms_pipeline
ALICE_TOKEN = 101

# A modifiedTime the accumulator can parse to epoch-millis for ts_ms.
_TS = "2026-07-09T10:00:00.000Z"


def _person_envelopes(envelopes):
    return [e for e in envelopes if (e.get("source") or {}).get("table") == "person"]


def _org_envelopes(envelopes):
    return [e for e in envelopes if (e.get("source") or {}).get("table") == "org"]


def test_person_facts_weld_shape():
    """A sharer (bob, writer) becomes a person fact with the BARE `email` weld
    key under source gdrive:contacts.person and owner-only visibility. The file
    owner (== the crawl subject alice) is excluded (self is not a correspondent);
    a type=group grant never becomes a person; and alice's OWN domain is excluded
    from the org lane when exclude_owner_domain is on."""
    connector = GDriveConnector(
        FixtureTransport(), GDriveConfig(delegated_subject=ALICE, tenant_id=TENANT)
    )
    # perms_pricing: bob@corp.example (writer). perms_doc: alice owner + group.
    connector._observe_permissions(_load("perms_pricing.json")["permissions"], _TS)
    connector._observe_permissions(_load("perms_doc.json")["permissions"], _TS)

    registry = StaticRegistry({f"user:{ALICE}": ALICE_TOKEN})
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(connector, registry, sink)

    people = _person_envelopes(sink.envelopes)
    assert persons == len(people) == 1
    bob = people[0]
    assert bob["after"]["email"] == "bob@corp.example"  # bare email == weld key
    assert bob["after"]["id"] == "bob@corp.example"
    assert bob["after"]["correspondence"] == "shared_with"
    # ts_ms is optional; assert the identity triple that names the weld source.
    assert bob["source"]["connector"] == "gdrive"
    assert bob["source"]["db"] == "contacts"
    assert bob["source"]["table"] == "person"
    assert bob["verity_acl"]["visibility"] == [ALICE_TOKEN]
    assert bob["op"] == "c"

    # alice (owner == subject) is not a person; eng-leads group is not a person.
    person_emails = {e["after"]["email"] for e in people}
    assert ALICE not in person_emails
    assert "eng-leads@corp.example" not in person_emails

    # corp.example is alice's OWN domain → excluded from the org lane.
    org_domains = {e["after"]["domain"] for e in _org_envelopes(sink.envelopes)}
    assert "corp.example" not in org_domains
    assert orgs == 0


def test_person_facts_owner_role_marks_correspondence_owner():
    """When the crawl subject is a DIFFERENT user, the file owner (alice) does
    survive as a person with correspondence=='owner' (role=owner)."""
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    connector._observe_permissions(_load("perms_doc.json")["permissions"], _TS)
    registry = StaticRegistry({"user:ops@ourco.com": 501})
    sink = DryRunFactSink(stream=io.StringIO())
    deliver_facts(connector, registry, sink)
    people = {e["after"]["email"]: e for e in _person_envelopes(sink.envelopes)}
    assert ALICE in people
    assert people[ALICE]["after"]["correspondence"] == "owner"


def test_service_account_and_denylist_excluded():
    """A service account never becomes a person OR an org; a role-local user
    email drops from the person lane but its domain STILL proves the org; a real
    external user survives as a shared_with person."""
    perms = [
        {"type": "user", "emailAddress": "svc-123@my-proj.iam.gserviceaccount.com", "role": "owner"},
        {"type": "user", "emailAddress": "no-reply@acme.com", "role": "writer"},
        {"type": "user", "emailAddress": "jane@vendor.io", "role": "reader"},
    ]
    # Owner at a DIFFERENT domain so exclude_owner_domain doesn't eat acme/vendor.
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    connector._observe_permissions(perms, _TS)
    registry = StaticRegistry({"user:ops@ourco.com": 501})
    sink = DryRunFactSink(stream=io.StringIO())
    deliver_facts(connector, registry, sink)

    person_emails = {e["after"]["email"] for e in _person_envelopes(sink.envelopes)}
    assert person_emails == {"jane@vendor.io"}
    jane = next(e for e in _person_envelopes(sink.envelopes) if e["after"]["email"] == "jane@vendor.io")
    assert jane["after"]["correspondence"] == "shared_with"

    org_domains = {e["after"]["domain"] for e in _org_envelopes(sink.envelopes)}
    assert "acme.com" in org_domains  # role-local user email still proves the org
    assert "vendor.io" in org_domains
    assert not any(d.endswith("gserviceaccount.com") for d in org_domains)
    # Service account never leaked as a person either.
    assert not any(p.endswith("gserviceaccount.com") for p in person_emails)


def test_group_domain_anyone_never_produce_person_facts():
    """type=group, type=domain, and type=anyone contribute NO person facts.
    type=domain seeds an org; group/anyone contribute nothing at all."""
    perms = [
        {"type": "group", "emailAddress": "eng-leads@corp.example", "role": "reader"},
        {"type": "domain", "domain": "partner.io", "role": "reader"},
        {"type": "anyone", "role": "reader"},
    ]
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    connector._observe_permissions(perms, _TS)
    registry = StaticRegistry({"user:ops@ourco.com": 501})
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(connector, registry, sink)
    assert persons == 0
    assert _person_envelopes(sink.envelopes) == []
    org_domains = {e["after"]["domain"] for e in _org_envelopes(sink.envelopes)}
    assert org_domains == {"partner.io"}  # domain-perm seeds org; group/anyone do not


def test_fact_lane_fail_closed_when_owner_unresolvable():
    """Subject set but the owner principal resolves to nothing → (0,0), ZERO
    envelopes. And no delegated subject at all (shared-drive) → (0,0), zero
    envelopes — the document lane is untouched either way."""
    perms = _load("perms_pricing.json")["permissions"]

    # (a) owner set, registry returns nothing for it.
    connector = GDriveConnector(
        FixtureTransport(), GDriveConfig(delegated_subject=ALICE, tenant_id=TENANT)
    )
    connector._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    assert deliver_facts(connector, StaticRegistry({}), sink) == (0, 0)
    assert sink.envelopes == []

    # (b) no delegated subject → owner empty → fail closed.
    connector = GDriveConnector(
        FixtureTransport(), GDriveConfig(delegated_subject=None, tenant_id=TENANT)
    )
    connector._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    # Even a registry that COULD resolve someone yields nothing: no owner token.
    assert deliver_facts(connector, StaticRegistry({f"user:{ALICE}": ALICE_TOKEN}), sink) == (0, 0)
    assert sink.envelopes == []


def test_emit_flags():
    """emit_facts=False → (0,0) regardless of accumulated state. emit_people=
    False → orgs still emitted, zero person envelopes."""
    perms = [
        {"type": "user", "emailAddress": "jane@vendor.io", "role": "reader"},
    ]
    registry = StaticRegistry({"user:ops@ourco.com": 501})

    off = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT, emit_facts=False),
    )
    off._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    assert deliver_facts(off, registry, sink) == (0, 0)
    assert sink.envelopes == []

    no_people = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT, emit_people=False),
    )
    no_people._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(no_people, registry, sink)
    assert persons == 0
    assert _person_envelopes(sink.envelopes) == []
    assert orgs >= 1
    assert "vendor.io" in {e["after"]["domain"] for e in _org_envelopes(sink.envelopes)}


def test_every_emitted_fact_carries_owner_only_visibility():
    """Belt-and-suspenders: EVERY delivered envelope (org and person) carries
    verity_acl.visibility == [owner_token] — never empty, never missing."""
    perms = [
        {"type": "user", "emailAddress": "jane@vendor.io", "role": "reader"},
        {"type": "user", "emailAddress": "ops@ourco.com", "role": "owner"},
    ]
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    connector._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(connector, StaticRegistry({"user:ops@ourco.com": 501}), sink)
    assert orgs + persons == len(sink.envelopes) >= 1
    for env in sink.envelopes:
        assert env["verity_acl"]["visibility"] == [501]


def test_freemail_sharer_never_becomes_person_or_org():
    """A gmail.com sharer is freemail: never a person (no weld between two
    strangers at gmail.com) and never an org."""
    perms = [{"type": "user", "emailAddress": "randomdude@gmail.com", "role": "writer"}]
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    connector._observe_permissions(perms, _TS)
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(connector, StaticRegistry({"user:ops@ourco.com": 501}), sink)
    assert (orgs, persons) == (0, 0)
    assert sink.envelopes == []


def test_document_lane_unchanged_by_fact_lane():
    """After wiring the observe side-effect, the document request bodies are
    byte-identical to test_sink_request_bodies_exact — proving the additive fact
    lane touched nothing in the doc/chunk/ACL lane (no _FILE_FIELDS change)."""
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
        {
            "tenant_id": TENANT,
            "source": "gdrive",
            "document_id": XLSX_ID,
            "content_base64": base64.b64encode(XLSX_BYTES).decode("ascii"),
            "filename": "q3-pipeline.xlsx",
            "entities": [],
            "valid_from": "2026-07-09T10:11:12.000Z",
            "visibility": [101, 202],
            "acl_provenance": "mirrored",
        },
    ]


def test_poll_side_effect_accumulates_then_delivers_person_and_org():
    """End-to-end through poll(): the document pass fills the fact accumulators
    as a side-effect; a subject at a foreign domain yields bob (corp.example) as
    a person and corp.example as an org (foreign to the subject)."""
    connector = GDriveConnector(
        FixtureTransport(),
        GDriveConfig(delegated_subject="ops@ourco.com", tenant_id=TENANT),
    )
    asyncio.run(connector.poll("387"))
    sink = DryRunFactSink(stream=io.StringIO())
    deliver_facts(connector, StaticRegistry({"user:ops@ourco.com": 501}), sink)
    person_emails = {e["after"]["email"] for e in _person_envelopes(sink.envelopes)}
    org_domains = {e["after"]["domain"] for e in _org_envelopes(sink.envelopes)}
    # alice (owner) + bob (writer) appear; the group/domain/anyone do not.
    assert "alice@corp.example" in person_emails
    assert "bob@corp.example" in person_emails
    assert "eng-leads@corp.example" not in person_emails
    assert "corp.example" in org_domains  # foreign to ops@ourco.com
