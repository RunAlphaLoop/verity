"""Conformance tests for the Notion connector (SPEC.md §5, §5e.2).

Fixtures under ``fixtures/notion/`` are recorded from Notion's documented
shapes:

- ``/v1/search`` list pages — documented: ``results``/``next_cursor``/
  ``has_more`` with ``page``/``database`` objects carrying ``last_edited_time``,
  ``parent``, ``created_by``/``last_edited_by`` and a ``properties`` map
  (developer.notion.com post-search / page object). The API returns NO sharing
  or permissions field on any object — the ACL-honesty point.
- ``/v1/users`` — documented ``person``/``bot`` shapes; ``person.email`` present
  for members, absent for guests/email-less persons; bots carry no email.
- ``/v1/blocks/{id}/children`` — documented block shapes with ``rich_text``.

No live API calls; HTTP is exercised through ``httpx.MockTransport``. There are
no live Notion tokens in this environment (fixtures-only, like Salesforce); a
live smoke is GATED on the user supplying NOTION_TOKEN and is never faked.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.connectors.notion import (
    NotionConnector,
    NotionFactEvent,
    _read_credential_file,
    _read_cursor,
    _write_cursor,
    group_principal,
    user_principal,
)
from verity_ingest.connector import DocumentEvent

FIXTURES = Path(__file__).parent / "fixtures" / "notion"
POLICY = [7, 12]
SEARCH_PATH = "/v1/search"
USERS_PATH = "/v1/users"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ---------- mock Notion: /v1/search + /v1/users + /v1/blocks ----------


def make_mock_notion(
    log: list[dict],
    *,
    auth_fail: bool = False,
    users_fail: bool = False,
) -> httpx.MockTransport:
    """Routes ``/v1/search`` (two pages), ``/v1/users``, and
    ``/v1/blocks/{id}/children`` to fixtures, logging path + auth + version.
    ``auth_fail`` returns a 401 on the search call (rotate-the-token path);
    ``users_fail`` returns a 403 on the roster (authorship degrade, NOT a
    DEGRADED_ACL_SIGNAL — the admin floor is unaffected)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        log.append(
            {
                "path": path,
                "auth": request.headers.get("Authorization"),
                "version": request.headers.get("Notion-Version"),
                "params": dict(request.url.params),
                "body": request.content.decode() if request.content else "",
            }
        )
        if path == SEARCH_PATH:
            if auth_fail:
                return httpx.Response(401, json={"object": "error", "code": "unauthorized"})
            body = json.loads(request.content) if request.content else {}
            if body.get("start_cursor") == "cursor-page-2":
                return httpx.Response(200, json=fixture("search_pages_page2.json"))
            return httpx.Response(200, json=fixture("search_pages_page1.json"))
        if path == USERS_PATH:
            if users_fail:
                return httpx.Response(403, json={"object": "error", "code": "restricted_resource"})
            return httpx.Response(200, json=fixture("users_list.json"))
        if path.startswith("/v1/blocks/"):
            return httpx.Response(200, json=fixture("blocks_children.json"))
        raise AssertionError(f"unexpected path {path}")

    return httpx.MockTransport(handler)


def make_connector(log: list[dict], **kwargs) -> NotionConnector:
    with_content = kwargs.pop("with_content", False)
    transport = make_mock_notion(log, **kwargs)
    return NotionConnector(
        POLICY,
        token="notion-tok",
        with_content=with_content,
        client=httpx.AsyncClient(
            base_url="https://api.notion.test",
            transport=transport,
            headers={
                "Authorization": "Bearer notion-tok",
                "Notion-Version": "2022-06-28",
            },
        ),
    )


def run_poll(connector: NotionConnector, cursor: str | None):
    async def run():
        try:
            return await connector.poll(cursor)
        finally:
            await connector.aclose()

    return asyncio.run(run())


# ---------- field-mapping conformance: search page → FactEvents ----------


def test_search_page1_maps_exactly() -> None:
    users = {"user-ada": "ada@acme.test"}
    events, quarantined = NotionConnector.events_from_search_page(
        fixture("search_pages_page1.json"), POLICY, users
    )
    assert quarantined == 0
    raw_page, raw_db = fixture("search_pages_page1.json")["results"]
    edited_page = utc(2026, 7, 8, 18, 4, 57)
    edited_db = utc(2026, 7, 9, 1, 12, 3)

    # Page 1111: Notes (empty rich_text) skipped; sorted Due, Name, Owners, Stage.
    # Database: title lives at top level (not a property); only Description maps.
    expected = [
        NotionFactEvent(
            source="notion",
            entity_id="11111111-1111-1111-1111-111111111111",
            field_name="Due",
            value="2026-09-30",
            valid_from=edited_page,
            raw_payload=raw_page,
            object_type="page",
            visibility_policy=[7, 12],
            authorship=["user:ada@acme.test"],
        ),
        NotionFactEvent(
            source="notion",
            entity_id="11111111-1111-1111-1111-111111111111",
            field_name="Name",
            value="Q3 Roadmap",
            valid_from=edited_page,
            raw_payload=raw_page,
            object_type="page",
            visibility_policy=[7, 12],
            authorship=["user:ada@acme.test"],
        ),
        NotionFactEvent(
            source="notion",
            entity_id="11111111-1111-1111-1111-111111111111",
            field_name="Owners",
            value="user-ada",
            valid_from=edited_page,
            raw_payload=raw_page,
            object_type="page",
            visibility_policy=[7, 12],
            authorship=["user:ada@acme.test"],
        ),
        NotionFactEvent(
            source="notion",
            entity_id="11111111-1111-1111-1111-111111111111",
            field_name="Stage",
            value="Negotiation",
            valid_from=edited_page,
            raw_payload=raw_page,
            object_type="page",
            visibility_policy=[7, 12],
            authorship=["user:ada@acme.test"],
        ),
        NotionFactEvent(
            source="notion",
            entity_id="db-projects-0001",
            field_name="Description",
            value="All active projects",
            valid_from=edited_db,
            raw_payload=raw_db,
            object_type="database",
            visibility_policy=[7, 12],
            authorship=["user:ada@acme.test"],
        ),
    ]
    assert events == expected
    # HONEST provenance: no per-record audience is ever derived.
    assert all(e.record_principals is None for e in events)
    assert all(e.source == "notion" and e.visibility_policy == POLICY for e in events)


def test_search_page2_maps_multiselect_number_checkbox() -> None:
    events, quarantined = NotionConnector.events_from_search_page(
        fixture("search_pages_page2.json"), POLICY, {"user-ada": "ada@acme.test"}
    )
    assert quarantined == 0
    modified = utc(2026, 7, 9, 3, 15, 22)
    assert [(e.field_name, e.value, e.valid_from) for e in events] == [
        ("Name", "Launch Plan", modified),
        ("Priority", 3, modified),
        ("Shipped", True, modified),
        ("Tags", "growth, urgent", modified),
    ]
    # created_by=user-bot (a bot → no email), last_edited_by=user-guest (not in
    # roster) → authorship empty (dropped; never a guessed principal).
    assert all(e.authorship == [] for e in events)


# ---------- authorship crosswalk: person ids → user:<email>, bots/guests dropped ----------


def test_authorship_renders_lowercased_email_and_drops_bot_and_guest() -> None:
    # Roster built from users_list.json: only user-ada resolves; user-noemail has
    # no email; user-bot is a bot. Authorship is INFORMATIONAL, never audience.
    log: list[dict] = []
    connector = make_connector(log)
    events, _ = run_poll(connector, None)
    facts = [e for e in events if isinstance(e, NotionFactEvent)]
    by_entity = {e.entity_id: e.authorship for e in facts}
    # Page 1111 authored+owned by user-ada → user:ada@acme.test (lowercased).
    assert by_entity["11111111-1111-1111-1111-111111111111"] == ["user:ada@acme.test"]
    # Database created by the bot, edited by ada → only ada resolves.
    assert by_entity["db-projects-0001"] == ["user:ada@acme.test"]
    # Page 2222 bot + guest only → authorship dropped entirely.
    assert by_entity["22222222-2222-2222-2222-222222222222"] == []
    assert user_principal("Ada@ACME.test") == "user:ada@acme.test"
    assert group_principal("ts-1") == "group:notion-teamspace-ts-1"


# ---------- sink conformance: FactEvent → exact Debezium envelope ----------


def test_debezium_envelope_source_connector_notion() -> None:
    events, _ = NotionConnector.events_from_search_page(
        fixture("search_pages_page1.json"), POLICY, {}
    )
    name = next(e for e in events if e.field_name == "Name")
    assert VerityDebeziumSink.envelope(name) == {
        "op": "u",
        "source": {"connector": "notion", "table": "page", "ts_ms": 1783533897000},
        "after": {"id": "11111111-1111-1111-1111-111111111111", "Name": "Q3 Roadmap"},
    }


def test_no_inline_acl_every_event_rides_admin_floor() -> None:
    # HONEST ACL: no record_principals ever → no inline verity_acl → every event
    # rides the connector-bound admin ?visibility= floor (never a guessed audience).
    events, _ = NotionConnector.events_from_search_page(
        fixture("search_pages_page1.json"), POLICY, {}
    )
    for e in events:
        assert e.record_principals is None
        assert "verity_acl" not in VerityDebeziumSink.envelope(e)
    assert VerityDebeziumSink._bound_visibility(list(events)) == "7,12"


# ---------- truth lane: poll() against the mock ----------


def test_poll_paginates_and_advances_cursor() -> None:
    log: list[dict] = []
    events, next_cursor = run_poll(make_connector(log), None)
    facts = [e for e in events if isinstance(e, NotionFactEvent)]

    # page1: 4 (page) + 1 (database) = 5; page2: 4 = 9 facts total.
    assert len(facts) == 9
    # cursor = max last_edited_time seen, exactly as the API returned it.
    assert next_cursor == "2026-07-09T03:15:22.000Z"

    paths = [entry["path"] for entry in log]
    # roster fetched once, then two search pages.
    assert paths == [USERS_PATH, SEARCH_PATH, SEARCH_PATH]
    assert all(entry["auth"] == "Bearer notion-tok" for entry in log)
    assert all(entry["version"] == "2022-06-28" for entry in log)
    # search sorts ascending by last_edited_time (resumable), pagination via
    # start_cursor on the second call.
    first_body = json.loads(log[1]["body"])
    assert first_body["sort"] == {"timestamp": "last_edited_time", "direction": "ascending"}
    assert "start_cursor" not in first_body
    assert json.loads(log[2]["body"])["start_cursor"] == "cursor-page-2"


def test_poll_client_side_gate_keeps_paging_no_data_loss() -> None:
    # A cursor between page1 record1 (18:04:57) and record2 (07-09 01:12:03):
    # record1 is ≤ cursor and individually skipped, but the ascending scan MUST
    # keep paging — the newest record (22222222 @ 03:15:22) lives on page2, which
    # is NEWER than the cursor and must NOT be dropped.
    log: list[dict] = []
    events, next_cursor = run_poll(make_connector(log), "2026-07-08T18:04:57.000Z")
    facts = [e for e in events if isinstance(e, NotionFactEvent)]
    entity_ids = {e.entity_id for e in facts}
    # record1 (11111111...) gated out; database (page1) + newest page2 record kept.
    assert "11111111-1111-1111-1111-111111111111" not in entity_ids
    assert "db-projects-0001" in entity_ids
    assert "22222222-2222-2222-2222-222222222222" in entity_ids
    # cursor advances to the newest record seen (page2), not stalled on page1.
    assert next_cursor == "2026-07-09T03:15:22.000Z"
    # page2 (start_cursor=cursor-page-2) WAS requested — no early-stop data loss.
    assert any(
        json.loads(e["body"]).get("start_cursor") == "cursor-page-2"
        for e in log
        if e["path"] == SEARCH_PATH
    )


def test_full_crawl_is_unfiltered_poll_from_epoch() -> None:
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            return [e async for e in connector.full_crawl()]
        finally:
            await connector.aclose()

    crawl = asyncio.run(run())
    facts = [e for e in crawl if isinstance(e, NotionFactEvent)]
    assert len(facts) == 9  # same as poll(None): no cursor gate


# ---------- fail-closed / quarantine ----------


def test_unparseable_records_are_quarantined_not_emitted() -> None:
    # A record with no id and a non-page/database object are both quarantined —
    # skipped and counted, NEVER emitted with a guessed ACL.
    events, quarantined = NotionConnector.events_from_search_page(
        fixture("search_unparseable.json"), POLICY, {}
    )
    assert events == []
    assert quarantined == 2


def test_poll_401_fails_closed_never_permissive() -> None:
    # A 401 on search (rotate-the-token) must raise, not silently emit facts with
    # a permissive/guessed ACL. Fail closed.
    log: list[dict] = []
    connector = make_connector(log, auth_fail=True)
    with pytest.raises(httpx.HTTPStatusError):
        run_poll(connector, None)


def test_users_403_degrades_authorship_only_not_the_facts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A 403 on /v1/users drops authorship metadata but NEVER gates or widens the
    # admin-floored facts — it is authorship-only, not a DEGRADED_ACL_SIGNAL.
    log: list[dict] = []
    connector = make_connector(log, users_fail=True)
    events, next_cursor = run_poll(connector, None)
    facts = [e for e in events if isinstance(e, NotionFactEvent)]
    assert len(facts) == 9  # facts proceed unaffected
    assert connector.users_degraded is True
    assert all(e.authorship == [] for e in facts)  # authorship dropped
    assert all(e.record_principals is None for e in facts)  # still admin floor
    stderr = capsys.readouterr().err
    assert "notion: /v1/users roster fetch failed" in stderr
    # NOT the degraded-ACL signal (the enforced admin policy is unaffected).
    assert "verity.backfill.degraded_acl" not in stderr


# ---------- --with-content: block body → DocumentEvent ----------


def test_with_content_emits_document_events() -> None:
    log: list[dict] = []
    connector = make_connector(log, with_content=True)
    events, _ = run_poll(connector, None)
    docs = [e for e in events if isinstance(e, DocumentEvent)]
    # one document per page object (2 pages across the two search pages).
    assert len(docs) == 2
    doc = next(d for d in docs if d.document_id == "11111111-1111-1111-1111-111111111111")
    assert doc.source == "notion"
    assert doc.content == b"Roadmap Overview\nShip the launch by Q3."
    # blocks carry no ACL; the doc rides the admin floor (resolvable envelope).
    assert doc.acl.resolvable is True
    assert doc.acl.principals == []
    assert any(e["path"].startswith("/v1/blocks/") for e in log)


# ---------- push lane is a documented no-op ----------


def test_push_events_is_documented_noop() -> None:
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            return [e async for e in connector.push_events()]
        finally:
            await connector.aclose()

    assert asyncio.run(run()) == []
    assert log == []  # no HTTP at all


# ---------- BYOT + ACL-honesty doctrine guards ----------


def test_visibility_policy_is_required() -> None:
    with pytest.raises(TypeError):
        NotionConnector(token="notion-tok")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        NotionConnector.events_from_search_page({"results": []})  # type: ignore[call-arg]


def test_credentials_come_from_env_and_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTION_TOKEN", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        NotionConnector(POLICY)
    assert "NOTION_TOKEN" in str(excinfo.value)


def test_env_token_flows_into_bearer_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTION_TOKEN", "secret-tok")
    connector = NotionConnector(POLICY)
    assert connector._client.headers["Authorization"] == "Bearer secret-tok"
    assert connector._client.headers["Notion-Version"] == "2022-06-28"
    asyncio.run(connector.aclose())


# ---------- --credential-file (server spawn channel; token is the file body) ----------


def _write_cred(tmp_path: Path, token: str, mode: int = 0o600) -> Path:
    p = tmp_path / "bearer.token"
    p.write_text(token)
    p.chmod(mode)
    return p


def test_credential_file_reads_body_and_strips_trailing_newline(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "notion-tok-from-file\n")
    assert _read_credential_file(p) == "notion-tok-from-file"


def test_credential_file_rejects_non_0600_mode(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "notion-tok-secret\n", mode=0o644)
    with pytest.raises(PermissionError, match="0600"):
        _read_credential_file(p)


def test_credential_file_rejects_empty(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "\n")
    with pytest.raises(ValueError, match="empty"):
        _read_credential_file(p)


def test_credential_file_token_wins_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file body is PREFERRED over NOTION_TOKEN — a server spawn never needs
    # the token in the child environment.
    monkeypatch.setenv("NOTION_TOKEN", "notion-tok-from-env")
    p = _write_cred(tmp_path, "notion-tok-from-file\n")
    connector = NotionConnector(POLICY, token=_read_credential_file(p))
    assert connector._client.headers["Authorization"] == "Bearer notion-tok-from-file"
    asyncio.run(connector.aclose())


# ---------- cursor plumbing ----------


def test_cursor_state_file_roundtrip(tmp_path: Path) -> None:
    state_file = tmp_path / "state" / "notion_cursor"
    assert _read_cursor(state_file) is None  # missing file → poll from epoch
    _write_cursor(state_file, "2026-07-09T03:15:22.000Z")
    assert _read_cursor(state_file) == "2026-07-09T03:15:22.000Z"
