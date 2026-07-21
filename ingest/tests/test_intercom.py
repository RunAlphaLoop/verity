"""Conformance tests for the Intercom connector (SPEC.md §5, §5e.2).

Fixtures under ``fixtures/intercom/`` are recorded from Intercom's documented
shapes:

- ``/admins`` — documented ``admins[]`` with ``id``, ``email``, ``team_ids``;
  an email-less operator/bot seat is included to prove the drop path.
- ``/teams`` — documented ``teams[]`` with ``id``, ``name``, ``admin_ids`` (the
  group→member edges).
- ``POST /conversations/search`` — documented Search API: ``conversations[]``
  with ``updated_at`` (Unix epoch), ``admin_assignee_id``, ``team_assignee_id``,
  and ``pages.next.starting_after`` cursor pagination.
- ``POST /contacts/search`` / ``POST /companies/list`` — workspace-wide records
  with no per-record audience (admin-floor path).
- ``GET /articles`` — a mix of ``state:"published"`` (world-readable) and
  ``draft`` / an unknown state (teammate-only floor; never public).

No live API calls; HTTP is exercised through ``httpx.MockTransport``. There are
no live Intercom tokens in this environment (fixtures-only, like Salesforce); a
live smoke is GATED on the user supplying INTERCOM_ACCESS_TOKEN and never faked.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.connectors.intercom import (
    DEGRADED_ACL_SIGNAL,
    IntercomConnector,
    IntercomFactEvent,
    _read_credential_file,
    _read_cursor,
    _write_cursor,
    group_principal,
    user_principal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "intercom"
POLICY = [7, 12]
TOKEN = "intercom-token"
ADMINS_PATH = "/admins"
TEAMS_PATH = "/teams"
CONVERSATIONS_SEARCH_PATH = "/conversations/search"
CONTACTS_SEARCH_PATH = "/contacts/search"
COMPANIES_LIST_PATH = "/companies/list"
ARTICLES_PATH = "/articles"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ---------- mock Intercom: roster + search/list/articles ----------


def make_mock_intercom(
    log: list[dict],
    *,
    auth_fail: bool = False,
    admins_403: bool = False,
    teams_500: bool = False,
) -> httpx.MockTransport:
    """Routes ``/admins``, ``/teams``, the conversation/contact search, the
    company list, and ``/articles`` to fixtures, logging path + auth + version +
    body. ``auth_fail`` returns a 401 on the conversation search (rotate-the-
    token path); ``admins_403`` 403s the ``/admins`` roster (degraded-ACL path);
    ``teams_500`` returns a non-403 500 on ``/teams`` (non-403 degrade path)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        log.append(
            {
                "path": path,
                "auth": request.headers.get("Authorization"),
                "version": request.headers.get("Intercom-Version"),
                "params": dict(request.url.params),
                "body": json.loads(request.content) if request.content else None,
            }
        )
        if path == ADMINS_PATH:
            if admins_403:
                return httpx.Response(403, json={"errors": [{"code": "forbidden"}]})
            return httpx.Response(200, json=fixture("admins.json"))
        if path == TEAMS_PATH:
            if teams_500:
                return httpx.Response(500, json={"errors": [{"code": "server_error"}]})
            return httpx.Response(200, json=fixture("teams.json"))
        if path == CONVERSATIONS_SEARCH_PATH:
            if auth_fail:
                return httpx.Response(401, json={"errors": [{"code": "unauthorized"}]})
            body = json.loads(request.content)
            after = (body.get("pagination") or {}).get("starting_after")
            if after == "conv-cursor-page-2":
                return httpx.Response(200, json=fixture("conversations_search_page2.json"))
            return httpx.Response(200, json=fixture("conversations_search_page1.json"))
        if path == CONTACTS_SEARCH_PATH:
            return httpx.Response(200, json=fixture("contacts_search.json"))
        if path == COMPANIES_LIST_PATH:
            return httpx.Response(200, json=fixture("companies_list.json"))
        if path == ARTICLES_PATH:
            return httpx.Response(200, json=fixture("articles_list.json"))
        raise AssertionError(f"unexpected path {path}")

    return httpx.MockTransport(handler)


def make_connector(log: list[dict], **kwargs) -> IntercomConnector:
    connector_kwargs = {}
    for key in ("public_maps_to", "fetch_articles", "fetch_companies"):
        if key in kwargs:
            connector_kwargs[key] = kwargs.pop(key)
    transport = make_mock_intercom(log, **kwargs)
    return IntercomConnector(
        POLICY,
        token=TOKEN,
        client=httpx.AsyncClient(
            base_url="https://api.intercom.test",
            transport=transport,
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Accept": "application/json",
                "Intercom-Version": "2.11",
            },
        ),
        **connector_kwargs,
    )


def run_poll(connector: IntercomConnector, cursor: str | None):
    async def run():
        try:
            return await connector.poll(cursor)
        finally:
            await connector.aclose()

    return asyncio.run(run())


# ---------- BYOT + ACL-honesty doctrine guards ----------


def test_visibility_policy_is_required() -> None:
    with pytest.raises(TypeError):
        IntercomConnector(token=TOKEN)  # type: ignore[call-arg]


def test_credential_comes_from_env_and_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTERCOM_ACCESS_TOKEN", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        IntercomConnector(POLICY)
    message = str(excinfo.value)
    assert "INTERCOM_ACCESS_TOKEN" in message
    assert "BYOT" in message  # hint: create it in YOUR OWN workspace

    monkeypatch.setenv("INTERCOM_ACCESS_TOKEN", "env-token")
    connector = IntercomConnector(POLICY)
    assert connector._client.headers["Authorization"] == "Bearer env-token"
    assert connector._client.headers["Intercom-Version"] == "2.11"
    asyncio.run(connector.aclose())


# ---------- --credential-file (server spawn channel; token is the file body) ----------


def _write_cred(tmp_path: Path, token: str, mode: int = 0o600) -> Path:
    p = tmp_path / "bearer.token"
    p.write_text(token)
    p.chmod(mode)
    return p


def test_credential_file_reads_body_and_strips_trailing_newline(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "intercom-tok-from-file\n")
    assert _read_credential_file(p) == "intercom-tok-from-file"


def test_credential_file_rejects_non_0600_mode(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "intercom-tok-secret\n", mode=0o644)
    with pytest.raises(PermissionError, match="0600"):
        _read_credential_file(p)


def test_credential_file_rejects_empty(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "\n")
    with pytest.raises(ValueError, match="empty"):
        _read_credential_file(p)


def test_credential_file_token_wins_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file body is PREFERRED over INTERCOM_ACCESS_TOKEN — a server spawn
    # never needs the token in the child environment.
    monkeypatch.setenv("INTERCOM_ACCESS_TOKEN", "intercom-tok-from-env")
    p = _write_cred(tmp_path, "intercom-tok-from-file\n")
    connector = IntercomConnector(POLICY, token=_read_credential_file(p))
    assert connector._client.headers["Authorization"] == "Bearer intercom-tok-from-file"
    asyncio.run(connector.aclose())


def test_no_secret_in_logs() -> None:
    # The token flows ONLY into the Authorization header; it must never appear in
    # a request body or query string the connector constructs.
    log: list[dict] = []
    run_poll(make_connector(log), "0")
    for entry in log:
        assert entry["auth"] == f"Bearer {TOKEN}"
        assert TOKEN not in json.dumps(entry.get("body"))
        assert TOKEN not in json.dumps(entry.get("params"))


# ---------- field-mapping conformance: page → FactEvents ----------


def test_conversation_page_maps_exactly() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    # roster must be populated for principal resolution
    asyncio.run(connector._fetch_roster())
    page = fixture("conversations_search_page1.json")
    events, quarantined = connector.events_from_page("conversation", page["conversations"])
    asyncio.run(connector.aclose())

    assert quarantined == 0
    raw_1, raw_2 = page["conversations"]
    # conv 101: fields sorted; id/created_at/updated_at/assignee ids are metadata.
    # assigned to admin 814860 (user:ada@acme.test) + team 491.
    assert [(e.entity_id, e.field_name, e.value, e.valid_from) for e in events] == [
        ("101", "priority", "priority", utc(2026, 7, 8, 8, 56, 40)),
        ("101", "state", "open", utc(2026, 7, 8, 8, 56, 40)),
        ("101", "title", "Login issue", utc(2026, 7, 8, 8, 56, 40)),
        ("102", "priority", "not_priority", utc(2026, 7, 8, 9, 13, 20)),
        ("102", "state", "open", utc(2026, 7, 8, 9, 13, 20)),
        ("102", "title", "Billing question", utc(2026, 7, 8, 9, 13, 20)),
    ]
    assert all(e.source == "intercom" and e.object_type == "conversation" for e in events)
    assert all(e.visibility_policy == POLICY for e in events)
    # conv 101: admin + team assignee → both principals; conv 102: team only.
    conv_101 = [e for e in events if e.entity_id == "101"]
    assert all(
        e.record_principals == ["user:ada@acme.test", "group:intercom-team-491"]
        for e in conv_101
    )
    conv_102 = [e for e in events if e.entity_id == "102"]
    assert all(e.record_principals == ["group:intercom-team-492"] for e in conv_102)


def test_unassigned_conversation_rides_admin_floor() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    page = fixture("conversations_search_page2.json")
    events, _ = connector.events_from_page("conversation", page["conversations"])
    asyncio.run(connector.aclose())
    # conv 103: admin_assignee_id 0 + team_assignee_id null → no audience → floor
    assert events, "expected mapped fields for the unassigned conversation"
    assert all(e.entity_id == "103" for e in events)
    assert all(e.record_principals is None for e in events)


def test_contacts_and_companies_ride_admin_floor() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    contacts, _ = connector.events_from_page("contact", fixture("contacts_search.json")["data"])
    companies, _ = connector.events_from_page("company", fixture("companies_list.json")["data"])
    asyncio.run(connector.aclose())
    # workspace-wide; the API exposes no per-record audience → None (admin floor)
    assert contacts and all(e.record_principals is None for e in contacts)
    assert companies and all(e.record_principals is None for e in companies)
    assert all(e.object_type == "contact" for e in contacts)
    assert all(e.object_type == "company" for e in companies)


# ---------- ACL honesty: published article public class vs teammate-only ----------


def test_published_article_maps_to_public_when_configured() -> None:
    log: list[dict] = []
    connector = make_connector(log, public_maps_to="org:everyone")
    asyncio.run(connector._fetch_roster())
    articles = fixture("articles_list.json")["data"]
    events, _ = connector.events_from_page("article", articles)
    asyncio.run(connector.aclose())

    by_id: dict[str, list[str] | None] = {}
    for e in events:
        by_id[e.entity_id] = e.record_principals
    # published → the operator-declared public principal; draft + unknown → floor
    assert by_id["9001"] == ["org:everyone"]
    assert by_id["9002"] is None  # draft → teammate-only floor
    assert by_id["9003"] is None  # unknown "archived" state → floor, NEVER public


def test_published_article_rides_floor_when_public_unset() -> None:
    # With no --public-maps-to a published article has no proven mappable
    # audience → admin floor (fail closed; never a minted public token).
    log: list[dict] = []
    connector = make_connector(log)  # public_maps_to defaults to None
    asyncio.run(connector._fetch_roster())
    articles = fixture("articles_list.json")["data"]
    events, _ = connector.events_from_page("article", articles)
    asyncio.run(connector.aclose())
    assert events and all(e.record_principals is None for e in events)


# ---------- crosswalk: admins/teams → principals + edges ----------


def test_roster_crosswalk_and_team_edges() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    asyncio.run(connector.aclose())
    # admin → user:<email.lower()> (ADA@acme.test lowercased); email-less bot dropped
    assert connector.admins_by_id == {
        "814860": "user:ada@acme.test",
        "814861": "user:grace@acme.test",
    }
    assert "814862" not in connector.admins_by_id  # email-less operator dropped
    # team edges from admin_ids; the email-less admin (814862) contributes no edge
    assert connector.group_edges == {
        "group:intercom-team-491": {"user:ada@acme.test", "user:grace@acme.test"},
        "group:intercom-team-492": {"user:grace@acme.test"},
    }
    assert connector.roster_degraded is False


def test_unmappable_team_assignee_drops_to_floor() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    # a conversation assigned to a team the roster does not know → team dropped;
    # with no admin assignee either, the record rides the admin floor.
    record = {
        "type": "conversation",
        "id": "999",
        "title": "Orphan",
        "admin_assignee_id": 0,
        "team_assignee_id": 777,  # not in /teams
        "updated_at": 1783510000,
    }
    events, _ = connector.events_from_page("conversation", [record])
    asyncio.run(connector.aclose())
    assert events and all(e.record_principals is None for e in events)


# ---------- sink conformance: FactEvent → exact Debezium envelope ----------


def test_debezium_envelope_source_connector_intercom() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    page = fixture("conversations_search_page1.json")
    events, _ = connector.events_from_page("conversation", page["conversations"])
    asyncio.run(connector.aclose())
    title = next(e for e in events if e.entity_id == "101" and e.field_name == "title")
    assert VerityDebeziumSink.envelope(title) == {
        "op": "u",
        "source": {"connector": "intercom", "table": "conversation", "ts_ms": 1783501000 * 1000},
        "after": {"id": "101", "title": "Login issue"},
    }


def test_envelope_no_inline_acl_for_floor_records() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    page = fixture("conversations_search_page2.json")
    events, _ = connector.events_from_page("conversation", page["conversations"])
    asyncio.run(connector.aclose())
    # unassigned conv 103 rides the floor → no inline verity_acl; bound = "7,12"
    bare = events[0]
    assert bare.record_principals is None
    assert "verity_acl" not in VerityDebeziumSink.envelope(bare)
    assert VerityDebeziumSink._bound_visibility([bare]) == "7,12"


def test_stamp_unions_admin_floor_into_resolved_visibility() -> None:
    # A conversation's assignment is a SUBSET of effective visibility, so the sink
    # UNIONs the admin --visibility floor (POLICY) into the resolved tokens, floor
    # first, so the inline (REPLACE-semantics) block is a SUPERSET of the floor.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/principals":
            body = json.loads(request.content)
            table = {"user:ada@acme.test": 41, "group:intercom-team-491": 55}
            return httpx.Response(
                200, json={"mappings": {p: table[p] for p in body["principals"] if p in table}}
            )
        raise AssertionError(request.url.path)

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    event = IntercomFactEvent(
        source="intercom",
        entity_id="101",
        field_name="title",
        value="Login issue",
        valid_from=utc(2026, 7, 8, 8, 56, 40),
        raw_payload={},
        object_type="conversation",
        visibility_policy=POLICY,
        record_principals=["user:ada@acme.test", "group:intercom-team-491"],
    )
    sink._stamp_record_visibility([event])
    assert event.record_visibility == [7, 12, 41, 55]  # floor unioned in, floor first
    acl = VerityDebeziumSink.envelope(event)["verity_acl"]
    assert acl == {
        "visibility": [7, 12, 41, 55],
        "confidentiality": "internal",
        "acl_provenance": "approximated",
    }


# ---------- truth lane: poll() against the mock ----------


def test_poll_paginates_and_advances_cursor() -> None:
    log: list[dict] = []
    events, next_cursor = run_poll(make_connector(log, public_maps_to="org:everyone"), "0")

    # conversations: conv101 (3) + conv102 (3) + conv103 (3) = 9
    # contact carol (name,email,phone,role = 4) + company blue sun (5) +
    # articles 9001/9002/9003 (title,description,state = 3 each = 9) = 27
    convs = [e for e in events if e.object_type == "conversation"]
    assert len(convs) == 9
    assert {e.entity_id for e in convs} == {"101", "102", "103"}

    # cursor = max updated_at (epoch) across ALL object types, as a string.
    # company 1783505000 < article 9001 1783506000 → 1783506000.
    assert next_cursor == "1783506000"

    # roster fetched first (admins then teams), then the search/list lanes.
    paths = [entry["path"] for entry in log]
    assert paths[0] == ADMINS_PATH
    assert paths[1] == TEAMS_PATH
    assert CONVERSATIONS_SEARCH_PATH in paths
    assert paths.count(CONVERSATIONS_SEARCH_PATH) == 2  # two pages

    # search body carries the incremental updated_at filter + ascending sort
    conv_bodies = [e["body"] for e in log if e["path"] == CONVERSATIONS_SEARCH_PATH]
    assert conv_bodies[0]["query"] == {"field": "updated_at", "operator": ">", "value": 0}
    assert conv_bodies[0]["sort"] == {"field": "updated_at", "order": "ascending"}
    # page-2 request carried the starting_after cursor from page 1
    assert conv_bodies[1]["pagination"]["starting_after"] == "conv-cursor-page-2"

    # published article public class present exactly once (9001)
    pub = [e for e in events if e.object_type == "article" and e.record_principals == ["org:everyone"]]
    assert {e.entity_id for e in pub} == {"9001"}


def test_poll_incremental_cursor_gates_records() -> None:
    # From a cursor past conv101/102 but before conv103 & the article, only the
    # newer records survive. The conversation search sends the cursor to the API
    # (server-side filter); companies/articles are gated client-side.
    log: list[dict] = []
    events, next_cursor = run_poll(make_connector(log), "1783505300")
    conv_bodies = [e["body"] for e in log if e["path"] == CONVERSATIONS_SEARCH_PATH]
    assert conv_bodies[0]["query"]["value"] == 1783505300
    # company 1783505000 <= cursor → gated out; articles 9001 (1783506000) and
    # 9002 (1783505500) survive; 9003 (1783505200) <= cursor → gated out.
    assert not any(e.object_type == "company" for e in events)
    articles = [e for e in events if e.object_type == "article"]
    assert {e.entity_id for e in articles} == {"9001", "9002"}
    assert next_cursor == "1783506000"


def test_articles_descending_early_stop() -> None:
    # /articles is DESCENDING by updated_at; a cursor between 9002 and 9001 must
    # early-stop after 9001 (never emit the older 9002/9003).
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            return await connector._fetch_articles(1783505800)
        finally:
            await connector.aclose()

    fresh = asyncio.run(run())
    assert [a["id"] for a in fresh] == ["9001"]


def test_poll_from_none_has_no_gate_and_full_crawl_matches() -> None:
    log: list[dict] = []
    connector = make_connector(log, public_maps_to="org:everyone")

    async def run():
        try:
            return [e async for e in connector.full_crawl()]
        finally:
            await connector.aclose()

    crawl_events = asyncio.run(run())
    conv_bodies = [e["body"] for e in log if e["path"] == CONVERSATIONS_SEARCH_PATH]
    assert conv_bodies[0]["query"]["value"] == 0  # from epoch, no gate
    # same full set a poll("0") yields
    events, _ = run_poll(make_connector([], public_maps_to="org:everyone"), "0")
    assert len(crawl_events) == len(events)


# ---------- fail-closed / degradation ----------


def test_admins_403_degrades_to_admin_floor(capsys: pytest.CaptureFixture[str]) -> None:
    log: list[dict] = []
    connector = make_connector(log, admins_403=True)
    events, _ = run_poll(connector, "0")
    # facts proceed; every ROSTER-DERIVED audience (conversations) falls back to
    # the admin --visibility floor — never stamp on an empty/partial roster.
    assert events
    convs = [e for e in events if e.object_type == "conversation"]
    assert convs and all(e.record_principals is None for e in convs)
    assert connector.roster_degraded is True
    assert connector.group_edges == {}
    stderr = capsys.readouterr().err
    assert "intercom: /admins or /teams roster fetch failed" in stderr


def test_public_article_class_survives_roster_degrade() -> None:
    # A published article's audience is OPERATOR-DECLARED (--public-maps-to), not
    # roster-derived, so it is honestly unaffected by an admins/teams degrade —
    # only assignment-derived (conversation) principals drop to the floor.
    log: list[dict] = []
    connector = make_connector(log, admins_403=True, public_maps_to="org:everyone")
    events, _ = run_poll(connector, "0")
    assert connector.roster_degraded is True
    pub = [e for e in events if e.object_type == "article" and e.entity_id == "9001"]
    assert pub and all(e.record_principals == ["org:everyone"] for e in pub)


def test_teams_non_403_error_degrades() -> None:
    # A non-403 roster error (teams 500) means the team edges were never
    # mirrored; degrade exactly like the 403 path (drop all record_principals to
    # the floor + set roster_degraded) so the runner emits DEGRADED_ACL_SIGNAL.
    log: list[dict] = []
    connector = make_connector(log, teams_500=True)
    events, _ = run_poll(connector, "0")
    assert connector.roster_degraded is True
    assert connector.group_edges == {}
    assert all(e.record_principals is None for e in events if isinstance(e, IntercomFactEvent))


def test_auth_fail_raises_never_permissive() -> None:
    # A 401 on the conversation search must fail closed (raise), never fall
    # through to a permissive/guessed audience.
    log: list[dict] = []
    with pytest.raises(httpx.HTTPStatusError):
        run_poll(make_connector(log, auth_fail=True), "0")


def test_record_without_id_is_quarantined() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    asyncio.run(connector._fetch_roster())
    records = [
        {"type": "conversation", "title": "no id here", "updated_at": 1783510000},
        {"type": "conversation", "id": "500", "title": "ok", "updated_at": 1783510000},
    ]
    events, quarantined = connector.events_from_page("conversation", records)
    asyncio.run(connector.aclose())
    assert quarantined == 1
    assert {e.entity_id for e in events} == {"500"}  # the id-less record dropped


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


def test_no_articles_and_no_companies_skip_lanes() -> None:
    log: list[dict] = []
    connector = make_connector(log, fetch_articles=False, fetch_companies=False)
    events, _ = run_poll(connector, "0")
    paths = [entry["path"] for entry in log]
    assert ARTICLES_PATH not in paths
    assert COMPANIES_LIST_PATH not in paths
    assert not any(e.object_type in ("article", "company") for e in events)


# ---------- principal helpers + cursor plumbing ----------


def test_principal_helpers() -> None:
    assert user_principal("ADA@Acme.Test") == "user:ada@acme.test"
    assert group_principal("491") == "group:intercom-team-491"


def test_degraded_acl_signal_is_the_shared_string() -> None:
    # The server greps a single connector-agnostic token across all connectors.
    assert DEGRADED_ACL_SIGNAL == "verity.backfill.degraded_acl"


def test_cursor_state_file_roundtrip(tmp_path: Path) -> None:
    state_file = tmp_path / "state" / "intercom_cursor"
    assert _read_cursor(state_file) is None  # missing file → poll from epoch
    _write_cursor(state_file, "1783506000")
    assert _read_cursor(state_file) == "1783506000"
