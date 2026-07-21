"""Conformance tests for the Salesforce connector (SPEC.md §5, §5e.2).

Fixtures under ``fixtures/salesforce/`` are recorded from Salesforce's
documented shapes:

- token endpoint response — documented: the client_credentials response
  carries no ``expires_in`` and no refresh token (help.salesforce.com,
  remoteaccess_oauth_client_credentials_flow);
- query/queryMore pages — documented: ``totalSize``/``done``/
  ``nextRecordsUrl``/``records`` with an ``attributes`` envelope per record
  (developer.salesforce.com REST API resources_query);
- AccountShare rows — documented fields ``AccountId``, ``UserOrGroupId``,
  ``AccountAccessLevel``, ``RowCause`` (object reference); the 005/00G
  UserOrGroupId key prefixes are documented ID prefixes.

No live API calls; HTTP is exercised through ``httpx.MockTransport``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.connectors.salesforce import (
    VIEW_ALL_GROUP,
    SalesforceConnector,
    SalesforceFactEvent,
    _read_cursor,
    _soql_datetime,
    _write_cursor,
    role_principal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "salesforce"
POLICY = [7, 12]
TOKEN_PATH = "/services/oauth2/token"
QUERY_PATH = "/services/data/v62.0/query"
NEXT_RECORDS_PATH = "/services/data/v62.0/query/01gRO0000016PIAYA2-2000"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ---------- mock Salesforce: token endpoint + query/queryMore ----------


def make_mock_salesforce(
    log: list[dict],
    *,
    reject_first_query: bool = False,
    shares_fail: bool = False,
    roster_fail: bool = False,
    roster_500: bool = False,
    view_all_assignees: list[dict] | None = None,
    view_all_fail: bool = False,
) -> httpx.MockTransport:
    """Routes the token endpoint and SOQL queries to fixtures. Tokens mint as
    ``sf-token-1``, ``sf-token-2``, ... With ``reject_first_query`` the very
    first data request gets a documented 401 INVALID_SESSION_ID body to
    exercise the shared 401-retry-once hook. With ``roster_fail`` the
    User/GroupMember roster queries 403 (degraded-ACL path); with
    ``roster_500`` the User query returns a non-403 500 (non-403 degrade path)."""
    state = {"mints": 0, "data_requests": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            state["mints"] += 1
            payload = dict(fixture("token.json"))
            payload["access_token"] = f"sf-token-{state['mints']}"
            log.append({"path": TOKEN_PATH, "body": request.content.decode()})
            return httpx.Response(200, json=payload)

        state["data_requests"] += 1
        soql = request.url.params.get("q", "")
        log.append(
            {
                "path": request.url.path,
                "auth": request.headers.get("Authorization"),
                "q": soql,
            }
        )
        if reject_first_query and state["data_requests"] == 1:
            return httpx.Response(
                401,
                json=[{"message": "Session expired or invalid", "errorCode": "INVALID_SESSION_ID"}],
            )
        if request.url.path == NEXT_RECORDS_PATH:
            return httpx.Response(200, json=fixture("query_accounts_page2.json"))
        assert request.url.path == QUERY_PATH
        # Roster queries — matched most-specific first (GroupMember before
        # User / Account so substrings don't collide). No FROM Group query is
        # issued: the group token derives from the id alone.
        if "FROM PermissionSetAssignment" in soql:
            if view_all_fail:
                return httpx.Response(403, json=[{"errorCode": "INSUFFICIENT_ACCESS"}])
            return httpx.Response(200, json={"records": view_all_assignees or []})
        if "FROM UserRole" in soql:
            # No role hierarchy by default → role-hierarchy reconstruction
            # short-circuits after this one query (existing tests unaffected).
            return httpx.Response(200, json={"records": []})
        if "FROM GroupMember" in soql:
            if roster_fail:
                return httpx.Response(403, json=[{"errorCode": "INSUFFICIENT_ACCESS"}])
            return httpx.Response(200, json=fixture("query_groupmembers.json"))
        if "FROM User " in soql:
            if roster_fail:
                return httpx.Response(403, json=[{"errorCode": "INSUFFICIENT_ACCESS"}])
            if roster_500:
                return httpx.Response(500, json=[{"errorCode": "UNKNOWN_EXCEPTION"}])
            return httpx.Response(200, json=fixture("query_users.json"))
        if "FROM AccountShare" in soql:
            if shares_fail:
                return httpx.Response(500, json=[{"errorCode": "UNKNOWN_EXCEPTION"}])
            return httpx.Response(200, json=fixture("query_accountshare.json"))
        if "FROM OpportunityShare" in soql:
            # No Opportunity sharing in the base fixtures → opps ride the floor.
            return httpx.Response(200, json={"records": []})
        if "FROM Account" in soql:
            return httpx.Response(200, json=fixture("query_accounts_page1.json"))
        if "FROM Contact" in soql:
            return httpx.Response(200, json=fixture("query_contacts.json"))
        if "FROM Opportunity" in soql:
            return httpx.Response(200, json=fixture("query_opportunities.json"))
        raise AssertionError(f"unexpected SOQL: {soql}")

    return httpx.MockTransport(handler)


def make_connector(log: list[dict], **kwargs) -> SalesforceConnector:
    transport = make_mock_salesforce(log, **kwargs)
    return SalesforceConnector(
        POLICY,
        my_domain="acme",
        client_id="consumer-key",
        client_secret="consumer-secret",
        client=httpx.AsyncClient(base_url="https://acme.my.salesforce.com", transport=transport),
        token_client=httpx.AsyncClient(transport=transport),
    )


def run_poll(connector: SalesforceConnector, cursor: str | None):
    async def run():
        try:
            return await connector.poll(cursor)
        finally:
            await connector.aclose()

    return asyncio.run(run())


# ---------- field-mapping conformance: query page → FactEvents ----------


def test_account_query_page_maps_exactly() -> None:
    page = fixture("query_accounts_page1.json")
    events = SalesforceConnector.events_from_query_page("Account", page, POLICY)

    raw_1, raw_2 = page["records"]
    expected = [
        # Acme Corp: fields sorted by name; Id / LastModifiedDate / attributes
        # are metadata, never facts.
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb1AAG",
            field_name="AnnualRevenue",
            value=25000000.0,
            valid_from=utc(2026, 7, 8, 18, 4, 57),
            raw_payload=raw_1,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb1AAG",
            field_name="Industry",
            value="Technology",
            valid_from=utc(2026, 7, 8, 18, 4, 57),
            raw_payload=raw_1,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb1AAG",
            field_name="Name",
            value="Acme Corp",
            valid_from=utc(2026, 7, 8, 18, 4, 57),
            raw_payload=raw_1,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb1AAG",
            field_name="Website",
            value="https://acme.test",
            valid_from=utc(2026, 7, 8, 18, 4, 57),
            raw_payload=raw_1,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
        # Globex: null Industry and AnnualRevenue are skipped.
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb2AAG",
            field_name="Name",
            value="Globex",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_2,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
        SalesforceFactEvent(
            source="salesforce",
            entity_id="001xx000003DGb2AAG",
            field_name="Website",
            value="https://globex.test",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_2,
            object_type="Account",
            visibility_policy=[7, 12],
        ),
    ]
    assert events == expected


def test_contact_and_opportunity_pages_map_exactly() -> None:
    contacts = SalesforceConnector.events_from_query_page(
        "Contact", fixture("query_contacts.json"), POLICY
    )
    # Title is null → skipped; sorted by field name.
    assert [(e.entity_id, e.field_name, e.value, e.valid_from) for e in contacts] == [
        ("003xx000004TmiQAAS", "AccountId", "001xx000003DGb1AAG", utc(2026, 7, 9, 3, 0, 0)),
        ("003xx000004TmiQAAS", "Email", "ada@acme.test", utc(2026, 7, 9, 3, 0, 0)),
        ("003xx000004TmiQAAS", "FirstName", "Ada", utc(2026, 7, 9, 3, 0, 0)),
        ("003xx000004TmiQAAS", "LastName", "Lovelace", utc(2026, 7, 9, 3, 0, 0)),
    ]
    assert all(e.object_type == "Contact" for e in contacts)

    opportunities = SalesforceConnector.events_from_query_page(
        "Opportunity", fixture("query_opportunities.json"), POLICY
    )
    modified = utc(2026, 7, 9, 3, 15, 22)
    assert [(e.field_name, e.value, e.valid_from) for e in opportunities] == [
        ("AccountId", "001xx000003DGb1AAG", modified),
        ("Amount", 84000.0, modified),
        ("CloseDate", "2026-09-30", modified),
        ("Name", "Acme expansion", modified),
        ("StageName", "Negotiation", modified),
    ]
    assert all(e.source == "salesforce" for e in opportunities)
    assert all(e.visibility_policy == POLICY for e in opportunities)
    assert all(e.share_principals == [] for e in contacts + opportunities)


# ---------- ACL honesty: AccountShare rows → additive principal metadata ----------


def test_principal_for_share_classifies_raw_ids() -> None:
    # principal_for_share is now a RAW-ID classifier, not a token minter: the
    # raw-id ``user:005…``/``group:00G…`` strings it used to return were the
    # identity gap. Token crosswalk happens in resolve_share_principals.
    assert (
        SalesforceConnector.principal_for_share({"UserOrGroupId": "005xx000001X8UzAAK"})
        == "005xx000001X8UzAAK"
    )
    assert (
        SalesforceConnector.principal_for_share({"UserOrGroupId": "00Gxx0000000001EAA"})
        == "00Gxx0000000001EAA"
    )
    # Unknown prefixes contribute nothing (skipping cannot widen visibility).
    assert SalesforceConnector.principal_for_share({"UserOrGroupId": "0DLxx00000001AAA"}) is None
    assert SalesforceConnector.principal_for_share({}) is None


def test_resolve_share_principals_crosswalk() -> None:
    from verity_ingest.connectors.salesforce import SalesforceUserInfo

    # M2 2b — the 005 resolves via FederationIdentifier (the SSO subject), NOT
    # User.Email. resolve_share_principals returns (groups, owner_subjects); the
    # SINK sends owner_subjects through the `emails` gate to the canonical token.
    roster = {
        "005xx000001X8UzAAK": SalesforceUserInfo(
            email="ae.divergent@acme.sf",  # divergent login — NEVER a join key
            federation_identifier="ae@acme.test",
            is_active=True,
        )
    }
    # (a) User → its FederationIdentifier subject; Group → stable salesforce group.
    assert SalesforceConnector.resolve_share_principals(
        ["005xx000001X8UzAAK", "00Gxx0000000001EAA"], roster
    ) == (["group:salesforce-group-00Gxx0000000001EAA"], ["ae@acme.test"])
    # The divergent User.Email is NEVER emitted as a resolution value.
    _, subjects = SalesforceConnector.resolve_share_principals(["005xx000001X8UzAAK"], roster)
    assert subjects == ["ae@acme.test"]
    assert "ae.divergent@acme.sf" not in (subjects or [])
    # unresolvable 005 (not in roster / no federation id / inactive) → dropped
    assert SalesforceConnector.resolve_share_principals(["005xx000009ZZZAAK"], roster) == (
        None,
        None,
    )
    assert SalesforceConnector.resolve_share_principals(["005xx000001X8UzAAK"], {}) == (None, None)
    # a 005 present but with no FederationIdentifier is dropped (no User.Email fallback)
    no_fed = {
        "005xx000001X8UzAAK": SalesforceUserInfo(email="x@acme.sf", federation_identifier=None)
    }
    assert SalesforceConnector.resolve_share_principals(["005xx000001X8UzAAK"], no_fed) == (
        None,
        None,
    )
    # an inactive 005 (IsActive=false) is dropped even with a federation id
    inactive = {
        "005xx000001X8UzAAK": SalesforceUserInfo(
            email="x@acme.sf", federation_identifier="x@acme.test", is_active=False
        )
    }
    assert SalesforceConnector.resolve_share_principals(["005xx000001X8UzAAK"], inactive) == (
        None,
        None,
    )
    # all-dropped / empty → (None, None) so the record rides the admin floor
    assert SalesforceConnector.resolve_share_principals([], roster) == (None, None)
    # a group id alone still resolves (no roster dependency)
    assert SalesforceConnector.resolve_share_principals(["00Gxx0000000001EAA"], {}) == (
        ["group:salesforce-group-00Gxx0000000001EAA"],
        None,
    )


# ---------- sink conformance: FactEvent → exact Debezium envelope ----------


def test_debezium_envelope_source_connector_salesforce() -> None:
    page = fixture("query_accounts_page1.json")
    name = SalesforceConnector.events_from_query_page("Account", page, POLICY)[2]
    assert name.field_name == "Name"
    assert VerityDebeziumSink.envelope(name) == {
        "op": "u",
        "source": {"connector": "salesforce", "table": "Account", "ts_ms": 1783533897000},
        "after": {"id": "001xx000003DGb1AAG", "Name": "Acme Corp"},
    }


# ---------- truth lane: poll() against the mock ----------


def test_poll_paginates_attaches_shares_and_advances_cursor() -> None:
    log: list[dict] = []
    events, next_cursor = run_poll(make_connector(log), "2026-07-08T00:00:00.000+0000")

    # 6 account facts (pages 1+2 minus nulls: 4+2) + 3 (Initech, page 2)
    # + 4 contact + 5 opportunity = 18
    assert len(events) == 18
    # cursor = max LastModifiedDate seen, exactly as the API returned it
    assert next_cursor == "2026-07-09T03:15:22.000+0000"

    # one token mint, then Account (query + queryMore), Contact, Opportunity,
    # AccountShare, then the roster (User + GroupMember, BFS) — all with the
    # cached Bearer token.
    paths = [entry["path"] for entry in log]
    assert paths[:6] == [
        TOKEN_PATH,
        QUERY_PATH,
        NEXT_RECORDS_PATH,
        QUERY_PATH,
        QUERY_PATH,
        QUERY_PATH,
    ]
    assert paths.count(TOKEN_PATH) == 1
    assert "grant_type=client_credentials" in log[0]["body"]
    data_requests = log[1:]
    assert all(entry["auth"] == "Bearer sf-token-1" for entry in data_requests)

    # SOQL shape: cursor truncated to whole seconds, unquoted dateTime literal,
    # ascending order for resumability
    assert data_requests[0]["q"] == (
        "SELECT Id, Name, Industry, Website, AnnualRevenue, LastModifiedDate FROM Account "
        "WHERE LastModifiedDate > 2026-07-08T00:00:00Z ORDER BY LastModifiedDate ASC"
    )
    share_soql = next(q for entry in data_requests if "FROM AccountShare" in (q := entry["q"]))
    assert share_soql.startswith(
        "SELECT AccountId, UserOrGroupId, RowCause FROM AccountShare"
    )
    for account_id in ("001xx000003DGb1AAG", "001xx000003DGb2AAG", "001xx000003DGb3AAG"):
        assert f"'{account_id}'" in share_soql

    # roster queries fired for the collected share ids
    queries = [entry["q"] for entry in data_requests]
    user_soql = next(q for q in queries if "FROM User " in q)
    # M2 2b — the roster SELECT carries the FederationIdentifier join key (+ keeps
    # Email/Username/IsActive). Email is NEVER the crosswalk key.
    assert user_soql == (
        "SELECT Id, Email, Username, FederationIdentifier, IsActive FROM User "
        "WHERE Id IN ('005xx000001X8UzAAK')"
    )
    assert any("FROM GroupMember" in q and "'00Gxx0000000001EAA'" in q for q in queries)

    # RAW share ids collected as additive metadata on Account events only
    by_account = {
        e.entity_id: e.share_principals
        for e in events
        if isinstance(e, SalesforceFactEvent) and e.object_type == "Account"
    }
    assert by_account == {
        "001xx000003DGb1AAG": ["005xx000001X8UzAAK", "00Gxx0000000001EAA"],
        "001xx000003DGb2AAG": ["005xx000001X8UzAAK"],
        "001xx000003DGb3AAG": [],  # no AccountShare rows recorded for Initech
    }
    assert all(
        e.share_principals == []
        for e in events
        if isinstance(e, SalesforceFactEvent) and e.object_type != "Account"
    )

    # M2 2b — share ids crosswalked: a 005 owner becomes its FederationIdentifier
    # SSO subject in record_owner_emails (the sink resolves it via the `emails`
    # gate — NEVER User.Email); a 00G becomes an already-canonical group string in
    # record_principals. Non-Account events untouched.
    by_account_groups = {
        e.entity_id: e.record_principals
        for e in events
        if isinstance(e, SalesforceFactEvent) and e.object_type == "Account"
    }
    by_account_owners = {
        e.entity_id: e.record_owner_emails
        for e in events
        if isinstance(e, SalesforceFactEvent) and e.object_type == "Account"
    }
    assert by_account_groups == {
        "001xx000003DGb1AAG": ["group:salesforce-group-00Gxx0000000001EAA"],
        "001xx000003DGb2AAG": None,  # user-only share → no group
        "001xx000003DGb3AAG": None,  # no shares → admin --visibility floor
    }
    assert by_account_owners == {
        "001xx000003DGb1AAG": ["ae@acme.test"],  # the federation subject, not the email
        "001xx000003DGb2AAG": ["ae@acme.test"],
        "001xx000003DGb3AAG": None,
    }
    # The divergent User.Email is NEVER used as an owner value.
    assert all(
        "ae.divergent@acme.sf" not in (e.record_owner_emails or [])
        for e in events
        if isinstance(e, SalesforceFactEvent)
    )
    # Contact (Controlled by Parent) INHERITS its parent Account's resolved
    # principals: the fixture contact hangs off DGb1AAG (group + owner resolved).
    contacts = [
        e for e in events if isinstance(e, SalesforceFactEvent) and e.object_type == "Contact"
    ]
    assert contacts and all(
        e.record_principals == ["group:salesforce-group-00Gxx0000000001EAA"]
        and e.record_owner_emails == ["ae@acme.test"]
        for e in contacts
    )
    # Opportunity has no OpportunityShare in the fixture → still rides the floor
    # (it does NOT inherit from its Account — Opportunities have their own shares).
    assert all(
        e.record_principals is None and e.record_owner_emails is None
        for e in events
        if isinstance(e, SalesforceFactEvent) and e.object_type == "Opportunity"
    )


def test_poll_401_mints_fresh_token_and_retries_once() -> None:
    log: list[dict] = []
    events, next_cursor = run_poll(
        make_connector(log, reject_first_query=True), "2026-07-08T00:00:00.000+0000"
    )

    assert len(events) == 18
    assert next_cursor == "2026-07-09T03:15:22.000+0000"
    # mint, 401 on the first Account query, re-mint, retried Account query
    paths = [entry["path"] for entry in log]
    assert paths[:4] == [TOKEN_PATH, QUERY_PATH, TOKEN_PATH, QUERY_PATH]
    assert paths.count(TOKEN_PATH) == 2
    assert log[1]["auth"] == "Bearer sf-token-1"
    assert log[3]["auth"] == "Bearer sf-token-2"
    assert log[1]["q"] == log[3]["q"]  # identical query retried
    # everything after the refresh reuses the cached second token
    assert all(entry["auth"] == "Bearer sf-token-2" for entry in log[3:])


def test_share_fetch_failure_never_gates_facts() -> None:
    log: list[dict] = []
    events, next_cursor = run_poll(
        make_connector(log, shares_fail=True), "2026-07-08T00:00:00.000+0000"
    )
    assert len(events) == 18  # facts proceed
    assert next_cursor == "2026-07-09T03:15:22.000+0000"
    assert all(e.share_principals == [] for e in events if isinstance(e, SalesforceFactEvent))


def test_fetch_account_shares_false_skips_share_query() -> None:
    log: list[dict] = []
    transport = make_mock_salesforce(log)
    connector = SalesforceConnector(
        POLICY,
        my_domain="acme",
        client_id="consumer-key",
        client_secret="consumer-secret",
        client=httpx.AsyncClient(base_url="https://acme.my.salesforce.com", transport=transport),
        token_client=httpx.AsyncClient(transport=transport),
        fetch_account_shares=False,
    )
    events, _ = run_poll(connector, "2026-07-08T00:00:00.000+0000")
    assert len(events) == 18
    assert not any("FROM AccountShare" in entry.get("q", "") for entry in log)


# ---------- group-edge mirroring: GroupMember → SpiceDB (nested, cycle-safe) ----------


def test_poll_builds_nested_cycle_safe_group_edges() -> None:
    log: list[dict] = []
    connector = make_connector(log)
    run_poll(connector, "2026-07-08T00:00:00.000+0000")

    # Direct edges only (SpiceDB closes transitivity). Nesting preserved: a
    # 00G member becomes a group:salesforce-group-<child> edge. The mutual
    # reference (1⊃2, 2⊃1) terminates via the visited-set (no hang). M2 2b — a
    # 005 group member is emitted as its `fed:<FederationIdentifier>` marker; the
    # sink canonicalizes it through the registry `emails` gate before mirroring.
    assert connector.group_edges == {
        "group:salesforce-group-00Gxx0000000001EAA": {
            "fed:ae@acme.test",
            "group:salesforce-group-00Gxx0000000002EAA",
        },
        "group:salesforce-group-00Gxx0000000002EAA": {
            "group:salesforce-group-00Gxx0000000001EAA",
        },
    }


def test_poll_mirrors_org_wide_view_all_as_a_group_on_every_record() -> None:
    # SPEC §14.3 completeness: a user with profile/permission-set View All Data
    # reads EVERY record regardless of sharing — not an AccountShare row, so the
    # connector over-hid them (measured live). Now mirrored as VIEW_ALL_GROUP whose
    # members are the view-all users' fed subjects, stamped on every record.
    log: list[dict] = []
    connector = make_connector(
        log,
        view_all_assignees=[
            {"AssigneeId": "005xx000001X8UzAAK"},  # active, fed Ae@Acme.test
            {"AssigneeId": "005xx000001X9IntAAK"},  # inactive + no fed → dropped
        ],
    )
    events, _ = run_poll(connector, "2026-07-08T00:00:00.000+0000")
    # the group carries only the active, fed-bearing subject (lowercased)
    assert connector.group_edges[VIEW_ALL_GROUP] == {"fed:ae@acme.test"}
    # every emitted Salesforce record (Account, Contact, Opportunity) carries it
    sf_events = [e for e in events if isinstance(e, SalesforceFactEvent)]
    assert sf_events
    assert all(VIEW_ALL_GROUP in (e.record_principals or []) for e in sf_events)


def test_view_all_query_403_over_hides_never_leaks() -> None:
    # A 403 (integration user lacks read on PermissionSetAssignment) degrades to
    # NO view-all stamp: view-all users stay over-hidden (safe), never a leak, and
    # the base sync never crashes.
    log: list[dict] = []
    connector = make_connector(
        log, view_all_fail=True, view_all_assignees=[{"AssigneeId": "005xx000001X8UzAAK"}]
    )
    events, _ = run_poll(connector, "2026-07-08T00:00:00.000+0000")
    assert VIEW_ALL_GROUP not in connector.group_edges
    assert all(
        VIEW_ALL_GROUP not in (e.record_principals or [])
        for e in events
        if isinstance(e, SalesforceFactEvent)
    )


def test_mirror_view_all_false_skips_query_and_stamp() -> None:
    log: list[dict] = []
    transport = make_mock_salesforce(
        log, view_all_assignees=[{"AssigneeId": "005xx000001X8UzAAK"}]
    )
    connector = SalesforceConnector(
        POLICY,
        my_domain="acme",
        client_id="consumer-key",
        client_secret="consumer-secret",
        client=httpx.AsyncClient(base_url="https://acme.my.salesforce.com", transport=transport),
        token_client=httpx.AsyncClient(transport=transport),
        mirror_view_all=False,
    )
    events, _ = run_poll(connector, "2026-07-08T00:00:00.000+0000")
    assert VIEW_ALL_GROUP not in connector.group_edges
    assert not any("FROM PermissionSetAssignment" in e.get("q", "") for e in log)
    assert all(
        VIEW_ALL_GROUP not in (e.record_principals or [])
        for e in events
        if isinstance(e, SalesforceFactEvent)
    )


def _connector_with(handler) -> SalesforceConnector:
    def wrapped(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(TOKEN_PATH):
            return httpx.Response(200, json={"access_token": "t", "token_type": "Bearer"})
        return handler(request)

    transport = httpx.MockTransport(wrapped)
    return SalesforceConnector(
        POLICY,
        my_domain="acme",
        client_id="k",
        client_secret="s",
        client=httpx.AsyncClient(base_url="https://acme.my.salesforce.com", transport=transport),
        token_client=httpx.AsyncClient(transport=transport),
    )


async def _fetch_hierarchy(conn: SalesforceConnector, account_ids, object_type="Account"):
    try:
        return await conn._fetch_role_hierarchy(object_type, account_ids)
    finally:
        await conn.aclose()


def test_role_hierarchy_reconstructs_ancestor_role_groups() -> None:
    # A1 owned by a rep in REPROLE, under MGRROLE, under VPROLE. Role-hierarchy
    # access is IMPLICIT in Salesforce (no AccountShare row), so the connector
    # reconstructs it: A1 is stamped with the role group of EACH ancestor
    # (manager, VP), whose members resolve through it. An inactive ancestor
    # member confers nothing (fail closed).
    def handler(request: httpx.Request) -> httpx.Response:
        soql = request.url.params.get("q", "")
        if "FROM UserRole" in soql:
            return httpx.Response(
                200,
                json={
                    "records": [
                        {"Id": "REPROLE", "ParentRoleId": "MGRROLE"},
                        {"Id": "MGRROLE", "ParentRoleId": "VPROLE"},
                        {"Id": "VPROLE", "ParentRoleId": None},
                    ]
                },
            )
        if "OwnerId FROM Account" in soql:
            return httpx.Response(200, json={"records": [{"Id": "A1", "OwnerId": "005REP"}]})
        if "FROM User" in soql and "WHERE UserRoleId IN" in soql:  # ancestor members
            return httpx.Response(
                200,
                json={
                    "records": [
                        {"Id": "005MGR", "FederationIdentifier": "Mgr@Acme.test",
                         "IsActive": True, "UserRoleId": "MGRROLE"},
                        {"Id": "005VP", "FederationIdentifier": "Vp@Acme.test",
                         "IsActive": True, "UserRoleId": "VPROLE"},
                        {"Id": "005OFF", "FederationIdentifier": "off@acme.test",
                         "IsActive": False, "UserRoleId": "MGRROLE"},  # inactive → dropped
                    ]
                },
            )
        if "FROM User" in soql and "WHERE Id IN" in soql:  # owner's role
            return httpx.Response(200, json={"records": [{"Id": "005REP", "UserRoleId": "REPROLE"}]})
        raise AssertionError(f"unexpected SOQL: {soql}")

    per_account, edges = asyncio.run(_fetch_hierarchy(_connector_with(handler), ["A1"]))
    # both ancestors stamped (manager first, then VP — ancestor order up the tree)
    assert per_account == {"A1": [role_principal("MGRROLE"), role_principal("VPROLE")]}
    assert edges == {
        role_principal("MGRROLE"): {"fed:mgr@acme.test"},  # inactive member excluded
        role_principal("VPROLE"): {"fed:vp@acme.test"},
    }


def test_role_hierarchy_no_roles_short_circuits() -> None:
    # An org with no role hierarchy → the single UserRole query returns empty and
    # nothing else is fetched (no owner/role/member queries).
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        soql = request.url.params.get("q", "")
        seen.append(soql)
        if "FROM UserRole" in soql:
            return httpx.Response(200, json={"records": []})
        raise AssertionError(f"should not query beyond UserRole: {soql}")

    per_account, edges = asyncio.run(_fetch_hierarchy(_connector_with(handler), ["A1"]))
    assert per_account == {} and edges == {}
    assert sum("FROM UserRole" in s for s in seen) == 1
    assert not any("OwnerId FROM Account" in s for s in seen)


def test_role_hierarchy_403_over_hides_never_leaks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        soql = request.url.params.get("q", "")
        if "FROM UserRole" in soql:
            return httpx.Response(403, json=[{"errorCode": "INSUFFICIENT_ACCESS"}])
        raise AssertionError(f"unexpected SOQL: {soql}")

    per_account, edges = asyncio.run(_fetch_hierarchy(_connector_with(handler), ["A1"]))
    assert per_account == {} and edges == {}


def test_poll_resolves_opportunity_shares() -> None:
    # An Opportunity resolves its OWN OpportunityShare (owner) through the roster —
    # the same crosswalk as Account, a different share object.
    def handler(request: httpx.Request) -> httpx.Response:
        soql = request.url.params.get("q", "")
        if "FROM AccountShare" in soql:
            return httpx.Response(200, json={"records": []})
        if "FROM OpportunityShare" in soql:
            return httpx.Response(
                200,
                json={"records": [
                    {"OpportunityId": "006OPP", "UserOrGroupId": "005OWN", "RowCause": "Owner"}
                ]},
            )
        if "FROM UserRole" in soql:
            return httpx.Response(200, json={"records": []})
        if "FROM PermissionSetAssignment" in soql:
            return httpx.Response(200, json={"records": []})
        if "FROM GroupMember" in soql:
            return httpx.Response(200, json={"records": []})
        if "FROM User" in soql:
            return httpx.Response(
                200,
                json={"records": [
                    {"Id": "005OWN", "Email": "o@x.test", "Username": "o",
                     "FederationIdentifier": "Owner@Fed", "IsActive": True}
                ]},
            )
        if "FROM Contact" in soql:
            return httpx.Response(200, json={"records": []})
        if "FROM Opportunity" in soql:  # main object query (Share already matched)
            return httpx.Response(
                200,
                json={"records": [
                    {"Id": "006OPP", "Name": "Big", "StageName": "Won", "Amount": 1,
                     "CloseDate": "2026-01-01", "AccountId": "001A",
                     "LastModifiedDate": "2026-07-08T00:00:00.000+0000"}
                ]},
            )
        if "FROM Account" in soql:  # main object query
            return httpx.Response(200, json={"records": []})
        raise AssertionError(f"unexpected SOQL: {soql}")

    events, _ = run_poll(_connector_with(handler), None)
    opps = [e for e in events if isinstance(e, SalesforceFactEvent) and e.object_type == "Opportunity"]
    assert opps
    # resolved on FederationIdentifier (lowercased), NOT User.Email
    assert all(e.record_owner_emails == ["owner@fed"] for e in opps)
    assert all(e.record_principals is None for e in opps)  # owner-only share → no group


def test_group_only_member_user_is_fetched_and_edged() -> None:
    # A user (005) that is ONLY a GroupMember — never a direct AccountShare
    # principal — must still be queried for its FederationIdentifier and edged
    # into the group. This is the common case for group shares; the User query
    # covers the UNION of share-derived AND group-member 005 ids.
    GROUP = "00Gxx0000000009EAA"
    MEMBER = "005xx000009MEMBER1"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            payload = dict(fixture("token.json"))
            payload["access_token"] = "sf-token-1"
            return httpx.Response(200, json=payload)
        soql = request.url.params.get("q", "")
        if "FROM GroupMember" in soql:
            return httpx.Response(
                200,
                json={
                    "totalSize": 1,
                    "done": True,
                    "records": [{"GroupId": GROUP, "UserOrGroupId": MEMBER}],
                },
            )
        if "FROM User " in soql:
            # The member 005 must be IN this query even though no AccountShare
            # named it (we pass NO share-derived user_ids below).
            assert f"'{MEMBER}'" in soql
            return httpx.Response(
                200,
                json={
                    "totalSize": 1,
                    "done": True,
                    "records": [
                        {
                            "Id": MEMBER,
                            "Email": "member1.divergent@acme.sf",
                            "FederationIdentifier": "member1@acme.test",
                            "IsActive": True,
                        }
                    ],
                },
            )
        raise AssertionError(f"unexpected SOQL: {soql}")

    connector = SalesforceConnector(
        POLICY,
        my_domain="acme",
        client_id="k",
        client_secret="s",
        client=httpx.AsyncClient(
            base_url="https://acme.my.salesforce.com", transport=httpx.MockTransport(handler)
        ),
        token_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    async def run():
        try:
            # NO share-derived user_ids — the member 005 is discovered purely via
            # the group. It must land as its `fed:<FederationIdentifier>` marker.
            return await connector._fetch_roster([], [GROUP])
        finally:
            await connector.aclose()

    _users, group_edges = asyncio.run(run())
    assert group_edges == {"group:salesforce-group-00Gxx0000000009EAA": {"fed:member1@acme.test"}}


def test_sync_group_edges_posts_sorted_and_nest_capable() -> None:
    posts: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append(json.loads(request.content))
        return httpx.Response(200, json={})

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    edges = {
        "group:salesforce-group-00Gxx0000000001EAA": {
            "group:salesforce-group-00Gxx0000000002EAA",
            "user:ae@acme.test",
        },
    }
    assert sink.sync_group_edges(edges) == 2
    # deterministic: groups sorted, members sorted within each; a member that is
    # itself a group flows through unchanged (endpoint is nest-capable).
    assert [(p["group"], p["member"]) for p in posts] == [
        ("group:salesforce-group-00Gxx0000000001EAA", "group:salesforce-group-00Gxx0000000002EAA"),
        ("group:salesforce-group-00Gxx0000000001EAA", "user:ae@acme.test"),
    ]
    # empty map → no-op
    assert sink.sync_group_edges({}) == 0
    # back-compat alias unchanged for HubSpot
    assert VerityDebeziumSink.sync_team_edges is VerityDebeziumSink.sync_group_edges


# ---------- degraded ACL: 403 on the roster → admin fallback + signal ----------


def test_roster_403_degrades_to_admin_fallback(capsys: pytest.CaptureFixture[str]) -> None:
    log: list[dict] = []
    events, _ = run_poll(make_connector(log, roster_fail=True), "2026-07-08T00:00:00.000+0000")

    # facts proceed; every record falls back to the admin --visibility floor
    assert len(events) == 18
    assert all(
        e.record_principals is None for e in events if isinstance(e, SalesforceFactEvent)
    )
    stderr = capsys.readouterr().err
    assert "salesforce: User/Group roster query returned 403" in stderr


def test_roster_degraded_flag_set_on_403() -> None:
    log: list[dict] = []
    connector = make_connector(log, roster_fail=True)
    run_poll(connector, "2026-07-08T00:00:00.000+0000")
    assert connector.roster_degraded is True
    assert connector.group_edges == {}


# ---------- envelope: resolved verity_acl UNIONed over the admin floor ----------


def test_envelope_emits_approximated_verity_acl_when_resolved() -> None:
    page = fixture("query_accounts_page1.json")
    event = SalesforceConnector.events_from_query_page("Account", page, POLICY)[2]
    event.record_visibility = [41, 55]  # sink-resolved tokens
    assert VerityDebeziumSink.envelope(event)["verity_acl"] == {
        "visibility": [41, 55],
        "confidentiality": "internal",
        "acl_provenance": "approximated",
    }
    # a share-less event carries NO inline block → rides the ?visibility= floor
    bare = SalesforceConnector.events_from_query_page("Account", page, POLICY)[3]
    assert "verity_acl" not in VerityDebeziumSink.envelope(bare)
    assert VerityDebeziumSink._bound_visibility([bare]) == "7,12"


def test_stamp_unions_admin_floor_into_resolved_visibility() -> None:
    # The write path REPLACES the bound admin policy with any inline verity_acl
    # (ingest.rs or_else). AccountShare is a SUBSET of effective visibility, so
    # the sink must UNION the admin --visibility floor (POLICY = [7, 12]) into
    # the resolved record_visibility, floor first, so the inline block is a
    # SUPERSET of the floor — the record can never LOSE its admin floor.
    #
    # M2 2b — the owner is resolved via its FederationIdentifier through the
    # `emails` gate (→ canonical user:ae@acme.test / token 41); the group is
    # resolved as an already-canonical principal (token 55). The server keys
    # `mappings` by canonical, so the FederationIdentifier request echoes the
    # canonical string back.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/principals":
            body = json.loads(request.content)
            mappings: dict[str, int] = {}
            # FederationIdentifier ae@acme.test → canonical user:ae@acme.test (41)
            if "ae@acme.test" in body.get("emails", []):
                mappings["user:ae@acme.test"] = 41
            for p in body.get("principals", []):
                if p == "group:salesforce-group-00Gxx0000000001EAA":
                    mappings[p] = 55
            return httpx.Response(200, json={"mappings": mappings, "quarantined": False})
        raise AssertionError(request.url.path)

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    event = SalesforceFactEvent(
        source="salesforce",
        entity_id="001xx000003DGb1AAG",
        field_name="Name",
        value="Acme Corp",
        valid_from=utc(2026, 7, 8, 18, 4, 57),
        raw_payload={},
        object_type="Account",
        visibility_policy=POLICY,
        record_principals=["group:salesforce-group-00Gxx0000000001EAA"],
        record_owner_emails=["ae@acme.test"],  # the FederationIdentifier, NOT User.Email
    )
    sink._stamp_record_visibility([event])
    # floor [7, 12] UNIONed in, floor first, deduped; owner (41) + group (55)
    assert event.record_visibility == [7, 12, 55, 41]
    assert VerityDebeziumSink.envelope(event)["verity_acl"]["visibility"] == [7, 12, 55, 41]


def test_federation_absent_confers_no_visibility_never_email_fallback() -> None:
    # M2 2b — a 005 whose FederationIdentifier does not match any declared SSO
    # alias resolves to NOTHING at the sink (the `emails` gate returns no
    # mapping). The record has no inline ACL and rides the admin floor; the
    # divergent User.Email is NEVER used as a fallback join key.
    from verity_ingest.connectors.salesforce import SalesforceUserInfo

    roster = {
        "005xx000001X8UzAAK": SalesforceUserInfo(
            email="ae.divergent@acme.sf", federation_identifier="unmatched@acme.test"
        )
    }
    groups, owner_emails = SalesforceConnector.resolve_share_principals(
        ["005xx000001X8UzAAK"], roster
    )
    assert groups is None and owner_emails == ["unmatched@acme.test"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/principals":
            body = json.loads(request.content)
            # No declared alias for unmatched@acme.test → nothing resolves.
            assert "ae.divergent@acme.sf" not in body.get("emails", [])
            return httpx.Response(200, json={"mappings": {}, "quarantined": True})
        raise AssertionError(request.url.path)

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    event = SalesforceFactEvent(
        source="salesforce",
        entity_id="A",
        field_name="Name",
        value="Acme",
        valid_from=utc(2026, 7, 8, 18, 4, 57),
        raw_payload={},
        object_type="Account",
        visibility_policy=POLICY,
        record_owner_emails=list(owner_emails or []),
    )
    sink._stamp_record_visibility([event])
    assert event.record_visibility is None  # no inline ACL → admin floor
    assert "verity_acl" not in VerityDebeziumSink.envelope(event)


def test_roster_non_403_error_degrades_and_signals(capsys: pytest.CaptureFixture[str]) -> None:
    # A non-403 roster HTTP error (User query 500) means GroupMember edges were
    # never mirrored this cycle; the connector must degrade like the 403 path
    # (drop all record_principals to the admin floor + set roster_degraded) so
    # the runner emits DEGRADED_ACL_SIGNAL — never stamp on a partial roster.
    log: list[dict] = []
    connector = make_connector(log, roster_500=True)
    events, _ = run_poll(connector, "2026-07-08T00:00:00.000+0000")
    assert connector.roster_degraded is True
    assert connector.group_edges == {}
    assert all(
        e.record_principals is None for e in events if isinstance(e, SalesforceFactEvent)
    )


def test_no_group_query_is_issued() -> None:
    # The group token derives from the id alone; Group.Type is never needed, so
    # no FROM Group query is issued (only GroupMember + User).
    log: list[dict] = []
    run_poll(make_connector(log), "2026-07-08T00:00:00.000+0000")
    assert not any("FROM Group " in entry.get("q", "") for entry in log)
    assert any("FROM GroupMember" in entry.get("q", "") for entry in log)


def test_poll_from_none_has_no_where_and_full_crawl_matches() -> None:
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            return [e async for e in connector.full_crawl()]
        finally:
            await connector.aclose()

    crawl_events = asyncio.run(run())
    assert len(crawl_events) == 18
    account_soql = next(entry["q"] for entry in log if "FROM Account " in entry.get("q", ""))
    assert "WHERE" not in account_soql
    assert account_soql.endswith("ORDER BY LastModifiedDate ASC")


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
        SalesforceConnector(my_domain="acme")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        SalesforceConnector.events_from_query_page(  # type: ignore[call-arg]
            "Account", {"records": []}
        )


def test_credentials_come_from_env_and_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SF_MY_DOMAIN", "SF_CLIENT_ID", "SF_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        SalesforceConnector(POLICY)
    message = str(excinfo.value)
    for var in ("SF_MY_DOMAIN", "SF_CLIENT_ID", "SF_CLIENT_SECRET"):
        assert var in message
    assert "Connected App" in message  # BYOT hint: create it in YOUR OWN org

    monkeypatch.setenv("SF_MY_DOMAIN", "acme")
    monkeypatch.setenv("SF_CLIENT_ID", "consumer-key")
    with pytest.raises(RuntimeError, match="SF_CLIENT_SECRET"):
        SalesforceConnector(POLICY)


def test_env_configured_connector_builds_token_url_from_my_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SF_MY_DOMAIN", "acme")
    monkeypatch.setenv("SF_CLIENT_ID", "consumer-key")
    monkeypatch.setenv("SF_CLIENT_SECRET", "consumer-secret")
    connector = SalesforceConnector(POLICY)
    assert connector.credential.token_url == "https://acme.my.salesforce.com/services/oauth2/token"
    assert str(connector._client.base_url) == "https://acme.my.salesforce.com"
    asyncio.run(connector.aclose())


# ---------- cursor plumbing ----------


def test_soql_datetime_truncates_to_whole_seconds() -> None:
    assert _soql_datetime("2026-07-09T03:00:00.500+0000") == "2026-07-09T03:00:00Z"
    assert _soql_datetime("2026-07-09T03:00:00.000Z") == "2026-07-09T03:00:00Z"


def test_cursor_state_file_roundtrip(tmp_path: Path) -> None:
    state_file = tmp_path / "state" / "salesforce_cursor"
    assert _read_cursor(state_file) is None  # missing file → poll from epoch
    _write_cursor(state_file, "2026-07-09T03:15:22.000+0000")
    assert _read_cursor(state_file) == "2026-07-09T03:15:22.000+0000"
