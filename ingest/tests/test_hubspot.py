"""Conformance tests for the HubSpot connector (SPEC.md §5: field-mapping
conformance is load-bearing infrastructure — wrong mappings silently corrupt
L1).

Fixtures are recorded from HubSpot's documented shapes (CRM v3 search API
response pages, v3 webhook subscription payloads); no live API calls. HTTP is
exercised through ``httpx.MockTransport``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from verity_ingest.connectors.hubspot import (
    HubSpotConnector,
    HubSpotFactEvent,
    OwnerInfo,
    VerityDebeziumSink,
    owner_principal,
    team_principal,
)

FIXTURES = Path(__file__).parent / "fixtures"
POLICY = [7, 12]


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ---------- field-mapping conformance: search API → FactEvents ----------


def test_contacts_search_page_maps_exactly() -> None:
    page = fixture("hubspot_search_contacts_page1.json")
    events = HubSpotConnector.events_from_search_page("contacts", page, POLICY)

    raw_301, raw_302 = page["results"]
    expected = [
        # contact 301: null lifecyclestage skipped; hs_object_id and
        # lastmodifieddate are metadata, never facts. Sorted by field name.
        HubSpotFactEvent(
            source="hubspot",
            entity_id="301",
            field_name="createdate",
            value="2026-06-01T09:00:00.000Z",
            valid_from=utc(2026, 7, 8, 18, 4, 57, 406000),
            raw_payload=raw_301,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="301",
            field_name="email",
            value="ada@acme.test",
            valid_from=utc(2026, 7, 8, 18, 4, 57, 406000),
            raw_payload=raw_301,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="301",
            field_name="firstname",
            value="Ada",
            valid_from=utc(2026, 7, 8, 18, 4, 57, 406000),
            raw_payload=raw_301,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="301",
            field_name="lastname",
            value="Lovelace",
            valid_from=utc(2026, 7, 8, 18, 4, 57, 406000),
            raw_payload=raw_301,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="302",
            field_name="createdate",
            value="2026-06-15T10:30:00.000Z",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_302,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="302",
            field_name="email",
            value="grace@acme.test",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_302,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="302",
            field_name="firstname",
            value="Grace",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_302,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="302",
            field_name="lastname",
            value="Hopper",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_302,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="302",
            field_name="lifecyclestage",
            value="customer",
            valid_from=utc(2026, 7, 9, 1, 12, 3),
            raw_payload=raw_302,
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
    ]
    assert events == expected


def test_deals_search_page_maps_exactly() -> None:
    page = fixture("hubspot_search_deals.json")
    events = HubSpotConnector.events_from_search_page("deals", page, POLICY)
    modified = utc(2026, 7, 9, 2, 11, 0, 150000)  # hs_lastmodifieddate

    assert [(e.entity_id, e.field_name, e.value, e.valid_from) for e in events] == [
        ("9843211", "amount", "84000", modified),
        ("9843211", "closedate", "2026-09-30T00:00:00.000Z", modified),
        ("9843211", "createdate", "2026-04-02T11:00:00.000Z", modified),
        ("9843211", "dealname", "Acme expansion", modified),
        ("9843211", "dealstage", "negotiation", modified),
        ("9843211", "pipeline", "default", modified),
    ]
    assert all(e.source == "hubspot" for e in events)
    assert all(e.object_type == "deals" for e in events)
    assert all(e.visibility_policy == POLICY for e in events)


def test_companies_search_page_maps_exactly() -> None:
    page = fixture("hubspot_search_companies.json")
    events = HubSpotConnector.events_from_search_page("companies", page, POLICY)
    modified = utc(2026, 7, 8, 22, 45, 10)

    assert [(e.entity_id, e.field_name, e.value, e.valid_from) for e in events] == [
        ("5001", "createdate", "2026-05-20T14:00:00.000Z", modified),
        ("5001", "domain", "acme.test", modified),
        ("5001", "industry", "COMPUTER_SOFTWARE", modified),
        ("5001", "name", "Acme Corp", modified),
    ]


# ---------- push-lane conformance: v3 webhook payload → FactEvents ----------


def test_webhook_payload_maps_exactly() -> None:
    payload = fixture("hubspot_webhook_v3.json")
    events = HubSpotConnector.handle_webhook(payload, POLICY)

    # Third fixture event is contact.creation — not a propertyChange, skipped
    # (the truth lane reconciles creations).
    expected = [
        HubSpotFactEvent(
            source="hubspot",
            entity_id="301",
            field_name="lifecyclestage",
            value="customer",
            valid_from=utc(2026, 7, 9, 0, 0, 0, 123000),
            raw_payload=payload[0],
            object_type="contacts",
            visibility_policy=[7, 12],
        ),
        HubSpotFactEvent(
            source="hubspot",
            entity_id="9843211",
            field_name="amount",
            value="84000",
            valid_from=utc(2026, 7, 9, 0, 0, 5),
            raw_payload=payload[1],
            object_type="deals",
            visibility_policy=[7, 12],
        ),
    ]
    assert events == expected


# ---------- sink conformance: FactEvent → exact Debezium envelope ----------


def test_debezium_envelope_bodies_exact() -> None:
    payload = fixture("hubspot_webhook_v3.json")
    events = HubSpotConnector.handle_webhook(payload, POLICY)

    assert [VerityDebeziumSink.envelope(e) for e in events] == [
        {
            "op": "u",
            "source": {"connector": "hubspot", "table": "contacts", "ts_ms": 1783555200123},
            "after": {"id": "301", "lifecyclestage": "customer"},
        },
        {
            "op": "u",
            "source": {"connector": "hubspot", "table": "deals", "ts_ms": 1783555205000},
            "after": {"id": "9843211", "amount": "84000"},
        },
    ]


def test_debezium_envelope_from_search_event() -> None:
    page = fixture("hubspot_search_deals.json")
    amount = HubSpotConnector.events_from_search_page("deals", page, POLICY)[0]
    assert VerityDebeziumSink.envelope(amount) == {
        "op": "u",
        "source": {"connector": "hubspot", "table": "deals", "ts_ms": 1783563060150},
        "after": {"id": "9843211", "amount": "84000"},
    }


def test_sink_posts_batch_with_tenant_pk_and_bearer() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "url": str(request.url),
                "auth": request.headers.get("Authorization"),
                "body": json.loads(request.content),
            }
        )
        return httpx.Response(
            200, json={"written": 2, "superseded": 0, "retired": 0, "unchanged": 0}
        )

    sink = VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001",
        admin_token="secret-token",
        transport=httpx.MockTransport(handler),
    )
    events = HubSpotConnector.handle_webhook(fixture("hubspot_webhook_v3.json"), POLICY)
    summary = sink.post(events, cursor="2026-07-09T16:00:05.000Z")

    assert summary == {"written": 2, "superseded": 0, "retired": 0, "unchanged": 0}
    # First request: the delivery batch itself. The admin-assigned policy the
    # events carry (POLICY == [7, 12]) rides as the connector-bound visibility
    # on the query string — the server materializes every fact against it with
    # admin-assigned provenance (tier C has no per-record ACL to mirror).
    assert seen[0]["url"] == (
        "http://verity.local:7717/v1/ingest/debezium"
        "?tenant_id=0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001&pk=id&visibility=7%2C12"
    )
    assert seen[0]["auth"] == "Bearer secret-token"
    assert seen[0]["body"] == [VerityDebeziumSink.envelope(e) for e in events]
    # Second request: the best-effort heartbeat, after successful delivery.
    assert seen[1]["url"] == "http://verity.local:7717/v1/admin/connector-status"
    assert seen[1]["auth"] == "Bearer secret-token"
    assert seen[1]["body"] == {
        "tenant_id": "0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001",
        "source": "hubspot",
        "items_synced": 2,
        "last_event_at": max(e.valid_from for e in events).isoformat(),
        "cursor": "2026-07-09T16:00:05.000Z",
    }
    assert len(seen) == 2


def test_bound_visibility_is_the_events_policy_as_comma_string() -> None:
    # The admin-assigned policy the connector stamped on every event becomes the
    # connector-bound `?visibility=` the server materializes facts against. This
    # is the line that was silently missing: before it, HubSpot facts reached
    # the post-0026 server with NO ACL and were refused wholesale.
    events = HubSpotConnector.handle_webhook(fixture("hubspot_webhook_v3.json"), POLICY)
    assert VerityDebeziumSink._bound_visibility(events) == "7,12"


def test_bound_visibility_refuses_a_batch_that_mixes_policies() -> None:
    # The bound policy is per-POST; two events under different policies must not
    # be silently collapsed to one — that would apply one record's ACL to
    # another. Fail closed instead.
    a = HubSpotConnector.handle_webhook(fixture("hubspot_webhook_v3.json"), [7, 12])
    b = HubSpotConnector.handle_webhook(fixture("hubspot_webhook_v3.json"), [99])
    with pytest.raises(ValueError, match="mixes visibility policies"):
        VerityDebeziumSink._bound_visibility(a + b)


def test_bound_visibility_none_when_events_carry_no_policy() -> None:
    # A plain FactEvent (no visibility_policy attr) yields no bound policy — the
    # server then refuses it unless it declares an inline ACL. Never permissive.
    from verity_ingest.connector import FactEvent

    bare = FactEvent(
        source="hubspot",
        entity_id="1",
        field_name="email",
        value="x@y.z",
        valid_from=utc(2026, 7, 9),
        raw_payload={},
    )
    assert VerityDebeziumSink._bound_visibility([bare]) is None


def test_sink_heartbeat_failure_never_fails_the_sync() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/connector-status":
            return httpx.Response(500, text="heartbeat plane down")
        return httpx.Response(
            200, json={"written": 2, "superseded": 0, "retired": 0, "unchanged": 0}
        )

    sink = VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001",
        transport=httpx.MockTransport(handler),
    )
    events = HubSpotConnector.handle_webhook(fixture("hubspot_webhook_v3.json"), POLICY)
    # The 500 on the heartbeat is swallowed; the delivery summary survives.
    assert sink.post(events) == {"written": 2, "superseded": 0, "retired": 0, "unchanged": 0}


def test_sink_no_events_no_post() -> None:
    sink = VerityDebeziumSink(url="http://x", tenant_id="t")
    assert sink.post([]) == {"written": 0, "superseded": 0, "retired": 0, "unchanged": 0}


# ---------- truth lane: poll() against a mock HubSpot ----------


def make_mock_hubspot(
    requests_log: list[dict], owners: dict | None = None
) -> httpx.MockTransport:
    """Serves the fixture pages; contacts paginate; the first deals request
    is a 429 with Retry-After to exercise rate-limit handling. The Owners API
    (a GET, not logged with the search POSTs) returns ``owners`` — default an
    empty roster, so records stay unowned and ride the admin fallback."""
    state = {"deals_throttled": False}
    owners_body = owners if owners is not None else {"results": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/crm/v3/owners":
            return httpx.Response(200, json=owners_body)
        body = json.loads(request.content)
        requests_log.append(
            {"path": request.url.path, "auth": request.headers.get("Authorization"), "body": body}
        )
        if request.url.path == "/crm/v3/objects/contacts/search":
            if body.get("after") == "2":
                return httpx.Response(200, json=fixture("hubspot_search_contacts_page2.json"))
            return httpx.Response(200, json=fixture("hubspot_search_contacts_page1.json"))
        if request.url.path == "/crm/v3/objects/companies/search":
            return httpx.Response(200, json=fixture("hubspot_search_companies.json"))
        if request.url.path == "/crm/v3/objects/deals/search":
            if not state["deals_throttled"]:
                state["deals_throttled"] = True
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, json=fixture("hubspot_search_deals.json"))
        raise AssertionError(f"unexpected path {request.url.path}")

    return httpx.MockTransport(handler)


def make_connector(requests_log: list[dict]) -> HubSpotConnector:
    client = httpx.AsyncClient(
        base_url="https://api.hubapi.test",
        transport=make_mock_hubspot(requests_log),
        headers={"Authorization": "Bearer pat-na1-test"},
    )
    return HubSpotConnector(POLICY, token="pat-na1-test", client=client)


def test_poll_paginates_retries_and_advances_cursor() -> None:
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            return await connector.poll("2026-07-08T00:00:00+00:00")
        finally:
            await connector.aclose()

    events, next_cursor = asyncio.run(run())

    # 4 (contact 301) + 5 (302) + 5 (303, page 2) + 4 (company) + 6 (deal)
    assert len(events) == 24
    # cursor = max last-modified seen across all objects, as returned by the API
    assert next_cursor == "2026-07-09T03:00:00.500Z"

    # contacts paged twice, companies once, deals throttled once then served
    paths = [r["path"] for r in log]
    assert paths == [
        "/crm/v3/objects/contacts/search",
        "/crm/v3/objects/contacts/search",
        "/crm/v3/objects/companies/search",
        "/crm/v3/objects/deals/search",
        "/crm/v3/objects/deals/search",
    ]
    assert log[1]["body"]["after"] == "2"

    # incremental filter: last-modified property GT cursor, in epoch ms
    first = log[0]["body"]
    assert first["filterGroups"] == [
        {
            "filters": [
                {
                    "propertyName": "lastmodifieddate",
                    "operator": "GT",
                    "value": "1783468800000",  # 2026-07-08T00:00:00Z
                }
            ]
        }
    ]
    assert first["sorts"] == [{"propertyName": "lastmodifieddate", "direction": "ASCENDING"}]
    assert first["limit"] == 100
    deals_body = log[-1]["body"]
    assert deals_body["filterGroups"][0]["filters"][0]["propertyName"] == "hs_lastmodifieddate"
    assert all(r["auth"] == "Bearer pat-na1-test" for r in log)


def test_poll_from_none_has_no_filter_and_full_crawl_matches() -> None:
    log: list[dict] = []
    connector = make_connector(log)

    async def run():
        try:
            crawl = [e async for e in connector.full_crawl()]
            return crawl
        finally:
            await connector.aclose()

    crawl_events = asyncio.run(run())
    assert len(crawl_events) == 24
    assert log[0]["body"]["filterGroups"] == []  # from epoch: no cursor filter


# ---------- BYOT + tier-C doctrine guards ----------


def test_visibility_policy_is_required() -> None:
    with pytest.raises(TypeError):
        HubSpotConnector(token="pat-na1-test")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        HubSpotConnector.handle_webhook([])  # type: ignore[call-arg]


def test_token_comes_from_env_and_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    # Neither credential set → fail closed, naming both env vars.
    monkeypatch.delenv("HUBSPOT_SERVICE_KEY", raising=False)
    monkeypatch.delenv("HUBSPOT_PRIVATE_APP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="HUBSPOT_SERVICE_KEY"):
        HubSpotConnector(POLICY)

    # A Service Key (the current path) is used as a bearer token.
    monkeypatch.setenv("HUBSPOT_SERVICE_KEY", "pat-na1-service-key")
    connector = HubSpotConnector(POLICY)
    assert connector._client.headers["Authorization"] == "Bearer pat-na1-service-key"
    asyncio.run(connector.aclose())

    # The legacy private-app token still works (backward compat); the Service
    # Key wins when both are set.
    monkeypatch.delenv("HUBSPOT_SERVICE_KEY", raising=False)
    monkeypatch.setenv("HUBSPOT_PRIVATE_APP_TOKEN", "pat-na1-from-env")
    legacy = HubSpotConnector(POLICY)
    assert legacy._client.headers["Authorization"] == "Bearer pat-na1-from-env"
    asyncio.run(legacy.aclose())


# ---------- owner/team ACL mirror (SPEC §5e.2) ----------

OWNER_MAP = {
    "77": OwnerInfo(email="rep.one@acme.test", team_ids=("10", "20")),
    "88": OwnerInfo(email="rep.two@acme.test", team_ids=("10",)),
}


def test_record_principals_owner_first_then_teams_deduped() -> None:
    record = {"properties": {"hubspot_owner_id": "77"}}
    assert HubSpotConnector.record_principals(record, OWNER_MAP) == [
        "user:rep.one@acme.test",  # owner first, deterministic
        "group:hubspot-team-10",
        "group:hubspot-team-20",
    ]


def test_record_principals_none_when_unowned_or_unknown_or_no_map() -> None:
    # No owner map (owners scope absent) → fallback for everything.
    assert HubSpotConnector.record_principals({"properties": {}}, None) is None
    # Owner id absent/blank → unowned → fallback.
    assert HubSpotConnector.record_principals({"properties": {}}, OWNER_MAP) is None
    assert (
        HubSpotConnector.record_principals(
            {"properties": {"hubspot_owner_id": None}}, OWNER_MAP
        )
        is None
    )
    # Owner id present but not in the roster → fail closed (fallback), never a
    # fabricated principal.
    assert (
        HubSpotConnector.record_principals(
            {"properties": {"hubspot_owner_id": "does-not-exist"}}, OWNER_MAP
        )
        is None
    )


def test_team_members_inverts_roster_lowercasing_and_dropping_emailless() -> None:
    owners = HubSpotConnector._team_members(
        {
            "77": OwnerInfo(email="rep.one@acme.test", team_ids=("10", "20")),
            "88": OwnerInfo(email="rep.two@acme.test", team_ids=("10",)),
            "99": OwnerInfo(email="", team_ids=("10",)),  # emailless queue → dropped
        }
    )
    assert owners == {
        "group:hubspot-team-10": {"user:rep.one@acme.test", "user:rep.two@acme.test"},
        "group:hubspot-team-20": {"user:rep.one@acme.test"},
    }


def owned_contacts_mock(log: list[dict], owners: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/crm/v3/owners":
            return httpx.Response(200, json=owners)
        body = json.loads(request.content)
        log.append({"path": request.url.path, "body": body})
        if request.url.path == "/crm/v3/objects/contacts/search":
            return httpx.Response(200, json=fixture("hubspot_search_contacts_owned.json"))
        # companies/deals empty for this focused test
        return httpx.Response(200, json={"results": []})

    return httpx.MockTransport(handler)


def test_poll_mirrors_owner_and_team_acl_and_builds_edges() -> None:
    log: list[dict] = []
    client = httpx.AsyncClient(
        base_url="https://api.hubapi.test",
        transport=owned_contacts_mock(log, fixture("hubspot_owners.json")),
        headers={"Authorization": "Bearer pat-na1-test"},
    )
    connector = HubSpotConnector(POLICY, token="pat-na1-test", client=client)

    async def run():
        try:
            return await connector.poll(None)
        finally:
            await connector.aclose()

    events, _ = asyncio.run(run())

    # Record 401 (owner 77 → teams 10,20): its facts carry owner + both teams.
    e401 = next(e for e in events if e.entity_id == "401")
    assert e401.record_principals == [
        "user:rep.one@acme.test",  # owner email lowercased from "Rep.One@acme.test"
        "group:hubspot-team-10",
        "group:hubspot-team-20",
    ]
    # Record 402 (owner 88 → team 10 only).
    e402 = next(e for e in events if e.entity_id == "402")
    assert e402.record_principals == ["user:rep.two@acme.test", "group:hubspot-team-10"]
    # Record 403 (unowned) → no per-record ACL → admin fallback.
    e403 = next(e for e in events if e.entity_id == "403")
    assert e403.record_principals is None

    # Team edges inverted from the FULL roster (owner 99 is emailless → dropped).
    assert connector.team_members == {
        "group:hubspot-team-10": {"user:rep.one@acme.test", "user:rep.two@acme.test"},
        "group:hubspot-team-20": {"user:rep.one@acme.test"},
    }


def test_poll_owners_403_degrades_to_admin_fallback() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/crm/v3/owners":
            return httpx.Response(403, json={"message": "missing scope"})
        json.loads(request.content)
        return httpx.Response(200, json=fixture("hubspot_search_contacts_owned.json")) if (
            request.url.path == "/crm/v3/objects/contacts/search"
        ) else httpx.Response(200, json={"results": []})

    client = httpx.AsyncClient(
        base_url="https://api.hubapi.test",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer pat-na1-test"},
    )
    connector = HubSpotConnector(POLICY, token="pat-na1-test", client=client)

    async def run():
        try:
            return await connector.poll(None)
        finally:
            await connector.aclose()

    events, _ = asyncio.run(run())
    # Owners 403 → empty roster → every record unowned → admin fallback, no edges.
    assert all(e.record_principals is None for e in events)
    assert connector.team_members == {}


def test_envelope_owned_carries_inline_approximated_acl() -> None:
    event = HubSpotFactEvent(
        source="hubspot",
        entity_id="401",
        field_name="email",
        value="owned@acme.test",
        valid_from=utc(2026, 7, 10, 12),
        raw_payload={},
        object_type="contacts",
        visibility_policy=POLICY,
        record_principals=["user:rep.one@acme.test", "group:hubspot-team-10"],
        record_visibility=[31, 32],  # resolved tokens
    )
    env = VerityDebeziumSink.envelope(event)
    assert env["verity_acl"] == {
        "visibility": [31, 32],
        "confidentiality": "internal",
        "acl_provenance": "approximated",
    }
    # An unowned event (no record_visibility) emits NO inline block.
    unowned = HubSpotFactEvent(
        source="hubspot",
        entity_id="403",
        field_name="email",
        value="unowned@acme.test",
        valid_from=utc(2026, 7, 10, 14),
        raw_payload={},
        object_type="contacts",
        visibility_policy=POLICY,
    )
    assert "verity_acl" not in VerityDebeziumSink.envelope(unowned)


def test_sink_resolves_owned_records_and_falls_back_for_unowned() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        seen.append({"path": path, "url": str(request.url), "body": body})
        if path == "/v1/admin/principals":
            # Deterministic materialization of the owner/team strings.
            table = {
                "user:rep.one@acme.test": 31,
                "group:hubspot-team-10": 32,
            }
            return httpx.Response(
                200, json={"mappings": {p: table[p] for p in body["principals"] if p in table}}
            )
        if path == "/v1/ingest/debezium":
            return httpx.Response(
                200,
                json={
                    "facts_inserted": len(body),
                    "facts_refused_no_acl": 0,
                    "facts_retired": 0,
                    "facts_superseded": 0,
                    "facts_unchanged": 0,
                },
            )
        return httpx.Response(200, json={})  # heartbeat

    owned = HubSpotFactEvent(
        source="hubspot",
        entity_id="401",
        field_name="email",
        value="owned@acme.test",
        valid_from=utc(2026, 7, 10, 12),
        raw_payload={},
        object_type="contacts",
        visibility_policy=POLICY,
        record_principals=["user:rep.one@acme.test", "group:hubspot-team-10"],
    )
    unowned = HubSpotFactEvent(
        source="hubspot",
        entity_id="403",
        field_name="email",
        value="unowned@acme.test",
        valid_from=utc(2026, 7, 10, 14),
        raw_payload={},
        object_type="contacts",
        visibility_policy=POLICY,
    )
    sink = VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001",
        transport=httpx.MockTransport(handler),
    )
    sink.post([owned, unowned])

    # The owned event got its owner/team principals resolved and stamped.
    assert owned.record_visibility == [31, 32]
    assert unowned.record_visibility is None
    # The batch still carries the admin-assigned fallback for the unowned record.
    ingest = next(s for s in seen if s["path"] == "/v1/ingest/debezium")
    assert "visibility=7%2C12" in ingest["url"]
    bodies = ingest["body"]
    owned_env = next(b for b in bodies if b["after"]["id"] == "401")
    assert owned_env["verity_acl"] == {
        "visibility": [31, 32],
        "confidentiality": "internal",
        "acl_provenance": "approximated",
    }
    unowned_env = next(b for b in bodies if b["after"]["id"] == "403")
    assert "verity_acl" not in unowned_env  # rides the ?visibility= fallback


def test_sink_sync_team_edges_posts_group_membership_in_order() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={})

    sink = VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="tnt",
        transport=httpx.MockTransport(handler),
    )
    written = sink.sync_team_edges(
        {
            team_principal("20"): {owner_principal("Rep.One@acme.test")},
            team_principal("10"): {
                owner_principal("rep.two@acme.test"),
                owner_principal("rep.one@acme.test"),
            },
        }
    )
    assert written == 3
    # Deterministic order: groups sorted, members sorted within each group.
    assert seen == [
        {"tenant_id": "tnt", "group": "group:hubspot-team-10", "member": "user:rep.one@acme.test"},
        {"tenant_id": "tnt", "group": "group:hubspot-team-10", "member": "user:rep.two@acme.test"},
        {"tenant_id": "tnt", "group": "group:hubspot-team-20", "member": "user:rep.one@acme.test"},
    ]
    assert sink.sync_team_edges({}) == 0  # empty roster → no-op
