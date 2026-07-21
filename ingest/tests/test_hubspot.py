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

from verity_ingest.acl_diff import AclState
from verity_ingest.connectors.hubspot import (
    DEGRADED_ACL_SIGNAL,
    HubSpotConnector,
    HubSpotFactEvent,
    OwnerInfo,
    VerityDebeziumSink,
    _read_credential_file,
    main as hubspot_main,
    owner_principal,
    run_backfill,
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


def test_record_access_owner_id_and_teams_deduped() -> None:
    # M2 2b — the owner is carried as its raw ownerId (resolved via the
    # (hubspot, ownerId) crosswalk by the sink), NOT a blind user:<email>. Teams
    # are already-canonical group strings.
    record = {"properties": {"hubspot_owner_id": "77"}}
    owner_id, teams = HubSpotConnector.record_access(record, OWNER_MAP)
    assert owner_id == "77"
    assert teams == ["group:hubspot-team-10", "group:hubspot-team-20"]


def test_record_access_none_when_unowned_or_unknown_or_no_map() -> None:
    # No owner map (owners scope absent) → fallback for everything.
    assert HubSpotConnector.record_access({"properties": {}}, None) == (None, None)
    # Owner id absent/blank → unowned → fallback.
    assert HubSpotConnector.record_access({"properties": {}}, OWNER_MAP) == (None, None)
    assert HubSpotConnector.record_access(
        {"properties": {"hubspot_owner_id": None}}, OWNER_MAP
    ) == (None, None)
    # Owner id present but not in the roster → fail closed (fallback), never a
    # fabricated principal.
    assert HubSpotConnector.record_access(
        {"properties": {"hubspot_owner_id": "does-not-exist"}}, OWNER_MAP
    ) == (None, None)


def test_team_members_inverts_roster_keyed_by_owner_id_marker() -> None:
    # M2 2b — team members are keyed by their ownerId as a hubspot-owner:<id>
    # crosswalk marker (the sink canonicalizes to user:<primaryEmail> before
    # mirroring the edge); the owner's email is NO LONGER a group-edge member.
    owners = HubSpotConnector._team_members(
        {
            "77": OwnerInfo(email="rep.one@acme.test", team_ids=("10", "20")),
            "88": OwnerInfo(email="rep.two@acme.test", team_ids=("10",)),
        }
    )
    assert owners == {
        "group:hubspot-team-10": {"hubspot-owner:77", "hubspot-owner:88"},
        "group:hubspot-team-20": {"hubspot-owner:77"},
    }


# --- M2 2b: ownerId crosswalk (admin_explicit), email_fallback OFF ------------


def test_sink_resolves_owner_via_crosswalk_ownerid_not_email() -> None:
    # The sink sends (hubspot, ownerId) through `resolvable` — NOT owner.email
    # via `principals`/`emails`. The record's owner email is irrelevant to the
    # token it gets; the admin_explicit crosswalk row (77 → canonical) decides.
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        if request.url.path == "/v1/admin/principals":
            seen.append(body)
            mappings: dict[str, int] = {}
            for owner in body.get("resolvable", []):
                if owner == {"source": "hubspot", "local_id": "77"}:
                    mappings["user:alice@corp.com"] = 900  # the canonical, not the email
            declared = bool(body.get("resolvable") or body.get("emails"))
            return httpx.Response(
                200, json={"mappings": mappings, "quarantined": declared and not mappings}
            )
        return httpx.Response(200, json={"facts_inserted": 1})

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    event = HubSpotFactEvent(
        source="hubspot",
        entity_id="H",
        field_name="dealname",
        value="Big deal",
        valid_from=utc(2026, 7, 10, 12),
        raw_payload={},
        object_type="deals",
        visibility_policy=POLICY,
        record_owner_id="77",  # the ownerId — NOT owner.email
    )
    sink._stamp_record_visibility([event])
    assert event.record_visibility == [900]
    # The request carried the ownerId via `resolvable`; no blind email/principal.
    assert seen == [{"tenant_id": "t", "resolvable": [{"source": "hubspot", "local_id": "77"}]}]


def test_sink_crosswalk_resolution_carries_admin_bearer() -> None:
    # Regression (live-org SSO-alias closure): the owner/team crosswalk-resolution
    # client must carry the admin bearer on its POST /v1/admin/principals. It
    # previously did NOT — only the fact-post path attached auth — so against a
    # real auth-gated server, owner resolution 401'd the moment a record actually
    # had an owner to resolve. Fixtures missed it because their MockTransport
    # ignores auth AND they construct the sink with no admin_token. This asserts
    # the Authorization header rides the resolve call itself.
    auth_seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/principals":
            auth_seen.append(request.headers.get("Authorization"))
            body = json.loads(request.content) if request.content else {}
            mappings: dict[str, int] = {}
            for owner in body.get("resolvable", []):
                if owner == {"source": "hubspot", "local_id": "77"}:
                    mappings["user:alice@corp.com"] = 900
            declared = bool(body.get("resolvable") or body.get("emails"))
            return httpx.Response(
                200, json={"mappings": mappings, "quarantined": declared and not mappings}
            )
        return httpx.Response(200, json={"facts_inserted": 1})

    sink = VerityDebeziumSink(
        url="http://sink",
        tenant_id="t",
        transport=httpx.MockTransport(handler),
        admin_token="secret-token",
    )
    event = HubSpotFactEvent(
        source="hubspot",
        entity_id="H",
        field_name="dealname",
        value="Big deal",
        valid_from=utc(2026, 7, 10, 12),
        raw_payload={},
        object_type="deals",
        visibility_policy=POLICY,
        record_owner_id="77",
    )
    sink._stamp_record_visibility([event])
    assert event.record_visibility == [900]  # resolution succeeded...
    assert auth_seen == ["Bearer secret-token"]  # ...because the resolve call was authed


def test_sink_unlinked_ownerid_confers_no_visibility() -> None:
    # An ownerId with no crosswalk row → the server drops it → the record has no
    # inline ACL and rides the admin --visibility floor (never a fabricated token).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/principals":
            return httpx.Response(200, json={"mappings": {}, "quarantined": True})
        return httpx.Response(200, json={"facts_inserted": 1})

    sink = VerityDebeziumSink(
        url="http://sink", tenant_id="t", transport=httpx.MockTransport(handler)
    )
    event = HubSpotFactEvent(
        source="hubspot",
        entity_id="H",
        field_name="dealname",
        value="v",
        valid_from=utc(2026, 7, 10, 12),
        raw_payload={},
        object_type="deals",
        visibility_policy=POLICY,
        record_owner_id="unlinked",
    )
    sink._stamp_record_visibility([event])
    assert event.record_visibility is None  # no inline ACL → admin floor
    assert "verity_acl" not in VerityDebeziumSink.envelope(event)


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

    # M2 2b — Record 401 (owner 77 → teams 10,20): the owner is its ownerId (the
    # sink resolves it via the (hubspot, 77) crosswalk), teams are canonical.
    e401 = next(e for e in events if e.entity_id == "401")
    assert e401.record_owner_id == "77"
    assert e401.record_principals == ["group:hubspot-team-10", "group:hubspot-team-20"]
    # Record 402 (owner 88 → team 10 only).
    e402 = next(e for e in events if e.entity_id == "402")
    assert e402.record_owner_id == "88"
    assert e402.record_principals == ["group:hubspot-team-10"]
    # Record 403 (unowned) → no per-record ACL → admin fallback.
    e403 = next(e for e in events if e.entity_id == "403")
    assert e403.record_owner_id is None and e403.record_principals is None

    # Team edges inverted from the FULL roster, keyed by ownerId marker.
    assert connector.team_members == {
        "group:hubspot-team-10": {"hubspot-owner:77", "hubspot-owner:88"},
        "group:hubspot-team-20": {"hubspot-owner:77"},
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
            # Already-canonical team group; ownerId 77 resolves via the crosswalk.
            table = {"group:hubspot-team-10": 32}
            mappings = {p: table[p] for p in body.get("principals", []) if p in table}
            for owner in body.get("resolvable", []):
                if owner.get("source") == "hubspot" and owner.get("local_id") == "77":
                    mappings["user:rep.one@acme.test"] = 31
            declared = bool(body.get("resolvable") or body.get("emails"))
            return httpx.Response(
                200, json={"mappings": mappings, "quarantined": declared and not mappings}
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
        record_principals=["group:hubspot-team-10"],
        record_owner_id="77",
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

    # The owned event got its team group (32) + crosswalked owner (31) stamped.
    assert owned.record_visibility == [32, 31]
    assert unowned.record_visibility is None
    # The batch still carries the admin-assigned fallback for the unowned record.
    ingest = next(s for s in seen if s["path"] == "/v1/ingest/debezium")
    assert "visibility=7%2C12" in ingest["url"]
    bodies = ingest["body"]
    owned_env = next(b for b in bodies if b["after"]["id"] == "401")
    assert owned_env["verity_acl"] == {
        "visibility": [32, 31],
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


# ---------- --credential-file (server spawn channel; token is the file body) ----------


def _write_cred(tmp_path: Path, token: str, mode: int = 0o600) -> Path:
    p = tmp_path / "bearer.token"
    p.write_text(token)
    p.chmod(mode)
    return p


def test_credential_file_reads_body_and_strips_trailing_newline(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "pat-na1-from-file\n")
    assert _read_credential_file(p) == "pat-na1-from-file"


def test_credential_file_rejects_non_0600_mode(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "pat-na1-secret\n", mode=0o644)
    with pytest.raises(PermissionError, match="0600"):
        _read_credential_file(p)


def test_credential_file_rejects_empty(tmp_path: Path) -> None:
    p = _write_cred(tmp_path, "\n")
    with pytest.raises(ValueError, match="empty"):
        _read_credential_file(p)


def test_credential_file_token_wins_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file body is PREFERRED over both env vars — a server spawn never needs
    # the token in the child environment.
    monkeypatch.setenv("HUBSPOT_SERVICE_KEY", "pat-na1-from-env")
    p = _write_cred(tmp_path, "pat-na1-from-file\n")
    connector = HubSpotConnector(POLICY, token=_read_credential_file(p))
    assert connector._client.headers["Authorization"] == "Bearer pat-na1-from-file"
    asyncio.run(connector.aclose())


# ---------- --backfill runner (§5a; mirrors gdrive/gmail run_backfill) ----------


def _backfill_sink(seen: list[dict]) -> VerityDebeziumSink:
    """A VerityDebeziumSink over a mock server that accepts principals, debezium
    ingest, group edges, connector-status and backfill progress posts."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        seen.append({"path": path, "body": body})
        if path == "/v1/admin/principals":
            # Already-canonical strings (team groups).
            principal_table = {
                "group:hubspot-team-10": 32,
                "group:hubspot-team-20": 34,
            }
            # M2 2b — the crosswalk: (hubspot, ownerId) → canonical user token.
            owner_table = {
                "77": ("user:rep.one@acme.test", 31),
                "88": ("user:rep.two@acme.test", 33),
            }
            mappings: dict[str, int] = {
                p: principal_table[p]
                for p in body.get("principals", [])
                if p in principal_table
            }
            declared = bool(body.get("resolvable") or body.get("emails"))
            for owner in body.get("resolvable", []):
                if owner.get("source") == "hubspot" and owner.get("local_id") in owner_table:
                    canon, token = owner_table[owner["local_id"]]
                    mappings[canon] = token
            quarantined = declared and not mappings
            return httpx.Response(200, json={"mappings": mappings, "quarantined": quarantined})
        if path == "/v1/ingest/debezium":
            return httpx.Response(200, json={"facts_inserted": len(body)})
        return httpx.Response(200, json={})  # groups, connector-status, backfill

    return VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="tnt-uuid",
        admin_token="admin-tok",
        transport=httpx.MockTransport(handler),
    )


def test_run_backfill_delivers_and_finishes_clean() -> None:
    from verity_ingest.connectors.backfill import BackfillReporter

    hub_log: list[dict] = []
    connector = HubSpotConnector(
        POLICY,
        token="pat-na1-test",
        client=httpx.AsyncClient(
            base_url="https://api.hubapi.test",
            transport=make_mock_hubspot(hub_log, fixture("hubspot_owners.json")),
            headers={"Authorization": "Bearer pat-na1-test"},
        ),
    )
    seen: list[dict] = []
    sink = _backfill_sink(seen)
    reporter = BackfillReporter(
        sink.url, sink.tenant_id, connector.name, api_key=sink.admin_token, run_id="run-1",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))),
    )
    progress: list[dict] = []
    reporter._post = lambda body: progress.append(dict(body))  # type: ignore[method-assign]

    delivered = run_backfill(connector, sink, reporter)
    asyncio.run(connector.aclose())

    assert delivered > 0
    # Team edges synced (owners fixture resolves), then facts ingested.
    assert any(s["path"] == "/v1/admin/groups" for s in seen)
    assert any(s["path"] == "/v1/ingest/debezium" for s in seen)
    # Lifecycle: running → advance(s) → completed with NO degraded note.
    assert progress[0]["state"] == "running"
    assert progress[-1]["state"] == "completed"
    assert "error" not in progress[-1]


def test_run_backfill_owners_403_emits_degraded_acl_signal(capsys) -> None:
    from verity_ingest.connectors.backfill import BackfillReporter

    def hub_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/crm/v3/owners":
            return httpx.Response(403, json={"message": "missing scope"})
        json.loads(request.content)
        if request.url.path == "/crm/v3/objects/contacts/search":
            return httpx.Response(200, json=fixture("hubspot_search_contacts_owned.json"))
        return httpx.Response(200, json={"results": []})

    connector = HubSpotConnector(
        POLICY,
        token="pat-na1-test",
        client=httpx.AsyncClient(
            base_url="https://api.hubapi.test",
            transport=httpx.MockTransport(hub_handler),
            headers={"Authorization": "Bearer pat-na1-test"},
        ),
    )
    seen: list[dict] = []
    sink = _backfill_sink(seen)
    reporter = BackfillReporter(
        sink.url, sink.tenant_id, connector.name, run_id="run-2",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))),
    )
    progress: list[dict] = []
    reporter._post = lambda body: progress.append(dict(body))  # type: ignore[method-assign]

    run_backfill(connector, sink, reporter)
    asyncio.run(connector.aclose())

    assert connector.owners_degraded is True
    # Distinct machine-readable signal on stdout (the read-once contract).
    assert DEGRADED_ACL_SIGNAL in capsys.readouterr().out
    # And a distinct reporter note on the clean finish — never a silent success.
    assert progress[-1]["state"] == "completed"
    assert progress[-1]["error"] == DEGRADED_ACL_SIGNAL


def test_main_backfill_wins_over_once_and_uses_credential_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VERITY_TENANT_ID", "tnt-uuid")
    monkeypatch.setenv("VERITY_BACKFILL_RUN_ID", "server-minted-run")
    monkeypatch.delenv("HUBSPOT_SERVICE_KEY", raising=False)
    monkeypatch.delenv("HUBSPOT_PRIVATE_APP_TOKEN", raising=False)
    cred = _write_cred(tmp_path, "pat-na1-file-only\n")

    captured: dict = {}

    def fake_run_backfill(connector, sink, reporter, **kw):
        captured["auth"] = connector._client.headers["Authorization"]
        captured["run_id"] = reporter.run_id
        return 5

    monkeypatch.setattr("verity_ingest.connectors.hubspot.run_backfill", fake_run_backfill)

    # --backfill wins over --once (both passed): the one-shot backfill path runs.
    rc = hubspot_main(
        ["--backfill", "--once", "--visibility", "7,12", "--credential-file", str(cred)]
    )
    assert rc == 0
    # The token came from the file (env was unset), never echoed.
    assert captured["auth"] == "Bearer pat-na1-file-only"
    # The server-minted run_id flowed through VERITY_BACKFILL_RUN_ID.
    assert captured["run_id"] == "server-minted-run"


def test_main_requires_exactly_one_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERITY_TENANT_ID", "tnt-uuid")
    with pytest.raises(SystemExit):
        hubspot_main(["--visibility", "7,12"])  # no mode
    with pytest.raises(SystemExit):
        hubspot_main(["--backfill", "--webhook-file", "x.json", "--visibility", "7,12"])


# --- M1 connector ACL-diff lane (build #5) --------------------------------


def _owned_event(entity_id: str, field: str, value, principals: list[str]) -> HubSpotFactEvent:
    """An owner/team-scoped HubSpotFactEvent carrying `record_principals`."""
    return HubSpotFactEvent(
        source="hubspot",
        entity_id=entity_id,
        field_name=field,
        value=value,
        valid_from=datetime(2026, 7, 20, tzinfo=timezone.utc),
        raw_payload={},
        object_type="contacts",
        visibility_policy=[7, 12],
        record_principals=list(principals),
    )


def _acl_lane_sink(handler) -> VerityDebeziumSink:
    return VerityDebeziumSink(
        url="http://verity.local:7717",
        tenant_id="0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001",
        admin_token="secret-token",
        transport=httpx.MockTransport(handler),
    )


def test_acl_diff_emits_acl_change_on_tightening(tmp_path: Path) -> None:
    # Two syncs of one owned record. Sync 1 establishes the baseline (no emit).
    # Sync 2 REMOVES a principal (a team un-share) → exactly one acl-change POST
    # per derived fact key, carrying the NEW FULL resolved token set (REPLACE)
    # and the removed principal in the audit fields.
    token_map = {
        "user:owner@acme.example": 3,
        "group:hubspot-team-1": 7,
        "group:hubspot-team-2": 9,
    }
    posts: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        body = json.loads(request.content) if request.content else {}
        if url.endswith("/v1/admin/principals"):
            wanted = body["principals"]
            return httpx.Response(
                200, json={"mappings": {p: token_map[p] for p in wanted if p in token_map}}
            )
        if url.endswith("/v1/ingest/acl-change"):
            posts.append(body)
            return httpx.Response(200, json={"kind": "fact", "rows_rewritten": 1})
        return httpx.Response(200, json={})

    sink = _acl_lane_sink(handler)
    state_file = tmp_path / "hubspot.acl.json"
    state = AclState(state_file)

    before = ["user:owner@acme.example", "group:hubspot-team-1", "group:hubspot-team-2"]
    after = ["user:owner@acme.example", "group:hubspot-team-1"]  # team-2 un-shared

    # Sync 1: baseline, no emit.
    sync1 = [
        _owned_event("501", "name", "Acme", before),
        _owned_event("501", "domain", "acme.example", before),
    ]
    assert sink.emit_acl_changes(sync1, state) == 0
    assert posts == []

    # Sync 2: team-2 removed → one acl-change per fact key (name, domain).
    state2 = AclState(state_file)  # reload from disk (proves persistence)
    sync2 = [
        _owned_event("501", "name", "Acme", after),
        _owned_event("501", "domain", "acme.example", after),
    ]
    emitted = sink.emit_acl_changes(sync2, state2)
    assert emitted == 2, "one acl-change per derived fact key of the tightened record"
    assert len(posts) == 2
    for body in posts:
        assert body["source"] == "hubspot:contacts"
        assert body["fact"]["entity_id"] == "501"
        assert body["fact"]["field"] in {"name", "domain"}
        # REPLACE: the NEW FULL resolved set (owner=3, team-1=7); team-2=9 gone.
        assert body["verity_acl"]["visibility"] == [3, 7]
        assert body["reason"] == "source_unshare"


def test_acl_diff_grant_only_change_does_not_emit(tmp_path: Path) -> None:
    # A record that GAINS a principal (a widening) must NOT emit — grants take
    # effect on the next mint via the normal ingest path.
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/v1/admin/principals"):
            return httpx.Response(200, json={"mappings": {}})
        assert not url.endswith("/v1/ingest/acl-change"), "grant must not emit an acl-change"
        return httpx.Response(200, json={})

    sink = _acl_lane_sink(handler)
    state = AclState(tmp_path / "hs.acl.json")
    narrow = ["user:owner@acme.example"]
    wide = ["user:owner@acme.example", "group:hubspot-team-1"]
    assert sink.emit_acl_changes([_owned_event("9", "name", "X", narrow)], state) == 0
    # Widen: adds team-1. No tightening → no emit.
    assert sink.emit_acl_changes([_owned_event("9", "name", "X", wide)], state) == 0
