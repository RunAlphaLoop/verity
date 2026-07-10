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
    VerityDebeziumSink,
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
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = json.loads(request.content)
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
    summary = sink.post(events)

    assert summary == {"written": 2, "superseded": 0, "retired": 0, "unchanged": 0}
    assert seen["url"] == (
        "http://verity.local:7717/v1/ingest/debezium"
        "?tenant_id=0b0e8b9e-6a34-4b1e-9a75-1de1f3a1c001&pk=id"
    )
    assert seen["auth"] == "Bearer secret-token"
    assert seen["body"] == [VerityDebeziumSink.envelope(e) for e in events]


def test_sink_no_events_no_post() -> None:
    sink = VerityDebeziumSink(url="http://x", tenant_id="t")
    assert sink.post([]) == {"written": 0, "superseded": 0, "retired": 0, "unchanged": 0}


# ---------- truth lane: poll() against a mock HubSpot ----------


def make_mock_hubspot(requests_log: list[dict]) -> httpx.MockTransport:
    """Serves the fixture pages; contacts paginate; the first deals request
    is a 429 with Retry-After to exercise rate-limit handling."""
    state = {"deals_throttled": False}

    def handler(request: httpx.Request) -> httpx.Response:
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
    monkeypatch.delenv("HUBSPOT_PRIVATE_APP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="HUBSPOT_PRIVATE_APP_TOKEN"):
        HubSpotConnector(POLICY)

    monkeypatch.setenv("HUBSPOT_PRIVATE_APP_TOKEN", "pat-na1-from-env")
    connector = HubSpotConnector(POLICY)
    assert connector._client.headers["Authorization"] == "Bearer pat-na1-from-env"
    asyncio.run(connector.aclose())
