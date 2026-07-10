"""HubSpot native flagship connector (SPEC.md §5, §5e.2).

Auth is bring-your-own-token (BYOT doctrine): a private-app token created in
the customer's own portal (~2 min), read from env ``HUBSPOT_PRIVATE_APP_TOKEN``.
Never a vendor-hosted OAuth app — that is strictly a cloud-edition concern.

HubSpot is **ACL tier C** (SPEC.md §5e.2): the CRM exposes no per-record ACL
API, so nothing here can mint a faithful AclEnvelope. Instead the constructor
requires an admin-assigned ``visibility_policy`` (materialized principal
tokens, SPEC §7b) with **no default**, and every emitted event carries it —
the fail-closed alternative to permissive indexing. Provenance tag:
``admin-assigned``.

Two lanes:

- **Truth lane** — ``poll(cursor)`` incrementally syncs contacts, companies,
  and deals via the CRM search API, filtering on the object's last-modified
  property (``hs_lastmodifieddate``; contacts use ``lastmodifieddate`` — a
  documented HubSpot quirk) strictly greater than the cursor, paginated, and
  rate-limit aware (429 Retry-After honored). The cursor is the max
  last-modified timestamp seen, as an ISO-8601 string.
- **Push lane** — HubSpot v3 webhook subscriptions are UI-configured only
  (SPEC §5e.2 table) and deliver to the server's minted webhook URLs, so
  ``push_events`` is a documented no-op; ``handle_webhook`` maps a recorded
  v3 subscription payload (propertyChange events) to FactEvents.

Runner::

    python -m verity_ingest.connectors.hubspot --once --visibility 1,2
    python -m verity_ingest.connectors.hubspot --webhook-file payload.json --visibility 1,2
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx

from verity_ingest.connector import Connector, DocumentEvent, FactEvent

SOURCE = "hubspot"
BASE_URL = "https://api.hubapi.com"
TOKEN_ENV = "HUBSPOT_PRIVATE_APP_TOKEN"
PAGE_SIZE = 100  # search API maximum
MAX_RETRIES = 5

#: Object type → last-modified property used for the incremental filter and
#: for ``valid_from``. Contacts are the documented exception: they expose
#: ``lastmodifieddate`` where every other CRM object uses ``hs_lastmodifieddate``.
LAST_MODIFIED_PROPERTY = {
    "contacts": "lastmodifieddate",
    "companies": "hs_lastmodifieddate",
    "deals": "hs_lastmodifieddate",
}

#: Default properties requested per object type (the last-modified property is
#: always added). Override via the ``properties`` constructor arg.
DEFAULT_PROPERTIES = {
    "contacts": ["email", "firstname", "lastname", "lifecyclestage"],
    "companies": ["name", "domain", "industry"],
    "deals": ["dealname", "amount", "dealstage", "pipeline", "closedate"],
}

#: Webhook ``subscriptionType`` prefix → CRM object type.
WEBHOOK_OBJECT_TYPES = {
    "contact": "contacts",
    "company": "companies",
    "deal": "deals",
}

#: Properties never emitted as facts: the pk mirror, and the last-modified
#: metadata properties (they become ``valid_from``, not L1 fields).
_METADATA_PROPERTIES = {"hs_object_id", "lastmodifieddate", "hs_lastmodifieddate"}


@dataclass
class HubSpotFactEvent(FactEvent):
    """A FactEvent plus what tier-C ingestion requires: the CRM object type
    (→ Debezium ``source.table``) and the admin-assigned visibility policy."""

    object_type: str
    visibility_policy: list[int]


def _parse_hs_timestamp(value: str) -> datetime:
    """HubSpot returns ISO-8601 with millisecond precision and a Z suffix."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso_to_ms(value: str) -> int:
    return int(_parse_hs_timestamp(value).timestamp() * 1000)


def _ms_to_datetime(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


class HubSpotConnector(Connector):
    """Truth-lane polling connector for HubSpot CRM objects.

    ``visibility_policy`` is required and has no default (tier C, fail
    closed). The token defaults to env ``HUBSPOT_PRIVATE_APP_TOKEN``.
    """

    name = SOURCE
    object_types = tuple(LAST_MODIFIED_PROPERTY)

    def __init__(
        self,
        visibility_policy: list[int],
        *,
        token: str | None = None,
        base_url: str = BASE_URL,
        properties: dict[str, list[str]] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        token = token or os.environ.get(TOKEN_ENV)
        if not token:
            raise RuntimeError(
                f"no HubSpot credential: set {TOKEN_ENV} to a private-app token "
                "(BYOT — create it in your own portal, Settings → Integrations → Private Apps)"
            )
        self.visibility_policy = list(visibility_policy)
        self.properties = dict(DEFAULT_PROPERTIES, **(properties or {}))
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )

    # ---------- deterministic mapping (pure; exercised by conformance tests) ----------

    @classmethod
    def events_from_search_page(
        cls, object_type: str, page: dict, visibility_policy: list[int]
    ) -> list[HubSpotFactEvent]:
        """Map one CRM search response page to FactEvents.

        One event per non-null property, sorted by property name for
        determinism; metadata properties (pk mirror, last-modified) are
        excluded — the last-modified timestamp becomes ``valid_from``.
        """
        events: list[HubSpotFactEvent] = []
        for record in page.get("results", []):
            props = record.get("properties", {})
            modified = props.get(LAST_MODIFIED_PROPERTY[object_type]) or record.get("updatedAt")
            valid_from = _parse_hs_timestamp(modified)
            for name in sorted(props):
                value = props[name]
                if name in _METADATA_PROPERTIES or value is None:
                    continue
                events.append(
                    HubSpotFactEvent(
                        source=SOURCE,
                        entity_id=str(record["id"]),
                        field_name=name,
                        value=value,
                        valid_from=valid_from,
                        raw_payload=record,
                        object_type=object_type,
                        visibility_policy=list(visibility_policy),
                    )
                )
        return events

    @classmethod
    def handle_webhook(
        cls, payload: list[dict], visibility_policy: list[int]
    ) -> list[HubSpotFactEvent]:
        """Map a HubSpot v3 webhook subscription payload (a JSON array of
        events) to FactEvents.

        Only ``*.propertyChange`` events map to facts; creation/deletion and
        unknown subscription types are skipped here and reconciled by the
        truth lane. ``visibility_policy`` is required for the same reason it
        is on the constructor: tier C events cannot carry a mirrored ACL.
        """
        events: list[HubSpotFactEvent] = []
        for item in payload:
            subscription = item.get("subscriptionType", "")
            prefix, _, kind = subscription.partition(".")
            object_type = WEBHOOK_OBJECT_TYPES.get(prefix)
            if kind != "propertyChange" or object_type is None:
                continue
            events.append(
                HubSpotFactEvent(
                    source=SOURCE,
                    entity_id=str(item["objectId"]),
                    field_name=item["propertyName"],
                    value=item.get("propertyValue"),
                    valid_from=_ms_to_datetime(item["occurredAt"]),
                    raw_payload=item,
                    object_type=object_type,
                    visibility_policy=list(visibility_policy),
                )
            )
        return events

    # ---------- lanes ----------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op by design: HubSpot v3 webhook subscriptions are UI-configured
        only under a private app (SPEC §5e.2), so delivery happens through the
        server's minted webhook URLs; recorded payloads are decoded with
        :meth:`handle_webhook`. The truth lane reconciles any drops."""
        return
        yield  # pragma: no cover — makes this an (empty) async generator

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """One truth-lane cycle: for each object type, search records whose
        last-modified property is strictly greater than ``cursor`` (ISO-8601;
        None = from epoch), ascending, paginated. Returns the events and the
        max last-modified seen as the next cursor.

        Note: the search API caps one query at 10,000 results; because results
        are sorted ascending by last-modified and the cursor advances, the next
        cycle resumes where a capped one stopped.
        """
        events: list[FactEvent | DocumentEvent] = []
        next_cursor = cursor or "1970-01-01T00:00:00+00:00"
        for object_type in self.object_types:
            async for page in self._search_pages(object_type, cursor):
                page_events = self.events_from_search_page(
                    object_type, page, self.visibility_policy
                )
                events.extend(page_events)
                for record in page.get("results", []):
                    modified = record.get("properties", {}).get(
                        LAST_MODIFIED_PROPERTY[object_type]
                    ) or record.get("updatedAt")
                    if modified and _iso_to_ms(modified) > _iso_to_ms(next_cursor):
                        next_cursor = modified
        return events, next_cursor

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl: identical to a poll from epoch. (HubSpot has
        no per-record ACLs to drift, and archived-record reconciliation lands
        with the §8c tombstone work.)"""
        events, _ = await self.poll(None)
        for event in events:
            yield event

    # ---------- HTTP plumbing ----------

    def _search_body(self, object_type: str, cursor: str | None, after: str | None) -> dict:
        modified_prop = LAST_MODIFIED_PROPERTY[object_type]
        body: dict[str, Any] = {
            "filterGroups": [],
            "sorts": [{"propertyName": modified_prop, "direction": "ASCENDING"}],
            "properties": [*self.properties[object_type], modified_prop],
            "limit": PAGE_SIZE,
        }
        if cursor:
            # Datetime filters take epoch-millisecond values, as strings.
            body["filterGroups"] = [
                {
                    "filters": [
                        {
                            "propertyName": modified_prop,
                            "operator": "GT",
                            "value": str(_iso_to_ms(cursor)),
                        }
                    ]
                }
            ]
        if after is not None:
            body["after"] = after
        return body

    async def _search_pages(self, object_type: str, cursor: str | None) -> AsyncIterator[dict]:
        after: str | None = None
        while True:
            page = await self._post_with_retry(
                f"/crm/v3/objects/{object_type}/search",
                self._search_body(object_type, cursor, after),
            )
            yield page
            after = page.get("paging", {}).get("next", {}).get("after")
            if not after:
                return

    async def _post_with_retry(self, path: str, body: dict) -> dict:
        """POST honoring 429 Retry-After (the search API allows ~5 req/s per
        token); other errors raise after `httpx` status checking."""
        for attempt in range(MAX_RETRIES):
            response = await self._client.post(path, json=body)
            if response.status_code == 429 and attempt < MAX_RETRIES - 1:
                retry_after = float(response.headers.get("Retry-After", "1"))
                await asyncio.sleep(retry_after)
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------- sink: FactEvents → the server's deterministic L1 path ----------


@dataclass
class VerityDebeziumSink:
    """POSTs FactEvents to a running Verity server as bare Debezium-style
    payloads on ``POST /v1/ingest/debezium?tenant_id=...&pk=id`` — reusing the
    already-built deterministic L1 upsert path (one envelope in → one L0
    episode + L1 upserts, no LLM, no embedding).

    The admin-assigned visibility policy rides on the events; the ingest
    endpoint is the trusted connector plane and does not yet accept it —
    it lands with the server's ingest-token work.
    """

    url: str
    tenant_id: str
    admin_token: str | None = None
    pk: str = "id"
    transport: httpx.BaseTransport | None = None  # injection point for tests

    @classmethod
    def from_env(cls) -> "VerityDebeziumSink":
        tenant_id = os.environ.get("VERITY_TENANT_ID")
        if not tenant_id:
            raise RuntimeError("VERITY_TENANT_ID is required (a tenant UUID)")
        return cls(
            url=os.environ.get("VERITY_URL", "http://127.0.0.1:7717"),
            tenant_id=tenant_id,
            admin_token=os.environ.get("VERITY_ADMIN_TOKEN"),
        )

    @staticmethod
    def envelope(event: HubSpotFactEvent) -> dict:
        """One event → one bare Debezium payload (the server accepts bare
        payloads and arrays of them; see crates/verity-server/src/ingest.rs).
        ``source`` becomes the L1 partition ``hubspot:<object_type>``."""
        return {
            "op": "u",
            "source": {
                "connector": SOURCE,
                "table": event.object_type,
                "ts_ms": int(event.valid_from.timestamp() * 1000),
            },
            "after": {"id": event.entity_id, event.field_name: event.value},
        }

    def post(self, events: list[HubSpotFactEvent]) -> dict:
        """POST a batch; returns the server's write summary."""
        if not events:
            return {"written": 0, "superseded": 0, "retired": 0, "unchanged": 0}
        headers = {}
        if self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        with httpx.Client(timeout=30.0, transport=self.transport) as client:
            response = client.post(
                f"{self.url.rstrip('/')}/v1/ingest/debezium",
                params={"tenant_id": self.tenant_id, "pk": self.pk},
                json=[self.envelope(e) for e in events],
                headers=headers,
            )
            response.raise_for_status()
            return response.json()


# ---------- runner ----------


def _read_cursor(state_file: Path) -> str | None:
    try:
        return state_file.read_text().strip() or None
    except FileNotFoundError:
        return None


def _write_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(cursor + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.hubspot",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument("--once", action="store_true", help="run one truth-lane poll cycle")
    parser.add_argument(
        "--webhook-file",
        type=Path,
        help="process a recorded HubSpot v3 webhook payload (JSON array)",
    )
    parser.add_argument(
        "--visibility",
        required=True,
        help="comma-separated principal tokens — the admin-assigned visibility "
        "policy (tier C source; required, no default, per SPEC §5e.2)",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("HUBSPOT_STATE_FILE", ".verity/hubspot_cursor")),
        help="cursor persistence path (default: $HUBSPOT_STATE_FILE or .verity/hubspot_cursor)",
    )
    args = parser.parse_args(argv)

    try:
        policy = [int(tok) for tok in args.visibility.split(",") if tok.strip()]
    except ValueError:
        parser.error("--visibility must be comma-separated integers, e.g. 1,2")
    if not policy:
        parser.error("--visibility must name at least one principal token (fail closed)")

    if args.once == bool(args.webhook_file):
        parser.error("exactly one of --once or --webhook-file is required")

    sink = VerityDebeziumSink.from_env()

    if args.webhook_file:
        payload = json.loads(args.webhook_file.read_text())
        events = HubSpotConnector.handle_webhook(payload, policy)
        summary = sink.post(events)
        print(f"webhook: {len(events)} fact event(s) -> {summary}")
        return 0

    async def run_once() -> tuple[list[HubSpotFactEvent], str]:
        connector = HubSpotConnector(policy)
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            return list(events), next_cursor  # type: ignore[arg-type]
        finally:
            await connector.aclose()

    events, next_cursor = asyncio.run(run_once())
    summary = sink.post(events)
    _write_cursor(args.state_file, next_cursor)
    print(f"poll: {len(events)} fact event(s), cursor -> {next_cursor} -> {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
