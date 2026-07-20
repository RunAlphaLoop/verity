"""HubSpot native flagship connector (SPEC.md §5, §5e.2).

Auth is bring-your-own-token (BYOT doctrine): a **Service Key** created in the
customer's own portal (Development → Keys → Service keys, ~2 min), read from env
``HUBSPOT_SERVICE_KEY``. HubSpot deprecated private apps in 2026 in favour of
Service Keys; a legacy private-app token (``HUBSPOT_PRIVATE_APP_TOKEN``) is still
accepted for backward compat — both are used identically as
``Authorization: Bearer <key>`` at the v3 CRM endpoints. Never a vendor-hosted
OAuth app — that is strictly a cloud-edition concern.

**Access model (SPEC.md §5e.2).** HubSpot record access is driven by the
record's **owner** (``hubspot_owner_id``) and the owner's **team(s)**. The
connector mirrors this: each owned record's facts carry an inline
owner+team ACL (``user:<owner>`` + ``group:hubspot-team-<id>``) with provenance
``approximated`` — it is a container/owner approximation, not a literal source
ACL, because two access inputs are NOT visible from the record side: each
user's permission level ("Everything" sees all records) and manual per-record
shares. The mirror therefore deliberately UNDER-grants (over-hides — fail
closed). Team **hierarchy** (a parent team seeing child-team records) is also
not modeled — HubSpot's public API does not expose parent/child team ids.

Owner/team resolution needs the ``crm.objects.owners.read`` scope on the key;
without it (or for an unowned record, or the webhook lane) facts fall back to
an **admin-assigned** ``visibility_policy`` (materialized principal tokens,
SPEC §7b) — required on the constructor with **no default**, the fail-closed
alternative to permissive indexing.

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
from typing import Any, AsyncIterator, Mapping, Sequence

import httpx

from verity_ingest.acl_diff import AclChange, AclState, diff_acl, emit_acl_change
from verity_ingest.connector import Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter
from verity_ingest.credentials import StaticKey

SOURCE = "hubspot"
BASE_URL = "https://api.hubapi.com"
#: Stable, machine-readable stdout token emitted (once) by a --backfill run when
#: the owners scope 403-degraded the whole run: owner/team ACLs collapsed to the
#: admin-assigned --visibility policy. The server greps stdout for this token to
#: surface backfill ``state=degraded_acl`` (it is ALSO reported to the backfill
#: dashboard via BackfillReporter.finish(error=DEGRADED_ACL_SIGNAL)). Do NOT bury
#: the degrade in stderr only — this token is the read-once contract.
DEGRADED_ACL_SIGNAL = "verity.backfill.degraded_acl"
#: Preferred credential env var. A HubSpot **Service Key** (Development → Keys →
#: Service keys) is the current single-account credential; HubSpot deprecated
#: private apps in 2026. Both are used identically as `Authorization: Bearer
#: <key>` at the same v3 CRM endpoints, so either drops in unchanged.
SERVICE_KEY_ENV = "HUBSPOT_SERVICE_KEY"
#: Legacy fallback: a private-app token. Still accepted for backward compat.
TOKEN_ENV = "HUBSPOT_PRIVATE_APP_TOKEN"
PAGE_SIZE = 100  # search API maximum
MAX_RETRIES = 5
#: Owners API — read-only roster of CRM owners (users who can own records).
#: Each owner carries `id` (matches a record's `hubspot_owner_id`), `email`,
#: and a `teams` array (`id`, `name`, `primary`). Requires the
#: `crm.objects.owners.read` scope on the Service Key.
OWNERS_PATH = "/crm/v3/owners"
#: The record property naming the owner. Drives HubSpot record-level access:
#: a record is reachable by its owner and (per each user's permission level)
#: the owner's team(s). We mirror owner + team; per-user "Everything" access and
#: manual per-record shares are NOT visible from the record side, so the mirror
#: deliberately UNDER-grants (over-hides — fail closed) and is labeled
#: `approximated`, never `mirrored`.
OWNER_ID_PROPERTY = "hubspot_owner_id"

#: Object type → last-modified property used for the incremental filter and
#: for ``valid_from``. Contacts are the documented exception: they expose
#: ``lastmodifieddate`` where every other CRM object uses ``hs_lastmodifieddate``.
LAST_MODIFIED_PROPERTY = {
    "contacts": "lastmodifieddate",
    "companies": "hs_lastmodifieddate",
    "deals": "hs_lastmodifieddate",
}

#: Default properties requested per object type (the last-modified property AND
#: the owner property are always added). Override via the ``properties`` arg.
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

#: Properties never emitted as facts: the pk mirror, the last-modified metadata
#: properties (they become ``valid_from``, not L1 fields), and the owner id
#: (it is ACL plumbing — it drives per-record visibility, not a content fact).
_METADATA_PROPERTIES = {
    "hs_object_id",
    "lastmodifieddate",
    "hs_lastmodifieddate",
    OWNER_ID_PROPERTY,
}


@dataclass(frozen=True)
class OwnerInfo:
    """One CRM owner as the Owners API returns it, reduced to what access
    mirroring needs: the (lowercased) login email and the ids of every team the
    owner belongs to (primary + secondary — HubSpot grants team access on both).
    """

    email: str
    team_ids: tuple[str, ...]


def owner_principal(email: str) -> str:
    """The record-owner principal. Lowercased ``user:<email>`` so it is the SAME
    SpiceDB object a Gmail/Drive subject resolves to — a person owning a HubSpot
    deal and appearing in Drive/Gmail is ONE identity across sources."""
    return f"user:{email.lower()}"


def team_principal(team_id: str) -> str:
    """The team-visibility principal, a SpiceDB group. Members are attached via
    ``POST /v1/admin/groups`` (``group:hubspot-team-<id> ⊃ user:<member>``), so
    a subject resolves through their team membership exactly like a Google
    Group. Team hierarchy (parent teams seeing child records) is NOT modeled:
    HubSpot's public API does not expose parent/child team ids, so a manager who
    can see a child team's records only through the hierarchy is under-granted
    here (over-hides — fail closed), never over-granted."""
    return f"group:hubspot-team-{team_id}"


@dataclass
class HubSpotFactEvent(FactEvent):
    """A FactEvent plus what CRM ingestion requires: the object type (→ Debezium
    ``source.table``) and the resolved visibility for this record.

    Visibility precedence, per record:
    - ``record_principals`` — the owner+team principal STRINGS this record's
      access mirrors (``user:<owner>`` + ``group:hubspot-team-<id>``), or
      ``None`` when the record is unowned. Computed at map time from the owner
      roster; source of truth for the SpiceDB team edges too.
    - ``record_visibility`` — those strings resolved to int tokens (filled by
      the runner via ``/v1/admin/principals``). When set, the envelope carries
      an inline ``verity_acl`` with ``acl_provenance: approximated``.
    - ``visibility_policy`` — the admin-assigned fallback (``--visibility``).
      Used for unowned records (and the webhook lane, which has no owner
      context): delivered as the connector-bound policy, ``admin-assigned``.
    """

    object_type: str
    visibility_policy: list[int]
    record_principals: list[str] | None = None
    record_visibility: list[int] | None = None


def _parse_hs_timestamp(value: str) -> datetime:
    """HubSpot returns ISO-8601 with millisecond precision and a Z suffix."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso_to_ms(value: str) -> int:
    return int(_parse_hs_timestamp(value).timestamp() * 1000)


def _ms_to_datetime(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


class HubSpotConnector(Connector):
    """Truth-lane polling connector for HubSpot CRM objects.

    Owned records mirror their owner+team access (``approximated``); unowned
    records (and any record when the owners scope is absent) fall back to the
    admin-assigned ``visibility_policy``, which is required and has no default
    (fail closed). The credential defaults to env ``HUBSPOT_SERVICE_KEY`` (a
    Service Key), falling back to the legacy ``HUBSPOT_PRIVATE_APP_TOKEN``.
    """

    name = SOURCE
    object_types = tuple(LAST_MODIFIED_PROPERTY)

    def __init__(
        self,
        visibility_policy: list[int],
        *,
        token: str | None = None,
        credential: StaticKey | None = None,
        base_url: str = BASE_URL,
        properties: dict[str, list[str]] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        # Credential lifecycle via the shared §5e.2 abstraction. HubSpot
        # private-app tokens are the static-key shape: no minting, no refresh
        # (a 401 means "rotate the token", never "retry"), and no published
        # expiry — pass a `credential` with `expiry` set to get the 7-day
        # expiry-telemetry warning if your org rotates tokens on a schedule.
        # Service Keys (the current path) and legacy private-app tokens are both
        # bearer credentials against the same v3 CRM API — either drops in
        # unchanged. Prefer HUBSPOT_SERVICE_KEY; fall back to the legacy env var.
        resolved = token or os.environ.get(SERVICE_KEY_ENV) or os.environ.get(TOKEN_ENV)
        self.credential = credential or StaticKey(
            SERVICE_KEY_ENV,
            value=resolved,
            missing_hint="a HubSpot Service Key (Development → Keys → Service "
            "keys — the current path) or a legacy private-app token; set "
            "HUBSPOT_SERVICE_KEY or HUBSPOT_PRIVATE_APP_TOKEN. Both are bearer tokens",
        )
        self.visibility_policy = list(visibility_policy)
        self.properties = dict(DEFAULT_PROPERTIES, **(properties or {}))
        #: Filled by :meth:`poll` from the Owners API. ``team_members`` maps each
        #: ``group:hubspot-team-<id>`` to the set of ``user:<email>`` members —
        #: the SpiceDB edges the runner syncs so a subject resolves through team
        #: membership. Empty when the owners scope is absent (fail-closed to the
        #: admin-assigned fallback).
        self.team_members: dict[str, set[str]] = {}
        #: Set True by :meth:`_fetch_owners` when the Owners API 403s (the Service
        #: Key lacks ``crm.objects.owners.read``). The whole run then degrades to
        #: the admin-assigned ``--visibility`` for every record; the runner turns
        #: this into a distinct, machine-readable ``degraded_acl`` signal so the
        #: server can surface it (never buried in stderr).
        self.owners_degraded: bool = False
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {self.credential.value}"},
            timeout=30.0,
        )

    # ---------- deterministic mapping (pure; exercised by conformance tests) ----------

    @staticmethod
    def record_principals(
        record: dict, owner_map: Mapping[str, OwnerInfo] | None
    ) -> list[str] | None:
        """The owner+team principal strings this record's access mirrors, or
        ``None`` when the record is unowned or its owner is unknown (→ the
        admin-assigned fallback applies; never a permissive default).

        ``user:<owner>`` first (deterministic), then one ``group:hubspot-team-``
        per team the owner belongs to, deduplicated, order preserved.
        """
        if not owner_map:
            return None
        owner_id = (record.get("properties", {}) or {}).get(OWNER_ID_PROPERTY)
        if not owner_id:
            return None
        owner = owner_map.get(str(owner_id))
        if owner is None or not owner.email:
            return None
        principals = [owner_principal(owner.email)]
        for team_id in owner.team_ids:
            principal = team_principal(team_id)
            if principal not in principals:
                principals.append(principal)
        return principals

    @classmethod
    def events_from_search_page(
        cls,
        object_type: str,
        page: dict,
        visibility_policy: list[int],
        owner_map: Mapping[str, OwnerInfo] | None = None,
    ) -> list[HubSpotFactEvent]:
        """Map one CRM search response page to FactEvents.

        One event per non-null property, sorted by property name for
        determinism; metadata properties (pk mirror, last-modified, owner id)
        are excluded — the last-modified timestamp becomes ``valid_from`` and
        the owner id drives the ACL. Each event carries the record's owner+team
        principals (``record_principals``) when ``owner_map`` resolves them.
        """
        events: list[HubSpotFactEvent] = []
        for record in page.get("results", []):
            props = record.get("properties", {})
            modified = props.get(LAST_MODIFIED_PROPERTY[object_type]) or record.get("updatedAt")
            valid_from = _parse_hs_timestamp(modified)
            principals = cls.record_principals(record, owner_map)
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
                        record_principals=list(principals) if principals else None,
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
        # Fetch the owner roster ONCE per cycle: it resolves each record's
        # owner+team ACL and is the source of the team-membership edges.
        owner_map = await self._fetch_owners()
        self.team_members = self._team_members(owner_map)
        for object_type in self.object_types:
            async for page in self._search_pages(object_type, cursor):
                page_events = self.events_from_search_page(
                    object_type, page, self.visibility_policy, owner_map
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
        """Reconciliation crawl: identical to a poll from epoch. Re-reads the
        owner roster too, so owner/team ACL drift (a record reassigned to a new
        owner, a user moved between teams) reconciles. (Archived-record
        reconciliation lands with the §8c tombstone work.)"""
        events, _ = await self.poll(None)
        for event in events:
            yield event

    # ---------- HTTP plumbing ----------

    def _search_body(self, object_type: str, cursor: str | None, after: str | None) -> dict:
        modified_prop = LAST_MODIFIED_PROPERTY[object_type]
        body: dict[str, Any] = {
            "filterGroups": [],
            "sorts": [{"propertyName": modified_prop, "direction": "ASCENDING"}],
            # The owner id is always requested — it drives per-record visibility
            # even though it is not emitted as a content fact.
            "properties": [*self.properties[object_type], modified_prop, OWNER_ID_PROPERTY],
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

    async def _fetch_owners(self) -> dict[str, OwnerInfo]:
        """The CRM owner roster, keyed by owner id (matches a record's
        ``hubspot_owner_id``). Paginated, 429-aware.

        A **403** means the Service Key lacks ``crm.objects.owners.read``: we
        degrade to an EMPTY roster (every record → the admin-assigned fallback),
        loudly, rather than failing the sync — fail closed, never permissive.
        """
        owners: dict[str, OwnerInfo] = {}
        after: str | None = None
        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if after:
                params["after"] = after
            for attempt in range(MAX_RETRIES):
                response = await self._client.get(OWNERS_PATH, params=params)
                if response.status_code == 429 and attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(float(response.headers.get("Retry-After", "1")))
                    continue
                break
            if response.status_code == 403:
                self.owners_degraded = True
                print(
                    "hubspot: Owners API returned 403 — add the "
                    "'crm.objects.owners.read' scope to the Service Key to mirror "
                    "owner/team ACLs; falling back to the admin-assigned "
                    "--visibility for every record",
                    file=sys.stderr,
                )
                return {}
            response.raise_for_status()
            body = response.json()
            for owner in body.get("results", []):
                owner_id = owner.get("id")
                if owner_id is None:
                    continue
                email = (owner.get("email") or "").strip().lower()
                team_ids = tuple(
                    str(team["id"]) for team in owner.get("teams", []) or [] if team.get("id")
                )
                owners[str(owner_id)] = OwnerInfo(email=email, team_ids=team_ids)
            after = body.get("paging", {}).get("next", {}).get("after")
            if not after:
                return owners

    @staticmethod
    def _team_members(owner_map: Mapping[str, OwnerInfo]) -> dict[str, set[str]]:
        """Invert the owner roster into SpiceDB team edges: each
        ``group:hubspot-team-<id>`` → the ``user:<email>`` of every owner on
        that team (primary or secondary). This is what lets a subject resolve
        through their team to a team-owned record."""
        members: dict[str, set[str]] = {}
        for owner in owner_map.values():
            if not owner.email:
                continue
            member = owner_principal(owner.email)
            for team_id in owner.team_ids:
                members.setdefault(team_principal(team_id), set()).add(member)
        return members

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------- sink: FactEvents → the server's deterministic L1 path ----------


class _SinkAclEmitter:
    """Adapts the sink's ``resolve_principals`` to the ``resolve`` surface the
    shared ``emit_acl_change`` helper expects (a PrincipalRegistry). Reuses the
    sink's already-open client so the acl-change lane shares the batch's
    connection + auth."""

    def __init__(self, sink: "VerityDebeziumSink", client: httpx.Client) -> None:
        self._sink = sink
        self._client = client

    def resolve(self, principals: Sequence[str]) -> dict[str, int]:
        return self._sink.resolve_principals(list(principals))


@dataclass
class VerityDebeziumSink:
    """POSTs FactEvents to a running Verity server as bare Debezium-style
    payloads on ``POST /v1/ingest/debezium?tenant_id=...&pk=id`` — reusing the
    already-built deterministic L1 upsert path (one envelope in → one L0
    episode + L1 upserts, no LLM, no embedding).

    Two visibility paths, per record, mirroring HubSpot's own model:

    - **Owned records** carry an inline ``verity_acl`` with the owner+team
      tokens (``record_visibility``) and ``acl_provenance: approximated`` — an
      owner/team approximation of HubSpot record access (it cannot see per-user
      "Everything" permission or manual shares, so it under-grants; never
      ``mirrored``, which would claim a literal source ACL). :meth:`post`
      resolves the owner/team principal strings to tokens here and stamps them.
    - **Unowned records** (and the webhook lane) fall through to the
      admin-assigned ``visibility_policy`` (``--visibility``), delivered as the
      connector-bound policy on the POST query string (``?visibility=1,2``) with
      ``admin-assigned`` provenance. Inline wins over the bound policy
      server-side, so a mixed batch resolves each record correctly.
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
    def envelope(event: FactEvent) -> dict:
        """One event → one bare Debezium payload (the server accepts bare
        payloads and arrays of them; see crates/verity-server/src/ingest.rs).
        ``source.connector`` comes from the event, so this sink is shared by
        every structured CRM connector (HubSpot, Salesforce) whose events
        carry an ``object_type``; the L1 partition becomes
        ``<source>:<object_type>``.

        When the event has a resolved per-record ACL (``record_visibility``), a
        TOP-LEVEL ``verity_acl`` sibling carries it with ``approximated``
        provenance; otherwise none is emitted and the server applies the
        connector-bound admin-assigned policy from the query string."""
        payload = {
            "op": "u",
            "source": {
                "connector": event.source,
                "table": event.object_type,  # type: ignore[attr-defined]
                "ts_ms": int(event.valid_from.timestamp() * 1000),
            },
            "after": {"id": event.entity_id, event.field_name: event.value},
        }
        record_visibility = getattr(event, "record_visibility", None)
        if record_visibility is not None:
            payload["verity_acl"] = {
                "visibility": list(record_visibility),
                "confidentiality": "internal",
                "acl_provenance": "approximated",
            }
        return payload

    @staticmethod
    def _bound_visibility(events: list[FactEvent]) -> str | None:
        """The admin-assigned policy to bind on this POST, as ``"1,2"``.

        Read off the events' ``visibility_policy`` (every tier-C CRM event
        carries it). The bound policy is per-POST, so a batch MUST share one
        policy; a batch that mixes policies is a programming error and raises
        (fail closed) rather than silently applying one event's ACL to another.
        Returns ``None`` only when the events carry no policy at all — then the
        server refuses them unless they declare an inline ACL."""
        policies = {
            tuple(p)
            for e in events
            if (p := getattr(e, "visibility_policy", None)) is not None
        }
        if not policies:
            return None
        if len(policies) > 1:
            raise ValueError(
                "batch mixes visibility policies "
                f"({sorted(policies)}); the connector-bound policy is per-POST"
            )
        return ",".join(str(t) for t in next(iter(policies)))

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.admin_token}"} if self.admin_token else {}

    def resolve_principals(self, principals: list[str]) -> dict[str, int]:
        """Materialize owner/team principal strings to int tokens via
        ``POST /v1/admin/principals`` (idempotent; a principal keeps its token
        forever). Principals absent from the response stay unresolved and confer
        no visibility (fail closed)."""
        if not principals:
            return {}
        with httpx.Client(timeout=120.0, transport=self.transport) as client:
            response = client.post(
                f"{self.url.rstrip('/')}/v1/admin/principals",
                json={"tenant_id": self.tenant_id, "principals": list(principals)},
                headers=self._headers(),
            )
            response.raise_for_status()
            return {
                principal: token
                for principal, token in response.json().get("mappings", {}).items()
                if isinstance(token, int)
            }

    def sync_group_edges(self, group_members: Mapping[str, set[str]]) -> int:
        """Write group-membership edges into SpiceDB via ``POST /v1/admin/groups``
        (``group ⊃ member``), so a subject resolves through the group to
        group-scoped records. Eagerly allocates each group's token. Deterministic
        order (groups sorted, members sorted within each). Returns the edge count.
        No-op (0) on an empty map.

        Source-neutral: ``group`` is any principal string and ``member`` may be a
        ``user:<…>`` OR another ``group:<…>`` — the endpoint is nest-capable, so
        HubSpot's flat ``group:hubspot-team-<id> ⊃ user:<email>`` edges and
        Salesforce's NESTED ``group:salesforce-group-<parent> ⊃
        group:salesforce-group-<child>`` edges both flow through unchanged."""
        if not group_members:
            return 0
        written = 0
        with httpx.Client(timeout=120.0, transport=self.transport) as client:
            for group in sorted(group_members):
                for member in sorted(group_members[group]):
                    response = client.post(
                        f"{self.url.rstrip('/')}/v1/admin/groups",
                        json={"tenant_id": self.tenant_id, "group": group, "member": member},
                        headers=self._headers(),
                    )
                    response.raise_for_status()
                    written += 1
        return written

    #: Back-compat alias — HubSpot's flat team edges are just group edges.
    sync_team_edges = sync_group_edges

    def _stamp_record_visibility(self, events: list[FactEvent]) -> None:
        """Resolve every owned record's owner/team principals to tokens in one
        round-trip and stamp ``record_visibility`` on those events. Unowned
        events are left untouched (they use the admin-assigned fallback). The
        owner principal is minted on demand, so an owned record always resolves
        to at least its owner — it can never silently degrade to the broader
        admin fallback.

        The write-path choke point (crates/verity-server/src/ingest.rs) applies
        an inline ``verity_acl`` with REPLACE semantics — it wins over the
        connector-bound admin ``?visibility=`` policy (``parse_inline_acl().
        or_else(bound_policy)``), it does NOT union with it. So for a connector
        whose per-record ACL is a known SUBSET of effective visibility (e.g.
        Salesforce AccountShare, which omits OWD / role hierarchy / sharing
        rules / implicit parent→child / territories), stamping the resolved
        tokens alone would silently DROP the admin floor. Such an event opts in
        via a truthy ``union_policy_floor`` attribute: its ``visibility_policy``
        tokens are UNIONed into ``record_visibility`` so the inline block is a
        superset of the floor (over-hide, never under-hide). HubSpot events do
        not set the attribute and are unaffected."""
        distinct = sorted(
            {p for e in events for p in (getattr(e, "record_principals", None) or [])}
        )
        if not distinct:
            return
        tokens = self.resolve_principals(distinct)
        for event in events:
            principals = getattr(event, "record_principals", None)
            if not principals:
                continue
            resolved = [tokens[p] for p in principals if p in tokens]
            if resolved and getattr(event, "union_policy_floor", False):
                # UNION the admin floor in (dedup, floor first) so the inline
                # REPLACE-semantics block is a superset of the bound policy.
                floor = list(getattr(event, "visibility_policy", None) or [])
                resolved = list(dict.fromkeys([*floor, *resolved]))
            event.record_visibility = resolved or None  # type: ignore[attr-defined]

    def post(self, events: list[FactEvent], cursor: str | None = None) -> dict:
        """POST a batch; returns the server's write summary.

        Owned records get their owner/team principals resolved to tokens and
        stamped as an inline ``approximated`` ACL; unowned records ride the
        connector-bound admin-assigned ``?visibility=`` policy.

        After a successful delivery a best-effort heartbeat goes to
        ``POST /v1/admin/connector-status`` (source, batch size, newest event
        time, and — when the runner passes it — the cursor). A heartbeat
        failure NEVER fails the sync: the facts are already committed and the
        heartbeat is telemetry (see migrations/0012_connector_status.sql).
        """
        if not events:
            return {"written": 0, "superseded": 0, "retired": 0, "unchanged": 0}
        self._stamp_record_visibility(events)
        headers = {}
        if self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        params = {"tenant_id": self.tenant_id, "pk": self.pk}
        bound = self._bound_visibility(events)
        if bound is not None:
            params["visibility"] = bound
        with httpx.Client(timeout=30.0, transport=self.transport) as client:
            response = client.post(
                f"{self.url.rstrip('/')}/v1/ingest/debezium",
                params=params,
                json=[self.envelope(e) for e in events],
                headers=headers,
            )
            response.raise_for_status()
            summary = response.json()
            self._heartbeat(client, headers, events, cursor)
            return summary

    def emit_acl_changes(self, events: list[HubSpotFactEvent], state: AclState) -> int:
        """ACL-diff lane (additive): diff each RECORD's owner/team principal set
        against its last-seen set and, on a TIGHTENING, POST an acl-change per
        derived fact key so the server retracts the lost principal.

        A record fans out to one FactEvent per field; the ACL is a per-record
        property (all its facts share ``record_principals``), so we diff ONCE per
        ``entity_id`` (keyed with the object type, since the same id can recur
        across object types) and emit per ``(source, entity_id, field)`` fact key.
        Owner/team-scoped records only — an unowned record has no per-record ACL
        to diff (it rides the admin-assigned bound policy). Returns the number of
        acl-change POSTs. Purely additive; never affects the fact-delivery count.
        """
        with httpx.Client(timeout=30.0, transport=self.transport) as client:
            emitter = _SinkAclEmitter(self, client)
            emitted = 0
            # Group fields by record so the diff runs once per record.
            by_record: dict[str, list[HubSpotFactEvent]] = {}
            for e in events:
                if not getattr(e, "record_principals", None):
                    continue
                # source keyed to the L1 partition the server builds:
                # "{connector}:{object_type}".
                key = f"{e.object_type}:{e.entity_id}"
                by_record.setdefault(key, []).append(e)
            for facts in by_record.values():
                first = facts[0]
                fact_source = f"{first.source}:{first.object_type}"
                record_id = f"{first.object_type}:{first.entity_id}"
                change = diff_acl(
                    state,
                    record_id,
                    list(first.record_principals or []),
                    source=fact_source,
                    entity_id=first.entity_id,
                    field=first.field_name,
                )
                if change is None:
                    continue
                # Retract EVERY derived fact key of this record (one per field).
                for f in facts:
                    per_field = AclChange(
                        source=fact_source,
                        entity_id=f.entity_id,
                        field=f.field_name,
                        new_principals=change.new_principals,
                        removed_principals=change.removed_principals,
                    )
                    emit_acl_change(
                        per_field,
                        tenant_id=self.tenant_id,
                        registry=emitter,
                        client=client,
                        base_url=self.url,
                    )
                    emitted += 1
            state.flush()
            return emitted

    def _heartbeat(
        self,
        client: httpx.Client,
        headers: dict,
        events: list[FactEvent],
        cursor: str | None,
    ) -> None:
        """Best-effort connector heartbeat; swallows every failure."""
        try:
            body = {
                "tenant_id": self.tenant_id,
                "source": events[0].source,
                "items_synced": len(events),
                "last_event_at": max(e.valid_from for e in events).isoformat(),
            }
            if cursor is not None:
                body["cursor"] = cursor
            client.post(
                f"{self.url.rstrip('/')}/v1/admin/connector-status",
                json=body,
                headers=headers,
            )
        except Exception:  # noqa: BLE001 — telemetry must never fail the sync
            pass


# ---------- runner ----------


def _read_cursor(state_file: Path) -> str | None:
    try:
        return state_file.read_text().strip() or None
    except FileNotFoundError:
        return None


def _write_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(cursor + "\n")


def _read_credential_file(path: Path) -> str:
    """Read the bearer token from a 0600 credential file (server-materialized).

    The token is the file body (never argv/env — argv is world-visible via
    ``/proc``). Trailing newline is stripped. The token is NEVER echoed or
    logged. Enforces owner-only 0600 permissions (fail closed on a laxer mode —
    a decrypted bearer must not be group/world-readable). An empty file is
    rejected here so the error is attributable to the flag, not a downstream
    missing-env message.
    """
    st = path.stat()
    if st.st_mode & 0o077:
        raise PermissionError(
            f"--credential-file {path} must be 0600 (owner-only); "
            f"found mode {st.st_mode & 0o777:o}"
        )
    token = path.read_text().rstrip("\n")
    if not token.strip():
        raise ValueError(f"--credential-file {path} is empty (no bearer token)")
    return token


def run_backfill(
    connector: HubSpotConnector,
    sink: VerityDebeziumSink,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 1,
) -> int:
    """§5a reconciliation backfill: drive :meth:`HubSpotConnector.full_crawl`
    (a poll from epoch over contacts/companies/deals) into the sink, reporting
    progress to the backfill dashboard.

    Mirrors gdrive/gmail ``run_backfill`` exactly in lifecycle — one-shot,
    ``total=None`` up front (the search API gives no cheap count), a crash
    reports a ``failed`` run and re-raises, a clean finish marks ``completed`` —
    but delivers HubSpot's fact envelopes via :meth:`VerityDebeziumSink.post`
    (+ :meth:`sync_team_edges`), NOT gmail's DocumentSink.

    Owner/team edges are synced FIRST so a subject resolves through their team
    the moment the team-owned facts land. When the owners scope 403-degraded the
    whole run (``connector.owners_degraded``), the reporter's clean finish
    carries the distinct :data:`DEGRADED_ACL_SIGNAL` note and the runner prints
    the stable stdout token — so the server surfaces ``state=degraded_acl``
    rather than a silent success. Returns the number of delivered fact events."""
    if reporter is not None:
        reporter.start(total=None)
    delivered = 0
    pending = 0
    collected: list[HubSpotFactEvent] = []

    async def _crawl() -> None:
        async for event in connector.full_crawl():
            collected.append(event)  # type: ignore[arg-type]

    try:
        asyncio.run(_crawl())
        # Sync team membership FIRST so a subject can resolve through their team
        # the moment the team-owned facts land (identical to the --once runner).
        sink.sync_team_edges(connector.team_members)
        for start in range(0, len(collected), max(1, flush_every)):
            batch = collected[start : start + max(1, flush_every)]
            sink.post(batch)
            delivered += len(batch)
            pending += len(batch)
            if reporter is not None and pending >= flush_every:
                reporter.advance(pending)
                pending = 0
    except Exception as exc:  # noqa: BLE001 — surface as a failed run, then re-raise
        if reporter is not None:
            if pending:
                reporter.advance(pending)
            reporter.fail(exc)
        raise
    if reporter is not None:
        if pending:
            reporter.advance(pending)
        # A run whose owners scope 403-degraded finishes CLEAN (the rows landed)
        # but carries the distinct degraded_acl note so the server surfaces it.
        reporter.finish(error=DEGRADED_ACL_SIGNAL if connector.owners_degraded else None)
    if connector.owners_degraded:
        # Stable, machine-readable stdout token — the read-once contract the
        # server greps for backfill state=degraded_acl (never stderr-only).
        print(DEGRADED_ACL_SIGNAL)
    return delivered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.hubspot",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument("--once", action="store_true", help="run one truth-lane poll cycle")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the §5a reconciliation backfill (poll from epoch over "
        "contacts/companies/deals) once, reporting progress to the backfill "
        "dashboard, then exit (one-shot; wins over --once)",
    )
    parser.add_argument(
        "--webhook-file",
        type=Path,
        help="process a recorded HubSpot v3 webhook payload (JSON array)",
    )
    parser.add_argument(
        "--credential-file",
        type=Path,
        default=None,
        help="read the HubSpot bearer token from this 0600 file (the file BODY, "
        "trailing newline stripped) — PREFERRED over HUBSPOT_SERVICE_KEY / "
        "HUBSPOT_PRIVATE_APP_TOKEN env so a server spawn never puts the token in "
        "argv or the child environment; never echoed or logged",
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

    # --backfill is the one-shot reconciliation mode and WINS over --once (a
    # server spawn passes --backfill; --once is ignored if both slip in). Absent
    # --backfill, exactly one of --once / --webhook-file is required (unchanged).
    if not args.backfill and args.once == bool(args.webhook_file):
        parser.error(
            "exactly one of --backfill, --once, or --webhook-file is required"
        )
    if args.backfill and args.webhook_file:
        parser.error("--backfill and --webhook-file are mutually exclusive")

    # --credential-file wins over both env vars: read the bearer from the 0600
    # file (server spawn channel; token is the file body, never argv/env).
    cred_token: str | None = None
    if args.credential_file is not None:
        cred_token = _read_credential_file(args.credential_file)

    sink = VerityDebeziumSink.from_env()

    if args.webhook_file:
        payload = json.loads(args.webhook_file.read_text())
        events = HubSpotConnector.handle_webhook(payload, policy)
        summary = sink.post(events)
        print(f"webhook: {len(events)} fact event(s) -> {summary}")
        return 0

    if args.backfill:
        # A backfill is a one-shot job, not the poll loop. A server-triggered
        # backfill pre-mints the run_id and passes it via VERITY_BACKFILL_RUN_ID
        # so the console panel can poll GET /v1/admin/backfill keyed on THIS run;
        # a CLI backfill leaves it unset and the reporter self-mints (uuid4).
        run_id = os.environ.get("VERITY_BACKFILL_RUN_ID") or None
        backfill_connector = HubSpotConnector(policy, token=cred_token)
        try:
            reporter = BackfillReporter(
                sink.url,
                sink.tenant_id,
                backfill_connector.name,
                api_key=sink.admin_token,
                run_id=run_id,
            )
            delivered = run_backfill(backfill_connector, sink, reporter)
        finally:
            asyncio.run(backfill_connector.aclose())
        print(f"hubspot: backfill delivered {delivered} fact event(s)")
        return 0

    async def run_once() -> tuple[list[HubSpotFactEvent], str, dict[str, set[str]]]:
        connector = HubSpotConnector(policy, token=cred_token)
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            # team_members is the source of the SpiceDB edges; capture it before
            # the client closes.
            return list(events), next_cursor, dict(connector.team_members)  # type: ignore[arg-type]
        finally:
            await connector.aclose()

    events, next_cursor, team_members = asyncio.run(run_once())
    # Sync team membership FIRST so a subject can resolve through their team the
    # moment the team-owned facts land.
    edges = sink.sync_team_edges(team_members)
    summary = sink.post(events, cursor=next_cursor)
    _write_cursor(args.state_file, next_cursor)
    # ACL-diff lane (additive): retract records whose owner/team access tightened
    # since the last sync. Best-effort — a failure here never fails a sync whose
    # facts already committed. Sidecar sits next to the cursor file.
    retracted = 0
    try:
        acl_state = AclState(args.state_file.with_suffix(args.state_file.suffix + ".acl"))
        retracted = sink.emit_acl_changes(events, acl_state)
    except Exception as exc:  # noqa: BLE001 — additive lane must not fail the sync
        print(f"hubspot: acl-diff lane skipped: {exc}", file=sys.stderr)
    owned = sum(1 for e in events if getattr(e, "record_principals", None))
    print(
        f"poll: {len(events)} fact event(s) ({owned} owner/team-scoped, "
        f"{edges} team edge(s), {retracted} acl-change retraction(s)), "
        f"cursor -> {next_cursor} -> {summary}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
