"""Notion ingestion connector (SPEC.md §5, §5e.2) — FIXTURES-ONLY.

Auth is bring-your-own-token (BYOT doctrine): a **Notion internal
integration token** (or an OAuth access token / PAT) created in the customer's
own workspace and shared with the pages the integration should see. Read from
env ``NOTION_TOKEN`` and used as ``Authorization: Bearer <token>`` against the
Notion REST API (``https://api.notion.com``) with the pinned ``Notion-Version``
header. The bearer is a STATIC key — there is no refresh lifecycle; a 401 means
"rotate the token" (misconfiguration), surfaced loudly rather than retried.

There are no live Notion tokens in this environment: this connector is built
and proven ENTIRELY against recorded fixtures via ``httpx.MockTransport`` (the
same pattern as the Salesforce connector). A live smoke is GATED on the user
supplying ``NOTION_TOKEN`` and is never faked.

Two lanes:

- **Truth lane** — ``poll(cursor)`` lists ``page`` and ``database`` objects via
  ``POST /v1/search`` sorted ascending by ``last_edited_time``, following
  ``next_cursor``/``has_more`` pagination. Search SORTS by ``last_edited_time``
  but does NOT filter by it, so the connector applies a client-side
  ``last_edited_time > cursor`` gate and early-stops (results are ascending).
  Each non-null scalar page ``property`` maps to one FactEvent keyed
  ``(source="notion", entity_id=page.id, field=property_name)``; the cursor is
  the max ``last_edited_time`` seen, stored as the API returned it (RFC-3339). A
  ≤1s replay is safe: delivery is at-least-once into deterministic keyed L1
  upserts. ``--with-content`` additionally fetches page bodies via
  ``GET /v1/blocks/{page_id}/children`` as DocumentEvents.
- **Push lane** — Notion has no CDC/webhook transport this poll-first connector
  speaks; ``push_events`` is a documented no-op and the truth lane reconciles.

ACL honesty (read this before trusting anything about audience):

Notion is a "NO ACL TABLE" source. The public API exposes **no endpoint and no
field** that enumerates who a page is shared with — page/database/block objects
carry no permissions field, teamspace membership is not exposed per page, and
guest grants are invisible. What the API can TRUTHFULLY tell you is only:

- **Which records the integration was GRANTED access to** — ``/v1/search``
  returns solely content the admin connected the integration to. This is an
  admin-chosen access FLOOR, NOT the page's real audience.
- **Workspace members and their emails** — via ``/v1/users`` (guests excluded;
  bots and email-less persons carry no email).
- **Structural parentage** — ``parent.type`` (workspace / database_id / page_id
  / block_id) plus ``created_by`` / ``last_edited_by``. None of that is an
  audience.

Therefore the enforced ACL on EVERY record is the **admin-assigned**
``--visibility`` policy (required on the constructor, NO DEFAULT — fail closed).
There are no per-record share principals to derive, so ``record_principals`` is
always ``None`` and every record rides the admin floor, delivered as the
connector-bound ``?visibility=`` policy (delivery-path provenance
``admin-assigned``). Where a per-record inline ACL is ever stamped its
provenance is :data:`SHARE_ACL_PROVENANCE` = ``"approximated"`` — NEVER
``"mirrored"``: Salesforce earns "approximated" from a real (if incomplete)
``AccountShare`` table, but Notion has NO share table at all, so "approximated"
here is even weaker — a documented admin-declared under-granting floor.

Authorship (``created_by`` / ``last_edited_by`` / ``people`` properties) is
resolved to informational ``user:<email.lower()>`` strings via ``/v1/users`` and
attached to ``raw_payload`` ONLY — it is authorship, NOT audience, and is NEVER
folded into ``record_visibility``. A ``/v1/users`` failure degrades authorship
rendering alone (those informational strings drop); it never widens or gates the
admin-floored facts, so it is NOT a DEGRADED_ACL_SIGNAL condition (the enforced
admin policy is unaffected — simpler than Salesforce, which has a real share
table to degrade).

Fail closed: no ``--visibility`` ⇒ constructor rejects ⇒ nothing ships; a record
with no ``id`` or an ``object`` that is not page/database ⇒ QUARANTINE (skip +
count), never emitted with a guessed ACL.

NOTE (identity crosswalk): principals use the CURRENT email-based convention
(``user:<email.lower()>``). The identity-crosswalk workflow on ``main`` will
later swap these for canonical identity tokens; this connector is written to
merge cleanly with that, and a crosswalk update follows.

Sink: the same :class:`~verity_ingest.connectors.hubspot.VerityDebeziumSink` as
HubSpot/Salesforce (source-generic; imported, never forked) — one bare Debezium
payload per event, ``op: "u"``, ``source.connector: "notion"``,
``source.table`` the object type (``page``/``database``).

Runner::

    python -m verity_ingest.connectors.notion --once --visibility 1,2
    python -m verity_ingest.connectors.notion --once --visibility 1,2 --with-content
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import httpx

from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.credentials import StaticKey

logger = logging.getLogger(__name__)

SOURCE = "notion"
BASE_URL = "https://api.notion.com"
#: Pinned Notion API version (sent on every request as ``Notion-Version``) so
#: response shapes stay stable across Notion's dated releases.
NOTION_VERSION = "2022-06-28"
#: BYOT credential env var: a Notion internal-integration token / OAuth access
#: token / PAT. Used only as ``Authorization: Bearer <token>``; never logged.
NOTION_TOKEN_ENV = "NOTION_TOKEN"
SEARCH_PATH = "/v1/search"
USERS_PATH = "/v1/users"
PAGE_SIZE = 100  # Notion search/list maximum
MAX_RETRIES = 5

#: Provenance intent of any per-record inline ACL this connector could stamp
#: (SPEC §5e: mirrored | approximated | admin-assigned | quarantined). Notion
#: has NO share table, so a derived audience could only ever be "approximated"
#: (an admin-declared under-granting floor) — never "mirrored". In practice this
#: connector derives no per-record audience, so every record takes the
#: admin-assigned --visibility floor; the constant documents the ceiling.
SHARE_ACL_PROVENANCE = "approximated"

#: Stable, machine-readable stdout token the server greps for backfill
#: ``state=degraded_acl`` (connector-agnostic — identical value across
#: connectors). Notion does NOT emit it: there is no per-record ACL to degrade
#: (the enforced ACL is the admin policy, unaffected by a roster failure). The
#: constant exists so the framework shape matches the other connectors.
DEGRADED_ACL_SIGNAL = "verity.backfill.degraded_acl"

#: Property/record keys never emitted as facts: the pk mirror, the object tag,
#: the URL, the timestamps (``last_edited_time`` becomes ``valid_from``), and
#: the archived flag. ``parent`` / ``created_by`` / ``last_edited_by`` are ACL/
#: authorship plumbing carried on ``raw_payload`` only, never as facts.
_METADATA_FIELDS = {
    "object",
    "id",
    "url",
    "last_edited_time",
    "created_time",
    "archived",
    "parent",
    "created_by",
    "last_edited_by",
}

#: Object types this connector mirrors from ``/v1/search``. A ``data_source``
#: is Notion's newer name for a database; both map to ``database`` here.
_PAGE_OBJECT = "page"
_DATABASE_OBJECTS = {"database", "data_source"}


def user_principal(email: str) -> str:
    """An authorship principal, lowercased ``user:<email>`` so it is the SAME
    SpiceDB object a Gmail/Drive/HubSpot subject resolves to — one human is one
    identity across every source. In Notion this is INFORMATIONAL (authorship,
    carried on ``raw_payload``), NEVER audience: the API cannot prove who a page
    is shared with, so authorship is never folded into enforced visibility."""
    return f"user:{email.lower()}"


def group_principal(teamspace_id: str) -> str:
    """A teamspace-visibility principal, a SpiceDB group. Defined for shape
    parity with the other connectors, but the Notion public API does NOT expose
    teamspace membership per page, so this connector emits no such principal —
    there is no provable Notion group to mirror (see the module ACL-honesty
    docstring). Left in place so a future crosswalk can populate it."""
    return f"group:notion-teamspace-{teamspace_id}"


@dataclass(frozen=True)
class NotionUserInfo:
    """One workspace ``person`` reduced to the authorship join key: the
    lowercased email. Bots and email-less persons yield no roster entry and are
    dropped (they contribute no authorship principal)."""

    email: str


@dataclass
class NotionFactEvent(FactEvent):
    """A FactEvent plus what structured ingestion requires.

    Visibility precedence, per record:
    - ``record_principals`` — a per-record audience, or ``None``. For Notion it
      is ALWAYS ``None``: the public API exposes no share audience, so every
      record rides the admin-assigned ``visibility_policy`` floor (fail closed;
      never a guessed audience). The field exists for framework parity and so a
      future crosswalk can populate it without a shape change.
    - ``record_visibility`` — those strings resolved to int tokens by the shared
      sink; ``None`` here (no ``record_principals`` to resolve).
    - ``visibility_policy`` — the admin-assigned ``--visibility`` floor, the
      HONEST primary (not a fallback) since there is nothing better to derive.

    ``authorship`` carries the informational ``user:<email>`` strings for the
    record's ``created_by``/``last_edited_by``/``people`` — authorship, NOT
    audience; it is NEVER folded into ``record_visibility``.
    """

    object_type: str
    visibility_policy: list[int]
    record_principals: list[str] | None = None
    record_visibility: list[int] | None = None
    authorship: list[str] = field(default_factory=list)
    #: The admin ``--visibility`` floor is a genuine floor that must never be
    #: dropped, so if an inline ACL is ever stamped the sink UNIONs the floor in
    #: (superset semantics). In practice no inline ACL is stamped (no
    #: ``record_principals``), so this is inert — but honest if that changes.
    union_policy_floor: bool = True


def _parse_notion_timestamp(value: str) -> datetime:
    """Notion returns RFC-3339 UTC timestamps (e.g. ``2026-07-08T18:04:57.000Z``
    or ``...+00:00``); both the ``Z`` and offset forms are handled."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _rich_text_plain(value: Any) -> str:
    """Concatenate a Notion ``rich_text``/``title`` array to its plain text."""
    if not isinstance(value, list):
        return ""
    return "".join(part.get("plain_text", "") for part in value if isinstance(part, dict))


def _flatten_property(prop: Mapping[str, Any]) -> Any:
    """Flatten one Notion page ``property`` object to a scalar display value (or
    ``None`` when empty). Covers the common scalar property types; an unknown /
    unsupported type yields ``None`` and is skipped (never a guessed value)."""
    ptype = prop.get("type")
    if ptype in ("title", "rich_text"):
        text = _rich_text_plain(prop.get(ptype))
        return text or None
    if ptype == "number":
        return prop.get("number")
    if ptype == "checkbox":
        return prop.get("checkbox")
    if ptype == "url":
        return prop.get("url")
    if ptype == "email":
        return prop.get("email")
    if ptype == "phone_number":
        return prop.get("phone_number")
    if ptype == "select":
        sel = prop.get("select")
        return sel.get("name") if isinstance(sel, dict) else None
    if ptype == "status":
        st = prop.get("status")
        return st.get("name") if isinstance(st, dict) else None
    if ptype == "multi_select":
        opts = prop.get("multi_select") or []
        names = [o.get("name") for o in opts if isinstance(o, dict) and o.get("name")]
        return ", ".join(names) if names else None
    if ptype == "date":
        date = prop.get("date")
        if not isinstance(date, dict) or not date.get("start"):
            return None
        return f"{date['start']}/{date['end']}" if date.get("end") else date["start"]
    if ptype == "people":
        people = prop.get("people") or []
        ids = [p.get("id") for p in people if isinstance(p, dict) and p.get("id")]
        return ", ".join(ids) if ids else None
    return None  # unknown/unsupported type → skipped (never guessed)


def _person_ids(record: Mapping[str, Any]) -> list[str]:
    """Collect the workspace-person ids referenced by a record's authorship
    (``created_by``/``last_edited_by``) and any ``people`` properties, in a
    deterministic order. Used to render informational authorship principals."""
    ids: list[str] = []
    for key in ("created_by", "last_edited_by"):
        ref = record.get(key)
        if isinstance(ref, dict) and ref.get("id"):
            ids.append(str(ref["id"]))
    for prop in (record.get("properties") or {}).values():
        if isinstance(prop, dict) and prop.get("type") == "people":
            for person in prop.get("people") or []:
                if isinstance(person, dict) and person.get("id"):
                    ids.append(str(person["id"]))
    seen: set[str] = set()
    ordered: list[str] = []
    for pid in ids:
        if pid not in seen:
            seen.add(pid)
            ordered.append(pid)
    return ordered


def _authorship_principals(
    record: Mapping[str, Any], users_map: Mapping[str, str]
) -> list[str]:
    """Render a record's person ids → informational ``user:<email>`` strings via
    the workspace roster. Ids with no roster email (bots, guests, email-less
    persons) are dropped. Order-preserving, deduplicated."""
    principals: list[str] = []
    for pid in _person_ids(record):
        email = users_map.get(pid)
        if not email:
            continue
        principal = user_principal(email)
        if principal not in principals:
            principals.append(principal)
    return principals


class NotionConnector(Connector):
    """Truth-lane polling connector for Notion pages/databases.

    ``visibility_policy`` is required and has no default (fail closed; see the
    module docstring — Notion has no share table, so the admin-assigned policy
    is the enforced ACL, not a fallback). Credential defaults to the env
    ``NOTION_TOKEN`` static bearer.
    """

    name = SOURCE

    def __init__(
        self,
        visibility_policy: list[int],
        *,
        token: str | None = None,
        credential: StaticKey | None = None,
        base_url: str = BASE_URL,
        with_content: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.visibility_policy = list(visibility_policy)
        self.with_content = with_content
        #: Filled by :meth:`poll` from ``/v1/users``: workspace ``person`` id →
        #: lowercased email. Authorship-only; never audience.
        self.users_map: dict[str, str] = {}
        #: Set True by :meth:`_fetch_users` when the roster fetch fails.
        #: Authorship rendering degrades (informational strings drop); the
        #: enforced admin-floor facts are UNAFFECTED, so this is NOT a
        #: DEGRADED_ACL_SIGNAL condition.
        self.users_degraded: bool = False
        #: Count of records skipped as unparseable (no id / not a page or
        #: database) — quarantined, never emitted with a guessed ACL.
        self.quarantined: int = 0

        # Static bearer credential via the shared abstraction. A Notion token
        # has no refresh lifecycle: a 401 means "rotate the token", never
        # "retry". Token flows ONLY into the Authorization header — never logged.
        self.credential = credential or StaticKey(
            NOTION_TOKEN_ENV,
            value=token,
            missing_hint="a Notion internal-integration token / OAuth access "
            "token / PAT (BYOT — create an integration in YOUR OWN workspace and "
            f"share the target pages with it); set {NOTION_TOKEN_ENV}",
        )
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {self.credential.value}",
                "Notion-Version": NOTION_VERSION,
            },
            timeout=30.0,
        )

    # ---------- deterministic mapping (pure; exercised by conformance tests) ----------

    @classmethod
    def events_from_search_page(
        cls,
        page: dict,
        visibility_policy: list[int],
        users_map: Mapping[str, str] | None = None,
    ) -> tuple[list[NotionFactEvent], int]:
        """Map one ``/v1/search`` response page to FactEvents, returning
        ``(events, quarantined)``.

        One event per non-null scalar property, sorted by property name for
        determinism; ``id`` is the entity id, ``last_edited_time`` becomes
        ``valid_from``, and metadata/plumbing keys (see ``_METADATA_FIELDS``) are
        never facts. A record with no ``id`` or an ``object`` that is not a page
        or database is QUARANTINED (skipped + counted), never emitted with a
        guessed ACL. ``record_principals`` stays ``None`` — Notion exposes no
        per-record audience, so every event rides the admin ``visibility_policy``
        floor. Authorship person ids are rendered to informational
        ``user:<email>`` strings on ``authorship``/``raw_payload`` only.
        """
        events: list[NotionFactEvent] = []
        quarantined = 0
        roster = users_map or {}
        for record in page.get("results", []):
            obj = record.get("object")
            record_id = record.get("id")
            if not record_id or (obj != _PAGE_OBJECT and obj not in _DATABASE_OBJECTS):
                quarantined += 1
                continue
            object_type = _PAGE_OBJECT if obj == _PAGE_OBJECT else "database"
            edited = record.get("last_edited_time")
            if not edited:
                quarantined += 1
                continue
            valid_from = _parse_notion_timestamp(edited)
            authorship = _authorship_principals(record, roster)
            fields: dict[str, Any] = {}
            for name, prop in (record.get("properties") or {}).items():
                if name in _METADATA_FIELDS or not isinstance(prop, dict):
                    continue
                flattened = _flatten_property(prop)
                if flattened is None:
                    continue
                fields[name] = flattened
            for name in sorted(fields):
                events.append(
                    NotionFactEvent(
                        source=SOURCE,
                        entity_id=str(record_id),
                        field_name=name,
                        value=fields[name],
                        valid_from=valid_from,
                        raw_payload=record,
                        object_type=object_type,
                        visibility_policy=list(visibility_policy),
                        record_principals=None,  # no provable audience → admin floor
                        authorship=list(authorship),
                    )
                )
        return events, quarantined

    # ---------- lanes ----------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op by design: Notion exposes no CDC/webhook transport this
        poll-first connector speaks; the truth lane reconciles everything."""
        return
        yield  # pragma: no cover — makes this an (empty) async generator

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """One truth-lane cycle: list pages/databases via ``POST /v1/search``
        sorted ascending by ``last_edited_time``, applying a client-side
        ``last_edited_time > cursor`` gate (Search sorts but does not filter).
        Records at/older-than the cursor are individually skipped (``continue``),
        but paging continues until ``has_more`` is exhausted so newer records on
        later pages are never dropped. (An ascending scan CANNOT early-stop on the
        first ``<=cursor`` record: everything after it is NEWER, not older — unlike
        the descending article lane in the Intercom connector, which can.) Returns
        the events and the max ``last_edited_time`` seen as the next cursor.

        The workspace roster is fetched ONCE per cycle for authorship rendering
        only (informational); a roster failure degrades authorship strings but
        NEVER gates or widens the admin-floored facts (fail closed by
        construction — the enforced ACL is the admin ``--visibility`` policy).
        With ``--with-content`` each page also yields a DocumentEvent of its
        block body (blocks inherit the page's admin-floor visibility).
        """
        events: list[FactEvent | DocumentEvent] = []
        next_cursor = cursor or "1970-01-01T00:00:00.000Z"
        self.users_map = await self._fetch_users()
        cursor_dt = _parse_notion_timestamp(cursor) if cursor else None
        async for page in self._search_pages():
            gated: dict[str, Any] = {"results": []}
            for record in page.get("results", []):
                edited = record.get("last_edited_time")
                if cursor_dt is not None and edited and _parse_notion_timestamp(edited) <= cursor_dt:
                    # Skip this stale record but keep paging: an ascending scan
                    # places NEWER records after older ones, so a later page may
                    # still hold records > cursor. NEVER early-stop here.
                    continue
                gated["results"].append(record)
                if edited and _parse_notion_timestamp(edited) > _parse_notion_timestamp(
                    next_cursor
                ):
                    next_cursor = edited
            page_events, quarantined = self.events_from_search_page(
                gated, self.visibility_policy, self.users_map
            )
            events.extend(page_events)
            self.quarantined += quarantined
            if self.with_content:
                for record in gated["results"]:
                    if record.get("object") == _PAGE_OBJECT:
                        doc = await self._fetch_page_document(record)
                        if doc is not None:
                            events.append(doc)
        return events, next_cursor

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl: identical to a poll from epoch (no cursor gate,
        every granted page re-read)."""
        events, _ = await self.poll(None)
        for event in events:
            yield event

    # ---------- HTTP plumbing ----------

    async def _search_pages(self) -> AsyncIterator[dict]:
        """``POST /v1/search`` sorted ascending by ``last_edited_time``,
        following ``next_cursor``/``has_more`` pagination."""
        start_cursor: str | None = None
        while True:
            body: dict[str, Any] = {
                "sort": {"timestamp": "last_edited_time", "direction": "ascending"},
                "page_size": PAGE_SIZE,
            }
            if start_cursor is not None:
                body["start_cursor"] = start_cursor
            page = await self._post_with_retry(SEARCH_PATH, body)
            yield page
            if not page.get("has_more"):
                return
            start_cursor = page.get("next_cursor")
            if not start_cursor:
                return

    async def _fetch_users(self) -> dict[str, str]:
        """The workspace member roster: ``person`` id → lowercased email, for
        INFORMATIONAL authorship rendering only. Bots and email-less persons are
        dropped; guests are excluded from ``/v1/users`` by Notion. A failure
        degrades authorship rendering (strings drop) but NEVER gates the
        admin-floored facts — it is not a DEGRADED_ACL_SIGNAL condition."""
        users: dict[str, str] = {}
        start_cursor: str | None = None
        try:
            while True:
                params: dict[str, Any] = {"page_size": PAGE_SIZE}
                if start_cursor is not None:
                    params["start_cursor"] = start_cursor
                page = await self._get_with_retry(USERS_PATH, params)
                for person in page.get("results", []):
                    if person.get("type") != "person":
                        continue  # bots carry no email
                    user_id = person.get("id")
                    email = ((person.get("person") or {}).get("email") or "").strip().lower()
                    if user_id and email:
                        users[str(user_id)] = email
                if not page.get("has_more"):
                    break
                start_cursor = page.get("next_cursor")
                if not start_cursor:
                    break
        except httpx.HTTPError as exc:
            # Authorship-only: the admin-floor facts are unaffected, so this is a
            # WARNING, not a DEGRADED_ACL_SIGNAL (no per-record ACL to degrade).
            self.users_degraded = True
            print(
                "notion: /v1/users roster fetch failed "
                f"({exc}); authorship metadata omitted — facts ride the "
                "admin-assigned --visibility floor unaffected",
                file=sys.stderr,
            )
            return {}
        return users

    async def _fetch_page_document(self, record: Mapping[str, Any]) -> DocumentEvent | None:
        """Fetch a page's block body via ``GET /v1/blocks/{id}/children`` and
        concatenate its ``rich_text`` into a DocumentEvent. Blocks carry NO
        permission field, so the document inherits the page's admin-floor
        visibility — the ACL envelope is marked ``resolvable`` because the
        enforced policy (the admin ``--visibility`` floor) is applied on delivery
        via the connector-bound ``?visibility=`` policy, not via principals."""
        page_id = record.get("id")
        if not page_id:
            return None
        texts: list[str] = []
        start_cursor: str | None = None
        while True:
            params: dict[str, Any] = {"page_size": PAGE_SIZE}
            if start_cursor is not None:
                params["start_cursor"] = start_cursor
            page = await self._get_with_retry(f"/v1/blocks/{page_id}/children", params)
            for block in page.get("results", []):
                btype = block.get("type")
                body = block.get(btype) if isinstance(btype, str) else None
                if isinstance(body, dict):
                    text = _rich_text_plain(body.get("rich_text"))
                    if text:
                        texts.append(text)
            if not page.get("has_more"):
                break
            start_cursor = page.get("next_cursor")
            if not start_cursor:
                break
        content = "\n".join(texts).encode("utf-8")
        return DocumentEvent(
            source=SOURCE,
            document_id=str(page_id),
            content=content,
            mime_type="text/plain",
            version=str(record.get("last_edited_time") or ""),
            # The admin --visibility floor is the enforced policy; there are no
            # source principals to map, so the envelope is resolvable (the floor
            # applies on delivery), never a guessed per-page audience.
            acl=AclEnvelope(resolvable=True, principals=[], groups=[]),
        )

    async def _post_with_retry(self, path: str, body: dict) -> dict:
        """POST honoring Notion's 429 ``Retry-After``; other errors raise."""
        for attempt in range(MAX_RETRIES):
            response = await self._client.post(path, json=body)
            if response.status_code == 429 and attempt < MAX_RETRIES - 1:
                await asyncio.sleep(float(response.headers.get("Retry-After", "1")))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("unreachable")  # pragma: no cover

    async def _get_with_retry(self, path: str, params: Mapping[str, Any]) -> dict:
        """GET honoring Notion's 429 ``Retry-After``; other errors raise."""
        for attempt in range(MAX_RETRIES):
            response = await self._client.get(path, params=dict(params))
            if response.status_code == 429 and attempt < MAX_RETRIES - 1:
                await asyncio.sleep(float(response.headers.get("Retry-After", "1")))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        await self._client.aclose()


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.notion",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument(
        "--once", action="store_true", required=True, help="run one truth-lane poll cycle"
    )
    parser.add_argument(
        "--visibility",
        required=True,
        help="comma-separated principal tokens — the admin-assigned visibility "
        "policy enforced on every event (required, no default; Notion has no "
        "per-record share audience, so this IS the enforced ACL — SPEC §5e.2)",
    )
    parser.add_argument(
        "--credential-file",
        type=Path,
        default=None,
        help="read the Notion bearer token from this 0600 file (the file BODY, "
        "trailing newline stripped) — PREFERRED over NOTION_TOKEN env so a "
        "server spawn never puts the token in argv or the child environment; "
        "never echoed or logged",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("NOTION_STATE_FILE", ".verity/notion_cursor")),
        help="cursor persistence path (default: $NOTION_STATE_FILE or "
        ".verity/notion_cursor)",
    )
    parser.add_argument(
        "--with-content",
        action="store_true",
        help="also ingest page bodies (blocks) as DocumentEvents (inherits the "
        "admin-assigned --visibility floor; blocks carry no ACL)",
    )
    args = parser.parse_args(argv)

    try:
        policy = [int(tok) for tok in args.visibility.split(",") if tok.strip()]
    except ValueError:
        parser.error("--visibility must be comma-separated integers, e.g. 1,2")
    if not policy:
        parser.error("--visibility must name at least one principal token (fail closed)")

    cred_token: str | None = None
    if args.credential_file is not None:
        cred_token = _read_credential_file(args.credential_file)

    sink = VerityDebeziumSink.from_env()

    async def run_once() -> tuple[list[FactEvent | DocumentEvent], str, int, bool]:
        connector = NotionConnector(policy, token=cred_token, with_content=args.with_content)
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            return list(events), next_cursor, connector.quarantined, connector.users_degraded
        finally:
            await connector.aclose()

    events, next_cursor, quarantined, users_degraded = asyncio.run(run_once())
    # No provable Notion groups → no group-edge sync (framework parity: the
    # runner still calls it, with an empty map, so the lifecycle matches).
    sink.sync_group_edges({})
    fact_events = [e for e in events if isinstance(e, FactEvent)]
    summary = sink.post(fact_events, cursor=next_cursor)
    _write_cursor(args.state_file, next_cursor)
    docs = sum(1 for e in events if isinstance(e, DocumentEvent))
    print(
        f"poll: {len(fact_events)} fact event(s) ({docs} document(s), "
        f"{quarantined} quarantined), cursor -> {next_cursor} -> {summary}"
    )
    if users_degraded:
        # Authorship-only degrade (NOT DEGRADED_ACL_SIGNAL): the enforced admin
        # policy is unaffected; surface it as a plain operator note.
        print("notion: authorship roster degraded (informational metadata omitted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
