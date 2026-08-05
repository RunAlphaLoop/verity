"""Intercom ingestion connector (SPEC.md §5, §5e.2) — FIXTURES-ONLY.

Auth is bring-your-own-token (BYOT doctrine): an **Intercom access token**
minted in the customer's own workspace (Settings → Developers → your app, or a
personal access token). Read from env ``INTERCOM_ACCESS_TOKEN`` and used as
``Authorization: Bearer <token>`` (RFC 6750) against the Intercom REST API
(``https://api.intercom.io``) with the pinned ``Intercom-Version`` header so
response shapes stay stable. The bearer is a STATIC key — there is no refresh
lifecycle; a 401 means "rotate the token" (misconfiguration), surfaced loudly
rather than retried.

There are no live Intercom tokens in this environment: this connector is built
and proven ENTIRELY against recorded fixtures via ``httpx.MockTransport`` (the
same pattern as the Salesforce connector). A live smoke is GATED on the user
supplying ``INTERCOM_ACCESS_TOKEN`` and is never faked.

Two lanes:

- **Truth lane** — ``poll(cursor)`` lists four object types with an incremental
  ``updated_at`` cursor (Unix epoch seconds):

  - **conversations** and **contacts** via the Search API
    (``POST /conversations/search`` / ``POST /contacts/search``) with
    ``query: {field:"updated_at", operator:">", value:<cursor>}`` and
    ``sort: {field:"updated_at", order:"ascending"}`` — the only honest
    incremental path (the plain ``GET`` list cannot filter by ``updated_at``);
  - **companies** via ``POST /companies/list`` with a client-side
    ``updated_at > cursor`` gate (older API versions expose no search-by-
    updated_at — documented ceiling);
  - **articles** via ``GET /articles``, which returns DESCENDING by
    ``updated_at``; the connector pages ``starting_after`` until the first
    ``updated_at <= cursor`` and early-stops.

  Each non-null scalar field of each record maps to one FactEvent keyed
  ``(source="intercom", entity_id=id, field=field_name)``; the cursor is the max
  ``updated_at`` seen, stored as the API returned it (epoch int, as a string in
  the state file). A ≤1s replay is safe: delivery is at-least-once into
  deterministic keyed L1 upserts.
- **Push lane** — Intercom webhooks/topics are a later addition this poll-first
  connector does not speak yet; ``push_events`` is a documented no-op and the
  truth lane reconciles everything.

ACL honesty (read this before trusting any per-record audience):

Unlike Notion (a "no ACL table" source), Intercom exposes the assignment,
admin, and team objects directly and enumerably — so per-record principals are
DERIVABLE for conversations. But an assignment is NOT the full effective
audience: in Intercom every teammate with an inbox seat and the right role can
typically see unassigned and team-inbox conversations regardless of the single
``admin_assignee_id``/``team_assignee_id``. The assignment fields are therefore
a STRICT SUBSET / under-granting floor — we over-hide, never claim "mirrored".
Provenance is :data:`SHARE_ACL_PROVENANCE` = ``"approximated"`` for every
derived audience.

Per record type:

- **Conversation** → audience = the union of its assignees: ``admin_assignee_id``
  (nonzero) → ``user:<admin email.lower()>`` via the ``/admins`` roster;
  ``team_assignee_id`` (nonnull) → ``group:intercom-team-<id>`` via ``/teams``,
  whose ``admin_ids`` become the SpiceDB group→member edges (mirrored FIRST so a
  subject resolves through the group the instant facts land). Because assignment
  is a SUBSET of effective visibility, ``union_policy_floor`` is True: the admin
  ``--visibility`` floor is UNIONed into the stamped tokens (the inline block is
  a SUPERSET of the floor). A conversation with **no assignee**
  (``admin_assignee_id:0``, ``team_assignee_id:null``) cannot enumerate a
  specific audience → ``record_principals = None`` → it rides the admin floor.
  Fail closed — never "all teammates".
- **Contacts / Companies** → workspace-wide; the API exposes NO per-record
  audience, so the connector INVENTS none → ``record_principals = None`` → they
  ride the admin-assigned ``--visibility`` floor. (Documented ceiling: "the API
  cannot prove a narrower audience, so they take the admin floor.")
- **Articles** → ``state == "published"`` help-center content is world-readable.
  This is the ONE record type whose audience is genuinely provable — but Verity
  has no canonical minted "public/world" principal (gdrive treats the analogous
  "anyone" grant as OPERATOR-CONFIGURED via ``--anyone-maps-to``, defaulting to
  quarantine). So a published article maps to the operator-declared
  ``--public-maps-to`` principal (e.g. ``org:everyone``) when set — resolved
  through the standard sink path, no sink change — and its honest public class
  is carried by THAT principal. When ``--public-maps-to`` is UNSET a published
  article has no proven mappable audience → it rides the admin ``--visibility``
  floor (fail closed; never a guessed/minted public token). ``state == "draft"``
  or ANY unknown/other state → teammate-only, audience not enumerable per-record
  → admin floor. Fail closed on unknown states — an ambiguous state is NEVER
  treated as public.

Fail closed everywhere: no ``--visibility`` ⇒ constructor rejects ⇒ nothing
ships; a 403 (or any non-403 HTTP error) on the ``/admins`` or ``/teams`` roster
trips :attr:`~IntercomConnector.roster_degraded`, drops every ROSTER-DERIVED
audience (conversations) back to the admin floor (never stamp on a partial
roster), and the runner emits :data:`DEGRADED_ACL_SIGNAL`; an admin/team
assignee absent from the roster is dropped (if it was the only principal, the
record rides the floor); a record with no ``id`` is QUARANTINED (skipped +
counted), never emitted. (A published article's ``--public-maps-to`` class is
OPERATOR-DECLARED config, NOT roster-derived, so it is honestly unaffected by a
roster degrade — the degrade only touches assignment-derived principals.)

NOTE (identity crosswalk): principals use the CURRENT email-based convention
(``user:<email.lower()>``, joined on ``Admin.email``). The identity-crosswalk
workflow on ``main`` will later swap these for canonical identity tokens; this
connector is written to merge cleanly with that, and a crosswalk update follows.

Sink: the same :class:`~verity_ingest.connectors.hubspot.VerityDebeziumSink` as
HubSpot/Salesforce (source-generic; imported, never forked) — one bare Debezium
payload per event, ``op: "u"``, ``source.connector: "intercom"``,
``source.table`` the object type (``conversation``/``contact``/``company``/
``article``).

Runner::

    python -m verity_ingest.connectors.intercom --once --visibility 1,2
    python -m verity_ingest.connectors.intercom --once --visibility 1,2 \
        --public-maps-to org:everyone
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import httpx

from verity_ingest.connector import Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.credentials import StaticKey

logger = logging.getLogger(__name__)

SOURCE = "intercom"
BASE_URL = "https://api.intercom.io"
#: Pinned Intercom API version (sent on every request as ``Intercom-Version``)
#: so response shapes stay stable across Intercom's dated releases.
API_VERSION = "2.11"
#: BYOT credential env var: an Intercom access token / PAT created in the
#: customer's OWN workspace. Used only as ``Authorization: Bearer <token>``;
#: never logged.
ACCESS_TOKEN_ENV = "INTERCOM_ACCESS_TOKEN"

ADMINS_PATH = "/admins"
TEAMS_PATH = "/teams"
CONVERSATIONS_SEARCH_PATH = "/conversations/search"
CONTACTS_SEARCH_PATH = "/contacts/search"
COMPANIES_LIST_PATH = "/companies/list"
ARTICLES_PATH = "/articles"

PER_PAGE = 150  # Intercom list/search maximum

#: Provenance intent of any per-record inline ACL this connector stamps
#: (SPEC §5e: mirrored | approximated | admin-assigned | quarantined). A
#: conversation's assignment is a strict SUBSET of effective teammate visibility
#: (admins/inbox-seat teammates see more), so a derived audience can only ever be
#: "approximated" — never "mirrored". The enforced policy on unowned records is
#: admin-assigned.
SHARE_ACL_PROVENANCE = "approximated"

#: Stable, machine-readable stdout token the server greps for backfill
#: ``state=degraded_acl`` (connector-agnostic — identical value across
#: connectors). A 403 (or any non-403 error) on the ``/admins`` or ``/teams``
#: roster trips this and every record falls back to the admin ``--visibility``.
DEGRADED_ACL_SIGNAL = "verity.backfill.degraded_acl"

#: Article ``state`` that is genuinely world-readable (help-center published).
#: EVERY other state (draft, or any unknown/future value) is teammate-only and
#: rides the admin floor — an ambiguous state is NEVER treated as public.
_PUBLISHED_ARTICLE_STATE = "published"

#: Per-object-type fields never emitted as facts: the pk mirror, the object tag,
#: the timestamps (``updated_at`` becomes ``valid_from``), and the ACL-plumbing
#: assignment/author ids carried on ``raw_payload`` only, never as facts.
_METADATA_FIELDS = {
    "type",
    "id",
    "created_at",
    "updated_at",
    "admin_assignee_id",
    "team_assignee_id",
    "author_id",
    "pages",
    "statistics",
}


def user_principal(email: str) -> str:
    """A teammate principal, lowercased ``user:<email>`` so it is the SAME
    SpiceDB object a Gmail/Drive/HubSpot/Salesforce subject resolves to — one
    human is one identity across every source. Join on ``Admin.email``
    (lowercased). An admin with no email yields no principal (fail closed)."""
    return f"user:{email.lower()}"


def group_principal(team_id: str) -> str:
    """A team-visibility principal, a SpiceDB group. Its member edges come from
    the team's ``admin_ids`` and are mirrored via ``POST /v1/admin/groups`` so a
    subject resolves through the team. Intercom teams are flat (no nesting)."""
    return f"group:intercom-team-{team_id}"


@dataclass(frozen=True)
class IntercomAdminInfo:
    """One Intercom ``admin`` reduced to the crosswalk join key: the lowercased
    email. An admin with no ``email`` (a bot/operator seat) yields no roster
    entry and its id is dropped (over-hide, fail closed)."""

    email: str


@dataclass
class IntercomFactEvent(FactEvent):
    """A FactEvent plus what structured ingestion requires.

    Visibility precedence, per record:
    - ``record_principals`` — the per-record audience as principal STRINGS, or
      ``None`` when the audience cannot be enumerated (unassigned conversation,
      workspace-wide contact/company, non-published article, or a published
      article with no ``--public-maps-to``). The shared sink reads this to
      resolve tokens; ``None`` → the record rides the admin ``visibility_policy``
      floor (fail closed; never a guessed audience).
    - ``record_visibility`` — those strings resolved to int tokens by the shared
      sink, UNIONed with ``visibility_policy`` (``union_policy_floor`` is True).
      When set, the envelope carries an inline ``verity_acl`` with
      ``acl_provenance: approximated``.
    - ``visibility_policy`` — the admin-assigned ``--visibility`` floor. The
      write path applies an inline ``verity_acl`` with REPLACE semantics (it wins
      over the connector-bound policy), and a conversation's assignment is a
      strict SUBSET of effective Intercom visibility, so ``union_policy_floor``
      makes the sink fold this floor INTO the stamped token set — the inline
      block is always a superset of the admin floor (over-hide, never drop it).
    """

    object_type: str
    visibility_policy: list[int]
    record_principals: list[str] | None = None
    record_visibility: list[int] | None = None
    union_policy_floor: bool = True


def _parse_intercom_timestamp(value: int | float) -> datetime:
    """Intercom returns Unix epoch seconds (an int) for ``updated_at`` etc.;
    render it as an aware UTC datetime for ``valid_from``."""
    return datetime.fromtimestamp(int(value), tz=timezone.utc)


class IntercomConnector(Connector):
    """Truth-lane polling connector for Intercom conversations/contacts/
    companies/articles.

    ``visibility_policy`` is required and has no default (fail closed; see the
    module docstring — assignment is approximated metadata, never the enforced
    ACL). Credential defaults to the env ``INTERCOM_ACCESS_TOKEN`` static bearer.
    """

    name = SOURCE

    def __init__(
        self,
        visibility_policy: list[int],
        *,
        token: str | None = None,
        credential: StaticKey | None = None,
        base_url: str = BASE_URL,
        public_maps_to: str | None = None,
        fetch_articles: bool = True,
        fetch_companies: bool = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.visibility_policy = list(visibility_policy)
        #: Operator-declared principal that a PUBLISHED help-center article maps
        #: to (e.g. ``org:everyone``). None (the default) → published articles
        #: ride the admin floor (fail closed; never a minted public token). This
        #: mirrors gdrive's ``--anyone-maps-to`` doctrine for the "anyone" grant.
        self.public_maps_to = public_maps_to
        self.fetch_articles = fetch_articles
        self.fetch_companies = fetch_companies
        #: Filled by :meth:`_fetch_roster`: admin id → ``user:<email>``.
        self.admins_by_id: dict[str, str] = {}
        #: Filled by :meth:`_fetch_roster`: ``group:intercom-team-<id>`` → the set
        #: of member ``user:<email>`` principals (from the team's ``admin_ids``) —
        #: the SpiceDB edges the runner syncs FIRST. Empty when degraded.
        self.group_edges: dict[str, set[str]] = {}
        #: Set True by :meth:`_fetch_roster` when ``/admins`` or ``/teams`` fails
        #: (403 or any other HTTP error). Every record then falls back to the
        #: admin-assigned ``--visibility``; the runner turns this into the
        #: distinct, machine-readable ``degraded_acl`` signal.
        self.roster_degraded: bool = False
        #: Count of records skipped as unparseable (no id) — quarantined, never
        #: emitted with a guessed ACL.
        self.quarantined: int = 0

        # Static bearer credential via the shared abstraction. An Intercom token
        # has no refresh lifecycle: a 401 means "rotate the token", never
        # "retry". Token flows ONLY into the Authorization header — never logged.
        self.credential = credential or StaticKey(
            ACCESS_TOKEN_ENV,
            value=token,
            missing_hint="an Intercom access token / PAT (BYOT — create an app "
            "or PAT in YOUR OWN workspace under Settings → Developers); set "
            f"{ACCESS_TOKEN_ENV}",
        )
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {self.credential.value}",
                "Accept": "application/json",
                "Intercom-Version": API_VERSION,
            },
            timeout=30.0,
        )

    # ---------- deterministic mapping (pure; exercised by conformance tests) ----------

    def record_principals_for(
        self, object_type: str, record: Mapping[str, Any]
    ) -> list[str] | None:
        """Compute the per-record audience STRINGS for one record, or ``None``
        when the audience cannot be enumerated (→ admin floor).

        - conversation → union of ``admin_assignee_id`` (nonzero → ``user:``) and
          ``team_assignee_id`` (nonnull → ``group:intercom-team-<id>``), each
          resolved through the roster; unresolvable assignees are dropped; an
          all-dropped / unassigned conversation → ``None`` (admin floor).
        - article → ``published`` maps to ``public_maps_to`` when set, else
          ``None``; any other/unknown state → ``None`` (teammate-only floor,
          never public).
        - contact / company → ``None`` (workspace-wide; no per-record audience).
        """
        if object_type == "conversation":
            principals: list[str] = []
            admin_id = record.get("admin_assignee_id")
            if admin_id:  # 0 / None → unassigned to an individual
                principal = self.admins_by_id.get(str(admin_id))
                if principal and principal not in principals:
                    principals.append(principal)
            team_id = record.get("team_assignee_id")
            if team_id is not None:
                team_principal = group_principal(str(team_id))
                # Only stamp a team the roster actually knows (fail closed on an
                # unmappable team assignee — its edges were never mirrored).
                if team_principal in self.group_edges and team_principal not in principals:
                    principals.append(team_principal)
            return principals or None
        if object_type == "article":
            if record.get("state") == _PUBLISHED_ARTICLE_STATE and self.public_maps_to:
                return [self.public_maps_to]
            return None  # draft / unknown state → teammate-only floor (never public)
        # contact / company → workspace-wide, no per-record audience
        return None

    def events_from_page(
        self, object_type: str, records: list[dict]
    ) -> tuple[list[IntercomFactEvent], int]:
        """Map a list of records to FactEvents, returning ``(events, quarantined)``.

        One event per non-null scalar field, sorted by field name for
        determinism; ``id`` is the entity id, ``updated_at`` becomes
        ``valid_from``, and metadata/plumbing keys (see ``_METADATA_FIELDS``) are
        never facts. A record with no ``id`` is QUARANTINED (skipped + counted),
        never emitted with a guessed ACL. ``record_principals`` is computed per
        the honest ACL matrix (see :meth:`record_principals_for`).
        """
        events: list[IntercomFactEvent] = []
        quarantined = 0
        for record in records:
            record_id = record.get("id")
            updated = record.get("updated_at")
            if not record_id or updated is None:
                quarantined += 1
                continue
            valid_from = _parse_intercom_timestamp(updated)
            principals = self.record_principals_for(object_type, record)
            fields: dict[str, Any] = {}
            for name in record:
                if name in _METADATA_FIELDS:
                    continue
                value = record[name]
                if value is None or isinstance(value, (dict, list)):
                    continue  # scalars only (nested objects are plumbing)
                fields[name] = value
            for name in sorted(fields):
                events.append(
                    IntercomFactEvent(
                        source=SOURCE,
                        entity_id=str(record_id),
                        field_name=name,
                        value=fields[name],
                        valid_from=valid_from,
                        raw_payload=record,
                        object_type=object_type,
                        visibility_policy=list(self.visibility_policy),
                        record_principals=list(principals) if principals else None,
                    )
                )
        return events, quarantined

    # ---------- lanes ----------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op by design: Intercom webhooks/topics are a later addition this
        poll-first connector does not speak yet; the truth lane reconciles
        everything the push lane would have delivered."""
        return
        yield  # pragma: no cover — makes this an (empty) async generator

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """One truth-lane cycle. Fetches the ``/admins`` + ``/teams`` roster ONCE
        (a 403 or any other error degrades to the admin floor + trips
        :attr:`roster_degraded`; never stamp on a partial roster), then lists
        each object type with ``updated_at`` strictly greater than ``cursor``
        ascending, mapping records to FactEvents and attaching per-record
        principals. Returns the events and the max ``updated_at`` (epoch) seen as
        the next cursor (a string).
        """
        cursor_epoch = int(cursor) if cursor else 0
        events: list[FactEvent | DocumentEvent] = []
        max_updated = cursor_epoch

        await self._fetch_roster()

        # conversations + contacts via the Search API (updated_at > cursor, asc);
        # companies via list + client-side gate; articles via GET (desc, early
        # stop). Every list is filtered/gated to updated_at > cursor.
        search_types = [
            ("conversation", CONVERSATIONS_SEARCH_PATH, "conversations"),
            ("contact", CONTACTS_SEARCH_PATH, "data"),
        ]
        for object_type, path, key in search_types:
            async for page in self._search_pages(path, cursor_epoch):
                records = page.get(key, [])
                page_events, quarantined = self.events_from_page(object_type, records)
                events.extend(page_events)
                self.quarantined += quarantined
                for record in records:
                    updated = record.get("updated_at")
                    if isinstance(updated, (int, float)) and int(updated) > max_updated:
                        max_updated = int(updated)

        if self.fetch_companies:
            async for page in self._list_pages(COMPANIES_LIST_PATH):
                records = [
                    r
                    for r in page.get("data", [])
                    if isinstance(r.get("updated_at"), (int, float))
                    and int(r["updated_at"]) > cursor_epoch
                ]
                page_events, quarantined = self.events_from_page("company", records)
                events.extend(page_events)
                self.quarantined += quarantined
                for record in records:
                    max_updated = max(max_updated, int(record["updated_at"]))

        if self.fetch_articles:
            for record in await self._fetch_articles(cursor_epoch):
                page_events, quarantined = self.events_from_page("article", [record])
                events.extend(page_events)
                self.quarantined += quarantined
                updated = record.get("updated_at")
                if isinstance(updated, (int, float)):
                    max_updated = max(max_updated, int(updated))

        return events, str(max_updated)

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl: identical to a poll from epoch (no cursor gate,
        every record re-read)."""
        events, _ = await self.poll(None)
        for event in events:
            yield event

    # ---------- HTTP plumbing ----------

    async def _fetch_roster(self) -> None:
        """Build the identity crosswalk from ``/admins`` + ``/teams``.

        ``/admins`` → ``admins_by_id[id] = user:<email.lower()>`` (an admin with
        no email is dropped). ``/teams`` → ``group_edges[group:intercom-team-<id>]
        = {user:<email> for each admin_id}`` (SpiceDB edges the runner mirrors
        FIRST). A 403 (token lacks the scope) OR any other HTTP error degrades to
        an EMPTY roster, trips :attr:`roster_degraded`, and every record falls
        back to the admin ``--visibility`` floor — never stamp on a partial
        roster.
        """
        try:
            admins = await self._get_all(ADMINS_PATH, "admins")
            for admin in admins:
                admin_id = admin.get("id")
                email = (admin.get("email") or "").strip().lower()
                if admin_id and email:
                    self.admins_by_id[str(admin_id)] = user_principal(email)

            teams = await self._get_all(TEAMS_PATH, "teams")
            for team in teams:
                team_id = team.get("id")
                if not team_id:
                    continue
                parent = group_principal(str(team_id))
                edge = self.group_edges.setdefault(parent, set())
                for admin_id in team.get("admin_ids", []):
                    principal = self.admins_by_id.get(str(admin_id))
                    if principal:
                        edge.add(principal)
        except httpx.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            self.roster_degraded = True
            self.admins_by_id = {}
            self.group_edges = {}
            print(
                f"intercom: /admins or /teams roster fetch failed ({status or exc}) — "
                "grant the token the 'Read admins'/'Read teams' scope to crosswalk "
                "assignee ids to cross-source principals; falling back to the "
                "admin-assigned --visibility for every record",
                file=sys.stderr,
            )

    async def _search_pages(self, path: str, cursor_epoch: int) -> AsyncIterator[dict]:
        """``POST <path>`` (Search API): ``updated_at > cursor`` ascending,
        following ``pages.next.starting_after`` in the request BODY."""
        starting_after: str | None = None
        while True:
            pagination: dict[str, Any] = {"per_page": PER_PAGE}
            if starting_after is not None:
                pagination["starting_after"] = starting_after
            body = {
                "query": {
                    "field": "updated_at",
                    "operator": ">",
                    "value": cursor_epoch,
                },
                "sort": {"field": "updated_at", "order": "ascending"},
                "pagination": pagination,
            }
            page = await self._post_with_retry(path, body)
            yield page
            starting_after = ((page.get("pages") or {}).get("next") or {}).get("starting_after")
            if not starting_after:
                return

    async def _list_pages(self, path: str) -> AsyncIterator[dict]:
        """``POST <path>`` list endpoint (e.g. ``/companies/list``): pagination
        rides the request BODY as ``{"pagination": {...}}`` — NOT the query
        string. Intercom 400s the empty-body ``?per_page=`` form; the pagination
        must be in the JSON body, exactly like the Search endpoints. Follows
        ``pages.next.starting_after``; the caller applies the ``updated_at`` gate."""
        starting_after: str | None = None
        while True:
            pagination: dict[str, Any] = {"per_page": PER_PAGE}
            if starting_after is not None:
                pagination["starting_after"] = starting_after
            page = await self._post_with_retry(path, {"pagination": pagination})
            yield page
            starting_after = ((page.get("pages") or {}).get("next") or {}).get("starting_after")
            if not starting_after:
                return

    async def _fetch_articles(self, cursor_epoch: int) -> list[dict]:
        """``GET /articles`` (DESCENDING by ``updated_at``): page
        ``starting_after`` until the first ``updated_at <= cursor`` and stop.
        Returns only articles newer than the cursor."""
        fresh: list[dict] = []
        starting_after: str | None = None
        stop = False
        while not stop:
            params: dict[str, Any] = {"per_page": PER_PAGE}
            if starting_after is not None:
                params["starting_after"] = starting_after
            page = await self._get_with_retry(ARTICLES_PATH, params)
            for record in page.get("data", []):
                updated = record.get("updated_at")
                if isinstance(updated, (int, float)) and int(updated) <= cursor_epoch:
                    # Descending: everything after this is also ≤ cursor.
                    stop = True
                    break
                fresh.append(record)
            if stop:
                break
            starting_after = ((page.get("pages") or {}).get("next") or {}).get("starting_after")
            if not starting_after:
                break
        return fresh

    async def _get_all(self, path: str, key: str) -> list[dict]:
        """GET a (possibly paginated) list endpoint, concatenating ``key``."""
        items: list[dict] = []
        starting_after: str | None = None
        while True:
            params: dict[str, Any] = {"per_page": PER_PAGE}
            if starting_after is not None:
                params["starting_after"] = starting_after
            page = await self._get_with_retry(path, params)
            items.extend(page.get(key, []))
            starting_after = ((page.get("pages") or {}).get("next") or {}).get("starting_after")
            if not starting_after:
                return items

    async def _post_with_retry(
        self, path: str, body: dict, params: Mapping[str, Any] | None = None
    ) -> dict:
        """POST honoring Intercom's 429 ``Retry-After``; other errors raise."""
        for attempt in range(5):
            response = await self._client.post(path, json=body, params=dict(params or {}))
            if response.status_code == 429 and attempt < 4:
                await asyncio.sleep(float(response.headers.get("Retry-After", "1")))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("unreachable")  # pragma: no cover

    async def _get_with_retry(self, path: str, params: Mapping[str, Any]) -> dict:
        """GET honoring Intercom's 429 ``Retry-After``; other errors raise."""
        for attempt in range(5):
            response = await self._client.get(path, params=dict(params))
            if response.status_code == 429 and attempt < 4:
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
        prog="python -m verity_ingest.connectors.intercom",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument(
        "--once", action="store_true", required=True, help="run one truth-lane poll cycle"
    )
    parser.add_argument(
        "--visibility",
        required=True,
        help="comma-separated principal tokens — the admin-assigned visibility "
        "policy enforced on every event (required, no default; assignment-"
        "derived principals are approximated metadata, not enforcement — "
        "SPEC §5e.2)",
    )
    parser.add_argument(
        "--credential-file",
        type=Path,
        default=None,
        help="read the Intercom bearer token from this 0600 file (the file BODY, "
        "trailing newline stripped) — PREFERRED over INTERCOM_ACCESS_TOKEN env "
        "so a server spawn never puts the token in argv or the child "
        "environment; never echoed or logged",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("INTERCOM_STATE_FILE", ".verity/intercom_cursor")),
        help="cursor persistence path (default: $INTERCOM_STATE_FILE or "
        ".verity/intercom_cursor)",
    )
    parser.add_argument(
        "--public-maps-to",
        default=os.environ.get("INTERCOM_PUBLIC_MAPS_TO"),
        help='map PUBLISHED help-center articles to this principal (e.g. '
        '"org:everyone"); default: published articles ride the admin '
        "--visibility floor (fail closed; never a minted public token)",
    )
    parser.add_argument(
        "--no-articles", action="store_true", help="skip the help-center article lane"
    )
    parser.add_argument(
        "--no-companies", action="store_true", help="skip the companies lane"
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

    # Explicit source: the shared sink's idle heartbeats must key "intercom"
    # for the server's per-source freshness gate, never the HubSpot default.
    sink = VerityDebeziumSink.from_env(SOURCE)

    async def run_once() -> tuple[list[IntercomFactEvent], str, dict[str, set[str]], int, bool]:
        connector = IntercomConnector(
            policy,
            token=cred_token,
            public_maps_to=args.public_maps_to,
            fetch_articles=not args.no_articles,
            fetch_companies=not args.no_companies,
        )
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            return (
                [e for e in events if isinstance(e, IntercomFactEvent)],
                next_cursor,
                {g: set(m) for g, m in connector.group_edges.items()},
                connector.quarantined,
                connector.roster_degraded,
            )
        finally:
            await connector.aclose()

    events, next_cursor, group_edges, quarantined, roster_degraded = asyncio.run(run_once())
    # Sync team membership FIRST so a subject resolves through their team the
    # moment team-scoped facts land (identical to the HubSpot/Salesforce runner
    # lifecycle).
    edges = sink.sync_group_edges(group_edges)
    summary = sink.post(events, cursor=next_cursor)
    _write_cursor(args.state_file, next_cursor)
    scoped = sum(1 for e in events if e.record_principals)
    print(
        f"poll: {len(events)} fact event(s) ({scoped} audience-scoped, "
        f"{edges} team edge(s), {quarantined} quarantined), "
        f"cursor -> {next_cursor} -> {summary}"
    )
    if roster_degraded:
        # Stable, machine-readable stdout token — the read-once contract the
        # server greps for backfill state=degraded_acl (never stderr-only).
        print(DEGRADED_ACL_SIGNAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
