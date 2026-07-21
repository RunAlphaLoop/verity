"""Salesforce native flagship connector (SPEC.md §5, §5e.2).

Auth is bring-your-own-token (BYOT doctrine): a **customer-created Connected
App** in the customer's own org with the client-credentials flow enabled —
the §5e.2 survey row notes the post-Sept-2025 crackdown made vendor-
distributed apps harder while customer-created stayed easy. Credentials come
from env ``SF_MY_DOMAIN`` / ``SF_CLIENT_ID`` / ``SF_CLIENT_SECRET`` and are
minted via the shared :class:`~verity_ingest.credentials.ClientCredentials`
lifecycle against ``https://<mydomain>.my.salesforce.com/services/oauth2/token``.
Salesforce's client_credentials response carries **no ``expires_in`` and no
refresh token** (documented shape), so the access token is cached until a 401
(``INVALID_SESSION_ID``) triggers the shared 401-retry-once hook
(:func:`~verity_ingest.credentials.request_with_auth_retry`).

Two lanes:

- **Truth lane** — ``poll(cursor)`` runs SOQL through
  ``GET /services/data/v62.0/query`` for Account, Contact, and Opportunity
  with ``WHERE LastModifiedDate > <cursor> ORDER BY LastModifiedDate ASC``,
  following ``nextRecordsUrl`` (queryMore) pagination, and maps each non-null
  field of each record to one FactEvent. The cursor is the max
  ``LastModifiedDate`` seen, stored as the API returned it. SOQL dateTime
  literals carry no sub-second precision, so the cursor is truncated to whole
  seconds in the WHERE clause — a ≤1s window can replay, which is safe:
  delivery is at-least-once into deterministic keyed L1 upserts.
- **Push lane** — Salesforce CDC arrives over the Pub/Sub API (gRPC), a
  transport this poll-first connector does not speak yet; ``push_events`` is
  a documented no-op and the truth lane reconciles everything.

ACL honesty (read this before trusting ``share_principals``):

Salesforce is ACL tier **A** in the §5e.2 survey — the ``*Share`` tables and
ObjectPermissions are readable — but it is flagged as the *hardest
reconstruction of the 20*. Full effective visibility is the union of org-wide
defaults, the role hierarchy, sharing rules, manual/team shares, **implicit
sharing** (parent-account access implied by child contact/opportunity/case
access and vice versa — not represented as ``*Share`` rows the way explicit
shares are), and territory management. This connector does **not** reconstruct
that; AccountShare is a strict SUBSET of effective visibility, so the enforced
ACL stays provenance ``"approximated"`` — we over-hide, never claim "mirrored".
What it does, per poll cycle:

- For Accounts changed in the window it fetches ``AccountShare`` rows and
  collects each row's RAW ``UserOrGroupId`` (005 User / 00G Group) on the event
  as ``share_principals`` (Accounts only; empty on Contact/Opportunity).
- It CROSSWALKS those raw ids to cross-source principals through a roster built
  from the ``User`` and ``GroupMember`` objects. M2 2b — a 005 User resolves via
  its ``FederationIdentifier`` (the SSO subject), matched server-side against a
  directory-declared ``principal_sso_alias`` → the ONE canonical
  ``user:<primaryEmail.lower()>`` the directory vouched. The join key is
  ``FederationIdentifier``, NEVER ``User.Email``: a divergent login
  (``User.Email = alice.n@corp.sf`` vs a vouched primary ``alice@corp.com``)
  must not be invisible or welded to the wrong human. A 005 with no
  ``FederationIdentifier`` — or no alias match, or ``IsActive=false`` — confers
  NOTHING (over-hide; ``email_fallback`` is OFF for SF, so it is never rescued
  by ``User.Email`` — the admin must publish an ``admin_explicit`` crosswalk
  link). A 00G → the stable ``group:salesforce-group-<id>``. Nested
  ``GroupMember`` edges (a member may be another 00G) are mirrored into SpiceDB
  via ``POST /v1/admin/groups`` — the runner syncs them FIRST so a subject
  resolves through the group the instant group-scoped facts land. The expansion
  is breadth-first and cycle-safe.
- The resolved principals are materialized to int tokens by the shared sink and
  stamped as an INLINE ``verity_acl`` (``acl_provenance: approximated``). The
  write-path choke point applies an inline block with REPLACE semantics (it
  wins over the connector-bound admin ``--visibility`` policy, it does not union
  server-side), so because AccountShare is a known subset we UNION the admin
  ``--visibility`` floor INTO the stamped token set before it ships (via the
  event's ``union_policy_floor`` flag → :meth:`VerityDebeziumSink.
  _stamp_record_visibility`). The inline block is therefore always a SUPERSET of
  the admin floor: an unresolvable share id is dropped, but the record still
  carries the full admin-policy visibility. Enforcement is fail-closed by
  construction — the constructor requires an admin ``visibility_policy`` (no
  default), share/roster fetch failures never gate facts, and a 403 (or any
  other error) on the roster query trips :attr:`~SalesforceConnector.
  roster_degraded`, dropping every record back to the admin floor and emitting
  :data:`DEGRADED_ACL_SIGNAL`.

Sink: the same :class:`~verity_ingest.connectors.hubspot.VerityDebeziumSink`
pattern as HubSpot — one bare Debezium payload per event, ``op: "u"``,
``source.connector: "salesforce"``, ``source.table`` the sobject type. The
sink class is imported from the hubspot module (it is source-generic; it
moves to a shared module when a third structured connector lands).

Runner::

    python -m verity_ingest.connectors.salesforce --once --visibility 1,2
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator, Mapping, Sequence

import httpx

from verity_ingest import crosswalk
from verity_ingest.connector import Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.hubspot import VerityDebeziumSink
from verity_ingest.credentials import ClientCredentials, Credential, request_with_auth_retry

logger = logging.getLogger(__name__)

SOURCE = "salesforce"
API_VERSION = "v62.0"
QUERY_PATH = f"/services/data/{API_VERSION}/query"

MY_DOMAIN_ENV = "SF_MY_DOMAIN"
CLIENT_ID_ENV = "SF_CLIENT_ID"
CLIENT_SECRET_ENV = "SF_CLIENT_SECRET"

#: Provenance intent of share-derived principals (SPEC §5e: mirrored |
#: approximated | admin-assigned | quarantined). AccountShare rows omit
#: implicit sharing and territories, so they can only ever be "approximated";
#: the *enforced* policy on these events is admin-assigned.
SHARE_ACL_PROVENANCE = "approximated"

#: Salesforce ID key-prefixes for AccountShare.UserOrGroupId.
USER_KEY_PREFIX = "005"
GROUP_KEY_PREFIX = "00G"

#: Marker prefix for a group-member 005's FederationIdentifier SSO subject in the
#: ``group_edges`` map (M2 2b). A ``fed:<subject>`` member is NOT a canonical
#: principal — the sink resolves it through the registry ``emails`` gate to the
#: canonical ``user:<primaryEmail>`` before mirroring the group edge, so a group
#: member is never welded to a blind ``user:<sourceEmail>``. Shared with the sink
#: (defined in ``verity_ingest.crosswalk``).
FEDERATION_SUBJECT_PREFIX = crosswalk.FEDERATION_MEMBER_PREFIX

#: SOQL ``IN (...)`` chunk size for AccountShare / roster lookups (keeps each
#: query comfortably under the SOQL statement-length limit).
SHARE_QUERY_CHUNK = 200

#: Standard objects whose per-record visibility comes from a dedicated share
#: object (``<Object>Share`` with an ``<Object>Id`` key + ``UserOrGroupId``).
#: Account and Opportunity both expose owner/manual/rule/hierarchy grants this
#: way; Contact under the common "Controlled by Parent" OWD has NO share rows —
#: its access is the parent Account's, so it is resolved by INHERITANCE (via
#: ``Contact.AccountId``), not through this map.
SHARE_OBJECTS = {
    "Account": ("AccountShare", "AccountId"),
    "Opportunity": ("OpportunityShare", "OpportunityId"),
}

#: The synthetic group carrying org-wide View All Data / Modify All Data (SPEC
#: §14.3 completeness). Those profile/permission-set grants let a user read EVERY
#: record regardless of sharing, and they are NOT expressed as AccountShare rows —
#: so the connector mirrors them as a group whose members are the view-all users'
#: ``fed:`` subjects, stamped on every emitted record. Measured over-hide-only:
#: adding it can never widen visibility beyond what Salesforce itself grants.
VIEW_ALL_GROUP = "group:salesforce-view-all-data"

#: Stable, machine-readable stdout token the server greps for backfill
#: ``state=degraded_acl`` (connector-agnostic — same value HubSpot emits). A
#: 403 on the User/Group/GroupMember roster query trips this and every record
#: falls back to the admin-assigned ``--visibility``.
DEGRADED_ACL_SIGNAL = "verity.backfill.degraded_acl"

#: Hard backstop on the breadth-first Group/GroupMember expansion. Combined with
#: the ``seen`` visited-set this makes a membership cycle (``A⊃B``, ``B⊃A``)
#: terminate and caps a pathological roster.
GROUP_EXPANSION_MAX = 5000


def group_principal(group_id: str) -> str:
    """The group-visibility principal, a SpiceDB group. Stable for ALL Salesforce
    Group ``Type`` values (Regular, Queue, Role, RoleAndSubordinates, …) — a
    Role group is represented as a group like any other. Nested GroupMember
    edges are mirrored via ``POST /v1/admin/groups``; SpiceDB closes the graph."""
    return f"group:salesforce-group-{group_id}"


def role_principal(role_id: str) -> str:
    """The visibility group for one UserRole (SPEC §14.3 role-hierarchy
    completeness). Salesforce grants a manager access to records owned BELOW them
    in the role tree, and this access is IMPLICIT — it is not an AccountShare row,
    so the connector cannot see it from shares alone. The connector reconstructs
    it: a record owned by a user in role R is stamped with the role group of each
    ANCESTOR role of R, whose members (the managers up the chain) then resolve
    through it. Distinct namespace from :func:`group_principal` so a role group and
    a public Group with the same raw id never collide."""
    return f"group:salesforce-role-{role_id}"


@dataclass(frozen=True)
class SalesforceUserInfo:
    """One Salesforce ``User`` (005) reduced to what identity resolution needs.

    M2 2b — the join key is ``FederationIdentifier`` (the SSO subject), matched
    against a declared ``principal_sso_alias`` server-side, NEVER ``User.Email``:
    a divergent login (``User.Email = alice.n@corp.sf`` while the directory-vouched
    primary is ``alice@corp.com``) would otherwise be invisible or, worse, welded
    to the wrong human. ``email`` is retained for observability/logging only — it
    is never a resolution key. A user with no ``FederationIdentifier`` (or
    ``IsActive=false``) yields nothing to resolve → dropped (over-hide, fail
    closed); no ``User.Email`` fallback (``email_fallback`` is OFF for SF)."""

    email: str
    federation_identifier: str | None = None
    is_active: bool = True

#: Default fields per sobject (Id and LastModifiedDate are always added).
#: Override via the ``fields`` constructor arg.
DEFAULT_FIELDS = {
    "Account": ["Name", "Industry", "Website", "AnnualRevenue"],
    "Contact": ["FirstName", "LastName", "Email", "Title", "AccountId"],
    "Opportunity": ["Name", "StageName", "Amount", "CloseDate", "AccountId"],
}

#: Record keys never emitted as facts: the pk mirror, the REST envelope's
#: attributes object, and LastModifiedDate (it becomes ``valid_from``).
_METADATA_FIELDS = {"Id", "LastModifiedDate", "attributes"}


@dataclass
class SalesforceFactEvent(FactEvent):
    """A FactEvent plus what CRM ingestion requires.

    Visibility precedence, per record:
    - ``share_principals`` — the RAW ``005``/``00G`` AccountShare ids for this
      record, pre-resolution (Accounts only; empty elsewhere).
    - ``record_principals`` — the already-canonical group strings this record's
      access mirrors (``group:salesforce-group-<id>``), or ``None`` when unowned.
      The shared sink resolves these via the ``principals`` field.
    - ``record_owner_emails`` — M2 2b: the ``FederationIdentifier`` SSO subjects
      of the record's 005 owners. The shared sink resolves these through the
      registry ``emails`` gate (``idp_subject``/``principal_sso_alias`` match) to
      the canonical ``user:<primaryEmail>`` token — NEVER ``User.Email``. An
      unvouched/unmatched subject is dropped (fail closed).
    - ``record_visibility`` — the union of the resolved group + owner tokens
      (filled by the sink via ``/v1/admin/principals``), UNIONed with
      ``visibility_policy`` (``union_policy_floor`` is True — see below). When
      set, the envelope carries an inline ``verity_acl`` with
      ``acl_provenance: approximated``.
    - ``visibility_policy`` — the admin-assigned fallback (``--visibility``).
      The write path applies an inline ``verity_acl`` with REPLACE semantics
      (it wins over the connector-bound policy, no server-side union), and
      AccountShare is a strict SUBSET of effective Salesforce visibility, so
      ``union_policy_floor`` makes the sink fold this floor INTO the stamped
      token set — the inline block is always a superset of the admin floor.
    """

    object_type: str
    visibility_policy: list[int]
    share_principals: list[str] = field(default_factory=list)
    record_principals: list[str] | None = None
    #: M2 2b — the ``FederationIdentifier`` SSO subjects of this record's 005
    #: owners, resolved through the registry ``emails`` gate (NOT ``User.Email``).
    record_owner_emails: list[str] | None = None
    record_visibility: list[int] | None = None
    #: Read by the shared sink: because the write path REPLACES the bound admin
    #: policy with any inline ACL (ingest.rs ``or_else``), and AccountShare is a
    #: known subset of effective visibility, the admin ``--visibility`` floor is
    #: UNIONed into ``record_visibility`` before stamping so the inline block is
    #: a superset of the floor (over-hide, never drop the floor).
    union_policy_floor: bool = True


def _parse_sf_timestamp(value: str) -> datetime:
    """Salesforce REST returns ISO-8601 with milliseconds and a ``+0000``
    offset (e.g. ``2026-07-08T18:04:57.000+0000``); ``Z`` also handled."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _soql_datetime(value: str) -> str:
    """Render a cursor as a SOQL dateTime literal (UTC, whole seconds, ``Z``).

    SOQL dateTime literals are unquoted and carry no fractional seconds;
    truncation can replay a ≤1s window (at-least-once, safe on keyed upserts).
    """
    dt = _parse_sf_timestamp(value).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mydomain_host(my_domain: str) -> str:
    """``acme`` → ``acme.my.salesforce.com``; already-qualified hosts pass through."""
    return my_domain if "." in my_domain else f"{my_domain}.my.salesforce.com"


def _chunks(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _merge_principals(existing: Sequence[str] | None, extra: Iterable[str]) -> list[str] | None:
    """Union ``extra`` into ``existing`` preserving order + dedup (existing first).
    Returns None only if the merged set is empty (so an unowned record stays on the
    admin floor rather than carrying an empty inline ACL)."""
    out = list(existing or [])
    for principal in extra:
        if principal not in out:
            out.append(principal)
    return out or None


class SalesforceConnector(Connector):
    """Truth-lane polling connector for Salesforce sobjects.

    ``visibility_policy`` is required and has no default (fail closed; see
    the module docstring — share rows are approximated metadata, never the
    enforced ACL). Credentials default to the env-configured Connected-App
    client-credentials flow.
    """

    name = SOURCE
    object_types = tuple(DEFAULT_FIELDS)

    def __init__(
        self,
        visibility_policy: list[int],
        *,
        my_domain: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        credential: Credential | None = None,
        base_url: str | None = None,
        fields: dict[str, list[str]] | None = None,
        client: httpx.AsyncClient | None = None,
        fetch_account_shares: bool = True,
        mirror_view_all: bool = True,
        mirror_role_hierarchy: bool = True,
        token_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.visibility_policy = list(visibility_policy)
        self.fields = dict(DEFAULT_FIELDS, **(fields or {}))
        self.fetch_account_shares = fetch_account_shares
        #: Mirror org-wide View All Data / Modify All Data as :data:`VIEW_ALL_GROUP`
        #: stamped on every record (SPEC §14.3 completeness; over-hide-only).
        self.mirror_view_all = mirror_view_all
        #: Reconstruct implicit role-hierarchy access — a record owned in role R is
        #: stamped with the role group of each ANCESTOR role (SPEC §14.3; Accounts,
        #: over-hide-only). Salesforce never materializes this as a share row.
        self.mirror_role_hierarchy = mirror_role_hierarchy
        #: Filled by :meth:`poll` from the Group/GroupMember roster. Maps each
        #: ``group:salesforce-group-<id>`` to the set of member principals
        #: (``user:<email>`` or nested ``group:salesforce-group-<child>``) — the
        #: SpiceDB edges the runner syncs FIRST so a subject resolves through the
        #: group the moment group-scoped facts land. Empty when unowned/degraded.
        self.group_edges: dict[str, set[str]] = {}
        #: Set True by :meth:`_fetch_roster` when the User/Group/GroupMember query
        #: 403s (the integration user lacks read on those objects). Every record
        #: then falls back to the admin-assigned ``--visibility``; the runner
        #: turns this into the distinct, machine-readable ``degraded_acl`` signal.
        self.roster_degraded: bool = False

        my_domain = my_domain or os.environ.get(MY_DOMAIN_ENV)
        if credential is None:
            client_id = client_id or os.environ.get(CLIENT_ID_ENV)
            client_secret = client_secret or os.environ.get(CLIENT_SECRET_ENV)
            missing = [
                name
                for name, value in [
                    (MY_DOMAIN_ENV, my_domain),
                    (CLIENT_ID_ENV, client_id),
                    (CLIENT_SECRET_ENV, client_secret),
                ]
                if not value
            ]
            if missing:
                raise RuntimeError(
                    f"no Salesforce credential: set {', '.join(missing)} (BYOT — create "
                    "a Connected App in YOUR OWN org, enable the OAuth client-credentials "
                    "flow with a run-as integration user, and paste its consumer key/secret)"
                )
            assert my_domain is not None and client_id is not None and client_secret is not None
            credential = ClientCredentials(
                token_url=f"https://{_mydomain_host(my_domain)}/services/oauth2/token",
                client_id=client_id,
                client_secret=client_secret,
                client=token_client,
            )
        self.credential = credential

        if client is None:
            if base_url is None:
                if not my_domain:
                    raise RuntimeError(
                        f"no Salesforce instance: set {MY_DOMAIN_ENV} or pass base_url/client"
                    )
                base_url = f"https://{_mydomain_host(my_domain)}"
            client = httpx.AsyncClient(base_url=base_url, timeout=30.0)
        self._client = client

    # ---------- deterministic mapping (pure; exercised by conformance tests) ----------

    @classmethod
    def events_from_query_page(
        cls, sobject: str, page: dict, visibility_policy: list[int]
    ) -> list[SalesforceFactEvent]:
        """Map one query/queryMore response page to FactEvents.

        One event per non-null field, sorted by field name for determinism;
        ``Id`` is the entity id, ``LastModifiedDate`` becomes ``valid_from``,
        and the REST ``attributes`` envelope is never a fact.
        """
        events: list[SalesforceFactEvent] = []
        for record in page.get("records", []):
            valid_from = _parse_sf_timestamp(record["LastModifiedDate"])
            for name in sorted(record):
                value = record[name]
                if name in _METADATA_FIELDS or value is None:
                    continue
                events.append(
                    SalesforceFactEvent(
                        source=SOURCE,
                        entity_id=str(record["Id"]),
                        field_name=name,
                        value=value,
                        valid_from=valid_from,
                        raw_payload=record,
                        object_type=sobject,
                        visibility_policy=list(visibility_policy),
                    )
                )
        return events

    @staticmethod
    def principal_for_share(row: Mapping[str, Any]) -> str | None:
        """Classify one AccountShare row → its RAW ``UserOrGroupId`` id.

        A ``005`` (User) or ``00G`` (Group) id is returned VERBATIM for the
        per-account id list; anything else contributes nothing (skipping an
        unknown prefix cannot widen visibility). This is a classifier, NOT a
        token minter — the raw-id ``user:005…`` / ``group:00G…`` strings it used
        to return were the identity gap; crosswalk to cross-source principal
        tokens happens in :meth:`resolve_share_principals` against the roster.
        """
        user_or_group = str(row.get("UserOrGroupId") or "")
        if user_or_group.startswith(USER_KEY_PREFIX) or user_or_group.startswith(GROUP_KEY_PREFIX):
            return user_or_group
        logger.debug("AccountShare row with unrecognized UserOrGroupId prefix: %r", user_or_group)
        return None

    @staticmethod
    def resolve_share_principals(
        share_ids: Iterable[str], users_by_id: Mapping[str, SalesforceUserInfo]
    ) -> tuple[list[str] | None, list[str] | None]:
        """Crosswalk raw AccountShare ids → (group principals, owner subjects).

        M2 2b — a ``005`` User resolves NOT to ``user:<email>`` but to its
        ``FederationIdentifier`` SSO subject, which the shared sink sends through
        the registry ``emails`` gate (``idp_subject``/``principal_sso_alias``
        match → the canonical ``user:<primaryEmail>`` token). A ``005`` with no
        ``FederationIdentifier`` — or ``IsActive=false``, or absent from the
        roster — is DROPPED (over-hide, fail closed; ``User.Email`` is NEVER a
        fallback for SF). A ``00G`` Group → the already-canonical
        ``group:salesforce-group-<id>`` string (mirrored into SpiceDB by
        :meth:`_fetch_roster`), resolved via the ``principals`` field.

        Returns ``(groups, owner_emails)`` — each ``[] → None`` — so an unowned /
        all-dropped record rides the admin ``--visibility`` floor.
        """
        groups: list[str] = []
        owner_emails: list[str] = []
        for share_id in share_ids:
            if share_id.startswith(USER_KEY_PREFIX):
                info = users_by_id.get(share_id)
                if info is None or not info.is_active or not info.federation_identifier:
                    continue  # unresolvable 005 (no SSO subject / inactive) → dropped
                subject = info.federation_identifier.strip().lower()
                if subject and subject not in owner_emails:
                    owner_emails.append(subject)
            elif share_id.startswith(GROUP_KEY_PREFIX):
                principal = group_principal(share_id)
                if principal not in groups:
                    groups.append(principal)
        return (groups or None, owner_emails or None)

    # ---------- lanes ----------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op by design: Salesforce CDC is delivered over the Pub/Sub API
        (gRPC), which this poll-first connector does not speak yet; the truth
        lane reconciles everything the push lane would have delivered."""
        return
        yield  # pragma: no cover — makes this an (empty) async generator

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """One truth-lane cycle: for each sobject, SOQL-select records with
        ``LastModifiedDate`` strictly greater than ``cursor`` (None = from
        epoch, no WHERE clause), ascending, following queryMore pagination.
        Returns the events and the max LastModifiedDate seen as next cursor.

        Accounts changed in the window additionally get their AccountShare
        ``005``/``00G`` ids (``share_principals``), crosswalked through the
        User/Group roster into ``record_principals`` (``user:<email>`` /
        ``group:salesforce-group-<id>``) and the nested GroupMember edges into
        :attr:`group_edges` (mirrored to SpiceDB by the runner BEFORE facts land).
        A failed share/roster fetch never gates the facts — they ride the admin
        ``--visibility`` floor (fail closed); a 403 trips :attr:`roster_degraded`.
        """
        events: list[FactEvent | DocumentEvent] = []
        next_cursor = cursor or "1970-01-01T00:00:00+00:00"
        records_by_type: dict[str, list[str]] = {}
        contact_parent: dict[str, str] = {}
        for sobject in self.object_types:
            async for page in self._query_pages(self._soql(sobject, cursor)):
                events.extend(self.events_from_query_page(sobject, page, self.visibility_policy))
                for record in page.get("records", []):
                    modified = record.get("LastModifiedDate")
                    if modified and _parse_sf_timestamp(modified) > _parse_sf_timestamp(
                        next_cursor
                    ):
                        next_cursor = modified
                    records_by_type.setdefault(sobject, []).append(str(record["Id"]))
                    if sobject == "Contact":
                        parent = record.get("AccountId")
                        if isinstance(parent, str) and parent:
                            contact_parent[str(record["Id"])] = parent

        # Per-record ACL reconstruction (shares + role hierarchy + Contact
        # parent-inheritance) across Account/Opportunity/Contact. Best-effort and
        # fail-closed throughout: a failed fetch leaves records on the admin floor.
        if self.fetch_account_shares:
            await self._resolve_visibility(events, records_by_type, contact_parent)

        # ORG-WIDE VIEW ALL DATA / MODIFY ALL DATA (SPEC §14.3 completeness). These
        # profile/permission-set grants let a user read EVERY record regardless of
        # sharing and are NOT AccountShare rows, so the connector over-hides such
        # users today (measured: the fidelity audit's `view-all-data` cause). Mirror
        # them as VIEW_ALL_GROUP whose members are the view-all users' fed subjects,
        # stamped on every record. Over-hide-only by construction: it can only ADD
        # visibility Salesforce itself already grants. A 403/error on the query →
        # empty set → no stamp (stays over-hidden; fail closed, never a leak).
        if self.mirror_view_all:
            view_all_subjects = await self._fetch_view_all_subjects()
            if view_all_subjects:
                self.group_edges[VIEW_ALL_GROUP] = {
                    f"{FEDERATION_SUBJECT_PREFIX}{s}" for s in sorted(view_all_subjects)
                }
                for event in events:
                    if isinstance(event, SalesforceFactEvent):
                        principals = list(event.record_principals or [])
                        if VIEW_ALL_GROUP not in principals:
                            principals.append(VIEW_ALL_GROUP)
                        event.record_principals = principals
        return events, next_cursor

    async def _resolve_visibility(
        self,
        events: list[FactEvent | DocumentEvent],
        records_by_type: Mapping[str, list[str]],
        contact_parent: Mapping[str, str],
    ) -> None:
        """Reconstruct per-record visibility for Account/Opportunity/Contact.

        - **Account, Opportunity** — resolve their ``<Object>Share`` rows (owner +
          manual/rule/group shares) through the roster, plus implicit role-hierarchy
          (ancestor-role groups). One shared roster fetch covers every object's
          share ids so nested group edges are mirrored once.
        - **Contact** — under the common "Controlled by Parent" OWD a contact has NO
          share rows; its access IS the parent Account's, so it INHERITS the parent
          Account's fully-resolved principals (owner + shares + hierarchy) via
          ``Contact.AccountId``.

        Fail-closed: a share-fetch error leaves those records on the admin floor; a
        roster error degrades EVERYTHING to the floor (never stamp on a partial
        roster). Mutates the events + :attr:`group_edges` in place."""
        # (A) records needing a share lookup, by object; contacts pull in their
        # parent Accounts so inheritance has a resolved parent to copy.
        account_ids = set(records_by_type.get("Account", []))
        account_ids |= set(contact_parent.values())
        share_ids: dict[str, list[str]] = {
            "Account": sorted(account_ids),
            "Opportunity": sorted(set(records_by_type.get("Opportunity", []))),
        }

        # (B) fetch <Object>Share rows (best-effort; additive metadata).
        shares: dict[str, list[str]] = {}
        for object_type, ids in share_ids.items():
            if not ids:
                continue
            try:
                shares.update(await self._object_share_principals(object_type, ids))
            except httpx.HTTPError as exc:
                logger.warning(
                    "%sShare fetch failed (%s); those records ride admin floor",
                    object_type,
                    exc,
                )
        for event in events:
            if isinstance(event, SalesforceFactEvent) and event.object_type in SHARE_OBJECTS:
                event.share_principals = list(shares.get(event.entity_id, []))

        # (C) ONE roster fetch over every object's share ids → users + group edges.
        user_ids = sorted({s for v in shares.values() for s in v if s.startswith(USER_KEY_PREFIX)})
        group_ids = sorted({s for v in shares.values() for s in v if s.startswith(GROUP_KEY_PREFIX)})
        users_by_id: dict[str, SalesforceUserInfo] = {}
        if user_ids or group_ids:
            try:
                users_by_id, self.group_edges = await self._fetch_roster(user_ids, group_ids)
            except httpx.HTTPError as exc:
                # 403 already set roster_degraded; any other error means the
                # GroupMember edges never reached SpiceDB — stamping would
                # under-grant. Drop everything to the floor (fail closed).
                logger.warning("roster fetch failed (%s); facts ride admin policy", exc)
                users_by_id, self.group_edges = {}, {}
                self.roster_degraded = True
        if self.roster_degraded:
            return

        # (D) resolve every Account (incl. contact parents) once — the source of
        # both Account-event stamps and Contact inheritance.
        account_resolved: dict[str, tuple[list[str] | None, list[str] | None]] = {
            acct: self.resolve_share_principals(shares.get(acct, []), users_by_id)
            for acct in account_ids
        }
        # (E) stamp Account + Opportunity events from their own shares.
        for event in events:
            if isinstance(event, SalesforceFactEvent) and event.object_type in SHARE_OBJECTS:
                groups, owner_emails = self.resolve_share_principals(
                    event.share_principals or [], users_by_id
                )
                event.record_principals = groups
                event.record_owner_emails = owner_emails

        # (F) role hierarchy per share-object; fold Account hierarchy groups into
        # account_resolved so contacts inherit their parent's managers too.
        if self.mirror_role_hierarchy:
            for object_type in SHARE_OBJECTS:
                hier_groups, hier_edges = await self._fetch_role_hierarchy(
                    object_type, share_ids[object_type]
                )
                self.group_edges.update(hier_edges)
                if not hier_groups:
                    continue
                for event in events:
                    if isinstance(event, SalesforceFactEvent) and event.object_type == object_type:
                        extra = hier_groups.get(event.entity_id)
                        if extra:
                            event.record_principals = _merge_principals(
                                event.record_principals, extra
                            )
                if object_type == "Account":
                    for acct, extra in hier_groups.items():
                        groups, owners = account_resolved.get(acct, (None, None))
                        account_resolved[acct] = (_merge_principals(groups, extra), owners)

        # (G) Contact inheritance (Controlled by Parent): copy the parent Account's
        # resolved principals onto the contact.
        for event in events:
            if isinstance(event, SalesforceFactEvent) and event.object_type == "Contact":
                parent = contact_parent.get(event.entity_id)
                if parent and parent in account_resolved:
                    groups, owner_emails = account_resolved[parent]
                    event.record_principals = list(groups) if groups else None
                    event.record_owner_emails = list(owner_emails) if owner_emails else None

    async def _fetch_role_hierarchy(
        self, object_type: str, record_ids: Sequence[str]
    ) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
        """Reconstruct implicit role-hierarchy read access for a set of records of
        ``object_type`` (Account or Opportunity — any object with an ``OwnerId``).

        Returns ``(per_record, edges)``:
        - ``per_record[record_id]`` = the :func:`role_principal` strings to stamp
          — one per ANCESTOR role of the record owner's role that has members.
        - ``edges[role_group]`` = the ``fed:<subject>`` members of that ancestor
          role (the managers), for :meth:`sync_group_edges` to mirror into SpiceDB.

        Four read-only queries: the record owners, the full UserRole tree, the
        owners' roles, and the ancestor roles' members (fed id + active). A user
        with no FederationIdentifier / inactive confers nothing (over-hide, fail
        closed). ANY HTTP error degrades to empty — managers stay over-hidden
        (safe), and the base sync never fails on an additive completeness source.
        """
        if not record_ids:
            return {}, {}
        try:
            # (1) the full role tree FIRST -> parent map. An org with NO roles (the
            # common case) short-circuits here after one cheap query — no hierarchy
            # to reconstruct, nothing more to fetch.
            parent: dict[str, str | None] = {}
            async for page in self._query_pages("SELECT Id, ParentRoleId FROM UserRole"):
                for row in page.get("records", []):
                    parent[str(row["Id"])] = row.get("ParentRoleId") or None
            if not parent:
                return {}, {}

            # (2) record -> owner 005
            owner_of: dict[str, str] = {}
            for chunk in _chunks(list(record_ids), SHARE_QUERY_CHUNK):
                ids = ", ".join(f"'{a}'" for a in chunk)
                async for page in self._query_pages(
                    f"SELECT Id, OwnerId FROM {object_type} WHERE Id IN ({ids})"
                ):
                    for row in page.get("records", []):
                        owner = str(row.get("OwnerId") or "")
                        if owner.startswith(USER_KEY_PREFIX):
                            owner_of[str(row["Id"])] = owner
            if not owner_of:
                return {}, {}

            def ancestors(role_id: str | None) -> list[str]:
                out: list[str] = []
                seen: set[str] = set()
                cur = parent.get(role_id) if role_id else None
                while cur and cur not in seen:
                    seen.add(cur)
                    out.append(cur)
                    cur = parent.get(cur)
                return out

            # (3) owners' roles
            owner_ids = sorted(set(owner_of.values()))
            role_of_owner: dict[str, str | None] = {}
            for chunk in _chunks(owner_ids, SHARE_QUERY_CHUNK):
                ids = ", ".join(f"'{u}'" for u in chunk)
                async for page in self._query_pages(
                    f"SELECT Id, UserRoleId FROM User WHERE Id IN ({ids})"
                ):
                    for row in page.get("records", []):
                        role_of_owner[str(row["Id"])] = row.get("UserRoleId") or None

            # per account -> the ancestor roles whose members should see it
            acct_ancestors: dict[str, list[str]] = {}
            needed_roles: set[str] = set()
            for acct, owner in owner_of.items():
                anc = ancestors(role_of_owner.get(owner))
                if anc:
                    acct_ancestors[acct] = anc
                    needed_roles.update(anc)
            if not needed_roles:
                return {}, {}

            # (4) members (fed subjects) of every needed ancestor role
            role_members: dict[str, set[str]] = {}
            for chunk in _chunks(sorted(needed_roles), SHARE_QUERY_CHUNK):
                ids = ", ".join(f"'{r}'" for r in chunk)
                async for page in self._query_pages(
                    "SELECT Id, FederationIdentifier, IsActive, UserRoleId "
                    f"FROM User WHERE UserRoleId IN ({ids})"
                ):
                    for row in page.get("records", []):
                        fed = (row.get("FederationIdentifier") or "").strip().lower()
                        if fed and bool(row.get("IsActive", True)):
                            role_members.setdefault(str(row["UserRoleId"]), set()).add(fed)

            edges: dict[str, set[str]] = {
                role_principal(r): {f"{FEDERATION_SUBJECT_PREFIX}{s}" for s in members}
                for r, members in role_members.items()
                if members
            }
            per_account: dict[str, list[str]] = {}
            for acct, anc in acct_ancestors.items():
                groups = [role_principal(r) for r in anc if role_members.get(r)]
                if groups:
                    per_account[acct] = groups
            return per_account, edges
        except httpx.HTTPError as exc:
            logger.warning(
                "salesforce: role-hierarchy query failed (%s); managers over-hide "
                "this cycle (fail closed, never a leak)",
                exc,
            )
            return {}, {}

    async def _fetch_view_all_subjects(self) -> set[str]:
        """FederationIdentifier subjects of active users with org-wide View All
        Data or Modify All Data.

        One join covers both profile- and permission-set-granted view-all: a
        Profile is a ``PermissionSet`` with ``IsOwnedByProfile=true``, so
        ``PermissionSetAssignment`` where the assigned set has
        ``PermissionsViewAllData``/``PermissionsModifyAllData`` enumerates every
        such user. Then one ``User`` query resolves their FederationIdentifier —
        the same join key as everywhere else; a user with no fed id / inactive
        confers nothing (over-hide, fail closed; no ``User.Email`` fallback).

        ANY HTTP error (403 lacking read on the permission objects, or a transient
        fault) degrades to the EMPTY set — records simply stay over-hidden for
        view-all users, which is safe. Never raises into the poll: mirroring
        view-all is additive, and failing it must never drop the base sync.
        """
        try:
            assignees: set[str] = set()
            soql = (
                "SELECT AssigneeId FROM PermissionSetAssignment WHERE "
                "PermissionSet.PermissionsViewAllData = true OR "
                "PermissionSet.PermissionsModifyAllData = true"
            )
            async for page in self._query_pages(soql):
                for row in page.get("records", []):
                    aid = str(row.get("AssigneeId") or "")
                    if aid.startswith(USER_KEY_PREFIX):
                        assignees.add(aid)
            subjects: set[str] = set()
            for chunk in _chunks(sorted(assignees), SHARE_QUERY_CHUNK):
                ids = ", ".join(f"'{uid}'" for uid in chunk)
                async for page in self._query_pages(
                    f"SELECT Id, FederationIdentifier, IsActive FROM User WHERE Id IN ({ids})"
                ):
                    for row in page.get("records", []):
                        fed = (row.get("FederationIdentifier") or "").strip().lower()
                        if fed and bool(row.get("IsActive", True)):
                            subjects.add(fed)
            return subjects
        except httpx.HTTPError as exc:
            logger.warning(
                "salesforce: View-All query failed (%s); records over-hide view-all "
                "users this cycle (fail closed, never a leak)",
                exc,
            )
            return set()

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl: identical to a poll from epoch. (Deleted-
        record reconciliation via queryAll/IsDeleted lands with the §8c
        tombstone work.)"""
        events, _ = await self.poll(None)
        for event in events:
            yield event

    # ---------- SOQL + HTTP plumbing ----------

    def _soql(self, sobject: str, cursor: str | None) -> str:
        names = ["Id", *self.fields[sobject], "LastModifiedDate"]
        soql = f"SELECT {', '.join(names)} FROM {sobject}"
        if cursor:
            soql += f" WHERE LastModifiedDate > {_soql_datetime(cursor)}"
        return soql + " ORDER BY LastModifiedDate ASC"

    async def _query_pages(self, soql: str) -> AsyncIterator[dict]:
        """GET /query then follow ``nextRecordsUrl`` (queryMore) until done."""
        page = await self._get_json(QUERY_PATH, params={"q": soql})
        yield page
        while not page.get("done", True):
            page = await self._get_json(page["nextRecordsUrl"])
            yield page

    async def _object_share_principals(
        self, object_type: str, record_ids: Iterable[str]
    ) -> dict[str, list[str]]:
        """``<Object>Share`` rows for the given records → per-record RAW share ids
        (005/00G, deduped, in row order). Chunked ``IN (...)`` queries.

        Generic over :data:`SHARE_OBJECTS` (Account, Opportunity): the share object
        and its foreign-key column differ per object, but the row shape — a
        ``UserOrGroupId`` classified by :meth:`principal_for_share` — is identical,
        so owner/manual/rule shares resolve through the same crosswalk regardless
        of which object they protect."""
        share_object, key = SHARE_OBJECTS[object_type]
        shares: dict[str, list[str]] = {}
        for chunk in _chunks(list(record_ids), SHARE_QUERY_CHUNK):
            ids = ", ".join(f"'{rid}'" for rid in chunk)
            soql = f"SELECT {key}, UserOrGroupId, RowCause FROM {share_object} WHERE {key} IN ({ids})"
            async for page in self._query_pages(soql):
                for row in page.get("records", []):
                    principal = self.principal_for_share(row)
                    if principal is None:
                        continue
                    principals = shares.setdefault(row[key], [])
                    if principal not in principals:
                        principals.append(principal)
        return shares

    async def _fetch_roster(
        self, user_ids: Iterable[str], group_ids: Iterable[str]
    ) -> tuple[dict[str, SalesforceUserInfo], dict[str, set[str]]]:
        """Build the identity crosswalk roster for a set of share ids.

        Two SOQL objects (reusing :meth:`_query_pages` / :meth:`_get_json` — no
        new HTTP path). ``Group.Type`` is never needed: the token derives from
        the id alone (:func:`group_principal`), so no ``FROM Group`` query is
        issued — only ``GroupMember`` and ``User``.

        1. ``GroupMember`` BFS over the ``group_ids`` set collects the raw
           member ids per parent group. ``UserOrGroupId`` may be a ``005`` User
           OR another ``00G`` Group (a NESTED edge); a child group is itself
           expanded — breadth-first, bounded by a ``seen`` visited-set (cycles
           terminate) and :data:`GROUP_EXPANSION_MAX`.
        2. ``User`` → ``users_by_id[005] = SalesforceUserInfo(email,
           federation_identifier, is_active)``. The query covers the UNION of the
           share-derived ``user_ids`` AND every ``005`` discovered as a
           GroupMember — so a user who is ONLY a group member (the common case
           for group shares) still gets an edge. M2 2b — the join key is
           ``FederationIdentifier`` (the SSO subject), NOT ``User.Email`` and NOT
           ``Username``. A ``005`` with no ``FederationIdentifier`` (or inactive)
           confers nothing (over-hide, fail closed; no ``User.Email`` fallback).
        3. ``group_edges[group:salesforce-group-<parent>]`` is assembled from
           the collected member ids: a ``00G`` member → a nested
           ``group:salesforce-group-<child>`` edge; a ``005`` member → its
           ``fed:<FederationIdentifier>`` subject marker, which the sink
           canonicalizes through the registry ``emails`` gate before mirroring
           the edge (dropped if inactive / no SSO subject / no alias match).

        A **403** on any roster query means the integration user lacks read on
        that object: degrade to EMPTY roster (every record → admin fallback),
        loudly, rather than failing the sync — fail closed, never permissive.
        (The caller treats ANY roster HTTPError the same way — see :meth:`poll`.)
        Only the DIRECT ``group ⊃ member`` edges are mirrored; SpiceDB closes
        transitivity server-side.
        """
        users_by_id: dict[str, SalesforceUserInfo] = {}
        group_edges: dict[str, set[str]] = {}
        try:
            # (1) BFS the GroupMember graph first, capturing raw member ids per
            # parent group so we can query EVERY member-005 email in one shot.
            raw_members: dict[str, list[str]] = {}
            member_user_ids: set[str] = set()
            seen: set[str] = set()
            frontier = [gid for gid in dict.fromkeys(group_ids)]
            while frontier and len(seen) < GROUP_EXPANSION_MAX:
                batch = [gid for gid in frontier if gid not in seen][
                    : GROUP_EXPANSION_MAX - len(seen)
                ]
                seen.update(batch)
                frontier = []
                if not batch:
                    break
                for chunk in _chunks(batch, SHARE_QUERY_CHUNK):
                    ids = ", ".join(f"'{gid}'" for gid in chunk)
                    member_soql = (
                        f"SELECT GroupId, UserOrGroupId FROM GroupMember WHERE GroupId IN ({ids})"
                    )
                    async for page in self._query_pages(member_soql):
                        for row in page.get("records", []):
                            parent = group_principal(str(row["GroupId"]))
                            member_id = str(row.get("UserOrGroupId") or "")
                            raw_members.setdefault(parent, []).append(member_id)
                            group_edges.setdefault(parent, set())
                            if member_id.startswith(GROUP_KEY_PREFIX):
                                if member_id not in seen:
                                    frontier.append(member_id)
                            elif member_id.startswith(USER_KEY_PREFIX):
                                member_user_ids.add(member_id)

            # (2) One User query over the union of share-derived AND group-member
            # 005 ids — a group-only user still gets its edge. M2 2b: SELECT the
            # FederationIdentifier SSO subject (the join key) + IsActive; Email is
            # kept for logging only, Username for the honest "not the join key"
            # note. A user with no FederationIdentifier / inactive confers nothing.
            all_user_ids = list(dict.fromkeys([*user_ids, *sorted(member_user_ids)]))
            for chunk in _chunks(all_user_ids, SHARE_QUERY_CHUNK):
                ids = ", ".join(f"'{uid}'" for uid in chunk)
                soql = (
                    "SELECT Id, Email, Username, FederationIdentifier, IsActive "
                    f"FROM User WHERE Id IN ({ids})"
                )
                async for page in self._query_pages(soql):
                    for row in page.get("records", []):
                        email = (row.get("Email") or "").strip().lower()
                        fed = (row.get("FederationIdentifier") or "").strip().lower() or None
                        users_by_id[str(row["Id"])] = SalesforceUserInfo(
                            email=email,
                            federation_identifier=fed,
                            is_active=bool(row.get("IsActive", True)),
                        )

            # (3) Resolve member ids → edge principals now that the roster is complete.
            # A 00G member is an already-canonical nested group. A 005 member is
            # emitted as its FederationIdentifier SSO subject wrapped as
            # ``fed:<subject>`` so the sink canonicalizes it through the registry
            # ``emails`` gate before mirroring the edge (NEVER a blind user:<email>
            # weld); an inactive / subject-less 005 confers no edge (fail closed).
            for parent, members in raw_members.items():
                edge = group_edges.setdefault(parent, set())
                for member_id in members:
                    if member_id.startswith(GROUP_KEY_PREFIX):
                        edge.add(group_principal(member_id))
                    elif member_id.startswith(USER_KEY_PREFIX):
                        info = users_by_id.get(member_id)
                        if info is not None and info.is_active and info.federation_identifier:
                            edge.add(f"{FEDERATION_SUBJECT_PREFIX}{info.federation_identifier}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                self.roster_degraded = True
                print(
                    "salesforce: User/Group roster query returned 403 — grant the "
                    "integration user read on User, Group and GroupMember to "
                    "crosswalk 005/00G share ids to cross-source principals; "
                    "falling back to the admin-assigned --visibility for every record",
                    file=sys.stderr,
                )
                return {}, {}
            raise
        return users_by_id, group_edges

    async def _get_json(self, path: str, params: Mapping[str, str] | None = None) -> dict:
        """GET with Bearer auth and the shared 401-retry-once hook (a 401
        means the cached client-credentials token died: mint and retry once)."""
        response = await request_with_auth_retry(
            self._client, self.credential, "GET", path, params=dict(params or {})
        )
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        await self._client.aclose()
        aclose = getattr(self.credential, "aclose", None)
        if aclose is not None:
            await aclose()


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
        prog="python -m verity_ingest.connectors.salesforce",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument(
        "--once", action="store_true", required=True, help="run one truth-lane poll cycle"
    )
    parser.add_argument(
        "--visibility",
        required=True,
        help="comma-separated principal tokens — the admin-assigned visibility "
        "policy enforced on every event (required, no default; share-derived "
        "principals are approximated metadata, not enforcement — SPEC §5e.2)",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("SALESFORCE_STATE_FILE", ".verity/salesforce_cursor")),
        help="cursor persistence path (default: $SALESFORCE_STATE_FILE or "
        ".verity/salesforce_cursor)",
    )
    parser.add_argument(
        "--no-shares",
        action="store_true",
        help="skip the best-effort AccountShare principal fetch",
    )
    args = parser.parse_args(argv)

    try:
        policy = [int(tok) for tok in args.visibility.split(",") if tok.strip()]
    except ValueError:
        parser.error("--visibility must be comma-separated integers, e.g. 1,2")
    if not policy:
        parser.error("--visibility must name at least one principal token (fail closed)")

    sink = VerityDebeziumSink.from_env()

    async def run_once() -> tuple[list[SalesforceFactEvent], str, dict[str, set[str]], bool]:
        connector = SalesforceConnector(policy, fetch_account_shares=not args.no_shares)
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            # group_edges is the source of the SpiceDB edges; capture it (and the
            # degraded flag) before the client closes.
            return (
                list(events),  # type: ignore[arg-type]
                next_cursor,
                {g: set(m) for g, m in connector.group_edges.items()},
                connector.roster_degraded,
            )
        finally:
            await connector.aclose()

    events, next_cursor, group_edges, roster_degraded = asyncio.run(run_once())
    # Sync group membership FIRST so a subject resolves through their group the
    # moment group-scoped facts land (identical to the HubSpot runner lifecycle).
    edges = sink.sync_group_edges(group_edges)
    # The shared sink heartbeats /v1/admin/connector-status after delivery
    # (best-effort; source rides on the events, so this reports "salesforce").
    summary = sink.post(events, cursor=next_cursor)
    _write_cursor(args.state_file, next_cursor)
    scoped = sum(1 for e in events if getattr(e, "record_principals", None))
    print(
        f"poll: {len(events)} fact event(s) ({scoped} share-scoped, "
        f"{edges} group edge(s)), cursor -> {next_cursor} -> {summary}"
    )
    if roster_degraded:
        # Stable, machine-readable stdout token — the read-once contract the
        # server greps for backfill state=degraded_acl (never stderr-only).
        print(DEGRADED_ACL_SIGNAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
