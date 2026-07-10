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
that. What it does, best-effort:

- For Accounts changed in a poll cycle it fetches ``AccountShare`` rows and
  records AclEnvelope-style principal strings — ``user:<UserOrGroupId>`` for
  005-prefixed users, ``group:<UserOrGroupId>`` for 00G-prefixed groups —
  on the event as ``share_principals``, with ACL provenance intent
  ``"approximated"`` (:data:`SHARE_ACL_PROVENANCE`).
- Those share-derived principals are **ADDITIVE metadata for the future
  identity crosswalk, not enforced visibility**. Enforcement uses the same
  fail-closed fallback as the tier-C HubSpot connector: the constructor
  requires an admin-assigned ``visibility_policy`` (no default), every
  emitted event carries it, and share failures never gate facts (the fetch
  is best-effort by construction). When the identity plane can crosswalk
  005/00G ids to Verity principal tokens *and* the implicit-sharing/territory
  gap is closed, these events already carry the raw material.

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

#: SOQL ``IN (...)`` chunk size for AccountShare lookups (keeps each query
#: comfortably under the SOQL statement-length limit).
SHARE_QUERY_CHUNK = 200

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
    """A FactEvent plus the sobject type (→ Debezium ``source.table``), the
    admin-assigned visibility policy (enforced, fail closed), and — for
    Accounts — best-effort share-derived principals (additive metadata with
    provenance intent :data:`SHARE_ACL_PROVENANCE`, NOT enforced)."""

    object_type: str
    visibility_policy: list[int]
    share_principals: list[str] = field(default_factory=list)


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
        token_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.visibility_policy = list(visibility_policy)
        self.fields = dict(DEFAULT_FIELDS, **(fields or {}))
        self.fetch_account_shares = fetch_account_shares

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
        """Map one AccountShare row to an AclEnvelope-style principal string.

        ``UserOrGroupId`` key-prefix 005 → ``user:<id>``, 00G → ``group:<id>``
        (public groups, roles-as-groups, territory groups all surface as 00G).
        Anything else contributes nothing — these principals are additive,
        unenforced metadata, so skipping the unknown cannot widen visibility.
        """
        user_or_group = str(row.get("UserOrGroupId") or "")
        if user_or_group.startswith(USER_KEY_PREFIX):
            return f"user:{user_or_group}"
        if user_or_group.startswith(GROUP_KEY_PREFIX):
            return f"group:{user_or_group}"
        logger.debug("AccountShare row with unrecognized UserOrGroupId prefix: %r", user_or_group)
        return None

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

        Accounts changed in the window additionally get best-effort
        ``share_principals`` from AccountShare (see the module docstring);
        a failed share fetch logs a warning and never gates the facts.
        """
        events: list[FactEvent | DocumentEvent] = []
        next_cursor = cursor or "1970-01-01T00:00:00+00:00"
        changed_accounts: list[str] = []
        for sobject in self.object_types:
            async for page in self._query_pages(self._soql(sobject, cursor)):
                events.extend(self.events_from_query_page(sobject, page, self.visibility_policy))
                for record in page.get("records", []):
                    modified = record.get("LastModifiedDate")
                    if modified and _parse_sf_timestamp(modified) > _parse_sf_timestamp(
                        next_cursor
                    ):
                        next_cursor = modified
                    if sobject == "Account" and record["Id"] not in changed_accounts:
                        changed_accounts.append(record["Id"])

        if changed_accounts and self.fetch_account_shares:
            try:
                shares = await self._account_share_principals(changed_accounts)
            except httpx.HTTPError as exc:
                # Best-effort by construction: share principals are additive
                # metadata; the admin-assigned policy already protects the facts.
                logger.warning("AccountShare fetch failed (%s); facts proceed without", exc)
                shares = {}
            for event in events:
                if isinstance(event, SalesforceFactEvent) and event.object_type == "Account":
                    event.share_principals = list(shares.get(event.entity_id, []))
        return events, next_cursor

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

    async def _account_share_principals(self, account_ids: Iterable[str]) -> dict[str, list[str]]:
        """AccountShare rows for the changed accounts → per-account principal
        strings (deduplicated, in row order). Chunked ``IN (...)`` queries."""
        shares: dict[str, list[str]] = {}
        for chunk in _chunks(list(account_ids), SHARE_QUERY_CHUNK):
            ids = ", ".join(f"'{account_id}'" for account_id in chunk)
            soql = (
                "SELECT AccountId, UserOrGroupId, AccountAccessLevel, RowCause "
                f"FROM AccountShare WHERE AccountId IN ({ids})"
            )
            async for page in self._query_pages(soql):
                for row in page.get("records", []):
                    principal = self.principal_for_share(row)
                    if principal is None:
                        continue
                    principals = shares.setdefault(row["AccountId"], [])
                    if principal not in principals:
                        principals.append(principal)
        return shares

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

    async def run_once() -> tuple[list[SalesforceFactEvent], str]:
        connector = SalesforceConnector(policy, fetch_account_shares=not args.no_shares)
        try:
            events, next_cursor = await connector.poll(_read_cursor(args.state_file))
            return list(events), next_cursor  # type: ignore[arg-type]
        finally:
            await connector.aclose()

    events, next_cursor = asyncio.run(run_once())
    # The shared sink heartbeats /v1/admin/connector-status after delivery
    # (best-effort; source rides on the events, so this reports "salesforce").
    summary = sink.post(events, cursor=next_cursor)
    _write_cursor(args.state_file, next_cursor)
    print(f"poll: {len(events)} fact event(s), cursor -> {next_cursor} -> {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
