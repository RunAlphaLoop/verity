"""Google Workspace directory-sync connector — the Identity Plane's first
directory surface (SPEC.md §6a), a *distinct connector surface from content
connectors*: it syncs principals and group membership, never documents.

This is the Admin SDK Directory API, **not** the Drive API: user list plus
full nested-group membership (Groups can contain Groups; Drive ACLs reference
the outer group; correct closure requires recursive membership resolution via
the Admin SDK — which is exactly why the gdrive connector defers nested-group
closure here instead of bolting it on). It pays ROADMAP.md's "Google Admin
SDK directory sync not yet" debt and unblocks §3 backfill ordering: identity
first, ACLs before content — without this sync, `group:...` visibility tokens
never match a caller's resolved principal set and every query fail-closes to
empty.

Auth (BYOT doctrine, §5e.2): the customer's *own* service account with
domain-wide delegation; key path from ``GOOGLE_APPLICATION_CREDENTIALS``,
google-auth lazily imported so fixture tests never need it (same path as
gdrive — see credentials.py for why Google connectors keep google-auth over
``ServiceAccountJwt``). Unlike Drive, the delegated subject is REQUIRED: the
Admin SDK only answers as an impersonated admin user (a workspace super-admin
or delegated-admin role holder), configured via ``GADMIN_DELEGATED_SUBJECT``
or ``--subject``. Scopes: ``admin.directory.user.readonly`` and
``admin.directory.group.readonly`` (member reads are covered by the group
scope); both must be granted in the customer's DWD config.

Truth lane — full reconcile, honestly: the Directory API has **no incremental
sync token** for users.list / groups.list / members.list (ETags are
cache-validation only), so each cycle pages the full user list, the full
group list, and every group's direct members, then diffs against the previous
cycle's snapshot (the JSON state file). Group-membership freshness is
therefore bounded by the poll interval — that bound is part of the published
ACL-sync SLO (§6a). The ``users.watch`` push lane is a later optimization,
mirroring gdrive's no-op push lane; poll is the truth lane per §6a either way.

Nested groups — deliver DIRECT edges, let SpiceDB own the closure: the server
models nesting natively (``POST /v1/admin/groups`` accepts
``member: "group:<inner>"``, and ``DELETE``'s tombstone resolution walks
``group_users``/``group_and_ancestors`` over that graph). So a members.list
entry of ``type=GROUP`` becomes a ``group:<outer> ⊃ group:<inner>`` tuple —
we deliberately do NOT use ``includeDerivedMembership`` (it flattens
transitive membership, destroying the nesting structure the ReBAC graph and
the server's ancestor-resolution logic depend on).
:func:`transitive_user_closure` computes the flat per-group user closure
locally — cycle-safe, since Google permits indirect membership cycles — for
the §6c conformance assertions and operator diagnostics only; it is never
what we deliver.

Member mapping (fail-closed, §6b):

- ``type=USER``     → ``user:<email>`` (lowercased), but only when the email
  belongs to an ACTIVE directory user — suspended/archived users and emails
  users.list never vouched for (the "email-only unverifiable" case) confer
  nothing.
- ``type=GROUP``    → ``group:<email>`` (lowercased), but only when the email
  is a group groups.list enumerated; self-membership is skipped (the server
  422s it).
- ``type=CUSTOMER`` → ``domain:<config.domain>`` (the whole-domain membership
  convention gdrive already emits); skipped when ``domain`` is unconfigured.
- ``type=EXTERNAL`` / anything else → contributes nothing.

Unlike a content ACL there is no envelope to poison: each unmappable member
simply confers no visibility (§6b), which only ever *narrows* what the group
grants.

Deprovisioning: a user suspended, archived, or deleted in Workspace drops out
of the desired snapshot, so the diff removes every membership tuple that
referenced them — each removal via ``DELETE /v1/admin/groups``, which writes
durable revocation tombstones BEFORE the SpiceDB tuple delete (fail-closed:
over-hides for the revocation window, never under-hides). There is no server
endpoint to retire the bare ``user:`` principal itself — principal tokens are
append-only — so the token stays allocated but grants nothing once no
tuple/ACL references it. Stated per the honest-limitations doctrine, not
hidden.

Diff-and-apply ordering (per cycle): upsert added principals → membership
ADDS → membership REMOVALS, each removal one tuple at a time (never a bulk
truncate-and-reload — every delete carries per-tuple revocation semantics).
Adds are idempotent (token upsert is keyed; re-writing an existing SpiceDB
tuple is a no-op) and re-running a removal only re-tombstones (over-hiding,
safe), so the whole cycle is at-least-once: the snapshot is checkpointed only
after every op delivers, and a crash mid-cycle replays the cycle.

Server contracts coded against (verified against the server as built —
crates/verity-server/src/main.rs; gdrive's ``HttpRegistry``, which predated
these shapes, was fixed to them alongside this connector):

- ``POST /v1/admin/principals``
  body ``{"tenant_id": "<uuid>", "principals": [...]}`` →
  ``{"mappings": {"user:a@x": 101, ...}}``. Idempotent keyed upsert.
- ``POST /v1/admin/groups``
  body ``{"tenant_id": "<uuid>", "group": "group:<g>", "member":
  "user:<u>" | "group:<inner>"}`` →
  ``{"written": true, "tokens": {...}}``. 503 without SpiceDB configured.
- ``DELETE /v1/admin/groups`` (same body) → tombstones first, then tuple
  delete; ``{"deleted": true, "tombstones": [...], ...}``.

Runner: ``python -m verity_ingest.connectors.gdirectory --once [--dry-run]``
with a JSON snapshot state file; ``--dry-run`` prints the would-be admin ops
instead of calling the server. Best-effort connector-status heartbeat after
each delivered cycle, like the content connectors.

Verification status (honest-limitations doctrine): this is a
**fixture-verified slice** — every behavior above is asserted against
fixtures built from Google's documented Admin SDK Directory API response
shapes (§6c conformance: pagination, nested groups, a membership cycle,
suspended-user deprovisioning, unverifiable-member denial), with byte-exact
expected admin-endpoint bodies. It has NOT been run against a live Google
Workspace org: live-org validation awaits a customer Workspace admin
credential (a DWD-configured service account plus an impersonable admin
subject), which we do not hold and will not fabricate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

import httpx

from verity_ingest.connectors.gdrive import (
    _HttpxAuthRequest,
    load_service_account_credentials,
)

ADMIN_BASE_URL = "https://admin.googleapis.com/admin/directory/v1"
ADMIN_USER_READONLY_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
ADMIN_GROUP_READONLY_SCOPE = "https://www.googleapis.com/auth/admin.directory.group.readonly"

PRINCIPALS_PATH = "/v1/admin/principals"
GROUPS_PATH = "/v1/admin/groups"
CONNECTOR_STATUS_PATH = "/v1/admin/connector-status"

SOURCE_NAME = "gdirectory"

# Field masks: ask Google for exactly what we consume, nothing more.
_USERS_FIELDS = "nextPageToken,users(id,primaryEmail,suspended,archived)"
_GROUPS_FIELDS = "nextPageToken,groups(id,email,name,directMembersCount)"
_MEMBERS_FIELDS = "nextPageToken,members(id,email,role,type,status)"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class GDirectoryConfig:
    """Connector configuration. No default widens visibility (§5e.8 #9)."""

    tenant_id: str = "default"
    # The workspace primary domain. Required to map type=CUSTOMER members
    # (whole-domain membership) to the `domain:<domain>` convention; when
    # unset, CUSTOMER members confer nothing (fail-closed).
    domain: str | None = None
    # Domain-wide delegation subject — REQUIRED for live runs: the Admin SDK
    # only answers as an impersonated (super/delegated) admin user.
    delegated_subject: str | None = None
    user_page_size: int = 500  # users.list maxResults cap
    group_page_size: int = 200  # groups.list / members.list maxResults cap


# ---------------------------------------------------------------------------
# Directory transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class DirectoryTransport(Protocol):
    """Minimal surface over Directory API REST, so tests run on fixtures."""

    def get_json(self, path: str, params: Mapping[str, str]) -> dict: ...


class HttpDirectoryTransport:
    """Live Directory API REST transport with service-account bearer auth."""

    def __init__(self, credentials: Any, client: httpx.Client | None = None) -> None:
        self._credentials = credentials
        self._client = client or httpx.Client(base_url=ADMIN_BASE_URL, timeout=60.0)
        self._auth_request = _HttpxAuthRequest()

    def _headers(self) -> dict[str, str]:
        if not self._credentials.valid:
            self._credentials.refresh(self._auth_request)
        return {"Authorization": f"Bearer {self._credentials.token}"}

    def get_json(self, path: str, params: Mapping[str, str]) -> dict:
        response = self._client.get(path, params=dict(params), headers=self._headers())
        response.raise_for_status()
        return response.json()


def load_directory_credentials(delegated_subject: str | None):
    """BYOT service-account credentials for the Admin SDK (google-auth, lazy).

    The delegated subject is mandatory: without impersonating a workspace
    admin the Directory API rejects every call, so failing here is clearer
    than failing on the first request.
    """
    if not delegated_subject:
        raise RuntimeError(
            "GADMIN_DELEGATED_SUBJECT is not set. The Admin SDK Directory API "
            "only answers as an impersonated admin user: grant your service "
            "account domain-wide delegation for scopes "
            "admin.directory.user.readonly + admin.directory.group.readonly "
            "and pass a (super/delegated) admin email via --subject or "
            "GADMIN_DELEGATED_SUBJECT."
        )
    return load_service_account_credentials(
        delegated_subject=delegated_subject,
        scopes=(ADMIN_USER_READONLY_SCOPE, ADMIN_GROUP_READONLY_SCOPE),
    )


# ---------------------------------------------------------------------------
# Desired-state snapshot: what the directory says right now
# ---------------------------------------------------------------------------


@dataclass
class DirectorySnapshot:
    """Canonical desired state for one reconcile cycle.

    ``users`` are the ACTIVE users' canonical principals (sorted, lowercase);
    suspended/archived users are deliberately absent — their absence is what
    drives deprovision removals in the diff. ``memberships`` are DIRECT
    ``(group, member)`` edges (sorted), where member is ``user:...``,
    ``group:...`` (nested) or ``domain:...``.
    """

    users: list[str] = field(default_factory=list)
    memberships: list[tuple[str, str]] = field(default_factory=list)

    def principals(self) -> list[str]:
        """Every principal string this snapshot references, sorted."""
        out = set(self.users)
        for group, member in self.memberships:
            out.add(group)
            out.add(member)
        return sorted(out)


def map_member(
    group: str,
    member: Mapping[str, Any],
    active_users: frozenset[str],
    known_groups: frozenset[str],
    domain: str | None,
) -> str | None:
    """Map one members.list entry to a canonical member principal, or None.

    Fail-closed per the module docstring: USER only when directory-active,
    GROUP only when groups.list enumerated it (and never the group itself —
    the server 422s self-membership), CUSTOMER only with a configured domain,
    EXTERNAL/unknown never. Returning None narrows, never widens (§6b).
    """
    mtype = member.get("type")
    email = (member.get("email") or "").lower()
    if mtype == "USER":
        return f"user:{email}" if email in active_users else None
    if mtype == "GROUP":
        if email in known_groups and f"group:{email}" != group:
            return f"group:{email}"
        return None
    if mtype == "CUSTOMER":
        return f"domain:{domain.lower()}" if domain else None
    return None  # EXTERNAL or anything Google adds later: never guess.


class GDirectoryConnector:
    """One Workspace customer's directory. Not a content ``Connector``: the
    directory surface emits principals and membership tuples (§6a), not
    Fact/Document events, so it does not subclass the content ABC."""

    name = SOURCE_NAME

    def __init__(
        self, transport: DirectoryTransport, config: GDirectoryConfig | None = None
    ) -> None:
        self._transport = transport
        self.config = config or GDirectoryConfig()

    # -- push lane ------------------------------------------------------------

    def push_events(self) -> None:
        """No-op: ``users.watch`` push needs a public HTTPS endpoint plus
        channel renewal; the reconciling poll is the truth lane (§6a) and is
        always sufficient. TODO: optional watch lane later, like gdrive's."""
        return None

    # -- truth lane: full reconcile -------------------------------------------

    def reconcile(self) -> DirectorySnapshot:
        """One full reconcile: page users, groups, and every group's direct
        members into a canonical :class:`DirectorySnapshot`."""
        active, suspended = self._list_users()
        groups = self._list_groups()
        known_groups = frozenset(groups)
        memberships: set[tuple[str, str]] = set()
        for group_email in groups:
            group = f"group:{group_email}"
            for member in self._list_members(group_email):
                mapped = map_member(group, member, active, known_groups, self.config.domain)
                if mapped is not None:
                    memberships.add((group, mapped))
        del suspended  # tracked for symmetry/debugging; absence drives removals
        return DirectorySnapshot(
            users=sorted(f"user:{email}" for email in active),
            memberships=sorted(memberships),
        )

    def _pages(self, path: str, params: dict[str, str]) -> Iterable[dict]:
        page_token: str | None = None
        while True:
            page_params = dict(params)
            if page_token:
                page_params["pageToken"] = page_token
            page = self._transport.get_json(path, page_params)
            yield page
            page_token = page.get("nextPageToken")
            if not page_token:
                return

    def _list_users(self) -> tuple[frozenset[str], frozenset[str]]:
        """(active emails, suspended-or-archived emails), lowercased."""
        active: set[str] = set()
        suspended: set[str] = set()
        params = {
            "customer": "my_customer",
            "maxResults": str(self.config.user_page_size),
            "projection": "basic",
            "showDeleted": "false",
            "fields": _USERS_FIELDS,
        }
        for page in self._pages("users", params):
            for user in page.get("users", []):
                email = (user.get("primaryEmail") or "").lower()
                if not email:
                    continue  # no vouched address: confers nothing
                if user.get("suspended") or user.get("archived"):
                    suspended.add(email)
                else:
                    active.add(email)
        return frozenset(active), frozenset(suspended)

    def _list_groups(self) -> list[str]:
        params = {
            "customer": "my_customer",
            "maxResults": str(self.config.group_page_size),
            "fields": _GROUPS_FIELDS,
        }
        emails: list[str] = []
        for page in self._pages("groups", params):
            for group in page.get("groups", []):
                email = (group.get("email") or "").lower()
                if email:
                    emails.append(email)
        return sorted(set(emails))

    def _list_members(self, group_email: str) -> list[dict]:
        # Deliberately NOT includeDerivedMembership: that flattens transitive
        # membership and destroys the nesting SpiceDB owns (module docstring).
        params = {
            "maxResults": str(self.config.group_page_size),
            "fields": _MEMBERS_FIELDS,
        }
        members: list[dict] = []
        for page in self._pages(f"groups/{group_email}/members", params):
            members.extend(page.get("members", []))
        return members


# ---------------------------------------------------------------------------
# Local closure (diagnostics + §6c conformance only — never delivered)
# ---------------------------------------------------------------------------


def transitive_user_closure(
    memberships: Iterable[tuple[str, str]],
) -> dict[str, set[str]]:
    """Flat ``group -> {user:... principals}`` transitive closure over the
    direct-edge graph. Cycle-safe: Google permits indirect membership cycles
    (A ⊃ B ⊃ A), so traversal keeps a visited set and terminates. Used for
    conformance assertions and operator diagnostics; the server's SpiceDB
    graph — fed direct edges — owns the closure that enforcement uses."""
    direct: dict[str, list[str]] = {}
    for group, member in memberships:
        direct.setdefault(group, []).append(member)
    closure: dict[str, set[str]] = {}
    for group in direct:
        users: set[str] = set()
        visited: set[str] = set()
        stack = [group]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for member in direct.get(current, []):
                if member.startswith("user:"):
                    users.add(member)
                elif member.startswith("group:"):
                    stack.append(member)
                # domain:* is its own principal, not a user expansion.
        closure[group] = users
    return closure


# ---------------------------------------------------------------------------
# Diff-and-apply
# ---------------------------------------------------------------------------


@dataclass
class SyncDiff:
    """What changed since the previous snapshot, in apply order."""

    added_principals: list[str] = field(default_factory=list)
    added_memberships: list[tuple[str, str]] = field(default_factory=list)
    removed_memberships: list[tuple[str, str]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.added_principals or self.added_memberships or self.removed_memberships)


def diff_snapshots(previous: DirectorySnapshot, desired: DirectorySnapshot) -> SyncDiff:
    """Diff two snapshots into admin ops.

    Removals include every tuple a deprovisioned (suspended/archived/deleted)
    user held, because such users are absent from the desired snapshot
    entirely. Principals are never removed — the server's registry is
    append-only; a token with no tuples/ACLs grants nothing.
    """
    prev_members = set(previous.memberships)
    want_members = set(desired.memberships)
    prev_principals = set(previous.principals())
    return SyncDiff(
        added_principals=sorted(set(desired.principals()) - prev_principals),
        added_memberships=sorted(want_members - prev_members),
        removed_memberships=sorted(prev_members - want_members),
    )


@dataclass(frozen=True)
class AdminOp:
    """One idempotent server call: (method, path, exact JSON body)."""

    method: str
    path: str
    body: Mapping[str, Any]


def build_admin_ops(diff: SyncDiff, tenant_id: str) -> list[AdminOp]:
    """Turn a diff into ordered admin ops: principals upsert → adds →
    removals. Removals go LAST and one tuple at a time — each DELETE writes
    revocation tombstones before the tuple delete server-side, so ordering is
    fail-closed (a crash mid-cycle leaves extra grants pending re-run of the
    adds, never a lost tombstone)."""
    ops: list[AdminOp] = []
    if diff.added_principals:
        ops.append(
            AdminOp(
                "POST",
                PRINCIPALS_PATH,
                {"tenant_id": tenant_id, "principals": list(diff.added_principals)},
            )
        )
    for group, member in diff.added_memberships:
        ops.append(
            AdminOp("POST", GROUPS_PATH, {"tenant_id": tenant_id, "group": group, "member": member})
        )
    for group, member in diff.removed_memberships:
        ops.append(
            AdminOp(
                "DELETE", GROUPS_PATH, {"tenant_id": tenant_id, "group": group, "member": member}
            )
        )
    return ops


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class AdminSink(Protocol):
    def apply(self, op: AdminOp) -> None: ...


class VerityAdminSink:
    """Applies admin ops against the server as built (module docstring
    contracts). Raises on any non-2xx: a failed op must abort the cycle
    before the snapshot checkpoint (at-least-once replay)."""

    def __init__(
        self,
        base_url: str,
        client: httpx.Client | None = None,
        api_key: str | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=30.0, headers=headers)
        self._base_url = base_url.rstrip("/")
        # Heartbeat accumulators, mirroring VerityDocumentSink's.
        self._applied = 0
        self._tenant_id: str | None = None

    def apply(self, op: AdminOp) -> None:
        # httpx.Client.delete() rejects a body; request() carries the JSON
        # membership tuple on DELETE the way the server expects.
        response = self._client.request(op.method, f"{self._base_url}{op.path}", json=dict(op.body))
        response.raise_for_status()
        self._applied += 1
        self._tenant_id = op.body.get("tenant_id", self._tenant_id)

    def heartbeat(self, cursor: str | None = None) -> None:
        """Best-effort ``POST /v1/admin/connector-status`` after a delivered
        cycle; resets the accumulator. Never raises — telemetry must never
        fail (or replay) a sync that already delivered."""
        if not self._applied or not self._tenant_id:
            return
        try:
            body: dict[str, Any] = {
                "tenant_id": self._tenant_id,
                "source": SOURCE_NAME,
                "items_synced": self._applied,
            }
            if cursor is not None:
                body["cursor"] = cursor
            self._client.post(f"{self._base_url}{CONNECTOR_STATUS_PATH}", json=body)
        except Exception:  # noqa: BLE001 — telemetry only
            pass
        finally:
            self._applied = 0


class DryRunAdminSink:
    """Collects and prints the would-be admin ops instead of calling them."""

    def __init__(self, stream: Any = None) -> None:
        self.ops: list[AdminOp] = []
        self._stream = stream if stream is not None else sys.stdout

    def apply(self, op: AdminOp) -> None:
        self.ops.append(op)
        print(
            f"[dry-run] {op.method} {op.path}\n"
            f"{json.dumps(dict(op.body), indent=2, sort_keys=True)}",
            file=self._stream,
        )


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.gdirectory --once [--dry-run]
# ---------------------------------------------------------------------------


def _load_snapshot(state_file: Path) -> DirectorySnapshot:
    if not state_file.exists():
        return DirectorySnapshot()
    raw = json.loads(state_file.read_text()).get("snapshot", {})
    return DirectorySnapshot(
        users=list(raw.get("users", [])),
        memberships=[(g, m) for g, m in raw.get("memberships", [])],
    )


def _save_snapshot(state_file: Path, snapshot: DirectorySnapshot, reconciled_at: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps(
            {
                "last_reconcile_at": reconciled_at,
                "snapshot": {
                    "users": snapshot.users,
                    "memberships": [list(pair) for pair in snapshot.memberships],
                },
            },
            indent=2,
        )
        + "\n"
    )


def run_once(
    connector: GDirectoryConnector,
    sink: AdminSink,
    state_file: Path,
    *,
    now: str | None = None,
) -> int:
    """One reconcile cycle: load previous snapshot, full reconcile, diff,
    apply ops in order, checkpoint. Returns the number of applied ops. The
    snapshot is checkpointed only after every op delivers, so a crash replays
    the cycle (at-least-once; every op is idempotent — removals re-tombstone,
    which over-hides, never under-hides)."""
    previous = _load_snapshot(state_file)
    desired = connector.reconcile()
    ops = build_admin_ops(diff_snapshots(previous, desired), connector.config.tenant_id)
    for op in ops:
        sink.apply(op)
    reconciled_at = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_snapshot(state_file, desired, reconciled_at)
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=reconciled_at)
    return len(ops)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.gdirectory",
        description="Verity Google Workspace directory sync (Identity Plane, §6a).",
    )
    parser.add_argument("--once", action="store_true", help="run a single reconcile cycle and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="print admin ops instead of calling the server"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("GADMIN_STATE_FILE", ".verity/gdirectory_snapshot.json")),
        help="JSON snapshot checkpoint file",
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url",
        default=os.environ.get("VERITY_URL", "http://localhost:8080"),
        help="Verity server base URL (admin principal/group endpoints)",
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("GADMIN_DOMAIN"),
        help="workspace primary domain, used to map type=CUSTOMER members to "
        "domain:<domain>; unset: CUSTOMER members confer nothing",
    )
    parser.add_argument(
        "--subject",
        default=os.environ.get("GADMIN_DELEGATED_SUBJECT"),
        help="domain-wide-delegation subject (a workspace admin to impersonate) — required",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("GADMIN_POLL_INTERVAL_SECS", "300")),
        help="reconcile interval in seconds (without --once); this interval IS "
        "the group-membership freshness bound in the ACL-sync SLO (§6a)",
    )
    args = parser.parse_args(argv)

    config = GDirectoryConfig(
        tenant_id=args.tenant_id, domain=args.domain, delegated_subject=args.subject
    )
    credentials = load_directory_credentials(config.delegated_subject)
    connector = GDirectoryConnector(HttpDirectoryTransport(credentials), config)

    api_key = os.environ.get("VERITY_API_KEY")
    sink: AdminSink = (
        DryRunAdminSink() if args.dry_run else VerityAdminSink(args.verity_url, api_key=api_key)
    )

    while True:
        applied = run_once(connector, sink, args.state_file)
        print(f"gdirectory: applied {applied} admin op(s); snapshot -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
