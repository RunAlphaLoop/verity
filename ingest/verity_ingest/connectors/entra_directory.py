"""Microsoft Entra ID (Azure AD) directory-sync connector — the Microsoft
analog of :mod:`gdirectory` and the identity **weld** for every Microsoft
source (SharePoint next). It closes a latent correctness gap: Verity's
crosswalk today only speaks Google groups, so every non-Google tenant's
group-based ACLs currently fail to resolve / over-hide.

Like :mod:`gdirectory` this is a *directory surface* connector (it syncs
principals + group membership, never documents) and reuses gdirectory's
source-agnostic diff/apply/sink core UNCHANGED — ``SyncDiff``,
``diff_snapshots``, ``AdminOp``, ``build_registry_ops``, ``build_admin_ops``,
``AdminSink``/``VerityAdminSink``/``DryRunAdminSink``, ``transitive_user_closure``,
``SsoAlias`` and ``DirectoryUser``. That reuse is only sound because
:meth:`EntraDirectoryConnector.reconcile_delta` folds each Graph delta into a
**persisted FULL snapshot** (not a delta cursor alone) before diffing —
``diff_snapshots`` computes removals by set-difference of two full snapshots,
so a delta stream on its own would miss members removed via member-object
deletion.

What makes this NOT a find-and-replace of gdirectory (and the fail-closed
guarantees each item enforces):

G2 — immutable-key-or-drop. The merge key is the Entra ``objectId`` GUID
ONLY. Never ``userPrincipalName`` (mutable, ``#EXT#``-mangled for guests),
never ``mail`` (mutable, nullable — security groups have ``mail == null``),
never ``displayName``/``onPremisesSamAccountName`` *as a key*. Group
principals are named ``group:entra-group-<objectId>``. An object with no
``id`` confers nothing.

G3 — fresh-or-fail, with the deprovision-doesn't-touch-edges correction baked
in. Entra has real delta (``/users/delta`` + ``/groups/delta``), a freshness
win, but the group-delta stream has a documented hole: *"the delta function
doesn't detect members that are removed from a group through deletion of the
member object."* A hard-deleted user emits NO ``members@delta`` removal for
their groups. The authoritative trigger is therefore the ``/users/delta``
``@removed`` tombstone, which must (a) ``POST /v1/admin/deprovision`` the
canonical AND (b) explicitly ``DELETE`` every ``(group, user:<canonical>)``
edge the connector's OWN persisted snapshot recorded for that objectId —
because ``admin_deprovision`` does NOT delete SpiceDB group edges
(``open_scope`` keeps group tokens for a deprovisioned subject) and a reused
email / group-scoped content would otherwise still resolve. A ``410 Gone`` /
``syncStateNotFound`` raises :class:`SyncStateReset` → full resync, failing
closed (do not checkpoint, do not serve last-known as live).

G4 — unknown-or-guest ⇒ exclude, never guess. Guest exclusion is a FOUR-PART
AND (:func:`is_active_member`): ``userType == "Member"`` AND
``externalUserState is None`` AND ``accountEnabled is True`` AND
``"#EXT#" not in userPrincipalName.upper()``. ``userType`` alone is
insufficient — B2B guests can be *converted* to ``userType == "Member"`` while
remaining external. The guest-excluded tenant token is a materialized
synthetic group ``group:entra-everyone-except-guests`` whose membership is
exactly ``{ u : is_active_member(u) }``. Any unknown/unmapped identity facet
(null ``userType``, device/servicePrincipal/orgContact member, unenumerated
group) contributes NO edge.

Identity crosswalk (no migration — ``principal_crosswalk.source``/``local_id``
are free ``text``): every active Member emits a self-crosswalk
``(source="entra", local_id=<objectId>, canonical=user:<email>,
link_method="directory_vouched")`` — the row a future SharePoint ACL carrying
an aad objectId resolves through — plus, if configured, an admin-declared
``principal_sso_alias`` weld (``alias_field``) so Entra does not mint a
competing ``canonical_principal`` when another IdP (e.g. Google) already
minted one for the same human. The alias upsert returns ``quarantined[]`` for
any alias already bound to a DIFFERENT canonical (a real under-merge / IdP
collision); a non-empty ``quarantined[]`` is a FAIL-CLOSED alarm
(:class:`AliasCollision`), never swallowed.

Auth (BYOT doctrine): the customer's own app registration + client-credentials
(app-only, admin-consented) grant — the Microsoft analog of Google
domain-wide delegation. ``msal`` is lazily imported so fixture tests need no
live credentials and no ``msal`` install (same path as gdirectory's lazy
google-auth). Least-privilege application permissions: ``User.Read.All``,
``Group.Read.All``, ``GroupMember.Read.All``.

Verification status (honest-limitations doctrine): a **fixture-verified
slice**. Every Graph behavior is asserted against fixtures built from the
documented Graph v1.0 response shapes (paging → deltaLink, nested groups, a
membership cycle, the four-part guest gate incl. converted-guest and ``#EXT#``
leaks, the user-tombstone group-delta-hole regression, ``SyncStateReset``).
NOT run against a live tenant: live validation (``onPremisesImmutableId`` ↔
SAML NameID confirmation, RU budget, end-to-end delete-user G3 proof) awaits
Matt's Entra admin consent — see phases 7-9.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Protocol, Sequence

import httpx

# Reuse gdirectory's source-agnostic core UNCHANGED. These are correct for any
# directory source once SOURCE_NAME and the canonical strings are right; forking
# the diff/apply engine would be a correctness liability (two engines to keep in
# lockstep). ``DirectoryUser``/``SsoAlias`` are reused verbatim for registry
# emission — an EntraUser projects to a DirectoryUser for build_registry_ops.
from verity_ingest.connectors.gdirectory import (
    CONNECTOR_STATUS_PATH,
    CROSSWALK_PATH,
    DEPROVISION_PATH,
    GROUPS_PATH,
    PRINCIPALS_PATH,
    REGISTRY_ALIAS_PATH,
    REGISTRY_CANONICAL_PATH,
    AdminOp,
    AdminSink,
    DirectoryUser,
    DryRunAdminSink,
    SsoAlias,
    SyncDiff,
    VerityAdminSink,
    build_admin_ops,
    build_registry_ops,
    diff_snapshots,
    transitive_user_closure,
)

__all__ = [
    "SOURCE_NAME",
    "EVERYONE_GROUP",
    "AliasCollision",
    "SyncStateReset",
    "EntraDirectoryConfig",
    "EntraUser",
    "EntraSnapshot",
    "ConformanceResult",
    "GraphTransport",
    "HttpGraphTransport",
    "EntraDirectoryConnector",
    "EntraAdminSink",
    "is_active_member",
    "map_member",
    "group_principal",
    "load_graph_credentials",
    "run_once",
    "main",
    # re-exported gdirectory core (so tests import from one module)
    "AdminOp",
    "DirectoryUser",
    "SsoAlias",
    "SyncDiff",
    "DryRunAdminSink",
    "VerityAdminSink",
    "build_admin_ops",
    "build_registry_ops",
    "diff_snapshots",
    "transitive_user_closure",
    "PRINCIPALS_PATH",
    "GROUPS_PATH",
    "REGISTRY_CANONICAL_PATH",
    "REGISTRY_ALIAS_PATH",
    "CROSSWALK_PATH",
    "DEPROVISION_PATH",
    "CONNECTOR_STATUS_PATH",
]

ENTRA_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

SOURCE_NAME = "entra"

#: The materialized guest-excluded tenant token (G4). One explicit
#: ``user:<canonical>`` edge per active Member; a bare ``domain:`` token would
#: over-include guests (their UPN is ``#EXT#``-mangled under the host domain).
EVERYONE_GROUP = "group:entra-everyone-except-guests"

# $select masks: ask Graph for exactly what we consume. The four-part guest gate
# needs userType + externalUserState + accountEnabled + userPrincipalName;
# creationType is a belt-and-suspenders external signal. The alias fields
# (onPremisesImmutableId, etc.) feed admin-declared SSO welding.
_USER_SELECT = (
    "id,userPrincipalName,mail,proxyAddresses,onPremisesImmutableId,"
    "onPremisesSamAccountName,onPremisesSecurityIdentifier,userType,"
    "externalUserState,accountEnabled,creationType,displayName"
)
_GROUP_SELECT = "id,displayName,mail,groupTypes,securityEnabled,mailEnabled"

#: The Graph member ``@odata.type`` discriminators we keep (fail-closed: a
#: device/servicePrincipal/orgContact member confers nothing).
_MEMBER_TYPE_USER = "#microsoft.graph.user"
_MEMBER_TYPE_GROUP = "#microsoft.graph.group"

#: The user fields eligible to be the admin-declared SSO NameID (``alias_field``).
#: onPremisesImmutableId (base64 of the on-prem objectGUID / sourceAnchor) is the
#: most common SAML NameID for federated tenants — the prime candidate. Which one
#: a tenant actually asserts is admin-config, never guessed.
_ALIAS_FIELDS = frozenset(
    {
        "onPremisesImmutableId",
        "onPremisesSecurityIdentifier",
        "onPremisesSamAccountName",
        "userPrincipalName",
        "mail",
    }
)


class SyncStateReset(RuntimeError):
    """Raised when Graph invalidates a delta token (410 Gone / syncStateNotFound).

    The delta token has expired (valid ~7 days) or the tenant reset sync state.
    The runner must discard the cursor and do a full resync; until it succeeds the
    connector fails closed (does not checkpoint, does not serve last-known as
    live) — G3."""


class AliasCollision(RuntimeError):
    """Raised when a ``registry/alias`` upsert returns a non-empty
    ``quarantined[]`` — the SSO subject is already bound to a DIFFERENT
    canonical (a real cross-IdP under-merge alarm). Fail closed: do not proceed
    as if the weld succeeded."""

    def __init__(self, quarantined: Sequence[Mapping[str, Any]]) -> None:
        self.quarantined = list(quarantined)
        super().__init__(f"alias collision (already bound to a different canonical): {quarantined}")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class EntraDirectoryConfig:
    """Connector configuration. No default widens visibility."""

    tenant_id: str = "default"  # Verity tenant UUID (opaque)
    # The Entra tenant (GUID or domain) used in the token endpoint. Distinct from
    # the Verity tenant_id above.
    graph_tenant: str | None = None
    client_id: str | None = None
    client_secret_file: str | None = None
    client_cert_file: str | None = None
    # Which Entra user field is the SSO NameID the tenant's OTHER sources assert
    # (e.g. Salesforce FederationIdentifier). ADMIN-declared, never guessed. When
    # unset, no aliases are welded (fail-closed: no false weld). See _ALIAS_FIELDS.
    alias_field: str | None = None
    # The guest-excluded synthetic tenant token (G4). Default on — the whole
    # point of the connector — but explicit so it can be disabled per tenant.
    everyone_group_enabled: bool = True
    user_page_size: int = 999  # Graph $top cap for /users
    group_page_size: int = 999


# ---------------------------------------------------------------------------
# Graph transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class GraphTransport(Protocol):
    """Minimal surface over Microsoft Graph REST, so tests run on fixtures.

    ``get_json`` is a single GET (with paging handled by the caller via the
    ``@odata.nextLink`` in the body). ``get_delta`` follows a delta stream from a
    starting path or a saved ``@odata.deltaLink`` through every ``nextLink`` to the
    terminal ``deltaLink``, yielding each raw page — a ``410``/``syncStateNotFound``
    anywhere in the walk raises :class:`SyncStateReset`."""

    def get_json(self, path: str, params: Mapping[str, str]) -> dict: ...

    def get_delta(self, url_or_path: str, params: Mapping[str, str]) -> Iterator[dict]: ...


class HttpGraphTransport:
    """Live Microsoft Graph REST transport with app-only bearer auth.

    Honors ``Retry-After`` on 429 (Graph throttling), sets a low throttle
    priority, and raises :class:`SyncStateReset` on 410/``syncStateNotFound`` so
    the runner fails closed and full-resyncs (G3)."""

    def __init__(
        self,
        token_provider: Any,
        client: httpx.Client | None = None,
        *,
        max_retries: int = 5,
    ) -> None:
        # token_provider() -> a valid bearer token string (refreshes on expiry).
        self._token_provider = token_provider
        self._client = client or httpx.Client(base_url=ENTRA_GRAPH_BASE_URL, timeout=60.0)
        self._max_retries = max_retries

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token_provider()}",
            "x-ms-throttle-priority": "low",
        }

    def _get(self, url_or_path: str, params: Mapping[str, str] | None) -> dict:
        attempt = 0
        while True:
            response = self._client.get(
                url_or_path, params=dict(params or {}), headers=self._headers()
            )
            if response.status_code == 429 and attempt < self._max_retries:
                retry_after = float(response.headers.get("Retry-After", "1"))
                time.sleep(retry_after)
                attempt += 1
                continue
            # A stale/invalid delta token: 410 Gone, or a 4xx carrying the
            # syncStateNotFound error code. Fail closed to a full resync.
            if response.status_code == 410 or (
                response.status_code >= 400 and "syncStateNotFound" in response.text
            ):
                raise SyncStateReset(f"delta token invalidated: {url_or_path}")
            response.raise_for_status()
            return response.json()

    def get_json(self, path: str, params: Mapping[str, str]) -> dict:
        return self._get(path, params)

    def get_delta(self, url_or_path: str, params: Mapping[str, str]) -> Iterator[dict]:
        # $select/params are baked into a saved deltaLink; only set them on the
        # very first call (a bare path). A saved link is followed verbatim.
        first = not url_or_path.startswith("http")
        next_url: str | None = url_or_path
        next_params: Mapping[str, str] | None = params if first else None
        while next_url is not None:
            page = self._get(next_url, next_params)
            next_params = None  # subsequent links carry their own query
            yield page
            next_url = page.get("@odata.nextLink")


def load_graph_credentials(config: EntraDirectoryConfig):
    """BYOT app-only token provider for Microsoft Graph (msal, LAZILY imported).

    ``msal`` is imported here — never at module import — so fixture tests need
    neither live credentials nor a msal install (mirrors gdirectory's lazy
    google-auth). Returns a zero-arg callable yielding a fresh bearer token."""
    if not config.graph_tenant or not config.client_id:
        raise RuntimeError(
            "ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required. Register an Entra "
            "app with admin-consented application permissions User.Read.All + "
            "Group.Read.All + GroupMember.Read.All and provide a client secret "
            "(ENTRA_CLIENT_SECRET_FILE) or certificate (ENTRA_CLIENT_CERT_FILE)."
        )
    if not config.client_secret_file and not config.client_cert_file:
        raise RuntimeError(
            "one of ENTRA_CLIENT_SECRET_FILE or ENTRA_CLIENT_CERT_FILE is required "
            "for app-only (client-credentials) auth."
        )

    import msal  # lazy: fixture tests never reach here

    authority = f"https://login.microsoftonline.com/{config.graph_tenant}"
    if config.client_secret_file:
        secret = Path(config.client_secret_file).read_text().strip()
        credential: Any = secret
    else:
        # A certificate credential is a dict; we read the PEM off disk. Thumbprint
        # derivation is left to a live-auth follow-up (fixture tests never run it).
        credential = {"private_key": Path(config.client_cert_file).read_text()}

    app = msal.ConfidentialClientApplication(
        client_id=config.client_id, authority=authority, client_credential=credential
    )

    def token_provider() -> str:
        result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        if "access_token" not in result:
            raise RuntimeError(
                f"Graph token acquisition failed: {result.get('error_description', result)}"
            )
        return str(result["access_token"])

    return token_provider


# ---------------------------------------------------------------------------
# Desired-state model
# ---------------------------------------------------------------------------


def group_principal(object_id: str) -> str:
    """The SpiceDB group principal for an Entra group, keyed on the immutable
    objectId GUID (G2) — never on ``mail`` (null for security groups)."""
    return f"group:entra-group-{object_id}"


@dataclass(frozen=True)
class EntraUser:
    """One Entra user reduced to the facets the connector needs, keyed on the
    immutable ``object_id`` (G2). ``canonical`` is ``user:<primary_email>``
    where primary = ``mail`` → fallback ``userPrincipalName`` (lowercased)."""

    object_id: str
    upn: str
    mail: str | None
    user_type: str | None
    external_user_state: str | None
    account_enabled: bool
    creation_type: str | None
    aliases: tuple[SsoAlias, ...] = ()

    @property
    def primary_email(self) -> str:
        return (self.mail or self.upn or "").lower()

    @property
    def canonical(self) -> str:
        return f"user:{self.primary_email}"

    def as_directory_user(self) -> DirectoryUser:
        """Project to gdirectory's ``DirectoryUser`` so ``build_registry_ops`` can
        emit canonical + alias + self-crosswalk rows UNCHANGED. ``local_id`` is
        the objectId (G2) — the key a future SharePoint ACL resolves through."""
        return DirectoryUser(
            directory_id=self.object_id,
            primary_email=self.primary_email,
            aliases=self.aliases,
        )


def is_active_member(user: EntraUser) -> bool:
    """The G4 four-part AND. All four must hold for a user to be an internal,
    active Member — anything else (guest, converted-guest-as-Member,
    externalUserState set, disabled, ``#EXT#`` UPN, null ``userType``,
    Invitation creationType) is excluded, contributing NO edge and absent from
    the tenant token. This only ever narrows visibility."""
    return (
        user.user_type == "Member"
        and user.external_user_state is None
        and user.account_enabled is True
        and "#EXT#" not in (user.upn or "").upper()
        and user.creation_type != "Invitation"
    )


@dataclass
class EntraSnapshot:
    """Canonical desired state for one reconcile cycle — persisted in FULL.

    ``users`` are the active Members' canonicals (sorted, lowercase).
    ``memberships`` are DIRECT ``(group, member)`` edges (sorted), member being
    ``user:...`` or ``group:entra-group-...`` (nesting; SpiceDB owns closure).
    ``everyone_members`` are the active-Member canonicals in the guest-excluded
    tenant token. ``directory_users`` are the registry-populate records.

    ``oid_to_canonical`` (objectId → canonical, active Members only) is
    LOAD-BEARING for G3(b): on a user-object-deletion tombstone the connector
    reads it (from its OWN persisted snapshot) to find every group edge that
    objectId held and delete each — because ``admin_deprovision`` does not touch
    SpiceDB group edges. The two delta cursors ride along so a cycle can resume.

    This whole object is persisted (not just cursors), because ``diff_snapshots``
    computes removals by set-difference of FULL snapshots."""

    users: list[str] = field(default_factory=list)
    memberships: list[tuple[str, str]] = field(default_factory=list)
    everyone_members: list[str] = field(default_factory=list)
    directory_users: list[DirectoryUser] = field(default_factory=list)
    oid_to_canonical: dict[str, str] = field(default_factory=dict)
    users_delta_link: str | None = None
    groups_delta_link: str | None = None

    def principals(self) -> list[str]:
        out = set(self.users)
        for group, member in self.memberships:
            out.add(group)
            out.add(member)
        return sorted(out)

    def to_directory_snapshot(self):
        """Materialize the gdirectory ``DirectorySnapshot`` view the reused
        ``diff_snapshots`` diffs. The guest-excluded tenant token is folded in as
        just another group's edges, so it deprovisions/adds like any group."""
        from verity_ingest.connectors.gdirectory import DirectorySnapshot

        memberships = list(self.memberships)
        if self.everyone_members:
            memberships += [(EVERYONE_GROUP, m) for m in self.everyone_members]
        return DirectorySnapshot(
            users=sorted(self.users),
            memberships=sorted(set(memberships)),
            directory_users=list(self.directory_users),
        )


@dataclass(frozen=True)
class ConformanceResult:
    """The output of :meth:`EntraDirectoryConnector.conformance_oracle` — a
    DIAGNOSTIC comparison of the connector's delivered direct-edge closure for one
    group against Graph's authoritative ``/transitiveMembers``. Never fed back into
    the delivery path. ``conforms`` is True iff the two active-Member user sets are
    equal; ``missing_locally`` are users Graph resolves that we did NOT deliver
    (an under-share risk), ``extra_locally`` are users we delivered that Graph does
    NOT resolve (an over-share risk)."""

    group: str
    local_users: frozenset[str] | set[str]
    graph_users: frozenset[str] | set[str]
    missing_locally: frozenset[str] | set[str]
    extra_locally: frozenset[str] | set[str]

    @property
    def conforms(self) -> bool:
        return not self.missing_locally and not self.extra_locally


# ---------------------------------------------------------------------------
# Member mapping (fail-closed, G2/G4)
# ---------------------------------------------------------------------------


def map_member(
    group: str,
    member: Mapping[str, Any],
    active_oid_to_canonical: Mapping[str, str],
    known_group_oids: frozenset[str],
) -> str | None:
    """Map one Graph member entry to a canonical member principal, or None.

    Keyed on ``@odata.type`` + objectId (G2), fail-closed (G4):
    - ``#microsoft.graph.user`` → ``user:<canonical>`` ONLY if that objectId is an
      active Member (the four-part gate ran at user-list time and populated
      ``active_member_oids``/``_oid_to_canonical``); a guest/disabled/deleted user
      confers nothing.
    - ``#microsoft.graph.group`` → ``group:entra-group-<objectId>`` ONLY if that
      group was enumerated and is not the group itself (server 422s self-membership).
    - device/servicePrincipal/orgContact/unknown → None (never guess).

    Returning None narrows, never widens."""
    mtype = member.get("@odata.type")
    oid = str(member.get("id") or "")
    if not oid:
        return None
    if mtype == _MEMBER_TYPE_USER:
        return active_oid_to_canonical.get(oid)  # active Members only (four-part gate)
    if mtype == _MEMBER_TYPE_GROUP:
        inner = group_principal(oid)
        if oid in known_group_oids and inner != group:
            return inner
        return None
    return None  # device / servicePrincipal / orgContact / anything Graph adds


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class EntraDirectoryConnector:
    """One Entra tenant's directory. Like gdirectory it is NOT a content
    ``Connector`` — it emits principals + membership tuples, never documents."""

    name = SOURCE_NAME

    def __init__(
        self, transport: GraphTransport, config: EntraDirectoryConfig | None = None
    ) -> None:
        self._transport = transport
        self.config = config or EntraDirectoryConfig()
        self.warnings: list[str] = []  # surfaced in the heartbeat (null alias_field, …)

    def push_events(self) -> None:
        """No-op: the delta poll is the truth lane; Graph change notifications
        need a public HTTPS endpoint + subscription renewal (a later lane)."""
        return None

    # -- full reconcile (first run) ------------------------------------------

    def reconcile(self) -> EntraSnapshot:
        """One full reconcile: page /users, /groups, and every group's direct
        /members into a FULL :class:`EntraSnapshot`, priming the delta cursors so
        the next cycle can go incremental. Direct edges keyed on objectId (G2)."""
        users, users_link = self._list_users()
        groups, groups_link = self._list_groups()
        return self._build_snapshot(
            users=users,
            groups=groups,
            memberships=self._walk_memberships(users, groups),
            users_delta_link=users_link,
            groups_delta_link=groups_link,
        )

    def _build_snapshot(
        self,
        *,
        users: dict[str, EntraUser],
        groups: dict[str, dict],
        memberships: set[tuple[str, str]],
        users_delta_link: str | None,
        groups_delta_link: str | None,
    ) -> EntraSnapshot:
        active = {u.object_id: u for u in users.values() if is_active_member(u)}
        oid_to_canonical = {oid: u.canonical for oid, u in active.items()}
        everyone = sorted({u.canonical for u in active.values()})
        directory_users = [
            active[oid].as_directory_user() for oid in sorted(active, key=lambda o: active[o].canonical)
        ]
        # G4-on-delta as an EXPLICIT invariant, not an emergent side effect: a
        # delivered user edge survives ONLY if its canonical is an active Member
        # THIS cycle. Drops any edge to a now-guest/inactive/deleted user no matter
        # how the fold resolved it. Group-as-member edges (group:entra-group-…) pass.
        active_canonicals = set(oid_to_canonical.values())
        gated = {
            (g, m)
            for (g, m) in memberships
            if m.startswith("group:entra-group-") or m in active_canonicals
        }
        return EntraSnapshot(
            users=sorted(oid_to_canonical.values()),
            memberships=sorted(gated),
            everyone_members=everyone if self.config.everyone_group_enabled else [],
            directory_users=directory_users,
            oid_to_canonical=oid_to_canonical,
            users_delta_link=users_delta_link,
            groups_delta_link=groups_delta_link,
        )

    def _walk_memberships(
        self, users: Mapping[str, EntraUser], groups: Mapping[str, dict]
    ) -> set[tuple[str, str]]:
        active = {oid: u.canonical for oid, u in users.items() if is_active_member(u)}
        known_group_oids = frozenset(groups)
        memberships: set[tuple[str, str]] = set()
        for oid in groups:
            group = group_principal(oid)
            for member in self._list_group_members(oid):
                mapped = map_member(group, member, active, known_group_oids)
                if mapped is not None:
                    memberships.add((group, mapped))
        return memberships

    # -- delta reconcile (steady state) --------------------------------------

    def reconcile_delta(self, prev: EntraSnapshot) -> EntraSnapshot:
        """Fold the /users and /groups delta into the persisted ``prev`` snapshot,
        returning a NEW FULL :class:`EntraSnapshot` (adds applied, ``@removed``
        entries deleted, ``oid_to_canonical`` updated). Returning a full snapshot
        is what lets the reused ``diff_snapshots`` set-difference math stay valid.

        A ``@removed`` user tombstone (G3(b)) is folded here: the user drops out of
        ``oid_to_canonical`` and out of every edge — so the diff produces the
        edge removals — and the runner ALSO fires the deprovision + explicit
        per-edge deletes (see :func:`tombstoned_user_ops`).

        If either stream's saved deltaLink is missing, fall back to a full
        ``reconcile`` (first-ever delta run). A :class:`SyncStateReset` propagates
        (fail closed → full resync, no checkpoint)."""
        if not prev.users_delta_link or not prev.groups_delta_link:
            return self.reconcile()

        # 1. Rebuild the FULL user set: prior users + delta adds/changes, minus
        #    tombstoned objectIds.
        users, user_tombstones, users_link = self._users_delta(prev)
        # Active-Member map for THIS cycle (four-part G4 gate over the folded user
        # set), threaded explicitly into the group-delta resolver — no module global
        # — so a members@delta add can only resolve to a user that is an active
        # Member in the very snapshot we are building (fixes the cross-cycle leak).
        active = {
            oid: u.canonical for oid, u in users.items() if is_active_member(u)
        }
        # 2. Rebuild the FULL group membership set: prior direct edges + group-delta
        #    adds, minus group-delta member removals, minus every edge belonging to
        #    a tombstoned user (the group-delta hole: a member-object deletion emits
        #    NO members@delta removal, so we clear it from OUR snapshot ourselves).
        groups, memberships, groups_link = self._groups_delta(
            prev, user_tombstones, active
        )
        for oid in user_tombstones:
            canonical = prev.oid_to_canonical.get(oid)
            if canonical is not None:
                memberships = {(g, m) for (g, m) in memberships if m != canonical}

        return self._build_snapshot(
            users=users,
            groups=groups,
            memberships=memberships,
            users_delta_link=users_link,
            groups_delta_link=groups_link,
        )

    def _users_delta(
        self, prev: EntraSnapshot
    ) -> tuple[dict[str, EntraUser], set[str], str | None]:
        """Fold /users/delta into the prior full user set. Returns
        (objectId→EntraUser full set, tombstoned objectIds, new deltaLink)."""
        # Reconstruct prior EntraUsers from oid_to_canonical + directory_users so a
        # user unchanged this cycle survives. We only carry the canonical facet for
        # unchanged users (enough to re-key edges); changed users are re-read whole.
        users: dict[str, EntraUser] = {}
        dir_by_email = {du.primary_email: du for du in prev.directory_users}
        for oid, canonical in prev.oid_to_canonical.items():
            email = canonical[len("user:") :]
            du = dir_by_email.get(email)
            users[oid] = EntraUser(
                object_id=oid,
                upn=email,
                mail=email,
                user_type="Member",
                external_user_state=None,
                account_enabled=True,
                creation_type=None,
                aliases=du.aliases if du else (),
            )
        tombstones: set[str] = set()
        link = prev.users_delta_link
        for page, delta_link in self._delta_pages(prev.users_delta_link):
            if delta_link is not None:
                link = delta_link
            for raw in page.get("value", []):
                oid = str(raw.get("id") or "")
                if not oid:
                    continue
                if "@removed" in raw:
                    tombstones.add(oid)
                    users.pop(oid, None)
                    continue
                user = self._parse_user(raw)
                users[oid] = user
                tombstones.discard(oid)
        return users, tombstones, link

    def _groups_delta(
        self,
        prev: EntraSnapshot,
        user_tombstones: set[str],
        active_oid_to_canonical: Mapping[str, str],
    ) -> tuple[dict[str, dict], set[tuple[str, str]], str | None]:
        """Fold /groups/delta into the prior full membership set. Returns
        (objectId→group full set, full membership edge set, new deltaLink).

        Large-group members split across pages with the SAME group id recurring
        anywhere in the nextLink sequence (no ordering) — we merge per-group-id
        locally by objectId."""
        # Prior groups keyed by objectId (recovered from the edge set).
        groups: dict[str, dict] = {}
        for group, _ in prev.memberships:
            if group.startswith("group:entra-group-"):
                groups[group[len("group:entra-group-") :]] = {}
        # Prior direct edges we still trust (exclude the synthetic tenant token —
        # it is recomputed from the user set, not the group delta).
        memberships: set[tuple[str, str]] = {
            (g, m) for (g, m) in prev.memberships if g != EVERYONE_GROUP
        }
        removed_group: set[str] = set()
        link = prev.groups_delta_link
        for page, delta_link in self._delta_pages(prev.groups_delta_link):
            if delta_link is not None:
                link = delta_link
            for raw in page.get("value", []):
                oid = str(raw.get("id") or "")
                if not oid:
                    continue
                group = group_principal(oid)
                if "@removed" in raw:
                    removed_group.add(oid)
                    groups.pop(oid, None)
                    memberships = {(g, m) for (g, m) in memberships if g != group}
                    continue
                groups.setdefault(oid, {})
                for member in raw.get("members@delta", []):
                    mapped, is_removed = self._map_delta_member(
                        group, member, active_oid_to_canonical
                    )
                    if mapped is None:
                        continue
                    if is_removed:
                        memberships.discard((group, mapped))
                    else:
                        memberships.add((group, mapped))
        # A group deleted this cycle drops all its edges (done above); a member
        # object deleted this cycle is handled by the caller via user_tombstones.
        del removed_group
        return groups, memberships, link

    def _map_delta_member(
        self,
        group: str,
        member: Mapping[str, Any],
        active_oid_to_canonical: Mapping[str, str],
    ) -> tuple[str | None, bool]:
        """Map a ``members@delta`` entry to (principal, is_removed). The user branch
        resolves ONLY against this cycle's active-Member map (threaded in, never a
        module global), so an add can never resolve to a stale, other-tenant, or
        non-active canonical; ``_build_snapshot`` re-gates the final edge set on the
        same active map as an explicit invariant. Group members map by objectId (G2)."""
        is_removed = "@removed" in member
        mtype = member.get("@odata.type")
        oid = str(member.get("id") or "")
        if not oid:
            return None, is_removed
        if mtype == _MEMBER_TYPE_GROUP:
            inner = group_principal(oid)
            return (inner if inner != group else None), is_removed
        # user member: active-Member map for THIS cycle only (fail-closed on miss).
        return active_oid_to_canonical.get(oid), is_removed

    def _delta_pages(self, start_link: str) -> Iterable[tuple[dict, str | None]]:
        """Yield (page, deltaLink-or-None) walking a saved deltaLink to the
        terminal deltaLink. The deltaLink is only present on the final page."""
        for page in self._transport.get_delta(start_link, {}):
            yield page, page.get("@odata.deltaLink")

    # -- Graph listing -------------------------------------------------------

    def _list_users(self) -> tuple[dict[str, EntraUser], str | None]:
        """Full /users/delta pull (first run). Returns (objectId→EntraUser,
        terminal deltaLink to persist for the next cycle)."""
        users: dict[str, EntraUser] = {}
        link: str | None = None
        params = {"$select": _USER_SELECT, "$top": str(self.config.user_page_size)}
        for page in self._transport.get_delta("users/delta", params):
            for raw in page.get("value", []):
                if "@removed" in raw:
                    continue  # nothing to remove on a first full pull
                oid = str(raw.get("id") or "")
                if oid:
                    users[oid] = self._parse_user(raw)
            link = page.get("@odata.deltaLink") or link
        self._audit_alias_field(users)
        return users, link

    def _list_groups(self) -> tuple[dict[str, dict], str | None]:
        """Full /groups/delta pull with members (first run). Returns
        (objectId→group, terminal deltaLink)."""
        groups: dict[str, dict] = {}
        link: str | None = None
        params = {"$select": _GROUP_SELECT, "$top": str(self.config.group_page_size)}
        for page in self._transport.get_delta("groups/delta", params):
            for raw in page.get("value", []):
                if "@removed" in raw:
                    continue
                oid = str(raw.get("id") or "")
                if oid:
                    groups.setdefault(oid, {"raw": raw})
            link = page.get("@odata.deltaLink") or link
        return groups, link

    def _list_group_members(self, group_oid: str) -> list[dict]:
        """Direct members of one group (first run). Deliberately NOT
        /transitiveMembers — flattening destroys the nesting SpiceDB owns."""
        members: list[dict] = []
        params = {"$select": "id"}
        next_path: str | None = f"groups/{group_oid}/members"
        next_params: Mapping[str, str] | None = params
        while next_path is not None:
            page = self._transport.get_json(next_path, next_params or {})
            members.extend(page.get("value", []))
            next_path = page.get("@odata.nextLink")
            next_params = None
        return members

    def _parse_user(self, raw: Mapping[str, Any]) -> EntraUser:
        return EntraUser(
            object_id=str(raw.get("id") or ""),
            upn=str(raw.get("userPrincipalName") or ""),
            mail=(raw.get("mail") or None),
            user_type=raw.get("userType"),
            external_user_state=raw.get("externalUserState"),
            account_enabled=bool(raw.get("accountEnabled", False)),
            creation_type=raw.get("creationType"),
            aliases=self._collect_aliases(raw),
        )

    def _collect_aliases(self, raw: Mapping[str, Any]) -> tuple[SsoAlias, ...]:
        """Collect the admin-declared SSO alias (``alias_field``) for a user,
        lowercased. Never guessed — only the configured field is read; an unset
        field or a null value yields no alias (fail-closed: no false weld)."""
        field_name = self.config.alias_field
        if not field_name or field_name not in _ALIAS_FIELDS:
            return ()
        value = raw.get(field_name)
        if field_name == "proxyAddresses" and isinstance(value, list):
            value = next(
                (p[len("SMTP:") :] for p in value if isinstance(p, str) and p.startswith("SMTP:")),
                None,
            )
        alias = str(value or "").strip().lower()
        primary = (raw.get("mail") or raw.get("userPrincipalName") or "").lower()
        if not alias or alias == primary:
            return ()
        return (SsoAlias(alias=alias, source=f"{SOURCE_NAME}_declared"),)

    def _audit_alias_field(self, users: Mapping[str, EntraUser]) -> None:
        """G-honesty: if ``alias_field`` is configured but ≥1 active Member has no
        alias for it, emit a LOUD operator warning — cloud-only tenants have
        ``onPremisesImmutableId == null`` for everyone, so welding silently
        produces zero aliases. Fail-closed, but surfaced, never silent."""
        if not self.config.alias_field:
            return
        missing = [
            u.canonical
            for u in users.values()
            if is_active_member(u) and not u.aliases
        ]
        if missing:
            self.warnings.append(
                f"alias_field={self.config.alias_field!r} yielded no SSO alias for "
                f"{len(missing)} active Member(s) (e.g. {missing[0]}); cross-IdP "
                "welding will not fire for them. On a cloud-only tenant this field "
                "is null for everyone — confirm the tenant's actual SAML NameID field."
            )

    # -- conformance oracle (DIAGNOSTICS ONLY) -------------------------------

    def conformance_oracle(
        self, group_object_id: str, snapshot: EntraSnapshot
    ) -> ConformanceResult:
        """DIAGNOSTIC oracle: does the connector's DELIVERED direct-edge closure for
        one group match Graph's authoritative ``/transitiveMembers`` for it?

        Pulls Graph ``/groups/{id}/transitiveMembers`` (the flattened, server-side
        transitive set) and compares it to :func:`transitive_user_closure` over the
        ``snapshot``'s DELIVERED direct edges (the exact edges the connector shipped
        — ``group:entra-group-…`` nesting let SpiceDB close). The Graph side is
        gated through the SAME four-part :func:`is_active_member` rule, because
        ``/transitiveMembers`` returns guests / disabled / nested-group principals
        the delivery path deliberately excludes — comparing raw would flag every
        guest as a false discrepancy.

        This is a READ-ONLY CHECK. It MUST NEVER feed the reconcile edge set or the
        delivered truth: direct-edges-let-SpiceDB-close stays the ONE delivery path.
        A discrepancy is REPORTED (for an operator / CI conformance gate), never
        silently reconciled into what we ship."""
        gp = group_principal(group_object_id)
        # Local: the connector's delivered closure for THIS group (active-Member
        # user canonicals only), from the snapshot's own direct edges.
        local_users = transitive_user_closure(snapshot.memberships).get(gp, set())

        # Graph oracle: the server-side transitive member set, gated to active
        # Members exactly as delivery gates (so the two sets are comparable).
        graph_users: set[str] = set()
        for raw in self._list_transitive_members(group_object_id):
            if raw.get("@odata.type") != _MEMBER_TYPE_USER:
                continue  # only user leaves compare; nested groups are structure
            user = self._parse_user(raw)
            if is_active_member(user):
                graph_users.add(user.canonical)

        return ConformanceResult(
            group=gp,
            local_users=local_users,
            graph_users=graph_users,
            missing_locally=graph_users - local_users,
            extra_locally=local_users - graph_users,
        )

    def _list_transitive_members(self, group_oid: str) -> list[dict]:
        """Graph ``/groups/{id}/transitiveMembers`` (paged) — the flattened
        transitive set, used ONLY by :meth:`conformance_oracle`. Never on the
        delivery path (that walks DIRECT members and lets SpiceDB close)."""
        members: list[dict] = []
        params = {
            "$select": _USER_SELECT,
        }
        next_path: str | None = f"groups/{group_oid}/transitiveMembers"
        next_params: Mapping[str, str] | None = params
        while next_path is not None:
            page = self._transport.get_json(next_path, next_params or {})
            members.extend(page.get("value", []))
            next_path = page.get("@odata.nextLink")
            next_params = None
        return members


# ---------------------------------------------------------------------------
# Tombstone → deprovision + per-edge delete (G3(b))
# ---------------------------------------------------------------------------


def tombstoned_user_ops(
    tombstoned_oids: Iterable[str], prev: EntraSnapshot, tenant_id: str
) -> list[AdminOp]:
    """The G3(b) ops for user-object-deletion tombstones, in fail-closed order:
    for each tombstoned objectId, first DELETE every ``(group, user:<canonical>)``
    edge the connector's OWN persisted ``prev`` snapshot recorded for it (because
    ``admin_deprovision`` does NOT delete SpiceDB group edges and ``open_scope``
    keeps group tokens for a deprovisioned subject), THEN ``POST /deprovision``
    the canonical (kills direct grants + fires the durable revoke).

    The edge deletes come from ``prev`` (the snapshot), NOT from any delta — that
    is the whole point of closing the member-object-deletion hole."""
    ops: list[AdminOp] = []
    deprovisions: list[AdminOp] = []
    for oid in sorted(set(tombstoned_oids)):
        canonical = prev.oid_to_canonical.get(oid)
        if canonical is None:
            continue
        for group, member in sorted(prev.memberships):
            if member == canonical and group != EVERYONE_GROUP:
                ops.append(
                    AdminOp(
                        "DELETE",
                        GROUPS_PATH,
                        {"tenant_id": tenant_id, "group": group, "member": member},
                    )
                )
        deprovisions.append(
            AdminOp(
                "POST",
                DEPROVISION_PATH,
                {"tenant_id": tenant_id, "principal": canonical},
            )
        )
    ops.extend(deprovisions)
    return ops


def _diff_tombstones(prev: EntraSnapshot, desired: EntraSnapshot) -> set[str]:
    """ObjectIds present in the prior snapshot's ``oid_to_canonical`` but absent
    from the desired one — the users that dropped out this cycle (deleted,
    disabled, Member→Guest, ``#EXT#``, or delta-tombstoned). Each fires the
    G3(b) deprovision + per-edge-delete path."""
    return set(prev.oid_to_canonical) - set(desired.oid_to_canonical)


# ---------------------------------------------------------------------------
# Sink: reuse VerityAdminSink but inspect registry/alias for quarantine (G-alias)
# ---------------------------------------------------------------------------


class EntraAdminSink(VerityAdminSink):
    """gdirectory's ``VerityAdminSink`` PLUS a fail-closed alias-collision guard:
    a ``registry/alias`` op returning a non-empty ``quarantined[]`` (the SSO
    subject is already bound to a DIFFERENT canonical) raises
    :class:`AliasCollision`, aborting the cycle before checkpoint. The base sink
    only checks HTTP status; the alias route returns 200 with the collision in
    the body, so it must be inspected here.

    It also OVERRIDES ``heartbeat`` for two reasons: (1) the base ``heartbeat``
    hardcodes gdirectory's module ``SOURCE_NAME`` (``"gdirectory"``); an Entra
    heartbeat must report ``source="entra"`` or it would masquerade as a Google
    sync in the operator panel; (2) it surfaces the fail-closed **alarms**
    (:attr:`_alarms`) — a swallowed ``SyncStateReset`` is a silent stale-open, and
    the operator's ONLY signal that a fail-closed event happened is this heartbeat
    body. Alarms are accumulated by the runner via :meth:`record_alarm` (null
    ``alias_field`` warnings, an :class:`AliasCollision` that aborted a cycle, a
    :class:`SyncStateReset` that forced a full resync) and posted in the same
    best-effort ``connector-status`` body."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Fail-closed alarm accumulator, drained on each heartbeat (mirrors the
        # ``_applied`` accumulator). Each entry: {"kind": str, "detail": str}.
        self._alarms: list[dict[str, str]] = []

    def apply(self, op: AdminOp) -> None:
        response = self._client.request(
            op.method, f"{self._base_url}{op.path}", json=dict(op.body)
        )
        response.raise_for_status()
        if op.path == REGISTRY_ALIAS_PATH:
            try:
                quarantined = response.json().get("quarantined") or []
            except Exception:  # noqa: BLE001 — a non-JSON 2xx is not a collision
                quarantined = []
            if quarantined:
                raise AliasCollision(quarantined)
        self._applied += 1
        self._tenant_id = op.body.get("tenant_id", self._tenant_id)

    def record_alarm(self, kind: str, detail: str) -> None:
        """Queue one fail-closed alarm for the next heartbeat. ``kind`` is a
        stable machine tag (``sync_state_reset`` / ``alias_collision`` /
        ``null_alias_field``); ``detail`` is a human string (never a secret)."""
        self._alarms.append({"kind": kind, "detail": detail})

    def heartbeat(self, cursor: str | None = None) -> None:
        """Best-effort ``POST /v1/admin/connector-status`` for ``source="entra"``.
        Unlike the base, it fires when there are **alarms** even if zero ops were
        applied — a ``SyncStateReset`` that delivered nothing MUST still reach the
        operator. Never raises; drains both accumulators in ``finally``."""
        alarms = list(self._alarms)
        if not alarms and (not self._applied or not self._tenant_id):
            # Nothing delivered and nothing to alarm: no signal to send. Still
            # drain so a stale accumulator can't leak into a later cycle.
            self._applied = 0
            self._alarms = []
            return
        # A tenant is required to key the row; fall back to the connector's
        # configured tenant if no op set it (alarm-only cycles set no _tenant_id).
        tenant = self._tenant_id or self.alarm_tenant_id
        if not tenant:
            self._applied = 0
            self._alarms = []
            return
        try:
            body: dict[str, Any] = {
                "tenant_id": tenant,
                "source": SOURCE_NAME,
                "items_synced": self._applied,
            }
            if cursor is not None:
                body["cursor"] = cursor
            if alarms:
                body["alarms"] = alarms
            self._client.post(f"{self._base_url}{CONNECTOR_STATUS_PATH}", json=body)
        except Exception:  # noqa: BLE001 — telemetry only
            pass
        finally:
            self._applied = 0
            self._alarms = []

    #: Set by the runner so an alarm-only heartbeat (zero applied ops, e.g. a
    #: SyncStateReset on the very first fold) can still key its row by tenant.
    alarm_tenant_id: str | None = None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _load_snapshot(state_file: Path) -> EntraSnapshot:
    if not state_file.exists():
        return EntraSnapshot()
    raw = json.loads(state_file.read_text()).get("snapshot", {})
    directory_users = [
        DirectoryUser(
            directory_id=str(u.get("directory_id", "")),
            primary_email=str(u.get("primary_email", "")),
            aliases=tuple(
                SsoAlias(alias=str(a.get("alias", "")), source=str(a.get("source", "")))
                for a in u.get("aliases", [])
            ),
        )
        for u in raw.get("directory_users", [])
    ]
    return EntraSnapshot(
        users=list(raw.get("users", [])),
        memberships=[(g, m) for g, m in raw.get("memberships", [])],
        everyone_members=list(raw.get("everyone_members", [])),
        directory_users=directory_users,
        oid_to_canonical=dict(raw.get("oid_to_canonical", {})),
        users_delta_link=raw.get("users_delta_link"),
        groups_delta_link=raw.get("groups_delta_link"),
    )


def _save_snapshot(state_file: Path, snapshot: EntraSnapshot, reconciled_at: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps(
            {
                "last_reconcile_at": reconciled_at,
                "snapshot": {
                    "users": snapshot.users,
                    "memberships": [list(pair) for pair in snapshot.memberships],
                    "everyone_members": snapshot.everyone_members,
                    "directory_users": [
                        {
                            "directory_id": u.directory_id,
                            "primary_email": u.primary_email,
                            "aliases": [
                                {"alias": a.alias, "source": a.source} for a in u.aliases
                            ],
                        }
                        for u in snapshot.directory_users
                    ],
                    "oid_to_canonical": snapshot.oid_to_canonical,
                    "users_delta_link": snapshot.users_delta_link,
                    "groups_delta_link": snapshot.groups_delta_link,
                },
            },
            indent=2,
        )
        + "\n"
    )


def build_cycle_ops(prev: EntraSnapshot, desired: EntraSnapshot, tenant_id: str) -> list[AdminOp]:
    """The full ordered op list for one cycle: the reused ``build_admin_ops`` over
    the DirectorySnapshot views (registry → principals → adds → removals →
    deprovisions), PLUS the G3(b) tombstone ops (per-edge deletes + deprovision)
    for users that dropped out via object-deletion, whose group edges the base
    diff also removes but whose deprovision + explicit edge-delete the base diff
    does NOT emit (it deprovisions on ``directory_users`` diff, which a delta may
    not repopulate for a deleted user). We de-dup so a user caught by both paths
    is deprovisioned once and its edges deleted once."""
    base = build_admin_ops(
        diff_snapshots(prev.to_directory_snapshot(), desired.to_directory_snapshot()),
        tenant_id,
        SOURCE_NAME,
    )
    tombstoned = _diff_tombstones(prev, desired)
    extra = tombstoned_user_ops(tombstoned, prev, tenant_id)
    # De-dup: keep base ops, then append only tombstone ops not already present.
    seen = {(op.method, op.path, json.dumps(op.body, sort_keys=True)) for op in base}
    merged = list(base)
    for op in extra:
        key = (op.method, op.path, json.dumps(op.body, sort_keys=True))
        if key not in seen:
            seen.add(key)
            merged.append(op)
    return merged


def _record_alarm(sink: AdminSink, kind: str, detail: str) -> None:
    """Queue a fail-closed alarm on the sink if it can carry one (the real
    :class:`EntraAdminSink`); a dry-run/other sink silently ignores it — the
    alarm still prints on stdout via the caller. Never swallowed on the real
    path: a swallowed SyncStateReset is a silent stale-open."""
    record = getattr(sink, "record_alarm", None)
    if record is not None:
        record(kind, detail)


def _fire_heartbeat(sink: AdminSink, *, cursor: str | None) -> None:
    """Fire the sink's best-effort heartbeat if it has one. On the real sink this
    posts ``connector-status`` with the drained alarms + items_synced; on a
    dry-run sink there is none, so this is a no-op."""
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=cursor)


def run_once(
    connector: EntraDirectoryConnector,
    sink: AdminSink,
    state_file: Path,
    *,
    now: str | None = None,
    persist: bool = True,
) -> int:
    """One reconcile cycle: load the prior FULL snapshot, reconcile (full first
    run, else delta-fold into a new full snapshot), diff old-full vs new-full,
    apply ops in order, checkpoint. A :class:`SyncStateReset` from the transport
    forces a full resync and FAILS CLOSED — it propagates without checkpointing
    (the caller discards the cursor and retries full). ``persist=False`` (dry
    run) never advances the snapshot.

    Fail-closed **alarms** are threaded into the connector-status heartbeat, not
    just stdout, so the operator sees them: a null-``alias_field`` warning after a
    delivered cycle, and — because they abort before the normal heartbeat —
    :class:`SyncStateReset` and :class:`AliasCollision`, each of which fires a
    dedicated alarm heartbeat before re-raising. A swallowed SyncStateReset would
    be a silent stale-open."""
    # Let an alarm-only heartbeat (zero applied ops) still key its row by tenant.
    if hasattr(sink, "alarm_tenant_id"):
        sink.alarm_tenant_id = connector.config.tenant_id
    reconciled_at = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    previous = _load_snapshot(state_file)
    try:
        if previous.users_delta_link and previous.groups_delta_link:
            desired = connector.reconcile_delta(previous)
        else:
            desired = connector.reconcile()
    except SyncStateReset as exc:
        # Fail closed: do NOT checkpoint. Discard cursors so the next cycle does a
        # clean full resync, surface the reset as an operator alarm (never just
        # swallowed to stdout), and re-raise so the runner logs it.
        if persist and state_file.exists():
            state_file.unlink()
        _record_alarm(
            sink,
            "sync_state_reset",
            f"delta token invalidated ({exc}); forced full resync — group-membership "
            "freshness paused until it succeeds (fail-closed).",
        )
        _fire_heartbeat(sink, cursor=None)
        raise
    ops = build_cycle_ops(previous, desired, connector.config.tenant_id)
    try:
        for op in ops:
            sink.apply(op)
    except AliasCollision as exc:
        # A cross-IdP under-merge: the alias is already bound to a different
        # canonical. The cycle aborted before checkpoint; surface it as an alarm
        # so the operator can remediate, then re-raise.
        _record_alarm(
            sink,
            "alias_collision",
            f"SSO alias already bound to a different canonical (cross-IdP under-merge): "
            f"{exc.quarantined}",
        )
        _fire_heartbeat(sink, cursor=None)
        raise
    # Surface any null-alias_field / honesty warnings the connector raised this
    # cycle as alarms alongside the delivered heartbeat.
    for warning in connector.warnings:
        _record_alarm(sink, "null_alias_field", warning)
    if persist:
        _save_snapshot(state_file, desired, reconciled_at)
    _fire_heartbeat(sink, cursor=reconciled_at)
    return len(ops)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.entra_directory",
        description="Verity Microsoft Entra ID directory sync (Identity Plane).",
    )
    parser.add_argument("--once", action="store_true", help="run a single reconcile cycle and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="print admin ops instead of calling the server"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("ENTRA_STATE_FILE", ".verity/entra_directory_snapshot.json")),
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url", default=os.environ.get("VERITY_URL", "http://localhost:8080")
    )
    parser.add_argument("--graph-tenant", default=os.environ.get("ENTRA_TENANT_ID"))
    parser.add_argument("--client-id", default=os.environ.get("ENTRA_CLIENT_ID"))
    parser.add_argument(
        "--alias-field",
        default=os.environ.get("ENTRA_ALIAS_FIELD"),
        help="the Entra user field that is the tenant's SSO NameID (e.g. "
        "onPremisesImmutableId) — admin-declared, never guessed. Unset: no SSO "
        "aliases welded (fail-closed).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("ENTRA_POLL_INTERVAL_SECS", "300")),
        help="reconcile interval in seconds (without --once); this interval IS the "
        "group-membership freshness bound (G3).",
    )
    args = parser.parse_args(argv)

    config = EntraDirectoryConfig(
        tenant_id=args.tenant_id,
        graph_tenant=args.graph_tenant,
        client_id=args.client_id,
        client_secret_file=os.environ.get("ENTRA_CLIENT_SECRET_FILE"),
        client_cert_file=os.environ.get("ENTRA_CLIENT_CERT_FILE"),
        alias_field=args.alias_field,
    )
    token_provider = load_graph_credentials(config)
    connector = EntraDirectoryConnector(HttpGraphTransport(token_provider), config)

    api_key = os.environ.get("VERITY_API_KEY")
    sink: AdminSink = (
        DryRunAdminSink() if args.dry_run else EntraAdminSink(args.verity_url, api_key=api_key)
    )

    while True:
        try:
            applied = run_once(connector, sink, args.state_file, persist=not args.dry_run)
        except SyncStateReset:
            # run_once already fired the fail-closed alarm heartbeat before re-raising.
            print("entra_directory: delta token invalidated — full resync next cycle (fail-closed)")
            connector.warnings.clear()
            if args.once:
                return 1
            time.sleep(args.interval)
            continue
        except AliasCollision as exc:
            # run_once already fired the alarm heartbeat. A cross-IdP under-merge
            # aborts THIS cycle (no checkpoint); the operator must remediate the
            # colliding alias. Keep the supervised loop alive.
            print(
                "entra_directory: alias collision — SSO subject already bound to a "
                f"different canonical (fail-closed, not welded): {exc.quarantined}"
            )
            connector.warnings.clear()
            if args.once:
                return 1
            time.sleep(args.interval)
            continue
        for warning in connector.warnings:
            print(f"entra_directory: WARNING: {warning}")
        connector.warnings.clear()
        dest = "(dry-run, snapshot unchanged)" if args.dry_run else f"snapshot -> {args.state_file}"
        print(f"entra_directory: applied {applied} admin op(s); {dest}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
