"""SharePoint Online / OneDrive-for-Business connector — the Microsoft-shop
Google Drive: a rung-1 mirrored-grant content connector with fail-closed
reconstructed effective visibility (build contract: the red-teamed SharePoint
plan; structural template: :mod:`gdrive`; Graph transport + identity weld:
:mod:`entra_directory`).

The four load-bearing fail-closed guarantees (every design choice below serves
one; where one cannot be met the affected scope is QUARANTINED, never guessed):

G1 — complete-ACL-or-quarantine (R1). Graph's ``…/permissions`` endpoint is
CALLER-FILTERED for non-owner identities: an under-privileged app identity can
receive a *partial* permission list with a 200 OK, indistinguishable from a
genuinely narrow ACL. Completeness is therefore *proven per drive*, never
assumed: an operator-configured :class:`DriveCanary` names an item on the drive
plus a co-owner grant (an Entra objectId) that MUST appear in that item's
permission list. Canary absent, unreadable, or the expected grant missing ⇒ the
whole drive is delivered ``acl_provenance="quarantined"`` with no ``visibility``
— and, ACL-before-content, no per-item permissions or content are fetched at
all. With ``require_complete_acl=True`` (default) a drive WITHOUT a configured
canary is also quarantined wholesale (completeness unprovable ⇒ over-hide).

G2 — immutable-key-or-drop (R2/R5). Users key on the Entra ``objectId`` GUID
(``grantedToV2.user.id``) ONLY, emitted as an ``aad-oid:<objectId>`` principal
marker that resolves through the ``principal_crosswalk`` row the Entra
directory sync writes: ``(source="entra", local_id=<objectId>) → canonical``.
(The plan sketched ``("sharepoint", "aad-oid:<oid>")`` as the row shape; the
dir-sync AS BUILT stamps ``source="entra"``/bare-objectId — the weld targets
the row that exists.) ``siteUser.loginName`` is NEVER an identity key: its
UPN encoding is undocumented and tenant-dependent, so even a strictly-parsing
``i:0#.f|membership|…`` claim is not emitted — the opportunistic cross-checked
``emails`` secondary is deferred to the live lane. A direct grant missing its
objectId poisons the item; a link RECIPIENT missing it is dropped (dropping a
recipient only narrows; if nothing else survives the item quarantines anyway).

G3 — fresh-or-quarantine for NEW indexing (R3/R4); retraction of PREVIOUSLY-
INDEXED content IS enforced at the index via the ``POST /v1/admin/retire``
drain (below). Delta tracks by id and does
NOT surface children whose only change is an inherited permission change from
a parent — a parent-only revocation can go stale-open. Mitigations, in order:
(a) a folder surfacing in the delta stream triggers a subtree re-walk of its
children (fresh ACL re-read per child); (b) the bounded reconcile SLA —
``poll`` compares the cursor's ``last_reconcile_at`` (stamped only by a
completed, ZERO-FAILURE full backfill) against ``reconcile_sla_hours``;
past-SLA (or never reconciled), every polled document event is FORCED to
quarantine posture until a backfill re-verifies.

ENFORCEMENT (the retire drain): a detected retraction — a removal marker, or
an item transitioning to ``acl_provenance="quarantined"`` — produces NO
documents-endpoint op (the ingest ladder has nothing to deliver); each such
body is PARKED in the ``sharepoint_parked_retractions.json`` ledger next to
the cursor state (dedup'd by document_id) and every parked entry is REPLAYED
as ``POST /v1/admin/retire`` under the same admin bearer the sinks use.
Replay ORDER is load-bearing (the over-retire race): each cycle drains the
PRE-EXISTING ledger BEFORE delivering the cycle's events, parks the cycle's
own rejects after delivery, then drains those; and a successful delivery
UNPARKS any older entry for the same document_id — a parked signal is
strictly older than that delivery, so replaying it afterwards would blank
the just-written chunks of a restored document.
The server closes the document's current chunks
(``valid_to`` + blanked visibility), so previously-indexed content stops
serving on the next read after the drain. Any 2xx — including the idempotent
0-chunk replay of an already-retired or never-indexed document — removes the
entry from the ledger; any failure keeps it parked and alarmed on the
connector-status heartbeat (``kind="parked_retraction"``, counting only what
remains) until a later cycle drains it. The reconcile SLA is recorded and
alarmed, not enforced against the existing index. The delta cursor still
advances past parked retractions — blocking it would livelock on
permanently-quarantined items; the ledger, not the cursor, carries the signal
until its retire replay lands. Honest remainder: a per-item ACL NARROWING
that stays mirrored (fewer principals, not a quarantine transition) is a
re-index, not a retraction — it rides the re-ingest / acl-change paths, never
this drain; and the gdrive connector has no drain wired yet (its removal
markers still ride the documents endpoint only).
A 410/``syncStateNotFound`` raises :class:`SyncStateReset` (reused from
entra_directory) — the runner discards the cursor, alarms
``kind="delta_reset"`` (a full re-backfill is REQUIRED to re-narrow
visibility; until it runs, previously-indexed items keep serving), and
re-raises; the Location-header ``resyncChangesApplyDifferences`` optimization
is a live-lane refinement (a full re-backfill is the conservative superset).

G4 — unknown-principal-or-scope ⇒ poison item (R6/R7). Any unmapped identity
facet, unrecognized link scope, legacy non-V2 ``grantedTo`` shape, special
principal without an explicit safe mapping, or plain "Everyone" poisons the
WHOLE item's ACL (``AclEnvelope(resolvable=False)``) — never guess, never
partial-emit. Specifically:

- "Everyone except external users" — the ``spo-grid-all-users`` claim
  (``c:0-.f|rolemanager|spo-grid-all-users/<tenantGUID>``) — maps to
  entra_directory's materialized guest-excluded tenant token
  ``group:entra-everyone-except-guests`` ONLY when the claim's tenant GUID
  matches the configured ``tenant_guid`` (anchored, never guessed); otherwise
  poison. (The plan's e2 required a guest-excluded token: EVERYONE_GROUP is
  guest-excluded BY CONSTRUCTION — the four-part is_active_member gate — so no
  operator domain-token config can get it wrong.)
- Plain "Everyone" (``c:0(.s|true``, includes external/anonymous) — ALWAYS
  poison, no operator override (an internet-exposure claim).
- Sharing links by scope: ``anonymous`` ⇒ quarantine unless the operator sets
  the loudly-warned ``anonymous_maps_to`` foot-gun; ``organization`` ⇒ the same
  guest-excluded tenant token (guests who can redeem org links are excluded —
  over-hide, never over-share; deviation from the plan's config'd domain token,
  strictly narrower and config-error-proof); ``users`` ⇒ the enumerated
  ``grantedToIdentitiesV2`` recipients; ``existingAccess`` ⇒ nothing (never
  widens); anything else ⇒ poison.
- SP-native site groups (``grantedToV2.siteGroup``): the principal
  ``group:sp-site-<siteId>-<principalId>`` is emitted for structure, but their
  membership needs the SharePoint-REST audience (cert-auth, a separate
  workstream — R8) which does not exist yet, so with
  ``site_groups_resolvable=False`` (default) any item carrying a site-group
  grant is QUARANTINED — the prompt-hardened default, strictly narrower than
  the plan's "closes to nobody" row, because an unexpanded site group commonly
  hides an Everyone claim behind it.
- Entra group grants emit ``group:entra-group-<objectId>`` — imported
  :func:`entra_directory.group_principal`, so grants weld to the synced graph
  by construction, never by string coincidence.
- Unredeemed invitations and ``application``/``device`` identities confer
  nothing (rows f/g).
- Roles are allowlisted (C1): a permission whose ``roles`` contain any value
  outside the tight confers-read set {read, write, owner, sp.full control,
  fullcontrol} (case-insensitive), or whose ``roles`` are empty/missing,
  poisons the item — a role vocabulary we have not audited must never be
  assumed to confer-or-not-confer read.

Items with NEITHER a ``file`` nor a ``folder`` facet (packages, unknown item
kinds — C3) are skipped entirely: no permission fetch, no content, no sink
body; the skip is counted and reported, never silent.

Resolution (mirrors gdrive's registry split, Microsoft-shaped): principals are
split by :func:`crosswalk.split_sharepoint_principals` — ``aad-oid:`` markers
become ``CrosswalkOwner("entra", <objectId>)`` on the ``resolvable`` path,
everything else rides ``principals`` — one ``POST /v1/admin/principals`` round
trip. Per plan ACL-table row a, an objectId with no crosswalk row contributes
NOTHING (the surviving grants still mirror); zero surviving tokens quarantines
the item (same ladder as gdrive's build_document_request).

Honesty notes carried from the plan: a ``preventsDownload``/view-only/password
link still yields extracted text served to whoever the mirrored grant resolves
to — Verity cannot honor link-level view-only semantics (stated, not hidden).
There is no UserRecordAccess-style oracle for SharePoint; effective visibility
is reconstructed, fail-closed, and unaudited until a live fidelity harness
exists. This module is FIXTURE-VERIFIED; live lanes still open: SP-REST site
group resolution + cert auth (R8), change-notification subscriptions (root
``updated`` only, no item detail — they just trigger a delta cycle), the
``deltashowsharingchanges``/FullControl near-real-time tier, and locking the
claim strings + canary privilege level on a real tenant.

Auth (BYOT): the same customer app registration + ENTRA_* env contract as
:mod:`entra_directory` (Graph audience only), via its lazy-msal
``load_graph_credentials`` — imported, not forked. Scope posture: per-site
``Sites.Selected`` at a privilege level that PROVES G1 completeness (the
canary is the proof, not the scope name). SHAREPOINT_* env vars cover what is
distinct (site ids, tenant GUID, canaries, SLA).

Sink contract: the same ``POST /v1/ingest/documents`` bodies as gdrive
(``document_id="{driveId}:{itemId}"`` — the drive prefix is load-bearing,
item ids are drive-scoped; ``valid_from=<lastModifiedDateTime>``; inline
``content`` for text, ``content_base64``+``filename`` for the server-side
Tier-1 binary lane; quarantined bodies carry NO ``visibility``).

Runner: ``python -m verity_ingest.connectors.sharepoint --once|--backfill
[--dry-run]`` with a JSON cursor state file (per-drive deltaLinks +
``last_reconcile_at``) and, beside it, the ``sharepoint_parked_retractions``
ledger of detected retractions awaiting their ``/v1/admin/retire`` replay
(see G3; drained every cycle).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterable, Iterator, Mapping, Protocol, Sequence

import httpx

from verity_ingest import crosswalk
from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

# Graph plumbing reused from the Entra directory sync (import, don't fork):
# HttpGraphTransport already carries bearer auth, 429/Retry-After honoring,
# 410/syncStateNotFound → SyncStateReset, and the nextLink-verbatim fix
# (params=None on followed links — a live-caught bug; do not regress it).
# group_principal + EVERYONE_GROUP are imported so SharePoint grants weld to
# the synced identity graph BY CONSTRUCTION, never by string coincidence.
from verity_ingest.connectors.entra_directory import (
    EVERYONE_GROUP,
    EntraDirectoryConfig,
    HttpGraphTransport,
    SyncStateReset,
    group_principal,
    load_graph_credentials,
)

# Sink + content-typing conventions reused from gdrive (the content-connector
# template): one documents endpoint, one fail-closed body ladder, the same
# binary lane. _is_indexable_body is the runner's fail-closed skip gate.
from verity_ingest.connectors.gdrive import (
    CONNECTOR_STATUS_PATH,
    DOCUMENTS_PATH,
    DocumentSink,
    DryRunSink,
    VerityDocumentSink,
    _is_indexable_body,
    is_binary_extractable,
    is_extractable,
)

__all__ = [
    "SOURCE_NAME",
    "DOCUMENTS_PATH",
    "RETIRE_PATH",
    "EVERYONE_GROUP",
    "SyncStateReset",
    "DriveCanary",
    "SharePointConfig",
    "SharePointDocumentEvent",
    "SharePointTransport",
    "HttpSharePointTransport",
    "SharePointConnector",
    "SharePointRegistry",
    "StaticSharePointRegistry",
    "HttpSharePointRegistry",
    "DryRunSink",
    "VerityDocumentSink",
    "SharePointStatusSink",
    "map_permissions",
    "site_group_principal",
    "group_principal",
    "build_sharepoint_document_request",
    "load_sharepoint_credentials",
    "run_once",
    "run_backfill",
    "main",
]

SOURCE_NAME = "sharepoint"

#: The server-side retraction-enforcement route the parked-retractions drain
#: replays into (admin plane; same bearer as the sinks). One body per parked
#: document: ``{tenant_id, source, document_id, reason}``.
RETIRE_PATH = "/v1/admin/retire"

#: The sharePointIdentitySet facets Graph v1.0 documents. Any OTHER key in an
#: identity set is an unknown facet ⇒ poison the item (G4 — never guess what a
#: new facet grants).
_KNOWN_FACETS = frozenset({"user", "group", "siteUser", "siteGroup", "application", "device"})

#: "Everyone except external users" claim, tenant-GUID-anchored (R6):
#: ``c:0-.f|rolemanager|spo-grid-all-users/<tenantGUID>``. Matched as a strict
#: PREFIX of the whole loginName (C4) — a substring match would let a lookalike
#: claim that merely EMBEDS this string mint the tenant-wide token.
_SPO_GRID_PREFIX = "c:0-.f|rolemanager|spo-grid-all-users/"

#: Plain "Everyone" (INCLUDES external/anonymous) — always poison, no override.
_EVERYONE_CLAIM = "c:0(.s|true"

#: The confers-read roles allowlist (C1). Graph v1.0 permission ``roles``
#: values this connector has audited as read-conferring grants it can mirror:
#: ``read`` and ``write`` (the documented sharing roles), ``owner`` (drive
#: owner grants), and SharePoint's full-control spellings ``sp.full control``
#: (the SP role-definition name Graph surfaces on site permissions) /
#: ``fullcontrol``. Case-insensitive. ANY other value — or an empty/missing
#: ``roles`` on a permission — poisons the item (G4): an unaudited role must
#: never be assumed to confer-or-not-confer read.
_CONFERS_READ_ROLES = frozenset({"read", "write", "owner", "sp.full control", "fullcontrol"})

#: Poison sentinel returned by the identity-set mapper (G4).
_POISON: Any = object()


# ---------------------------------------------------------------------------
# Config & events
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriveCanary:
    """The G1 completeness proof for one drive: ``item_id`` names an item whose
    permission list is KNOWN (operator-verified) to contain a grant to the Entra
    user ``expected_user_oid`` (a co-owner planted for this purpose). If the
    app's view of that item's permissions omits the grant, the view is
    caller-filtered (R1) and the whole drive quarantines."""

    item_id: str
    expected_user_oid: str


@dataclass
class SharePointConfig:
    """Connector configuration. No default widens visibility."""

    tenant_id: str = "default"  # Verity tenant (opaque)
    # Graph auth — same BYOT app registration + env contract as entra_directory.
    graph_tenant: str | None = None  # ENTRA_TENANT_ID (GUID or domain)
    client_id: str | None = None  # ENTRA_CLIENT_ID
    client_secret_file: str | None = None  # ENTRA_CLIENT_SECRET_FILE
    client_cert_file: str | None = None  # ENTRA_CLIENT_CERT_FILE
    # The sites to crawl (Sites.Selected posture: explicit, per-site — the
    # least-privilege default; whole-tenant enumeration is a deliberate opt-in
    # a later lane may add, never implicit).
    site_ids: list[str] = field(default_factory=list)
    # The Entra tenant GUID that anchors the spo-grid-all-users claim (R6).
    # Unset ⇒ the "everyone except external" claim POISONS (never guessed).
    tenant_guid: str | None = None
    # Foot-gun (R7): maps PUBLIC-INTERNET anonymous links to an internal
    # principal. Off by default; setting it emits a loud startup warning.
    anonymous_maps_to: str | None = None
    # SP-native site-group membership needs the SharePoint-REST audience
    # (cert auth, separate workstream — R8). Until that sync exists, an item
    # carrying a siteGroup grant QUARANTINES (fail-closed default).
    site_groups_resolvable: bool = False
    # G1: drives whose ACL-completeness cannot be proven (no canary, canary
    # unreadable, or expected grant missing) quarantine wholesale.
    require_complete_acl: bool = True
    canaries: dict[str, DriveCanary] = field(default_factory=dict)  # drive_id → canary
    # G3: items not re-verified by a full backfill within this window are
    # served quarantined, not stale-open.
    reconcile_sla_hours: int = 24
    page_size: int = 200


@dataclass
class SharePointDocumentEvent(DocumentEvent):
    """DocumentEvent + the SPO timestamp, item name, and removal marker."""

    modified_time: str = ""
    name: str = ""
    removed: bool = False


def site_group_principal(site_id: str, principal_id: str) -> str:
    """SP-native site-group principal, keyed ``(siteId, principalId)`` (G2) —
    site groups are site-scoped classic principals, so the site id is
    load-bearing. Membership arrives only via the future SP-REST sync (R8)."""
    return f"group:sp-site-{site_id}-{principal_id}"


# ---------------------------------------------------------------------------
# ACL mapping (fail-closed, the plan's table rows a–h)
# ---------------------------------------------------------------------------


def _map_claim(login_name: str, tenant_guid: str | None) -> Any:
    """Map a siteUser claims loginName: the guest-excluded tenant token, poison,
    or None (not a special claim — the caller decides what the facet means)."""
    low = login_name.lower()
    if low.startswith(_SPO_GRID_PREFIX):
        # "Everyone except external users", keyed by tenant GUID. The claim
        # must be EXACTLY the rolemanager prefix + the configured tenant GUID
        # (C4: a substring match would let a lookalike loginName that embeds
        # the marker mint the tenant-wide token). Map to the dir-sync's
        # materialized guest-excluded token ONLY when anchored; anything else
        # is never guessed (e2/R6).
        claim_guid = low[len(_SPO_GRID_PREFIX) :]
        if tenant_guid and claim_guid == tenant_guid.lower():
            return EVERYONE_GROUP
        return _POISON
    if low.startswith(_EVERYONE_CLAIM):
        # Plain "Everyone" includes external/anonymous: always quarantine, no
        # operator override (e1/R6 — an internet-exposure claim).
        return _POISON
    return None


def _map_identity_set(
    idset: Mapping[str, Any],
    *,
    site_id: str,
    tenant_guid: str | None,
    recipient: bool,
) -> Any:
    """Map one sharePointIdentitySet to a list of principal strings, ``[]``
    (confers nothing), or ``_POISON`` (G4).

    ``recipient=True`` is the link-recipient mode (plan row d3): an
    unresolvable recipient is DROPPED (narrows only — if nothing else survives
    the item quarantines on zero tokens anyway). Direct grants (``recipient=
    False``) poison instead — silently dropping a direct grant would mis-mirror
    the ACL (plan rows a/h)."""
    unknown = set(idset) - _KNOWN_FACETS
    if unknown:
        return _POISON  # a facet Graph added after this code was written: never guess
    site_user = idset.get("siteUser")
    if site_user is not None:
        claim = _map_claim(str(site_user.get("loginName") or ""), tenant_guid)
        if claim is _POISON:
            return _POISON
        if claim is not None:
            return [claim]
    user = idset.get("user")
    if user is not None:
        oid = str(user.get("id") or "")
        if oid:
            # G2: the immutable Entra objectId is the ONLY user key. The
            # sibling siteUser.loginName — even a strictly-parsing membership
            # claim — is never emitted (R2: undocumented encoding, and a parse
            # that "succeeds" on a malformed value would weld the wrong human).
            return [f"{crosswalk.AAD_OID_PREFIX}{oid}"]
        return [] if recipient else _POISON
    group = idset.get("group")
    if group is not None:
        gid = str(group.get("id") or "")
        if gid:
            return [group_principal(gid)]  # entra_directory's naming, by import
        return [] if recipient else _POISON
    site_group = idset.get("siteGroup")
    if site_group is not None:
        pid = str(site_group.get("id") or "")
        if pid:
            return [site_group_principal(site_id, pid)]
        return [] if recipient else _POISON
    if "application" in idset or "device" in idset:
        return []  # machines confer no read visibility (row g)
    if site_user is not None:
        # A BARE siteUser (no user facet) whose loginName is not a recognized
        # special claim: the loginName is never an identity key (R2), and there
        # is no immutable key to fall back to (siteUser.id is a SP-local
        # principal id, not an Entra objectId).
        return [] if recipient else _POISON
    return _POISON  # empty/unrecognizable identity set


def map_permissions(
    permissions: Iterable[Mapping[str, Any]],
    *,
    site_id: str,
    config: SharePointConfig,
) -> AclEnvelope:
    """Map a Graph ``…/permissions`` list to an AclEnvelope — the plan's full
    ACL table, fail-closed (G4): any row we cannot faithfully mirror poisons
    the WHOLE envelope (``resolvable=False`` → quarantine); a partially-mapped
    ACL is never emitted.

    Precondition: the caller has already proven the list is COMPLETE for this
    drive (the G1 canary) — a faithful mapping of a caller-filtered partial
    list would still be a mis-mirror."""
    principals: list[str] = []
    groups: list[str] = []

    def add(mapped: str) -> None:
        target = principals if mapped.startswith(crosswalk.AAD_OID_PREFIX) else groups
        if mapped not in target:
            target.append(mapped)

    for perm in permissions:
        # C1: roles gate first, for EVERY permission shape. A value outside the
        # audited confers-read allowlist — or an empty/missing roles list — is
        # a grant whose semantics we cannot mirror: poison (same G4 posture as
        # an unknown facet), never "probably harmless".
        roles = perm.get("roles")
        if not roles:
            return AclEnvelope(resolvable=False)
        if any(str(role).lower() not in _CONFERS_READ_ROLES for role in roles):
            return AclEnvelope(resolvable=False)
        link = perm.get("link")
        if link is not None:
            scope = link.get("scope")
            if scope == "anonymous":
                # Public-internet link (d1). preventsDownload/hasPassword do not
                # change what Verity would serve (extracted text), so they buy
                # no exception (R7).
                if config.anonymous_maps_to:
                    add(config.anonymous_maps_to)
                else:
                    return AclEnvelope(resolvable=False)
            elif scope == "organization":
                # Guest-excluded by construction: guests can redeem org links,
                # so this only ever over-hides (see module docstring).
                add(EVERYONE_GROUP)
            elif scope == "users":
                for idset in perm.get("grantedToIdentitiesV2") or []:
                    mapped = _map_identity_set(
                        idset,
                        site_id=site_id,
                        tenant_guid=config.tenant_guid,
                        recipient=True,
                    )
                    if mapped is _POISON:
                        return AclEnvelope(resolvable=False)
                    for principal in mapped:
                        add(principal)
            elif scope == "existingAccess":
                continue  # grants no extra privilege (d4)
            else:
                return AclEnvelope(resolvable=False)  # unknown link scope (G4)
            continue
        granted = perm.get("grantedToV2")
        if granted is not None:
            mapped = _map_identity_set(
                granted,
                site_id=site_id,
                tenant_guid=config.tenant_guid,
                recipient=False,
            )
            if mapped is _POISON:
                return AclEnvelope(resolvable=False)
            for principal in mapped:
                add(principal)
            continue
        if perm.get("invitation") is not None:
            continue  # unredeemed invitation confers nothing yet (row f)
        # Legacy non-V2 grantedTo, or a permission shape we don't recognize:
        # never guess (G4).
        return AclEnvelope(resolvable=False)

    if not config.site_groups_resolvable and any(
        g.startswith("group:sp-site-") for g in groups
    ):
        # Fail-closed default until the SP-REST site-group sync exists (R8):
        # an unexpanded site group can hide an Everyone claim behind it, so the
        # item quarantines rather than mirroring a grant we cannot see into.
        return AclEnvelope(resolvable=False)
    return AclEnvelope(resolvable=True, principals=principals, groups=groups)


# ---------------------------------------------------------------------------
# Principal resolution: aad-oid markers via the entra crosswalk (G2)
# ---------------------------------------------------------------------------


class SharePointRegistry(Protocol):
    """Resolves a typed :class:`crosswalk.ResolveRequest` (canonical principals
    + ``(entra, objectId)`` crosswalk owners) to int visibility tokens."""

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult: ...


class StaticSharePointRegistry:
    """Fixed mapping, from config or fixtures. Keys are canonical principal
    strings (groups, the tenant token) and ``entra:<objectId>`` owner keys.
    Missing keys stay unresolved; ``quarantined`` mirrors the server contract
    (owners declared, none survived)."""

    def __init__(self, mapping: Mapping[str, int]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult:
        mappings: dict[str, int] = {}
        declared_survivor = False
        for principal in request.principals:
            token = self._mapping.get(principal)
            if isinstance(token, int):
                mappings[principal] = token
        for email in request.emails:
            token = self._mapping.get(email)
            if isinstance(token, int):
                mappings[email] = token
                declared_survivor = True
        for owner in request.resolvable:
            token = self._mapping.get(f"{owner.source}:{owner.local_id}")
            if isinstance(token, int):
                mappings[f"{owner.source}:{owner.local_id}"] = token
                declared_survivor = True
        quarantined = request.declared_resolvable() and not declared_survivor
        return crosswalk.ResolveResult(mappings=mappings, quarantined=quarantined)


class HttpSharePointRegistry:
    """Resolves via ``POST /v1/admin/principals`` (crosswalk.resolve_via):
    ``aad-oid:`` markers ride ``resolvable`` as ``(entra, <objectId>)`` owners
    — resolved against the directory_vouched rows the Entra dir-sync writes —
    and group/tenant-token principals ride ``principals`` unchanged. An
    unresolved owner contributes nothing (fail-closed, no blind mint)."""

    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        client: httpx.Client | None = None,
        api_key: str | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=120.0, headers=headers)
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult:
        return crosswalk.resolve_via(self._client, self._base_url, self._tenant_id, request)


# ---------------------------------------------------------------------------
# Graph transport (extends entra's with the byte lane)
# ---------------------------------------------------------------------------


class SharePointTransport(Protocol):
    """entra_directory's GraphTransport surface + ``get_bytes`` for
    ``…/content`` downloads, so tests run on recorded fixtures."""

    def get_json(self, path: str, params: Mapping[str, str]) -> dict: ...

    def get_delta(self, url_or_path: str, params: Mapping[str, str]) -> Iterator[dict]: ...

    def get_bytes(self, path: str, params: Mapping[str, str]) -> bytes: ...


class HttpSharePointTransport(HttpGraphTransport):
    """entra's live Graph transport (bearer auth, 429/Retry-After,
    410→SyncStateReset, nextLink-followed-verbatim) + the byte lane:
    ``…/content`` replies 302 to a pre-authenticated download URL, so
    redirects are followed here and only here."""

    def get_bytes(self, path: str, params: Mapping[str, str]) -> bytes:
        response = self._client.get(
            path,
            params=dict(params) if params else None,
            headers=self._headers(),
            follow_redirects=True,
        )
        response.raise_for_status()
        return response.content


def load_sharepoint_credentials(config: SharePointConfig):
    """BYOT Graph token provider — entra_directory's lazy-msal loader, reused
    (import, don't fork): same app registration, same ENTRA_* env contract,
    Graph audience only. The SharePoint-REST audience the site-group sync
    needs (``https://{tenant}.sharepoint.com/.default``, cert-auth) is a
    separate workstream (R8) and is NOT provisioned here."""
    return load_graph_credentials(
        EntraDirectoryConfig(
            graph_tenant=config.graph_tenant,
            client_id=config.client_id,
            client_secret_file=config.client_secret_file,
            client_cert_file=config.client_cert_file,
        )
    )


# ---------------------------------------------------------------------------
# The connector
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_cursor(cursor: str | None) -> dict:
    if not cursor:
        return {}
    try:
        parsed = json.loads(cursor)
    except ValueError:
        return {}  # unreadable cursor: treated as never-synced (fail closed via SLA)
    return parsed if isinstance(parsed, dict) else {}


class SharePointConnector(Connector):
    name = SOURCE_NAME

    def __init__(
        self,
        transport: SharePointTransport,
        config: SharePointConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport
        self.config = config or SharePointConfig()
        self._clock = clock or _utcnow
        if self.config.anonymous_maps_to:
            print(
                "sharepoint: WARNING: anonymous_maps_to maps PUBLIC-INTERNET "
                f"anonymous links to {self.config.anonymous_maps_to!r} — content "
                "shared to the whole internet will be indexed under an internal "
                "principal. This is a foot-gun; unset it to quarantine instead.",
                file=sys.stderr,
            )
        # Filled by full_crawl for the runner to persist: the terminal deltaLink
        # per drive and the reconcile stamp that satisfies the G3 SLA.
        self.backfill_delta_links: dict[str, str] = {}
        self.backfill_completed_at: str | None = None
        # C3: items with neither a file nor a folder facet are skipped entirely
        # (no body, no content, no permission fetch) — counted here per cycle
        # so the runner can report the skip, never silent.
        self.skipped_nonfile = 0

    # -- push lane ----------------------------------------------------------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op: Graph subscriptions on SPO/ODB drives support only the
        ``updated`` changeType on the drive root and carry NO item detail — a
        notification can only trigger a delta cycle, which poll already is.
        Poll + the reconcile SLA is the truth lane; the subscription receiver
        is a later optimization, never a correctness dependency."""
        return
        yield  # pragma: no cover - makes this an async generator

    # -- G1: per-drive ACL-completeness canary --------------------------------

    def verify_drive_complete(self, drive_id: str) -> bool:
        """Prove the app's permission view of ``drive_id`` is complete (G1/R1).

        The permissions endpoint caller-filters for non-owner identities — a
        partial ACL arrives as a clean 200. The only honest proof is a canary:
        an item whose permission list is KNOWN to contain a specific co-owner
        grant. Expected grant present ⇒ proven. Canary missing, unreadable, or
        the grant absent ⇒ unprovable ⇒ the caller quarantines the drive."""
        if not self.config.require_complete_acl:
            return True
        canary = self.config.canaries.get(drive_id)
        if canary is None:
            return False
        try:
            permissions = self._list_permissions(drive_id, canary.item_id)
        except httpx.HTTPStatusError:
            return False  # canary unreadable: completeness unprovable
        for perm in permissions:
            granted = perm.get("grantedToV2") or {}
            user = granted.get("user") or {}
            if str(user.get("id") or "") == canary.expected_user_oid:
                return True
        return False

    # -- truth lane ----------------------------------------------------------

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """Incremental delta from the per-drive deltaLinks in ``cursor``.

        First run (no saved link for a drive): prime the drive's deltaLink via
        ``root/delta?token=latest`` and emit nothing — enumeration is
        ``full_crawl``'s job (and until a backfill stamps ``last_reconcile_at``
        the G3 SLA holds every polled document in quarantine posture anyway).

        Past-SLA (or never reconciled): document events are FORCED to
        quarantine posture — delta can miss parent-only permission revocations
        (R3), so an un-reconciled window never gets NEWLY indexed as mirrored.
        Quarantine posture and removal markers produce bodies the ingest
        ladder cannot deliver — the runner parks them in the retraction ledger
        and drains it as ``POST /v1/admin/retire`` replays, enforcing the
        retraction at the index; only entries whose replay fails stay parked
        and alarmed (see module docstring, G3)."""
        now = self._clock()
        self.skipped_nonfile = 0
        state = _parse_cursor(cursor)
        drives_state: dict[str, str] = dict(state.get("drives") or {})
        last_reconcile_at = state.get("last_reconcile_at")
        stale = self._stale(last_reconcile_at, now)
        events: list[FactEvent | DocumentEvent] = []
        for site_id in self.config.site_ids:
            for drive in self._list_drives(site_id):
                drive_id = str(drive.get("id") or "")
                if not drive_id:
                    continue
                link = drives_state.get(drive_id)
                if link is None:
                    primed = self._transport.get_json(
                        f"drives/{drive_id}/root/delta", {"token": "latest"}
                    )
                    new_link = primed.get("@odata.deltaLink")
                    if new_link:
                        drives_state[drive_id] = new_link
                    continue
                complete = self.verify_drive_complete(drive_id)
                for page in self._transport.get_delta(link, {}):
                    delta_link = page.get("@odata.deltaLink")
                    if delta_link:
                        drives_state[drive_id] = delta_link
                    for item in page.get("value", []):
                        events.extend(
                            self._poll_item_events(
                                site_id, drive_id, item, complete=complete, stale=stale
                            )
                        )
        next_state = {"drives": drives_state, "last_reconcile_at": last_reconcile_at}
        return events, json.dumps(next_state, sort_keys=True)

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """§5a backfill: per drive, the G1 canary then a tokenless
        ``root/delta`` walk (the only enumeration guaranteed complete under
        concurrent writes) — ACL then content per item. Terminal deltaLinks
        and the reconcile stamp land on ``backfill_delta_links`` /
        ``backfill_completed_at`` for the runner to persist (they satisfy the
        G3 SLA only once the WHOLE crawl finished)."""
        now = self._clock()
        self.backfill_delta_links = {}
        self.backfill_completed_at = None
        self.skipped_nonfile = 0
        for site_id in self.config.site_ids:
            for drive in self._list_drives(site_id):
                drive_id = str(drive.get("id") or "")
                if not drive_id:
                    continue
                complete = self.verify_drive_complete(drive_id)
                link: str | None = None
                for page in self._transport.get_delta(
                    f"drives/{drive_id}/root/delta", {"$top": str(self.config.page_size)}
                ):
                    link = page.get("@odata.deltaLink") or link
                    for item in page.get("value", []):
                        event = self._item_event(site_id, drive_id, item, complete=complete)
                        if event is not None:
                            yield event
                if link:
                    self.backfill_delta_links[drive_id] = link
        self.backfill_completed_at = _iso(now)

    # -- per-item plumbing ---------------------------------------------------

    def _stale(self, last_reconcile_at: Any, now: datetime) -> bool:
        """G3: True when no full backfill completed within the reconcile SLA
        (including never / unparseable — fail closed)."""
        if not last_reconcile_at or not isinstance(last_reconcile_at, str):
            return True
        try:
            then = datetime.fromisoformat(last_reconcile_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        return (now - then) > timedelta(hours=self.config.reconcile_sla_hours)

    def _poll_item_events(
        self,
        site_id: str,
        drive_id: str,
        item: Mapping[str, Any],
        *,
        complete: bool,
        stale: bool,
    ) -> list[SharePointDocumentEvent]:
        """One delta entry → events. A FOLDER surfacing in delta may be the
        only signal of an inheritance-affecting permission change on its
        subtree (R4: children whose only change is an inherited permission do
        not appear themselves), so its children are re-walked with fresh ACL
        reads. The root folder is exempt (it would re-walk the whole drive
        every cycle; root/site-level changes are the reconcile SLA's job)."""
        if item.get("deleted") is not None:
            event = self._item_event(site_id, drive_id, item, complete=complete)
            return [event] if event is not None else []
        if item.get("folder") is not None or item.get("root") is not None:
            if item.get("root") is not None:
                return []
            events: list[SharePointDocumentEvent] = []
            folder_id = str(item.get("id") or "")
            if folder_id:
                for child in self._list_children(drive_id, folder_id):
                    events.extend(
                        self._poll_item_events(
                            site_id, drive_id, child, complete=complete, stale=stale
                        )
                    )
            return events
        event = self._item_event(
            site_id, drive_id, item, complete=complete, force_quarantine=stale
        )
        return [event] if event is not None else []

    def _item_event(
        self,
        site_id: str,
        drive_id: str,
        item: Mapping[str, Any],
        *,
        complete: bool,
        force_quarantine: bool = False,
    ) -> SharePointDocumentEvent | None:
        item_id = str(item.get("id") or "")
        if not item_id:
            return None
        # m4: item ids are drive-scoped — the drive prefix is load-bearing.
        document_id = f"{drive_id}:{item_id}"
        modified = str(item.get("lastModifiedDateTime") or "")
        if item.get("deleted") is not None:
            return SharePointDocumentEvent(
                source=self.name,
                document_id=document_id,
                content=b"",
                mime_type="",
                version="",
                acl=AclEnvelope(resolvable=True),  # nothing indexed; grants nothing
                modified_time=modified,
                removed=True,
            )
        if item.get("folder") is not None or item.get("root") is not None:
            return None  # folders are containers, not documents
        if item.get("file") is None:
            # C3: neither file nor folder facet (a package, or an item kind we
            # don't recognize): skip ENTIRELY — no permission fetch, no
            # content, no sink body. Counted for the runner's report.
            self.skipped_nonfile += 1
            return None
        name = str(item.get("name") or "")
        mime = str((item.get("file") or {}).get("mimeType") or "")
        version = str(item.get("eTag") or "")
        if not complete or force_quarantine:
            # G1 (drive unproven) / G3 (past-SLA): quarantine posture. ACL-
            # before-content — neither permissions nor bytes are fetched (a
            # caller-filtered permission read would be unusable anyway).
            return SharePointDocumentEvent(
                source=self.name,
                document_id=document_id,
                content=b"",
                mime_type=mime,
                version=version,
                acl=AclEnvelope(resolvable=False),
                modified_time=modified,
                name=name,
            )
        try:
            raw_permissions = self._list_permissions(drive_id, item_id)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                # We cannot mirror an ACL we cannot read: quarantine, skip
                # content, keep crawling (mirrors gdrive).
                acl = AclEnvelope(resolvable=False)
            else:
                raise
        else:
            acl = map_permissions(raw_permissions, site_id=site_id, config=self.config)
        content = b""
        if acl.resolvable and (is_extractable(mime) or is_binary_extractable(mime)):
            content = self._transport.get_bytes(
                f"drives/{drive_id}/items/{item_id}/content", {}
            )
        return SharePointDocumentEvent(
            source=self.name,
            document_id=document_id,
            content=content,
            mime_type=mime,
            version=version,
            acl=acl,
            modified_time=modified,
            name=name,
        )

    # -- Graph listing -------------------------------------------------------

    def _paged_values(self, path: str, params: Mapping[str, str]) -> list[dict]:
        """Walk ``value`` arrays across ``@odata.nextLink`` pages. Followed
        links go out with empty params (the transport sends params=None —
        never strip a link's own $skiptoken)."""
        values: list[dict] = []
        next_path: str | None = path
        next_params: Mapping[str, str] = params
        while next_path:
            page = self._transport.get_json(next_path, next_params)
            values.extend(page.get("value", []))
            next_path = page.get("@odata.nextLink")
            next_params = {}
        return values

    def _list_drives(self, site_id: str) -> list[dict]:
        return self._paged_values(
            f"sites/{site_id}/drives", {"$top": str(self.config.page_size)}
        )

    def _list_children(self, drive_id: str, item_id: str) -> list[dict]:
        return self._paged_values(
            f"drives/{drive_id}/items/{item_id}/children",
            {"$top": str(self.config.page_size)},
        )

    def _list_permissions(self, drive_id: str, item_id: str) -> list[dict]:
        return self._paged_values(
            f"drives/{drive_id}/items/{item_id}/permissions",
            {"$top": str(self.config.page_size)},
        )


# ---------------------------------------------------------------------------
# Sink bodies: POST /v1/ingest/documents (gdrive's ladder, Microsoft-resolved)
# ---------------------------------------------------------------------------


def build_sharepoint_document_request(
    event: SharePointDocumentEvent, registry: SharePointRegistry, tenant_id: str
) -> dict:
    """Build the ``/v1/ingest/documents`` body for one event.

    Fail-closed ladder (mirrors gdrive's build_document_request):
    - removal marker → ``{"removed": true}`` body;
    - unresolvable envelope → quarantine body (no ``visibility``);
    - resolvable but zero principals resolve to tokens → quarantine (plan row
      a: an objectId with no crosswalk row contributes nothing; all-nothing ⇒
      quarantine, never a blind mint);
    - otherwise → mirrored body with sorted int visibility tokens."""
    if event.removed:
        return {
            "tenant_id": tenant_id,
            "source": event.source,
            "document_id": event.document_id,
            "removed": True,
            "valid_from": event.modified_time,
        }

    body: dict[str, Any] = {
        "tenant_id": tenant_id,
        "source": event.source,
        "document_id": event.document_id,
        "entities": list(event.entity_tags),
        "valid_from": event.modified_time,
    }
    if event.acl.resolvable and is_binary_extractable(event.mime_type):
        body["content_base64"] = base64.b64encode(event.content).decode("ascii")
        if event.name:
            body["filename"] = event.name
    else:
        body["content"] = (
            event.content.decode("utf-8", errors="replace")
            if event.acl.resolvable and is_extractable(event.mime_type)
            else None
        )
    if not event.acl.resolvable:
        body["acl_provenance"] = "quarantined"
        return body

    ordered: list[str] = []
    for principal in [*event.acl.principals, *event.acl.groups]:
        if principal not in ordered:
            ordered.append(principal)
    owners, canonical = crosswalk.split_sharepoint_principals(ordered)
    result = registry.resolve(
        crosswalk.ResolveRequest(principals=canonical, resolvable=owners)
    )
    tokens = result.tokens()
    if not tokens:
        body["acl_provenance"] = "quarantined"
        return body
    body["visibility"] = tokens
    body["acl_provenance"] = "mirrored"
    return body


class SharePointStatusSink(VerityDocumentSink):
    """gdrive's :class:`VerityDocumentSink` + entra_directory's fail-closed
    ``alarms[]`` heartbeat pattern (mirrors ``EntraAdminSink``): the runner
    queues alarms via :meth:`record_alarm` (``parked_retraction`` /
    ``delta_reset`` / ``backfill_incomplete``) and they ride the best-effort
    ``POST /v1/admin/connector-status`` body. Unlike the base heartbeat, an
    alarm-bearing heartbeat fires even when ZERO documents were delivered —
    a delta reset or an all-parked cycle that delivered nothing MUST still
    reach the operator. Never raises; drains accumulators in ``finally``."""

    #: Set by the runner so an alarm-only heartbeat (zero delivered docs) can
    #: still key its connector-status row by tenant.
    alarm_tenant_id: str | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._alarms: list[dict[str, str]] = []

    def record_alarm(self, kind: str, detail: str) -> None:
        """Queue one fail-closed alarm for the next heartbeat. ``kind`` is a
        stable machine tag; ``detail`` is a human string (never a secret)."""
        self._alarms.append({"kind": kind, "detail": detail})

    def retire(self, request: Mapping[str, Any]) -> None:
        """Replay one parked retraction as ``POST /v1/admin/retire`` (module
        docstring, G3): the server closes the document's current chunks
        (``valid_to`` + blanked visibility), enforcing the retraction at the
        index. Same client + admin bearer as :meth:`deliver`. Raises on
        non-2xx — the drain keeps the entry parked and re-alarms; a replay of
        an already-retired document is a 2xx with ``chunks_retired: 0``."""
        response = self._client.post(f"{self._base_url}{RETIRE_PATH}", json=dict(request))
        response.raise_for_status()

    def heartbeat(self, cursor: str | None = None) -> None:
        alarms = list(self._alarms)
        self._alarms = []
        if not alarms:
            super().heartbeat(cursor)
            return
        tenant = self._tenant_id or self.alarm_tenant_id
        if not tenant:
            self._delivered = 0
            self._last_event_at = None
            return
        try:
            body: dict[str, Any] = {
                "tenant_id": tenant,
                "source": SOURCE_NAME,
                "items_synced": self._delivered,
                "alarms": alarms,
            }
            if cursor is not None:
                body["cursor"] = cursor
            if self._last_event_at:
                body["last_event_at"] = self._last_event_at
            self._client.post(f"{self._base_url}{CONNECTOR_STATUS_PATH}", json=body)
        except Exception:  # noqa: BLE001 — telemetry only
            pass
        finally:
            self._delivered = 0
            self._last_event_at = None


# ---------------------------------------------------------------------------
# Parked-retractions ledger (L1) + the /v1/admin/retire drain that empties it
# ---------------------------------------------------------------------------


def _ledger_path(state_file: Path) -> Path:
    """The parked-retractions ledger lives NEXT TO the cursor state so the two
    travel together (same .verity/ dir, same backup/rotation story)."""
    return state_file.with_name("sharepoint_parked_retractions.json")


def _park_retractions(
    state_file: Path, entries: Sequence[Mapping[str, str]], now_iso: str
) -> tuple[int, Path]:
    """Persist detected retractions pending their ``/v1/admin/retire`` replay
    (module docstring, G3) — the drain (:func:`_drain_parked_retractions`)
    runs right after parking, so an entry normally lives here only for the
    instant between detection and its 2xx replay; it PERSISTS across cycles
    only while the replay keeps failing (server down, refused body).

    Each entry carries ``{drive_id, item_id, document_id, reason}``; the ledger
    dedups by ``document_id`` (a permanently-quarantined item that resurfaces
    every cycle updates ``last_seen``/``reason``, it does not grow the file —
    the no-livelock design). Returns ``(total_outstanding, ledger_path)`` —
    with no new entries it just counts, so the heartbeat alarm keeps firing
    while anything is still parked. An unparseable ledger is moved aside to
    ``*.corrupt``, never silently overwritten (the signal must not be lost)."""
    path = _ledger_path(state_file)
    ledger: list[dict] = []
    if path.exists():
        try:
            raw = json.loads(path.read_text())
        except ValueError:
            path.replace(path.with_name(path.name + ".corrupt"))
        else:
            if isinstance(raw, list):
                ledger = [e for e in raw if isinstance(e, dict)]
    if not entries:
        return len(ledger), path
    by_document = {str(e.get("document_id")): e for e in ledger}
    for entry in entries:
        existing = by_document.get(entry["document_id"])
        if existing is not None:
            existing["last_seen"] = now_iso
            existing["reason"] = entry["reason"]
            continue
        record = dict(entry)
        record["first_seen"] = now_iso
        record["last_seen"] = now_iso
        ledger.append(record)
        by_document[record["document_id"]] = record
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    return len(ledger), path


def _parked_entry(event: SharePointDocumentEvent, body: Mapping[str, Any]) -> dict[str, str]:
    drive_id, _, item_id = event.document_id.partition(":")
    return {
        "drive_id": drive_id,
        "item_id": item_id,
        "document_id": event.document_id,
        "reason": "removed" if body.get("removed") else "quarantined",
    }


def _unpark_delivered(state_file: Path, document_ids: set[str]) -> int:
    """Remove parked entries for documents successfully DELIVERED this cycle —
    the other half of the over-retire-race guard: a 2xx delivery is strictly
    NEWER evidence than any still-parked retraction signal for the same
    document (the park predates the poll window that restored it). Left in
    place, a later drain would replay the STALE ``removed``/``quarantined``
    entry and blank the chunks the delivery just wrote. Returns the number of
    entries removed."""
    if not document_ids:
        return 0
    path = _ledger_path(state_file)
    if not path.exists():
        return 0
    try:
        raw = json.loads(path.read_text())
    except ValueError:
        return 0  # corrupt-ledger handling (move-aside) is _park_retractions' job
    ledger = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
    remaining = [e for e in ledger if str(e.get("document_id")) not in document_ids]
    if len(remaining) != len(ledger):
        path.write_text(json.dumps(remaining, indent=2, sort_keys=True) + "\n")
    return len(ledger) - len(remaining)


def _drain_parked_retractions(
    state_file: Path, sink: DocumentSink, tenant_id: str
) -> tuple[int, int]:
    """Replay EVERY parked-retractions ledger entry as ``POST /v1/admin/retire``
    ``{tenant_id, source, document_id, reason}`` — the enforcement half (module
    docstring, G3): the server closes the document's current chunks, so the
    retraction takes effect on the next read. Any 2xx (including the
    idempotent ``chunks_retired: 0`` replay) removes the entry from the
    ledger; any failure keeps it parked for the next cycle — the alarm then
    counts only what remains. Sinks without a ``retire`` transport (dry-run,
    capture-only fixtures) drain nothing: every entry stays parked and
    alarmed, never silently dropped. Returns ``(outstanding, drained)``."""
    path = _ledger_path(state_file)
    if not path.exists():
        return 0, 0
    try:
        raw = json.loads(path.read_text())
    except ValueError:
        return 0, 0  # corrupt-ledger handling (move-aside) is _park_retractions' job
    ledger = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
    retire = getattr(sink, "retire", None)
    if not ledger or not callable(retire):
        return len(ledger), 0
    remaining: list[dict] = []
    for entry in ledger:
        body = {
            "tenant_id": tenant_id,
            "source": SOURCE_NAME,
            "document_id": str(entry.get("document_id") or ""),
            "reason": str(entry.get("reason") or ""),
        }
        try:
            retire(body)
        except Exception:  # noqa: BLE001 — deliberately broad, see below
            # ANY replay failure — transport (httpx), auth, an unexpected
            # response shape, even a sink bug — keeps the entry parked and
            # alarmed, never crashes the drain. The ledger is the ONLY
            # carrier of a detected retraction once the delta cursor has
            # advanced past it: under the old httpx-only catch a non-HTTP
            # exception aborted the whole cycle mid-drain (no checkpoint, no
            # parked_retraction alarm, no heartbeat), leaving the operator
            # blind to unenforced retractions. Fail closed; retried next
            # cycle.
            remaining.append(entry)
    if len(remaining) != len(ledger):
        path.write_text(json.dumps(remaining, indent=2, sort_keys=True) + "\n")
    return len(remaining), len(ledger) - len(remaining)


def _alarm_parked(sink: DocumentSink, total: int, ledger_path: Path) -> None:
    """Alarm the outstanding (post-drain) parked-retraction count on sinks that
    support the alarms[] heartbeat (best-effort on others — the ledger is the
    durable signal either way). An empty ledger alarms nothing."""
    record_alarm = getattr(sink, "record_alarm", None)
    if total and callable(record_alarm):
        record_alarm(
            "parked_retraction",
            f"{total} detected retraction(s) parked — the {RETIRE_PATH} replay "
            f"failed or is unavailable on this sink, so the content is NOT yet "
            f"removed from the index; retried next cycle; ledger: {ledger_path}",
        )


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.sharepoint --once|--backfill
# ---------------------------------------------------------------------------


def _load_cursor(state_file: Path) -> str | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text()).get("cursor")


def _save_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"cursor": cursor}, indent=2) + "\n")


def run_once(
    connector: SharePointConnector,
    registry: SharePointRegistry,
    sink: DocumentSink,
    state_file: Path,
) -> int:
    """One poll cycle: load cursor, poll, deliver, checkpoint, drain.

    Retraction bodies the ingest ladder cannot deliver — removal markers and
    quarantined bodies — are PARKED in the retraction ledger, then the whole
    ledger is DRAINED as ``POST /v1/admin/retire`` replays (enforced at the
    index, next read); entries whose replay fails stay parked + alarmed,
    never silently dropped. ORDER is load-bearing (the over-retire race): the
    PRE-EXISTING ledger drains BEFORE this cycle's deliveries, and a
    successful delivery UNPARKS any older entry for its document_id — a
    parked signal is strictly older than the delivery, so replaying it after
    would blank the just-written chunks of a restored document. The cursor
    still advances (holding it back would livelock on permanently-quarantined
    items — the ledger, not the cursor, carries the signal until its replay
    lands). A :class:`SyncStateReset` (expired/invalidated deltaLink)
    discards the cursor WITHOUT checkpointing, still drains the pre-existing
    ledger (its replays do not depend on the cursor), alarms ``delta_reset``
    (plus ``parked_retraction`` for the post-drain remainder) on one
    heartbeat, and re-raises — a full ``--backfill`` is REQUIRED to re-narrow
    visibility; until it runs, previously-indexed items keep serving (the
    honest statement of the G3 limit)."""
    cursor = _load_cursor(state_file)
    try:
        events, next_cursor = asyncio.run(connector.poll(cursor))
    except SyncStateReset:
        if state_file.exists():
            state_file.unlink()
        # A reset cycle must still ENFORCE what is already parked: the
        # ledger predates the lost delta window and its retire replays are
        # independent of the cursor. Whatever remains after the drain rides
        # THIS heartbeat — otherwise the operator sees "reset" with no hint
        # that detected retractions are still unenforced.
        total_parked, _ = _drain_parked_retractions(
            state_file, sink, connector.config.tenant_id
        )
        _alarm_parked(sink, total_parked, _ledger_path(state_file))
        record_alarm = getattr(sink, "record_alarm", None)
        if callable(record_alarm):
            record_alarm(
                "delta_reset",
                "delta token invalidated (410/syncStateNotFound); cursor "
                "discarded — a full --backfill is REQUIRED to re-narrow "
                "visibility (previously-indexed items keep serving until it runs)",
            )
            heartbeat = getattr(sink, "heartbeat", None)
            if heartbeat is not None:
                heartbeat()
        raise
    # THE RACE, guard #1: drain the PRE-EXISTING ledger BEFORE delivering.
    # A parked entry is strictly older than anything this cycle delivers, so
    # its replay must land on the OLD index state — drained after delivery it
    # would blank the fresh chunks of a document this cycle just restored.
    _, pre_drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    delivered = 0
    delivered_ids: set[str] = set()
    parked: list[dict[str, str]] = []
    for event in events:
        assert isinstance(event, SharePointDocumentEvent)
        body = build_sharepoint_document_request(event, registry, connector.config.tenant_id)
        if not _is_indexable_body(body):
            # L1: an undeliverable retraction signal — park it, never drop it.
            parked.append(_parked_entry(event, body))
            delivered_ids.discard(event.document_id)  # in-stream, the park is newer
            continue
        sink.deliver(body)
        delivered += 1
        delivered_ids.add(event.document_id)
        # In-stream order is truth order: this delivery supersedes any
        # EARLIER same-cycle park for the same document.
        parked = [p for p in parked if p["document_id"] != event.document_id]
    # THE RACE, guard #2: a successful delivery is strictly newer than any
    # entry still parked for the same document (e.g. guard #1's replay failed
    # and the entry survived) — unpark it, or a later drain replays the STALE
    # retraction over the chunks just written.
    _unpark_delivered(state_file, delivered_ids)
    total_parked, ledger_path = _park_retractions(
        state_file, parked, _iso(connector._clock())
    )
    total_parked, drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    drained += pre_drained
    if parked or drained:
        print(
            f"sharepoint: parked {len(parked)} retraction signal(s) this cycle; "
            f"drained {drained} via POST {RETIRE_PATH}; "
            f"{total_parked} still parked -> {ledger_path}"
        )
    if connector.skipped_nonfile:
        print(
            f"sharepoint: skipped {connector.skipped_nonfile} item(s) with "
            "neither file nor folder facet"
        )
    _save_cursor(state_file, next_cursor)
    _alarm_parked(sink, total_parked, ledger_path)
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=next_cursor)
    return delivered


def run_backfill(
    connector: SharePointConnector,
    registry: SharePointRegistry,
    sink: DocumentSink,
    state_file: Path,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 20,
) -> int:
    """§5a backfill: drive :meth:`SharePointConnector.full_crawl` into the
    sink, then persist the per-drive deltaLinks AND the ``last_reconcile_at``
    stamp — the stamp lands ONLY after a COMPLETE crawl with ZERO ingest
    failures (L2: a crashed OR partially-failed backfill re-proved nothing;
    with failures the prior stamp — possibly none — is carried unchanged and
    ``backfill_incomplete`` is alarmed). Retraction bodies the ingest ladder
    cannot deliver (removal markers, quarantined items) are parked in the
    retraction ledger, then drained as ``POST /v1/admin/retire`` replays —
    enforced at the index; failed replays stay parked + alarmed, never
    silently dropped. Same over-retire-race ordering as :func:`run_once`:
    the pre-existing ledger drains BEFORE the crawl delivers, and a
    successful delivery unparks any older entry for its document_id (module
    docstring, G3)."""
    if reporter is not None:
        reporter.start(total=None)
    # THE RACE, guard #1 (same as run_once): the PRE-EXISTING ledger drains
    # BEFORE the crawl delivers anything — a parked entry is strictly older
    # than this backfill's writes and must never blank them.
    _, pre_drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    delivered = 0
    pending = 0
    failed = 0
    delivered_ids: set[str] = set()
    parked: list[dict[str, str]] = []

    async def _drive() -> None:
        nonlocal delivered, pending, failed
        async for event in connector.full_crawl():
            assert isinstance(event, SharePointDocumentEvent)
            body = build_sharepoint_document_request(
                event, registry, connector.config.tenant_id
            )
            if not _is_indexable_body(body):
                # L1: an undeliverable retraction signal — park it, never drop it.
                parked.append(_parked_entry(event, body))
                delivered_ids.discard(event.document_id)  # in-stream, the park is newer
                continue
            try:
                sink.deliver(body)
            except httpx.HTTPError:
                failed += 1  # one bad document never aborts a whole-drive backfill
                continue
            delivered += 1
            delivered_ids.add(event.document_id)
            # In-stream order is truth order: this delivery supersedes any
            # EARLIER same-crawl park for the same document.
            parked[:] = [p for p in parked if p["document_id"] != event.document_id]
            pending += 1
            if reporter is not None and pending >= flush_every:
                reporter.advance(pending)
                pending = 0

    try:
        asyncio.run(_drive())
    except Exception as exc:  # noqa: BLE001 — surface as a failed run, then re-raise
        if reporter is not None:
            if pending:
                reporter.advance(pending)
            reporter.fail(exc)
        raise
    if reporter is not None:
        if pending:
            reporter.advance(pending)
        reporter.finish()
    # THE RACE, guard #2 (same as run_once): deliveries are strictly newer
    # than any still-parked entry for the same document — unpark before the
    # post-crawl park + drain.
    _unpark_delivered(state_file, delivered_ids)
    total_parked, ledger_path = _park_retractions(
        state_file, parked, _iso(connector._clock())
    )
    total_parked, drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    drained += pre_drained
    if parked or drained or failed:
        print(
            f"sharepoint: parked {len(parked)} retraction signal(s); "
            f"drained {drained} via POST {RETIRE_PATH} "
            f"({total_parked} still parked -> {ledger_path}), "
            f"{failed} ingest failure(s)"
        )
    if connector.skipped_nonfile:
        print(
            f"sharepoint: skipped {connector.skipped_nonfile} item(s) with "
            "neither file nor folder facet"
        )
    record_alarm = getattr(sink, "record_alarm", None)
    saved_cursor: str | None = None
    if connector.backfill_completed_at:
        if failed == 0:
            stamp: Any = connector.backfill_completed_at
        else:
            # L2: ingest failures mean the crawl did NOT re-prove the index —
            # carry the prior stamp (possibly none: the SLA then fails closed).
            stamp = _parse_cursor(_load_cursor(state_file)).get("last_reconcile_at")
            if callable(record_alarm):
                record_alarm(
                    "backfill_incomplete",
                    f"{failed} ingest failure(s); last_reconcile_at NOT stamped "
                    "— the reconcile SLA stays unmet until a zero-failure "
                    "backfill completes",
                )
        saved_cursor = json.dumps(
            {
                "drives": connector.backfill_delta_links,
                "last_reconcile_at": stamp,
            },
            sort_keys=True,
        )
        _save_cursor(state_file, saved_cursor)
    _alarm_parked(sink, total_parked, ledger_path)
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=saved_cursor)
    return delivered


def _load_canaries(path: Path | None) -> dict[str, DriveCanary]:
    """Canary config file: ``{"<driveId>": {"item_id": "...",
    "expected_user_oid": "<Entra objectId GUID>"}, ...}``."""
    if path is None:
        return {}
    raw = json.loads(path.read_text())
    return {
        drive_id: DriveCanary(
            item_id=str(spec["item_id"]),
            expected_user_oid=str(spec["expected_user_oid"]),
        )
        for drive_id, spec in raw.items()
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.sharepoint",
        description="Verity SharePoint Online / OneDrive-for-Business connector "
        "(rung-1 mirrored per-item grants, fail-closed).",
    )
    parser.add_argument("--once", action="store_true", help="run a single poll cycle and exit")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the full per-drive delta backfill (stamps the reconcile SLA), then exit",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print request bodies instead of POSTing"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("SHAREPOINT_STATE_FILE", ".verity/sharepoint_cursor.json")),
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url", default=os.environ.get("VERITY_URL", "http://localhost:8080")
    )
    parser.add_argument(
        "--principal-map",
        type=Path,
        default=None,
        help="JSON file {principal-or-'entra:<oid>': int token} -> StaticSharePointRegistry",
    )
    parser.add_argument(
        "--site-ids",
        default=os.environ.get("SHAREPOINT_SITE_IDS", ""),
        help="comma-separated Graph site ids to crawl (Sites.Selected posture)",
    )
    parser.add_argument(
        "--tenant-guid",
        default=os.environ.get("SHAREPOINT_TENANT_GUID"),
        help="Entra tenant GUID anchoring the spo-grid-all-users claim; unset ⇒ "
        "the 'everyone except external' claim poisons (never guessed)",
    )
    parser.add_argument(
        "--canaries-file",
        type=Path,
        default=(
            Path(os.environ["SHAREPOINT_CANARIES_FILE"])
            if os.environ.get("SHAREPOINT_CANARIES_FILE")
            else None
        ),
        help="JSON {driveId: {item_id, expected_user_oid}} — the G1 completeness "
        "canaries; a drive without one is quarantined wholesale",
    )
    parser.add_argument(
        "--reconcile-sla-hours",
        type=int,
        default=int(os.environ.get("SHAREPOINT_RECONCILE_SLA_HOURS", "24")),
    )
    parser.add_argument(
        "--interval", type=float, default=300.0, help="poll interval in seconds (without --once)"
    )
    args = parser.parse_args(argv)

    config = SharePointConfig(
        tenant_id=args.tenant_id,
        graph_tenant=os.environ.get("ENTRA_TENANT_ID"),
        client_id=os.environ.get("ENTRA_CLIENT_ID"),
        client_secret_file=os.environ.get("ENTRA_CLIENT_SECRET_FILE"),
        client_cert_file=os.environ.get("ENTRA_CLIENT_CERT_FILE"),
        site_ids=[s.strip() for s in args.site_ids.split(",") if s.strip()],
        tenant_guid=args.tenant_guid,
        anonymous_maps_to=os.environ.get("SHAREPOINT_ANONYMOUS_MAPS_TO"),
        canaries=_load_canaries(args.canaries_file),
        reconcile_sla_hours=args.reconcile_sla_hours,
    )
    token_provider = load_sharepoint_credentials(config)
    connector = SharePointConnector(HttpSharePointTransport(token_provider), config)

    api_key = os.environ.get("VERITY_API_KEY")
    registry: SharePointRegistry
    if args.principal_map:
        registry = StaticSharePointRegistry(json.loads(args.principal_map.read_text()))
    else:
        registry = HttpSharePointRegistry(
            args.verity_url, tenant_id=config.tenant_id, api_key=api_key
        )
    sink: DocumentSink
    if args.dry_run:
        sink = DryRunSink()
    else:
        status_sink = SharePointStatusSink(args.verity_url, api_key=api_key)
        # Alarm-only heartbeats (e.g. a delta_reset that delivered nothing)
        # still need a tenant to key their connector-status row.
        status_sink.alarm_tenant_id = config.tenant_id
        sink = status_sink

    if args.backfill:
        run_id = os.environ.get("VERITY_BACKFILL_RUN_ID") or None
        reporter = (
            None
            if args.dry_run
            else BackfillReporter(
                args.verity_url, config.tenant_id, connector.name, api_key=api_key, run_id=run_id
            )
        )
        delivered = run_backfill(connector, registry, sink, args.state_file, reporter)
        print(f"sharepoint: backfill delivered {delivered} request(s)")
        return 0

    while True:
        try:
            delivered = run_once(connector, registry, sink, args.state_file)
        except SyncStateReset:
            print(
                "sharepoint: delta token invalidated — cursor discarded; a full "
                "--backfill is REQUIRED to re-narrow visibility (previously-"
                "indexed items keep serving until it runs; alarmed as delta_reset)"
            )
            if args.once:
                return 1
            time.sleep(args.interval)
            continue
        print(f"sharepoint: delivered {delivered} request(s); cursor -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
