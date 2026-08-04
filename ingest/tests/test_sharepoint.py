"""SharePoint Online / OneDrive-for-Business connector conformance tests.

All Graph payloads are recorded fixtures authored from the documented Graph
v1.0 response shapes (sites/{id}/drives, drives/{id}/root/delta,
drives/{id}/items/{id}/permissions, sharePointIdentitySet, sharingLink). No
live API calls and no credentials anywhere in this file (msal is never
imported; the fixture transport short-circuits load_sharepoint_credentials).

The suite exercises the red-teamed LEAK cases, not just happy paths:

- every ACL-table row incl. BOTH tenant-token claims (spo-grid-all-users
  anchored to the tenant GUID; plain "Everyone" always poison, no override);
- anonymous link ⇒ quarantine; unknown link scope ⇒ poison; site-group grant
  ⇒ fail-closed by default (R8);
- G1/R1: a caller-filtered 200 (the canary co-owner grant missing from the
  permissions response) quarantines the WHOLE drive — no per-item permission
  or content fetches at all; a drive with no canary is equally unprovable;
- G2/R2: a direct user grant missing its Entra objectId poisons; a link
  recipient missing it is dropped (and a sole dropped recipient quarantines
  via zero tokens); a loginName — parseable or not — is NEVER an identity key;
- G3: past-SLA (or never-reconciled) polls are forced to quarantine posture
  for NEW indexing — and a detected retraction (a removal marker, a
  mirrored→quarantined transition) produces NO documents-endpoint op: it is
  PARKED in the retraction ledger, then DRAINED as a byte-exact POST
  /v1/admin/retire replay (enforced at the index, next read). The suite
  asserts a 2xx empties the ledger + clears the alarm, a failed replay stays
  parked + alarmed, a re-detected document re-parks and re-drains safely
  (idempotent server), and a sink WITHOUT the retire transport (dry-run /
  capture-only) keeps everything parked + alarmed, never silently consumed
  by the advancing delta cursor. A delta reset still loses the window's
  retraction signal until a full re-backfill re-detects it;
- L2: a backfill with ingest failures must NOT stamp last_reconcile_at and
  must alarm backfill_incomplete;
- C1: roles outside the confers-read allowlist — or empty/missing — poison;
- C3: an item with neither file nor folder facet is skipped entirely;
- C4: the spo-grid-all-users claim is PREFIX-anchored (a lookalike loginName
  that merely embeds the marker must not mint the tenant token), and the
  crosswalk's entra source string cannot drift from the directory sync's
  SOURCE_NAME;
- R1 partial-response modeling: the permissions endpoint pages via
  @odata.nextLink and the follow-up link is fetched with EMPTY params (never
  re-sent query that would strip the $skiptoken).
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
from datetime import datetime, timezone

import httpx
import pytest

from verity_ingest import crosswalk
from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.entra_directory import (
    EVERYONE_GROUP,
    SOURCE_NAME as ENTRA_SOURCE_NAME,
    group_principal as entra_group_principal,
)
from verity_ingest.connectors.sharepoint import (
    RETIRE_PATH,
    DriveCanary,
    HttpSharePointRegistry,
    SharePointConfig,
    SharePointConnector,
    SharePointDocumentEvent,
    SharePointStatusSink,
    StaticSharePointRegistry,
    SyncStateReset,
    build_sharepoint_document_request,
    map_permissions,
    run_backfill,
    run_once,
    site_group_principal,
)
from verity_ingest.connectors.gdrive import DryRunSink

TENANT = "t-contoso"
SITE = "contoso.sharepoint.com,1111aaaa-1111-4111-8111-111111111111,2222bbbb"
TENANT_GUID = "31a2f861-4444-4d55-9c88-aaaaaaaaaaaa"

DRIVE = "b!driveGOOD"
DRIVE_BAD = "b!driveFILTERED"

ALICE_OID = "00000000-0000-0000-0000-00000000a11c"
BOB_OID = "00000000-0000-0000-0000-00000000b0b0"
OWNER_OID = "00000000-0000-0000-0000-0000000c0c0c"  # the planted G1 canary co-owner
ENG_GID = "10000000-0000-0000-0000-0000000000e2"

ENG = entra_group_principal(ENG_GID)  # group:entra-group-<oid> — the weld, by import
ALICE = f"{crosswalk.AAD_OID_PREFIX}{ALICE_OID}"

DELTA_LINK = f"https://graph.microsoft.com/v1.0/drives/{DRIVE}/root/delta?token=abc"
NEW_DELTA_LINK = f"https://graph.microsoft.com/v1.0/drives/{DRIVE}/root/delta?token=def"
THIRD_DELTA_LINK = f"https://graph.microsoft.com/v1.0/drives/{DRIVE}/root/delta?token=ghi"
BAD_DELTA_LINK = f"https://graph.microsoft.com/v1.0/drives/{DRIVE_BAD}/root/delta?token=bad"
PERM_PAGE2 = (
    f"https://graph.microsoft.com/v1.0/drives/{DRIVE}/items/item-notes/permissions"
    "?$skiptoken=page2"
)

PDF_BYTES = b"%PDF-1.7 tiny report stand-in bytes"

REGISTRY_MAP = {
    f"entra:{ALICE_OID}": 101,  # the (entra, objectId) directory_vouched crosswalk row
    ENG: 202,
    EVERYONE_GROUP: 303,
}

_CLOCK_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)


def _clock() -> datetime:
    return _CLOCK_NOW


# ---------------------------------------------------------------------------
# Permission fixture builders (Graph v1.0 shapes)
# ---------------------------------------------------------------------------


def _user_grant(oid: str, upn: str = "alice@contoso.com") -> dict:
    # Real tenants return BOTH facets; the siteUser.loginName rides along so
    # every user-grant test also proves the loginName is never consulted when
    # the immutable objectId is present.
    return {
        "id": "perm-user",
        "roles": ["write"],
        "grantedToV2": {
            "user": {"id": oid, "displayName": "Some User"},
            "siteUser": {"id": "6", "loginName": f"i:0#.f|membership|{upn}"},
        },
    }


def _group_grant(gid: str) -> dict:
    return {
        "id": "perm-group",
        "roles": ["read"],
        "grantedToV2": {"group": {"id": gid, "displayName": "Engineering"}},
    }


def _site_group_grant(principal_id: str = "5") -> dict:
    return {
        "id": "perm-sitegroup",
        "roles": ["read"],
        "grantedToV2": {
            "siteGroup": {
                "id": principal_id,
                "displayName": "Contoso Members",
                "loginName": "Contoso Members",
            }
        },
    }


def _link(scope: str, identities: list[dict] | None = None) -> dict:
    perm: dict = {
        "id": f"perm-link-{scope}",
        "roles": ["read"],
        "link": {"scope": scope, "type": "view", "webUrl": "https://contoso.sharepoint.com/x"},
    }
    if identities is not None:
        perm["grantedToIdentitiesV2"] = identities
    return perm


def _everyone_except_external(guid: str) -> dict:
    return {
        "id": "perm-eee",
        "roles": ["read"],
        "grantedToV2": {
            # The real shape: the claim lives on siteUser.loginName; the user
            # facet has a display name but NO id — must not poison.
            "siteUser": {
                "id": "4",
                "loginName": f"c:0-.f|rolemanager|spo-grid-all-users/{guid}",
                "displayName": "Everyone except external users",
            },
            "user": {"displayName": "Everyone except external users"},
        },
    }


def _plain_everyone() -> dict:
    return {
        "id": "perm-everyone",
        "roles": ["read"],
        "grantedToV2": {
            "siteUser": {"id": "3", "loginName": "c:0(.s|true", "displayName": "Everyone"}
        },
    }


def _cfg(**overrides) -> SharePointConfig:
    defaults: dict = dict(
        tenant_id=TENANT,
        site_ids=[SITE],
        tenant_guid=TENANT_GUID,
        canaries={
            DRIVE: DriveCanary(item_id="canary-item", expected_user_oid=OWNER_OID),
            DRIVE_BAD: DriveCanary(item_id="canary-bad", expected_user_oid=OWNER_OID),
        },
    )
    defaults.update(overrides)
    return SharePointConfig(**defaults)


def _map(perms: list[dict], **cfg_overrides) -> AclEnvelope:
    return map_permissions(perms, site_id=SITE, config=_cfg(**cfg_overrides))


# ---------------------------------------------------------------------------
# ACL mapping conformance — the plan's table, row by row (fail-closed)
# ---------------------------------------------------------------------------


def test_user_grant_keys_on_entra_object_id_only():
    envelope = _map([_user_grant(ALICE_OID)])
    assert envelope == AclEnvelope(resolvable=True, principals=[ALICE], groups=[])
    # G2/R2: the sibling loginName UPN appears NOWHERE in the envelope.
    assert not any("contoso.com" in p for p in envelope.principals + envelope.groups)


def test_entra_group_grant_welds_to_directory_sync_naming():
    envelope = _map([_group_grant(ENG_GID)])
    # The principal string is entra_directory.group_principal BY IMPORT — the
    # grant welds to the synced graph, never by string coincidence.
    assert envelope == AclEnvelope(resolvable=True, principals=[], groups=[ENG])
    assert ENG == f"group:entra-group-{ENG_GID}"


def test_site_group_grant_fails_closed_by_default():
    # R8: site-group membership needs the SP-REST audience (not built) — an
    # unexpanded site group can hide an Everyone claim, so the ITEM quarantines
    # even when other resolvable grants are present.
    assert _map([_site_group_grant()]) == AclEnvelope(resolvable=False)
    assert _map([_user_grant(ALICE_OID), _site_group_grant()]) == AclEnvelope(resolvable=False)


def test_site_group_grant_emits_site_scoped_principal_when_resolvable():
    envelope = _map([_site_group_grant("5")], site_groups_resolvable=True)
    assert envelope == AclEnvelope(
        resolvable=True, principals=[], groups=[site_group_principal(SITE, "5")]
    )
    assert site_group_principal(SITE, "5") == f"group:sp-site-{SITE}-5"


def test_anonymous_link_quarantines_even_alongside_real_grants():
    assert _map([_link("anonymous")]) == AclEnvelope(resolvable=False)
    # A public-internet link poisons the WHOLE item — never partial-emit.
    assert _map([_user_grant(ALICE_OID), _link("anonymous")]) == AclEnvelope(resolvable=False)


def test_anonymous_maps_to_is_an_explicit_foot_gun():
    envelope = _map([_link("anonymous")], anonymous_maps_to="org:everyone")
    assert envelope == AclEnvelope(resolvable=True, principals=[], groups=["org:everyone"])


def test_organization_link_maps_to_guest_excluded_tenant_token():
    envelope = _map([_link("organization")])
    assert envelope == AclEnvelope(resolvable=True, principals=[], groups=[EVERYONE_GROUP])
    assert EVERYONE_GROUP == "group:entra-everyone-except-guests"


def test_users_link_enumerates_recipients():
    identities = [
        {"user": {"id": ALICE_OID, "displayName": "Alice"}},
        {"group": {"id": ENG_GID, "displayName": "Engineering"}},
    ]
    envelope = _map([_link("users", identities)])
    assert envelope == AclEnvelope(resolvable=True, principals=[ALICE], groups=[ENG])


def test_existing_access_link_confers_nothing():
    envelope = _map([_user_grant(ALICE_OID), _link("existingAccess")])
    assert envelope == AclEnvelope(resolvable=True, principals=[ALICE], groups=[])


def test_unknown_link_scope_poisons_the_item():
    # G4: a scope Graph adds later must never be guessed at — even alongside
    # perfectly mappable grants.
    assert _map([_user_grant(ALICE_OID), _link("blanketShare")]) == AclEnvelope(resolvable=False)


def test_everyone_except_external_claim_maps_when_tenant_anchored():
    envelope = _map([_everyone_except_external(TENANT_GUID)])
    assert envelope == AclEnvelope(resolvable=True, principals=[], groups=[EVERYONE_GROUP])


def test_everyone_except_external_wrong_or_missing_tenant_guid_poisons():
    # R6: the claim is tenant-GUID-anchored, never substring-guessed.
    other_guid = "99999999-9999-4999-8999-999999999999"
    assert _map([_everyone_except_external(other_guid)]) == AclEnvelope(resolvable=False)
    assert _map(
        [_everyone_except_external(TENANT_GUID)], tenant_guid=None
    ) == AclEnvelope(resolvable=False)


def test_plain_everyone_claim_always_poisons_no_override():
    # e1/R6: "Everyone" includes external/anonymous — an internet-exposure
    # claim. No config combination maps it.
    assert _map([_plain_everyone()]) == AclEnvelope(resolvable=False)
    assert _map(
        [_plain_everyone()], anonymous_maps_to="org:everyone", site_groups_resolvable=True
    ) == AclEnvelope(resolvable=False)


def test_unredeemed_invitation_confers_nothing():
    envelope = _map([{"id": "perm-inv", "roles": ["read"], "invitation": {"email": "x@y.com"}}])
    assert envelope == AclEnvelope(resolvable=True, principals=[], groups=[])
    # Sole grant ⇒ zero principals ⇒ the sink body quarantines (zero tokens).
    event = _event(acl=envelope)
    body = build_sharepoint_document_request(
        event, StaticSharePointRegistry(REGISTRY_MAP), TENANT
    )
    assert body["acl_provenance"] == "quarantined"
    assert "visibility" not in body


def test_application_and_device_identities_confer_nothing():
    perms = [
        {"id": "p-app", "roles": ["read"], "grantedToV2": {"application": {"id": "app-1"}}},
        {"id": "p-dev", "roles": ["read"], "grantedToV2": {"device": {"id": "dev-1"}}},
        _user_grant(ALICE_OID),
    ]
    assert _map(perms) == AclEnvelope(resolvable=True, principals=[ALICE], groups=[])


def test_unknown_identity_facet_poisons():
    perms = [{"id": "p-x", "roles": ["read"], "grantedToV2": {"fancyPrincipal": {"id": "9"}}}]
    assert _map(perms) == AclEnvelope(resolvable=False)


def test_legacy_non_v2_granted_to_shape_poisons():
    perms = [
        {"id": "p-legacy", "roles": ["read"], "grantedTo": {"user": {"id": ALICE_OID}}}
    ]
    assert _map(perms) == AclEnvelope(resolvable=False)


def test_direct_user_grant_missing_object_id_poisons():
    # G2 rows a/h: a direct grant with no immutable key cannot be dropped
    # silently (that would mis-mirror the ACL) — the whole item poisons.
    perms = [{"id": "p-noid", "roles": ["read"], "grantedToV2": {"user": {"displayName": "?"}}}]
    assert _map(perms) == AclEnvelope(resolvable=False)


def test_link_recipient_missing_object_id_drops_then_zero_tokens_quarantine():
    # d3: an unresolvable link RECIPIENT is dropped (narrows only)…
    identities = [
        {"user": {"displayName": "No Id"}},
        {"user": {"id": ALICE_OID, "displayName": "Alice"}},
    ]
    envelope = _map([_link("users", identities)])
    assert envelope == AclEnvelope(resolvable=True, principals=[ALICE], groups=[])
    # …and when the dropped recipient was the ONLY grantee, zero principals
    # survive and the sink body quarantines.
    sole = _map([_link("users", [{"user": {"displayName": "No Id"}}])])
    assert sole == AclEnvelope(resolvable=True, principals=[], groups=[])
    body = build_sharepoint_document_request(
        _event(acl=sole), StaticSharePointRegistry(REGISTRY_MAP), TENANT
    )
    assert body["acl_provenance"] == "quarantined"
    assert "visibility" not in body


def test_login_name_is_never_an_identity_key():
    # R2: a bare siteUser (no user facet, no objectId) is never keyed off its
    # loginName — not when it strictly parses as a membership claim, and not
    # when it is the documented bare display-name form.
    strict = [
        {
            "id": "p-su1",
            "roles": ["read"],
            "grantedToV2": {"siteUser": {"id": "7", "loginName": "i:0#.f|membership|bob@contoso.com"}},
        }
    ]
    assert _map(strict) == AclEnvelope(resolvable=False)
    malformed = [
        {
            "id": "p-su2",
            "roles": ["read"],
            "grantedToV2": {"siteUser": {"id": "8", "loginName": "Misty Suarez"}},
        }
    ]
    assert _map(malformed) == AclEnvelope(resolvable=False)


def test_unknown_role_vocabulary_poisons():
    # C1: a role outside the audited confers-read allowlist is a grant whose
    # semantics we cannot mirror — poison, even alongside mappable grants.
    weird = _user_grant(ALICE_OID)
    weird["roles"] = ["manageLists"]
    assert _map([weird]) == AclEnvelope(resolvable=False)
    assert _map([_user_grant(ALICE_OID), weird]) == AclEnvelope(resolvable=False)
    mixed = _group_grant(ENG_GID)
    mixed["roles"] = ["read", "webDesigner"]  # one bad role poisons the item
    assert _map([mixed]) == AclEnvelope(resolvable=False)


def test_roleless_grant_poisons():
    # C1: empty or missing roles on a grant — we cannot know what it confers.
    empty = _user_grant(ALICE_OID)
    empty["roles"] = []
    assert _map([empty]) == AclEnvelope(resolvable=False)
    missing = _group_grant(ENG_GID)
    del missing["roles"]
    assert _map([missing]) == AclEnvelope(resolvable=False)


def test_full_control_role_spellings_stay_within_the_allowlist():
    # The allowlist admits both full-control spellings Graph surfaces (case-
    # insensitive) — full control confers read, so the grant still mirrors.
    owner = _user_grant(ALICE_OID)
    owner["roles"] = ["owner"]
    assert _map([owner]) == AclEnvelope(resolvable=True, principals=[ALICE], groups=[])
    full = _group_grant(ENG_GID)
    full["roles"] = ["sp.Full Control"]
    assert _map([full]) == AclEnvelope(resolvable=True, principals=[], groups=[ENG])
    compact = _group_grant(ENG_GID)
    compact["roles"] = ["fullControl"]
    assert _map([compact]) == AclEnvelope(resolvable=True, principals=[], groups=[ENG])


def test_spo_grid_claim_is_prefix_anchored_not_substring_matched():
    # C4: a lookalike loginName that merely EMBEDS the spo-grid marker (with
    # the CORRECT tenant GUID at the end) must not mint the tenant-wide token
    # — under the old substring match it did. Prefix-anchored, it falls
    # through to the bare-siteUser rule and poisons (fail closed).
    lookalike = {
        "id": "p-fake-grid",
        "roles": ["read"],
        "grantedToV2": {
            "siteUser": {
                "id": "9",
                "loginName": f"i:0#.f|membership|c:0-.f|rolemanager|spo-grid-all-users/{TENANT_GUID}",
            }
        },
    }
    assert _map([lookalike]) == AclEnvelope(resolvable=False)
    # The genuine prefix-anchored claim still maps (anchoring did not over-tighten).
    assert _map([_everyone_except_external(TENANT_GUID)]) == AclEnvelope(
        resolvable=True, principals=[], groups=[EVERYONE_GROUP]
    )


def test_entra_crosswalk_source_cannot_drift_from_the_directory_sync():
    # C4 drift guard: aad-oid markers weld to the rows the Entra dir-sync
    # writes under ITS SOURCE_NAME — if either constant moves, the weld
    # silently breaks (every user grant would resolve to nothing).
    assert ENTRA_SOURCE_NAME == crosswalk.ENTRA_CROSSWALK_SOURCE


# ---------------------------------------------------------------------------
# Fixture transport (recorded Graph pages)
# ---------------------------------------------------------------------------


class FixtureSharePointTransport:
    """SharePointTransport backed by in-memory fixture pages.

    ``json_routes`` maps a path (or a followed full URL) to a response dict —
    or to an int status, which raises the matching httpx.HTTPStatusError.
    ``delta_routes`` maps a delta start path / saved deltaLink to its page
    list (the transport walks nextLinks internally, like the live one).
    ``reset_links`` raise SyncStateReset (410 / expired token)."""

    def __init__(self, *, json_routes=None, delta_routes=None, bytes_routes=None, reset_links=()):
        self.json_routes = dict(json_routes or {})
        self.delta_routes = dict(delta_routes or {})
        self.bytes_routes = dict(bytes_routes or {})
        self.reset_links = set(reset_links)
        self.json_calls: list[tuple[str, dict]] = []
        self.delta_calls: list[tuple[str, dict]] = []
        self.bytes_calls: list[tuple[str, dict]] = []

    def get_json(self, path, params):
        self.json_calls.append((path, dict(params or {})))
        if path not in self.json_routes:
            raise AssertionError(f"unexpected Graph GET {path} {params}")
        route = self.json_routes[path]
        if isinstance(route, int):
            request = httpx.Request("GET", f"https://graph.microsoft.com/v1.0/{path}")
            raise httpx.HTTPStatusError(
                f"{route}", request=request, response=httpx.Response(route, request=request)
            )
        return route

    def get_delta(self, url_or_path, params):
        self.delta_calls.append((url_or_path, dict(params or {})))
        if url_or_path in self.reset_links:
            raise SyncStateReset(f"reset: {url_or_path}")
        if url_or_path not in self.delta_routes:
            raise AssertionError(f"unexpected delta walk {url_or_path}")
        yield from self.delta_routes[url_or_path]

    def get_bytes(self, path, params):
        self.bytes_calls.append((path, dict(params or {})))
        if path not in self.bytes_routes:
            raise AssertionError(f"unexpected content fetch {path}")
        return self.bytes_routes[path]


# driveItem fixtures ---------------------------------------------------------

_ROOT_ITEM = {"id": "root0", "name": "root", "root": {}, "folder": {"childCount": 3}}
_NOTES_ITEM = {
    "id": "item-notes",
    "name": "oncall-notes.txt",
    "file": {"mimeType": "text/plain"},
    "lastModifiedDateTime": "2026-08-01T09:00:00Z",
    "eTag": '"v7"',
    "parentReference": {"driveId": DRIVE},
}
_REPORT_ITEM = {
    "id": "item-report",
    "name": "q3-report.pdf",
    "file": {"mimeType": "application/pdf"},
    "lastModifiedDateTime": "2026-08-01T10:00:00Z",
    "eTag": '"v3"',
}
_OPEN_ITEM = {
    "id": "item-open",
    "name": "share-me.txt",
    "file": {"mimeType": "text/plain"},
    "lastModifiedDateTime": "2026-08-01T10:30:00Z",
    "eTag": '"v2"',
}
_GONE_ITEM = {
    "id": "item-gone",
    "deleted": {"state": "deleted"},
    "lastModifiedDateTime": "2026-08-01T11:00:00Z",
}
_SECRET_ITEM = {
    "id": "item-secret",
    "name": "secret.txt",
    "file": {"mimeType": "text/plain"},
    "lastModifiedDateTime": "2026-08-01T11:30:00Z",
    "eTag": '"v9"',
}


def _backfill_transport() -> FixtureSharePointTransport:
    """Two drives on one site: DRIVE proves its G1 canary; DRIVE_BAD's canary
    response is a caller-filtered 200 (the planted co-owner grant is missing —
    R1) so the whole drive must quarantine."""
    return FixtureSharePointTransport(
        json_routes={
            f"sites/{SITE}/drives": {
                "value": [
                    {"id": DRIVE, "name": "Documents"},
                    {"id": DRIVE_BAD, "name": "Filtered"},
                ]
            },
            f"drives/{DRIVE}/items/canary-item/permissions": {
                "value": [_user_grant(OWNER_OID, upn="owner@contoso.com"), _group_grant(ENG_GID)]
            },
            # R1: a 200 OK with the co-owner grant silently absent.
            f"drives/{DRIVE_BAD}/items/canary-bad/permissions": {"value": [_group_grant(ENG_GID)]},
            # item-notes permissions page across @odata.nextLink (R1 paging).
            f"drives/{DRIVE}/items/item-notes/permissions": {
                "value": [_user_grant(ALICE_OID)],
                "@odata.nextLink": PERM_PAGE2,
            },
            PERM_PAGE2: {"value": [_group_grant(ENG_GID)]},
            f"drives/{DRIVE}/items/item-report/permissions": {"value": [_user_grant(ALICE_OID)]},
            f"drives/{DRIVE}/items/item-open/permissions": {"value": [_link("anonymous")]},
        },
        delta_routes={
            f"drives/{DRIVE}/root/delta": [
                {"value": [_ROOT_ITEM, _NOTES_ITEM, _REPORT_ITEM]},
                {"value": [_OPEN_ITEM, _GONE_ITEM], "@odata.deltaLink": DELTA_LINK},
            ],
            f"drives/{DRIVE_BAD}/root/delta": [
                {"value": [_SECRET_ITEM], "@odata.deltaLink": BAD_DELTA_LINK}
            ],
        },
        bytes_routes={
            f"drives/{DRIVE}/items/item-notes/content": b"oncall notes body",
            f"drives/{DRIVE}/items/item-report/content": PDF_BYTES,
        },
    )


async def _collect(gen):
    return [event async for event in gen]


def _backfill_events():
    transport = _backfill_transport()
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events = asyncio.run(_collect(connector.full_crawl()))
    return transport, connector, events


def _event(acl: AclEnvelope, **kw) -> SharePointDocumentEvent:
    defaults = dict(
        source="sharepoint",
        document_id=f"{DRIVE}:item-x",
        content=b"",
        mime_type="text/plain",
        version='"v1"',
        acl=acl,
        modified_time="2026-08-01T09:00:00Z",
        name="x.txt",
    )
    defaults.update(kw)
    return SharePointDocumentEvent(**defaults)


class AlarmSink(DryRunSink):
    """DryRunSink + the record_alarm/heartbeat surface the runners probe for
    (capture-only). Deliberately has NO ``retire`` transport: the drain must
    leave everything parked + alarmed on such a sink (fail closed), which is
    what the pre-drain parking tests below assert."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())
        self.alarms: list[dict[str, str]] = []
        self.heartbeats: list[str | None] = []

    def record_alarm(self, kind: str, detail: str) -> None:
        self.alarms.append({"kind": kind, "detail": detail})

    def heartbeat(self, cursor: str | None = None) -> None:
        self.heartbeats.append(cursor)


class FailingSink(AlarmSink):
    """Fails delivery for selected document_ids (an ingest 5xx stand-in)."""

    def __init__(self, fail_document_ids) -> None:
        super().__init__()
        self._fail = set(fail_document_ids)

    def deliver(self, request: dict) -> None:
        if request["document_id"] in self._fail:
            raise httpx.HTTPError("ingest 500")
        super().deliver(request)


class RetiringSink(AlarmSink):
    """AlarmSink + the ``retire`` transport (the live SharePointStatusSink
    shape): every replay succeeds (a 2xx), bodies are captured byte-exact.
    ``calls`` interleaves deliver/retire so order can be asserted (the
    over-retire race is an ORDERING bug)."""

    def __init__(self) -> None:
        super().__init__()
        self.retired: list[dict] = []
        self.calls: list[tuple[str, str]] = []

    def deliver(self, request: dict) -> None:
        self.calls.append(("deliver", request["document_id"]))
        super().deliver(request)

    def retire(self, request: dict) -> None:
        self.calls.append(("retire", request["document_id"]))
        self.retired.append(dict(request))


class FailingRetireSink(RetiringSink):
    """Records the replay attempt, then fails it (a retire 5xx stand-in)."""

    def retire(self, request: dict) -> None:
        super().retire(request)
        raise httpx.HTTPError("retire 500")


class ToggleRetireSink(RetiringSink):
    """Retire fails while ``failing`` is True — a retire route that recovers
    between cycles (the race window's precondition)."""

    def __init__(self) -> None:
        super().__init__()
        self.failing = True

    def retire(self, request: dict) -> None:
        super().retire(request)
        if self.failing:
            raise httpx.HTTPError("retire 500")


def _ledger(tmp_path) -> list[dict]:
    return json.loads((tmp_path / "sharepoint_parked_retractions.json").read_text())


def _preexisting_park(tmp_path, item_id: str = "item-old", reason: str = "removed") -> str:
    """Write a prior-cycle parked entry straight into the ledger; returns its
    document_id."""
    document_id = f"{DRIVE}:{item_id}"
    entry = {
        "drive_id": DRIVE,
        "item_id": item_id,
        "document_id": document_id,
        "reason": reason,
        "first_seen": "2026-08-02T00:00:00Z",
        "last_seen": "2026-08-02T00:00:00Z",
    }
    (tmp_path / "sharepoint_parked_retractions.json").write_text(
        json.dumps([entry], indent=2, sort_keys=True) + "\n"
    )
    return document_id


# ---------------------------------------------------------------------------
# Backfill: enumeration, ACL-before-content, G1 drive quarantine
# ---------------------------------------------------------------------------


def test_backfill_enumerates_and_mirrors():
    transport, connector, events = _backfill_events()
    by_id = {e.document_id: e for e in events}
    # The root folder is a container, never a document event.
    assert f"{DRIVE}:root0" not in by_id

    notes = by_id[f"{DRIVE}:item-notes"]
    # Permissions were walked ACROSS pages (both grants present).
    assert notes.acl == AclEnvelope(resolvable=True, principals=[ALICE], groups=[ENG])
    assert notes.content == b"oncall notes body"
    assert notes.modified_time == "2026-08-01T09:00:00Z"
    # R1 paging: the followed permissions nextLink went out with EMPTY params
    # (the transport sends params=None — the $skiptoken is never stripped).
    assert (PERM_PAGE2, {}) in transport.json_calls

    gone = by_id[f"{DRIVE}:item-gone"]
    assert gone.removed

    # Terminal deltaLinks + the reconcile stamp landed for the runner.
    assert connector.backfill_delta_links == {DRIVE: DELTA_LINK, DRIVE_BAD: BAD_DELTA_LINK}
    assert connector.backfill_completed_at == "2026-08-03T12:00:00Z"


def test_anonymous_item_quarantines_and_content_is_never_fetched():
    transport, _, events = _backfill_events()
    open_item = {e.document_id: e for e in events}[f"{DRIVE}:item-open"]
    assert open_item.acl == AclEnvelope(resolvable=False)
    assert open_item.content == b""
    # ACL-before-content: the only thing keeping these bytes unfetched is the
    # quarantine (text/plain WOULD otherwise download).
    assert all(not p.startswith(f"drives/{DRIVE}/items/item-open") for p, _ in transport.bytes_calls)


def test_g1_canary_failure_quarantines_whole_drive():
    transport, _, events = _backfill_events()
    secret = {e.document_id: e for e in events}[f"{DRIVE_BAD}:item-secret"]
    assert secret.acl == AclEnvelope(resolvable=False)
    # The drive failed its completeness proof: NO per-item permission fetch
    # (whose 200 could be caller-filtered) and NO content fetch happened.
    assert all(
        not path.startswith(f"drives/{DRIVE_BAD}/items/item-secret")
        for path, _ in transport.json_calls
    )
    assert all(not path.startswith(f"drives/{DRIVE_BAD}") for path, _ in transport.bytes_calls)


def test_g1_missing_canary_is_unprovable_and_quarantines():
    transport = _backfill_transport()
    config = _cfg(canaries={DRIVE: DriveCanary("canary-item", OWNER_OID)})  # DRIVE_BAD: none
    connector = SharePointConnector(transport, config, clock=_clock)
    events = asyncio.run(_collect(connector.full_crawl()))
    secret = {e.document_id: e for e in events}[f"{DRIVE_BAD}:item-secret"]
    assert secret.acl == AclEnvelope(resolvable=False)


def test_g1_unreadable_canary_quarantines():
    transport = _backfill_transport()
    transport.json_routes[f"drives/{DRIVE_BAD}/items/canary-bad/permissions"] = 403
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events = asyncio.run(_collect(connector.full_crawl()))
    secret = {e.document_id: e for e in events}[f"{DRIVE_BAD}:item-secret"]
    assert secret.acl == AclEnvelope(resolvable=False)


def test_unreadable_item_permissions_quarantine_without_aborting_the_crawl():
    transport = _backfill_transport()
    transport.json_routes[f"drives/{DRIVE}/items/item-report/permissions"] = 403
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events = asyncio.run(_collect(connector.full_crawl()))
    by_id = {e.document_id: e for e in events}
    assert by_id[f"{DRIVE}:item-report"].acl == AclEnvelope(resolvable=False)
    # The rest of the drive still mirrored.
    assert by_id[f"{DRIVE}:item-notes"].acl.resolvable


# ---------------------------------------------------------------------------
# Sink request bodies (POST /v1/ingest/documents contract)
# ---------------------------------------------------------------------------


def test_backfill_request_bodies_exact():
    _, connector, events = _backfill_events()
    registry = StaticSharePointRegistry(REGISTRY_MAP)
    bodies = [
        build_sharepoint_document_request(e, registry, TENANT)
        for e in events
    ]
    by_id = {b["document_id"]: b for b in bodies}
    assert by_id[f"{DRIVE}:item-notes"] == {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE}:item-notes",
        "content": "oncall notes body",
        "entities": [],
        "valid_from": "2026-08-01T09:00:00Z",
        "visibility": [101, 202],
        "acl_provenance": "mirrored",
    }
    # Binary lane: PDF bytes ride content_base64 + filename for server-side
    # Tier-1 extraction (never /v1/files — that would replace the mirrored ACL).
    assert by_id[f"{DRIVE}:item-report"] == {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE}:item-report",
        "content_base64": base64.b64encode(PDF_BYTES).decode("ascii"),
        "filename": "q3-report.pdf",
        "entities": [],
        "valid_from": "2026-08-01T10:00:00Z",
        "visibility": [101],
        "acl_provenance": "mirrored",
    }
    assert by_id[f"{DRIVE}:item-open"] == {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE}:item-open",
        "content": None,
        "entities": [],
        "valid_from": "2026-08-01T10:30:00Z",
        "acl_provenance": "quarantined",
    }
    assert by_id[f"{DRIVE}:item-gone"] == {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE}:item-gone",
        "removed": True,
        "valid_from": "2026-08-01T11:00:00Z",
    }
    # G1-quarantined drive: no visibility, no content.
    assert by_id[f"{DRIVE_BAD}:item-secret"] == {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE_BAD}:item-secret",
        "content": None,
        "entities": [],
        "valid_from": "2026-08-01T11:30:00Z",
        "acl_provenance": "quarantined",
    }


def test_unresolved_object_id_contributes_nothing_and_all_unresolved_quarantines():
    # Plan row a: an objectId with no directory_vouched crosswalk row confers
    # nothing; the surviving grants still mirror (over-hide, never over-share).
    acl = AclEnvelope(
        resolvable=True,
        principals=[ALICE, f"{crosswalk.AAD_OID_PREFIX}{BOB_OID}"],  # bob: no crosswalk row
        groups=[ENG],
    )
    registry = StaticSharePointRegistry(REGISTRY_MAP)
    body = build_sharepoint_document_request(_event(acl=acl), registry, TENANT)
    assert body["visibility"] == [101, 202]
    assert body["acl_provenance"] == "mirrored"
    # Nothing resolves at all (no dir-sync): fail closed to quarantine.
    body = build_sharepoint_document_request(
        _event(acl=acl), StaticSharePointRegistry({}), TENANT
    )
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"


def test_http_registry_routes_object_ids_through_the_entra_crosswalk():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "mappings": {"user:alice@contoso.com": 101, ENG: 202},
                "quarantined": False,
            },
        )

    registry = HttpSharePointRegistry(
        "http://verity.local:8080",
        tenant_id=TENANT,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    acl = AclEnvelope(resolvable=True, principals=[ALICE], groups=[ENG])
    body = build_sharepoint_document_request(_event(acl=acl), registry, TENANT)
    # The aad-oid marker rode `resolvable` as the (entra, objectId) owner the
    # dir-sync's directory_vouched row resolves; the group rode `principals`.
    assert seen == {
        "method": "POST",
        "path": crosswalk.PRINCIPALS_PATH,
        "body": {
            "tenant_id": TENANT,
            "principals": [ENG],
            "resolvable": [{"source": "entra", "local_id": ALICE_OID}],
        },
    }
    assert body["visibility"] == [101, 202]
    assert body["acl_provenance"] == "mirrored"


# ---------------------------------------------------------------------------
# Truth lane: delta polling, G3 SLA, R4 folder re-walk, SyncStateReset
# ---------------------------------------------------------------------------


def _poll_transport(**delta_overrides) -> FixtureSharePointTransport:
    delta_routes = {
        DELTA_LINK: [
            {"value": [_ROOT_ITEM, _NOTES_ITEM, _GONE_ITEM], "@odata.deltaLink": NEW_DELTA_LINK}
        ]
    }
    delta_routes.update(delta_overrides)
    return FixtureSharePointTransport(
        json_routes={
            f"sites/{SITE}/drives": {"value": [{"id": DRIVE, "name": "Documents"}]},
            f"drives/{DRIVE}/items/canary-item/permissions": {
                "value": [_user_grant(OWNER_OID, upn="owner@contoso.com")]
            },
            f"drives/{DRIVE}/items/item-notes/permissions": {
                "value": [_user_grant(ALICE_OID)],
                "@odata.nextLink": PERM_PAGE2,
            },
            PERM_PAGE2: {"value": [_group_grant(ENG_GID)]},
            f"drives/{DRIVE}/root/delta": {"value": [], "@odata.deltaLink": DELTA_LINK},
        },
        delta_routes=delta_routes,
        bytes_routes={f"drives/{DRIVE}/items/item-notes/content": b"oncall notes body"},
    )


def _cursor(link: str = DELTA_LINK, last_reconcile_at: str | None = "2026-08-03T00:00:00Z"):
    return json.dumps({"drives": {DRIVE: link}, "last_reconcile_at": last_reconcile_at})


def test_first_poll_primes_delta_links_and_emits_nothing():
    transport = _poll_transport()
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events, cursor = asyncio.run(connector.poll(None))
    assert events == []
    assert json.loads(cursor) == {"drives": {DRIVE: DELTA_LINK}, "last_reconcile_at": None}
    # Primed via token=latest (m1) — enumeration is full_crawl's job.
    assert (f"drives/{DRIVE}/root/delta", {"token": "latest"}) in transport.json_calls


def test_poll_within_sla_mirrors_and_advances_cursor():
    transport = _poll_transport()
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events, cursor = asyncio.run(connector.poll(_cursor()))
    by_id = {e.document_id: e for e in events}
    notes = by_id[f"{DRIVE}:item-notes"]
    assert notes.acl == AclEnvelope(resolvable=True, principals=[ALICE], groups=[ENG])
    assert notes.content == b"oncall notes body"
    assert by_id[f"{DRIVE}:item-gone"].removed
    # The root item never triggers a whole-drive re-walk.
    assert all("root0/children" not in path for path, _ in transport.json_calls)
    assert json.loads(cursor) == {
        "drives": {DRIVE: NEW_DELTA_LINK},
        "last_reconcile_at": "2026-08-03T00:00:00Z",
    }


def test_poll_past_sla_forces_quarantine_posture():
    # G3/R3: delta can miss parent-only revocations; past the reconcile SLA
    # (clock 2026-08-03T12:00Z, last reconcile >24h before) nothing gets NEWLY
    # indexed as mirrored — permissions and content are not even fetched.
    # Enforcement against the index is the RUNNER's job, not poll's: the
    # quarantined bodies it emits get parked and drained via /v1/admin/retire
    # (asserted in the drain tests).
    transport = _poll_transport()
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events, _ = asyncio.run(connector.poll(_cursor(last_reconcile_at="2026-08-01T00:00:00Z")))
    by_id = {e.document_id: e for e in events}
    assert by_id[f"{DRIVE}:item-notes"].acl == AclEnvelope(resolvable=False)
    # The removal-marker EVENT still surfaces — the runner parks it and the
    # drain replays it as a /v1/admin/retire, which IS the narrowing.
    assert by_id[f"{DRIVE}:item-gone"].removed
    assert transport.bytes_calls == []
    assert all("item-notes/permissions" not in path for path, _ in transport.json_calls)


def test_poll_never_reconciled_is_stale():
    transport = _poll_transport()
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events, _ = asyncio.run(connector.poll(_cursor(last_reconcile_at=None)))
    notes = {e.document_id: e for e in events}[f"{DRIVE}:item-notes"]
    assert notes.acl == AclEnvelope(resolvable=False)


def test_changed_folder_rewalks_its_subtree():
    # R4: a child whose only change is an INHERITED permission change does not
    # itself appear in delta — the surfaced parent folder triggers a re-walk
    # with fresh per-child ACL reads.
    folder = {"id": "folder-legal", "name": "legal", "folder": {"childCount": 1}}
    transport = _poll_transport(
        **{DELTA_LINK: [{"value": [folder], "@odata.deltaLink": NEW_DELTA_LINK}]}
    )
    transport.json_routes[f"drives/{DRIVE}/items/folder-legal/children"] = {
        "value": [_NOTES_ITEM]
    }
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events, _ = asyncio.run(connector.poll(_cursor()))
    notes = {e.document_id: e for e in events}[f"{DRIVE}:item-notes"]
    assert notes.acl == AclEnvelope(resolvable=True, principals=[ALICE], groups=[ENG])


def test_run_once_delivers_checkpoints_and_parks_the_removal_marker(tmp_path):
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    connector = SharePointConnector(_poll_transport(), _cfg(), clock=_clock)
    sink = AlarmSink()
    delivered = run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    # notes delivered. The removal marker cannot ride the documents endpoint;
    # it is PARKED in the retraction ledger — and because this sink has no
    # retire transport, the drain leaves it parked + alarmed (fail closed,
    # never silently dropped). The enforced path is asserted in the
    # drain tests below.
    assert delivered == 1
    assert [r["document_id"] for r in sink.requests] == [f"{DRIVE}:item-notes"]
    ledger = _ledger(tmp_path)
    assert [e["document_id"] for e in ledger] == [f"{DRIVE}:item-gone"]
    assert ledger[0]["reason"] == "removed"
    assert ledger[0]["drive_id"] == DRIVE
    assert ledger[0]["item_id"] == "item-gone"
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved["drives"] == {DRIVE: NEW_DELTA_LINK}


def test_sync_state_reset_discards_cursor_and_alarms_delta_reset(tmp_path):
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    transport = _poll_transport()
    transport.reset_links.add(DELTA_LINK)
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = AlarmSink()
    with pytest.raises(SyncStateReset):
        run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    # No checkpoint: the cursor is gone; the next cycle re-primes and the G3
    # SLA holds NEW indexing in quarantine posture until a backfill completes.
    # HONESTY: everything already indexed keeps serving (a 410 consumed
    # whatever retraction signal the lost delta window held) — so the reset
    # MUST alarm, naming the required full re-backfill, and the alarm must
    # ride a heartbeat even though nothing was delivered.
    assert not state_file.exists()
    assert sink.requests == []
    assert [a["kind"] for a in sink.alarms] == ["delta_reset"]
    assert "backfill" in sink.alarms[0]["detail"]
    assert sink.heartbeats == [None]


def test_run_backfill_persists_delta_links_and_reconcile_stamp(tmp_path):
    state_file = tmp_path / "sharepoint_cursor.json"
    connector = SharePointConnector(_backfill_transport(), _cfg(), clock=_clock)
    sink = AlarmSink()
    delivered = run_backfill(
        connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file
    )
    # notes + report mirrored; open/secret quarantined + gone removed cannot
    # ride the documents endpoint — they are PARKED in the ledger, and with no
    # retire transport on this sink they STAY parked + alarmed (fail closed,
    # never silently dropped).
    assert delivered == 2
    assert sorted(r["document_id"] for r in sink.requests) == [
        f"{DRIVE}:item-notes",
        f"{DRIVE}:item-report",
    ]
    parked = {e["document_id"]: e["reason"] for e in _ledger(tmp_path)}
    assert parked == {
        f"{DRIVE}:item-open": "quarantined",
        f"{DRIVE}:item-gone": "removed",
        f"{DRIVE_BAD}:item-secret": "quarantined",
    }
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]
    assert "3 detected retraction(s)" in sink.alarms[0]["detail"]
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved == {
        "drives": {DRIVE: DELTA_LINK, DRIVE_BAD: BAD_DELTA_LINK},
        "last_reconcile_at": "2026-08-03T12:00:00Z",
    }
    # The stamp satisfies the SLA for the very next poll (fresh clock).
    assert not connector._stale(saved["last_reconcile_at"], _CLOCK_NOW)


def test_failed_backfill_does_not_stamp_the_sla_and_alarms(tmp_path):
    # L2: a backfill with ingest failures re-proved NOTHING — stamping
    # last_reconcile_at would let the next poll serve mirrored against an
    # index the crawl failed to reconcile. No stamp (the SLA stays unmet,
    # fail closed) + a backfill_incomplete alarm.
    state_file = tmp_path / "sharepoint_cursor.json"
    connector = SharePointConnector(_backfill_transport(), _cfg(), clock=_clock)
    sink = FailingSink({f"{DRIVE}:item-report"})
    delivered = run_backfill(
        connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file
    )
    assert delivered == 1
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved["drives"] == {DRIVE: DELTA_LINK, DRIVE_BAD: BAD_DELTA_LINK}
    assert saved["last_reconcile_at"] is None  # no prior stamp to carry
    assert connector._stale(saved["last_reconcile_at"], _CLOCK_NOW)  # SLA unmet
    kinds = [a["kind"] for a in sink.alarms]
    assert "backfill_incomplete" in kinds
    detail = next(a["detail"] for a in sink.alarms if a["kind"] == "backfill_incomplete")
    assert "1 ingest failure(s)" in detail and "NOT stamped" in detail


def test_mirrored_to_quarantined_transition_is_parked_and_alarmed(tmp_path):
    # The probe-verified detection: item-notes was previously indexed
    # mirrored; this cycle its ACL gained an anonymous link ⇒ quarantined body
    # ⇒ no documents-endpoint op. On a sink WITHOUT the retire transport the
    # signal must not be consumed silently: it lands in the parked-retractions
    # ledger and alarms on the heartbeat (the already-indexed content keeps
    # serving ONLY until a retire-capable cycle drains it — the enforced end
    # state is test_mirrored_to_quarantined_transition_is_fully_enforced).
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    transport = _poll_transport()
    transport.json_routes[f"drives/{DRIVE}/items/item-notes/permissions"] = {
        "value": [_user_grant(ALICE_OID), _link("anonymous")]
    }
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = AlarmSink()
    delivered = run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert delivered == 0
    assert sink.requests == []  # NO delivered op — the honest statement
    parked = {e["document_id"]: e for e in _ledger(tmp_path)}
    notes = parked[f"{DRIVE}:item-notes"]
    assert notes["reason"] == "quarantined"
    assert notes["drive_id"] == DRIVE and notes["item_id"] == "item-notes"
    assert notes["first_seen"] == notes["last_seen"] == "2026-08-03T12:00:00Z"
    assert parked[f"{DRIVE}:item-gone"]["reason"] == "removed"
    detail = next(a["detail"] for a in sink.alarms if a["kind"] == "parked_retraction")
    assert "2 detected retraction(s)" in detail
    assert "sharepoint_parked_retractions.json" in detail
    # DOCUMENTED BEHAVIOR: the delta cursor STILL advances — blocking it would
    # livelock on permanently-quarantined items. The ledger, not the cursor,
    # carries the signal (the delta stream will never resurface this item).
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved["drives"] == {DRIVE: NEW_DELTA_LINK}
    assert sink.heartbeats  # the alarm rode a heartbeat
    # A second cycle re-surfacing the same item DEDUPS by document_id
    # (updating last_seen), so the ledger cannot grow without bound.
    transport.delta_routes[NEW_DELTA_LINK] = [
        {"value": [_NOTES_ITEM], "@odata.deltaLink": NEW_DELTA_LINK}
    ]
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert len(_ledger(tmp_path)) == 2


# ---------------------------------------------------------------------------
# The retire drain: parked retractions ENFORCED via POST /v1/admin/retire
# ---------------------------------------------------------------------------


def test_run_once_drains_the_removal_marker_and_clears_the_alarm(tmp_path):
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    connector = SharePointConnector(_poll_transport(), _cfg(), clock=_clock)
    sink = RetiringSink()
    delivered = run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert delivered == 1
    # The parked removal marker was replayed byte-exact against the retire
    # route (admin plane, same bearer as deliver on the live sink)…
    assert sink.retired == [
        {
            "tenant_id": TENANT,
            "source": "sharepoint",
            "document_id": f"{DRIVE}:item-gone",
            "reason": "removed",
        }
    ]
    # …the 2xx emptied the ledger, so NO parked_retraction alarm fires.
    assert _ledger(tmp_path) == []
    assert sink.alarms == []


def test_failed_retire_replay_keeps_the_entry_parked_and_alarmed(tmp_path):
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    connector = SharePointConnector(_poll_transport(), _cfg(), clock=_clock)
    sink = FailingRetireSink()
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    # The replay was attempted, failed, and the entry survives for the next
    # cycle; the alarm counts exactly what remains.
    assert [r["document_id"] for r in sink.retired] == [f"{DRIVE}:item-gone"]
    assert [e["document_id"] for e in _ledger(tmp_path)] == [f"{DRIVE}:item-gone"]
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]
    detail = sink.alarms[0]["detail"]
    assert "1 detected retraction(s)" in detail
    assert RETIRE_PATH in detail


def test_mirrored_to_quarantined_transition_is_fully_enforced(tmp_path):
    # The full enforcement arc of the probe-confirmed gap: item-notes was
    # previously indexed mirrored; its ACL gains an anonymous link ⇒
    # quarantined body ⇒ no documents-endpoint op ⇒ PARKED ⇒ DRAINED as a
    # /v1/admin/retire replay — the server closes the current chunks (valid_to
    # + blanked visibility), so the content stops serving on the next read.
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    transport = _poll_transport()
    transport.json_routes[f"drives/{DRIVE}/items/item-notes/permissions"] = {
        "value": [_user_grant(ALICE_OID), _link("anonymous")]
    }
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = RetiringSink()
    delivered = run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert delivered == 0
    assert sink.requests == []  # the retraction never rides the ingest ladder
    assert sorted(sink.retired, key=lambda b: b["document_id"]) == [
        {
            "tenant_id": TENANT,
            "source": "sharepoint",
            "document_id": f"{DRIVE}:item-gone",
            "reason": "removed",
        },
        {
            "tenant_id": TENANT,
            "source": "sharepoint",
            "document_id": f"{DRIVE}:item-notes",
            "reason": "quarantined",
        },
    ]
    assert _ledger(tmp_path) == []
    assert sink.alarms == []  # fully enforced ⇒ nothing left to alarm
    # The cursor advanced as before — the ledger + drain, not the cursor,
    # carried the signal to enforcement.
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved["drives"] == {DRIVE: NEW_DELTA_LINK}


def test_replay_safe_redetected_document_re_parks_and_re_drains(tmp_path):
    # Replay safety: a document whose retraction already drained gets
    # re-surfaced by delta (still quarantined) — it re-parks, re-drains, and
    # the server's idempotent retire (0 chunks closed, still a 2xx) unparks it
    # again with no error and no leftover alarm.
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    transport = _poll_transport()
    transport.json_routes[f"drives/{DRIVE}/items/item-notes/permissions"] = {
        "value": [_user_grant(ALICE_OID), _link("anonymous")]
    }
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = RetiringSink()
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert _ledger(tmp_path) == []
    # Cycle 2: delta re-surfaces the same (still-quarantined) item.
    transport.delta_routes[NEW_DELTA_LINK] = [
        {"value": [_NOTES_ITEM], "@odata.deltaLink": NEW_DELTA_LINK}
    ]
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    notes_replays = [b for b in sink.retired if b["document_id"] == f"{DRIVE}:item-notes"]
    assert len(notes_replays) == 2  # one per detection; identical bodies
    assert notes_replays[0] == notes_replays[1]
    assert _ledger(tmp_path) == []
    assert sink.alarms == []


def test_run_backfill_drains_all_three_parked_retractions(tmp_path):
    # The backfill lane drains too: open/secret (quarantined) + gone (removed)
    # all end enforced; nothing outstanding, no alarm.
    state_file = tmp_path / "sharepoint_cursor.json"
    connector = SharePointConnector(_backfill_transport(), _cfg(), clock=_clock)
    sink = RetiringSink()
    delivered = run_backfill(
        connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file
    )
    assert delivered == 2
    assert {b["document_id"]: b["reason"] for b in sink.retired} == {
        f"{DRIVE}:item-open": "quarantined",
        f"{DRIVE}:item-gone": "removed",
        f"{DRIVE_BAD}:item-secret": "quarantined",
    }
    assert all(
        b["tenant_id"] == TENANT and b["source"] == "sharepoint" for b in sink.retired
    )
    assert _ledger(tmp_path) == []
    assert sink.alarms == []


def test_restored_document_unparks_its_stale_retraction(tmp_path):
    # THE over-retire race, regression-pinned. Cycle N: item-gone is removed;
    # its retire replay fails (server down) so the entry stays parked. Cycle
    # N+1: the item is RESTORED, delivered mirrored, and freshly indexed —
    # under the old order the end-of-cycle drain then replayed the STALE
    # parked "removed" and blanked the just-written chunks. Fixed: the
    # delivery is strictly newer than the parked signal, so it UNPARKS the
    # entry; no retire for the document ever fires at-or-after its delivery,
    # and once the retire route recovers there is nothing left to replay.
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    doc = f"{DRIVE}:item-gone"
    restored = {
        "id": "item-gone",
        "name": "restored.txt",
        "file": {"mimeType": "text/plain"},
        "lastModifiedDateTime": "2026-08-03T09:00:00Z",
        "eTag": '"v2"',
    }
    transport = _poll_transport()  # cycle N: DELTA_LINK emits gone as removed
    transport.delta_routes[NEW_DELTA_LINK] = [
        {"value": [restored], "@odata.deltaLink": THIRD_DELTA_LINK}
    ]
    transport.delta_routes[THIRD_DELTA_LINK] = [
        {"value": [], "@odata.deltaLink": THIRD_DELTA_LINK}
    ]
    transport.json_routes[f"drives/{DRIVE}/items/item-gone/permissions"] = {
        "value": [_user_grant(ALICE_OID)]
    }
    transport.bytes_routes[f"drives/{DRIVE}/items/item-gone/content"] = b"restored body"
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = ToggleRetireSink()

    # Cycle N: removal parked; the replay fails; the entry survives, alarmed.
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert [e["document_id"] for e in _ledger(tmp_path)] == [doc]
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]

    # Cycle N+1: restored + delivered while the retire route is STILL down.
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    bodies = [r for r in sink.requests if r["document_id"] == doc]
    assert bodies and bodies[-1]["visibility"] == [101]  # freshly indexed, visible
    assert all(e["document_id"] != doc for e in _ledger(tmp_path))  # unparked
    # No retire for it at-or-after its delivery: the stale signal can never
    # land on the fresh chunks (the pre-drain attempt, which failed, came first).
    deliver_at = sink.calls.index(("deliver", doc))
    assert ("retire", doc) not in sink.calls[deliver_at:]
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]  # cycle N's only

    # Cycle N+2: the retire route recovers — NOTHING fires for the restored
    # document (the unpark, not luck, is what protects it) and it stays visible.
    sink.failing = False
    replays_before = len(sink.retired)
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert len(sink.retired) == replays_before
    assert _ledger(tmp_path) == []


def test_preexisting_ledger_drains_before_any_delivery(tmp_path):
    # Order guard #1: a parked entry from a PRIOR cycle replays BEFORE this
    # cycle delivers anything — its retire must land on the old index state,
    # never on chunks this cycle writes.
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    old_doc = _preexisting_park(tmp_path)
    connector = SharePointConnector(_poll_transport(), _cfg(), clock=_clock)
    sink = RetiringSink()
    run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    delivers = [i for i, c in enumerate(sink.calls) if c[0] == "deliver"]
    assert delivers, "the cycle delivered (the ordering assertion is real)"
    assert sink.calls.index(("retire", old_doc)) < min(delivers)
    # This cycle's own reject (item-gone) still parks after delivery and drains.
    assert ("retire", f"{DRIVE}:item-gone") in sink.calls[min(delivers) :]
    assert _ledger(tmp_path) == []
    assert sink.alarms == []


def test_backfill_preexisting_ledger_drains_before_any_delivery(tmp_path):
    # The same order guard on the backfill lane.
    state_file = tmp_path / "sharepoint_cursor.json"
    old_doc = _preexisting_park(tmp_path)
    connector = SharePointConnector(_backfill_transport(), _cfg(), clock=_clock)
    sink = RetiringSink()
    run_backfill(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    delivers = [i for i, c in enumerate(sink.calls) if c[0] == "deliver"]
    assert delivers
    assert sink.calls.index(("retire", old_doc)) < min(delivers)
    assert _ledger(tmp_path) == []
    assert sink.alarms == []


def test_sync_state_reset_still_drains_the_preexisting_ledger(tmp_path):
    # Fix: a delta reset must not skip enforcement of what is ALREADY parked
    # — the ledger predates the lost window and its replays are independent
    # of the cursor. The post-drain remainder rides the SAME heartbeat as the
    # delta_reset alarm.
    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    old_doc = _preexisting_park(tmp_path)
    transport = _poll_transport()
    transport.reset_links.add(DELTA_LINK)
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    sink = FailingRetireSink()
    with pytest.raises(SyncStateReset):
        run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    # The replay was attempted, failed, and the entry survives; BOTH alarms
    # rode the one delta_reset heartbeat.
    assert [r["document_id"] for r in sink.retired] == [old_doc]
    assert [e["document_id"] for e in _ledger(tmp_path)] == [old_doc]
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction", "delta_reset"]
    assert sink.heartbeats == [None]
    assert not state_file.exists()

    # A retire-capable reset cycle drains it clean: only delta_reset remains.
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    ok = RetiringSink()
    with pytest.raises(SyncStateReset):
        run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), ok, state_file)
    assert [r["document_id"] for r in ok.retired] == [old_doc]
    assert _ledger(tmp_path) == []
    assert [a["kind"] for a in ok.alarms] == ["delta_reset"]
    assert ok.heartbeats == [None]


def test_drain_survives_non_http_retire_failures(tmp_path):
    # The drain catches Exception, not just httpx.HTTPError: a sink bug or an
    # unexpected response shape keeps the entry parked + alarmed — under the
    # narrow catch it aborted the whole cycle (no checkpoint, no alarm, no
    # heartbeat), leaving the operator blind to unenforced retractions.
    class ExplodingRetireSink(RetiringSink):
        def retire(self, request: dict) -> None:
            super().retire(request)
            raise ValueError("unexpected sink bug")

    state_file = tmp_path / "sharepoint_cursor.json"
    state_file.write_text(json.dumps({"cursor": _cursor()}, indent=2) + "\n")
    connector = SharePointConnector(_poll_transport(), _cfg(), clock=_clock)
    sink = ExplodingRetireSink()
    delivered = run_once(connector, StaticSharePointRegistry(REGISTRY_MAP), sink, state_file)
    assert delivered == 1  # the cycle completed
    assert [e["document_id"] for e in _ledger(tmp_path)] == [f"{DRIVE}:item-gone"]
    assert [a["kind"] for a in sink.alarms] == ["parked_retraction"]
    assert sink.heartbeats  # the heartbeat still fired
    saved = json.loads(json.loads(state_file.read_text())["cursor"])
    assert saved["drives"] == {DRIVE: NEW_DELTA_LINK}  # checkpoint landed


def test_status_sink_retire_posts_the_admin_retire_body_and_raises_on_failure():
    posts: list[tuple[str, str | None, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append(
            (
                request.url.path,
                request.headers.get("Authorization"),
                json.loads(request.content),
            )
        )
        if len(posts) > 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"chunks_retired": 3})

    sink = SharePointStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer admin-key"},
        ),
    )
    body = {
        "tenant_id": TENANT,
        "source": "sharepoint",
        "document_id": f"{DRIVE}:item-gone",
        "reason": "removed",
    }
    sink.retire(body)
    # The replay rides the admin route under the same bearer as deliver().
    assert posts == [(RETIRE_PATH, "Bearer admin-key", body)]
    # A non-2xx raises — the drain keeps the entry parked and re-alarms.
    with pytest.raises(httpx.HTTPStatusError):
        sink.retire(body)


def test_item_with_neither_file_nor_folder_facet_is_skipped_entirely():
    # C3: a package (e.g. a OneNote notebook) has neither facet — no body, no
    # permission fetch, no content; counted, not silent.
    package = {
        "id": "item-onenote",
        "name": "Team Notebook",
        "package": {"type": "oneNote"},
        "lastModifiedDateTime": "2026-08-01T12:00:00Z",
        "eTag": '"v1"',
    }
    transport = FixtureSharePointTransport(
        json_routes={
            f"sites/{SITE}/drives": {"value": [{"id": DRIVE, "name": "Documents"}]},
            f"drives/{DRIVE}/items/canary-item/permissions": {
                "value": [_user_grant(OWNER_OID, upn="owner@contoso.com")]
            },
            f"drives/{DRIVE}/items/item-report/permissions": {"value": [_user_grant(ALICE_OID)]},
        },
        delta_routes={
            f"drives/{DRIVE}/root/delta": [
                {"value": [_ROOT_ITEM, package, _REPORT_ITEM], "@odata.deltaLink": DELTA_LINK}
            ]
        },
        bytes_routes={f"drives/{DRIVE}/items/item-report/content": PDF_BYTES},
    )
    connector = SharePointConnector(transport, _cfg(), clock=_clock)
    events = asyncio.run(_collect(connector.full_crawl()))
    assert all(e.document_id != f"{DRIVE}:item-onenote" for e in events)
    assert connector.skipped_nonfile == 1
    # Truly ENTIRELY skipped: no permission fetch, no content fetch.
    assert all("item-onenote" not in path for path, _ in transport.json_calls)
    assert all("item-onenote" not in path for path, _ in transport.bytes_calls)
    # The neighboring real file still crawled.
    assert any(e.document_id == f"{DRIVE}:item-report" for e in events)


def test_status_sink_heartbeat_carries_alarms_even_with_zero_deliveries():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    sink = SharePointStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.alarm_tenant_id = TENANT
    sink.record_alarm("delta_reset", "cursor discarded; full --backfill required")
    sink.heartbeat()
    assert posts == [
        (
            "/v1/admin/connector-status",
            {
                "tenant_id": TENANT,
                "source": "sharepoint",
                "items_synced": 0,
                "alarms": [
                    {
                        "kind": "delta_reset",
                        "detail": "cursor discarded; full --backfill required",
                    }
                ],
            },
        )
    ]
    # Drained: a later alarm-free heartbeat with nothing delivered stays silent.
    sink.heartbeat()
    assert len(posts) == 1


def test_split_sharepoint_principals_shapes_the_crosswalk_request():
    owners, others = crosswalk.split_sharepoint_principals([ALICE, ENG, EVERYONE_GROUP])
    assert owners == [crosswalk.CrosswalkOwner(source="entra", local_id=ALICE_OID)]
    assert others == [ENG, EVERYONE_GROUP]
