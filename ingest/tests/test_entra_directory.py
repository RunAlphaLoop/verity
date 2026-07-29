"""Microsoft Entra ID directory-sync conformance tests — the Microsoft analog
of test_gdirectory.py, mirroring its FixtureTransport pattern.

All Graph payloads are recorded fixtures authored from the documented Graph
v1.0 response shapes (/users/delta, /groups/delta, /groups/{id}/members). No
live API calls and no real credentials anywhere in this file (msal is never
imported: the fixture transport short-circuits load_graph_credentials).

The suite exercises the red-team LEAK cases explicitly, not just happy paths:

- (t4) guest-as-Member (userType==Member + externalUserState set) AND a
  #EXT#-UPN Member are excluded from the everyone token AND from group edges.
- (t7/t8) a delta fold produces a correct FULL snapshot (adds + removals).
- (t9) a user-object-deletion tombstone deletes ALL that objectId's group
  edges from the persisted snapshot AND deprovisions the canonical — even with
  NO corresponding members@delta removal (the group-delta hole).
- (t11) a SyncStateReset (410 / syncStateNotFound) forces a full resync and
  does NOT checkpoint stale state.
"""

from __future__ import annotations

import io
import json

import httpx
import pytest

from verity_ingest.connectors.entra_directory import (
    CROSSWALK_PATH,
    DEPROVISION_PATH,
    EVERYONE_GROUP,
    GROUPS_PATH,
    PRINCIPALS_PATH,
    REGISTRY_ALIAS_PATH,
    REGISTRY_CANONICAL_PATH,
    AdminOp,
    AliasCollision,
    EntraAdminSink,
    EntraDirectoryConfig,
    EntraDirectoryConnector,
    EntraSnapshot,
    EntraUser,
    SyncStateReset,
    build_cycle_ops,
    build_registry_ops,
    diff_snapshots,
    group_principal,
    is_active_member,
    map_member,
    run_once,
    transitive_user_closure,
)

TENANT = "8b1c8d7e-0a63-4a1a-9d1e-000000000001"

# Immutable objectId GUIDs (G2 keys) and their canonicals.
ALICE_OID = "00000000-0000-0000-0000-00000000a11c"
BOB_OID = "00000000-0000-0000-0000-00000000b0b0"
CAROL_OID = "00000000-0000-0000-0000-0000000ca401"
GUEST_OID = "00000000-0000-0000-0000-000000009857"
EXTMEMBER_OID = "00000000-0000-0000-0000-00000000e123"
DISABLED_OID = "00000000-0000-0000-0000-00000000d15a"

ALL_GID = "10000000-0000-0000-0000-0000000000a1"  # group:all
ENG_GID = "10000000-0000-0000-0000-0000000000e2"  # group:eng
LEADS_GID = "10000000-0000-0000-0000-00000000001e"  # group:eng-leads

ALICE = "user:alice@corp.example"
BOB = "user:bob@corp.example"
CAROL = "user:carol@corp.example"

ALL = group_principal(ALL_GID)
ENG = group_principal(ENG_GID)
LEADS = group_principal(LEADS_GID)


def _user(oid, upn, mail, *, user_type="Member", ext_state=None, enabled=True, creation=None):
    return {
        "id": oid,
        "userPrincipalName": upn,
        "mail": mail,
        "userType": user_type,
        "externalUserState": ext_state,
        "accountEnabled": enabled,
        "creationType": creation,
    }


def _group(oid, name, mail=None):
    return {"id": oid, "displayName": name, "mail": mail, "securityEnabled": True}


def _umember(oid):
    return {"@odata.type": "#microsoft.graph.user", "id": oid}


def _gmember(oid):
    return {"@odata.type": "#microsoft.graph.group", "id": oid}


# ---------------------------------------------------------------------------
# FixtureGraphTransport: recorded /users/delta, /groups/delta, /members pages
# ---------------------------------------------------------------------------


class FixtureGraphTransport:
    """GraphTransport backed by in-memory fixture pages.

    ``users``/``groups`` are the delta pages (a list of page dicts, the last
    carrying an ``@odata.deltaLink``). ``members`` maps a group objectId to its
    direct-member page list. ``delta_pages`` maps a saved deltaLink string to the
    pages returned when it is followed (for reconcile_delta). ``reset_links`` is a
    set of deltaLinks that raise SyncStateReset when followed."""

    def __init__(
        self,
        *,
        users=None,
        groups=None,
        members=None,
        delta_pages=None,
        reset_links=None,
    ):
        self.users_pages = users or []
        self.groups_pages = groups or []
        self.members = members or {}
        self.delta_pages = delta_pages or {}
        self.reset_links = set(reset_links or ())
        self.calls: list[tuple[str, dict]] = []

    def get_json(self, path, params):
        self.calls.append((path, dict(params)))
        # groups/{oid}/members
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "groups" and parts[2] == "members":
            pages = self.members.get(parts[1], [{"value": []}])
            return pages[0] if pages else {"value": []}
        raise AssertionError(f"unexpected Graph GET {path} {params}")

    def get_delta(self, url_or_path, params):
        self.calls.append((url_or_path, dict(params)))
        if url_or_path in self.reset_links:
            raise SyncStateReset(f"reset: {url_or_path}")
        if url_or_path == "users/delta":
            yield from self.users_pages
        elif url_or_path == "groups/delta":
            yield from self.groups_pages
        elif url_or_path in self.delta_pages:
            for page in self.delta_pages[url_or_path]:
                yield page
        else:
            # An unknown saved deltaLink with no recorded follow-up: empty, but
            # still terminal (persist the same link).
            yield {"value": [], "@odata.deltaLink": url_or_path}


def _config(**kw):
    return EntraDirectoryConfig(tenant_id=TENANT, **kw)


# The canonical first-sync fixture: all ⊃ eng ⊃ eng-leads ⊃ alice; eng ⊃ bob;
# all ⊃ carol. Three active Members (alice/bob/carol) + a guest + a #EXT# member
# + a disabled user (all excluded).
GUEST_UPN = "guest_gmail.com#EXT#@corp.onmicrosoft.com"
EXT_MEMBER_UPN = "converted#EXT#@corp.onmicrosoft.com"


def _first_sync_transport():
    users = [
        {
            "value": [
                _user(ALICE_OID, "alice@corp.example", "alice@corp.example"),
                _user(BOB_OID, "bob@corp.example", "bob@corp.example"),
                _user(CAROL_OID, "carol@corp.example", "carol@corp.example"),
                # Guest: userType Guest → excluded.
                _user(GUEST_OID, GUEST_UPN, "guest@gmail.com", user_type="Guest"),
                # Converted guest: userType Member BUT #EXT# in UPN AND
                # externalUserState set → excluded (the four-part-AND leak).
                _user(
                    EXTMEMBER_OID,
                    EXT_MEMBER_UPN,
                    "converted@gmail.com",
                    user_type="Member",
                    ext_state="Accepted",
                ),
                # Disabled internal Member → excluded.
                _user(
                    DISABLED_OID,
                    "disabled@corp.example",
                    "disabled@corp.example",
                    enabled=False,
                ),
            ],
            "@odata.deltaLink": "https://graph/users-delta-1",
        }
    ]
    groups = [
        {
            "value": [
                _group(ALL_GID, "all"),
                _group(ENG_GID, "eng"),
                _group(LEADS_GID, "eng-leads"),
            ],
            "@odata.deltaLink": "https://graph/groups-delta-1",
        }
    ]
    members = {
        ALL_GID: [{"value": [_gmember(ENG_GID), _umember(CAROL_OID)]}],
        # eng members split across two pages (large-group paging).
        ENG_GID: [
            {
                "value": [_gmember(LEADS_GID), _umember(BOB_OID)],
                "@odata.nextLink": "eng-p2",
            }
        ],
        LEADS_GID: [
            {
                "value": [
                    _umember(ALICE_OID),
                    # A device member → confers nothing (fail-closed).
                    {"@odata.type": "#microsoft.graph.device", "id": "dev-1"},
                    # The excluded users appear as members too — must be dropped.
                    _umember(GUEST_OID),
                    _umember(EXTMEMBER_OID),
                    _umember(DISABLED_OID),
                ]
            }
        ],
    }
    # eng page 2 via nextLink.
    t = FixtureGraphTransport(users=users, groups=groups, members=members)

    # Patch members paging: eng has a nextLink to a second page.
    def get_json(path, params, _orig=t.get_json):
        if path == "eng-p2":
            return {"value": []}
        return _orig(path, params)

    t.get_json = get_json
    # eng first page nextLink points at 'eng-p2' which get_json handles.
    return t


SYNC1_MEMBERSHIPS = sorted(
    [
        (ALL, ENG),
        (ALL, CAROL),
        (ENG, LEADS),
        (ENG, BOB),
        (LEADS, ALICE),
    ]
)


# ---------------------------------------------------------------------------
# t1 — reconcile: users, groups, direct edges keyed on objectId
# ---------------------------------------------------------------------------


def test_reconcile_users_lowercase_and_exclude_non_members():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    # Only the three clean active Members; guest / converted-guest / disabled gone.
    assert snap.users == [ALICE, BOB, CAROL]


def test_reconcile_membership_edges_exact_and_keyed_on_objectid():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    assert snap.memberships == SYNC1_MEMBERSHIPS
    flat = json.dumps(snap.memberships)
    # Group principals are entra-group-<objectId>, never mail/displayName.
    assert "group:entra-group-" in flat
    assert "eng@" not in flat and "displayName" not in flat
    # No excluded principal leaked into any edge.
    assert "guest@" not in flat and "converted@" not in flat and "disabled@" not in flat


def test_reconcile_never_uses_transitive_members():
    t = _first_sync_transport()
    EntraDirectoryConnector(t, _config()).reconcile()
    for path, _ in t.calls:
        assert "transitiveMembers" not in path


def test_reconcile_persists_both_delta_cursors():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    assert snap.users_delta_link == "https://graph/users-delta-1"
    assert snap.groups_delta_link == "https://graph/groups-delta-1"


def test_reconcile_populates_oid_to_canonical():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    assert snap.oid_to_canonical == {
        ALICE_OID: ALICE,
        BOB_OID: BOB,
        CAROL_OID: CAROL,
    }


# ---------------------------------------------------------------------------
# t2 — nested groups + t3 cycle (server owns closure)
# ---------------------------------------------------------------------------


def test_nested_group_edge_is_group_to_group():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    assert (ALL, ENG) in snap.memberships  # group ⊃ group preserved
    assert (ENG, LEADS) in snap.memberships


def test_transitive_closure_is_cycle_safe_and_diagnostic_only():
    cyclic = [(ALL, ENG), (ENG, ALL), (ENG, ALICE)]  # ALL ⊃ ENG ⊃ ALL
    closure = transitive_user_closure(cyclic)
    assert closure[ALL] == {ALICE} and closure[ENG] == {ALICE}


# ---------------------------------------------------------------------------
# t4 — GUEST EXCLUSION is a four-part AND (the leak cases)
# ---------------------------------------------------------------------------


def test_is_active_member_four_part_and():
    clean = EntraUser(ALICE_OID, "alice@corp.example", "alice@corp.example", "Member", None, True, None)
    assert is_active_member(clean) is True
    # userType Guest.
    assert is_active_member(EntraUser("g", "g@x", "g@x", "Guest", None, True, None)) is False
    # userType Member BUT externalUserState set (converted guest) — the leak.
    assert is_active_member(EntraUser("g", "g@x", "g@x", "Member", "Accepted", True, None)) is False
    # userType Member BUT #EXT# in UPN — the leak.
    assert is_active_member(
        EntraUser("g", "conv#EXT#@corp.onmicrosoft.com", "g@x", "Member", None, True, None)
    ) is False
    # Disabled.
    assert is_active_member(EntraUser("d", "d@x", "d@x", "Member", None, False, None)) is False
    # Null userType (limited-info member) — never read as Member.
    assert is_active_member(EntraUser("n", "n@x", "n@x", None, None, True, None)) is False
    # creationType Invitation.
    assert is_active_member(
        EntraUser("i", "i@x", "i@x", "Member", None, True, "Invitation")
    ) is False


def test_everyone_token_excludes_guests_and_ext_members():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    assert snap.everyone_members == [ALICE, BOB, CAROL]
    # The synthetic tenant token carries exactly the active Members as edges.
    ds = snap.to_directory_snapshot()
    everyone_edges = {m for (g, m) in ds.memberships if g == EVERYONE_GROUP}
    assert everyone_edges == {ALICE, BOB, CAROL}
    flat = json.dumps(ds.memberships)
    assert "guest@" not in flat and "converted@" not in flat and "disabled@" not in flat


def test_everyone_group_can_be_disabled():
    snap = EntraDirectoryConnector(
        _first_sync_transport(), _config(everyone_group_enabled=False)
    ).reconcile()
    assert snap.everyone_members == []


# ---------------------------------------------------------------------------
# map_member (fail-closed, G2/G4)
# ---------------------------------------------------------------------------


def test_map_member_user_requires_active_member_objectid():
    # The active-Member map is passed explicitly (no module global): a user resolves
    # only if its objectId is a key, i.e. it passed the four-part gate this cycle.
    active = {ALICE_OID: ALICE}
    known = frozenset({ENG_GID})
    assert map_member(ENG, _umember(ALICE_OID), active, known) == ALICE
    assert map_member(ENG, _umember("ghost-oid"), active, known) is None


def test_map_member_group_keys_on_objectid_and_skips_self():
    known = frozenset({ENG_GID, ALL_GID})
    assert map_member(ALL, _gmember(ENG_GID), {}, known) == ENG
    assert map_member(ENG, _gmember(ENG_GID), {}, known) is None  # self
    assert map_member(ALL, _gmember("unknown-gid"), {}, known) is None


def test_map_member_device_and_unknown_confer_nothing():
    known = frozenset({ENG_GID})
    assert map_member(ENG, {"@odata.type": "#microsoft.graph.device", "id": "d"}, {}, known) is None
    assert map_member(ENG, {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "s"}, {}, known) is None
    assert map_member(ENG, {"id": "no-type"}, {}, known) is None


# ---------------------------------------------------------------------------
# t5 — group typing: security group (mail null) keys on objectId
# ---------------------------------------------------------------------------


def test_security_group_with_null_mail_keys_on_objectid():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    # eng has mail=None in the fixture; its principal is still objectId-keyed.
    assert ENG == group_principal(ENG_GID)
    assert any(g == ENG for g, _ in snap.memberships)


# ---------------------------------------------------------------------------
# t6 — crosswalk / registry emission + alias quarantine alarm
# ---------------------------------------------------------------------------


def test_registry_ops_self_crosswalk_keys_on_objectid():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    ops = build_registry_ops(snap.directory_users, TENANT, "entra")
    # canonical batch first.
    assert ops[0].path == REGISTRY_CANONICAL_PATH
    # self-crosswalk local_id is the objectId (G2), not the email.
    crosswalks = [op for op in ops if op.path == CROSSWALK_PATH]
    alice_xwalk = next(op for op in crosswalks if op.body["canonical"] == ALICE)
    assert alice_xwalk.body == {
        "tenant_id": TENANT,
        "source": "entra",
        "local_id": ALICE_OID,
        "canonical": ALICE,
        "link_method": "directory_vouched",
    }


def test_alias_field_welds_declared_sso_subject():
    users = [
        {
            "value": [
                {
                    **_user(ALICE_OID, "alice@corp.example", "alice@corp.example"),
                    "onPremisesImmutableId": "ALICE-ANCHOR-b64==",
                }
            ],
            "@odata.deltaLink": "https://graph/users-delta-1",
        }
    ]
    t = FixtureGraphTransport(users=users, groups=[{"value": [], "@odata.deltaLink": "g"}])
    snap = EntraDirectoryConnector(t, _config(alias_field="onPremisesImmutableId")).reconcile()
    du = snap.directory_users[0]
    assert du.aliases[0].alias == "alice-anchor-b64=="
    assert du.aliases[0].source == "entra_declared"


def test_null_alias_field_surfaces_warning_not_silent():
    # A Member with onPremisesImmutableId absent (cloud-only tenant) under a
    # configured alias_field must emit a loud operator warning.
    conn = EntraDirectoryConnector(
        _first_sync_transport(), _config(alias_field="onPremisesImmutableId")
    )
    conn.reconcile()
    assert conn.warnings, "expected a null-alias_field warning"
    assert "onPremisesImmutableId" in conn.warnings[0]


def test_alias_quarantine_raises_fail_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == REGISTRY_ALIAS_PATH:
            return httpx.Response(
                200,
                json={
                    "upserted": [],
                    "quarantined": [
                        {"alias": "x@y", "canonical": ALICE, "reason": "alias_already_bound"}
                    ],
                },
            )
        return httpx.Response(200, json={"ok": True})

    sink = EntraAdminSink(
        "http://verity.local:8080", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(AliasCollision):
        sink.apply(
            AdminOp(
                "POST",
                REGISTRY_ALIAS_PATH,
                {"tenant_id": TENANT, "aliases": [{"canonical": ALICE, "alias": "x@y", "source": "entra_declared"}]},
            )
        )


# ---------------------------------------------------------------------------
# t7/t8 — delta fold produces a correct FULL snapshot
# ---------------------------------------------------------------------------


def _seed_snapshot():
    """A prior full snapshot to fold deltas into: alice/bob/carol, the SYNC1
    membership graph, cursors primed."""
    conn = EntraDirectoryConnector(_first_sync_transport(), _config())
    return conn.reconcile()


def test_delta_fold_applies_group_member_removal_into_full_snapshot():
    prev = _seed_snapshot()
    # /groups/delta: bob removed from eng (members@delta @removed).
    groups_delta = {
        "https://graph/groups-delta-1": [
            {
                "value": [
                    {
                        "id": ENG_GID,
                        "members@delta": [{**_umember(BOB_OID), "@removed": {"reason": "changed"}}],
                    }
                ],
                "@odata.deltaLink": "https://graph/groups-delta-2",
            }
        ]
    }
    users_delta = {
        "https://graph/users-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/users-delta-2"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    conn = EntraDirectoryConnector(t, _config())
    new = conn.reconcile_delta(prev)
    # Full snapshot: bob no longer in eng, everything else intact.
    assert (ENG, BOB) not in new.memberships
    assert (ALL, ENG) in new.memberships and (LEADS, ALICE) in new.memberships
    # Diffing prev vs new yields exactly one DELETE.
    diff = diff_snapshots(prev.to_directory_snapshot(), new.to_directory_snapshot())
    assert diff.removed_memberships == [(ENG, BOB)]
    assert diff.added_memberships == []


def test_delta_fold_applies_group_member_add_into_full_snapshot():
    prev = _seed_snapshot()
    groups_delta = {
        "https://graph/groups-delta-1": [
            {
                "value": [{"id": ENG_GID, "members@delta": [_umember(CAROL_OID)]}],
                "@odata.deltaLink": "https://graph/groups-delta-2",
            }
        ]
    }
    users_delta = {
        "https://graph/users-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/users-delta-2"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    new = EntraDirectoryConnector(t, _config()).reconcile_delta(prev)
    assert (ENG, CAROL) in new.memberships
    diff = diff_snapshots(prev.to_directory_snapshot(), new.to_directory_snapshot())
    assert diff.added_memberships == [(ENG, CAROL)]


def test_delta_large_group_members_split_across_pages_out_of_order():
    prev = _seed_snapshot()
    # The same group id (eng) recurs across pages, out of order, adding two users.
    groups_delta = {
        "https://graph/groups-delta-1": [
            {
                "value": [{"id": ENG_GID, "members@delta": [_umember(CAROL_OID)]}],
                "@odata.nextLink": "https://graph/groups-delta-1b",
            },
            {
                "value": [{"id": ENG_GID, "members@delta": [_umember(ALICE_OID)]}],
                "@odata.deltaLink": "https://graph/groups-delta-2",
            },
        ]
    }
    users_delta = {
        "https://graph/users-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/users-delta-2"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    new = EntraDirectoryConnector(t, _config()).reconcile_delta(prev)
    assert (ENG, CAROL) in new.memberships and (ENG, ALICE) in new.memberships


def test_delta_add_resolves_without_reconcile_priming():
    """Regression for the module-global leak: build ``prev`` as a bare snapshot
    (never via reconcile(), so nothing could have primed an in-process global) and
    fold a members@delta user-add. Resolution must come from the active-map threaded
    through reconcile_delta, not any process-cycle state."""
    prev = EntraSnapshot(
        users=[ALICE, BOB],
        memberships=[(ENG, ALICE)],
        oid_to_canonical={ALICE_OID: ALICE, BOB_OID: BOB},
        users_delta_link="https://graph/users-delta-1",
        groups_delta_link="https://graph/groups-delta-1",
    )
    users_delta = {
        "https://graph/users-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/users-delta-2"}
        ]
    }
    groups_delta = {
        "https://graph/groups-delta-1": [
            {
                "value": [{"id": ENG_GID, "members@delta": [_umember(BOB_OID)]}],
                "@odata.deltaLink": "https://graph/groups-delta-2",
            }
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    new = EntraDirectoryConnector(t, _config()).reconcile_delta(prev)
    assert (ENG, BOB) in new.memberships  # resolved via the folded snapshot, no global
    assert (ENG, ALICE) in new.memberships


def test_guest_added_via_delta_never_gets_an_edge():
    """The four-part G4 gate applies on the DELTA path, not just full reconcile: a
    guest added to a group via members@delta (even when it also arrives as a full
    /users/delta record) confers no principal and no edge."""
    prev = _seed_snapshot()
    guest_canonical = "user:guest@gmail.com"
    users_delta = {
        "https://graph/users-delta-1": [
            {
                "value": [_user(GUEST_OID, GUEST_UPN, "guest@gmail.com", user_type="Guest")],
                "@odata.deltaLink": "https://graph/users-delta-2",
            }
        ]
    }
    groups_delta = {
        "https://graph/groups-delta-1": [
            {
                "value": [{"id": ENG_GID, "members@delta": [_umember(GUEST_OID)]}],
                "@odata.deltaLink": "https://graph/groups-delta-2",
            }
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    new = EntraDirectoryConnector(t, _config()).reconcile_delta(prev)
    assert guest_canonical not in new.users
    assert GUEST_OID not in new.oid_to_canonical
    assert (ENG, guest_canonical) not in new.memberships
    assert all(m != guest_canonical for _, m in new.memberships)


# ---------------------------------------------------------------------------
# t9 — user-object-deletion tombstone: delete ALL edges from the persisted
#      snapshot AND deprovision, even with NO members@delta removal (the hole)
# ---------------------------------------------------------------------------


def test_user_tombstone_closes_group_delta_hole():
    prev = _seed_snapshot()
    # bob is in (ENG, BOB) in the prior snapshot. A /users/delta @removed for bob
    # arrives with NO corresponding members@delta removal in /groups/delta.
    users_delta = {
        "https://graph/users-delta-1": [
            {
                "value": [{"id": BOB_OID, "@removed": {"reason": "deleted"}}],
                "@odata.deltaLink": "https://graph/users-delta-2",
            }
        ]
    }
    groups_delta = {
        "https://graph/groups-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/groups-delta-2"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    conn = EntraDirectoryConnector(t, _config())
    new = conn.reconcile_delta(prev)
    # bob dropped from the full snapshot (canonical + every edge).
    assert BOB not in new.users
    assert BOB_OID not in new.oid_to_canonical
    assert all(m != BOB for _, m in new.memberships)

    ops = build_cycle_ops(prev, new, TENANT)
    # The persisted snapshot recorded (ENG, BOB); assert a DELETE for it AND a
    # deprovision — the edge delete comes from prev.memberships, not the delta.
    delete_bodies = [op.body for op in ops if op.method == "DELETE" and op.path == GROUPS_PATH]
    assert {"tenant_id": TENANT, "group": ENG, "member": BOB} in delete_bodies
    deprov = [op for op in ops if op.path == DEPROVISION_PATH]
    assert len(deprov) == 1 and deprov[0].body == {"tenant_id": TENANT, "principal": BOB}


def test_tombstoned_user_ops_read_edges_from_persisted_snapshot():
    from verity_ingest.connectors.entra_directory import tombstoned_user_ops

    prev = EntraSnapshot(
        users=[BOB],
        memberships=sorted([(ENG, BOB), (LEADS, BOB), (EVERYONE_GROUP, BOB)]),
        oid_to_canonical={BOB_OID: BOB},
    )
    ops = tombstoned_user_ops([BOB_OID], prev, TENANT)
    # Two real-group edge deletes (NOT the synthetic everyone edge — that is
    # recomputed from the user set) + one deprovision, deprovision last.
    deletes = [op.body for op in ops if op.method == "DELETE"]
    assert {"tenant_id": TENANT, "group": ENG, "member": BOB} in deletes
    assert {"tenant_id": TENANT, "group": LEADS, "member": BOB} in deletes
    assert ops[-1] == AdminOp("POST", DEPROVISION_PATH, {"tenant_id": TENANT, "principal": BOB})


# ---------------------------------------------------------------------------
# t10 — Member→Guest / disabled / #EXT# between cycles deprovisions
# ---------------------------------------------------------------------------


def test_member_flips_to_guest_between_cycles_deprovisions():
    prev = _seed_snapshot()
    # bob converted to a Guest (a delta change, not a tombstone).
    users_delta = {
        "https://graph/users-delta-1": [
            {
                "value": [_user(BOB_OID, "bob@corp.example", "bob@corp.example", user_type="Guest")],
                "@odata.deltaLink": "https://graph/users-delta-2",
            }
        ]
    }
    groups_delta = {
        "https://graph/groups-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/groups-delta-2"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    new = EntraDirectoryConnector(t, _config()).reconcile_delta(prev)
    assert BOB not in new.users and BOB_OID not in new.oid_to_canonical
    ops = build_cycle_ops(prev, new, TENANT)
    assert any(
        op.path == DEPROVISION_PATH and op.body["principal"] == BOB for op in ops
    )
    # bob's eng edge removed too.
    assert any(
        op.method == "DELETE" and op.body.get("member") == BOB and op.body.get("group") == ENG
        for op in ops
    )


# ---------------------------------------------------------------------------
# t11 — SyncStateReset forces full resync and does NOT checkpoint stale state
# ---------------------------------------------------------------------------


def test_sync_state_reset_propagates_and_does_not_checkpoint(tmp_path):
    prev = _seed_snapshot()
    state_file = tmp_path / "entra_snapshot.json"
    # Seed a persisted snapshot with cursors (so run_once takes the delta path).
    from verity_ingest.connectors.entra_directory import _save_snapshot

    _save_snapshot(state_file, prev, "2026-07-28T00:00:00Z")
    before = state_file.read_text()

    # The saved users deltaLink raises SyncStateReset when followed.
    t = FixtureGraphTransport(reset_links={"https://graph/users-delta-1"})
    conn = EntraDirectoryConnector(t, _config())

    from verity_ingest.connectors.entra_directory import DryRunAdminSink

    with pytest.raises(SyncStateReset):
        run_once(conn, DryRunAdminSink(io.StringIO()), state_file, now="2026-07-28T00:05:00Z")
    # Fail closed: the stale cursor state was discarded (not left as live), and
    # certainly not advanced.
    assert not state_file.exists() or state_file.read_text() != before
    assert not state_file.exists(), "SyncStateReset must discard the stale cursor, not checkpoint"


def test_http_transport_raises_sync_state_reset_on_410():
    from verity_ingest.connectors.entra_directory import HttpGraphTransport

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(410, json={"error": {"code": "syncStateNotFound"}})

    transport = HttpGraphTransport(
        lambda: "tok", client=httpx.Client(base_url="https://graph.microsoft.com/v1.0", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(SyncStateReset):
        list(transport.get_delta("https://graph/expired-link", {}))


def test_http_transport_honors_retry_after_on_429():
    from verity_ingest.connectors.entra_directory import HttpGraphTransport

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"value": [], "@odata.deltaLink": "d"})

    transport = HttpGraphTransport(
        lambda: "tok",
        client=httpx.Client(base_url="https://graph.microsoft.com/v1.0", transport=httpx.MockTransport(handler)),
    )
    pages = list(transport.get_delta("https://graph/x", {}))
    assert calls["n"] == 2 and pages[0]["@odata.deltaLink"] == "d"


# ---------------------------------------------------------------------------
# t12 — byte-exact ordered admin ops (first sync)
# ---------------------------------------------------------------------------


def test_first_sync_ops_ordered_registry_principals_adds():
    snap = EntraDirectoryConnector(_first_sync_transport(), _config()).reconcile()
    ops = build_cycle_ops(EntraSnapshot(), snap, TENANT)
    methods = [(op.method, op.path) for op in ops]
    # registry canonical leads.
    assert methods[0] == ("POST", REGISTRY_CANONICAL_PATH)
    # principals upsert appears before any group add.
    principals_idx = methods.index(("POST", PRINCIPALS_PATH))
    first_group_idx = next(i for i, m in enumerate(methods) if m == ("POST", GROUPS_PATH))
    assert principals_idx < first_group_idx
    # No removals / deprovisions on a first sync.
    assert not any(m == "DELETE" for m, _ in methods)
    assert not any(p == DEPROVISION_PATH for _, p in methods)
    # The everyone-except-guests token is emitted as group adds.
    everyone_adds = [
        op for op in ops if op.path == GROUPS_PATH and op.body.get("group") == EVERYONE_GROUP
    ]
    assert {op.body["member"] for op in everyone_adds} == {ALICE, BOB, CAROL}


# ---------------------------------------------------------------------------
# t13 — runner: dry-run never advances cursor; full replay after crash
# ---------------------------------------------------------------------------


def test_run_once_first_cycle_persists_full_snapshot(tmp_path):
    from verity_ingest.connectors.entra_directory import DryRunAdminSink

    state_file = tmp_path / "snap.json"
    applied = run_once(
        EntraDirectoryConnector(_first_sync_transport(), _config()),
        DryRunAdminSink(io.StringIO()),
        state_file,
        now="2026-07-28T08:00:00Z",
    )
    assert applied > 0
    state = json.loads(state_file.read_text())["snapshot"]
    assert state["users"] == [ALICE, BOB, CAROL]
    assert state["oid_to_canonical"] == {ALICE_OID: ALICE, BOB_OID: BOB, CAROL_OID: CAROL}
    assert state["users_delta_link"] == "https://graph/users-delta-1"


def test_dry_run_does_not_persist_snapshot(tmp_path):
    from verity_ingest.connectors.entra_directory import DryRunAdminSink

    state_file = tmp_path / "snap.json"
    run_once(
        EntraDirectoryConnector(_first_sync_transport(), _config()),
        DryRunAdminSink(io.StringIO()),
        state_file,
        persist=False,
    )
    assert not state_file.exists()


def test_run_once_no_change_second_cycle_applies_zero(tmp_path):
    from verity_ingest.connectors.entra_directory import DryRunAdminSink

    state_file = tmp_path / "snap.json"
    run_once(
        EntraDirectoryConnector(_first_sync_transport(), _config()),
        DryRunAdminSink(io.StringIO()),
        state_file,
    )
    # Second cycle: empty deltas fold to the same snapshot → zero ops.
    users_delta = {
        "https://graph/users-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/users-delta-1"}
        ]
    }
    groups_delta = {
        "https://graph/groups-delta-1": [
            {"value": [], "@odata.deltaLink": "https://graph/groups-delta-1"}
        ]
    }
    t = FixtureGraphTransport(delta_pages={**users_delta, **groups_delta})
    applied = run_once(
        EntraDirectoryConnector(t, _config()), DryRunAdminSink(io.StringIO()), state_file
    )
    assert applied == 0


def test_crash_before_checkpoint_replays_cycle(tmp_path):
    state_file = tmp_path / "snap.json"

    class ExplodingSink:
        def __init__(self):
            self.applied = 0

        def apply(self, op):
            self.applied += 1
            if self.applied == 2:
                raise httpx.HTTPStatusError("boom", request=None, response=None)

    with pytest.raises(httpx.HTTPStatusError):
        run_once(EntraDirectoryConnector(_first_sync_transport(), _config()), ExplodingSink(), state_file)
    assert not state_file.exists()  # nothing checkpointed → full replay next run


# ---------------------------------------------------------------------------
# Auth guardrail (no real credentials, ever; msal is never imported)
# ---------------------------------------------------------------------------


def test_load_graph_credentials_requires_tenant_and_client():
    from verity_ingest.connectors.entra_directory import load_graph_credentials

    with pytest.raises(RuntimeError, match="ENTRA_TENANT_ID"):
        load_graph_credentials(EntraDirectoryConfig(tenant_id=TENANT))
