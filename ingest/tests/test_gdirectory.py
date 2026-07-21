"""Google Workspace directory-sync conformance tests (SPEC.md §6a/§6c:
identity-mapping conformance is load-bearing and gates release).

All Admin SDK payloads are recorded fixtures authored from Google's
documented resource shapes (developers.google.com, Admin SDK Directory API
v1: users.list / groups.list / members.list). No live API calls and no real
credentials anywhere in this file.

The fixture directory satisfies §6c: nested groups three levels deep
(all ⊃ eng ⊃ eng-leads ⊃ alice), a membership CYCLE (loop-a ⊃ loop-b ⊃
loop-a — closure must terminate), a suspended (deprovisioned) user
(mallory), and an email-only unverifiable external member (partner@outside).
The conformance assertions are byte-exact expected admin-endpoint bodies —
including the DENIALS for the suspended and unverifiable users.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest

from verity_ingest.connectors.gdirectory import (
    CONNECTOR_STATUS_PATH,
    CROSSWALK_PATH,
    DEPROVISION_PATH,
    GROUPS_PATH,
    PRINCIPALS_PATH,
    REGISTRY_ALIAS_PATH,
    REGISTRY_CANONICAL_PATH,
    AdminOp,
    DirectorySnapshot,
    DirectoryUser,
    DryRunAdminSink,
    GDirectoryConfig,
    GDirectoryConnector,
    SsoAlias,
    VerityAdminSink,
    build_admin_ops,
    build_registry_ops,
    diff_snapshots,
    load_directory_credentials,
    map_member,
    run_once,
    transitive_user_closure,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gdirectory"

# The server's TenantId is a UUID; the connector treats it as opaque.
TENANT = "8b1c8d7e-0a63-4a1a-9d1e-000000000001"

ALL = "group:all@corp.example"
ENG = "group:eng@corp.example"
LEADS = "group:eng-leads@corp.example"
LOOP_A = "group:loop-a@corp.example"
LOOP_B = "group:loop-b@corp.example"
ALICE = "user:alice@corp.example"
BOB = "user:bob@corp.example"
CAROL = "user:carol@corp.example"
DOMAIN = "domain:corp.example"

# Direct edges only — nesting is delivered as group⊃group tuples; SpiceDB
# owns the closure (includeDerivedMembership is deliberately not used).
SYNC1_MEMBERSHIPS = [
    (ALL, DOMAIN),  # type=CUSTOMER → domain:<config.domain>
    (ALL, ENG),  # nested: level 1
    (ALL, CAROL),
    (LEADS, ALICE),  # nested: level 3 leaf
    (ENG, LEADS),  # nested: level 2
    (ENG, BOB),
    (LOOP_A, LOOP_B),  # cycle edge 1
    (LOOP_B, LOOP_A),  # cycle edge 2
    (LOOP_B, BOB),
]

SYNC1_PRINCIPALS = sorted({ALICE, BOB, CAROL, ALL, ENG, LEADS, LOOP_A, LOOP_B, DOMAIN})

# M2 2b — the active-user registry records the reconcile populates (sorted by
# primary email). Alice carries an admin-declared SSO alias from a custom-typed
# externalId (lowercased); Bob/Carol carry none. mallory (suspended) is absent.
SYNC1_DIRECTORY_USERS = [
    DirectoryUser(
        directory_id="100000000000000000001",
        primary_email="alice@corp.example",
        aliases=(SsoAlias(alias="alice.sso@corp.example", source="google_externalid"),),
    ),
    DirectoryUser(directory_id="100000000000000000002", primary_email="bob@corp.example"),
    DirectoryUser(directory_id="100000000000000000004", primary_email="carol@corp.example"),
]

# The registry ops that lead every populate cycle: canonical rows → alias rows →
# self-crosswalk rows (in that order — canonical must exist before its refs).
SYNC1_REGISTRY_OPS = build_registry_ops(SYNC1_DIRECTORY_USERS, TENANT)


def _config() -> GDirectoryConfig:
    return GDirectoryConfig(tenant_id=TENANT, domain="corp.example")


class FixtureTransport:
    """DirectoryTransport backed by recorded JSON fixtures.

    ``dirs`` are searched in order, so a second-sync directory only carries
    the pages that changed and falls back to the first sync for the rest.
    """

    def __init__(self, *dirs: Path) -> None:
        self.dirs = dirs
        self.calls: list[tuple[str, dict]] = []

    def _route(self, path: str, params: dict) -> str:
        token = params.get("pageToken")
        if path == "users":
            return "users_page2.json" if token == "users-p2" else "users_page1.json"
        if path == "groups":
            return "groups_page1.json"
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "groups" and parts[2] == "members":
            key = parts[1].split("@")[0].replace("-", "")
            if key == "eng":
                return "members_eng_page2.json" if token == "eng-p2" else "members_eng_page1.json"
            return f"members_{key}.json"
        raise AssertionError(f"unexpected Directory call: GET {path} {params}")

    def get_json(self, path: str, params: dict) -> dict:
        self.calls.append((path, dict(params)))
        name = self._route(path, params)
        for directory in self.dirs:
            candidate = directory / name
            if candidate.exists():
                return json.loads(candidate.read_text())
        raise AssertionError(f"no fixture {name} in {self.dirs}")


def _sync1_transport() -> FixtureTransport:
    return FixtureTransport(FIXTURES / "sync1")


def _sync2_transport() -> FixtureTransport:
    return FixtureTransport(FIXTURES / "sync2", FIXTURES / "sync1")


# ---------------------------------------------------------------------------
# Reconcile: users, groups, direct membership edges
# ---------------------------------------------------------------------------


def test_reconcile_users_paginate_lowercase_and_exclude_suspended():
    snapshot = GDirectoryConnector(_sync1_transport(), _config()).reconcile()
    # Alice@ is lowercased; mallory (suspended: true) is deprovisioned —
    # absent from the desired snapshot, always (§6c denial).
    assert snapshot.users == [ALICE, BOB, CAROL]


def test_reconcile_membership_tuples_exact_direct_edges():
    snapshot = GDirectoryConnector(_sync1_transport(), _config()).reconcile()
    # Byte-exact canonical tuples (§6c), including the denials: neither the
    # suspended mallory nor the unverifiable partner@outside.example (type
    # EXTERNAL) appears anywhere.
    assert snapshot.memberships == sorted(SYNC1_MEMBERSHIPS)
    flat = json.dumps(snapshot.memberships)
    assert "mallory" not in flat
    assert "partner@outside.example" not in flat


def test_reconcile_never_uses_derived_membership_and_asks_minimal_fields():
    transport = _sync1_transport()
    GDirectoryConnector(transport, _config()).reconcile()
    for path, params in transport.calls:
        assert "includeDerivedMembership" not in params  # nesting stays intact
        assert "fields" in params  # field-mask discipline


def test_member_pagination_is_followed():
    transport = _sync1_transport()
    GDirectoryConnector(transport, _config()).reconcile()
    eng_calls = [p for path, p in transport.calls if path == "groups/eng@corp.example/members"]
    assert [c.get("pageToken") for c in eng_calls] == [None, "eng-p2"]


# ---------------------------------------------------------------------------
# Member mapping (fail-closed, §6b)
# ---------------------------------------------------------------------------

ACTIVE = frozenset({"alice@corp.example"})
GROUPS = frozenset({"eng@corp.example", "all@corp.example"})


def test_map_member_user_requires_directory_active_email():
    member = {"type": "USER", "email": "Alice@corp.example"}
    assert map_member(ENG, member, ACTIVE, GROUPS, "corp.example") == ALICE
    ghost = {"type": "USER", "email": "ghost@corp.example"}  # never vouched
    assert map_member(ENG, ghost, ACTIVE, GROUPS, "corp.example") is None


def test_map_member_nested_group_requires_known_group_and_skips_self():
    inner = {"type": "GROUP", "email": "eng@corp.example"}
    assert map_member(ALL, inner, ACTIVE, GROUPS, None) == ENG
    # Self-membership: the server 422s it; never emitted.
    assert map_member(ENG, inner, ACTIVE, GROUPS, None) is None
    foreign = {"type": "GROUP", "email": "strangers@outside.example"}
    assert map_member(ALL, foreign, ACTIVE, GROUPS, None) is None


def test_map_member_customer_needs_configured_domain():
    member = {"type": "CUSTOMER", "id": "C03az79cb"}
    assert map_member(ALL, member, ACTIVE, GROUPS, "corp.example") == DOMAIN
    assert map_member(ALL, member, ACTIVE, GROUPS, None) is None  # fail-closed


def test_map_member_external_and_unknown_types_confer_nothing():
    assert (
        map_member(ENG, {"type": "EXTERNAL", "email": "p@x.example"}, ACTIVE, GROUPS, "x") is None
    )
    assert (
        map_member(ENG, {"type": "SERVICE_ACCOUNT?", "email": "a@x"}, ACTIVE, GROUPS, "x") is None
    )


# ---------------------------------------------------------------------------
# Local closure: cycle-safe, diagnostics-only
# ---------------------------------------------------------------------------


def test_transitive_closure_three_levels_and_cycle_terminates():
    closure = transitive_user_closure(SYNC1_MEMBERSHIPS)
    assert closure == {
        ALL: {ALICE, BOB, CAROL},  # alice via eng⊃eng-leads: 3 levels deep
        ENG: {ALICE, BOB},
        LEADS: {ALICE},
        LOOP_A: {BOB},  # via loop-b, despite loop-b ⊃ loop-a ⊃ loop-b …
        LOOP_B: {BOB},
    }


def test_closure_treats_domain_principal_as_opaque():
    closure = transitive_user_closure([(ALL, DOMAIN)])
    assert closure == {ALL: set()}  # domain:* is its own principal, not users


# ---------------------------------------------------------------------------
# Diff-and-apply: exact admin-endpoint bodies (server as built)
# ---------------------------------------------------------------------------


def test_first_sync_ops_exact():
    snapshot = GDirectoryConnector(_sync1_transport(), _config()).reconcile()
    ops = build_admin_ops(diff_snapshots(DirectorySnapshot(), snapshot), TENANT)
    n_reg = len(SYNC1_REGISTRY_OPS)
    # M2 2b — registry populate leads the cycle (canonical → alias → crosswalk).
    assert ops[:n_reg] == SYNC1_REGISTRY_OPS
    assert ops[n_reg] == AdminOp(
        "POST", PRINCIPALS_PATH, {"tenant_id": TENANT, "principals": SYNC1_PRINCIPALS}
    )
    assert ops[n_reg + 1 :] == [
        AdminOp("POST", GROUPS_PATH, {"tenant_id": TENANT, "group": g, "member": m})
        for g, m in sorted(SYNC1_MEMBERSHIPS)
    ]


def test_reconcile_populates_directory_users_with_aliases():
    snapshot = GDirectoryConnector(_sync1_transport(), _config()).reconcile()
    # M2 2b — full active-user records for the registry populate, aliases from the
    # custom-typed externalId only (organization-typed id is ignored), lowercased.
    assert snapshot.directory_users == SYNC1_DIRECTORY_USERS


def test_registry_ops_order_canonical_then_alias_then_crosswalk():
    # canonical rows first (one batched POST), then aliases (one batched POST for
    # the users that HAVE aliases), then a self-crosswalk POST per user.
    assert [(op.method, op.path) for op in SYNC1_REGISTRY_OPS] == [
        ("POST", REGISTRY_CANONICAL_PATH),
        ("POST", REGISTRY_ALIAS_PATH),
        ("POST", CROSSWALK_PATH),  # alice
        ("POST", CROSSWALK_PATH),  # bob
        ("POST", CROSSWALK_PATH),  # carol
    ]
    canonical = SYNC1_REGISTRY_OPS[0].body
    assert canonical["principals"][0] == {
        "canonical": ALICE,
        "kind": "user",
        "idp_subject": "alice@corp.example",
        "active": True,
    }
    # Exactly one alias row (alice's SSO externalId); bob/carol have none.
    assert SYNC1_REGISTRY_OPS[1].body["aliases"] == [
        {"canonical": ALICE, "alias": "alice.sso@corp.example", "source": "google_externalid"}
    ]
    # The self-crosswalk keys the directory id → canonical, directory_vouched.
    assert SYNC1_REGISTRY_OPS[2].body == {
        "tenant_id": TENANT,
        "source": "gdirectory",
        "local_id": "100000000000000000001",
        "canonical": ALICE,
        "link_method": "directory_vouched",
    }


def test_custom_schema_alias_read_under_projection_custom():
    # With an alias_schema configured, projection=custom + customFieldMask are
    # sent, and customSchemas values become google_customschema aliases.
    fixture_user = {
        "id": "100000000000000000009",
        "primaryEmail": "dave@corp.example",
        "customSchemas": {"verity": {"samlSubject": "dave.saml@corp.example"}},
    }

    class OneUserTransport:
        def __init__(self):
            self.calls = []

        def get_json(self, path, params):
            self.calls.append((path, dict(params)))
            if path == "users":
                return {"users": [fixture_user]}
            return {}  # no groups

    transport = OneUserTransport()
    config = GDirectoryConfig(tenant_id=TENANT, domain="corp.example", alias_schema="verity")
    snapshot = GDirectoryConnector(transport, config).reconcile()
    user_params = next(p for path, p in transport.calls if path == "users")
    assert user_params["projection"] == "custom"
    assert user_params["customFieldMask"] == "verity"
    assert snapshot.directory_users == [
        DirectoryUser(
            directory_id="100000000000000000009",
            primary_email="dave@corp.example",
            aliases=(SsoAlias(alias="dave.saml@corp.example", source="google_customschema"),),
        )
    ]


def test_second_sync_diff_emits_single_tombstoning_delete(tmp_path):
    config = _config()
    first = GDirectoryConnector(_sync1_transport(), config).reconcile()
    second = GDirectoryConnector(_sync2_transport(), config).reconcile()
    ops = build_admin_ops(diff_snapshots(first, second), TENANT)
    # bob left eng@: no principal upsert, no adds, exactly one DELETE — the
    # endpoint that writes revocation tombstones before the tuple delete.
    assert ops == [
        AdminOp("DELETE", GROUPS_PATH, {"tenant_id": TENANT, "group": ENG, "member": BOB})
    ]


def test_suspension_between_syncs_removes_every_membership_and_deprovisions():
    bob_user = DirectoryUser(directory_id="002", primary_email="bob@corp.example")
    alice_user = DirectoryUser(directory_id="001", primary_email="alice@corp.example")
    before = DirectorySnapshot(
        users=[ALICE, BOB],
        memberships=sorted([(ENG, BOB), (LOOP_B, BOB), (ENG, ALICE)]),
        directory_users=[alice_user, bob_user],
    )
    after = DirectorySnapshot(
        users=[ALICE], memberships=[(ENG, ALICE)], directory_users=[alice_user]
    )
    diff = diff_snapshots(before, after)
    assert diff.added_principals == [] and diff.added_memberships == []
    # Deprovision ⇒ all tuples removed (tombstoned server-side) AND bob fires a
    # /v1/admin/deprovision op (canonical inactive + durable 2a revoke).
    assert diff.removed_memberships == [(ENG, BOB), (LOOP_B, BOB)]
    assert diff.deprovisioned == ["bob@corp.example"]
    assert diff.registry_users == []  # alice unchanged → no re-populate
    ops = build_admin_ops(diff, TENANT)
    assert ops[-1] == AdminOp(
        "POST", DEPROVISION_PATH, {"tenant_id": TENANT, "principal": BOB}
    )


def test_ops_order_registry_then_principals_then_adds_then_removals_then_deprovision():
    new_bob = DirectoryUser(directory_id="002", primary_email="bob@corp.example")
    gone_carol = DirectoryUser(directory_id="004", primary_email="carol@corp.example")
    diff = diff_snapshots(
        DirectorySnapshot(
            users=[ALICE, CAROL], memberships=[(ENG, ALICE)], directory_users=[gone_carol]
        ),
        DirectorySnapshot(
            users=[ALICE, BOB], memberships=[(ENG, BOB)], directory_users=[new_bob]
        ),
    )
    ops = build_admin_ops(diff, TENANT)
    assert [(op.method, op.path) for op in ops] == [
        ("POST", REGISTRY_CANONICAL_PATH),  # populate new bob
        ("POST", CROSSWALK_PATH),
        ("POST", PRINCIPALS_PATH),
        ("POST", GROUPS_PATH),
        ("DELETE", GROUPS_PATH),
        ("POST", DEPROVISION_PATH),  # carol went active→absent
    ]
    assert ops[2].body == {"tenant_id": TENANT, "principals": [BOB]}
    assert ops[-1].body == {"tenant_id": TENANT, "principal": CAROL}


# ---------------------------------------------------------------------------
# Sinks: HTTP contract + heartbeat
# ---------------------------------------------------------------------------


def _mock_sink(handler) -> VerityAdminSink:
    return VerityAdminSink(
        "http://verity.local:8080", client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def test_verity_admin_sink_posts_and_deletes_with_json_bodies():
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"written": True, "tokens": {}})

    sink = _mock_sink(handler)
    add = {"tenant_id": TENANT, "group": ENG, "member": BOB}
    sink.apply(AdminOp("POST", GROUPS_PATH, add))
    sink.apply(AdminOp("DELETE", GROUPS_PATH, add))  # DELETE carries a body
    assert seen == [("POST", GROUPS_PATH, add), ("DELETE", GROUPS_PATH, add)]


def test_verity_admin_sink_raises_on_rejection():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "group management requires ReBAC"})

    with pytest.raises(httpx.HTTPStatusError):
        _mock_sink(handler).apply(
            AdminOp("POST", GROUPS_PATH, {"tenant_id": TENANT, "group": ENG, "member": BOB})
        )


def test_verity_admin_sink_heartbeat_reports_batch_then_resets():
    posted: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"recorded": True})

    sink = _mock_sink(handler)
    sink.apply(AdminOp("POST", GROUPS_PATH, {"tenant_id": TENANT, "group": ENG, "member": BOB}))
    sink.heartbeat(cursor="2026-07-11T00:00:00Z")
    assert posted[-1] == (
        CONNECTOR_STATUS_PATH,
        {
            "tenant_id": TENANT,
            "source": "gdirectory",
            "items_synced": 1,
            "cursor": "2026-07-11T00:00:00Z",
        },
    )
    calls_before = len(posted)
    sink.heartbeat(cursor="later")  # nothing applied since: posts nothing
    assert len(posted) == calls_before


# ---------------------------------------------------------------------------
# Runner: snapshot checkpointing (at-least-once)
# ---------------------------------------------------------------------------


def test_run_once_first_cycle_applies_all_then_second_cycle_deletes_one(tmp_path):
    state_file = tmp_path / "gdirectory_snapshot.json"
    config = _config()

    sink = DryRunAdminSink(stream=io.StringIO())
    applied = run_once(
        GDirectoryConnector(_sync1_transport(), config),
        sink,
        state_file,
        now="2026-07-11T08:00:00Z",
    )
    # M2 2b — registry ops + principals POST + 9 membership adds.
    assert applied == len(SYNC1_REGISTRY_OPS) + 1 + len(SYNC1_MEMBERSHIPS)
    state = json.loads(state_file.read_text())
    assert state["last_reconcile_at"] == "2026-07-11T08:00:00Z"
    assert state["snapshot"]["users"] == [ALICE, BOB, CAROL]
    assert [tuple(m) for m in state["snapshot"]["memberships"]] == sorted(SYNC1_MEMBERSHIPS)
    # The active-user registry records are checkpointed so the next cycle can
    # diff for changes/deprovisions.
    assert [u["primary_email"] for u in state["snapshot"]["directory_users"]] == [
        "alice@corp.example",
        "bob@corp.example",
        "carol@corp.example",
    ]

    sink = DryRunAdminSink(stream=io.StringIO())
    applied = run_once(
        GDirectoryConnector(_sync2_transport(), config),
        sink,
        state_file,
        now="2026-07-11T08:05:00Z",
    )
    assert applied == 1
    assert sink.ops == [
        AdminOp("DELETE", GROUPS_PATH, {"tenant_id": TENANT, "group": ENG, "member": BOB})
    ]
    state = json.loads(state_file.read_text())
    assert [ENG, BOB] not in state["snapshot"]["memberships"]


def test_dry_run_does_not_persist_snapshot(tmp_path):
    """A dry run (persist=False) must NOT advance the snapshot: it delivered
    nothing, so the NEXT real sync must still apply every op instead of diffing
    against un-applied state and no-opping to zero (the poisoning we hit live)."""
    state_file = tmp_path / "gdirectory_snapshot.json"
    config = _config()

    # Dry run: the full op set is still computed, but no snapshot is written.
    applied = run_once(
        GDirectoryConnector(_sync1_transport(), config),
        DryRunAdminSink(stream=io.StringIO()),
        state_file,
        now="2026-07-11T08:00:00Z",
        persist=False,
    )
    assert applied == len(SYNC1_REGISTRY_OPS) + 1 + len(SYNC1_MEMBERSHIPS)
    assert not state_file.exists(), "a dry run must leave no snapshot behind"

    # The following REAL sync starts clean and applies EVERYTHING, not zero.
    applied_real = run_once(
        GDirectoryConnector(_sync1_transport(), config),
        DryRunAdminSink(stream=io.StringIO()),
        state_file,
        now="2026-07-11T08:01:00Z",
    )
    expected = len(SYNC1_REGISTRY_OPS) + 1 + len(SYNC1_MEMBERSHIPS)
    assert applied_real == expected, "real sync after a dry run must not no-op"
    assert state_file.exists(), "a real sync persists the snapshot"


def test_run_once_reconverges_after_no_change():
    """A cycle with no directory change applies zero ops (idempotent diff)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        state_file = Path(tmp) / "snap.json"
        config = _config()
        run_once(
            GDirectoryConnector(_sync1_transport(), config),
            DryRunAdminSink(io.StringIO()),
            state_file,
        )
        applied = run_once(
            GDirectoryConnector(_sync1_transport(), config),
            DryRunAdminSink(io.StringIO()),
            state_file,
        )
        assert applied == 0


def test_run_once_crash_before_checkpoint_replays_cycle(tmp_path):
    """A sink failure aborts before the snapshot checkpoint: the next run
    replays the whole cycle (at-least-once; every op is idempotent)."""
    state_file = tmp_path / "snap.json"

    class ExplodingSink:
        def __init__(self) -> None:
            self.applied = 0

        def apply(self, op: AdminOp) -> None:
            self.applied += 1
            if self.applied == 3:
                raise httpx.HTTPStatusError("boom", request=None, response=None)

    connector = GDirectoryConnector(_sync1_transport(), _config())
    with pytest.raises(httpx.HTTPStatusError):
        run_once(connector, ExplodingSink(), state_file)
    assert not state_file.exists()  # nothing checkpointed

    sink = DryRunAdminSink(stream=io.StringIO())
    applied = run_once(GDirectoryConnector(_sync1_transport(), _config()), sink, state_file)
    assert applied == len(SYNC1_REGISTRY_OPS) + 1 + len(SYNC1_MEMBERSHIPS)  # full replay


# ---------------------------------------------------------------------------
# Auth guardrails (no real credentials, ever)
# ---------------------------------------------------------------------------


def test_delegated_subject_is_required_for_live_credentials():
    with pytest.raises(RuntimeError, match="GADMIN_DELEGATED_SUBJECT"):
        load_directory_credentials(None)
