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
    GROUPS_PATH,
    PRINCIPALS_PATH,
    AdminOp,
    DirectorySnapshot,
    DryRunAdminSink,
    GDirectoryConfig,
    GDirectoryConnector,
    VerityAdminSink,
    build_admin_ops,
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
    assert ops[0] == AdminOp(
        "POST", PRINCIPALS_PATH, {"tenant_id": TENANT, "principals": SYNC1_PRINCIPALS}
    )
    assert ops[1:] == [
        AdminOp("POST", GROUPS_PATH, {"tenant_id": TENANT, "group": g, "member": m})
        for g, m in sorted(SYNC1_MEMBERSHIPS)
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


def test_suspension_between_syncs_removes_every_membership():
    before = DirectorySnapshot(
        users=[ALICE, BOB],
        memberships=sorted([(ENG, BOB), (LOOP_B, BOB), (ENG, ALICE)]),
    )
    after = DirectorySnapshot(users=[ALICE], memberships=[(ENG, ALICE)])
    diff = diff_snapshots(before, after)
    assert diff.added_principals == [] and diff.added_memberships == []
    # Deprovision ⇒ all tuples removed (tombstoned server-side); the bare
    # user: token stays allocated but grants nothing (no retire endpoint).
    assert diff.removed_memberships == [(ENG, BOB), (LOOP_B, BOB)]


def test_ops_order_principals_then_adds_then_removals():
    diff = diff_snapshots(
        DirectorySnapshot(users=[ALICE], memberships=[(ENG, ALICE)]),
        DirectorySnapshot(users=[ALICE, BOB], memberships=[(ENG, BOB)]),
    )
    ops = build_admin_ops(diff, TENANT)
    assert [(op.method, op.path) for op in ops] == [
        ("POST", PRINCIPALS_PATH),
        ("POST", GROUPS_PATH),
        ("DELETE", GROUPS_PATH),
    ]
    assert ops[0].body == {"tenant_id": TENANT, "principals": [BOB]}


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
    assert applied == 1 + len(SYNC1_MEMBERSHIPS)  # principals POST + 9 adds
    state = json.loads(state_file.read_text())
    assert state["last_reconcile_at"] == "2026-07-11T08:00:00Z"
    assert state["snapshot"]["users"] == [ALICE, BOB, CAROL]
    assert [tuple(m) for m in state["snapshot"]["memberships"]] == sorted(SYNC1_MEMBERSHIPS)

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
    assert applied == 1 + len(SYNC1_MEMBERSHIPS)  # full replay, safely idempotent


# ---------------------------------------------------------------------------
# Auth guardrails (no real credentials, ever)
# ---------------------------------------------------------------------------


def test_delegated_subject_is_required_for_live_credentials():
    with pytest.raises(RuntimeError, match="GADMIN_DELEGATED_SUBJECT"):
        load_directory_credentials(None)
