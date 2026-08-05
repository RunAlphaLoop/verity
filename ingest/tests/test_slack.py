"""Slack connector conformance tests — leak cases first.

All Slack payloads are fixtures authored from the documented Web API response
shapes (users.list, conversations.list/members/history/replies, cursor
pagination via response_metadata.next_cursor, the {"ok": false} envelope,
HTTP 429 + Retry-After). No live API calls and no credentials anywhere in
this file.

The suite exercises the red-teamed LEAK cases, not just happy paths:

- G1: a shared / externally-shared / org-shared / pending-Slack-Connect
  channel quarantines WHOLE — no content, no membership edges, and a
  mirrored→quarantined transition retires everything previously indexed; a
  conversation shape the code does not recognize quarantines too; im/mpim
  are skipped AND counted, never silent;
- G2: a bot, a guest (is_restricted / is_ultra_restricted), a deleted user,
  and a member without a vouched profile.email confer NOTHING — no crosswalk
  row, no membership edge (narrowing, never poison); a member whose canonical
  does not ALREADY exist in the registry also confers nothing, and slack
  NEVER emits a canonical-creation op (profile.email is admin-mutable — Slack
  must not mint identity); Slack's word never fires a tenant-wide
  deprovision;
- L1 (the monotonic-supersede guard): the server retires only rows strictly
  OLDER than the incoming valid_from and replays ride its conflict-DO-NOTHING,
  so deleting the latest reply (stamp regresses) and editing the latest
  message (stamp unchanged — Slack edits keep ts) must ADVANCE valid_from
  past the last delivered stamp; unchanged content is skipped, and a replay
  of the same delivered version stays idempotent;
- G3: membership rides the reused gdirectory diff engine — byte-exact
  registry/crosswalk/principals/groups bodies, removals as one-at-a-time
  DELETEs;
- G4: a deleted thread / deleted channel / quarantine transition is PARKED
  in slack_parked_retractions.json and DRAINED as a byte-exact
  POST /v1/admin/retire replay; the sharepoint race guards hold verbatim
  (pre-existing ledger drains BEFORE delivery; a restored document UNPARKS
  its stale retraction); a failed replay stays parked + alarmed;
- quarantined bodies carry NO visibility (and no content);
- thread re-ingest supersedes (same document_id, newer valid_from);
- idle cycles heartbeat items_synced:0 with source="slack"; the
  reconcile_overdue alarm fires while no zero-failure backfill is fresh;
- the backfill reconcile sweeps gap-deletions the poll cannot see, resumes
  from per-channel cursors, and stamps last_reconcile_at ONLY on a
  zero-failure pass.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import httpx
import pytest

from verity_ingest import crosswalk
from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gdirectory import AdminOp
from verity_ingest.connectors.gdrive import DryRunSink
from verity_ingest.connectors.slack import (
    MIRRORED,
    QUARANTINED,
    RETIRE_PATH,
    SKIPPED_IM,
    SLACK_API_BASE_URL,
    HttpSlackTransport,
    SlackApiError,
    SlackConfig,
    SlackConnector,
    SlackDocumentEvent,
    SlackStatusSink,
    StaticSlackRegistry,
    build_slack_admin_ops,
    build_slack_document_request,
    channel_principal,
    classify_channel,
    content_digest,
    load_slack_credentials,
    map_slack_user,
    render_transcript,
    run_backfill,
    run_once,
    thread_document_id,
)

TENANT = "t-acme"

C_GEN = "C0GEN"
C_PRIV = "C0PRIV"
C_SHARED = "C0SHARED"

GEN_GROUP = channel_principal(C_GEN)  # group:slack-channel-C0GEN
PRIV_GROUP = channel_principal(C_PRIV)

# The G2 weld gate: user canonicals in the map ALREADY exist in the registry
# (a real directory sync vouched them); a member email absent here fails the
# existence check and confers nothing.
REGISTRY_MAP = {
    GEN_GROUP: 111,
    PRIV_GROUP: 222,
    "user:alice@acme.com": 1001,
    "user:bob@acme.com": 1002,
}

# Raw Slack ts values and their ISO renderings (epoch 1700000000 =
# 2023-11-14T22:13:20Z; the connector renders second resolution).
TS_BEFORE = "1699999000.000000"
TS_ROOT = "1700000000.000100"
ISO_ROOT = "2023-11-14T22:13:20Z"
TS_REPLY = "1700000100.000200"
ISO_REPLY = "2023-11-14T22:15:00Z"
TS_SOLO = "1700000200.000300"
ISO_SOLO = "2023-11-14T22:16:40Z"
TS_EDIT = "1700000300.000400"
ISO_EDIT = "2023-11-14T22:18:20Z"

_CLOCK_NOW = datetime(2023, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
NOW_ISO = "2023-11-15T00:00:00Z"
RECENT_RECONCILE = "2023-11-14T23:00:00Z"  # 1h before the clock: within the SLA


def _clock() -> datetime:
    return _CLOCK_NOW


# ---------------------------------------------------------------------------
# Fixture builders (Slack Web API shapes)
# ---------------------------------------------------------------------------


def _member(uid: str, email: str | None, **flags) -> dict:
    profile: dict = {"display_name": flags.pop("display", ""), "real_name": flags.pop("real", "")}
    if email:
        profile["email"] = email
    return {"id": uid, "name": uid.lower(), "profile": profile, **flags}


ALICE = _member("U0ALICE", "alice@acme.com", display="Alice")
BOB = _member("U0BOB", "bob@acme.com", real="Bob Builder")
# The leak cases: an email is NOT enough — bots, guests, and deleted users
# carry one too and must still confer nothing (G2).
BOT = _member("U0BOT", "bot@acme.com", is_bot=True, display="Robo")
GUEST = _member("U0GUEST", "guest@ext.example", is_restricted=True)
ULTRA = _member("U0ULTRA", "ultra@ext.example", is_ultra_restricted=True)
NOMAIL = _member("U0NOMAIL", None, display="Ghost")
GONE = _member("U0GONE", "gone@acme.com", deleted=True)

ALL_USERS = [ALICE, BOB, BOT, GUEST, ULTRA, NOMAIL, GONE]


def _channel(cid: str, name: str, **flags) -> dict:
    base = {
        "id": cid,
        "name": name,
        "is_channel": True,
        "is_private": False,
        "is_member": True,
        "is_shared": False,
        "is_ext_shared": False,
        "is_org_shared": False,
        "is_im": False,
        "is_mpim": False,
    }
    base.update(flags)
    return base


def _msg(ts: str, user: str, text: str, **kw) -> dict:
    return {"type": "message", "ts": ts, "user": user, "text": text, **kw}


THREAD_ROOT = _msg(TS_ROOT, "U0ALICE", "kickoff", thread_ts=TS_ROOT, reply_count=1)
THREAD_REPLY = _msg(TS_REPLY, "U0BOB", "reply", thread_ts=TS_ROOT)
SOLO_MSG = _msg(TS_SOLO, "U0BOB", "solo note")

# The default workspace's rendered transcripts (bookkeeping digests are taken
# over these exact bytes).
GEN_TRANSCRIPT = f"[{ISO_ROOT}] Alice: kickoff\n[{ISO_REPLY}] Bob Builder: reply"
SOLO_TRANSCRIPT = f"[{ISO_SOLO}] Bob Builder: solo note"


def _entry(delivered: str, text: str) -> dict:
    """One bookkept thread entry: the delivered valid_from + content digest."""
    return {"delivered": delivered, "digest": content_digest(text.encode())}


class FixtureSlackTransport:
    """SlackTransport backed by in-memory routes.

    ``routes`` maps a Web API method name to a response dict, a callable
    ``params -> dict``, or a :class:`SlackApiError` to raise. Calls are
    recorded so tests can assert what was (and was NOT) fetched — the
    ACL-before-content and skip-not-silent claims are call-log claims."""

    def __init__(self, routes) -> None:
        self.routes = dict(routes)
        self.calls: list[tuple[str, dict]] = []

    def call(self, method: str, params) -> dict:
        self.calls.append((method, dict(params)))
        route = self.routes.get(method)
        if route is None:
            raise AssertionError(f"unexpected slack call {method} {params}")
        result = route(dict(params)) if callable(route) else route
        if isinstance(result, SlackApiError):
            raise result
        return dict(result)

    def called(self, method: str, **param_filter) -> list[dict]:
        return [
            p
            for m, p in self.calls
            if m == method and all(p.get(k) == v for k, v in param_filter.items())
        ]


def _by_channel(mapping: dict):
    """Route conversations.history / conversations.members by channel id."""

    def route(params: dict):
        cid = params.get("channel")
        if cid not in mapping:
            raise AssertionError(f"unexpected channel fetch {cid} {params}")
        value = mapping[cid]
        result = value(params) if callable(value) else value
        if isinstance(result, SlackApiError):
            raise result
        if isinstance(result, list):
            return {"ok": True, "messages": result}
        return result

    return route


def _replies(mapping: dict):
    """Route conversations.replies by (channel, root ts)."""

    def route(params: dict):
        key = (params.get("channel"), params.get("ts"))
        if key not in mapping:
            raise AssertionError(f"unexpected replies fetch {key}")
        value = mapping[key]
        if isinstance(value, SlackApiError):
            raise value
        if isinstance(value, list):
            return {"ok": True, "messages": value}
        return value

    return route


def _workspace(
    *,
    users: list[dict] | None = None,
    channels: list[dict] | None = None,
    members: dict | None = None,
    history: dict | None = None,
    replies: dict | None = None,
) -> FixtureSlackTransport:
    """The default two-channel workspace: #general (public) and #eng-private
    (private), both mirrorable; membership carries every G2 leak case."""
    if channels is None:
        channels = [
            _channel(C_GEN, "general"),
            _channel(C_PRIV, "eng-private", is_private=True),
        ]
    if members is None:
        members = {
            C_GEN: {"ok": True, "members": ["U0ALICE", "U0BOB", "U0BOT", "U0GUEST", "U0NOMAIL"]},
            C_PRIV: {"ok": True, "members": ["U0ALICE"]},
        }
    if history is None:
        history = {C_GEN: [SOLO_MSG, THREAD_ROOT], C_PRIV: []}
    if replies is None:
        replies = {
            (C_GEN, TS_ROOT): [THREAD_ROOT, THREAD_REPLY],
            (C_GEN, TS_SOLO): [SOLO_MSG],
        }
    return FixtureSlackTransport(
        {
            "users.list": {"ok": True, "members": users if users is not None else ALL_USERS},
            "conversations.list": {"ok": True, "channels": channels},
            "conversations.members": _by_channel(members),
            "conversations.history": _by_channel(history),
            "conversations.replies": _replies(replies),
            "conversations.join": {"ok": True, "channel": {}},
        }
    )


def _connector(transport: FixtureSlackTransport, **cfg) -> SlackConnector:
    defaults = dict(tenant_id=TENANT)
    defaults.update(cfg)
    return SlackConnector(transport, SlackConfig(**defaults), clock=_clock)


def _seed_state(tmp_path, channels: dict, *, last_reconcile_at=RECENT_RECONCILE, snapshot=None):
    state = {
        "channels": channels,
        "snapshot": snapshot or {},
        "last_reconcile_at": last_reconcile_at,
    }
    state_file = tmp_path / "slack_cursor.json"
    state_file.write_text(
        json.dumps({"cursor": json.dumps(state, sort_keys=True)}, indent=2) + "\n"
    )
    return state_file


def _saved_state(state_file) -> dict:
    return json.loads(json.loads(state_file.read_text())["cursor"])


def _ledger(tmp_path) -> list[dict]:
    return json.loads((tmp_path / "slack_parked_retractions.json").read_text())


def _mirrored_gen_state(threads: dict[str, str] | None = None) -> dict:
    return {
        C_GEN: {
            "class": MIRRORED,
            "latest": TS_BEFORE,
            "threads": dict(threads or {}),
        },
        C_PRIV: {"class": MIRRORED, "latest": TS_BEFORE, "threads": {}},
    }


# ---------------------------------------------------------------------------
# Sinks (sharepoint's capture/retire shapes, adapted)
# ---------------------------------------------------------------------------


class AlarmSink(DryRunSink):
    """Capture-only DocumentSink + the record_alarm/heartbeat surface the
    runner probes for. Deliberately NO ``retire`` transport: the drain must
    leave everything parked + alarmed on such a sink (fail closed)."""

    def __init__(self) -> None:
        super().__init__(stream=io.StringIO())
        self.alarms: list[dict[str, str]] = []
        self.heartbeats: list[str | None] = []

    def record_alarm(self, kind: str, detail: str) -> None:
        self.alarms.append({"kind": kind, "detail": detail})

    def heartbeat(self, cursor: str | None = None) -> None:
        self.heartbeats.append(cursor)

    def alarm_kinds(self) -> list[str]:
        return [a["kind"] for a in self.alarms]


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
    """AlarmSink + the ``retire`` transport (the live SlackStatusSink shape):
    every replay succeeds (a 2xx), bodies are captured byte-exact. ``calls``
    interleaves deliver/retire so ORDER can be asserted (the over-retire race
    is an ordering bug)."""

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


class CaptureAdminSink:
    """Captures admin ops instead of POSTing them."""

    def __init__(self) -> None:
        self.ops: list[AdminOp] = []

    def apply(self, op: AdminOp) -> None:
        self.ops.append(op)

    def bodies(self, path: str) -> list[dict]:
        return [dict(op.body) for op in self.ops if op.path == path]


# ---------------------------------------------------------------------------
# G1 — channel classification: shared/external quarantine, im/mpim skip
# ---------------------------------------------------------------------------


def test_shared_and_external_channels_quarantine_whole_channel():
    for flag in ("is_shared", "is_ext_shared", "is_org_shared", "is_pending_ext_shared"):
        assert classify_channel(_channel(C_SHARED, "x", **{flag: True})) == QUARANTINED, flag
    # A pending Slack Connect invite is already a share in flight: quarantine
    # (both documented spellings of the invite-in-flight state).
    assert classify_channel(_channel(C_SHARED, "x", pending_shared=["E123"])) == QUARANTINED
    # Private channels quarantine on the same flags (no private exemption).
    assert (
        classify_channel(_channel(C_SHARED, "x", is_private=True, is_ext_shared=True))
        == QUARANTINED
    )


def test_unknown_conversation_shape_quarantines():
    # Neither is_channel nor legacy is_group: a kind Slack added later — never
    # guess what it shares (G1).
    assert classify_channel({"id": "C0WEIRD", "name": "weird"}) == QUARANTINED
    assert classify_channel({"id": "C0W2", "is_channel": False, "is_group": False}) == QUARANTINED
    # The plain shapes still mirror.
    assert classify_channel(_channel(C_GEN, "general")) == MIRRORED
    assert classify_channel(_channel(C_PRIV, "p", is_private=True)) == MIRRORED
    assert classify_channel({"id": "G0LEG", "is_group": True}) == MIRRORED  # legacy private


def test_im_and_mpim_are_skipped_and_counted_never_silent():
    transport = _workspace(
        channels=[
            _channel(C_GEN, "general"),
            {"id": "D0IM", "is_im": True, "user": "U0ALICE"},
            {"id": "G0MPIM", "is_mpim": True, "name": "mpdm-a--b-1"},
        ]
    )
    connector = _connector(transport)
    view = connector.survey()
    assert classify_channel({"id": "D0IM", "is_im": True}) == SKIPPED_IM
    assert connector.skipped_im == 2
    assert set(view.channels) == {C_GEN}
    # Truly skipped: no membership or history fetch for the DMs.
    assert transport.called("conversations.members", channel="D0IM") == []
    assert transport.called("conversations.history", channel="D0IM") == []


def test_quarantined_channel_gets_no_membership_edges_and_no_content_fetch(tmp_path):
    # A Slack Connect channel that was NEVER mirrored: nothing indexed,
    # nothing to retire — and crucially nothing FETCHED (ACL-before-content).
    transport = _workspace(
        channels=[_channel(C_SHARED, "with-partner", is_ext_shared=True)],
        members={},
        history={},
        replies={},
    )
    connector = _connector(transport)
    sink = RetiringSink()
    admin = CaptureAdminSink()
    state_file = tmp_path / "slack_cursor.json"
    delivered = run_once(connector, StaticSlackRegistry(REGISTRY_MAP), sink, admin, state_file)
    assert delivered == 0
    assert sink.requests == []
    assert transport.called("conversations.members") == []
    assert transport.called("conversations.history") == []
    # No membership edge ever mentions the shared channel's group token.
    for body in admin.bodies("/v1/admin/groups"):
        assert channel_principal(C_SHARED) not in (body.get("group"), body.get("member"))
    assert _saved_state(state_file)["channels"][C_SHARED] == {"class": QUARANTINED}


# ---------------------------------------------------------------------------
# G2 — identity: bots/guests/no-email/deleted confer nothing
# ---------------------------------------------------------------------------


def test_bot_guest_deleted_and_no_email_members_confer_nothing():
    assert map_slack_user(ALICE).canonical == "user:alice@acme.com"
    for user in (BOT, GUEST, ULTRA, NOMAIL, GONE):
        assert map_slack_user(user) is None, user["id"]


def test_membership_and_crosswalk_ops_byte_exact(tmp_path):
    transport = _workspace(history={C_GEN: [], C_PRIV: []})
    connector = _connector(transport)
    admin = CaptureAdminSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    run_once(connector, StaticSlackRegistry(REGISTRY_MAP), AlarmSink(), admin, state_file)
    # No /v1/admin/registry/canonical op ANYWHERE: slack welds to canonicals a
    # real directory sync already created, it never creates them (G2).
    assert admin.ops == [
        AdminOp(
            "POST",
            "/v1/admin/crosswalk",
            {
                "tenant_id": TENANT,
                "source": "slack",
                "local_id": "U0ALICE",
                "canonical": "user:alice@acme.com",
                "link_method": "directory_vouched",
            },
        ),
        AdminOp(
            "POST",
            "/v1/admin/crosswalk",
            {
                "tenant_id": TENANT,
                "source": "slack",
                "local_id": "U0BOB",
                "canonical": "user:bob@acme.com",
                "link_method": "directory_vouched",
            },
        ),
        AdminOp(
            "POST",
            "/v1/admin/principals",
            {
                "tenant_id": TENANT,
                "principals": [
                    GEN_GROUP,
                    PRIV_GROUP,
                    "user:alice@acme.com",
                    "user:bob@acme.com",
                ],
            },
        ),
        AdminOp(
            "POST",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:alice@acme.com"},
        ),
        AdminOp(
            "POST",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:bob@acme.com"},
        ),
        AdminOp(
            "POST",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": PRIV_GROUP, "member": "user:alice@acme.com"},
        ),
    ]
    # The G2 leak cases confer nothing: no bot/guest/no-email/deleted uid or
    # email appears in ANY admin body.
    flat = json.dumps([dict(op.body) for op in admin.ops])
    for marker in ("U0BOT", "U0GUEST", "U0ULTRA", "U0NOMAIL", "U0GONE", "bot@acme.com", "gone@"):
        assert marker not in flat, marker


def test_unknown_canonical_member_confers_nothing_and_slack_never_creates_canonicals(tmp_path):
    # T1: profile.email is workspace-admin-mutable and re-read every cycle. A
    # member whose email has NO pre-existing canonical in the registry (eve —
    # never vouched by gdirectory/entra) must confer nothing: no crosswalk
    # row, no membership edge, and NO canonical-creation op anywhere (Slack's
    # word must never mint an identity the admin plane would then trust).
    eve = _member("U0EVE", "eve@acme.com", display="Eve")
    transport = _workspace(
        users=[ALICE, eve],
        history={C_GEN: [], C_PRIV: []},
        members={
            C_GEN: {"ok": True, "members": ["U0ALICE", "U0EVE"]},
            C_PRIV: {"ok": True, "members": ["U0ALICE"]},
        },
    )
    connector = _connector(transport)
    admin = CaptureAdminSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    run_once(connector, StaticSlackRegistry(REGISTRY_MAP), AlarmSink(), admin, state_file)
    assert all(op.path != "/v1/admin/registry/canonical" for op in admin.ops)
    assert [b["local_id"] for b in admin.bodies("/v1/admin/crosswalk")] == ["U0ALICE"]
    assert (
        AdminOp(
            "POST",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:alice@acme.com"},
        )
        in admin.ops
    )
    flat = json.dumps([dict(op.body) for op in admin.ops])
    assert "U0EVE" not in flat and "eve@" not in flat


def test_member_leaving_a_channel_emits_a_tombstoning_delete_edge(tmp_path):
    transport = _workspace(
        history={C_GEN: [], C_PRIV: []},
        members={
            C_GEN: {"ok": True, "members": ["U0ALICE"]},  # bob left #general
            C_PRIV: {"ok": True, "members": ["U0ALICE"]},
        },
    )
    connector = _connector(transport)
    admin = CaptureAdminSink()
    prior = {
        "users": ["user:alice@acme.com", "user:bob@acme.com"],
        "memberships": [
            [GEN_GROUP, "user:alice@acme.com"],
            [GEN_GROUP, "user:bob@acme.com"],
            [PRIV_GROUP, "user:alice@acme.com"],
        ],
        "directory_users": [
            {"directory_id": "U0ALICE", "primary_email": "alice@acme.com"},
            {"directory_id": "U0BOB", "primary_email": "bob@acme.com"},
        ],
    }
    state_file = _seed_state(tmp_path, _mirrored_gen_state(), snapshot=prior)
    run_once(connector, StaticSlackRegistry(REGISTRY_MAP), AlarmSink(), admin, state_file)
    assert admin.ops == [
        AdminOp(
            "DELETE",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:bob@acme.com"},
        )
    ]


def test_slack_never_fires_a_tenant_wide_deprovision(tmp_path):
    # Bob is deactivated in Slack: every slack-channel edge goes (narrowing),
    # but Slack's word must NOT durably revoke his canonical tenant-wide.
    transport = _workspace(
        users=[ALICE, {**BOB, "deleted": True}],
        history={C_GEN: [], C_PRIV: []},
        members={
            C_GEN: {"ok": True, "members": ["U0ALICE", "U0BOB"]},
            C_PRIV: {"ok": True, "members": ["U0ALICE"]},
        },
    )
    connector = _connector(transport)
    admin = CaptureAdminSink()
    prior = {
        "users": ["user:alice@acme.com", "user:bob@acme.com"],
        "memberships": [
            [GEN_GROUP, "user:alice@acme.com"],
            [GEN_GROUP, "user:bob@acme.com"],
            [PRIV_GROUP, "user:alice@acme.com"],
        ],
        "directory_users": [
            {"directory_id": "U0ALICE", "primary_email": "alice@acme.com"},
            {"directory_id": "U0BOB", "primary_email": "bob@acme.com"},
        ],
    }
    state_file = _seed_state(tmp_path, _mirrored_gen_state(), snapshot=prior)
    run_once(connector, StaticSlackRegistry(REGISTRY_MAP), AlarmSink(), admin, state_file)
    paths = [op.path for op in admin.ops]
    assert "/v1/admin/deprovision" not in paths
    assert (
        AdminOp(
            "DELETE",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:bob@acme.com"},
        )
        in admin.ops
    )


# ---------------------------------------------------------------------------
# Documents: transcript, body ladder, supersede
# ---------------------------------------------------------------------------


def test_transcript_is_chronological_with_display_names_rendering_only():
    names = {"U0ALICE": "Alice", "U0BOB": "Bob Builder", "U0BOT": "Robo"}
    # Out of order on purpose; a bot message renders (content is visible to
    # members) even though the bot confers no visibility.
    messages = [THREAD_REPLY, _msg(TS_SOLO, "U0BOT", "beep"), THREAD_ROOT]
    assert render_transcript(messages, names) == (
        f"[{ISO_ROOT}] Alice: kickoff\n"
        f"[{ISO_REPLY}] Bob Builder: reply\n"
        f"[{ISO_SOLO}] Robo: beep"
    )
    # An unknown uid renders as the raw id — rendering only, never resolved.
    assert render_transcript([_msg(TS_SOLO, "U0MYSTERY", "hi")], names) == (
        f"[{ISO_SOLO}] U0MYSTERY: hi"
    )


def test_poll_delivers_thread_documents_byte_exact(tmp_path):
    transport = _workspace()
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    delivered = run_once(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 2
    assert sink.requests == [
        {
            "tenant_id": TENANT,
            "source": "slack",
            "document_id": f"slack:{C_GEN}:{TS_ROOT}",
            "entities": [],
            "valid_from": ISO_REPLY,  # the LATEST ts in the thread
            "content": f"[{ISO_ROOT}] Alice: kickoff\n[{ISO_REPLY}] Bob Builder: reply",
            "visibility": [111],
            "acl_provenance": "mirrored",
        },
        {
            "tenant_id": TENANT,
            "source": "slack",
            "document_id": f"slack:{C_GEN}:{TS_SOLO}",
            "entities": [],
            "valid_from": ISO_SOLO,
            "content": f"[{ISO_SOLO}] Bob Builder: solo note",
            "visibility": [111],
            "acl_provenance": "mirrored",
        },
    ]
    state = _saved_state(state_file)
    # Bookkeeping carries the DELIVERED stamp + content digest per thread (the
    # L1 guard's replay/regression signal).
    assert state["channels"][C_GEN] == {
        "class": MIRRORED,
        "latest": TS_SOLO,
        "threads": {
            TS_ROOT: _entry(ISO_REPLY, GEN_TRANSCRIPT),
            TS_SOLO: _entry(ISO_SOLO, SOLO_TRANSCRIPT),
        },
    }


def test_quarantined_body_carries_no_visibility_and_no_content():
    quarantined = SlackDocumentEvent(
        source="slack",
        document_id=thread_document_id(C_SHARED, TS_ROOT),
        content=b"never indexed",
        mime_type="text/plain",
        version="",
        acl=AclEnvelope(resolvable=False),
        modified_time=NOW_ISO,
        channel_id=C_SHARED,
        thread_ts=TS_ROOT,
    )
    body = build_slack_document_request(quarantined, StaticSlackRegistry(REGISTRY_MAP), TENANT)
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"
    assert body["content"] is None  # quarantine posture never carries text
    # A channel token the registry cannot resolve also quarantines (never a
    # blind mint) — still no visibility key.
    unresolved = SlackDocumentEvent(
        source="slack",
        document_id=thread_document_id("C0NEW", TS_ROOT),
        content=b"hello",
        mime_type="text/plain",
        version=TS_ROOT,
        acl=AclEnvelope(resolvable=True, groups=[channel_principal("C0NEW")]),
        modified_time=ISO_ROOT,
        channel_id="C0NEW",
        thread_ts=TS_ROOT,
    )
    body = build_slack_document_request(unresolved, StaticSlackRegistry(REGISTRY_MAP), TENANT)
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"


def test_thread_reingest_supersedes_same_document_id(tmp_path):
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    # Cycle 1: the thread lands.
    transport1 = _workspace(
        history={C_GEN: [THREAD_ROOT], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): [THREAD_ROOT, THREAD_REPLY]},
    )
    sink1 = RetiringSink()
    run_once(
        _connector(transport1),
        StaticSlackRegistry(REGISTRY_MAP),
        sink1,
        CaptureAdminSink(),
        state_file,
    )
    # Cycle 2: a message_changed SIGNAL row re-targets the edited thread; the
    # fresh replies fetch carries the edited text.
    edited_root = _msg(TS_ROOT, "U0ALICE", "kickoff (edited)", thread_ts=TS_ROOT, reply_count=1)
    signal = {
        "type": "message",
        "subtype": "message_changed",
        "ts": TS_EDIT,
        "message": {"ts": TS_ROOT, "thread_ts": TS_ROOT, "text": "kickoff (edited)"},
    }
    transport2 = _workspace(
        history={C_GEN: [signal], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): [edited_root, THREAD_REPLY]},
    )
    sink2 = RetiringSink()
    run_once(
        _connector(transport2),
        StaticSlackRegistry(REGISTRY_MAP),
        sink2,
        CaptureAdminSink(),
        state_file,
    )
    (first,) = sink1.requests
    (second,) = sink2.requests
    assert first["document_id"] == second["document_id"] == f"slack:{C_GEN}:{TS_ROOT}"
    assert "kickoff (edited)" in second["content"]
    assert second["visibility"] == [111]
    # The edit did not add a message, so the recomputed latest-ts stamp equals
    # the delivered one — the L1 guard advances valid_from to the signal's own
    # ts so the server supersede (strictly monotonic) actually retires v1.
    assert first["valid_from"] == ISO_REPLY
    assert second["valid_from"] == ISO_EDIT
    # The poll mark advanced past the signal row.
    assert _saved_state(state_file)["channels"][C_GEN]["latest"] == TS_EDIT


def test_deleting_the_latest_reply_still_supersedes(tmp_path):
    # THE L1 LEAK: the delivered stamp is the latest thread ts, which is
    # NON-monotonic — deleting the latest reply REGRESSES it (ISO_REPLY →
    # ISO_ROOT), while the server retires only rows with valid_from strictly
    # BELOW the incoming stamp. An honest re-delivery at the regressed stamp
    # would leave TWO open rows still serving the deleted reply. The guard
    # must advance valid_from past the bookkept delivered stamp (here: the
    # message_deleted signal's own ts).
    signal = {
        "type": "message",
        "subtype": "message_deleted",
        "ts": TS_EDIT,
        "previous_message": {"ts": TS_REPLY, "thread_ts": TS_ROOT},
    }
    transport = _workspace(
        history={C_GEN: [signal], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): [THREAD_ROOT]},  # the reply is gone
    )
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path, _mirrored_gen_state({TS_ROOT: _entry(ISO_REPLY, GEN_TRANSCRIPT)})
    )
    delivered = run_once(
        _connector(transport), StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 1
    (body,) = sink.requests
    assert body["content"] == f"[{ISO_ROOT}] Alice: kickoff"  # no deleted text
    assert body["valid_from"] == ISO_EDIT  # > ISO_REPLY: the old row retires
    assert _saved_state(state_file)["channels"][C_GEN]["threads"][TS_ROOT] == _entry(
        ISO_EDIT, f"[{ISO_ROOT}] Alice: kickoff"
    )


def test_editing_the_latest_message_still_supersedes(tmp_path):
    # Slack edits KEEP the message ts, so the recomputed stamp EQUALS the
    # delivered one — and the server's ON CONFLICT DO NOTHING (the replay-
    # idempotency contract) would silently drop the redaction. The guard must
    # advance valid_from past the bookkept stamp.
    edited = _msg(TS_SOLO, "U0BOB", "solo note (redacted)")
    signal = {
        "type": "message",
        "subtype": "message_changed",
        "ts": TS_EDIT,
        "message": {"ts": TS_SOLO, "text": "solo note (redacted)"},
    }
    transport = _workspace(
        history={C_GEN: [signal], C_PRIV: []},
        replies={(C_GEN, TS_SOLO): [edited]},
    )
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path, _mirrored_gen_state({TS_SOLO: _entry(ISO_SOLO, SOLO_TRANSCRIPT)})
    )
    delivered = run_once(
        _connector(transport), StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 1
    (body,) = sink.requests
    assert "(redacted)" in body["content"]
    assert body["valid_from"] == ISO_EDIT  # advanced: the pre-edit row retires


def test_unchanged_thread_is_not_redelivered_by_the_reconcile(tmp_path):
    # The reconcile re-walks every thread; unchanged content (digest match
    # against the bookkept delivered version) must be CARRIED, not re-sent —
    # neither index churn nor a false gap-deletion retire.
    transport = _workspace()
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path,
        _mirrored_gen_state(
            {
                TS_ROOT: _entry(ISO_REPLY, GEN_TRANSCRIPT),
                TS_SOLO: _entry(ISO_SOLO, SOLO_TRANSCRIPT),
            }
        ),
    )
    delivered = run_backfill(
        _connector(transport), StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 0 and sink.requests == []
    assert sink.retired == []  # carried forward, never mistaken for deleted
    state = _saved_state(state_file)
    assert state["channels"][C_GEN]["threads"][TS_ROOT] == _entry(ISO_REPLY, GEN_TRANSCRIPT)
    assert state["last_reconcile_at"] == NOW_ISO  # still a zero-failure pass


def test_replay_of_the_same_delivered_version_stays_idempotent(tmp_path):
    # At-least-once delivery: the SAME history row surfacing again (a resent
    # window) must not re-deliver or advance anything — the skip is what lets
    # the server keep its DO-NOTHING replay contract without ever being asked.
    def cycle_transport():
        return _workspace(
            history={C_GEN: [THREAD_ROOT], C_PRIV: []},
            replies={(C_GEN, TS_ROOT): [THREAD_ROOT, THREAD_REPLY]},
        )

    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    sink1 = RetiringSink()
    run_once(
        _connector(cycle_transport()),
        StaticSlackRegistry(REGISTRY_MAP),
        sink1,
        CaptureAdminSink(),
        state_file,
    )
    assert [r["document_id"] for r in sink1.requests] == [f"slack:{C_GEN}:{TS_ROOT}"]
    before = _saved_state(state_file)["channels"][C_GEN]["threads"]
    assert before == {TS_ROOT: _entry(ISO_REPLY, GEN_TRANSCRIPT)}
    sink2 = RetiringSink()
    delivered = run_once(
        _connector(cycle_transport()),
        StaticSlackRegistry(REGISTRY_MAP),
        sink2,
        CaptureAdminSink(),
        state_file,
    )
    assert delivered == 0 and sink2.requests == []
    assert _saved_state(state_file)["channels"][C_GEN]["threads"] == before


def test_first_sight_of_a_channel_primes_and_emits_nothing(tmp_path):
    transport = _workspace(history={C_GEN: [SOLO_MSG, THREAD_ROOT], C_PRIV: []})
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = tmp_path / "slack_cursor.json"  # no prior state at all
    delivered = run_once(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 0 and sink.requests == []
    state = _saved_state(state_file)
    # Primed to the newest ts (fixtures list newest first, as Slack does);
    # enumeration of everything older is the backfill's job.
    assert state["channels"][C_GEN] == {"class": MIRRORED, "latest": TS_SOLO, "threads": {}}


# ---------------------------------------------------------------------------
# G4 — park + drain: deletes, channel death, quarantine transitions, races
# ---------------------------------------------------------------------------


def test_deleted_thread_parks_and_drains_byte_exact(tmp_path):
    doc = f"slack:{C_GEN}:{TS_ROOT}"
    signal = {
        "type": "message",
        "subtype": "message_deleted",
        "ts": TS_EDIT,
        "previous_message": {"ts": TS_ROOT, "thread_ts": TS_ROOT},
    }
    transport = _workspace(
        history={C_GEN: [signal], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): SlackApiError("conversations.replies", "thread_not_found")},
    )
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state({TS_ROOT: ISO_REPLY}))
    delivered = run_once(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 0
    # Byte-exact retire replay, same admin route the sinks use.
    assert sink.retired == [
        {"tenant_id": TENANT, "source": "slack", "document_id": doc, "reason": "removed"}
    ]
    assert _ledger(tmp_path) == []  # drained
    assert sink.alarm_kinds() == []  # nothing left parked
    # The bookkeeping forgot the thread; the poll mark still advanced.
    state = _saved_state(state_file)
    assert state["channels"][C_GEN]["threads"] == {}
    assert state["channels"][C_GEN]["latest"] == TS_EDIT


def test_vanished_root_with_no_surviving_replies_parks(tmp_path):
    # The tombstone-only variant: replies answers, but nothing renderable
    # survives (the root is a tombstone, no replies) — same removal posture.
    tombstone = {"type": "message", "subtype": "tombstone", "ts": TS_ROOT, "text": "deleted"}
    transport = _workspace(
        history={C_GEN: [{**THREAD_ROOT}], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): [tombstone]},
    )
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state({TS_ROOT: ISO_REPLY}))
    run_once(connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file)
    assert [r["reason"] for r in sink.retired] == ["removed"]
    assert sink.requests == []


def test_channel_deleted_parks_every_bookkept_thread(tmp_path):
    transport = _workspace(
        channels=[_channel(C_PRIV, "eng-private", is_private=True)],
        members={C_PRIV: {"ok": True, "members": ["U0ALICE"]}},
        history={C_PRIV: []},
        replies={},
    )
    connector = _connector(transport)
    sink = AlarmSink()  # NO retire transport: everything must stay parked + alarmed
    state_file = _seed_state(
        tmp_path, _mirrored_gen_state({TS_ROOT: ISO_REPLY, TS_SOLO: ISO_SOLO})
    )
    delivered = run_once(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 0 and sink.requests == []
    entries = _ledger(tmp_path)
    assert [(e["document_id"], e["reason"]) for e in entries] == [
        (f"slack:{C_GEN}:{TS_ROOT}", "removed"),
        (f"slack:{C_GEN}:{TS_SOLO}", "removed"),
    ]
    assert entries[0]["channel_id"] == C_GEN and entries[0]["thread_ts"] == TS_ROOT
    assert "parked_retraction" in sink.alarm_kinds()
    # The dead channel is gone from the cursor — the LEDGER carries the signal.
    assert C_GEN not in _saved_state(state_file)["channels"]


def test_mirrored_to_quarantined_transition_retires_previous_threads(tmp_path):
    transport = _workspace(
        channels=[
            _channel(C_GEN, "general", is_shared=True),  # went Slack Connect
            _channel(C_PRIV, "eng-private", is_private=True),
        ],
        members={C_PRIV: {"ok": True, "members": ["U0ALICE"]}},
        history={C_PRIV: []},
        replies={},
    )
    connector = _connector(transport)
    sink = RetiringSink()
    admin = CaptureAdminSink()
    prior = {
        "users": ["user:alice@acme.com"],
        "memberships": [
            [GEN_GROUP, "user:alice@acme.com"],
            [PRIV_GROUP, "user:alice@acme.com"],
        ],
        "directory_users": [{"directory_id": "U0ALICE", "primary_email": "alice@acme.com"}],
    }
    state_file = _seed_state(
        tmp_path, _mirrored_gen_state({TS_ROOT: ISO_REPLY}), snapshot=prior
    )
    delivered = run_once(connector, StaticSlackRegistry(REGISTRY_MAP), sink, admin, state_file)
    assert delivered == 0
    # The previously-indexed thread is retired (reason: quarantined) …
    assert sink.retired == [
        {
            "tenant_id": TENANT,
            "source": "slack",
            "document_id": f"slack:{C_GEN}:{TS_ROOT}",
            "reason": "quarantined",
        }
    ]
    # … the membership edge is tombstone-deleted …
    assert (
        AdminOp(
            "DELETE",
            "/v1/admin/groups",
            {"tenant_id": TENANT, "group": GEN_GROUP, "member": "user:alice@acme.com"},
        )
        in admin.ops
    )
    # … and the now-shared channel was never content- or member-fetched.
    assert transport.called("conversations.history", channel=C_GEN) == []
    assert transport.called("conversations.members", channel=C_GEN) == []
    assert _saved_state(state_file)["channels"][C_GEN] == {"class": QUARANTINED}


def test_preexisting_ledger_drains_before_any_delivery(tmp_path):
    old_doc = f"slack:{C_GEN}:1690000000.000001"
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    (tmp_path / "slack_parked_retractions.json").write_text(
        json.dumps(
            [
                {
                    "channel_id": C_GEN,
                    "thread_ts": "1690000000.000001",
                    "document_id": old_doc,
                    "reason": "removed",
                    "first_seen": "2023-11-13T00:00:00Z",
                    "last_seen": "2023-11-13T00:00:00Z",
                }
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    sink = RetiringSink()
    run_once(
        _connector(_workspace()),
        StaticSlackRegistry(REGISTRY_MAP),
        sink,
        CaptureAdminSink(),
        state_file,
    )
    # Guard #1: the stale ledger entry replayed BEFORE anything delivered.
    assert sink.calls[0] == ("retire", old_doc)
    assert ("deliver", f"slack:{C_GEN}:{TS_ROOT}") in sink.calls
    assert _ledger(tmp_path) == []


def test_restored_document_unparks_its_stale_retraction(tmp_path):
    # A thread parked in an earlier cycle is DELIVERED this cycle (restored).
    # The pre-drain replay FAILS (retire route down) so the entry survives
    # guard #1 — guard #2 (unpark-on-delivery) must remove it, or a later
    # drain would blank the fresh chunks.
    doc = f"slack:{C_GEN}:{TS_ROOT}"
    state_file = _seed_state(tmp_path, _mirrored_gen_state())
    (tmp_path / "slack_parked_retractions.json").write_text(
        json.dumps(
            [
                {
                    "channel_id": C_GEN,
                    "thread_ts": TS_ROOT,
                    "document_id": doc,
                    "reason": "removed",
                    "first_seen": "2023-11-13T00:00:00Z",
                    "last_seen": "2023-11-13T00:00:00Z",
                }
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    sink = FailingRetireSink()
    run_once(
        _connector(_workspace()),
        StaticSlackRegistry(REGISTRY_MAP),
        sink,
        CaptureAdminSink(),
        state_file,
    )
    assert ("deliver", doc) in sink.calls
    assert _ledger(tmp_path) == []  # guard #2: unparked by the newer delivery
    # No retire attempt for the restored doc AFTER its delivery.
    after_delivery = sink.calls[sink.calls.index(("deliver", doc)) + 1 :]
    assert ("retire", doc) not in after_delivery
    # Nothing left parked → no parked_retraction alarm.
    assert "parked_retraction" not in sink.alarm_kinds()


def test_failed_retire_replay_stays_parked_and_alarmed(tmp_path):
    signal = {
        "type": "message",
        "subtype": "message_deleted",
        "ts": TS_EDIT,
        "previous_message": {"ts": TS_ROOT, "thread_ts": TS_ROOT},
    }
    transport = _workspace(
        history={C_GEN: [signal], C_PRIV: []},
        replies={(C_GEN, TS_ROOT): SlackApiError("conversations.replies", "thread_not_found")},
    )
    sink = FailingRetireSink()
    state_file = _seed_state(tmp_path, _mirrored_gen_state({TS_ROOT: ISO_REPLY}))
    run_once(
        _connector(transport), StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    entries = _ledger(tmp_path)
    assert [e["document_id"] for e in entries] == [f"slack:{C_GEN}:{TS_ROOT}"]
    assert "parked_retraction" in sink.alarm_kinds()
    # A NEXT cycle with a healthy retire route drains it (idempotent replay).
    transport2 = _workspace(history={C_GEN: [], C_PRIV: []}, replies={})
    sink2 = RetiringSink()
    run_once(
        _connector(transport2),
        StaticSlackRegistry(REGISTRY_MAP),
        sink2,
        CaptureAdminSink(),
        state_file,
    )
    assert [r["document_id"] for r in sink2.retired] == [f"slack:{C_GEN}:{TS_ROOT}"]
    assert _ledger(tmp_path) == []


# ---------------------------------------------------------------------------
# Heartbeats & alarms
# ---------------------------------------------------------------------------


def test_status_sink_idle_cycle_heartbeats_zero():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    sink = SlackStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.alarm_tenant_id = TENANT  # runner wiring (main sets this)
    sink.heartbeat(cursor="slack-cursor-42")
    assert posts == [
        (
            "/v1/admin/connector-status",
            {
                "tenant_id": TENANT,
                "source": "slack",
                "items_synced": 0,
                "cursor": "slack-cursor-42",
            },
        )
    ]


def test_status_sink_heartbeat_carries_alarms_even_with_zero_deliveries():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    sink = SlackStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.alarm_tenant_id = TENANT
    sink.record_alarm("reconcile_overdue", "no zero-failure backfill within 24h")
    sink.heartbeat()
    assert posts == [
        (
            "/v1/admin/connector-status",
            {
                "tenant_id": TENANT,
                "source": "slack",
                "items_synced": 0,
                "alarms": [
                    {
                        "kind": "reconcile_overdue",
                        "detail": "no zero-failure backfill within 24h",
                    }
                ],
            },
        )
    ]
    # Drained: the next alarm-free idle cycle still beats.
    sink.heartbeat()
    assert posts[-1] == (
        "/v1/admin/connector-status",
        {"tenant_id": TENANT, "source": "slack", "items_synced": 0},
    )


def test_status_sink_retire_posts_the_admin_retire_body_and_raises_on_failure():
    posts: list[tuple[str, str | None, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append(
            (request.url.path, request.headers.get("Authorization"), json.loads(request.content))
        )
        if len(posts) > 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"chunks_retired": 2})

    sink = SlackStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer admin-key"},
        ),
    )
    body = {
        "tenant_id": TENANT,
        "source": "slack",
        "document_id": f"slack:{C_GEN}:{TS_ROOT}",
        "reason": "removed",
    }
    sink.retire(body)
    assert posts == [(RETIRE_PATH, "Bearer admin-key", body)]
    with pytest.raises(httpx.HTTPStatusError):
        sink.retire(body)


def test_idle_cycle_still_heartbeats_and_reconcile_overdue_alarms(tmp_path):
    transport = _workspace(history={C_GEN: [], C_PRIV: []})
    connector = _connector(transport)
    sink = AlarmSink()
    # Never reconciled: the alarm must fire on an otherwise-idle cycle.
    state_file = _seed_state(tmp_path, _mirrored_gen_state(), last_reconcile_at=None)
    delivered = run_once(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 0
    assert sink.alarm_kinds() == ["reconcile_overdue"]
    assert len(sink.heartbeats) == 1  # EVERY cycle beats, idle included
    # A fresh reconcile silences it (same cycle shape, recent stamp).
    sink2 = AlarmSink()
    state_file2 = _seed_state(tmp_path, _mirrored_gen_state())
    run_once(
        _connector(_workspace(history={C_GEN: [], C_PRIV: []})),
        StaticSlackRegistry(REGISTRY_MAP),
        sink2,
        CaptureAdminSink(),
        state_file2,
    )
    assert "reconcile_overdue" not in sink2.alarm_kinds()


# ---------------------------------------------------------------------------
# Backfill: enumeration, gap-deletion sweep, SLA stamp, resumability
# ---------------------------------------------------------------------------


def test_backfill_enumerates_threads_and_stamps_the_sla(tmp_path):
    transport = _workspace()
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = tmp_path / "slack_cursor.json"
    delivered = run_backfill(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 2
    ids = [r["document_id"] for r in sink.requests]
    assert ids == [f"slack:{C_GEN}:{TS_ROOT}", f"slack:{C_GEN}:{TS_SOLO}"]
    state = _saved_state(state_file)
    assert state["last_reconcile_at"] == NOW_ISO  # zero-failure pass stamps
    assert "backfill" not in state  # resumable cursors cleared on completion
    assert state["channels"][C_GEN] == {
        "class": MIRRORED,
        "latest": TS_SOLO,
        "threads": {
            TS_ROOT: _entry(ISO_REPLY, GEN_TRANSCRIPT),
            TS_SOLO: _entry(ISO_SOLO, SOLO_TRANSCRIPT),
        },
    }


def test_backfill_sweeps_gap_deletions_the_poll_missed(tmp_path):
    # A thread bookkept from an earlier cycle no longer exists in Slack; the
    # incremental poll saw no message_deleted row (the honest gap). The
    # reconcile crawl diffs bookkeeping against reality and retires it.
    gone_ts = "1690000000.000001"
    transport = _workspace()
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path, _mirrored_gen_state({gone_ts: "2023-07-22T05:46:40Z", TS_ROOT: ISO_REPLY})
    )
    run_backfill(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert sink.retired == [
        {
            "tenant_id": TENANT,
            "source": "slack",
            "document_id": f"slack:{C_GEN}:{gone_ts}",
            "reason": "removed",
        }
    ]
    state = _saved_state(state_file)
    assert gone_ts not in state["channels"][C_GEN]["threads"]
    assert state["last_reconcile_at"] == NOW_ISO


def test_backfill_with_ingest_failures_does_not_stamp_the_sla(tmp_path):
    transport = _workspace()
    connector = _connector(transport)
    sink = FailingSink({f"slack:{C_GEN}:{TS_SOLO}"})
    state_file = tmp_path / "slack_cursor.json"
    delivered = run_backfill(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert delivered == 1
    state = _saved_state(state_file)
    assert state["last_reconcile_at"] is None  # NOT re-proven; SLA stays unmet
    assert "backfill_incomplete" in sink.alarm_kinds()


def test_backfill_crash_after_checkpoint_does_not_over_hide_a_restored_thread(tmp_path):
    # C2: a restored thread's stale park entry survives guard #1 (the retire
    # route is down), the crawl DELIVERS the thread and CHECKPOINTS, then
    # crashes before crawl end. The unpark must have ridden the checkpoint —
    # otherwise the resumed run's pre-drain replays the stale retraction
    # against a document the resume (rightly) skips re-delivering, and the
    # restored thread stays hidden until the next full backfill.
    doc = f"slack:{C_GEN}:{TS_ROOT}"
    state_file = _seed_state(tmp_path, _mirrored_gen_state(), last_reconcile_at=None)
    (tmp_path / "slack_parked_retractions.json").write_text(
        json.dumps(
            [
                {
                    "channel_id": C_GEN,
                    "thread_ts": TS_ROOT,
                    "document_id": doc,
                    "reason": "removed",
                    "first_seen": "2023-11-13T00:00:00Z",
                    "last_seen": "2023-11-13T00:00:00Z",
                }
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    def boom(params):
        raise RuntimeError("mid-crawl crash")

    transport = _workspace(history={C_GEN: [SOLO_MSG, THREAD_ROOT], C_PRIV: boom})
    sink = FailingRetireSink()  # guard #1's pre-drain fails: the entry survives it
    with pytest.raises(RuntimeError, match="mid-crawl crash"):
        run_backfill(
            _connector(transport),
            StaticSlackRegistry(REGISTRY_MAP),
            sink,
            CaptureAdminSink(),
            state_file,
            flush_every=1,
        )
    assert ("deliver", doc) in sink.calls
    # The delivery's unpark persisted WITH the mid-crawl checkpoint.
    assert _ledger(tmp_path) == []
    # Resume with a healthy retire route: C_GEN is checkpointed done (not
    # re-crawled, so the thread is NOT re-delivered) and — crucially — the
    # stale retraction is NOT replayed against it.
    transport2 = _workspace(history={C_PRIV: []}, replies={})
    sink2 = RetiringSink()
    run_backfill(
        _connector(transport2),
        StaticSlackRegistry(REGISTRY_MAP),
        sink2,
        CaptureAdminSink(),
        state_file,
    )
    assert transport2.called("conversations.history", channel=C_GEN) == []
    assert ("retire", doc) not in sink2.calls
    assert sink2.requests == []
    assert _saved_state(state_file)["last_reconcile_at"] == NOW_ISO


def test_backfill_resumes_past_channels_already_done(tmp_path):
    # A crashed backfill checkpointed C_GEN as done (its state already in the
    # cursor); the resumed run must not re-crawl it — and must still finish,
    # stamp, and clear the resume markers.
    transport = _workspace(history={C_PRIV: []}, replies={})
    connector = _connector(transport)
    sink = RetiringSink()
    done_state = {
        "class": MIRRORED,
        "latest": TS_SOLO,
        "threads": {TS_ROOT: ISO_REPLY, TS_SOLO: ISO_SOLO},
    }
    state = {
        "channels": {C_GEN: done_state, C_PRIV: {"class": MIRRORED, "latest": TS_BEFORE, "threads": {}}},
        "snapshot": {},
        "last_reconcile_at": None,
        "backfill": {"channels": {C_GEN: "done"}, "partial": {}},
    }
    state_file = tmp_path / "slack_cursor.json"
    state_file.write_text(
        json.dumps({"cursor": json.dumps(state, sort_keys=True)}, indent=2) + "\n"
    )
    run_backfill(
        connector, StaticSlackRegistry(REGISTRY_MAP), sink, CaptureAdminSink(), state_file
    )
    assert transport.called("conversations.history", channel=C_GEN) == []
    saved = _saved_state(state_file)
    assert saved["channels"][C_GEN] == done_state  # carried, not re-proven-empty
    assert saved["last_reconcile_at"] == NOW_ISO
    assert "backfill" not in saved
    # And CRUCIALLY no false gap-deletion: nothing was retired for C_GEN.
    assert sink.retired == []


# ---------------------------------------------------------------------------
# Transport: 429/Retry-After, the ok:false envelope, cursor pagination
# ---------------------------------------------------------------------------


def test_http_transport_honors_429_retry_after():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(429, headers={"Retry-After": "2.5"})
        return httpx.Response(200, json={"ok": True, "members": []})

    sleeps: list[float] = []
    transport = HttpSlackTransport(
        "xoxb-test",
        client=httpx.Client(
            transport=httpx.MockTransport(handler), base_url=SLACK_API_BASE_URL
        ),
        sleep=sleeps.append,
    )
    payload = transport.call("users.list", {"limit": "10"})
    assert payload["ok"] is True
    assert sleeps == [2.5]  # slept exactly what Slack asked, then retried
    assert seen[0].headers["Authorization"] == "Bearer xoxb-test"


def test_http_transport_surfaces_the_ok_false_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})

    transport = HttpSlackTransport(
        "xoxb-test",
        client=httpx.Client(
            transport=httpx.MockTransport(handler), base_url=SLACK_API_BASE_URL
        ),
    )
    with pytest.raises(SlackApiError) as excinfo:
        transport.call("conversations.list", {})
    assert excinfo.value.error == "invalid_auth"


def test_cursor_pagination_follows_next_cursor_verbatim():
    def users_route(params: dict) -> dict:
        if not params.get("cursor"):
            return {
                "ok": True,
                "members": [ALICE],
                "response_metadata": {"next_cursor": "dXNlcjpVMEJPQg=="},
            }
        assert params["cursor"] == "dXNlcjpVMEJPQg=="
        return {"ok": True, "members": [BOB], "response_metadata": {"next_cursor": ""}}

    transport = _workspace(channels=[], members={}, history={}, replies={})
    transport.routes["users.list"] = users_route
    connector = _connector(transport)
    view = connector.survey()
    assert {u.primary_email for u in view.users.values()} == {"alice@acme.com", "bob@acme.com"}
    assert len(transport.called("users.list")) == 2


# ---------------------------------------------------------------------------
# Config (BYOT: ~/.verity/config.toml [connectors.slack])
# ---------------------------------------------------------------------------


def test_credentials_load_from_verity_config_toml(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_APP_TOKEN", raising=False)
    config = tmp_path / "config.toml"
    config.write_text(
        '[connectors.slack]\napp_token = "xapp-1-A1-2-abc"\nbot_token = "xoxb-42-fixture"\n'
    )
    bot, app = load_slack_credentials(config)
    assert bot == "xoxb-42-fixture"
    assert app == "xapp-1-A1-2-abc"  # loaded but RESERVED (Socket-Mode lane)


def test_missing_credentials_name_the_wizard(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="verity-cli connect slack"):
        load_slack_credentials(tmp_path / "nope.toml")


def test_env_token_overrides_config(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('[connectors.slack]\nbot_token = "xoxb-from-file"\n')
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-from-env")
    monkeypatch.delenv("SLACK_APP_TOKEN", raising=False)
    bot, _ = load_slack_credentials(config)
    assert bot == "xoxb-from-env"


def test_crosswalk_source_matches_module_source_name():
    # The (slack, Uid) crosswalk row only welds if downstream resolvers present
    # the SAME source string this module stamps — pin it.
    from verity_ingest.connectors.slack import SOURCE_NAME

    assert SOURCE_NAME == "slack"
    ops = build_slack_admin_ops(
        _empty_snapshot(),
        _snapshot_with_alice(),
        TENANT,
    )
    crosswalk_ops = [op for op in ops if op.path == "/v1/admin/crosswalk"]
    assert crosswalk_ops and all(op.body["source"] == "slack" for op in crosswalk_ops)
    assert all(op.body["link_method"] == "directory_vouched" for op in crosswalk_ops)


def _empty_snapshot():
    from verity_ingest.connectors.gdirectory import DirectorySnapshot

    return DirectorySnapshot()


def _snapshot_with_alice():
    from verity_ingest.connectors.gdirectory import DirectorySnapshot, DirectoryUser

    return DirectorySnapshot(
        users=["user:alice@acme.com"],
        memberships=[(GEN_GROUP, "user:alice@acme.com")],
        directory_users=[DirectoryUser(directory_id="U0ALICE", primary_email="alice@acme.com")],
    )


def test_resolve_request_uses_the_principals_path_only():
    # Slack visibility is group-only; the document path must never smuggle
    # emails/crosswalk owners (identity is the ADMIN plane's job, G2).
    captured: list[crosswalk.ResolveRequest] = []

    class SpyRegistry:
        def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult:
            captured.append(request)
            return crosswalk.ResolveResult(mappings={GEN_GROUP: 111}, quarantined=False)

    event = SlackDocumentEvent(
        source="slack",
        document_id=thread_document_id(C_GEN, TS_ROOT),
        content=b"hello",
        mime_type="text/plain",
        version=TS_ROOT,
        acl=AclEnvelope(resolvable=True, groups=[GEN_GROUP]),
        modified_time=ISO_ROOT,
        channel_id=C_GEN,
        thread_ts=TS_ROOT,
    )
    body = build_slack_document_request(event, SpyRegistry(), TENANT)
    assert body["visibility"] == [111]
    (request,) = captured
    assert request.principals == [GEN_GROUP]
    assert request.emails == [] and request.resolvable == []
