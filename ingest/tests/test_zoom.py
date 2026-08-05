"""Zoom transcript connector conformance tests — leak cases first.

All Zoom payloads are fixtures authored from the documented API response
shapes (users/{id}/recordings paging + the 1-month window cap,
meetings/{uuid}/recordings, recordings/settings, past_meetings participants,
the Server-to-Server OAuth token mint on zoom.us, HTTP 429 + Retry-After,
Zoom VTT transcripts). No live API calls and no credentials in this file.

The suite exercises the red-teamed LEAK cases, not just happy paths:

- G1 (settings-read-or-quarantine, ACL BEFORE content): every row of the
  share_recording table including the poison branches — ``none`` → host-only
  mirrored; ``internally`` → operator token + host (admin-assigned), with
  maps-to unset / authentication_domains mismatch quarantining; ``publicly``
  quarantines even WITH a passcode; an unknown enum or unreadable settings
  quarantines; an unvouched or unreadable host email quarantines. Quarantined
  recordings fetch NO transcript and NO participants (call-log negatives) and
  their bodies carry NO visibility and NO content;
- G2: participants join the audience ONLY under the explicit opt-in flag, and
  only the directory-vouched ones — guests without a ``user_email`` and
  unvouched attendees confer nothing (narrowing, never poison); the
  provenance floors honestly (mirrored → approximated → admin-assigned);
- G3: document_id is ``zoom:{meeting_uuid}`` (NEVER the recycled numeric id);
  meeting UUIDs are ALWAYS double-URL-encoded in paths (the ``//`` case);
  the monotonic-stamp guard advances valid_from past the bookkept delivered
  stamp when content changed but the recording-end stamp regressed (deleted
  latest file) or stalled (transcript edit), and skips unchanged replays;
- G4: absence of a bookkept UUID from a re-listed window parks + drains a
  byte-exact POST /v1/admin/retire replay; the sharepoint race guards hold
  verbatim (pre-existing ledger drains BEFORE delivery; a restored recording
  UNPARKS its stale retraction; a failed replay stays parked + alarmed); a
  FAILED list never absence-retracts (no mass deletion from a partial list);
- month-window chunking (Zoom's 1-month list cap), 429/Retry-After, the
  token mint host + Basic header, the 0600 secret-file discipline;
- idle cycles heartbeat items_synced:0 with source="zoom"; reconcile_overdue
  alarms while no zero-failure backfill is fresh; last_reconcile_at is
  stamped ONLY by a zero-failure backfill.
"""

from __future__ import annotations

import io
import json
from datetime import date, datetime, timezone
from urllib.parse import quote

import httpx
import pytest

from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gdrive import DryRunSink
from verity_ingest.connectors.zoom import (
    RETIRE_PATH,
    ZOOM_API_BASE_URL,
    ZOOM_OAUTH_TOKEN_URL,
    HttpZoomTransport,
    StaticZoomRegistry,
    ZoomApiError,
    ZoomConfig,
    ZoomConnector,
    ZoomDocumentEvent,
    ZoomOAuth,
    ZoomStatusSink,
    build_zoom_document_request,
    classify_share_audience,
    content_digest,
    encode_meeting_uuid,
    floor_provenance,
    load_zoom_credentials,
    month_windows,
    parse_vtt,
    recording_document_id,
    render_transcript,
    run_backfill,
    run_once,
)

TENANT = "t-acme"

#: A typical base64-ish meeting UUID and the nasty ``/``-prefixed ``//`` one
#: Zoom requires double-encoding for (error 3001 otherwise).
UUID = "wGHtsdfLTS2eKrrVFmkabc=="
UUID_SLASHY = "/ajXp112Q//mdEbc4wQ=="
NUMERIC_ID = 987654321  # REUSED across recurrences: must never key a document

ENC = encode_meeting_uuid(UUID)
DOC = recording_document_id(UUID)

HOST_ID = "u0host"
HOST_EMAIL = "host@acme.com"

#: Vouched canonicals (a real directory sync created them); an email absent
#: here fails the existence check and confers nothing (G2).
REGISTRY_MAP = {
    "user:host@acme.com": 501,
    "user:pat@acme.com": 502,
    "group:zoom-internal": 700,
}

MEETING_DATE = "2026-07-14"
START_TIME = "2026-07-14T10:00:00Z"
REC_END = "2026-07-14T10:30:00Z"
REC_END_EARLY = "2026-07-14T10:15:00Z"

_CLOCK_NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = "2026-07-20T12:00:00Z"
RECENT_RECONCILE = "2026-07-20T11:00:00Z"  # 1h before the clock: within the SLA

TRANSCRIPT_URL = "https://zoom.example/rec/download/tr1"

VTT = (
    "WEBVTT\n"
    "\n"
    "1\n"
    "00:00:01.000 --> 00:00:03.000\n"
    "Host Person: hello everyone\n"
    "\n"
    "2\n"
    "00:00:03.500 --> 00:00:06.000\n"
    "Host Person: hello everyone welcome\n"
    "\n"
    "3\n"
    "00:00:06.500 --> 00:00:09.000\n"
    "Pat: hi there\n"
)

#: The rendered document for the default workspace (digests are taken over
#: these exact bytes).
CONTENT = (
    "Zoom recording: Weekly Sync\n"
    f"Start: {START_TIME}\n"
    f"Host: {HOST_EMAIL}\n"
    "Participants: Pat, Guest Visitor\n"
    "\n"
    "[00:00:01] Host Person: hello everyone welcome\n"
    "[00:00:06] Pat: hi there"
)


def _clock() -> datetime:
    return _CLOCK_NOW


# ---------------------------------------------------------------------------
# Fixture builders (Zoom API shapes)
# ---------------------------------------------------------------------------


def _meeting(uuid: str = UUID, **kw) -> dict:
    base = {
        "uuid": uuid,
        "id": NUMERIC_ID,
        "host_id": HOST_ID,
        "topic": "Weekly Sync",
        "start_time": START_TIME,
        "duration": 30,
    }
    base.update(kw)
    return base


def _settings(**kw) -> dict:
    base = {
        "share_recording": "none",
        "recording_authentication": False,
        "authentication_domains": "",
        "password": "",
    }
    base.update(kw)
    return base


def _detail(recording_end: str = REC_END, with_transcript: bool = True) -> dict:
    files = [
        {
            "id": "f-mp4",
            "file_type": "MP4",
            "recording_start": START_TIME,
            "recording_end": recording_end,
            "download_url": "https://zoom.example/rec/download/mp4",
        }
    ]
    if with_transcript:
        files.append(
            {
                "id": "f-vtt",
                "file_type": "TRANSCRIPT",
                "recording_start": START_TIME,
                "recording_end": recording_end,
                "download_url": TRANSCRIPT_URL,
            }
        )
    return {"uuid": UUID, "id": NUMERIC_ID, "topic": "Weekly Sync", "recording_files": files}


PARTICIPANTS = {
    "participants": [
        {"id": "p1", "name": "Pat", "user_email": "pat@acme.com"},
        # The null-guard case: a guest never signs in — user_email absent.
        {"id": "", "name": "Guest Visitor"},
    ]
}


class FixtureZoomTransport:
    """ZoomTransport backed by in-memory routes.

    ``routes`` maps an API path to a response dict, a callable
    ``params -> dict``, or a :class:`ZoomApiError` to raise. ``downloads``
    maps a download_url to bytes. Calls are recorded so tests can assert what
    was (and was NOT) fetched — the ACL-before-content claims are call-log
    claims."""

    def __init__(self, routes, downloads=None) -> None:
        self.routes = dict(routes)
        self.downloads = dict(downloads or {})
        self.calls: list[tuple[str, dict]] = []
        self.downloaded: list[str] = []

    def get(self, path: str, params) -> dict:
        self.calls.append((path, dict(params)))
        route = self.routes.get(path)
        if route is None:
            raise AssertionError(f"unexpected zoom call {path} {params}")
        result = route(dict(params)) if callable(route) else route
        if isinstance(result, ZoomApiError):
            raise result
        return dict(result)

    def download(self, url: str) -> bytes:
        self.downloaded.append(url)
        blob = self.downloads.get(url)
        if blob is None:
            raise AssertionError(f"unexpected download {url}")
        return blob

    def called(self, path: str) -> list[dict]:
        return [p for c, p in self.calls if c == path]

    def called_prefix(self, prefix: str) -> list[tuple[str, dict]]:
        return [(c, p) for c, p in self.calls if c.startswith(prefix)]


def _err(path: str, status: int = 404, code: int = 3001) -> ZoomApiError:
    return ZoomApiError(path, status, code, "Meeting does not exist")


def _workspace(
    *,
    meetings: list[dict] | None = None,
    settings=None,
    detail=None,
    participants=None,
    user=None,
    vtt: bytes = VTT.encode(),
    uuid: str = UUID,
) -> FixtureZoomTransport:
    """The default one-host workspace: one July recording with a transcript."""
    enc = encode_meeting_uuid(uuid)
    if meetings is None:
        meetings = [_meeting(uuid)]

    def list_route(params: dict) -> dict:
        frm, to = params["from"], params["to"]
        assert frm[:7] == to[:7], f"list window spans months: {frm}..{to}"  # the 1-month cap
        assert int(params["page_size"]) <= 300
        listed = [m for m in meetings if frm <= str(m.get("start_time") or "")[:10] <= to]
        return {"meetings": listed, "next_page_token": ""}

    return FixtureZoomTransport(
        {
            f"users/{HOST_ID}/recordings": list_route,
            f"users/{HOST_ID}": user if user is not None else {"id": HOST_ID, "email": HOST_EMAIL},
            f"meetings/{enc}/recordings/settings": settings if settings is not None else _settings(),
            f"meetings/{enc}/recordings": detail if detail is not None else _detail(),
            f"past_meetings/{enc}/participants": (
                participants if participants is not None else PARTICIPANTS
            ),
        },
        {TRANSCRIPT_URL: vtt},
    )


def _connector(transport: FixtureZoomTransport, **cfg) -> ZoomConnector:
    defaults = dict(
        tenant_id=TENANT,
        user_ids=(HOST_ID,),
        internal_maps_to="group:zoom-internal",
        internal_domains=frozenset({"acme.com"}),
    )
    defaults.update(cfg)
    return ZoomConnector(transport, ZoomConfig(**defaults), clock=_clock)


def _seed_state(tmp_path, meetings: dict, *, last_reconcile_at=RECENT_RECONCILE):
    state = {"meetings": meetings, "last_reconcile_at": last_reconcile_at}
    state_file = tmp_path / "zoom_cursor.json"
    state_file.write_text(
        json.dumps({"cursor": json.dumps(state, sort_keys=True)}, indent=2) + "\n"
    )
    return state_file


def _saved_state(state_file) -> dict:
    return json.loads(json.loads(state_file.read_text())["cursor"])


def _ledger(tmp_path) -> list[dict]:
    return json.loads((tmp_path / "zoom_parked_retractions.json").read_text())


def _entry(delivered: str, text: str, day: str = MEETING_DATE) -> dict:
    return {
        "date": day,
        "status": "mirrored",
        "delivered": delivered,
        "digest": content_digest(text.encode()),
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
    """AlarmSink + the ``retire`` transport (the live ZoomStatusSink shape):
    every replay succeeds (a 2xx), bodies captured byte-exact. ``calls``
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


REGISTRY = StaticZoomRegistry(REGISTRY_MAP)


def _run(connector, sink, state_file, registry=REGISTRY):
    return run_once(connector, registry, sink, state_file)


# ---------------------------------------------------------------------------
# G1 — the share_recording ACL table, poison branches first
# ---------------------------------------------------------------------------


def test_unreadable_settings_poison_quarantine_and_no_content_fetch(tmp_path):
    # The FIRST fetch is the settings read; when it fails the recording is
    # poison — parked as a quarantine, and crucially NOTHING else was fetched
    # (no participants, no recording files, no VTT: ACL-before-content).
    transport = _workspace(
        settings=_err(f"meetings/{ENC}/recordings/settings"),
    )
    sink = RetiringSink()
    state_file = tmp_path / "zoom_cursor.json"
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0 and sink.requests == []
    assert sink.retired == [
        {"tenant_id": TENANT, "source": "zoom", "document_id": DOC, "reason": "quarantined"}
    ]
    assert transport.called(f"past_meetings/{ENC}/participants") == []
    assert transport.called(f"meetings/{ENC}/recordings") == []
    assert transport.downloaded == []
    assert _saved_state(state_file)["meetings"][UUID]["status"] == "quarantined"


def test_unknown_share_enum_is_poison():
    decision = classify_share_audience(_settings(share_recording="with_approval"), ZoomConfig())
    assert decision.quarantined and decision.reason == "unknown-share-setting"
    assert classify_share_audience({"no": "share key"}, ZoomConfig()).quarantined
    assert classify_share_audience(None, ZoomConfig()).reason == "settings-unreadable"


def test_publicly_shared_quarantines_even_with_a_passcode(tmp_path):
    # A passcode gates the LINK, not an audience the connector can name —
    # publicly + passcode must still quarantine, with no VTT fetch.
    transport = _workspace(
        settings=_settings(share_recording="publicly", password="s3cret", viewer_download=True)
    )
    sink = RetiringSink()
    state_file = tmp_path / "zoom_cursor.json"
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert transport.downloaded == []
    assert transport.called(f"past_meetings/{ENC}/participants") == []


def test_share_none_delivers_host_only_mirrored_byte_exact(tmp_path):
    transport = _workspace()
    sink = RetiringSink()
    state_file = tmp_path / "zoom_cursor.json"
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 1
    assert sink.requests == [
        {
            "tenant_id": TENANT,
            "source": "zoom",
            "document_id": DOC,
            "entities": [],
            "valid_from": REC_END,  # the recording END ts
            "content": CONTENT,
            "visibility": [501],  # the host alone — nobody else
            "acl_provenance": "mirrored",
        }
    ]
    # Participants were fetched for CONTEXT (names in the header) but did not
    # widen visibility: the opt-in flag is off.
    assert transport.called(f"past_meetings/{ENC}/participants") != []
    assert _saved_state(state_file)["meetings"][UUID] == _entry(REC_END, CONTENT)


def test_share_internally_delivers_operator_token_plus_host_admin_assigned(tmp_path):
    transport = _workspace(settings=_settings(share_recording="internally"))
    sink = RetiringSink()
    delivered = _run(_connector(transport), sink, tmp_path / "zoom_cursor.json")
    assert delivered == 1
    (body,) = sink.requests
    assert body["visibility"] == [501, 700]  # host + the operator-declared token
    assert body["acl_provenance"] == "admin-assigned"  # an admin policy, not a source ACL


def test_share_internally_without_maps_to_quarantines_no_content_fetch(tmp_path):
    transport = _workspace(settings=_settings(share_recording="internally"))
    sink = RetiringSink()
    delivered = _run(
        _connector(transport, internal_maps_to=None), sink, tmp_path / "zoom_cursor.json"
    )
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert transport.downloaded == []
    assert transport.called(f"past_meetings/{ENC}/participants") == []


def test_authentication_domains_mismatch_quarantines_match_delivers(tmp_path):
    # Zoom would admit sign-ins from a domain the operator's token was never
    # declared to cover → quarantine.
    mismatch = _workspace(
        settings=_settings(
            share_recording="internally",
            recording_authentication=True,
            authentication_domains="acme.com,partner.example",
        )
    )
    sink = RetiringSink()
    delivered = _run(_connector(mismatch), sink, tmp_path / "zoom_cursor.json")
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert mismatch.downloaded == []
    # The declared set matching exactly delivers (list form tolerated too).
    for domains in ("acme.com", ["acme.com"]):
        match = _workspace(
            settings=_settings(
                share_recording="internally",
                recording_authentication=True,
                authentication_domains=domains,
            )
        )
        sink2 = RetiringSink()
        delivered = _run(_connector(match), sink2, tmp_path / f"c-{len(str(domains))}.json")
        assert delivered == 1, domains
        assert sink2.requests[0]["visibility"] == [501, 700]


def test_unvouched_host_quarantines_before_any_content_fetch(tmp_path):
    # The host's canonical does not pre-exist in the registry (never vouched
    # by a directory sync): the host-anchored audience is unprovable →
    # quarantine — and the VTT was never downloaded (vouch gate is part of
    # ACL-before-content).
    transport = _workspace()
    sink = RetiringSink()
    registry = StaticZoomRegistry({"group:zoom-internal": 700})  # no user:host@acme.com
    delivered = _run(_connector(transport), sink, tmp_path / "zoom_cursor.json", registry)
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert transport.downloaded == []
    assert transport.called(f"meetings/{ENC}/recordings") == []
    # The vouch gate decided BEFORE the participants read: no attendee
    # names/emails were pulled for a recording the gate quarantined.
    assert transport.called(f"past_meetings/{ENC}/participants") == []


def test_vouch_gate_quarantines_fetch_no_participants(tmp_path):
    # REGRESSION (review finding 2): a vouch-gate quarantine — host-unvouched
    # OR internal-token-unresolved — must trigger NO participants fetch:
    # attendee names + emails are content too, and ACL-before-content covers
    # the participants read, not just the VTT.
    unvouched = _workspace()
    sink = RetiringSink()
    _run(_connector(unvouched), sink, tmp_path / "a.json", StaticZoomRegistry({}))
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert unvouched.called(f"past_meetings/{ENC}/participants") == []
    assert unvouched.downloaded == []
    # internally + a declared token the registry cannot resolve: same gate.
    token_less = _workspace(settings=_settings(share_recording="internally"))
    sink2 = RetiringSink()
    _run(
        _connector(token_less),
        sink2,
        tmp_path / "b.json",
        StaticZoomRegistry({"user:host@acme.com": 501}),  # no group:zoom-internal
    )
    assert [r["reason"] for r in sink2.retired] == ["quarantined"]
    assert token_less.called(f"past_meetings/{ENC}/participants") == []
    assert token_less.downloaded == []


def test_unreadable_host_email_quarantines(tmp_path):
    transport = _workspace(user=_err(f"users/{HOST_ID}", 404, 1001))
    sink = RetiringSink()
    delivered = _run(_connector(transport), sink, tmp_path / "zoom_cursor.json")
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["quarantined"]
    assert transport.downloaded == []


def test_quarantined_body_carries_no_visibility_and_no_content():
    event = ZoomDocumentEvent(
        source="zoom",
        document_id=DOC,
        content=b"never indexed",
        mime_type="text/plain",
        version="",
        acl=AclEnvelope(resolvable=False),
        modified_time=NOW_ISO,
        meeting_uuid=UUID,
        quarantine_reason="publicly-shared",
    )
    body = build_zoom_document_request(event, TENANT)
    assert "visibility" not in body
    assert body["acl_provenance"] == "quarantined"
    assert body["content"] is None
    # Zero surviving tokens also quarantines (never index open).
    empty = ZoomDocumentEvent(
        source="zoom",
        document_id=DOC,
        content=b"hello",
        mime_type="text/plain",
        version=REC_END,
        acl=AclEnvelope(resolvable=True),
        modified_time=REC_END,
        meeting_uuid=UUID,
        visibility_tokens=[],
    )
    body = build_zoom_document_request(empty, TENANT)
    assert "visibility" not in body and body["acl_provenance"] == "quarantined"


# ---------------------------------------------------------------------------
# G2 — participants: opt-in only, vouched only, narrowing never poison
# ---------------------------------------------------------------------------


def test_participants_join_audience_only_under_the_opt_in_flag(tmp_path):
    participants = {
        "participants": [
            {"id": "p1", "name": "Pat", "user_email": "pat@acme.com"},  # vouched
            {"id": "p2", "name": "Eve", "user_email": "eve@acme.com"},  # NOT vouched
            {"id": "", "name": "Guest Visitor"},  # no user_email (null guard)
        ]
    }
    # Flag OFF (the default): host only.
    off = _workspace(participants=participants)
    sink_off = RetiringSink()
    _run(_connector(off), sink_off, tmp_path / "off.json")
    assert sink_off.requests[0]["visibility"] == [501]
    assert sink_off.requests[0]["acl_provenance"] == "mirrored"
    # Flag ON: only the VOUCHED participant joins; Eve and the guest confer
    # nothing (narrowing, never poison — the delivery still lands).
    on = _workspace(participants=participants)
    sink_on = RetiringSink()
    _run(_connector(on, participants_in_audience=True), sink_on, tmp_path / "on.json")
    (body,) = sink_on.requests
    assert body["visibility"] == [501, 502]
    # A participant-widened audience is at best a container approximation.
    assert body["acl_provenance"] == "approximated"


def test_participants_widening_floors_at_the_weakest_claim(tmp_path):
    transport = _workspace(settings=_settings(share_recording="internally"))
    sink = RetiringSink()
    _run(
        _connector(transport, participants_in_audience=True), sink, tmp_path / "zoom_cursor.json"
    )
    (body,) = sink.requests
    assert body["visibility"] == [501, 502, 700]
    # internally (admin-assigned) + participants (approximated) → the WEAKER
    # claim wins: admin-assigned.
    assert body["acl_provenance"] == "admin-assigned"
    assert floor_provenance("mirrored", "approximated") == "approximated"
    assert floor_provenance("admin-assigned", "approximated") == "admin-assigned"
    assert floor_provenance("mirrored") == "mirrored"


def test_failed_participants_read_narrows_but_never_poisons(tmp_path):
    transport = _workspace(participants=_err(f"past_meetings/{ENC}/participants", 404, 3001))
    sink = RetiringSink()
    delivered = _run(
        _connector(transport, participants_in_audience=True), sink, tmp_path / "zoom_cursor.json"
    )
    assert delivered == 1  # host anchor carries the grant
    (body,) = sink.requests
    assert body["visibility"] == [501]
    assert "Participants:" not in body["content"]


# ---------------------------------------------------------------------------
# G3 — identity of the document + UUID encoding + the monotonic stamp guard
# ---------------------------------------------------------------------------


def test_document_id_uses_the_uuid_never_the_numeric_meeting_id(tmp_path):
    transport = _workspace()
    sink = RetiringSink()
    _run(_connector(transport), sink, tmp_path / "zoom_cursor.json")
    assert sink.requests[0]["document_id"] == f"zoom:{UUID}"
    assert str(NUMERIC_ID) not in sink.requests[0]["document_id"]


def test_meeting_uuids_are_double_encoded_in_every_path(tmp_path):
    # The "//"-bearing, "/"-leading UUID must ride DOUBLE-encoded (else 3001);
    # defensively every UUID is, which the fixture routes themselves pin (the
    # route key IS the double-encoded path).
    enc = encode_meeting_uuid(UUID_SLASHY)
    assert enc == quote(quote(UUID_SLASHY, safe=""), safe="")
    assert "//" not in enc and not enc.startswith("/")
    assert "%252F" in enc  # "/" → %2F → %252F: encoded TWICE, not once
    transport = _workspace(uuid=UUID_SLASHY)
    sink = RetiringSink()
    delivered = _run(_connector(transport), sink, tmp_path / "zoom_cursor.json")
    assert delivered == 1
    paths = [c for c, _ in transport.calls]
    assert f"meetings/{enc}/recordings/settings" in paths
    assert f"meetings/{enc}/recordings" in paths
    assert f"past_meetings/{enc}/participants" in paths
    # The document id keeps the RAW uuid (identity), not the encoding.
    assert sink.requests[0]["document_id"] == f"zoom:{UUID_SLASHY}"


def test_unchanged_recording_is_skipped_not_redelivered(tmp_path):
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    sink = RetiringSink()
    delivered = _run(_connector(_workspace()), sink, state_file)
    assert delivered == 0 and sink.requests == []
    assert sink.retired == []  # carried, never mistaken for deleted
    assert _saved_state(state_file)["meetings"][UUID] == _entry(REC_END, CONTENT)


def test_deleting_the_latest_file_regresses_the_stamp_but_still_supersedes(tmp_path):
    # THE L1 LEAK (the slack lesson): valid_from = the recording end ts, which
    # REGRESSES when the latest recording file is deleted — while the server
    # retires only rows strictly OLDER than the incoming stamp. An honest
    # re-delivery at the regressed stamp would leave TWO open rows serving the
    # deleted content. The guard must advance valid_from past the bookkept
    # delivered stamp (detection-time signal: the cycle clock).
    short_vtt = "WEBVTT\n\n1\n00:00:01.000 --> 00:00:03.000\nHost Person: hello everyone\n"
    transport = _workspace(detail=_detail(recording_end=REC_END_EARLY), vtt=short_vtt.encode())
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 1
    (body,) = sink.requests
    assert "welcome" not in body["content"]  # the deleted tail is gone
    assert body["valid_from"] == NOW_ISO  # > REC_END: the old row retires
    assert _saved_state(state_file)["meetings"][UUID]["delivered"] == NOW_ISO


def test_transcript_edit_at_the_same_stamp_advances_valid_from(tmp_path):
    # A transcript edit keeps the recording end ts — the server's replay
    # DO-NOTHING would silently drop the redaction at a non-advancing stamp.
    edited = VTT.replace("hi there", "hi there (redacted)")
    transport = _workspace(vtt=edited.encode())
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 1
    (body,) = sink.requests
    assert "(redacted)" in body["content"]
    assert body["valid_from"] == NOW_ISO  # advanced past the bookkept REC_END


# ---------------------------------------------------------------------------
# G4 — absence-diff park + drain, race guards verbatim
# ---------------------------------------------------------------------------


def test_absence_of_a_bookkept_uuid_parks_and_drains_byte_exact(tmp_path):
    # The recording is GONE from the re-listed window (trashed or deleted —
    # the default list omits both): absence IS the retraction signal.
    transport = _workspace(meetings=[])
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0
    assert sink.retired == [
        {"tenant_id": TENANT, "source": "zoom", "document_id": DOC, "reason": "removed"}
    ]
    assert _ledger(tmp_path) == []  # drained
    assert sink.alarm_kinds() == []  # nothing left parked
    assert _saved_state(state_file)["meetings"] == {}


def test_mirrored_to_quarantined_transition_retires_the_indexed_content(tmp_path):
    # Yesterday it delivered; today the host flipped it to publicly-shared:
    # the transition parks a quarantine retraction for the indexed document.
    transport = _workspace(settings=_settings(share_recording="publicly"))
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0
    assert sink.retired == [
        {"tenant_id": TENANT, "source": "zoom", "document_id": DOC, "reason": "quarantined"}
    ]
    assert _saved_state(state_file)["meetings"][UUID]["status"] == "quarantined"


def test_failed_list_never_absence_retracts(tmp_path):
    # The host's list 429/500s away: a partial list must NEVER read as mass
    # deletion — nothing retires, bookkeeping is carried, the failure counted.
    transport = FixtureZoomTransport(
        {f"users/{HOST_ID}/recordings": _err(f"users/{HOST_ID}/recordings", 429, None)}
    )
    connector = _connector(transport)
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(connector, sink, state_file)
    assert delivered == 0
    assert sink.retired == []
    assert not (tmp_path / "zoom_parked_retractions.json").exists() or _ledger(tmp_path) == []
    assert connector.list_failures == [HOST_ID]
    assert _saved_state(state_file)["meetings"][UUID] == _entry(REC_END, CONTENT)


def test_preexisting_ledger_drains_before_any_delivery(tmp_path):
    old_doc = "zoom:OLDuuid=="
    state_file = _seed_state(tmp_path, {})
    (tmp_path / "zoom_parked_retractions.json").write_text(
        json.dumps(
            [
                {
                    "meeting_uuid": "OLDuuid==",
                    "document_id": old_doc,
                    "reason": "removed",
                    "first_seen": "2026-07-18T00:00:00Z",
                    "last_seen": "2026-07-18T00:00:00Z",
                }
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    sink = RetiringSink()
    _run(_connector(_workspace()), sink, state_file)
    # Guard #1: the stale ledger entry replayed BEFORE anything delivered.
    assert sink.calls[0] == ("retire", old_doc)
    assert ("deliver", DOC) in sink.calls
    assert _ledger(tmp_path) == []


def test_restored_recording_unparks_its_stale_retraction(tmp_path):
    # A recording parked in an earlier cycle (e.g. trashed) is DELIVERED this
    # cycle (recovered). The pre-drain replay FAILS (retire route down) so the
    # entry survives guard #1 — guard #2 (unpark-on-delivery) must remove it,
    # or a later drain would blank the chunks the delivery just wrote.
    state_file = _seed_state(tmp_path, {})
    (tmp_path / "zoom_parked_retractions.json").write_text(
        json.dumps(
            [
                {
                    "meeting_uuid": UUID,
                    "document_id": DOC,
                    "reason": "removed",
                    "first_seen": "2026-07-18T00:00:00Z",
                    "last_seen": "2026-07-18T00:00:00Z",
                }
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    sink = FailingRetireSink()
    _run(_connector(_workspace()), sink, state_file)
    assert ("deliver", DOC) in sink.calls
    assert _ledger(tmp_path) == []  # guard #2: unparked by the newer delivery
    after_delivery = sink.calls[sink.calls.index(("deliver", DOC)) + 1 :]
    assert ("retire", DOC) not in after_delivery
    assert "parked_retraction" not in sink.alarm_kinds()


def test_failed_retire_replay_stays_parked_and_alarmed_then_drains(tmp_path):
    transport = _workspace(meetings=[])
    sink = FailingRetireSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    _run(_connector(transport), sink, state_file)
    entries = _ledger(tmp_path)
    assert [e["document_id"] for e in entries] == [DOC]
    assert entries[0]["meeting_uuid"] == UUID
    assert "parked_retraction" in sink.alarm_kinds()
    # A NEXT cycle with a healthy retire route drains it (idempotent replay).
    sink2 = RetiringSink()
    _run(_connector(_workspace(meetings=[])), sink2, state_file)
    assert [r["document_id"] for r in sink2.retired] == [DOC]
    assert _ledger(tmp_path) == []


def test_transcript_vanishing_from_a_delivered_recording_retracts(tmp_path):
    # The meeting still lists, but its TRANSCRIPT file is gone: the indexed
    # text no longer exists at the source — retract, don't serve stale.
    transport = _workspace(detail=_detail(with_transcript=False))
    sink = RetiringSink()
    state_file = _seed_state(tmp_path, {UUID: _entry(REC_END, CONTENT)})
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0
    assert [r["reason"] for r in sink.retired] == ["removed"]
    assert UUID not in _saved_state(state_file)["meetings"]


def test_transcriptless_never_delivered_recording_is_counted_not_indexed(tmp_path):
    transport = _workspace(detail=_detail(with_transcript=False))
    connector = _connector(transport)
    sink = RetiringSink()
    delivered = _run(connector, sink, tmp_path / "zoom_cursor.json")
    assert delivered == 0 and sink.requests == [] and sink.retired == []
    assert connector.transcriptless == [UUID]


# ---------------------------------------------------------------------------
# Month windows & backfill
# ---------------------------------------------------------------------------


def test_month_windows_never_span_a_month_boundary():
    windows = month_windows(date(2026, 4, 20), date(2026, 7, 20))
    assert windows == [
        ("2026-04-20", "2026-04-30"),
        ("2026-05-01", "2026-05-31"),
        ("2026-06-01", "2026-06-30"),
        ("2026-07-01", "2026-07-20"),
    ]
    assert month_windows(date(2026, 7, 1), date(2026, 7, 1)) == [("2026-07-01", "2026-07-01")]
    assert month_windows(date(2026, 7, 2), date(2026, 7, 1)) == []
    # December rolls the year without crashing.
    assert month_windows(date(2025, 12, 15), date(2026, 1, 5)) == [
        ("2025-12-15", "2025-12-31"),
        ("2026-01-01", "2026-01-05"),
    ]


def test_backfill_chunks_months_and_stamps_the_sla_on_zero_failure(tmp_path):
    transport = _workspace()
    connector = _connector(transport, backfill_months=3)
    sink = RetiringSink()
    state_file = tmp_path / "zoom_cursor.json"
    delivered = run_backfill(connector, REGISTRY, sink, state_file)
    assert delivered == 1
    # Every list window stayed inside ONE month (the route asserts it) and
    # the crawl covered several months.
    list_windows = [
        (p["from"], p["to"]) for p in transport.called(f"users/{HOST_ID}/recordings")
    ]
    assert len(list_windows) >= 3
    for frm, to in list_windows:
        assert frm[:7] == to[:7] and frm <= to
    state = _saved_state(state_file)
    assert state["last_reconcile_at"] == NOW_ISO  # zero-failure pass stamps
    assert state["meetings"][UUID] == _entry(REC_END, CONTENT)


def test_backfill_with_ingest_failures_does_not_stamp_the_sla(tmp_path):
    transport = _workspace()
    connector = _connector(transport, backfill_months=1)
    sink = FailingSink({DOC})
    state_file = tmp_path / "zoom_cursor.json"
    delivered = run_backfill(connector, REGISTRY, sink, state_file)
    assert delivered == 0
    state = _saved_state(state_file)
    assert state["last_reconcile_at"] is None  # NOT re-proven; SLA stays unmet
    assert "backfill_incomplete" in sink.alarm_kinds()


def test_backfill_sweeps_deletions_older_than_the_poll_lookback(tmp_path):
    # Deleted in June, poll lookback is 7 days — only the reconcile sees it.
    gone_uuid = "JUNEuuidgone=="
    transport = _workspace()  # lists only the July meeting
    connector = _connector(transport, backfill_months=3)
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path,
        {
            UUID: _entry(REC_END, CONTENT),
            gone_uuid: _entry("2026-06-10T10:00:00Z", "old", day="2026-06-10"),
        },
        last_reconcile_at=None,
    )
    run_backfill(connector, REGISTRY, sink, state_file)
    assert sink.retired == [
        {
            "tenant_id": TENANT,
            "source": "zoom",
            "document_id": f"zoom:{gone_uuid}",
            "reason": "removed",
        }
    ]
    state = _saved_state(state_file)
    assert gone_uuid not in state["meetings"]
    assert state["last_reconcile_at"] == NOW_ISO


def test_backfill_crash_parks_detected_retractions_before_the_cursor(tmp_path):
    # REGRESSION (review finding 1, the retraction-durability LEAK): the
    # mid-crawl/crash checkpoint saves a book from which absence-retracted
    # uuids were already POPPED — if the pending parks are not persisted to
    # the ledger before (or with) that cursor, a crash makes the retraction
    # unrecoverable: no book entry left to diff, no ledger entry to drain,
    # and the DELETED recording serves forever.
    gone_uuid = "JUNEuuidgone=="

    def list_route(params: dict) -> dict:
        if str(params["from"]).startswith("2026-07"):
            raise RuntimeError("boom mid-crawl")  # the July window crashes
        return {"meetings": [], "next_page_token": ""}

    transport = FixtureZoomTransport({f"users/{HOST_ID}/recordings": list_route})
    connector = _connector(transport, backfill_months=3)
    sink = RetiringSink()
    state_file = _seed_state(
        tmp_path,
        {gone_uuid: _entry("2026-06-10T10:00:00Z", "old", day="2026-06-10")},
        last_reconcile_at=None,
    )
    with pytest.raises(RuntimeError, match="boom mid-crawl"):
        run_backfill(connector, REGISTRY, sink, state_file)
    # The June absence-retraction is DURABLE despite the crash: the cursor's
    # book no longer carries the uuid, so the ledger MUST.
    assert [e["document_id"] for e in _ledger(tmp_path)] == [f"zoom:{gone_uuid}"]
    assert gone_uuid not in _saved_state(state_file)["meetings"]
    # A subsequent healthy cycle pre-drains it: the deletion is enforced.
    sink2 = RetiringSink()
    _run(_connector(_workspace(meetings=[])), sink2, state_file)
    assert [r["document_id"] for r in sink2.retired] == [f"zoom:{gone_uuid}"]
    assert _ledger(tmp_path) == []


def test_ghost_bookkept_entries_block_the_reconcile_stamp(tmp_path):
    # REGRESSION (review finding 5): a bookkept entry NO crawled window can
    # ever re-list — an empty/malformed date, or a date beyond the whole
    # backfill horizon — can never be absence-retracted; a zero-failure crawl
    # must NOT stamp last_reconcile_at over it (the stamp would falsely
    # assert its deletion story was re-proven).
    transport = _workspace()
    connector = _connector(transport, backfill_months=3)
    sink = RetiringSink()
    ghost = "GHOSTdateless=="
    ancient = "ANCIENTuuid=="
    state_file = _seed_state(
        tmp_path,
        {
            UUID: _entry(REC_END, CONTENT),
            ghost: _entry("2026-01-01T00:00:00Z", "old", day=""),  # malformed date
            ancient: _entry("2020-01-01T00:00:00Z", "older", day="2020-01-01"),
        },
        last_reconcile_at=None,
    )
    delivered = run_backfill(connector, REGISTRY, sink, state_file)
    assert delivered == 0  # the live recording is unchanged (carried, not re-sent)
    assert connector.reconcile_unswept == sorted([ghost, ancient])
    state = _saved_state(state_file)
    assert state["last_reconcile_at"] is None  # NOT re-proven; SLA stays unmet
    assert "backfill_incomplete" in sink.alarm_kinds()
    # Alarmed, not blindly retired: the recordings may still exist at Zoom.
    assert sink.retired == []


# ---------------------------------------------------------------------------
# Heartbeats & alarms
# ---------------------------------------------------------------------------


def test_status_sink_idle_cycle_heartbeats_zero_with_source_zoom():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    sink = ZoomStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.alarm_tenant_id = TENANT  # runner wiring (main sets this)
    sink.heartbeat(cursor="zoom-cursor-42")
    assert posts == [
        (
            "/v1/admin/connector-status",
            {
                "tenant_id": TENANT,
                "source": "zoom",
                "items_synced": 0,
                "cursor": "zoom-cursor-42",
            },
        )
    ]


def test_status_sink_heartbeat_carries_alarms_even_with_zero_deliveries():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    sink = ZoomStatusSink(
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
                "source": "zoom",
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
        {"tenant_id": TENANT, "source": "zoom", "items_synced": 0},
    )


def test_status_sink_retire_posts_the_admin_retire_body_and_raises_on_failure():
    posts: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append((request.url.path, json.loads(request.content)))
        if len(posts) > 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"chunks_retired": 2})

    sink = ZoomStatusSink(
        "http://verity.local:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    body = {"tenant_id": TENANT, "source": "zoom", "document_id": DOC, "reason": "removed"}
    sink.retire(body)
    assert posts == [(RETIRE_PATH, body)]
    with pytest.raises(httpx.HTTPStatusError):
        sink.retire(body)


def test_idle_cycle_still_heartbeats_and_reconcile_overdue_alarms(tmp_path):
    transport = _workspace(meetings=[])
    sink = AlarmSink()
    # Never reconciled: the alarm must fire on an otherwise-idle cycle.
    state_file = _seed_state(tmp_path, {}, last_reconcile_at=None)
    delivered = _run(_connector(transport), sink, state_file)
    assert delivered == 0
    assert sink.alarm_kinds() == ["reconcile_overdue"]
    assert len(sink.heartbeats) == 1  # EVERY cycle beats, idle included
    # A fresh reconcile silences it.
    sink2 = AlarmSink()
    _run(_connector(_workspace(meetings=[])), sink2, _seed_state(tmp_path, {}))
    assert "reconcile_overdue" not in sink2.alarm_kinds()


# ---------------------------------------------------------------------------
# Transport: 429/Retry-After, the token mint, credentials
# ---------------------------------------------------------------------------


def _oauth(handler) -> ZoomOAuth:
    return ZoomOAuth(
        "acct-1",
        "client-1",
        "s3cret",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_oauth_mints_on_zoom_us_with_basic_auth_and_account_credentials():
    minted: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        minted.append(request)
        return httpx.Response(200, json={"access_token": f"tok-{len(minted)}", "expires_in": 3600})

    clock_now = [0.0]
    oauth = ZoomOAuth(
        "acct-1",
        "client-1",
        "s3cret",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: clock_now[0],
    )
    assert oauth.token() == "tok-1"
    request = minted[0]
    # The mint host is zoom.us, NOT api.zoom.us — the doc-sourced fact.
    assert str(request.url) == ZOOM_OAUTH_TOKEN_URL
    assert "api.zoom.us" not in str(request.url)
    import base64 as _b64

    assert request.headers["Authorization"] == "Basic " + _b64.b64encode(
        b"client-1:s3cret"
    ).decode()
    body = request.content.decode()
    assert "grant_type=account_credentials" in body and "account_id=acct-1" in body
    # Cached until near expiry; there is NO refresh grant — expiry re-mints.
    assert oauth.token() == "tok-1" and len(minted) == 1
    clock_now[0] = 3590.0  # inside the 60s slack window
    assert oauth.token() == "tok-2" and len(minted) == 2


def test_http_transport_honors_429_retry_after_on_get_and_download():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == ZOOM_OAUTH_TOKEN_URL:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(429, headers={"Retry-After": "2.5"})
        if request.url.path.endswith("/download/tr1"):
            return httpx.Response(200, content=b"WEBVTT")
        return httpx.Response(200, json={"meetings": []})

    sleeps: list[float] = []
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url=ZOOM_API_BASE_URL)
    oauth = _oauth(handler)
    transport = HttpZoomTransport(oauth, client=client, sleep=sleeps.append)
    payload = transport.get("users/u1/recordings", {"from": "2026-07-01", "to": "2026-07-20"})
    assert payload == {"meetings": []}
    assert sleeps == [2.5]  # slept exactly what Zoom asked, then retried
    assert seen[-1].headers["Authorization"] == "Bearer tok"
    assert transport.download("https://zoom.example/rec/download/tr1") == b"WEBVTT"


def test_http_transport_surfaces_the_zoom_error_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == ZOOM_OAUTH_TOKEN_URL:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(404, json={"code": 3001, "message": "Meeting does not exist"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url=ZOOM_API_BASE_URL)
    transport = HttpZoomTransport(_oauth(handler), client=client)
    with pytest.raises(ZoomApiError) as excinfo:
        transport.get("meetings/xyz/recordings/settings", {})
    assert excinfo.value.code == 3001 and excinfo.value.status == 404


def test_next_page_token_pagination_is_followed(tmp_path):
    pages: list[dict] = [
        {"meetings": [_meeting()], "next_page_token": "PAGE2"},
        {"meetings": [], "next_page_token": ""},
    ]
    calls: list[dict] = []

    def list_route(params: dict) -> dict:
        calls.append(params)
        if params.get("next_page_token"):
            assert params["next_page_token"] == "PAGE2"
            return pages[1]
        return pages[0]

    transport = _workspace()
    transport.routes[f"users/{HOST_ID}/recordings"] = list_route
    sink = RetiringSink()
    delivered = _run(_connector(transport), sink, tmp_path / "zoom_cursor.json")
    assert delivered == 1
    assert len(calls) == 2 and calls[1]["next_page_token"] == "PAGE2"


def test_secret_file_must_be_0600_and_envs_named_when_missing(tmp_path, monkeypatch):
    secret = tmp_path / "zoom_secret"
    secret.write_text("shhh-token\n")
    secret.chmod(0o644)
    monkeypatch.setenv("ZOOM_ACCOUNT_ID", "acct-1")
    monkeypatch.setenv("ZOOM_CLIENT_ID", "client-1")
    monkeypatch.setenv("ZOOM_CLIENT_SECRET_FILE", str(secret))
    with pytest.raises(PermissionError, match="0600"):
        load_zoom_credentials()
    secret.chmod(0o600)
    assert load_zoom_credentials() == ("acct-1", "client-1", "shhh-token")
    # An empty file is rejected attributably.
    secret.write_text("\n")
    secret.chmod(0o600)
    with pytest.raises(ValueError, match="empty"):
        load_zoom_credentials()
    # Missing envs are NAMED — never a half-configured run.
    monkeypatch.delenv("ZOOM_CLIENT_ID")
    monkeypatch.delenv("ZOOM_CLIENT_SECRET_FILE")
    with pytest.raises(RuntimeError, match="ZOOM_CLIENT_ID"):
        load_zoom_credentials()


def test_config_repr_never_echoes_the_client_secret():
    # REGRESSION (review finding 3): any debug print / log interpolation /
    # traceback formatting of the config must not leak the secret.
    cfg = ZoomConfig(
        tenant_id=TENANT,
        account_id="acct-1",
        client_id="client-1",
        client_secret="SUPER-SECRET-VALUE",
    )
    assert "SUPER-SECRET-VALUE" not in repr(cfg)
    assert "SUPER-SECRET-VALUE" not in str(cfg)
    assert "SUPER-SECRET-VALUE" not in f"{cfg}"
    # The non-secret fields still repr (debuggability is kept).
    assert "client-1" in repr(cfg)


# ---------------------------------------------------------------------------
# VTT parsing
# ---------------------------------------------------------------------------


def test_parse_vtt_speakers_rolling_dedup_and_turns():
    cues = parse_vtt(VTT)
    # Cue 2 extends cue 1 (a rolling caption): it REPLACES it, not both.
    assert cues == [
        ("00:00:01", "Host Person", "hello everyone welcome"),
        ("00:00:06", "Pat", "hi there"),
    ]
    assert render_transcript(cues) == (
        "[00:00:01] Host Person: hello everyone welcome\n[00:00:06] Pat: hi there"
    )


def test_parse_vtt_edge_cases():
    vtt = (
        "WEBVTT\n"
        "\n"
        "NOTE this block is metadata\n"
        "\n"
        "00:01.000 --> 00:03.000\n"
        "no speaker label here\n"
        "\n"
        "00:00:04.000 --> 00:00:06.000\n"
        "Pat: same words\n"
        "\n"
        "00:00:06.100 --> 00:00:08.000\n"
        "Pat: same words\n"
        "\n"
        "00:00:08.500 --> 00:00:10.000\n"
        "Pat: and a second turn line\n"
    )
    cues = parse_vtt(vtt)
    # mm:ss normalizes to hh:mm:ss; an exact same-speaker repeat is dropped;
    # consecutive same-speaker cues merge into ONE turn when rendered.
    assert cues == [
        ("00:00:01", "", "no speaker label here"),
        ("00:00:04", "Pat", "same words"),
        ("00:00:08", "Pat", "and a second turn line"),
    ]
    assert render_transcript(cues) == (
        "[00:00:01] unknown: no speaker label here\n"
        "[00:00:04] Pat: same words and a second turn line"
    )
    assert parse_vtt("WEBVTT\n") == []


def test_classify_table_is_total_over_the_documented_enum():
    config = ZoomConfig(
        internal_maps_to="group:zoom-internal", internal_domains=frozenset({"acme.com"})
    )
    assert not classify_share_audience(_settings(share_recording="none"), config).quarantined
    internally = classify_share_audience(_settings(share_recording="internally"), config)
    assert not internally.quarantined and internally.internal_token == "group:zoom-internal"
    assert classify_share_audience(_settings(share_recording="publicly"), config).quarantined
