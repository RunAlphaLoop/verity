"""Zoom cloud-recording transcript connector — recording-as-document content
connector with settings-derived, fail-closed visibility (build contract: the
red-teamed Zoom plan; structural template: :mod:`slack` for the bookkept
delivered-stamp/digest L1 guard and :mod:`sharepoint`/:mod:`gdrive` for the
park/drain retraction machinery, race guards, and alarms[] heartbeats).

The four load-bearing fail-closed guarantees (every design choice below serves
one; where one cannot be met the recording is QUARANTINED, never guessed):

G1 — settings-read-or-quarantine, ACL BEFORE content. For every listed
recording the FIRST fetch is ``GET /meetings/{uuid}/recordings/settings``; the
``share_recording`` enum {``publicly``, ``internally``, ``none``} is the whole
visibility signal Zoom exposes, and it is mapped conservatively:

- ``none`` → the HOST alone. The host's email (``GET /users/{host_id}``) must
  resolve to a canonical the directory sync ALREADY vouched — this connector
  never creates canonicals (Zoom profile data must not mint identity, the
  slack G2 lesson); an unreadable or unvouched host email QUARANTINES the
  recording (a host-only audience with no provable host is nobody, and
  indexing it under anything wider would be a leak).
- ``internally`` → the operator-declared ``ZOOM_INTERNAL_MAPS_TO`` principal
  token PLUS the host. The token is the operator's explicit assertion of what
  "everyone in the org signed-in" means in Verity terms; with it UNSET the
  recording quarantines (never guess an org-wide audience). When the settings
  carry a non-empty ``authentication_domains`` allowlist that differs from
  the operator-declared ``ZOOM_INTERNAL_DOMAINS`` set, the recording ALSO
  quarantines: Zoom would admit sign-ins from domains the operator's token
  was never declared to cover (or the operator declared domains Zoom does not
  enforce) — either mismatch makes the token an unproven audience.
- ``publicly`` → QUARANTINE, always. A passcode on the share link does NOT
  rescue it: a passcode gates the link, not an audience this connector can
  name — link-knowledge is not an ACL.
- an unrecognized ``share_recording`` value, or settings this connector could
  not read at all → QUARANTINE (poison posture: never guess what a new Zoom
  sharing mode reaches).

A quarantined recording's transcript is NEVER downloaded and its participants
are NEVER fetched — quarantine is decided on the settings/host reads alone
(ACL-before-content; the tests pin this as call-log negatives).

G2 — vouched-identity-or-nothing, narrowing-only participants. Audience
emails (the host; participants under the opt-in) resolve through the
``/v1/admin/principals`` ``emails`` gate, which only answers for ACTIVE
canonicals a REAL directory sync vouched — this connector never creates
``canonical_principal`` rows and emits NO admin ops at all. Participants join
the audience ONLY under ``ZOOM_PARTICIPANTS_IN_AUDIENCE=1`` (default OFF):
``GET /past_meetings/{uuid}/participants`` returns ``user_email`` only for
signed-in users (a behavioral, not contractual, observation — null-guarded),
so guests and unvouched attendees confer NOTHING. Dropping a participant only
NARROWS the audience (the host anchor already carries the grant), never
poisons — unlike the host facet, whose failure quarantines.

acl_provenance is stamped honestly per the house enum (mirrored /
approximated / admin-assigned / quarantined), floored across the facets that
actually widened the audience: ``none``→host-only is ``mirrored`` (Zoom's own
per-object access truth), ``internally`` rides the operator-declared token so
it is ``admin-assigned`` (an explicit admin policy, not a source ACL), and a
participant-widened audience is at best ``approximated`` (attendance is a
container approximation) — the weakest contributing claim wins, so a body can
never wear a stronger provenance than its weakest widening facet.

G3 — bi-temporal honesty (the slack L1 lesson, verbatim mechanics).
``document_id`` is ``zoom:{meeting_uuid}`` — the meeting UUID, NEVER the
numeric meeting id (the numeric id is REUSED across recurrences of the same
meeting; keying on it would splice different recordings into one document).
``valid_from`` is the recording END timestamp, advanced MONOTONICALLY per
document: the bookkept last-DELIVERED stamp plus a content digest decide —
unchanged content at a non-advancing stamp is SKIPPED outright (replay
idempotency without index churn); changed content whose recomputed stamp
regressed or stalled (a deleted latest recording file regresses the end ts; a
transcript edit keeps it) has its ``valid_from`` advanced past the bookkept
stamp via the detection-time signal (the cycle clock, else bookkept+1s) — the
server's supersede retires only rows strictly OLDER than the incoming stamp
and replays ride its insert-conflict DO NOTHING, so a non-advancing
re-delivery would leave deleted text serving or no-op the edit entirely.

G4 — retraction-is-enforced (the sharepoint park/drain, verbatim ordering).
Zoom's recordings list omits trashed AND deleted recordings by default, so
ABSENCE of a bookkept meeting UUID from a re-listed window IS the deletion
signal (trash included); a mirrored→quarantined transition retires the same
way. Each detected retraction is PARKED in ``zoom_parked_retractions.json``
next to the cursor state and REPLAYED as ``POST /v1/admin/retire``. Replay
ORDER is load-bearing (the over-retire race): each cycle drains the
PRE-EXISTING ledger BEFORE delivering the cycle's events, parks the cycle's
own rejects after delivery, then drains those; a successful delivery UNPARKS
any older entry for the same document_id, and an in-stream delivery
supersedes any earlier same-cycle park. Any 2xx (including the idempotent
0-chunk replay) removes the entry; any failure keeps it parked and alarmed
(``kind="parked_retraction"``) until a later cycle drains it.

HONEST REMAINDERS (stated, not hidden):

- The incremental poll re-lists only a ``lookback_days`` window (month-
  chunked — Zoom caps every list window at ONE month), so a deletion older
  than the lookback is invisible to the poll; the ``--backfill`` reconcile
  (``backfill_months`` of monthly windows) is the truth lane, and
  ``last_reconcile_at`` is stamped ONLY by a zero-failure backfill. The
  ``reconcile_overdue`` alarm fires on every heartbeat while that stamp is
  older than ``reconcile_sla_hours`` (default 24) — past-SLA the connector's
  deletion story is the quarantine posture in spirit: alarmed, never silent.
- Webhooks (``recording.trashed`` = retract signal / ``recording.deleted`` =
  terminal / ``recording.recovered`` = re-ingest; Zoom retries 3x at
  +5/+20/+60min) are a LATER push lane — :meth:`ZoomConnector.push_events`
  is a documented no-op; poll + the reconcile SLA is the truth lane either
  way.
- ``user_email`` on the participants read is populated for signed-in users
  only as OBSERVED behavior, not API contract — hence null-guarded and
  narrowing-only (G2).
- Which hosts to list is operator-declared (``ZOOM_USER_IDS``): the granted
  scope set reads users and their recordings, it does not enumerate the
  account — an undeclared host's recordings are simply never mirrored
  (under-index, never over-index).
- Rate limits: Zoom's list endpoints are sized for the Heavy-on-trial budget
  (1 req/s, 1k/day shared) because their category is unverified; the
  per-meeting GETs are confirmed LIGHT. The transport honors HTTP 429 +
  ``Retry-After`` on every call either way — obey the budget actually
  granted, never assume a tier.
- Cloud recording + transcripts need a Pro+ plan; live validation is a later
  lane (see Verification status).

Auth: Server-to-Server OAuth — ``POST https://zoom.us/oauth/token`` (the
marketing host, NOT api.zoom.us) with ``grant_type=account_credentials`` +
``account_id`` under Basic ``base64(client_id:client_secret)``; tokens live
3600s, there is NO refresh token — expiry re-mints (concurrent mints are
allowed by Zoom, so no cross-process lock is needed). The client secret
arrives ONLY via ``ZOOM_CLIENT_SECRET_FILE`` (0600-enforced, hubspot's
credential-file discipline: never argv, never env, never logged).

Meeting UUIDs in URL paths are ALWAYS double-URL-encoded (defensively — Zoom
requires it whenever the UUID starts with ``/`` or contains ``//``, and
answers error 3001 otherwise; encoding every UUID twice is safe for all).

Sink contract: ``POST /v1/ingest/documents`` bodies with
``document_id="zoom:{meeting_uuid}"``, ``content`` = a deterministic header
(topic / start / host / participants) + the chronological speaker-turn
transcript parsed python-side from the VTT (cue parsing, ``Name: text``
speaker extraction, rolling-caption dedup), ``valid_from`` = the recording
end ts under the G3 monotonic guard, ``visibility`` = the resolved int
tokens, ``acl_provenance`` per the floor above; quarantined bodies carry NO
``visibility`` and NO content.

Runner: ``python -m verity_ingest.connectors.zoom --once|--backfill
[--dry-run]`` with a JSON cursor state file (per-UUID bookkeeping +
``last_reconcile_at``) and, beside it, the ``zoom_parked_retractions``
ledger. Heartbeats post ``source="zoom"`` EVERY cycle including idle ones
(``items_synced: 0``) — the server's per-source freshness gate fences a
silent connector, so a quiet-but-healthy one must keep beating.

Verification status (honest-limitations doctrine): FIXTURE-VERIFIED — every
behavior above is asserted against fixtures authored from Zoom's documented
API response shapes (users/{id}/recordings paging + the 1-month window cap,
meetings/{uuid}/recordings, recordings/settings, past_meetings participants,
the OAuth token mint, 429/Retry-After, VTT). It has NOT run against a live
Zoom account (needs a Pro+ seat — Matt's lane); live lanes still open: the
webhook push lane, the participants ``user_email`` behavioral claim, and the
double-encoding claim against a real ``//``-bearing UUID.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import quote

import httpx

from verity_ingest import crosswalk
from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

# Sink + retire conventions reused from gdrive (the content-connector
# template): one documents endpoint, one fail-closed body ladder, the same
# /v1/admin/retire drain route. _is_indexable_body is the runner's park gate.
from verity_ingest.connectors.gdrive import (
    CONNECTOR_STATUS_PATH,
    DOCUMENTS_PATH,
    RETIRE_PATH,
    DocumentSink,
    DryRunSink,
    VerityDocumentSink,
    _is_indexable_body,
)

__all__ = [
    "SOURCE_NAME",
    "DOCUMENTS_PATH",
    "RETIRE_PATH",
    "ZOOM_API_BASE_URL",
    "ZOOM_OAUTH_TOKEN_URL",
    "PROV_MIRRORED",
    "PROV_APPROXIMATED",
    "PROV_ADMIN_ASSIGNED",
    "ZoomApiError",
    "ZoomConfig",
    "ZoomDocumentEvent",
    "ZoomOAuth",
    "ZoomTransport",
    "HttpZoomTransport",
    "ZoomConnector",
    "ZoomRegistry",
    "StaticZoomRegistry",
    "HttpZoomRegistry",
    "ZoomStatusSink",
    "DryRunSink",
    "AudienceDecision",
    "classify_share_audience",
    "floor_provenance",
    "encode_meeting_uuid",
    "recording_document_id",
    "month_windows",
    "parse_vtt",
    "render_transcript",
    "render_recording_content",
    "content_digest",
    "build_zoom_document_request",
    "load_zoom_credentials",
    "run_once",
    "run_backfill",
    "main",
]

logger = logging.getLogger(__name__)

SOURCE_NAME = "zoom"

ZOOM_API_BASE_URL = "https://api.zoom.us/v2/"
#: The token mint lives on zoom.us, NOT api.zoom.us (a doc-sourced fact the
#: transport test pins — the wrong host 404s in ways that look like auth bugs).
ZOOM_OAUTH_TOKEN_URL = "https://zoom.us/oauth/token"

#: House acl_provenance tags (verity-core AclProvenance, kebab-case), ordered
#: strongest→weakest claim. `quarantined` is the ladder's own posture, not a
#: floor input.
PROV_MIRRORED = "mirrored"
PROV_APPROXIMATED = "approximated"
PROV_ADMIN_ASSIGNED = "admin-assigned"
_PROVENANCE_RANK = {PROV_MIRRORED: 0, PROV_APPROXIMATED: 1, PROV_ADMIN_ASSIGNED: 2}

#: The share_recording enum this connector recognizes (G1). Anything else —
#: including a value Zoom adds later — is poison: quarantine, never guess.
_SHARE_PUBLICLY = "publicly"
_SHARE_INTERNALLY = "internally"
_SHARE_NONE = "none"

#: Zoom's hard cap on every recordings-list window (backfills chunk months).
_MAX_WINDOW_DAYS = 30


def recording_document_id(meeting_uuid: str) -> str:
    """``zoom:{meeting_uuid}`` — the UUID, NEVER the numeric meeting id: the
    numeric id is reused across recurrences of the same meeting, so keying on
    it would splice different recordings into one document (G3)."""
    return f"zoom:{meeting_uuid}"


def encode_meeting_uuid(meeting_uuid: str) -> str:
    """Double-URL-encode a meeting UUID for a path segment. Zoom REQUIRES the
    double encoding whenever the UUID begins with ``/`` or contains ``//``
    (else error 3001) and tolerates it for every UUID — so encode ALL of them
    twice, defensively, rather than pattern-match the failure cases."""
    return quote(quote(meeting_uuid, safe=""), safe="")


def content_digest(content: bytes) -> str:
    """Content fingerprint bookkept per delivered recording (the L1 guard's
    changed-vs-unchanged signal): sha256 over the exact bytes delivered."""
    return hashlib.sha256(content).hexdigest()


def month_windows(frm: date, to: date) -> list[tuple[str, str]]:
    """Chunk ``[frm, to]`` (inclusive) into ``(from, to)`` yyyy-MM-dd windows
    that each stay inside ONE calendar month — Zoom rejects any recordings
    list spanning more than a month, so backfills walk these windows."""
    if frm > to:
        return []
    windows: list[tuple[str, str]] = []
    cursor = frm
    while cursor <= to:
        if cursor.month == 12:
            month_end = date(cursor.year, 12, 31)
        else:
            month_end = date(cursor.year, cursor.month + 1, 1) - timedelta(days=1)
        end = min(month_end, to)
        windows.append((cursor.isoformat(), end.isoformat()))
        cursor = end + timedelta(days=1)
    return windows


def floor_provenance(*tags: str) -> str:
    """The WEAKEST contributing provenance claim wins (mirrored →
    approximated → admin-assigned): a body must never wear a stronger tag
    than its weakest audience-widening facet."""
    return max(tags, key=lambda tag: _PROVENANCE_RANK[tag])


# ---------------------------------------------------------------------------
# Config & credentials
# ---------------------------------------------------------------------------


@dataclass
class ZoomConfig:
    """Connector configuration. No default widens visibility: participants
    stay OUT of the audience unless explicitly opted in, and the internal
    token / internal domains default to unset (→ ``internally`` recordings
    quarantine until the operator declares what they mean)."""

    tenant_id: str = "default"  # Verity tenant (opaque)
    account_id: str | None = None
    client_id: str | None = None
    #: From ZOOM_CLIENT_SECRET_FILE only; repr=False so a debug print / log /
    #: traceback formatting of the config can never echo the secret.
    client_secret: str | None = field(default=None, repr=False)
    #: Hosts whose cloud recordings to mirror (user ids or emails). Operator-
    #: declared: the granted scopes read users, they do not enumerate the
    #: account (module docstring, honest remainders).
    user_ids: tuple[str, ...] = ()
    #: What ``share_recording="internally"`` maps to: a canonical principal
    #: token (e.g. ``group:everyone@acme.com``). Unset → quarantine.
    internal_maps_to: str | None = None
    #: The domain set the operator declares ``internally`` to cover. Compared
    #: against the settings' ``authentication_domains`` allowlist; any
    #: mismatch (including declared-empty vs non-empty) quarantines (G1).
    internal_domains: frozenset[str] = frozenset()
    #: Opt-in (default OFF): vouched participants join the audience. Even on,
    #: only directory-vouched emails confer anything (G2, narrowing-only).
    participants_in_audience: bool = False
    #: Alarm ``reconcile_overdue`` while no zero-failure backfill completed
    #: within this window (alarmed, not enforced — the SLA bounds deletion lag).
    reconcile_sla_hours: int = 24
    #: How far back the incremental poll re-lists (absence within this window
    #: is the poll's deletion signal; older deletions are the backfill's job).
    lookback_days: int = 7
    #: How many monthly windows the --backfill reconcile walks.
    backfill_months: int = 12
    page_size: int = 300  # Zoom's max


def _read_secret_file(path: Path) -> str:
    """Read the client secret from a 0600 credential file (hubspot's
    credential-file discipline). The secret is the file body — never argv
    (world-visible via /proc), never env, NEVER echoed or logged. Fails
    closed on group/world-readable modes and on an empty file."""
    st = path.stat()
    if st.st_mode & 0o077:
        raise PermissionError(
            f"ZOOM_CLIENT_SECRET_FILE {path} must be 0600 (owner-only); "
            f"found mode {st.st_mode & 0o777:o}"
        )
    secret = path.read_text().rstrip("\n")
    if not secret.strip():
        raise ValueError(f"ZOOM_CLIENT_SECRET_FILE {path} is empty (no client secret)")
    return secret


def load_zoom_credentials() -> tuple[str, str, str]:
    """(account_id, client_id, client_secret) from ``ZOOM_ACCOUNT_ID`` +
    ``ZOOM_CLIENT_ID`` + ``ZOOM_CLIENT_SECRET_FILE`` (0600-enforced). Any
    missing piece → a RuntimeError naming it — never a half-configured run."""
    account_id = os.environ.get("ZOOM_ACCOUNT_ID") or None
    client_id = os.environ.get("ZOOM_CLIENT_ID") or None
    secret_file = os.environ.get("ZOOM_CLIENT_SECRET_FILE") or None
    missing = [
        name
        for name, value in (
            ("ZOOM_ACCOUNT_ID", account_id),
            ("ZOOM_CLIENT_ID", client_id),
            ("ZOOM_CLIENT_SECRET_FILE", secret_file),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"zoom credentials incomplete: set {', '.join(missing)} "
            "(Server-to-Server OAuth app; the secret rides a 0600 file, never env/argv)"
        )
    assert account_id and client_id and secret_file
    return account_id, client_id, _read_secret_file(Path(secret_file))


# ---------------------------------------------------------------------------
# OAuth + transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class ZoomApiError(RuntimeError):
    """A Zoom API error envelope. ``code`` is Zoom's machine code (e.g. 3001
    meeting-not-found), ``status`` the HTTP status."""

    def __init__(self, path: str, status: int, code: int | None, message: str) -> None:
        super().__init__(f"zoom api {path}: http {status} code={code} {message}")
        self.path = path
        self.status = status
        self.code = code
        self.error_message = message


class ZoomTransport(Protocol):
    """Minimal surface over the Zoom REST API, so tests run on fixtures."""

    def get(self, path: str, params: Mapping[str, Any]) -> dict: ...

    def download(self, url: str) -> bytes: ...


class ZoomOAuth:
    """Server-to-Server OAuth token mint: ``POST https://zoom.us/oauth/token``
    (NOT api.zoom.us) with ``grant_type=account_credentials`` + ``account_id``
    under Basic ``base64(client_id:client_secret)``. Tokens live 3600s with NO
    refresh token — expiry re-mints (Zoom allows concurrent mints, so no lock).
    The secret is never logged and never rides an error string; the derived
    Basic credential IS retained (privately, for the hourly re-mints) but has
    no repr/log surface — honest statement, not a stronger claim."""

    def __init__(
        self,
        account_id: str,
        client_id: str,
        client_secret: str,
        client: httpx.Client | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._account_id = account_id
        self._basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        self._client = client or httpx.Client(timeout=30.0)
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    def token(self) -> str:
        """The current access token, re-minted with 60s of slack before
        expiry (a request in flight at the boundary must not carry a token
        that dies mid-call)."""
        if self._token is None or self._clock() >= self._expires_at - 60.0:
            response = self._client.post(
                ZOOM_OAUTH_TOKEN_URL,
                data={"grant_type": "account_credentials", "account_id": self._account_id},
                headers={"Authorization": f"Basic {self._basic}"},
            )
            response.raise_for_status()
            payload = response.json()
            self._token = str(payload["access_token"])
            self._expires_at = self._clock() + float(payload.get("expires_in") or 3600)
        return self._token


class HttpZoomTransport:
    """Live REST transport: bearer auth from :class:`ZoomOAuth`, HTTP 429 +
    ``Retry-After`` honored with bounded retries on EVERY call (the honest
    rate-limit posture: obey whatever budget the account actually grants —
    the list endpoints are budgeted for Heavy-on-trial, 1/s + 1k/day shared),
    and Zoom's JSON error envelope surfaced as :class:`ZoomApiError`."""

    def __init__(
        self,
        oauth: ZoomOAuth,
        client: httpx.Client | None = None,
        *,
        max_retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._oauth = oauth
        self._client = client or httpx.Client(base_url=ZOOM_API_BASE_URL, timeout=60.0)
        self._max_retries = max_retries
        self._sleep = sleep

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        attempt = 0
        while True:
            headers = {"Authorization": f"Bearer {self._oauth.token()}"}
            response = self._client.request(method, url, headers=headers, **kwargs)
            if response.status_code == 429 and attempt < self._max_retries:
                self._sleep(float(response.headers.get("Retry-After", "1")))
                attempt += 1
                continue
            return response

    def get(self, path: str, params: Mapping[str, Any]) -> dict:
        response = self._request("GET", path, params=dict(params))
        if response.status_code >= 400:
            code: int | None = None
            message = ""
            try:
                payload = response.json()
                code = payload.get("code")
                message = str(payload.get("message") or "")
            except ValueError:
                pass
            raise ZoomApiError(path, response.status_code, code, message)
        return response.json()

    def download(self, url: str) -> bytes:
        """Fetch a recording file (the VTT) via its ``download_url`` with the
        SAME OAuth bearer — download URLs are absolute, off the API base."""
        response = self._request("GET", url)
        response.raise_for_status()
        return response.content


# ---------------------------------------------------------------------------
# Principal resolution (host/participant emails + the internal token)
# ---------------------------------------------------------------------------


class ZoomRegistry(Protocol):
    """Resolves canonical principals / vouched emails to int visibility
    tokens via ``/v1/admin/principals`` (or a fixture stand-in)."""

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult: ...


class StaticZoomRegistry:
    """Fixed mapping, from config or fixtures. ``emails`` resolve iff their
    ``user:<email>`` canonical is in the map — the fixture stand-in for the
    live server's existence check (an email with no pre-existing canonical
    confers nothing: the directory-vouched gate, G2). Missing principals stay
    unresolved (the ladder then quarantines — fail closed)."""

    def __init__(self, mapping: Mapping[str, int]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult:
        mappings = {
            principal: token
            for principal in request.principals
            if isinstance(token := self._mapping.get(principal), int)
        }
        for email in request.emails:
            canonical = f"user:{email}"
            token = self._mapping.get(canonical)
            if isinstance(token, int):
                mappings[canonical] = token
        return crosswalk.ResolveResult(mappings=mappings, quarantined=False)


class HttpZoomRegistry:
    """Resolves via ``POST /v1/admin/principals`` (crosswalk.resolve_via):
    the internal token rides ``principals``, host/participant emails ride
    ``emails`` — the server answers only for canonicals a real directory
    sync vouched, and never creates one."""

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
# The ACL table (G1): share_recording → audience decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AudienceDecision:
    """One recording's settings verdict. Quarantine reasons are stable
    machine-ish strings (they ride the parked-retraction ledger + logs)."""

    quarantined: bool
    reason: str = ""
    internal_token: str | None = None  # rides `principals` when set
    provenance: str = ""


def _auth_domains(settings: Mapping[str, Any]) -> frozenset[str]:
    """The settings' ``authentication_domains`` allowlist as a lowered set.
    Zoom returns it as a comma-separated string (a list is tolerated)."""
    raw = settings.get("authentication_domains")
    if raw is None:
        return frozenset()
    parts: Iterator[str]
    if isinstance(raw, str):
        parts = iter(raw.split(","))
    elif isinstance(raw, (list, tuple)):
        parts = iter(str(p) for p in raw)
    else:
        # An allowlist shape this code does not recognize: treat as a
        # mismatch-in-waiting by returning an unmatchable sentinel set.
        return frozenset({"\x00unrecognized"})
    return frozenset(p.strip().lower() for p in parts if p and p.strip())


def classify_share_audience(
    settings: Mapping[str, Any] | None, config: ZoomConfig
) -> AudienceDecision:
    """The whole G1 table in one place (module docstring). The host anchor is
    NOT decided here — it is resolved (and vouch-gated) by the connector; this
    function decides only what the SETTINGS confer beyond the host."""
    if not isinstance(settings, Mapping):
        return AudienceDecision(quarantined=True, reason="settings-unreadable")
    share = settings.get("share_recording")
    if share == _SHARE_PUBLICLY:
        # A passcode does NOT rescue a public share: it gates the link, not
        # an audience this connector can name.
        return AudienceDecision(quarantined=True, reason="publicly-shared")
    if share == _SHARE_NONE:
        return AudienceDecision(quarantined=False, provenance=PROV_MIRRORED)
    if share == _SHARE_INTERNALLY:
        if not config.internal_maps_to:
            return AudienceDecision(quarantined=True, reason="internal-token-unset")
        domains = _auth_domains(settings)
        if domains and domains != config.internal_domains:
            return AudienceDecision(quarantined=True, reason="authentication-domain-mismatch")
        return AudienceDecision(
            quarantined=False,
            internal_token=config.internal_maps_to,
            provenance=PROV_ADMIN_ASSIGNED,
        )
    # An enum value this code does not recognize (or a missing one): poison.
    return AudienceDecision(quarantined=True, reason="unknown-share-setting")


# ---------------------------------------------------------------------------
# VTT parsing → speaker-turn transcript
# ---------------------------------------------------------------------------


def _vtt_start(timing_line: str) -> str:
    """``00:01:02.345 --> 00:01:05.000`` → ``00:01:02`` (second resolution;
    Zoom sometimes emits ``mm:ss.mmm`` — normalized to ``hh:mm:ss``)."""
    raw = timing_line.split("-->")[0].strip().split(".")[0].split(",")[0]
    parts = raw.split(":")
    while len(parts) < 3:
        parts.insert(0, "00")
    return ":".join(p.zfill(2) for p in parts[-3:])


def parse_vtt(vtt_text: str) -> list[tuple[str, str, str]]:
    """WebVTT → ``[(start, speaker, text)]`` cues, chronological, with
    rolling-caption dedup (Zoom live-transcript VTTs repeat a growing caption
    across consecutive cues: an identical same-speaker cue is dropped, a
    same-speaker extension REPLACES its predecessor). Speaker comes from the
    ``Name: text`` convention; a cue without one keeps speaker ``""``.
    ``WEBVTT``/``NOTE``/``STYLE`` blocks and bare cue-id lines are skipped."""
    cues: list[tuple[str, str, str]] = []
    for block in vtt_text.replace("\r\n", "\n").replace("\r", "\n").split("\n\n"):
        lines = [line for line in block.split("\n") if line.strip()]
        if not lines:
            continue
        head = lines[0].strip()
        if head.startswith(("WEBVTT", "NOTE", "STYLE")):
            continue
        timing_index = next((i for i, line in enumerate(lines) if "-->" in line), None)
        if timing_index is None:
            continue  # not a cue (an id-only stray, metadata, etc.)
        start = _vtt_start(lines[timing_index])
        text = " ".join(line.strip() for line in lines[timing_index + 1 :]).strip()
        if not text:
            continue
        speaker = ""
        if ": " in text:
            candidate, rest = text.split(": ", 1)
            # A speaker label is a short name, not a sentence with a colon.
            # (text is already newline-free: the cue lines were space-joined.)
            if candidate and len(candidate) <= 64:
                speaker, text = candidate.strip(), rest.strip()
        if cues:
            _, prev_speaker, prev_text = cues[-1]
            if prev_speaker == speaker:
                if text == prev_text:
                    continue  # exact repeat: dropped
                if text.startswith(prev_text):
                    cues[-1] = (cues[-1][0], speaker, text)  # rolling caption grew
                    continue
        cues.append((start, speaker, text))
    return cues


def render_transcript(cues: Sequence[tuple[str, str, str]]) -> str:
    """Chronological speaker-TURN transcript: consecutive same-speaker cues
    merge into one ``[hh:mm:ss] Name: text…`` turn (the turn keeps its first
    cue's timestamp). Speaker names are rendering sugar ONLY — never identity
    keys or visibility inputs (G2)."""
    turns: list[tuple[str, str, list[str]]] = []
    for start, speaker, text in cues:
        if turns and turns[-1][1] == speaker:
            turns[-1][2].append(text)
            continue
        turns.append((start, speaker, [text]))
    return "\n".join(
        f"[{start}] {speaker or 'unknown'}: {' '.join(texts)}" for start, speaker, texts in turns
    )


def render_recording_content(
    topic: str,
    start_time: str,
    host_display: str,
    participants: Sequence[str],
    vtt_text: str,
) -> str:
    """The delivered document: a deterministic header (topic / start / host /
    participant NAMES — rendering context only) + the speaker-turn
    transcript. Deterministic bytes → deterministic digest (the L1 guard)."""
    header = [
        f"Zoom recording: {topic}",
        f"Start: {start_time}",
        f"Host: {host_display}",
    ]
    if participants:
        header.append("Participants: " + ", ".join(participants))
    return "\n".join(header) + "\n\n" + render_transcript(parse_vtt(vtt_text))


# ---------------------------------------------------------------------------
# Events & the document-body ladder
# ---------------------------------------------------------------------------


@dataclass
class ZoomDocumentEvent(DocumentEvent):
    """DocumentEvent + the recording coordinates, the delivered stamp, the
    resolved tokens (resolution happens IN the connector, before any content
    fetch — the vouch gate is part of ACL-before-content), and the removal
    marker."""

    modified_time: str = ""
    meeting_uuid: str = ""
    removed: bool = False
    quarantine_reason: str = ""
    visibility_tokens: list[int] = field(default_factory=list)
    provenance: str = ""


def build_zoom_document_request(event: ZoomDocumentEvent, tenant_id: str) -> dict:
    """Build the ``/v1/ingest/documents`` body for one recording event.

    Fail-closed ladder (mirrors sharepoint/slack's):
    - removal marker → ``{"removed": true}`` body (parked → retire drain);
    - quarantined envelope → quarantine body with NO ``visibility`` and NO
      content (content was never fetched to begin with — G1);
    - resolvable but zero tokens survived → quarantine (never index open);
    - otherwise → mirrored-posture body with sorted int visibility tokens and
      the honestly-floored ``acl_provenance``."""
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
        "content": (
            event.content.decode("utf-8", errors="replace") if event.acl.resolvable else None
        ),
    }
    if not event.acl.resolvable or not event.visibility_tokens:
        body["acl_provenance"] = "quarantined"
        body["content"] = None
        return body
    body["visibility"] = sorted(set(event.visibility_tokens))
    body["acl_provenance"] = event.provenance
    return body


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


def _book_entry(raw: Any) -> dict[str, Any]:
    """Normalize one bookkept meeting entry: ``{"date": yyyy-MM-dd,
    "status": mirrored|quarantined, "delivered": iso|"", "digest": hex|None}``.
    A malformed entry reads as changed-content on next sight (over-delivers
    once, safe) and self-heals."""
    if isinstance(raw, Mapping):
        digest = raw.get("digest")
        return {
            "date": str(raw.get("date") or ""),
            "status": str(raw.get("status") or "mirrored"),
            "delivered": str(raw.get("delivered") or ""),
            "digest": str(digest) if digest else None,
        }
    return {"date": "", "status": "mirrored", "delivered": "", "digest": None}


def _advance_stamp(delivered: str, *candidates: str) -> str:
    """The smallest honest ``valid_from`` strictly AFTER the last delivered
    stamp: the first candidate that beats it (both are this module's fixed
    ``%Y-%m-%dT%H:%M:%SZ`` shape, so lexical order IS chronological), else
    ``delivered`` + 1s (deterministic last resort). Never returns a stamp <=
    ``delivered`` when ``delivered`` is a real stamp: the server supersede is
    strictly monotonic — a non-advancing stamp silently fails to retire the
    previous version. (A CORRUPT bookkept ``delivered`` falls back to the
    last candidate — the detection-time clock — since there is no real stamp
    to advance past; the server then compares real stamps either way.)"""
    for candidate in candidates:
        if candidate and candidate > delivered:
            return candidate
    try:
        then = datetime.fromisoformat(delivered.replace("Z", "+00:00"))
    except ValueError:
        return candidates[-1] if candidates else delivered
    return _iso(then + timedelta(seconds=1))


def _norm_iso(raw: Any) -> str:
    """A Zoom timestamp ("2026-07-14T10:30:00Z") normalized to the module's
    fixed second-resolution shape; unparseable → ""."""
    try:
        moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return _iso(moment)


class ZoomConnector(Connector):
    name = SOURCE_NAME

    def __init__(
        self,
        transport: ZoomTransport,
        config: ZoomConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport
        self.config = config or ZoomConfig()
        self._clock = clock or _utcnow
        # The vouch gate's registry (set by run_once/run_backfill before any
        # crawl). None (a bare connector driven outside the runners) fails
        # CLOSED: no canonical can be verified, so every deliverable
        # recording quarantines.
        self.registry: ZoomRegistry | None = None
        # Per-cycle host-email cache (GET /users/{host_id} is LIGHT but not free).
        self._host_emails: dict[str, str | None] = {}
        # Counted skips/failures, reported every cycle — never silent.
        self.transcriptless: list[str] = []
        self.list_failures: list[str] = []
        # Backfill lifecycle (run_backfill drives full_crawl).
        self.prior_book: dict[str, dict] = {}
        self.backfill_book: dict[str, dict] = {}
        self.backfill_completed_at: str | None = None
        # Bookkept uuids NO crawled window could re-list (empty/malformed
        # bookkept date, or older than the whole backfill horizon): their
        # deletion story is unverifiable, so they DISQUALIFY the reconcile
        # stamp (alarmed via backfill_incomplete, never silently ridden).
        self.reconcile_unswept: list[str] = []

    # -- push lane ----------------------------------------------------------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op: the webhook push lane (``recording.trashed`` = retract
        signal, ``recording.deleted`` = terminal, ``recording.recovered`` =
        re-ingest; Zoom retries failed deliveries 3x at +5/+20/+60min) is a
        LATER latency optimization — the poll's absence-diff + the reconcile
        SLA is the truth lane either way."""
        return
        yield  # pragma: no cover - makes this an async generator

    # -- Zoom reads ----------------------------------------------------------

    def _list_recordings(self, frm: str, to: str) -> list[dict] | None:
        """Every declared host's cloud recordings in one <=1-month window
        (``next_page_token`` paging, page_size<=300). Returns None when ANY
        host's list failed — an absence-diff over a partial list would retract
        recordings that are merely unlisted (fail closed: no diff, counted)."""
        meetings: list[dict] = []
        for user in self.config.user_ids:
            token = ""
            while True:
                params: dict[str, Any] = {
                    "from": frm,
                    "to": to,
                    "page_size": str(min(self.config.page_size, 300)),
                }
                if token:
                    params["next_page_token"] = token
                try:
                    page = self._transport.get(
                        f"users/{quote(str(user), safe='')}/recordings", params
                    )
                except ZoomApiError:
                    if user not in self.list_failures:
                        self.list_failures.append(str(user))
                    return None
                meetings.extend(m for m in page.get("meetings") or [] if isinstance(m, Mapping))
                token = str(page.get("next_page_token") or "").strip()
                if not token:
                    break
        return meetings

    def _recording_settings(self, encoded_uuid: str) -> Mapping[str, Any] | None:
        try:
            settings = self._transport.get(f"meetings/{encoded_uuid}/recordings/settings", {})
        except ZoomApiError:
            return None  # unreadable settings → the classify table poisons
        return settings if isinstance(settings, Mapping) else None

    def _host_email(self, host_id: str) -> str | None:
        """The host's email via ``GET /users/{host_id}`` (scope
        user:read:user:admin), cached per cycle. Unreadable → None (the
        caller quarantines: a host-anchored audience needs a provable host)."""
        if host_id in self._host_emails:
            return self._host_emails[host_id]
        email: str | None = None
        try:
            user = self._transport.get(f"users/{quote(host_id, safe='')}", {})
        except ZoomApiError:
            user = None
        if isinstance(user, Mapping):
            email = str(user.get("email") or "").strip().lower() or None
        self._host_emails[host_id] = email
        return email

    def _participants(self, encoded_uuid: str) -> list[dict]:
        """``GET /past_meetings/{uuid}/participants`` (paged). Fetched ONLY
        for deliverable recordings (G1 call-log contract). A failed read
        returns [] — participants are context + an opt-in NARROWING facet,
        so their absence never poisons (the host anchor carries the grant)."""
        participants: list[dict] = []
        token = ""
        while True:
            params: dict[str, Any] = {"page_size": str(min(self.config.page_size, 300))}
            if token:
                params["next_page_token"] = token
            try:
                page = self._transport.get(f"past_meetings/{encoded_uuid}/participants", params)
            except ZoomApiError:
                return []
            participants.extend(
                p for p in page.get("participants") or [] if isinstance(p, Mapping)
            )
            token = str(page.get("next_page_token") or "").strip()
            if not token:
                break
        return participants

    # -- event assembly ------------------------------------------------------

    def _removed_event(self, meeting_uuid: str) -> ZoomDocumentEvent:
        return ZoomDocumentEvent(
            source=self.name,
            document_id=recording_document_id(meeting_uuid),
            content=b"",
            mime_type="",
            version="",
            acl=AclEnvelope(resolvable=True),  # nothing indexed; grants nothing
            modified_time=_iso(self._clock()),
            meeting_uuid=meeting_uuid,
            removed=True,
        )

    def _quarantine_event(self, meeting_uuid: str, reason: str) -> ZoomDocumentEvent:
        """Quarantine posture (G1). NO content rides it — the body ladder
        yields a visibility-less quarantine body, which the runner PARKS and
        drains as a retire replay (anything previously indexed stops
        serving)."""
        return ZoomDocumentEvent(
            source=self.name,
            document_id=recording_document_id(meeting_uuid),
            content=b"",
            mime_type="text/plain",
            version="",
            acl=AclEnvelope(resolvable=False),
            modified_time=_iso(self._clock()),
            meeting_uuid=meeting_uuid,
            quarantine_reason=reason,
        )

    def _resolve_audience(
        self, decision: AudienceDecision, host_email: str
    ) -> tuple[set[int], str] | str:
        """(tokens, provenance) for the host anchor plus any internal token,
        or a quarantine reason string — resolved BEFORE the participants read:
        the vouch gate is part of ACL-before-content, so a recording it
        quarantines must trigger NO participants fetch (attendee names and
        emails are content too). Fail-closed facets: the HOST must resolve to
        a pre-existing vouched canonical and a declared internal token must
        resolve — either miss quarantines."""
        if self.registry is None:
            return "no-registry"  # bare connector: no vouch possible, fail closed
        principals = [decision.internal_token] if decision.internal_token else []
        result = self.registry.resolve(
            crosswalk.ResolveRequest(principals=list(principals), emails=[host_email])
        )
        host_token = result.mappings.get(f"user:{host_email}")
        if not isinstance(host_token, int):
            return "host-unvouched"
        tokens = {host_token}
        if decision.internal_token:
            internal_token = result.mappings.get(decision.internal_token)
            if not isinstance(internal_token, int):
                return "internal-token-unresolved"
            tokens.add(internal_token)
        return tokens, decision.provenance

    def _widen_with_participants(
        self, tokens: set[int], provenance: str, participant_emails: Sequence[str]
    ) -> tuple[set[int], str]:
        """The opt-in participant widening (G2, narrowing-only): a SECOND
        resolve, run only once the recording is already deliverable — vouched
        participants join the audience, everyone else (guests, unvouched)
        confers nothing. Any widening floors the provenance at
        ``approximated`` (attendance is a container approximation)."""
        if not participant_emails or self.registry is None:
            return tokens, provenance
        result = self.registry.resolve(
            crosswalk.ResolveRequest(principals=[], emails=sorted(participant_emails))
        )
        for email in participant_emails:
            token = result.mappings.get(f"user:{email}")
            if isinstance(token, int) and token not in tokens:
                tokens.add(token)
                provenance = floor_provenance(provenance, PROV_APPROXIMATED)
        return tokens, provenance

    def _meeting_event(
        self, meeting: Mapping[str, Any], entry: Mapping[str, Any] | None
    ) -> ZoomDocumentEvent | None:
        """One listed recording → its document event: a mirrored-posture
        delivery, a quarantine, a removal (transcript vanished from a
        previously-delivered recording), or None (nothing indexable and
        nothing previously indexed — counted, never silent).

        Order is the G1 contract: settings → host vouch (→ participants only
        under the opt-in and only once deliverable) → and ONLY THEN the
        recording-files read + VTT download."""
        meeting_uuid = str(meeting.get("uuid") or "")
        encoded = encode_meeting_uuid(meeting_uuid)
        # 1. ACL first: the settings verdict.
        decision = classify_share_audience(self._recording_settings(encoded), self.config)
        if decision.quarantined:
            return self._quarantine_event(meeting_uuid, decision.reason)
        # 2. The host anchor (vouched-or-quarantine).
        host_email = self._host_email(str(meeting.get("host_id") or ""))
        if not host_email:
            return self._quarantine_event(meeting_uuid, "host-email-unreadable")
        # 3. The vouch gate — BEFORE the participants read: a vouch-gate
        #    quarantine (host-unvouched / internal-token-unresolved /
        #    no-registry) must fetch NO attendee names or emails
        #    (ACL-before-content covers the participants read too).
        resolved = self._resolve_audience(decision, host_email)
        if isinstance(resolved, str):
            return self._quarantine_event(meeting_uuid, resolved)
        tokens, provenance = resolved
        # 4. Participants: fetched only now (deliverable) — names for context
        #    always; audience only under the opt-in, and only the vouched (G2).
        participants = self._participants(encoded)
        participant_names = [
            str(p.get("name") or "").strip() for p in participants if str(p.get("name") or "")
        ]
        participant_emails = (
            sorted(
                {
                    email
                    for p in participants
                    if (email := str(p.get("user_email") or "").strip().lower())
                    and email != host_email
                }
            )
            if self.config.participants_in_audience
            else []
        )
        tokens, provenance = self._widen_with_participants(tokens, provenance, participant_emails)
        # 5. Content, last: the per-meeting recording files + the VTT.
        try:
            detail = self._transport.get(f"meetings/{encoded}/recordings", {})
        except ZoomApiError:
            return self._quarantine_event(meeting_uuid, "recording-files-unreadable")
        files = [f for f in detail.get("recording_files") or [] if isinstance(f, Mapping)]
        transcript = next((f for f in files if f.get("file_type") == "TRANSCRIPT"), None)
        if transcript is None or not transcript.get("download_url"):
            if entry and entry.get("status") == "mirrored" and entry.get("delivered"):
                # The transcript this document indexed is GONE: retract.
                return self._removed_event(meeting_uuid)
            self.transcriptless.append(meeting_uuid)
            return None
        vtt = self._transport.download(str(transcript["download_url"]))
        ends = [_norm_iso(f.get("recording_end")) for f in files]
        valid_from = max((e for e in ends if e), default=_norm_iso(meeting.get("start_time")))
        content = render_recording_content(
            topic=str(meeting.get("topic") or detail.get("topic") or ""),
            start_time=_norm_iso(meeting.get("start_time") or detail.get("start_time")),
            host_display=host_email,
            participants=participant_names,
            vtt_text=vtt.decode("utf-8", errors="replace"),
        )
        return ZoomDocumentEvent(
            source=self.name,
            document_id=recording_document_id(meeting_uuid),
            content=content.encode("utf-8"),
            mime_type="text/plain",
            version=valid_from,
            acl=AclEnvelope(resolvable=True),
            modified_time=valid_from,
            meeting_uuid=meeting_uuid,
            visibility_tokens=sorted(tokens),
            provenance=provenance,
        )

    def _stamp_monotonic(
        self, event: ZoomDocumentEvent, entry: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        """The L1 non-monotonic-supersede guard (the slack lesson, verbatim
        mechanics). The natural stamp (the recording end ts) is NON-monotonic:
        deleting the latest recording file REGRESSES it and a transcript edit
        keeps it — either way the server's strictly-monotonic supersede (+
        insert-conflict DO NOTHING) would leave stale text serving or no-op
        the change. So: unchanged content at a non-advancing stamp → None
        (skip delivery outright); changed content at a non-advancing stamp →
        ``valid_from`` advances past the bookkept delivered stamp via the
        detection-time signal (cycle clock, else bookkept+1s). Returns the
        new bookkeeping ``{"delivered", "digest"}`` (mutating
        ``event.modified_time`` when it had to advance), or None."""
        digest = content_digest(event.content)
        if entry:
            delivered = str(entry.get("delivered") or "")
            if delivered and event.modified_time <= delivered:
                if entry.get("digest") == digest:
                    return None
                event.modified_time = _advance_stamp(delivered, _iso(self._clock()))
        return {"delivered": event.modified_time, "digest": digest}

    # -- crawling ------------------------------------------------------------

    def crawl_windows(
        self, windows: Sequence[tuple[str, str]], book: dict[str, dict]
    ) -> Iterator[ZoomDocumentEvent]:
        """Walk month-bounded windows: (re-)ingest every listed recording and
        absence-diff each window against the bookkeeping (G4: absence of a
        bookkept uuid from a fully-re-listed window IS the retraction — the
        default list omits trashed AND deleted). ``book`` is mutated to the
        post-crawl truth; a failed window diffs NOTHING (a partial list must
        never read as mass deletion — fail closed, counted, alarmed via the
        backfill-incomplete/SLA path)."""
        self._host_emails = {}
        for frm, to in windows:
            listed = self._list_recordings(frm, to)
            if listed is None:
                continue  # counted in list_failures; no diff over a partial list
            seen: set[str] = set()
            for meeting in listed:
                meeting_uuid = str(meeting.get("uuid") or "")
                if not meeting_uuid:
                    continue
                seen.add(meeting_uuid)
                day = str(meeting.get("start_time") or "")[:10]
                entry = book.get(meeting_uuid)
                event = self._meeting_event(meeting, entry)
                if event is None:
                    book.pop(meeting_uuid, None)  # nothing indexed, nothing bookkept
                    continue
                if event.removed:
                    book.pop(meeting_uuid, None)
                    yield event
                    continue
                if not event.acl.resolvable:
                    # Quarantined (fresh or a mirrored→quarantined transition):
                    # the runner parks + drains it; bookkeeping records the
                    # posture so the ledger, not the cursor, carries the signal.
                    book[meeting_uuid] = {"date": day, "status": "quarantined"}
                    yield event
                    continue
                stamped = self._stamp_monotonic(event, entry)
                if stamped is None:
                    carried = _book_entry(entry)
                    carried["date"] = day
                    book[meeting_uuid] = carried  # unchanged: carried, not re-sent
                    continue
                book[meeting_uuid] = {"date": day, "status": "mirrored", **stamped}
                yield event
            for meeting_uuid in sorted(
                uuid
                for uuid, entry in book.items()
                if frm <= str(entry.get("date") or "") <= to and uuid not in seen
            ):
                book.pop(meeting_uuid)
                yield self._removed_event(meeting_uuid)

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """Incremental poll: re-list the ``lookback_days`` window (month-
        chunked) and diff. New/changed recordings deliver; absence within the
        window parks a retraction. Deletions OLDER than the lookback are the
        ``--backfill`` reconcile's job (module docstring, honest remainders)."""
        self.transcriptless = []
        self.list_failures = []
        state = _parse_cursor(cursor)
        book = {
            str(uuid): _book_entry(entry)
            for uuid, entry in (state.get("meetings") or {}).items()
        }
        today = self._clock().date()
        windows = month_windows(today - timedelta(days=self.config.lookback_days), today)
        events: list[FactEvent | DocumentEvent] = list(self.crawl_windows(windows, book))
        next_state = {
            "meetings": book,
            "last_reconcile_at": state.get("last_reconcile_at"),
        }
        return events, json.dumps(next_state, sort_keys=True)

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """§5a backfill/reconcile: walk ``backfill_months`` of monthly
        windows, (re-)ingest every live recording, and absence-diff the WHOLE
        bookkept set in range — the deletions the poll's lookback cannot see.
        ``backfill_completed_at`` lands only after the whole crawl finished;
        the runner stamps the reconcile SLA from it only on a ZERO-FAILURE
        run (ingest failures, list failures, and UNSWEPT bookkept entries —
        a date outside every crawled window, including empty/malformed —
        all disqualify: a crawl that could not re-list an entry re-proved
        nothing about its deletion)."""
        self.transcriptless = []
        self.list_failures = []
        self.backfill_completed_at = None
        self.reconcile_unswept = []
        self.backfill_book = {
            str(uuid): _book_entry(entry) for uuid, entry in self.prior_book.items()
        }
        today = self._clock().date()
        start = today - timedelta(days=self.config.backfill_months * _MAX_WINDOW_DAYS)
        windows = month_windows(start, today)
        for event in self.crawl_windows(windows, self.backfill_book):
            yield event
        # Entries NO crawled window covered can never be absence-diffed: an
        # empty/malformed bookkept date, or one beyond the backfill horizon.
        # They must not ride silently under a stamped reconcile (the stamp
        # would falsely assert their deletion story was re-proven).
        first_frm, last_to = windows[0][0], windows[-1][1]
        self.reconcile_unswept = sorted(
            uuid
            for uuid, entry in self.backfill_book.items()
            if not (first_frm <= str(entry.get("date") or "") <= last_to)
        )
        self.backfill_completed_at = _iso(self._clock())


# ---------------------------------------------------------------------------
# Status sink: documents + retire + alarms[] heartbeat (sharepoint's pattern)
# ---------------------------------------------------------------------------


class ZoomStatusSink(VerityDocumentSink):
    """gdrive's :class:`VerityDocumentSink` + the fail-closed ``alarms[]``
    heartbeat + the ``POST /v1/admin/retire`` transport (sharepoint's
    pattern, verbatim): the runner queues alarms via :meth:`record_alarm`
    (``parked_retraction`` / ``reconcile_overdue`` / ``backfill_incomplete``)
    and they ride the best-effort ``POST /v1/admin/connector-status`` body.
    An alarm-bearing heartbeat fires even when ZERO documents were delivered,
    and IDLE cycles beat too (``items_synced: 0``) — the server's per-source
    freshness gate fences a silent connector. Never raises; drains
    accumulators in ``finally``."""

    default_source = SOURCE_NAME

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._alarms: list[dict[str, str]] = []

    def record_alarm(self, kind: str, detail: str) -> None:
        """Queue one fail-closed alarm for the next heartbeat. ``kind`` is a
        stable machine tag; ``detail`` is a human string (never a secret)."""
        self._alarms.append({"kind": kind, "detail": detail})

    def retire(self, request: Mapping[str, Any]) -> None:
        """Replay one parked retraction as ``POST /v1/admin/retire`` (G4).
        Raises on non-2xx — the drain keeps the entry parked and re-alarms; a
        replay of an already-retired document is a 2xx with
        ``chunks_retired: 0``."""
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
            # Not silently: without a tenant to key the row the queued alarms
            # cannot post (main always sets alarm_tenant_id — this is the
            # bare-sink miswiring path; surface it, matching the base class).
            logger.warning(
                "zoom connector-status heartbeat DROPPED %d alarm(s): no tenant to "
                "key the row — set alarm_tenant_id on the sink",
                len(alarms),
            )
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
# Parked-retractions ledger + the /v1/admin/retire drain (sharepoint, verbatim
# ordering; zoom entries carry {meeting_uuid, document_id, reason})
# ---------------------------------------------------------------------------


def _ledger_path(state_file: Path) -> Path:
    """The parked-retractions ledger lives NEXT TO the cursor state so the two
    travel together (same .verity/ dir, same backup/rotation story)."""
    return state_file.with_name("zoom_parked_retractions.json")


def _parked_entry(event: ZoomDocumentEvent, body: Mapping[str, Any]) -> dict[str, str]:
    return {
        "meeting_uuid": event.meeting_uuid,
        "document_id": event.document_id,
        "reason": "removed" if body.get("removed") else "quarantined",
    }


def _park_retractions(
    state_file: Path, entries: Sequence[Mapping[str, str]], now_iso: str
) -> tuple[int, Path]:
    """Persist detected retractions pending their ``/v1/admin/retire`` replay
    (G4) — the drain runs right after parking, so an entry normally lives
    here only for the instant between detection and its 2xx replay; it
    PERSISTS across cycles only while the replay keeps failing. Dedup'd by
    ``document_id`` (a permanently-quarantined recording that resurfaces
    every cycle updates ``last_seen``/``reason``, it does not grow the file).
    Returns ``(total_outstanding, ledger_path)``. An unparseable ledger is
    moved aside to ``*.corrupt``, never silently overwritten."""
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


def _unpark_delivered(state_file: Path, document_ids: set[str]) -> int:
    """Remove parked entries for documents successfully DELIVERED this cycle —
    the second half of the over-retire-race guard: a 2xx delivery is strictly
    NEWER evidence than any still-parked retraction for the same document.
    Left in place, a later drain would replay the STALE entry and blank the
    chunks the delivery just wrote. Returns the number removed."""
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
    """Replay EVERY ledger entry as ``POST /v1/admin/retire`` ``{tenant_id,
    source, document_id, reason}`` (G4 enforcement). Any 2xx removes the
    entry; ANY failure keeps it parked for the next cycle (the ledger is the
    ONLY carrier once the window has been re-listed). Sinks without a
    ``retire`` transport (dry-run, capture-only fixtures) drain nothing:
    everything stays parked + alarmed, never silently dropped. Returns
    ``(outstanding, drained)``."""
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
        except Exception:  # noqa: BLE001 — fail closed, retried next cycle
            remaining.append(entry)
    if len(remaining) != len(ledger):
        path.write_text(json.dumps(remaining, indent=2, sort_keys=True) + "\n")
    return len(remaining), len(ledger) - len(remaining)


def _alarm_parked(sink: DocumentSink, total: int, ledger_path: Path) -> None:
    """Alarm the outstanding (post-drain) parked-retraction count on sinks
    that support the alarms[] heartbeat (best-effort on others — the ledger
    is the durable signal either way). An empty ledger alarms nothing."""
    record_alarm = getattr(sink, "record_alarm", None)
    if total and callable(record_alarm):
        record_alarm(
            "parked_retraction",
            f"{total} detected retraction(s) parked — the {RETIRE_PATH} replay "
            f"failed or is unavailable on this sink, so the content is NOT yet "
            f"removed from the index; retried next cycle; ledger: {ledger_path}",
        )


def _reconcile_overdue(last_reconcile_at: Any, now: datetime, sla_hours: int) -> bool:
    """True when no zero-failure backfill completed within the SLA (including
    never / unparseable — fail closed)."""
    if not last_reconcile_at or not isinstance(last_reconcile_at, str):
        return True
    try:
        then = datetime.fromisoformat(last_reconcile_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (now - then) > timedelta(hours=sla_hours)


def _alarm_reconcile_overdue(
    sink: DocumentSink, connector: ZoomConnector, last_reconcile_at: Any
) -> None:
    """Queue the ``reconcile_overdue`` alarm when the SLA is unmet — EVERY
    cycle, so a stalled reconcile can never fade from the operator's view.
    Alarmed, not enforced: the poll keeps content fresh inside its lookback;
    the SLA bounds deletion lag beyond it (module docstring)."""
    sla = connector.config.reconcile_sla_hours
    if not _reconcile_overdue(last_reconcile_at, connector._clock(), sla):
        return
    record_alarm = getattr(sink, "record_alarm", None)
    if callable(record_alarm):
        record_alarm(
            "reconcile_overdue",
            f"no zero-failure --backfill reconcile within {sla}h "
            f"(last_reconcile_at={last_reconcile_at!r}) — deletions older than the "
            f"{connector.config.lookback_days}-day poll lookback are unbounded until one runs",
        )


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.zoom --once|--backfill
# ---------------------------------------------------------------------------


def _load_cursor(state_file: Path) -> str | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text()).get("cursor")


def _save_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"cursor": cursor}, indent=2) + "\n")


def _print_skips(connector: ZoomConnector) -> None:
    if connector.transcriptless:
        print(
            f"zoom: {len(connector.transcriptless)} recording(s) without a TRANSCRIPT file "
            "— nothing indexable (enable audio transcripts in Zoom to mirror them)"
        )
    if connector.list_failures:
        print(
            f"zoom: recordings list failed for {len(connector.list_failures)} host(s): "
            f"{', '.join(connector.list_failures)} — their windows were NOT diffed "
            "(no absence-retraction over a partial list; retried next cycle)"
        )


def run_once(
    connector: ZoomConnector,
    registry: ZoomRegistry,
    sink: DocumentSink,
    state_file: Path,
    *,
    persist: bool = True,
) -> int:
    """One poll cycle: poll, deliver documents, checkpoint, drain.

    Retraction bodies the ingest ladder cannot deliver — removal markers and
    quarantined bodies — are PARKED in the retraction ledger, then the whole
    ledger is DRAINED as ``POST /v1/admin/retire`` replays; entries whose
    replay fails stay parked + alarmed, never silently dropped. ORDER is
    load-bearing (the over-retire race, sharepoint's exact guards): the
    PRE-EXISTING ledger drains BEFORE this cycle's deliveries, a successful
    delivery UNPARKS any older entry for its document_id, and an in-stream
    delivery supersedes any earlier same-cycle park.

    ``persist=False`` (a DRY RUN) skips the checkpoint: a dry run delivers
    nothing, so it must NOT advance the bookkeeping — otherwise the next REAL
    cycle diffs against a state that was never applied (gdirectory's lesson)."""
    connector.registry = registry  # the vouch gate (G2)
    cursor = _load_cursor(state_file)
    events, next_cursor = asyncio.run(connector.poll(cursor))
    # THE RACE, guard #1: drain the PRE-EXISTING ledger BEFORE delivering.
    _, pre_drained = _drain_parked_retractions(state_file, sink, connector.config.tenant_id)
    delivered = 0
    delivered_ids: set[str] = set()
    parked: list[dict[str, str]] = []
    for event in events:
        assert isinstance(event, ZoomDocumentEvent)
        body = build_zoom_document_request(event, connector.config.tenant_id)
        if not _is_indexable_body(body):
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
    # entry still parked for the same document — unpark it.
    _unpark_delivered(state_file, delivered_ids)
    total_parked, ledger_path = _park_retractions(state_file, parked, _iso(connector._clock()))
    total_parked, drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    drained += pre_drained
    if parked or drained:
        print(
            f"zoom: parked {len(parked)} retraction signal(s) this cycle; "
            f"drained {drained} via POST {RETIRE_PATH}; "
            f"{total_parked} still parked -> {ledger_path}"
        )
    _print_skips(connector)
    if persist:
        _save_cursor(state_file, next_cursor)
    _alarm_parked(sink, total_parked, ledger_path)
    _alarm_reconcile_overdue(
        sink, connector, _parse_cursor(next_cursor).get("last_reconcile_at")
    )
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=next_cursor)
    return delivered


def run_backfill(
    connector: ZoomConnector,
    registry: ZoomRegistry,
    sink: DocumentSink,
    state_file: Path,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 20,
    persist: bool = True,
) -> int:
    """§5a backfill/reconcile: drive :meth:`ZoomConnector.full_crawl` into the
    sink, then stamp ``last_reconcile_at`` — ONLY after a COMPLETE crawl with
    ZERO ingest failures and ZERO list failures (a partial crawl re-proved
    nothing; the prior stamp — possibly none — is carried unchanged and
    ``backfill_incomplete`` is alarmed). Same over-retire-race ordering as
    :func:`run_once` (sharepoint's exact guards): pre-existing ledger drains
    BEFORE the crawl delivers, a successful delivery unparks any older entry
    for its document_id — persisted with EVERY mid-crawl checkpoint, so a
    crash never hands the next run's pre-drain a stale retraction for a
    document it will not re-deliver. Every checkpoint (mid-crawl, the
    crash handler, end-of-run) also PARKS the pending detected retractions
    BEFORE saving the cursor: the cursor's book has already popped the
    absence-retracted uuids, so a cursor that lands without its parks would
    lose those retractions permanently (deleted content serving forever)."""
    connector.registry = registry  # the vouch gate (G2)
    state = _parse_cursor(_load_cursor(state_file))
    connector.prior_book = {
        str(uuid): dict(entry)
        for uuid, entry in (state.get("meetings") or {}).items()
        if isinstance(entry, Mapping)
    }
    prior_reconcile = state.get("last_reconcile_at")
    if reporter is not None:
        reporter.start(total=None)
    # THE RACE, guard #1: the PRE-EXISTING ledger drains BEFORE the crawl
    # delivers anything.
    _, pre_drained = _drain_parked_retractions(state_file, sink, connector.config.tenant_id)
    delivered = 0
    pending = 0
    failed = 0
    delivered_ids: set[str] = set()
    parked: list[dict[str, str]] = []

    def _checkpoint(last_reconcile_at: Any) -> str:
        cursor = json.dumps(
            {"meetings": connector.backfill_book, "last_reconcile_at": last_reconcile_at},
            sort_keys=True,
        )
        if persist:
            # Park FIRST (retraction durability): the cursor about to land has
            # already POPPED every absence-retracted uuid from the book, so the
            # ledger MUST carry the pending parks before the cursor does — a
            # crash between the two re-detects and re-parks on the next crawl
            # (dedup'd, safe); the reverse order loses the retraction FOREVER
            # (no book entry to diff, no ledger entry to drain: the deleted
            # content serves indefinitely).
            _park_retractions(state_file, parked, _iso(connector._clock()))
            # Unpark next (C2): a crash between unpark and save re-crawls the
            # tail (safe); the reverse order would checkpoint a delivery whose
            # stale park entry survives for the next run's pre-drain.
            _unpark_delivered(state_file, delivered_ids)
            _save_cursor(state_file, cursor)
        return cursor

    async def _drive() -> None:
        nonlocal delivered, pending, failed
        async for event in connector.full_crawl():
            assert isinstance(event, ZoomDocumentEvent)
            body = build_zoom_document_request(event, connector.config.tenant_id)
            if not _is_indexable_body(body):
                parked.append(_parked_entry(event, body))
                delivered_ids.discard(event.document_id)  # in-stream, the park is newer
                continue
            try:
                sink.deliver(body)
            except httpx.HTTPError:
                failed += 1  # one bad recording never aborts a whole backfill
                continue
            delivered += 1
            delivered_ids.add(event.document_id)
            parked[:] = [p for p in parked if p["document_id"] != event.document_id]
            pending += 1
            if pending >= flush_every:
                if reporter is not None:
                    reporter.advance(pending)
                pending = 0
                _checkpoint(prior_reconcile)

    try:
        asyncio.run(_drive())
    except Exception as exc:  # noqa: BLE001 — surface as a failed run, then re-raise
        _checkpoint(prior_reconcile)
        if reporter is not None:
            if pending:
                reporter.advance(pending)
            reporter.fail(exc)
        raise
    if reporter is not None:
        if pending:
            reporter.advance(pending)
        reporter.finish()
    # THE RACE, guard #2: deliveries are strictly newer than any still-parked
    # entry for the same document — unpark before the post-crawl park + drain.
    _unpark_delivered(state_file, delivered_ids)
    total_parked, ledger_path = _park_retractions(state_file, parked, _iso(connector._clock()))
    cycle_parked = len(parked)
    # The ledger is now the durable carrier for every pending park — clear the
    # in-memory list so the FINAL checkpoint below (which parks for crash
    # durability) cannot re-park entries the drain just retired.
    parked.clear()
    total_parked, drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    drained += pre_drained
    if cycle_parked or drained or failed:
        print(
            f"zoom: parked {cycle_parked} retraction signal(s); "
            f"drained {drained} via POST {RETIRE_PATH} "
            f"({total_parked} still parked -> {ledger_path}), "
            f"{failed} ingest failure(s)"
        )
    _print_skips(connector)
    record_alarm = getattr(sink, "record_alarm", None)
    saved_cursor: str | None = None
    if connector.backfill_completed_at:
        clean = failed == 0 and not connector.list_failures and not connector.reconcile_unswept
        if clean:
            stamp: Any = connector.backfill_completed_at
        else:
            # A crawl with failures (or unlistable hosts, or bookkept entries
            # no window could re-list) did NOT re-prove the index — carry the
            # prior stamp (possibly none: the SLA alarm then keeps firing,
            # fail closed).
            stamp = prior_reconcile
            if callable(record_alarm):
                record_alarm(
                    "backfill_incomplete",
                    f"{failed} ingest failure(s), "
                    f"{len(connector.list_failures)} unlistable host(s), "
                    f"{len(connector.reconcile_unswept)} bookkept recording(s) outside "
                    "every crawled window (deletion story unverifiable — raise "
                    "--backfill-months or repair the cursor); "
                    "last_reconcile_at NOT stamped — the reconcile SLA stays unmet "
                    "until a zero-failure backfill completes",
                )
        saved_cursor = _checkpoint(stamp)
    _alarm_parked(sink, total_parked, ledger_path)
    _alarm_reconcile_overdue(
        sink, connector, _parse_cursor(saved_cursor).get("last_reconcile_at")
    )
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=saved_cursor)
    return delivered


def _env_flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip() in ("1", "true", "yes")


def _split_csv(raw: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (raw or "").split(",") if part.strip())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.zoom",
        description="Verity Zoom transcript connector (recording-as-document, "
        "settings-derived fail-closed visibility).",
    )
    parser.add_argument("--once", action="store_true", help="run a single poll cycle and exit")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the full monthly-window reconcile crawl (stamps the reconcile SLA), then exit",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print request bodies instead of POSTing"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("ZOOM_STATE_FILE", ".verity/zoom_cursor.json")),
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url", default=os.environ.get("VERITY_URL", "http://localhost:8080")
    )
    parser.add_argument(
        "--users",
        default=os.environ.get("ZOOM_USER_IDS", ""),
        help="comma-separated host user ids/emails whose cloud recordings to mirror",
    )
    parser.add_argument(
        "--principal-map",
        type=Path,
        default=None,
        help="JSON file {principal: int token} -> StaticZoomRegistry (fixtures/dev)",
    )
    parser.add_argument(
        "--reconcile-sla-hours",
        type=int,
        default=int(os.environ.get("ZOOM_RECONCILE_SLA_HOURS", "24")),
    )
    parser.add_argument(
        "--lookback-days", type=int, default=int(os.environ.get("ZOOM_LOOKBACK_DAYS", "7"))
    )
    parser.add_argument(
        "--backfill-months",
        type=int,
        default=int(os.environ.get("ZOOM_BACKFILL_MONTHS", "12")),
    )
    parser.add_argument(
        "--interval", type=float, default=300.0, help="poll interval in seconds (without --once)"
    )
    args = parser.parse_args(argv)

    account_id, client_id, client_secret = load_zoom_credentials()
    config = ZoomConfig(
        tenant_id=args.tenant_id,
        account_id=account_id,
        client_id=client_id,
        client_secret=client_secret,
        user_ids=_split_csv(args.users),
        internal_maps_to=os.environ.get("ZOOM_INTERNAL_MAPS_TO") or None,
        internal_domains=frozenset(
            d.lower() for d in _split_csv(os.environ.get("ZOOM_INTERNAL_DOMAINS"))
        ),
        participants_in_audience=_env_flag("ZOOM_PARTICIPANTS_IN_AUDIENCE"),
        reconcile_sla_hours=args.reconcile_sla_hours,
        lookback_days=args.lookback_days,
        backfill_months=args.backfill_months,
    )
    if not config.user_ids:
        raise RuntimeError(
            "no hosts to mirror: set ZOOM_USER_IDS (or --users) to the host user "
            "ids/emails whose cloud recordings this connector should read"
        )
    oauth = ZoomOAuth(account_id, client_id, client_secret)
    connector = ZoomConnector(HttpZoomTransport(oauth), config)

    api_key = os.environ.get("VERITY_API_KEY")
    registry: ZoomRegistry
    if args.principal_map:
        registry = StaticZoomRegistry(json.loads(args.principal_map.read_text()))
    else:
        registry = HttpZoomRegistry(args.verity_url, tenant_id=config.tenant_id, api_key=api_key)
    sink: DocumentSink
    if args.dry_run:
        sink = DryRunSink()
    else:
        status_sink = ZoomStatusSink(args.verity_url, api_key=api_key)
        # Alarm-only / idle heartbeats still need a tenant to key their row.
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
        delivered = run_backfill(
            connector, registry, sink, args.state_file, reporter, persist=not args.dry_run
        )
        print(f"zoom: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(connector, registry, sink, args.state_file, persist=not args.dry_run)
        dest = "(dry-run, state unchanged)" if args.dry_run else f"cursor -> {args.state_file}"
        print(f"zoom: delivered {delivered} request(s); {dest}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
