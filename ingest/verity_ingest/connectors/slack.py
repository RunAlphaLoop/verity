"""Slack connector — thread-as-document content connector with channel-scoped
mirrored visibility (build contract: the red-teamed Slack plan; structural
template: :mod:`sharepoint` for the park/drain retraction machinery and race
guards; :mod:`gdirectory`/:mod:`entra_directory` for the snapshot-diff
membership core, reused UNCHANGED).

The four load-bearing fail-closed guarantees (every design choice below serves
one; where one cannot be met the affected scope is QUARANTINED or the grant is
DROPPED, never guessed):

G1 — known-channel-shape-or-quarantine. Only ``public_channel`` /
``private_channel`` conversations whose ``is_shared`` / ``is_ext_shared`` /
``is_org_shared`` flags are ALL false (and with no pending Slack Connect
invite) are mirrored. A Slack Connect / externally-shared / org-shared channel
has members OUTSIDE the workspace the identity plane never vouched — the WHOLE
channel is quarantined: no content is indexed, no membership edges are
emitted, and threads previously indexed while the channel was un-shared are
retired through the parked-retractions drain the moment the transition is
seen. A conversation object whose type flags this code does not recognize
quarantines the same way (never guess what a new Slack channel kind shares).
``im``/``mpim`` conversations are SKIPPED — they are 1:1/small-group DMs, a
different consent surface the connector deliberately does not read — and the
skip is counted and reported every cycle, never silent.

G2 — directory-vouched-identity-or-nothing. ``users.list`` →
``profile.email`` → one ``principal_crosswalk`` row per full, active, human
member: ``(source="slack", local_id=<Uid>) → user:<email.lower()>`` with
``link_method="directory_vouched"`` — but ONLY when that canonical ALREADY
exists (active) in the registry, vouched by a REAL directory sync
(gdirectory/entra). ``profile.email`` is workspace-admin-mutable and gets
re-read every cycle, so Slack's word must never MINT identity: a Slack admin
who re-points a member's email could otherwise both redirect the member's
edges AND have this connector CREATE the target canonical on Slack's say-so.
The connector therefore emits crosswalk rows against pre-existing canonicals
and NEVER creates ``canonical_principal`` rows (canonical-creation ops are
filtered out of the reused gdirectory op stream; pre-existence is checked
through the ``/v1/admin/principals`` ``emails`` resolve, which only answers
for ACTIVE canonicals whose ``idp_subject``/SSO-alias a directory sync
vouched — and only an exact ``user:<email>`` canonical match welds; an
alias-resolved different canonical is dropped, never redirected to). A
member whose canonical does not pre-exist confers NOTHING — no crosswalk
row, no membership edge — exactly like ``deleted`` users, ``is_bot`` users,
users without a ``profile.email``, and single/multi-channel guests
(``is_restricted``/``is_ultra_restricted``). A drop only ever NARROWS what a
channel token reaches (visibility is single-group:
``group:slack-channel-<id>``), so dropping an unvouched member is safe,
unlike a content-ACL facet whose drop would mis-mirror a grant. Residual,
stated: an admin re-pointing an email can still REDIRECT edges among
already-vouched canonicals — the gate closes creation, not aim; the
directory sync stays the identity authority. Display names are rendering
sugar in transcripts ONLY, never identity keys.

G3 — membership as snapshot-diff, never truncate-and-reload. Per mirrored
channel, ``conversations.members`` is a FULL snapshot diffed through the
reused gdirectory core (:func:`diff_snapshots` → :func:`build_admin_ops`) into
``POST/DELETE /v1/admin/groups`` edges for ``group:slack-channel-<id>`` —
every removal writes revocation tombstones server-side before the tuple
delete, so a member who leaves a channel stops resolving its token on the
next mint (leaves are safe REGARDLESS of the document lane's gaps: the edge,
not the document, carries their access). Slack is NOT the authoritative
directory, so a deactivated Slack user loses every slack-channel edge via the
diff but deliberately does NOT fire ``/v1/admin/deprovision`` — Slack's word
must not durably revoke a canonical that Google/Entra still vouches.

G4 — retraction-is-enforced (the sharepoint park/drain, verbatim ordering).
A detected retraction — a vanished thread root with no surviving replies, a
``channel_deleted``/vanished channel, or a mirrored→quarantined transition —
produces NO documents-endpoint op; each such body is PARKED in the
``slack_parked_retractions.json`` ledger next to the cursor state and every
parked entry is REPLAYED as ``POST /v1/admin/retire`` under the same admin
bearer the sinks use. Replay ORDER is load-bearing (the over-retire race):
each cycle drains the PRE-EXISTING ledger BEFORE delivering the cycle's
events, parks the cycle's own rejects after delivery, then drains those; and
a successful delivery UNPARKS any older entry for the same document_id — a
parked signal is strictly older than that delivery, so replaying it
afterwards would blank the just-written chunks of a restored thread. Any 2xx
(including the idempotent 0-chunk replay) removes the entry; any failure
keeps it parked and alarmed (``kind="parked_retraction"``) until a later
cycle drains it.

HONEST REMAINDERS (poll-lane detection, stated not hidden):

- ``conversations.history`` returns channel-level rows only — thread REPLIES
  (except broadcasts) never surface there, so the incremental poll misses a
  quiet reply to an old thread AND a delete that leaves no
  ``message_deleted`` row in the fetched window. The full ``--backfill``
  reconcile is the truth lane: it re-walks every mirrored channel, re-ingests
  every live thread, and diffs the crawl against the previous cycle's thread
  bookkeeping — a bookkept thread the crawl no longer sees is a detected
  deletion and rides the retire drain. Until the Socket-Mode push lane lands,
  content freshness between reconciles is bounded by this gap; ACCESS
  freshness is not (membership edges are diffed every cycle — a removed
  member stops resolving regardless of stale content). The
  ``reconcile_overdue`` alarm fires on every heartbeat while
  ``last_reconcile_at`` (stamped ONLY by a zero-failure backfill) is older
  than ``reconcile_sla_hours``.
- The poll lane's edit/delete detection (``message_changed`` /
  ``message_deleted`` subtype rows in the fetched history window) is
  FIXTURE-SHAPED: it matches Slack's documented event/history subtypes, but a
  live ``conversations.history`` may instead surface an edit as the message
  row's ``edited`` field and a delete as plain ABSENCE of the row — neither
  of which this incremental lane would notice. Live falsification is still
  owed (see Verification status). The ``--backfill`` reconcile diff is the
  GUARANTEED catch either way — and the monotonic-supersede guard
  (:meth:`SlackConnector._stamp_monotonic`) is what makes its re-delivery of
  a changed-but-not-newer thread actually land at the index.
- A private channel the bot is kicked from simply vanishes from
  ``conversations.list`` — indistinguishable from deletion; the connector
  fail-closes and retires its threads (over-hide, never stale-open).

Rate-limit posture, honestly: Slack's May 2025 terms/rate-limit update
(https://api.slack.com/changelog/2025-05-terms-rate-limit-update-and-faq)
drastically caps ``conversations.history``/``conversations.replies`` (1
req/min, 15 items) for NON-MARKETPLACE apps distributed outside the Slack
Marketplace; per the FAQ, internal custom apps installed in their own
workspace — exactly what ``verity-cli connect slack`` creates (BYOT, SPEC
§5e.2) — are exempt and keep the classic method tiers. This connector still
does NOT assume Tier 3 unconditionally: the transport honors HTTP 429 +
``Retry-After`` on every call, so it degrades to whatever budget the
workspace actually grants instead of hammering it.

Auth (BYOT): the bot token (``xoxb-``) from ``[connectors.slack]`` in
``~/.verity/config.toml`` (written 0600 by ``verity-cli connect slack``);
``SLACK_BOT_TOKEN`` overrides for ad-hoc runs. The app-level token
(``xapp-``) is loaded alongside but RESERVED for the later Socket-Mode push
lane — the poll connector never opens the WebSocket.

Sink contract: ``POST /v1/ingest/documents`` bodies with
``document_id="slack:{channel_id}:{thread_ts}"`` (a non-threaded message is a
thread of one), ``content`` = the chronological transcript with display
names, ``valid_from`` = the LATEST ts in the thread — advanced monotonically
past the last DELIVERED stamp whenever the content changed without that ts
moving forward (deleting the latest reply regresses it; editing the latest
message keeps its ts): the server's supersede retires only rows strictly
OLDER than the incoming stamp and its replay-idempotency rides an
insert-conflict DO NOTHING, so a non-advancing re-delivery would leave the
deleted text serving or no-op the edit entirely (the L1 guard,
:meth:`SlackConnector._stamp_monotonic`) — ``visibility`` = the
resolved ``group:slack-channel-<id>`` token (via ``/v1/admin/principals``),
``acl_provenance`` mirrored; quarantined bodies carry NO ``visibility``.
Admin contract: the same ``/v1/admin/{principals,groups,crosswalk,registry}``
routes gdirectory codes against, via the reused :class:`VerityAdminSink`.

Runner: ``python -m verity_ingest.connectors.slack --once|--backfill
[--dry-run]`` with a JSON cursor state file (per-channel ``latest`` poll
marks + thread bookkeeping + the directory snapshot + resumable per-channel
backfill cursors) and, beside it, the ``slack_parked_retractions`` ledger.
Heartbeats post ``source="slack"`` EVERY cycle including idle ones
(``items_synced: 0``) — the server's per-source freshness gate fences a
silent connector, so a quiet-but-healthy one must keep beating.

Verification status (honest-limitations doctrine): FIXTURE-VERIFIED — every
behavior above is asserted against fixtures authored from Slack's documented
Web API response shapes (conversations.list/members/history/replies,
users.list, cursor pagination, 429/Retry-After). It has NOT run against a
live workspace; live lanes still open: the Socket-Mode push lane, live proof
of the internal-app rate-limit posture, ``channels:join`` semantics on a
real workspace, and the poll-lane edit/delete row shapes (whether a live
``conversations.history`` really surfaces ``message_changed`` /
``message_deleted`` subtype rows — see the honest remainder above).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterator, Mapping, Protocol, Sequence

import httpx

from verity_ingest import crosswalk
from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

# The snapshot-diff membership engine, reused UNCHANGED (G3): forking it would
# be a correctness liability — two engines to keep in lockstep. build_admin_ops
# threads `source` into build_registry_ops so the self-crosswalk rows stamp
# "slack" (the source a downstream resolve presents) without a fork.
from verity_ingest.connectors.gdirectory import (
    REGISTRY_CANONICAL_PATH,
    AdminOp,
    AdminSink,
    DirectorySnapshot,
    DirectoryUser,
    DryRunAdminSink,
    VerityAdminSink,
    build_admin_ops,
    diff_snapshots,
)

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
    "CHANNEL_GROUP_PREFIX",
    "SlackApiError",
    "SlackConfig",
    "SlackDocumentEvent",
    "SlackTransport",
    "HttpSlackTransport",
    "SlackConnector",
    "SlackRegistry",
    "StaticSlackRegistry",
    "HttpSlackRegistry",
    "SlackStatusSink",
    "DryRunSink",
    "DryRunAdminSink",
    "VerityAdminSink",
    "WorkspaceView",
    "classify_channel",
    "map_slack_user",
    "channel_principal",
    "content_digest",
    "thread_document_id",
    "render_transcript",
    "build_slack_document_request",
    "build_slack_admin_ops",
    "load_slack_credentials",
    "run_once",
    "run_backfill",
    "main",
]

SOURCE_NAME = "slack"

SLACK_API_BASE_URL = "https://slack.com/api/"

#: Channel-membership visibility token prefix (G3). The channel id — not the
#: mutable name — keys the group: Slack channel ids are immutable across
#: renames (`channel_rename` never moves membership or history).
CHANNEL_GROUP_PREFIX = "group:slack-channel-"

#: Where `verity-cli connect slack` stores the tokens (0600, owner-only).
DEFAULT_CONFIG_PATH = Path.home() / ".verity" / "config.toml"

#: Channel classifications (G1). "im" is the counted skip, never indexed.
MIRRORED = "mirrored"
QUARANTINED = "quarantined"
SKIPPED_IM = "im"

#: History-row subtypes that are edit/delete SIGNALS about another message —
#: they trigger a re-ingest of the referenced thread (poll-lane detection) and
#: never render into a transcript themselves.
_SIGNAL_SUBTYPES = frozenset({"message_changed", "message_deleted"})

#: Membership/housekeeping subtypes excluded from transcripts (rendering
#: noise, not content). "tombstone" is the placeholder Slack leaves for a
#: deleted thread root — rendering it would index "This message was deleted."
_NOISE_SUBTYPES = frozenset(
    {
        "channel_join",
        "channel_leave",
        "channel_topic",
        "channel_purpose",
        "channel_name",
        "channel_archive",
        "channel_unarchive",
        "tombstone",
    }
)


def channel_principal(channel_id: str) -> str:
    """The one visibility token a mirrored thread carries (G1/G3)."""
    return f"{CHANNEL_GROUP_PREFIX}{channel_id}"


def thread_document_id(channel_id: str, thread_ts: str) -> str:
    """``slack:{channel_id}:{thread_ts}`` — the channel id is load-bearing
    (thread ts values are only unique within a channel); a non-threaded
    message is a thread of one keyed by its own ts."""
    return f"slack:{channel_id}:{thread_ts}"


def _ts_iso(ts: str) -> str:
    """Slack epoch ts ("1722502800.000123") → UTC ISO-8601 (second
    resolution — the ingest `valid_from` contract)."""
    try:
        moment = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_max(a: str, b: str) -> str:
    """The later of two raw Slack ts strings (float compare, not lexical —
    Slack pads unevenly across the epoch-digit rollover)."""
    try:
        return a if float(a) >= float(b) else b
    except (TypeError, ValueError):
        return a or b


def content_digest(content: bytes) -> str:
    """Content fingerprint bookkept per delivered thread (the L1 guard's
    changed-vs-unchanged signal): sha256 over the exact transcript bytes
    delivered. Deterministic — the transcript renderer is deterministic — so
    a replay of the SAME version always matches and is skipped."""
    return hashlib.sha256(content).hexdigest()


def _thread_entry(raw: Any) -> dict[str, Any]:
    """Normalize one bookkept thread entry to ``{"delivered": iso, "digest":
    hex|None}``. ``delivered`` is the ``valid_from`` actually DELIVERED for
    the thread's current version (possibly advanced past the recomputed
    latest-ts — see :meth:`SlackConnector._stamp_monotonic`). A legacy bare
    ISO-string entry carries no digest: it reads as changed-content on next
    sight, which over-delivers once (safe) and then self-heals."""
    if isinstance(raw, Mapping):
        digest = raw.get("digest")
        return {
            "delivered": str(raw.get("delivered") or ""),
            "digest": str(digest) if digest else None,
        }
    return {"delivered": str(raw or ""), "digest": None}


def _advance_stamp(delivered: str, *candidates: str) -> str:
    """The smallest honest ``valid_from`` strictly AFTER the last delivered
    stamp: the first candidate that beats it (both are this module's fixed
    ``%Y-%m-%dT%H:%M:%SZ`` shape, so lexical order IS chronological order),
    else ``delivered`` + 1s (the deterministic last resort — e.g. clock skew
    put the cycle clock at/behind the bookkept stamp). Never returns a stamp
    <= ``delivered``: the server supersede is strictly monotonic, so a
    non-advancing stamp silently fails to retire the previous version."""
    for candidate in candidates:
        if candidate and candidate > delivered:
            return candidate
    try:
        then = datetime.fromisoformat(delivered.replace("Z", "+00:00"))
    except ValueError:
        # A tampered/foreign bookkept stamp: fall back to the last candidate
        # (the cycle clock) rather than crash the cycle.
        return candidates[-1] if candidates else delivered
    return _iso(then + timedelta(seconds=1))


# ---------------------------------------------------------------------------
# Config & credentials
# ---------------------------------------------------------------------------


@dataclass
class SlackConfig:
    """Connector configuration. No default widens visibility."""

    tenant_id: str = "default"  # Verity tenant (opaque)
    bot_token: str | None = None  # xoxb- (Web API reads)
    #: Reserved for the later Socket-Mode push lane; the poll connector never
    #: opens the WebSocket (loaded so the runner can pass it through unchanged
    #: when that lane lands).
    app_token: str | None = None
    #: Self-join public channels the bot is not yet a member of
    #: (`channels:join`). Private channels can never be self-joined — the bot
    #: must be invited, which is exactly the operator consent Slack enforces.
    join_public_channels: bool = True
    #: G4 remainder: alarm `reconcile_overdue` while no zero-failure backfill
    #: completed within this window (alarmed, not enforced — membership edges
    #: keep ACCESS fresh every cycle; the SLA bounds content-deletion lag).
    reconcile_sla_hours: int = 24
    page_size: int = 200


def load_slack_credentials(config_path: Path | None = None) -> tuple[str, str | None]:
    """(bot_token, app_token) — BYOT, from the operator's own machine only.

    Precedence: ``SLACK_BOT_TOKEN``/``SLACK_APP_TOKEN`` env (ad-hoc runs),
    else ``[connectors.slack]`` in ``~/.verity/config.toml`` (or
    ``VERITY_CONFIG``), the 0600 file ``verity-cli connect slack`` writes. No
    token → a RuntimeError naming the wizard, never a half-configured run."""
    bot = os.environ.get("SLACK_BOT_TOKEN") or None
    app = os.environ.get("SLACK_APP_TOKEN") or None
    path = config_path or Path(os.environ.get("VERITY_CONFIG") or DEFAULT_CONFIG_PATH)
    if (not bot or not app) and path.exists():
        section = tomllib.loads(path.read_text()).get("connectors", {}).get("slack", {})
        bot = bot or section.get("bot_token") or None
        app = app or section.get("app_token") or None
    if not bot:
        raise RuntimeError(
            f"no Slack bot token: run `verity-cli connect slack` (writes [connectors.slack] "
            f"to {path}), or set SLACK_BOT_TOKEN"
        )
    return bot, app


# ---------------------------------------------------------------------------
# Channel classification (G1) & identity mapping (G2)
# ---------------------------------------------------------------------------


def classify_channel(channel: Mapping[str, Any]) -> str:
    """One conversations.list object → MIRRORED / QUARANTINED / SKIPPED_IM.

    Known-channel-shape-or-quarantine (G1): only a plain public or private
    channel (``is_channel`` or legacy ``is_group``) with ``is_shared`` /
    ``is_ext_shared`` / ``is_org_shared`` all false and no pending Slack
    Connect invite (``pending_shared`` / ``is_pending_ext_shared`` — Slack
    documents both spellings for the invite-in-flight state) mirrors. Any
    shared flag, a pending share, or a shape this code does not recognize
    quarantines the WHOLE channel — its members are not all
    workspace-vouched, so channel membership no longer approximates
    visibility. ``im``/``mpim`` are skipped (counted by the caller, never
    silent) — DMs are a consent surface this connector does not read."""
    if channel.get("is_im") or channel.get("is_mpim"):
        return SKIPPED_IM
    if not (channel.get("is_channel") or channel.get("is_group")):
        return QUARANTINED  # a conversation kind Slack added later: never guess
    if (
        channel.get("is_shared")
        or channel.get("is_ext_shared")
        or channel.get("is_org_shared")
        or channel.get("is_pending_ext_shared")
        or channel.get("pending_shared")
    ):
        return QUARANTINED
    return MIRRORED


def map_slack_user(user: Mapping[str, Any]) -> DirectoryUser | None:
    """One users.list member → a :class:`DirectoryUser` for the registry, or
    None (confers nothing — G2).

    Only a FULL, ACTIVE, HUMAN member with an admin-vouched ``profile.email``
    maps: ``deleted`` accounts, bots (incl. Slackbot, whose ``is_bot`` is
    famously false — caught by the missing email), single/multi-channel
    guests (``is_restricted``/``is_ultra_restricted``), and members without
    an email all return None — no crosswalk row, no membership edge. Dropping
    only NARROWS (the channel token reaches fewer people), never poisons:
    visibility here is single-group, so there is no partial-ACL to mis-mirror."""
    if user.get("deleted") or user.get("is_bot"):
        return None
    if user.get("is_restricted") or user.get("is_ultra_restricted"):
        return None
    uid = str(user.get("id") or "")
    email = str((user.get("profile") or {}).get("email") or "").strip().lower()
    if not uid or not email:
        return None
    return DirectoryUser(directory_id=uid, primary_email=email)


def display_name(user: Mapping[str, Any]) -> str:
    """Rendering-only name for transcripts (NEVER an identity key — G2):
    display_name, else real_name, else the handle, else the raw id."""
    profile = user.get("profile") or {}
    return str(
        profile.get("display_name")
        or profile.get("real_name")
        or user.get("real_name")
        or user.get("name")
        or user.get("id")
        or "unknown"
    )


# ---------------------------------------------------------------------------
# Transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class SlackApiError(RuntimeError):
    """A Slack Web API ``{"ok": false}`` envelope. ``error`` is Slack's stable
    machine tag (e.g. ``not_in_channel``, ``thread_not_found``)."""

    def __init__(self, method: str, error: str) -> None:
        super().__init__(f"slack api {method}: {error}")
        self.method = method
        self.error = error


class SlackTransport(Protocol):
    """Minimal surface over the Slack Web API, so tests run on fixtures."""

    def call(self, method: str, params: Mapping[str, Any]) -> dict: ...


class HttpSlackTransport:
    """Live Web API transport: bot-token bearer auth, form-encoded POST (the
    Web API's universal calling convention), HTTP 429 + ``Retry-After``
    honored with bounded retries (the honest rate-limit posture — see the
    module docstring: never assume a tier, always obey the budget), and the
    ``{"ok": false}`` envelope surfaced as :class:`SlackApiError`."""

    def __init__(
        self,
        bot_token: str,
        client: httpx.Client | None = None,
        *,
        max_retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client or httpx.Client(base_url=SLACK_API_BASE_URL, timeout=60.0)
        self._headers = {"Authorization": f"Bearer {bot_token}"}
        self._max_retries = max_retries
        self._sleep = sleep

    def call(self, method: str, params: Mapping[str, Any]) -> dict:
        attempt = 0
        while True:
            response = self._client.post(method, data=dict(params), headers=self._headers)
            if response.status_code == 429 and attempt < self._max_retries:
                self._sleep(float(response.headers.get("Retry-After", "1")))
                attempt += 1
                continue
            response.raise_for_status()
            payload = response.json()
            if not payload.get("ok"):
                raise SlackApiError(method, str(payload.get("error") or "unknown_error"))
            return payload


# ---------------------------------------------------------------------------
# Principal resolution (the channel token, via /v1/admin/principals)
# ---------------------------------------------------------------------------


class SlackRegistry(Protocol):
    """Resolves canonical principal strings (the channel group token) to int
    visibility tokens."""

    def resolve(self, request: crosswalk.ResolveRequest) -> crosswalk.ResolveResult: ...


class StaticSlackRegistry:
    """Fixed mapping, from config or fixtures. Missing keys stay unresolved
    (the ladder then quarantines on zero tokens — fail closed). ``emails``
    resolve iff their ``user:<email>`` canonical is in the map — the fixture
    stand-in for the live server's idp_subject existence check (an email with
    no pre-existing canonical confers nothing, the G2 weld gate)."""

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


class HttpSlackRegistry:
    """Resolves via ``POST /v1/admin/principals`` (crosswalk.resolve_via).
    Slack visibility is group-only (``group:slack-channel-<id>`` is already
    canonical), so requests ride ``principals`` — no email/crosswalk owners
    on the document path (member identity is the ADMIN plane's job, G2)."""

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
# Events & the document-body ladder
# ---------------------------------------------------------------------------


@dataclass
class SlackDocumentEvent(DocumentEvent):
    """DocumentEvent + the thread coordinates, latest-ts stamp, and removal
    marker. ``modified_time`` is the ISO ``valid_from`` (the LATEST ts in the
    thread — an edit or new reply moves it forward, so the re-ingested
    document supersedes at the index)."""

    modified_time: str = ""
    channel_id: str = ""
    thread_ts: str = ""
    removed: bool = False


def build_slack_document_request(
    event: SlackDocumentEvent, registry: SlackRegistry, tenant_id: str
) -> dict:
    """Build the ``/v1/ingest/documents`` body for one thread event.

    Fail-closed ladder (mirrors sharepoint's):
    - removal marker → ``{"removed": true}`` body (parked → retire drain);
    - unresolvable envelope (a quarantined channel) → quarantine body with NO
      ``visibility`` and NO content (content was never fetched to begin with);
    - resolvable but the channel token resolves to nothing → quarantine (a
      channel group with no allocated token must never index open);
    - otherwise → mirrored body with the sorted int visibility tokens."""
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
    if not event.acl.resolvable:
        body["acl_provenance"] = "quarantined"
        return body
    result = registry.resolve(crosswalk.ResolveRequest(principals=list(event.acl.groups)))
    tokens = result.tokens()
    if not tokens:
        body["acl_provenance"] = "quarantined"
        return body
    body["visibility"] = tokens
    body["acl_provenance"] = "mirrored"
    return body


# ---------------------------------------------------------------------------
# Admin ops: identity crosswalk + membership diff (G2/G3)
# ---------------------------------------------------------------------------


def build_slack_admin_ops(
    previous: DirectorySnapshot, desired: DirectorySnapshot, tenant_id: str
) -> list[AdminOp]:
    """Diff two workspace snapshots into ordered admin ops via the reused
    gdirectory engine: registry populate (canonical + the ``(slack, Uid)``
    directory_vouched crosswalk) → principals upsert → membership ADDS →
    membership REMOVALS, each removal one at a time (tombstones before the
    tuple delete — G3).

    Deliberate deviations from the directory connectors (G2: Slack is not
    the authoritative directory — an admin-mutable ``profile.email`` must
    never mint or durably revoke identity on Slack's word alone):

    - ``deprovisioned`` is CLEARED. A member deactivated (or simply deleted)
      in Slack loses every ``group:slack-channel-*`` edge through the
      membership diff (access narrows immediately) but must NOT fire the
      tenant-wide ``/v1/admin/deprovision`` durable revoke; that verdict
      belongs to the gdirectory/entra sync.
    - canonical-CREATION ops are FILTERED OUT. Slack emits crosswalk rows
      only (welding its Uid to a canonical the weld gate in
      :meth:`SlackConnector.directory_snapshot` already proved pre-existing
      and active), never ``/v1/admin/registry/canonical`` upserts — a
      re-pointed email must not create (or re-activate) a canonical
      principal on Slack's say-so."""
    diff = diff_snapshots(previous, desired)
    diff.deprovisioned = []
    ops = build_admin_ops(diff, tenant_id, source=SOURCE_NAME)
    return [op for op in ops if op.path != REGISTRY_CANONICAL_PATH]


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


def _snapshot_to_dict(snapshot: DirectorySnapshot) -> dict:
    """gdirectory's snapshot serialization, embedded in the slack cursor so
    the whole cycle checkpoints atomically (one file, one write)."""
    return {
        "users": snapshot.users,
        "memberships": [list(pair) for pair in snapshot.memberships],
        "directory_users": [
            {"directory_id": u.directory_id, "primary_email": u.primary_email}
            for u in snapshot.directory_users
        ],
    }


def _snapshot_from_dict(raw: Mapping[str, Any] | None) -> DirectorySnapshot:
    raw = raw or {}
    return DirectorySnapshot(
        users=list(raw.get("users") or []),
        memberships=[(g, m) for g, m in (raw.get("memberships") or [])],
        directory_users=[
            DirectoryUser(
                directory_id=str(u.get("directory_id") or ""),
                primary_email=str(u.get("primary_email") or ""),
            )
            for u in raw.get("directory_users") or []
        ],
    )


@dataclass
class WorkspaceView:
    """One cycle's read of the workspace: mapped identities, rendering names,
    and the classified channel inventory (G1/G2)."""

    users: dict[str, DirectoryUser] = field(default_factory=dict)  # uid → mapped identity
    display_names: dict[str, str] = field(default_factory=dict)  # uid → rendering name
    channels: dict[str, dict] = field(default_factory=dict)  # cid → raw channel (not im/mpim)
    channel_class: dict[str, str] = field(default_factory=dict)  # cid → MIRRORED/QUARANTINED
    skipped_im: int = 0


class SlackConnector(Connector):
    name = SOURCE_NAME

    def __init__(
        self,
        transport: SlackTransport,
        config: SlackConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport
        self.config = config or SlackConfig()
        self._clock = clock or _utcnow
        # The G2 weld gate's registry (set by run_once/run_backfill before any
        # snapshot builds): a member welds only when its canonical ALREADY
        # exists — resolved via the registry's `emails` existence check. None
        # (a bare connector driven outside the runners) fails CLOSED: no
        # canonical can be verified, so no member confers anything.
        self.weld_registry: SlackRegistry | None = None
        # Set by poll()/prepare() for the runner: the cycle's desired identity
        # snapshot (admin ops are applied BEFORE document delivery).
        self.last_view: WorkspaceView | None = None
        self.last_snapshot: DirectorySnapshot | None = None
        # Counted skips, reported every cycle — never silent (G1).
        self.skipped_im = 0
        self.unreadable_channels: list[str] = []
        self.join_failures: list[str] = []
        # Backfill machinery (resumable per-channel cursors), driven by
        # run_backfill: progress is cid → history cursor | "done"; partial is
        # the in-progress channel's thread bookkeeping (so a resumed crawl
        # never mistakes an already-delivered thread for a deleted one);
        # channel_state collects each COMPLETED channel's poll state.
        self.prior_channels: dict[str, dict] = {}
        self.backfill_progress: dict[str, str] = {}
        self.backfill_partial: dict[str, dict] = {}
        self.backfill_channel_state: dict[str, dict] = {}
        self.backfill_completed_at: str | None = None

    # -- push lane ----------------------------------------------------------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op: the Socket-Mode push lane (the manifest's event
        subscriptions + the reserved xapp- token) is a LATER latency
        optimization; poll + the reconcile SLA is the truth lane either way —
        push may shrink the content-freshness gap, never replace the
        membership diff or the reconcile."""
        return
        yield  # pragma: no cover - makes this an async generator

    # -- workspace survey (users + channels, G1/G2) --------------------------

    def _paged(self, method: str, params: Mapping[str, Any], key: str) -> Iterator[dict]:
        """Walk one Web API list method across cursor pages
        (``response_metadata.next_cursor``, empty/whitespace = last page)."""
        cursor: str | None = None
        while True:
            page_params = dict(params)
            if cursor:
                page_params["cursor"] = cursor
            page = self._transport.call(method, page_params)
            yield from page.get(key) or []
            cursor = ((page.get("response_metadata") or {}).get("next_cursor") or "").strip()
            if not cursor:
                return

    def survey(self) -> WorkspaceView:
        """users.list + conversations.list → one classified WorkspaceView.

        conversations.list is asked for public+private channels only, but
        every returned object is STILL classified (defense in depth: a
        server-side filter is never trusted to enforce G1). im/mpim objects
        are skipped + counted; unknown/shared shapes quarantine."""
        view = WorkspaceView()
        for user in self._paged(
            "users.list", {"limit": str(self.config.page_size)}, "members"
        ):
            uid = str(user.get("id") or "")
            if not uid:
                continue
            view.display_names[uid] = display_name(user)
            mapped = map_slack_user(user)
            if mapped is not None:
                view.users[uid] = mapped
        for channel in self._paged(
            "conversations.list",
            {
                "types": "public_channel,private_channel",
                "exclude_archived": "false",
                "limit": str(self.config.page_size),
            },
            "channels",
        ):
            cid = str(channel.get("id") or "")
            if not cid:
                continue
            cls = classify_channel(channel)
            if cls == SKIPPED_IM:
                view.skipped_im += 1
                continue
            view.channels[cid] = dict(channel)
            view.channel_class[cid] = cls
        self.skipped_im = view.skipped_im
        return view

    def _vouched_canonicals(self, users: Sequence[DirectoryUser]) -> set[str]:
        """The G2 weld gate: which of these members' canonicals ALREADY exist
        (active) in the registry. One batched ``emails`` resolve — the server
        only answers for canonicals a real directory sync (gdirectory/entra)
        vouched via ``idp_subject``/SSO-alias, and NEVER creates one — so a
        surviving mapping key IS proof of pre-existence. No registry wired
        (``weld_registry is None``) → empty set, fail closed: Slack alone can
        never establish identity."""
        emails = sorted({u.primary_email for u in users})
        if not emails or self.weld_registry is None:
            return set()
        result = self.weld_registry.resolve(crosswalk.ResolveRequest(emails=emails))
        return set(result.mappings)

    def directory_snapshot(self, view: WorkspaceView) -> DirectorySnapshot:
        """The cycle's desired identity state (G2/G3): every VOUCHED member's
        registry record + one ``(group:slack-channel-<cid>, user:<email>)``
        edge per mirrored-channel member. Quarantined channels contribute NO
        edges (their token must reach nobody); unmapped member ids (bots,
        guests, no-email) contribute nothing; and — the G2 weld gate — a
        member whose canonical does not ALREADY exist in the registry also
        contributes nothing (no crosswalk row, no edge): Slack must never
        mint identity from an admin-mutable ``profile.email``. All of these
        drops only NARROW, never poison."""
        vouched = self._vouched_canonicals(list(view.users.values()))
        users = {
            uid: mapped for uid, mapped in view.users.items() if mapped.canonical in vouched
        }
        memberships: set[tuple[str, str]] = set()
        for cid in sorted(view.channels):
            if view.channel_class.get(cid) != MIRRORED:
                continue
            group = channel_principal(cid)
            for uid in self._paged(
                "conversations.members",
                {"channel": cid, "limit": str(self.config.page_size)},
                "members",
            ):
                mapped = users.get(str(uid))
                if mapped is not None:
                    memberships.add((group, mapped.canonical))
        directory_users = sorted(users.values(), key=lambda u: u.primary_email)
        return DirectorySnapshot(
            users=sorted({u.canonical for u in directory_users}),
            memberships=sorted(memberships),
            directory_users=directory_users,
        )

    def prepare(self) -> DirectorySnapshot:
        """Survey + snapshot, cached for the runner (poll/backfill both apply
        admin ops from ``last_snapshot`` BEFORE any content delivers)."""
        self.last_view = self.survey()
        self.last_snapshot = self.directory_snapshot(self.last_view)
        return self.last_snapshot

    # -- content plumbing ----------------------------------------------------

    def _ensure_member(self, channel: Mapping[str, Any]) -> None:
        """Self-join a mirrored PUBLIC channel (`channels:join`) so history is
        readable. Private channels are never self-joined (invitation IS the
        consent). A refused join is recorded — the channel then reads as
        unreadable, counted, never silently empty."""
        cid = str(channel.get("id") or "")
        if (
            not self.config.join_public_channels
            or channel.get("is_member")
            or channel.get("is_private")
            or not channel.get("is_channel")
        ):
            return
        try:
            self._transport.call("conversations.join", {"channel": cid})
        except SlackApiError:
            if cid not in self.join_failures:
                self.join_failures.append(cid)

    def _fetch_thread(self, channel_id: str, thread_ts: str) -> list[dict] | None:
        """conversations.replies → the thread's renderable messages, or None
        when the thread is GONE (vanished root with no surviving replies, or
        Slack answers thread_not_found) — the caller emits a removal marker.
        A tombstoned root WITH surviving replies still renders (the replies
        remain visible in Slack; only the root text is gone)."""
        try:
            messages = list(
                self._paged(
                    "conversations.replies",
                    {
                        "channel": channel_id,
                        "ts": thread_ts,
                        "limit": str(self.config.page_size),
                    },
                    "messages",
                )
            )
        except SlackApiError as exc:
            if exc.error in ("thread_not_found", "message_not_found"):
                return None
            raise
        renderable = [
            m
            for m in messages
            if str(m.get("ts") or "")
            and m.get("subtype") not in _SIGNAL_SUBTYPES
            and m.get("subtype") not in _NOISE_SUBTYPES
        ]
        return renderable or None

    def _thread_event(
        self, channel_id: str, thread_ts: str, view: WorkspaceView
    ) -> SlackDocumentEvent:
        """One thread → its document event (mirrored posture) or a removal
        marker. Visibility is exactly the channel token; the registry resolve
        happens at body-build time (ladder above)."""
        messages = self._fetch_thread(channel_id, thread_ts)
        if messages is None:
            return self._removed_event(channel_id, thread_ts)
        transcript = render_transcript(messages, view.display_names)
        latest = "0"
        for message in messages:
            latest = _ts_max(latest, str(message.get("ts") or "0"))
        return SlackDocumentEvent(
            source=self.name,
            document_id=thread_document_id(channel_id, thread_ts),
            content=transcript.encode("utf-8"),
            mime_type="text/plain",
            version=latest,
            acl=AclEnvelope(resolvable=True, groups=[channel_principal(channel_id)]),
            modified_time=_ts_iso(latest),
            channel_id=channel_id,
            thread_ts=thread_ts,
        )

    def _removed_event(self, channel_id: str, thread_ts: str) -> SlackDocumentEvent:
        return SlackDocumentEvent(
            source=self.name,
            document_id=thread_document_id(channel_id, thread_ts),
            content=b"",
            mime_type="",
            version="",
            acl=AclEnvelope(resolvable=True),  # nothing indexed; grants nothing
            modified_time=_iso(self._clock()),
            channel_id=channel_id,
            thread_ts=thread_ts,
            removed=True,
        )

    def _quarantine_event(self, channel_id: str, thread_ts: str) -> SlackDocumentEvent:
        """Quarantine posture for a thread in a channel that stopped being
        mirrorable (G1 transition). NO content rides it — the body ladder
        yields a visibility-less quarantine body, which the runner PARKS and
        drains as a retire replay (the previously-indexed transcript stops
        serving)."""
        return SlackDocumentEvent(
            source=self.name,
            document_id=thread_document_id(channel_id, thread_ts),
            content=b"",
            mime_type="text/plain",
            version="",
            acl=AclEnvelope(resolvable=False),
            modified_time=_iso(self._clock()),
            channel_id=channel_id,
            thread_ts=thread_ts,
        )

    def _stamp_monotonic(
        self, event: SlackDocumentEvent, entry: Mapping[str, Any] | None, *candidates: str
    ) -> dict[str, Any] | None:
        """The L1 non-monotonic-supersede guard. The server's supersede is
        STRICTLY monotonic by design: an ingest retires only the currently-
        open chunk rows ``WHERE valid_from < <new stamp>`` and the insert is
        ``ON CONFLICT (…, valid_from) DO NOTHING`` — at-least-once replay
        idempotency DEPENDS on that DO NOTHING, so the server must not bend.
        But this connector's natural stamp (the latest ts in the thread) is
        NON-monotonic: deleting the latest reply REGRESSES it (two open rows,
        the deleted text keeps serving) and editing the latest message keeps
        its ts (the redaction no-ops entirely). So the fix is ours: whenever
        the re-rendered content CHANGED but the recomputed stamp is <= the
        bookkept last-DELIVERED stamp, advance ``valid_from`` monotonically
        past the bookkept stamp — the detection signal's own ts where
        available, else the cycle clock, else bookkept+1s (deterministic last
        resort). Unchanged content at a non-advancing stamp returns None:
        skip the delivery outright (a replay of the same delivered version
        stays a no-op at the connector, not index churn).

        Returns the new bookkeeping entry ``{"delivered", "digest"}`` (and
        mutates ``event.modified_time`` when the stamp had to advance), or
        None when there is nothing to re-deliver."""
        digest = content_digest(event.content)
        if entry:
            delivered = str(entry.get("delivered") or "")
            if delivered and event.modified_time <= delivered:
                if entry.get("digest") == digest:
                    return None
                event.modified_time = _advance_stamp(
                    delivered, *candidates, _iso(self._clock())
                )
        return {"delivered": event.modified_time, "digest": digest}

    def _history_targets(
        self, channel_id: str, oldest: str
    ) -> tuple[dict[str, str], str, bool]:
        """(thread roots to re-ingest → the newest detecting row's ts, newest
        ts seen, readable) from the channel rows since ``oldest``
        (exclusive). ``message_changed`` / ``message_deleted`` signal rows
        re-target the EDITED message's thread (poll-lane edit/delete
        detection — fixture-shaped, see the module's honest remainders: live
        history may show edits/deletes differently; the backfill diff is the
        guaranteed catch); ordinary rows target their own thread (a reply
        broadcast re-targets its root). The detecting row's own ts is kept
        per target: it is the honest event-time candidate when the L1 guard
        must advance a non-advancing ``valid_from``. An unreadable channel
        (`not_in_channel` — the bot was never joined/invited) is counted,
        never silently empty."""
        targets: dict[str, str] = {}
        max_ts = oldest
        try:
            for message in self._paged(
                "conversations.history",
                {
                    "channel": channel_id,
                    "oldest": oldest,
                    "limit": str(self.config.page_size),
                },
                "messages",
            ):
                ts = str(message.get("ts") or "")
                if ts:
                    max_ts = _ts_max(max_ts, ts)
                target = _target_thread(message)
                if target:
                    targets[target] = _ts_max(targets.get(target) or "0", ts or "0")
        except SlackApiError as exc:
            if exc.error == "not_in_channel":
                if channel_id not in self.unreadable_channels:
                    self.unreadable_channels.append(channel_id)
                return {}, oldest, False
            raise
        return targets, max_ts, True

    def _newest_ts(self, channel_id: str) -> str:
        """Prime a never-polled channel: the newest ts right now (enumeration
        of anything older is the backfill's job — mirrors sharepoint's
        token=latest priming)."""
        try:
            page = self._transport.call(
                "conversations.history", {"channel": channel_id, "limit": "1"}
            )
        except SlackApiError as exc:
            if exc.error == "not_in_channel":
                if channel_id not in self.unreadable_channels:
                    self.unreadable_channels.append(channel_id)
                return "0"
            raise
        messages = page.get("messages") or []
        return str(messages[0].get("ts")) if messages else "0"

    # -- truth lane ----------------------------------------------------------

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """Incremental poll: survey + membership snapshot (cached on
        ``last_snapshot`` for the runner's admin ops), then per mirrored
        channel the history rows since the saved ``latest`` mark → the set of
        threads to (re-)ingest. First sight of a channel primes its mark and
        emits nothing (enumeration is the backfill's job). A channel that
        left the mirrorable set — quarantined (G1 transition) or vanished
        (deleted, archived away, or the bot was removed) — emits quarantine /
        removal events for every bookkept thread; the runner parks and drains
        them (G4)."""
        self.skipped_im = 0
        self.unreadable_channels = []
        self.join_failures = []
        state = _parse_cursor(cursor)
        channels_state: dict[str, dict] = {
            cid: dict(entry)
            for cid, entry in (state.get("channels") or {}).items()
            if isinstance(entry, dict)
        }
        snapshot = self.prepare()
        view = self.last_view
        assert view is not None
        events: list[FactEvent | DocumentEvent] = []
        next_channels: dict[str, dict] = {}
        for cid in sorted(view.channels):
            prev = channels_state.get(cid) or {}
            prev_threads = {
                str(k): _thread_entry(v) for k, v in (prev.get("threads") or {}).items()
            }
            if view.channel_class.get(cid) != MIRRORED:
                # G1: quarantined. A mirrored→quarantined TRANSITION retires
                # every bookkept thread; a channel that was never mirrored has
                # nothing indexed and emits nothing. Bookkeeping is dropped —
                # the ledger, not the cursor, carries the signal from here.
                if prev.get("class") == MIRRORED:
                    for thread_ts in sorted(prev_threads):
                        events.append(self._quarantine_event(cid, thread_ts))
                next_channels[cid] = {"class": QUARANTINED}
                continue
            self._ensure_member(view.channels[cid])
            latest = prev.get("latest") if prev.get("class") == MIRRORED else None
            if not latest:
                next_channels[cid] = {
                    "class": MIRRORED,
                    "latest": self._newest_ts(cid),
                    "threads": {},
                }
                continue
            targets, max_ts, readable = self._history_targets(cid, str(latest))
            threads = dict(prev_threads)
            for thread_ts in sorted(targets):
                event = self._thread_event(cid, thread_ts, view)
                if event.removed:
                    events.append(event)
                    threads.pop(thread_ts, None)
                    continue
                # L1 guard: skip an unchanged replay outright; advance a
                # changed-but-not-newer stamp past the delivered one (the
                # detecting row's ts is the honest event-time candidate).
                entry = self._stamp_monotonic(
                    event, threads.get(thread_ts), _ts_iso(targets[thread_ts])
                )
                if entry is None:
                    continue
                events.append(event)
                threads[thread_ts] = entry
            next_channels[cid] = {
                "class": MIRRORED,
                "latest": max_ts if readable else str(latest),
                "threads": threads,
            }
        for cid in sorted(set(channels_state) - set(view.channels)):
            # channel_deleted (or the bot lost sight of it): fail closed —
            # retire every bookkept thread; membership edges are already gone
            # via the snapshot diff.
            prev = channels_state[cid]
            for thread_ts in sorted(prev.get("threads") or {}):
                events.append(self._removed_event(cid, thread_ts))
        next_state = {
            "channels": next_channels,
            "snapshot": _snapshot_to_dict(snapshot),
            "last_reconcile_at": state.get("last_reconcile_at"),
        }
        return events, json.dumps(next_state, sort_keys=True)

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """§5a backfill/reconcile: per mirrored channel, walk the FULL history
        (resumable — ``backfill_progress``/``backfill_partial`` checkpoint the
        per-channel cursor + partial thread bookkeeping so a crashed crawl
        resumes instead of restarting), ingest every live thread, and at
        channel completion diff the crawl against the previous bookkeeping —
        a previously-bookkept thread the crawl no longer sees is a DETECTED
        DELETION (the gap-remainder the poll cannot see) and yields a removal
        marker. Quarantined channels retire prior bookkeeping (G1 transition);
        vanished channels retire theirs. ``backfill_completed_at`` lands only
        after the WHOLE crawl finished — the runner stamps the reconcile SLA
        from it only on a ZERO-FAILURE run."""
        now = self._clock()
        self.backfill_channel_state = {}
        self.backfill_completed_at = None
        self.unreadable_channels = []
        self.join_failures = []
        if self.last_view is None:
            self.prepare()
        view = self.last_view
        assert view is not None
        for cid in sorted(view.channels):
            prior = self.prior_channels.get(cid) or {}
            prior_entries = {
                str(k): _thread_entry(v) for k, v in (prior.get("threads") or {}).items()
            }
            prior_threads = set(prior_entries)
            prior_was_mirrored = prior.get("class") == MIRRORED
            if view.channel_class.get(cid) != MIRRORED:
                if prior_was_mirrored:
                    for thread_ts in sorted(prior_threads):
                        yield self._quarantine_event(cid, thread_ts)
                self.backfill_channel_state[cid] = {"class": QUARANTINED}
                self.backfill_progress[cid] = "done"
                continue
            if self.backfill_progress.get(cid) == "done":
                continue  # a resumed run already finished (and checkpointed) it
            self._ensure_member(view.channels[cid])
            partial = self.backfill_partial.get(cid) or {}
            threads: dict[str, dict] = {
                str(k): _thread_entry(v) for k, v in (partial.get("threads") or {}).items()
            }
            latest = str(partial.get("latest") or "0")
            cursor = self.backfill_progress.get(cid) or None
            unreadable = False
            while True:
                params: dict[str, Any] = {
                    "channel": cid,
                    "limit": str(self.config.page_size),
                }
                if cursor:
                    params["cursor"] = cursor
                try:
                    page = self._transport.call("conversations.history", params)
                except SlackApiError as exc:
                    if exc.error == "not_in_channel":
                        if cid not in self.unreadable_channels:
                            self.unreadable_channels.append(cid)
                        unreadable = True
                        break
                    raise
                targets: set[str] = set()
                for message in page.get("messages") or []:
                    ts = str(message.get("ts") or "")
                    if ts:
                        latest = _ts_max(latest, ts)
                    target = _target_thread(message)
                    if target:
                        targets.add(target)
                for thread_ts in sorted(targets):
                    if thread_ts in threads:
                        continue  # already ingested (or carried) this crawl
                    event = self._thread_event(cid, thread_ts, view)
                    if event.removed:
                        # A root already gone during the crawl: nothing was
                        # indexed for it this run; the completion diff below
                        # retires it if a PRIOR cycle had indexed it.
                        continue
                    # L1 guard (no detection signal in a full crawl — the
                    # cycle clock is the only advance candidate): a changed
                    # thread whose recomputed stamp did not advance past the
                    # last delivered one still supersedes; an unchanged one
                    # is carried, not re-delivered (no reconcile churn).
                    entry = self._stamp_monotonic(event, prior_entries.get(thread_ts))
                    if entry is None:
                        threads[thread_ts] = prior_entries[thread_ts]
                        continue
                    threads[thread_ts] = entry
                    yield event
                cursor = str(
                    (page.get("response_metadata") or {}).get("next_cursor") or ""
                ).strip()
                self.backfill_partial[cid] = {"latest": latest, "threads": dict(threads)}
                self.backfill_progress[cid] = cursor or "done"
                if not cursor:
                    break
            if unreadable:
                # Leave prior state untouched — an unreadable channel proves
                # nothing about its threads (counted + reported, and the run
                # counts as failed for SLA purposes via the runner).
                self.backfill_progress.pop(cid, None)
                self.backfill_partial.pop(cid, None)
                continue
            if prior_was_mirrored:
                # The reconcile's deletion sweep: bookkept threads the crawl
                # no longer sees are gone from Slack — retire them.
                for thread_ts in sorted(prior_threads - set(threads)):
                    yield self._removed_event(cid, thread_ts)
            self.backfill_channel_state[cid] = {
                "class": MIRRORED,
                "latest": latest,
                "threads": threads,
            }
            self.backfill_partial.pop(cid, None)
        for cid in sorted(set(self.prior_channels) - set(view.channels)):
            prior = self.prior_channels.get(cid) or {}
            for thread_ts in sorted(prior.get("threads") or {}):
                yield self._removed_event(cid, thread_ts)
        self.backfill_completed_at = _iso(now)


def _target_thread(message: Mapping[str, Any]) -> str:
    """Which thread root a history row points at. Signal subtypes
    (``message_changed``/``message_deleted``) carry the affected message
    nested under ``message``/``previous_message`` — re-target ITS thread;
    ordinary rows target their own (``thread_ts`` when a reply broadcast,
    else the row itself as a thread of one)."""
    if message.get("subtype") in _SIGNAL_SUBTYPES:
        inner = message.get("message") or message.get("previous_message") or {}
        return str(inner.get("thread_ts") or inner.get("ts") or message.get("ts") or "")
    return str(message.get("thread_ts") or message.get("ts") or "")


def render_transcript(
    messages: Sequence[Mapping[str, Any]], display_names: Mapping[str, str]
) -> str:
    """Chronological plain-text transcript: ``[iso-ts] name: text`` per
    message. Display names are RENDERING ONLY (G2) — a bot row renders under
    its ``username``/bot id, an unknown uid renders as the raw id; nothing
    here is ever an identity key or a visibility input."""
    lines: list[str] = []
    for message in sorted(messages, key=lambda m: float(m.get("ts") or 0)):
        uid = str(message.get("user") or "")
        who = (
            display_names.get(uid)
            or str(message.get("username") or "")
            or uid
            or str(message.get("bot_id") or "")
            or "unknown"
        )
        stamp = _ts_iso(str(message.get("ts") or "0"))
        lines.append(f"[{stamp}] {who}: {message.get('text') or ''}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Status sink: documents + retire + alarms[] heartbeat (sharepoint's pattern)
# ---------------------------------------------------------------------------


class SlackStatusSink(VerityDocumentSink):
    """gdrive's :class:`VerityDocumentSink` + the fail-closed ``alarms[]``
    heartbeat + the ``POST /v1/admin/retire`` transport (sharepoint's
    pattern, verbatim): the runner queues alarms via :meth:`record_alarm`
    (``parked_retraction`` / ``reconcile_overdue``) and they ride the
    best-effort ``POST /v1/admin/connector-status`` body. An alarm-bearing
    heartbeat fires even when ZERO documents were delivered, and IDLE cycles
    beat too (``items_synced: 0``) — the server's per-source freshness gate
    fences a silent connector. Never raises; drains accumulators in
    ``finally``."""

    #: Idle-cycle heartbeat source (base-class fallback; the alarm path below
    #: keeps its explicit ``SOURCE_NAME``).
    default_source = SOURCE_NAME

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._alarms: list[dict[str, str]] = []

    def record_alarm(self, kind: str, detail: str) -> None:
        """Queue one fail-closed alarm for the next heartbeat. ``kind`` is a
        stable machine tag; ``detail`` is a human string (never a secret)."""
        self._alarms.append({"kind": kind, "detail": detail})

    def retire(self, request: Mapping[str, Any]) -> None:
        """Replay one parked retraction as ``POST /v1/admin/retire`` (G4):
        the server closes the document's current chunks (``valid_to`` +
        blanked visibility). Same client + admin bearer as :meth:`deliver`.
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
# ordering; slack entries carry {channel_id, thread_ts, document_id, reason})
# ---------------------------------------------------------------------------


def _ledger_path(state_file: Path) -> Path:
    """The parked-retractions ledger lives NEXT TO the cursor state so the two
    travel together (same .verity/ dir, same backup/rotation story)."""
    return state_file.with_name("slack_parked_retractions.json")


def _parked_entry(event: SlackDocumentEvent, body: Mapping[str, Any]) -> dict[str, str]:
    return {
        "channel_id": event.channel_id,
        "thread_ts": event.thread_ts,
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
    ``document_id`` (a permanently-quarantined thread that resurfaces every
    cycle updates ``last_seen``/``reason``, it does not grow the file).
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
    source, document_id, reason}`` (G4 enforcement — the server closes the
    document's chunks). Any 2xx removes the entry; ANY failure — transport,
    auth, a sink bug — keeps it parked for the next cycle (the ledger is the
    ONLY carrier once the poll mark has advanced). Sinks without a ``retire``
    transport (dry-run, capture-only fixtures) drain nothing: everything
    stays parked + alarmed, never silently dropped. Returns
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
    sink: DocumentSink, connector: SlackConnector, last_reconcile_at: Any
) -> None:
    """Queue the ``reconcile_overdue`` alarm when the SLA is unmet — EVERY
    cycle, so a stalled reconcile can never fade from the operator's view.
    Alarmed, not enforced: membership diffs keep ACCESS fresh regardless; the
    SLA bounds content-deletion lag (module docstring, honest remainders)."""
    sla = connector.config.reconcile_sla_hours
    if not _reconcile_overdue(last_reconcile_at, connector._clock(), sla):
        return
    record_alarm = getattr(sink, "record_alarm", None)
    if callable(record_alarm):
        record_alarm(
            "reconcile_overdue",
            f"no zero-failure --backfill reconcile within {sla}h "
            f"(last_reconcile_at={last_reconcile_at!r}) — deletions and quiet thread "
            "replies the incremental poll cannot see are unbounded until one runs",
        )


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.slack --once|--backfill
# ---------------------------------------------------------------------------


def _load_cursor(state_file: Path) -> str | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text()).get("cursor")


def _save_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"cursor": cursor}, indent=2) + "\n")


def _print_skips(connector: SlackConnector) -> None:
    if connector.skipped_im:
        print(
            f"slack: skipped {connector.skipped_im} im/mpim conversation(s) — DMs are "
            "out of scope by design (G1)"
        )
    if connector.join_failures:
        print(
            f"slack: could not self-join {len(connector.join_failures)} public "
            f"channel(s): {', '.join(connector.join_failures)}"
        )
    if connector.unreadable_channels:
        print(
            f"slack: {len(connector.unreadable_channels)} channel(s) unreadable "
            f"(not_in_channel): {', '.join(connector.unreadable_channels)} — invite the "
            "bot (or let channels:join succeed) so their history can be mirrored"
        )


def run_once(
    connector: SlackConnector,
    registry: SlackRegistry,
    sink: DocumentSink,
    admin_sink: AdminSink,
    state_file: Path,
    *,
    persist: bool = True,
) -> int:
    """One poll cycle: poll, apply identity/membership admin ops (ACLs before
    content — G3), deliver documents, checkpoint, drain.

    Retraction bodies the ingest ladder cannot deliver — removal markers and
    quarantined bodies — are PARKED in the retraction ledger, then the whole
    ledger is DRAINED as ``POST /v1/admin/retire`` replays; entries whose
    replay fails stay parked + alarmed, never silently dropped. ORDER is
    load-bearing (the over-retire race, sharepoint's exact guards): the
    PRE-EXISTING ledger drains BEFORE this cycle's deliveries, and a
    successful delivery UNPARKS any older entry for its document_id. The poll
    mark still advances (holding it back would livelock on permanently-
    quarantined channels — the ledger, not the cursor, carries the signal).
    A failed admin op raises BEFORE any content delivers and before the
    checkpoint (at-least-once: the cycle replays; every op is idempotent).

    ``persist=False`` (a DRY RUN) skips the checkpoint: a dry run delivers
    nothing, so it must NOT advance the snapshot/marks — otherwise the next
    REAL cycle diffs against a state that was never applied and silently
    no-ops the real work (gdirectory's lesson)."""
    connector.weld_registry = registry  # the G2 weld gate's existence check
    cursor = _load_cursor(state_file)
    previous_snapshot = _snapshot_from_dict(_parse_cursor(cursor).get("snapshot"))
    events, next_cursor = asyncio.run(connector.poll(cursor))
    assert connector.last_snapshot is not None
    ops = build_slack_admin_ops(
        previous_snapshot, connector.last_snapshot, connector.config.tenant_id
    )
    for op in ops:
        admin_sink.apply(op)
    # THE RACE, guard #1: drain the PRE-EXISTING ledger BEFORE delivering.
    _, pre_drained = _drain_parked_retractions(state_file, sink, connector.config.tenant_id)
    delivered = 0
    delivered_ids: set[str] = set()
    parked: list[dict[str, str]] = []
    for event in events:
        assert isinstance(event, SlackDocumentEvent)
        body = build_slack_document_request(event, registry, connector.config.tenant_id)
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
            f"slack: parked {len(parked)} retraction signal(s) this cycle; "
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


def _backfill_checkpoint(
    state_file: Path,
    connector: SlackConnector,
    desired: DirectorySnapshot,
    prior_channels: Mapping[str, dict],
    last_reconcile_at: Any,
) -> str:
    """Mid-crawl checkpoint: completed channels' fresh state over the prior
    map, plus the resumable per-channel cursors + partial bookkeeping. Safe
    at-least-once: re-delivering a thread is a keyed upsert; losing the tail
    since the last checkpoint only re-crawls it."""
    cursor = json.dumps(
        {
            "channels": {**dict(prior_channels), **connector.backfill_channel_state},
            "snapshot": _snapshot_to_dict(desired),
            "last_reconcile_at": last_reconcile_at,
            "backfill": {
                "channels": dict(connector.backfill_progress),
                "partial": dict(connector.backfill_partial),
            },
        },
        sort_keys=True,
    )
    _save_cursor(state_file, cursor)
    return cursor


def run_backfill(
    connector: SlackConnector,
    registry: SlackRegistry,
    sink: DocumentSink,
    admin_sink: AdminSink,
    state_file: Path,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 20,
    persist: bool = True,
) -> int:
    """§5a backfill/reconcile: apply the cycle's admin ops (identity +
    membership FIRST), then drive :meth:`SlackConnector.full_crawl` into the
    sink with resumable per-channel cursors (checkpointed every
    ``flush_every`` deliveries), then stamp ``last_reconcile_at`` — ONLY
    after a COMPLETE crawl with ZERO ingest failures and ZERO unreadable
    channels (a partial crawl re-proved nothing; the prior stamp — possibly
    none — is carried unchanged and ``backfill_incomplete`` is alarmed).
    Same over-retire-race ordering as :func:`run_once` (sharepoint's exact
    guards): pre-existing ledger drains BEFORE the crawl delivers, a
    successful delivery unparks any older entry for its document_id — and
    the unpark is persisted INCREMENTALLY, with every checkpoint (not only
    at crawl end): a checkpoint that records a delivery while the stale park
    entry survives would otherwise hand the NEXT run's guard-#1 pre-drain a
    retraction for a document the resumed crawl will skip re-delivering
    (over-hidden until the next full backfill)."""
    connector.weld_registry = registry  # the G2 weld gate's existence check
    state = _parse_cursor(_load_cursor(state_file))
    prior_channels: dict[str, dict] = {
        cid: dict(entry)
        for cid, entry in (state.get("channels") or {}).items()
        if isinstance(entry, dict)
    }
    prior_reconcile = state.get("last_reconcile_at")
    connector.prior_channels = prior_channels
    resume = state.get("backfill") or {}
    connector.backfill_progress = {
        str(k): str(v) for k, v in (resume.get("channels") or {}).items()
    }
    connector.backfill_partial = {
        str(k): dict(v) for k, v in (resume.get("partial") or {}).items() if isinstance(v, dict)
    }
    previous_snapshot = _snapshot_from_dict(state.get("snapshot"))
    desired = connector.prepare()
    ops = build_slack_admin_ops(previous_snapshot, desired, connector.config.tenant_id)
    for op in ops:
        admin_sink.apply(op)
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

    async def _drive() -> None:
        nonlocal delivered, pending, failed
        async for event in connector.full_crawl():
            assert isinstance(event, SlackDocumentEvent)
            body = build_slack_document_request(event, registry, connector.config.tenant_id)
            if not _is_indexable_body(body):
                parked.append(_parked_entry(event, body))
                delivered_ids.discard(event.document_id)  # in-stream, the park is newer
                continue
            try:
                sink.deliver(body)
            except httpx.HTTPError:
                failed += 1  # one bad thread never aborts a whole-workspace backfill
                continue
            delivered += 1
            delivered_ids.add(event.document_id)
            parked[:] = [p for p in parked if p["document_id"] != event.document_id]
            pending += 1
            if pending >= flush_every:
                if reporter is not None:
                    reporter.advance(pending)
                pending = 0
                if persist:
                    # C2: the unpark rides EVERY checkpoint, unpark FIRST — a
                    # crash between the two re-crawls the tail (safe); the
                    # reverse order would checkpoint a delivery whose stale
                    # park entry survives for the next run's pre-drain.
                    _unpark_delivered(state_file, delivered_ids)
                    _backfill_checkpoint(
                        state_file, connector, desired, prior_channels, prior_reconcile
                    )

    try:
        asyncio.run(_drive())
    except Exception as exc:  # noqa: BLE001 — surface as a failed run, then re-raise
        # The resumable cursors are already checkpointed (every flush_every);
        # a re-run resumes instead of restarting. Unpark WITH the checkpoint
        # (C2): the crash checkpoint records deliveries the resume will skip.
        if persist:
            _unpark_delivered(state_file, delivered_ids)
            _backfill_checkpoint(state_file, connector, desired, prior_channels, prior_reconcile)
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
    total_parked, drained = _drain_parked_retractions(
        state_file, sink, connector.config.tenant_id
    )
    drained += pre_drained
    if parked or drained or failed:
        print(
            f"slack: parked {len(parked)} retraction signal(s); "
            f"drained {drained} via POST {RETIRE_PATH} "
            f"({total_parked} still parked -> {ledger_path}), "
            f"{failed} ingest failure(s)"
        )
    _print_skips(connector)
    record_alarm = getattr(sink, "record_alarm", None)
    saved_cursor: str | None = None
    if connector.backfill_completed_at:
        clean = failed == 0 and not connector.unreadable_channels
        if clean:
            stamp: Any = connector.backfill_completed_at
        else:
            # A crawl with failures (or unreadable channels) did NOT re-prove
            # the index — carry the prior stamp (possibly none: the SLA alarm
            # then keeps firing, fail closed).
            stamp = prior_reconcile
            if callable(record_alarm):
                record_alarm(
                    "backfill_incomplete",
                    f"{failed} ingest failure(s), "
                    f"{len(connector.unreadable_channels)} unreadable channel(s); "
                    "last_reconcile_at NOT stamped — the reconcile SLA stays unmet "
                    "until a zero-failure backfill completes",
                )
        final_channels = {**prior_channels, **connector.backfill_channel_state}
        for cid in set(prior_channels) - set(
            connector.last_view.channels if connector.last_view else {}
        ):
            final_channels.pop(cid, None)  # vanished channels: retired above
        saved_cursor = json.dumps(
            {
                "channels": final_channels,
                "snapshot": _snapshot_to_dict(desired),
                "last_reconcile_at": stamp,
            },
            sort_keys=True,
        )
        if persist:
            _save_cursor(state_file, saved_cursor)
    _alarm_parked(sink, total_parked, ledger_path)
    _alarm_reconcile_overdue(
        sink, connector, _parse_cursor(saved_cursor).get("last_reconcile_at")
    )
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=saved_cursor)
    return delivered


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.slack",
        description="Verity Slack connector (thread-as-document, channel-membership "
        "mirrored visibility, fail-closed).",
    )
    parser.add_argument("--once", action="store_true", help="run a single poll cycle and exit")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the full per-channel reconcile crawl (stamps the reconcile SLA), then exit",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print request bodies instead of POSTing"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("SLACK_STATE_FILE", ".verity/slack_cursor.json")),
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url", default=os.environ.get("VERITY_URL", "http://localhost:8080")
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=f"path to the verity-cli config.toml holding [connectors.slack] "
        f"(default {DEFAULT_CONFIG_PATH}; SLACK_BOT_TOKEN overrides)",
    )
    parser.add_argument(
        "--principal-map",
        type=Path,
        default=None,
        help="JSON file {principal: int token} -> StaticSlackRegistry (fixtures/dev)",
    )
    parser.add_argument(
        "--reconcile-sla-hours",
        type=int,
        default=int(os.environ.get("SLACK_RECONCILE_SLA_HOURS", "24")),
    )
    parser.add_argument(
        "--no-join",
        action="store_true",
        help="never self-join public channels (mirror only what the bot is already in)",
    )
    parser.add_argument(
        "--interval", type=float, default=300.0, help="poll interval in seconds (without --once)"
    )
    args = parser.parse_args(argv)

    bot_token, app_token = load_slack_credentials(args.config)
    config = SlackConfig(
        tenant_id=args.tenant_id,
        bot_token=bot_token,
        app_token=app_token,  # reserved: Socket-Mode lane (module docstring)
        join_public_channels=not args.no_join,
        reconcile_sla_hours=args.reconcile_sla_hours,
    )
    connector = SlackConnector(HttpSlackTransport(bot_token), config)

    api_key = os.environ.get("VERITY_API_KEY")
    registry: SlackRegistry
    if args.principal_map:
        registry = StaticSlackRegistry(json.loads(args.principal_map.read_text()))
    else:
        registry = HttpSlackRegistry(args.verity_url, tenant_id=config.tenant_id, api_key=api_key)
    sink: DocumentSink
    admin_sink: AdminSink
    if args.dry_run:
        sink = DryRunSink()
        admin_sink = DryRunAdminSink()
    else:
        status_sink = SlackStatusSink(args.verity_url, api_key=api_key)
        # Alarm-only / idle heartbeats still need a tenant to key their row.
        status_sink.alarm_tenant_id = config.tenant_id
        sink = status_sink
        admin_sink = VerityAdminSink(args.verity_url, api_key=api_key)

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
            connector,
            registry,
            sink,
            admin_sink,
            args.state_file,
            reporter,
            persist=not args.dry_run,
        )
        print(f"slack: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(
            connector, registry, sink, admin_sink, args.state_file, persist=not args.dry_run
        )
        dest = "(dry-run, state unchanged)" if args.dry_run else f"cursor -> {args.state_file}"
        print(f"slack: delivered {delivered} request(s); {dest}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
