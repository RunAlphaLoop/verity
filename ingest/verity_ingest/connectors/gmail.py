"""Gmail inbox connector — a Tier-A ACL-mirroring proof over email (SPEC.md §5, §5e.2).

Auth (BYOT doctrine, §5e.2, identical to gdrive/gdirectory): the customer's
*own* service account with domain-wide delegation, configured in their admin
console. The key file path comes from ``GOOGLE_APPLICATION_CREDENTIALS``; no
vendor OAuth app, ever (§5e.8 refusal #1). We speak plain Gmail v1 REST over
httpx; google-auth is used only to mint/refresh the service-account token
(lazy import, so fixture tests never need it). Unlike Drive, the delegated
subject is REQUIRED: Gmail is per-mailbox, so we impersonate a specific
workspace user (``--subject`` / ``GMAIL_DELEGATED_SUBJECT``) and read exactly
*that* user's mailbox as ``users/me``. Scope: ``gmail.readonly``.

Two load-bearing design decisions make the same email — which physically
exists as a separate Gmail message in every participant's mailbox (the
sender's Sent copy, each recipient's Inbox copy) — resolve to ONE Verity
memory when several of those mailboxes are crawled into the same tenant:

1. DEDUP KEY = the RFC822 ``Message-ID`` header, NOT Gmail's per-mailbox API
   id. The server's chunk store dedupes on ``(tenant_id, source, document_id,
   seq, valid_from)`` with ``ON CONFLICT DO NOTHING``. So the body posts with
   ``document_id`` = the ``Message-ID`` (angle brackets stripped). The Gmail
   message ``id`` differs per mailbox and would DOUBLE-INDEX the identical
   email; the ``Message-ID`` is stable across every copy. A message with no
   ``Message-ID`` header (rare — drafts, some automated senders) falls back to
   ``gmail-thread:<threadId>:<internalDate>``; that copy is only self-dedup'd,
   which we note rather than hide.

2. ACL = MIRROR PARTICIPANTS. The visibility set is intrinsic to the email:
   its participants ``From + To + Cc`` (addresses parsed out of those
   headers), each mapped to ``user:<email>`` (lowercased, canonical) and
   resolved to int visibility tokens via the server's principal registry
   (``POST /v1/admin/principals``, EXACTLY like gdrive's ``HttpRegistry``).
   ``acl_provenance = "mirrored"``. Because the audience is identical from any
   mailbox, first-crawler-wins under ``ON CONFLICT DO NOTHING`` is
   visibility-correct — the dedup can never pick the "wrong" ACL. If ZERO
   participants resolve to tokens the body quarantines (no ``visibility``
   field), the same fail-closed ladder as gdrive's ``build_document_request``.
   The participants are also emitted as ``entities`` (``user:<email>``) so the
   email links to the people (Verity resolves people by email, Tier-1, from
   the structured From/To/Cc).

Content lanes:

- BODY → the ``text/plain`` MIME part (or a minimal tag-strip of ``text/html``
  when only HTML exists), with the Subject prepended, delivered inline as
  ``content`` text. ``document_id`` = the ``Message-ID`` (decision #1).
- EACH ATTACHMENT → its OWN document. ``document_id`` =
  ``"<Message-ID>#att:<attachmentId-or-index>"`` (still Message-ID-derived, so
  attachments dedupe the same way), ``content_base64`` = the raw bytes, and
  ``filename`` = the attachment name. Gmail returns attachment bytes as
  URL-safe base64; we DECODE url-safe and let ``build_document_request``
  RE-ENCODE standard for the endpoint. The SERVER runs Tier-1 extraction
  (PDF/PPTX/XLS(X)/DOCX/DOC/text); images/scanned/unknown land metadata-only
  server-side. Attachments carry the SAME participant visibility + entities as
  their parent email. Oversized attachments (> ``MAX_ATTACHMENT_BYTES``, inline
  images and the like) are skipped-and-counted, never fetched.

Crawl lanes (mirroring gdrive):

- ``full_crawl`` (``--backfill``) → ``users.messages.list`` with a query
  (default ``newer_than:30d``, a ``--query`` / ``--newer-than`` flag), paging
  through and emitting body + attachment events per message. Progress is
  reported to the §5a backfill dashboard (``BackfillReporter``) plus the
  connector-status heartbeat as source ``gmail``.
- ``poll`` (``--once`` / interval) → ``users.history.list`` from a
  ``historyId`` cursor (the analogue of Drive's ``changes.list`` pageToken).
  First run (cursor ``None``) reads ``users.getProfile`` for the starting
  ``historyId`` and emits nothing — history before the cursor is
  ``full_crawl``'s job (backfill protocol, §5a). New messages
  (``messageAdded``) emit the same body + attachment events.

RESILIENCE (the gdrive/consolidation lesson — a bad episode must not crash the
crawl): every per-message ``messages.get`` + parse and every per-attachment
fetch is wrapped in try/except. On any httpx/parse error we skip-and-count-and-
log and continue; a message whose ACL can't resolve quarantines its body
rather than crashing. ``delivered``/``skipped`` are reported at the end.

Server contracts coded against are gdrive's verbatim (this connector imports
``HttpRegistry`` / ``VerityDocumentSink`` / ``DryRunSink`` / the fail-closed
``_is_indexable_body`` from :mod:`verity_ingest.connectors.gdrive` — one sink,
one visibility/entity mapping):

- ``POST /v1/admin/principals``  ``{"tenant_id", "principals": [...]}`` →
  ``{"mappings": {"user:a@x": 101, ...}}`` (null/absent/non-int → unresolved,
  fail-closed).
- ``POST /v1/ingest/documents``  body::

      {
        "tenant_id":      "<tenant>",
        "source":         "gmail",
        "document_id":    "<Message-ID>" | "<Message-ID>#att:<id>",
        "content":        "<subject + body text>" | null,   # body lane
        "content_base64": "<standard base64 bytes>",         # attachment lane
        "filename":       "<attachment filename>",           # attachment lane
        "entities":       ["user:<email>", ...],
        "visibility":     [<int token>, ...],                # only when mirrored
        "acl_provenance": "mirrored" | "quarantined",
        "valid_from":     "<RFC 3339 Date header>"
      }

  ``valid_from`` is the email's ``Date`` header (parsed to RFC 3339), NEVER the
  crawl time. Quarantined items carry NO ``visibility`` field.

Runner: ``python -m verity_ingest.connectors.gmail --once [--dry-run]`` (or
``--backfill``) with a JSON ``historyId`` cursor state file. ``--dry-run``
prints the would-be request bodies instead of POSTing.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import email.utils
import html as html_module
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator, Mapping, Sequence

import httpx

from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

# Reuse gdrive's server-contract shapes verbatim — one sink, one registry, one
# fail-closed indexability gate. Importing (rather than re-declaring) keeps the
# gmail and gdrive request bodies provably identical where they must be.
from verity_ingest.connectors.gdrive import (
    CONNECTOR_STATUS_PATH,
    DOCUMENTS_PATH,
    PRINCIPALS_PATH,
    DocumentSink,
    DryRunSink,
    HttpRegistry,
    PrincipalRegistry,
    StaticRegistry,
    VerityDocumentSink,
    _HttpxAuthRequest,
    _is_indexable_body,
    load_service_account_credentials,
)

__all__ = [
    "CONNECTOR_STATUS_PATH",
    "DOCUMENTS_PATH",
    "PRINCIPALS_PATH",
    "DocumentSink",
    "DryRunSink",
    "GmailConfig",
    "GmailConnector",
    "GmailDocumentEvent",
    "HttpGmailTransport",
    "HttpRegistry",
    "PrincipalRegistry",
    "StaticRegistry",
    "VerityDocumentSink",
    "build_document_request",
    "extract_body",
    "map_participants",
    "message_document_id",
    "parse_valid_from",
    "run_backfill",
    "run_once",
]

# users/me resolves to the impersonated (delegated) subject under DWD, so the
# mailbox owner is baked into the base URL and every path is mailbox-relative.
GMAIL_BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

SOURCE_NAME = "gmail"

# Inline images and huge attachments are skipped-and-counted, not fetched: a
# 25 MiB cap keeps one fat attachment from stalling the crawl. Server-side
# Tier-1 extraction is text-only anyway, so nothing indexable is lost.
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

# The participant headers whose addresses form the mirrored visibility set.
_PARTICIPANT_HEADERS = ("From", "To", "Cc")

_HTML_BLOCK_RE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")  # collapse runs of any whitespace, incl. &nbsp; (\xa0)


# ---------------------------------------------------------------------------
# Config & events
# ---------------------------------------------------------------------------


@dataclass
class GmailConfig:
    """Connector configuration. No default widens visibility (§5e.8 #9)."""

    tenant_id: str = "default"
    # Domain-wide delegation subject — REQUIRED for live runs: Gmail is
    # per-mailbox, so we must impersonate the mailbox owner to read it.
    delegated_subject: str | None = None
    # The backfill query. Defaults to a 30-day window (the cold-start lane);
    # `--query` / `--newer-than` on the CLI override it.
    query: str = "newer_than:30d"
    page_size: int = 100


@dataclass
class GmailDocumentEvent(DocumentEvent):
    """DocumentEvent + the email's Date (as ``valid_from``), an attachment
    filename, and an attachment marker.

    ``valid_from`` is the parsed ``Date`` header (RFC 3339), NOT the crawl
    time — it is what the chunk store keys on. ``is_attachment`` routes the
    event to the binary (``content_base64``) lane; body events ride the text
    (``content``) lane. ``filename`` rides along as the server's Tier-1
    detection hint for attachments.
    """

    valid_from: str = ""
    filename: str = ""
    is_attachment: bool = False


# ---------------------------------------------------------------------------
# Header parsing: participants, Message-ID, Date
# ---------------------------------------------------------------------------


def _header(headers: Iterable[Mapping[str, Any]], name: str) -> str | None:
    """First header value matching ``name`` (case-insensitive), or None."""
    wanted = name.lower()
    for header in headers:
        if (header.get("name") or "").lower() == wanted:
            return header.get("value")
    return None


def map_participants(headers: Iterable[Mapping[str, Any]]) -> AclEnvelope:
    """Mirror the email's participants (From + To + Cc) into an AclEnvelope.

    Every parsed address becomes a ``user:<email>`` principal (lowercased,
    deduped, order-preserving). Fail-closed (§5e.6): a message with ZERO
    parseable participant addresses yields ``resolvable=False`` — its body
    quarantines, never indexed against an empty audience. (A parsed-but-
    unresolvable audience — addresses that map to no token — quarantines one
    level up, in :func:`build_document_request`, exactly like gdrive.)
    """
    headers = list(headers)
    raw_values = [v for name in _PARTICIPANT_HEADERS if (v := _header(headers, name))]
    principals: list[str] = []
    seen: set[str] = set()
    for _display_name, address in email.utils.getaddresses(raw_values):
        address = (address or "").strip().lower()
        if not address or "@" not in address:
            continue
        principal = f"user:{address}"
        if principal not in seen:
            seen.add(principal)
            principals.append(principal)
    if not principals:
        return AclEnvelope(resolvable=False)
    return AclEnvelope(resolvable=True, principals=principals, groups=[])


def message_document_id(
    headers: Iterable[Mapping[str, Any]], thread_id: str, internal_date: str
) -> str:
    """The stable cross-mailbox dedup key (decision #1).

    The RFC822 ``Message-ID`` header with angle brackets stripped — identical
    in every mailbox that holds this email, so all copies collapse to one
    memory. When a message carries no ``Message-ID`` (drafts, some automated
    senders), fall back to ``gmail-thread:<threadId>:<internalDate>``; that
    copy then only self-dedups, which we accept rather than mint a fake id.
    """
    raw = _header(headers, "Message-ID") or _header(headers, "Message-Id")
    if raw:
        stripped = raw.strip().lstrip("<").rstrip(">").strip()
        if stripped:
            return stripped
    return f"gmail-thread:{thread_id}:{internal_date}"


def _to_rfc3339(value: datetime) -> str:
    """Normalize a datetime to a UTC RFC 3339 string (``...Z``)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_valid_from(headers: Iterable[Mapping[str, Any]], internal_date: str) -> str:
    """The email's ``Date`` header as RFC 3339 — the memory's ``valid_from``.

    Falls back to Gmail's ``internalDate`` (epoch millis, the server-receipt
    time) only when the ``Date`` header is missing or unparseable, so a
    malformed header degrades to a real timestamp rather than the crawl time.
    """
    raw = _header(headers, "Date")
    if raw:
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            return _to_rfc3339(parsed)
    if internal_date:
        try:
            millis = int(internal_date)
        except (TypeError, ValueError):
            return ""
        return _to_rfc3339(datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc))
    return ""


# ---------------------------------------------------------------------------
# Body & attachment extraction (MIME tree walk)
# ---------------------------------------------------------------------------


def _b64url_to_bytes(data: str) -> bytes:
    """Decode Gmail's URL-safe, possibly-unpadded base64 to raw bytes."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _collect_text_parts(part: Mapping[str, Any], mime_type: str) -> list[str]:
    """Recursively gather decoded ``mime_type`` body parts (skipping any part
    that is itself an attachment, i.e. carries a filename)."""
    out: list[str] = []
    if part.get("mimeType") == mime_type and not part.get("filename"):
        data = (part.get("body") or {}).get("data")
        if data:
            out.append(_b64url_to_bytes(data).decode("utf-8", errors="replace"))
    for sub in part.get("parts") or []:
        out.extend(_collect_text_parts(sub, mime_type))
    return out


def _strip_html(html: str) -> str:
    """Minimal HTML → text: drop script/style, strip tags, unescape entities."""
    text = _HTML_BLOCK_RE.sub(" ", html)
    text = _HTML_TAG_RE.sub(" ", text)
    text = html_module.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def extract_body(payload: Mapping[str, Any]) -> str:
    """Extract the email body as text: prefer ``text/plain``, else a minimal
    tag-strip of ``text/html``, else empty."""
    plain = _collect_text_parts(payload, "text/plain")
    if plain:
        return "\n".join(plain).strip()
    html_parts = _collect_text_parts(payload, "text/html")
    if html_parts:
        return "\n".join(_strip_html(h) for h in html_parts).strip()
    return ""


def _collect_attachments(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every attachment part (a filename + a fetchable ``attachmentId``), in
    document order, with a stable positional ``index`` for id fallback."""
    out: list[dict[str, Any]] = []

    def walk(part: Mapping[str, Any]) -> None:
        filename = part.get("filename")
        body = part.get("body") or {}
        if filename and body.get("attachmentId"):
            out.append(
                {
                    "filename": filename,
                    "attachmentId": body["attachmentId"],
                    "size": body.get("size"),
                    "mimeType": part.get("mimeType", ""),
                    "index": len(out),
                }
            )
        for sub in part.get("parts") or []:
            walk(sub)

    walk(payload)
    return out


# ---------------------------------------------------------------------------
# Gmail transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class GmailTransport:
    """Minimal surface over Gmail v1 REST, so tests run on recorded fixtures.

    Every Gmail response we consume is JSON — even attachment bytes arrive as
    a base64 ``data`` field — so a single ``get_json`` covers the connector.
    """

    def get_json(self, path: str, params: Mapping[str, str]) -> dict: ...


class HttpGmailTransport:
    """Live Gmail v1 REST transport with service-account bearer auth."""

    def __init__(self, credentials: Any, client: httpx.Client | None = None) -> None:
        self._credentials = credentials
        self._client = client or httpx.Client(base_url=GMAIL_BASE_URL, timeout=60.0)
        self._auth_request = _HttpxAuthRequest()

    def _headers(self) -> dict[str, str]:
        if not self._credentials.valid:
            self._credentials.refresh(self._auth_request)
        return {"Authorization": f"Bearer {self._credentials.token}"}

    def get_json(self, path: str, params: Mapping[str, str]) -> dict:
        response = self._client.get(path, params=dict(params), headers=self._headers())
        response.raise_for_status()
        return response.json()


def load_gmail_credentials(delegated_subject: str | None):
    """BYOT service-account credentials for Gmail (google-auth, lazy).

    The delegated subject is mandatory: Gmail is per-mailbox, so without
    impersonating the mailbox owner there is nothing to read. Failing here is
    clearer than failing on the first request.
    """
    if not delegated_subject:
        raise RuntimeError(
            "GMAIL_DELEGATED_SUBJECT is not set. Gmail is per-mailbox: grant "
            "your service account domain-wide delegation for scope "
            "gmail.readonly and pass the mailbox owner's email via --subject "
            "or GMAIL_DELEGATED_SUBJECT (the user whose inbox to read)."
        )
    return load_service_account_credentials(
        delegated_subject=delegated_subject, scopes=(GMAIL_READONLY_SCOPE,)
    )


# ---------------------------------------------------------------------------
# The connector
# ---------------------------------------------------------------------------


class GmailConnector(Connector):
    name = SOURCE_NAME

    def __init__(self, transport: GmailTransport, config: GmailConfig | None = None) -> None:
        self._transport = transport
        self.config = config or GmailConfig()
        # Per-crawl resilience counter: messages/attachments skipped on a
        # fetch or parse error. Reset at the start of each poll/full_crawl and
        # read by the runners for the end-of-run report.
        self.skipped = 0

    # -- push lane ----------------------------------------------------------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op: the ``users.watch`` push lane needs a public HTTPS endpoint
        and Pub/Sub wiring (SPEC §5); poll is the truth lane and is always
        sufficient. TODO: optional watch lane once the receiver ships."""
        return
        yield  # pragma: no cover - makes this an async generator

    # -- truth lane ---------------------------------------------------------

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """Incremental ``users.history.list`` from `cursor` (a ``historyId``).

        First run (cursor None): read ``users.getProfile`` for the current
        ``historyId`` and return it with no events — history before the cursor
        is ``full_crawl``'s job (backfill protocol, §5a), not the change feed.
        """
        self.skipped = 0
        if cursor is None:
            profile = self._transport.get_json("profile", {})
            return [], str(profile.get("historyId", ""))

        message_ids: list[str] = []
        seen: set[str] = set()
        next_cursor = cursor
        page_token: str | None = None
        while True:
            params: dict[str, str] = {
                "startHistoryId": cursor,
                "historyTypes": "messageAdded",
                "maxResults": str(self.config.page_size),
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._transport.get_json("history", params)
            for record in page.get("history", []):
                for added in record.get("messagesAdded", []):
                    mid = (added.get("message") or {}).get("id")
                    if mid and mid not in seen:
                        seen.add(mid)
                        message_ids.append(mid)
            if page.get("historyId"):
                next_cursor = str(page["historyId"])
            page_token = page.get("nextPageToken")
            if not page_token:
                break

        events: list[FactEvent | DocumentEvent] = []
        for mid in message_ids:
            # One bad message must never abort the poll (the consolidation
            # lesson): skip-and-count-and-log, keep going.
            try:
                events.extend(self._events_for_message(mid))
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                self.skipped += 1
                print(f"gmail: skipped message {mid}: {exc}", file=sys.stderr)
        return events, next_cursor

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """§5a reconciliation backfill: ``users.messages.list`` over the
        configured query window, emitting body + attachment events per
        message. Per-message errors are skipped-and-counted, never fatal."""
        self.skipped = 0
        for message_ref in self._list_messages():
            mid = message_ref.get("id")
            if not mid:
                continue
            try:
                events = self._events_for_message(mid)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                self.skipped += 1
                print(f"gmail: skipped message {mid}: {exc}", file=sys.stderr)
                continue
            for event in events:
                yield event

    # -- per-message plumbing -----------------------------------------------

    def _list_messages(self) -> Iterator[dict]:
        """Page ``users.messages.list`` over the configured query."""
        page_token: str | None = None
        while True:
            params: dict[str, str] = {
                "q": self.config.query,
                "maxResults": str(self.config.page_size),
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._transport.get_json("messages", params)
            yield from page.get("messages", [])
            page_token = page.get("nextPageToken")
            if not page_token:
                return

    def _events_for_message(self, message_id: str) -> list[GmailDocumentEvent]:
        """Fetch one message and build its body + attachment events.

        The ACL, entity tags, ``document_id`` prefix, and ``valid_from`` are
        computed ONCE from the email's headers and shared by the body and
        every attachment — they are intrinsic to the email, identical in any
        mailbox (decisions #1 and #2)."""
        message = self._transport.get_json(f"messages/{message_id}", {"format": "full"})
        payload = message.get("payload") or {}
        headers = payload.get("headers") or []
        thread_id = message.get("threadId", "")
        internal_date = str(message.get("internalDate", ""))

        document_id = message_document_id(headers, thread_id, internal_date)
        acl = map_participants(headers)
        entity_tags = list(acl.principals)  # participants ARE the entity links
        valid_from = parse_valid_from(headers, internal_date)

        subject = _header(headers, "Subject") or ""
        body_text = extract_body(payload)
        content = f"Subject: {subject}\n\n{body_text}" if subject else body_text

        events: list[GmailDocumentEvent] = [
            GmailDocumentEvent(
                source=self.name,
                document_id=document_id,
                content=content.encode("utf-8"),
                mime_type="text/plain",
                version=internal_date,
                acl=acl,
                entity_tags=entity_tags,
                valid_from=valid_from,
            )
        ]

        for attachment in _collect_attachments(payload):
            # One bad attachment must never sink the whole email: the body is
            # already queued above, so a fetch failure here just skips-and-
            # counts and moves on.
            try:
                raw = self._fetch_attachment(message_id, attachment)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                self.skipped += 1
                print(
                    f"gmail: skipped attachment {attachment.get('filename')!r} "
                    f"on {message_id}: {exc}",
                    file=sys.stderr,
                )
                continue
            if raw is None:
                continue
            attachment_id = attachment.get("attachmentId") or f"idx{attachment['index']}"
            events.append(
                GmailDocumentEvent(
                    source=self.name,
                    # Message-ID-derived, so attachments dedupe cross-mailbox
                    # exactly like their parent body (decision #1).
                    document_id=f"{document_id}#att:{attachment_id}",
                    content=raw,
                    mime_type=attachment.get("mimeType", ""),
                    version=internal_date,
                    acl=acl,
                    entity_tags=entity_tags,
                    valid_from=valid_from,
                    filename=attachment.get("filename", ""),
                    is_attachment=True,
                )
            )
        return events

    def _fetch_attachment(self, message_id: str, attachment: Mapping[str, Any]) -> bytes | None:
        """Fetch one attachment's raw bytes, or None to skip it.

        Oversized attachments (and inline images that trip the cap) are
        skipped-and-counted rather than fetched. Gmail returns URL-safe
        base64; we decode it to raw bytes here — ``build_document_request``
        re-encodes standard base64 for the endpoint."""
        size = attachment.get("size")
        if isinstance(size, int) and size > MAX_ATTACHMENT_BYTES:
            self.skipped += 1
            print(
                f"gmail: skipped oversized attachment "
                f"{attachment.get('filename')!r} ({size} bytes) on {message_id}",
                file=sys.stderr,
            )
            return None
        response = self._transport.get_json(
            f"messages/{message_id}/attachments/{attachment['attachmentId']}", {}
        )
        data = response.get("data")
        if not data:
            # Empty payload is nothing indexable, but count-and-log it rather
            # than dropping it silently — the connector's ethos is to account
            # for every item it declines to deliver.
            self.skipped += 1
            print(
                f"gmail: skipped empty attachment "
                f"{attachment.get('filename')!r} on {message_id}",
                file=sys.stderr,
            )
            return None
        return _b64url_to_bytes(data)


# ---------------------------------------------------------------------------
# Sink request builder: POST /v1/ingest/documents (gdrive's contract)
# ---------------------------------------------------------------------------


def build_document_request(
    event: GmailDocumentEvent, registry: PrincipalRegistry, tenant_id: str
) -> dict:
    """Build the /v1/ingest/documents body for one gmail event.

    Fail-closed ladder, identical to gdrive's:
    - attachment → raw bytes RE-ENCODED to standard base64 in
      ``content_base64`` (+ ``filename``); body → decoded ``content`` text;
    - unresolvable envelope (no parseable participants) → quarantine, and the
      text ``content`` is suppressed to None (never leak an un-scoped body);
    - resolvable but zero participants resolve to tokens → quarantine (§6b:
      unmappable principals confer nothing; all-unmappable → quarantine);
    - otherwise → mirrored body with int visibility tokens.
    """
    body: dict[str, Any] = {
        "tenant_id": tenant_id,
        "source": event.source,
        "document_id": event.document_id,
        "entities": list(event.entity_tags),
        "valid_from": event.valid_from,
    }
    if event.is_attachment:
        # Binary lane: DECODE-then-RE-ENCODE means the endpoint always sees
        # standard base64 even though Gmail handed us URL-safe. Mutually
        # exclusive with "content"; filename is the server's detection hint.
        body["content_base64"] = base64.b64encode(event.content).decode("ascii")
        if event.filename:
            body["filename"] = event.filename
    else:
        body["content"] = (
            event.content.decode("utf-8", errors="replace") if event.acl.resolvable else None
        )
    if not event.acl.resolvable:
        body["acl_provenance"] = "quarantined"
        return body

    ordered: list[str] = []
    for principal in [*event.acl.principals, *event.acl.groups]:
        if principal not in ordered:
            ordered.append(principal)
    tokens = registry.resolve(ordered)
    visibility = [tokens[p] for p in ordered if p in tokens]
    if not visibility:
        body["acl_provenance"] = "quarantined"
        return body

    body["visibility"] = visibility
    body["acl_provenance"] = "mirrored"
    return body


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.gmail --once [--dry-run]
# ---------------------------------------------------------------------------


def _load_cursor(state_file: Path) -> str | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text()).get("cursor")


def _save_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"cursor": cursor}, indent=2) + "\n")


def run_once(
    connector: GmailConnector,
    registry: PrincipalRegistry,
    sink: DocumentSink,
    state_file: Path,
) -> int:
    """One poll cycle: load cursor, poll, deliver, checkpoint. Returns the
    number of delivered requests. The cursor is checkpointed only after
    delivery, so a crash replays the window (at-least-once)."""
    cursor = _load_cursor(state_file)
    events, next_cursor = asyncio.run(connector.poll(cursor))
    delivered = 0
    skipped = 0
    for event in events:
        assert isinstance(event, GmailDocumentEvent)
        body = build_document_request(event, registry, connector.config.tenant_id)
        # A quarantined body (no participant resolved) is not accepted by the
        # documents endpoint — skip-and-count fail-closed, never index it.
        if not _is_indexable_body(body):
            skipped += 1
            continue
        sink.deliver(body)
        delivered += 1
    skipped += connector.skipped
    if skipped:
        print(f"gmail: skipped {skipped} item(s) (unresolvable ACL, oversized, or fetch error)")
    _save_cursor(state_file, next_cursor)
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=next_cursor)
    return delivered


def run_backfill(
    connector: GmailConnector,
    registry: PrincipalRegistry,
    sink: DocumentSink,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 20,
) -> int:
    """§5a reconciliation backfill: drive :meth:`GmailConnector.full_crawl`
    (``messages.list`` over the query window) into the sink, reporting
    progress to the backfill dashboard.

    ``messages.list`` gives no cheap up-front count, so the run opens with an
    indeterminate total (``total=None``) and a live processed count. A crash
    mid-crawl reports a ``failed`` run and re-raises; a clean finish marks it
    ``completed``. Returns the number of delivered requests."""
    if reporter is not None:
        reporter.start(total=None)
    delivered = 0
    pending = 0
    quarantined = 0
    failed = 0

    async def _drive() -> None:
        nonlocal delivered, pending, quarantined, failed
        async for event in connector.full_crawl():
            assert isinstance(event, GmailDocumentEvent)
            body = build_document_request(event, registry, connector.config.tenant_id)
            # Fail-closed skip: a body whose participants resolve to nothing is
            # not accepted by the index endpoint — counted, not fatal.
            if not _is_indexable_body(body):
                quarantined += 1
                continue
            # One document's ingest failure never aborts the backfill: record
            # and press on (the same skip-and-count as gdrive's).
            try:
                sink.deliver(body)
            except httpx.HTTPError:
                failed += 1
                continue
            delivered += 1
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
    if quarantined or failed or connector.skipped:
        print(
            f"gmail: quarantined {quarantined} (unresolvable ACL), skipped "
            f"{connector.skipped} message/attachment(s) (fetch/parse error or "
            f"oversized), {failed} ingest failure(s)"
        )
    return delivered


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.gmail",
        description="Verity Gmail connector (truth lane, Tier-A ACL mirroring).",
    )
    parser.add_argument("--once", action="store_true", help="run a single poll cycle and exit")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the §5a backfill (messages.list over the query window) once, "
        "reporting progress to the backfill dashboard, then exit",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print request bodies instead of POSTing"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("GMAIL_STATE_FILE", ".verity/gmail_cursor.json")),
        help="JSON historyId cursor checkpoint file",
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url",
        default=os.environ.get("VERITY_URL", "http://localhost:7717"),
        help="Verity server base URL (sink + principal resolution)",
    )
    parser.add_argument(
        "--principal-map",
        type=Path,
        default=None,
        help="JSON file {principal: int token} -> StaticRegistry instead of the server endpoint",
    )
    parser.add_argument(
        "--subject",
        default=os.environ.get("GMAIL_DELEGATED_SUBJECT"),
        help="domain-wide-delegation subject — REQUIRED: the mailbox owner to "
        "impersonate and read",
    )
    parser.add_argument(
        "--query",
        default=os.environ.get("GMAIL_QUERY"),
        help="full Gmail search query for the backfill (overrides --newer-than)",
    )
    parser.add_argument(
        "--newer-than",
        default=os.environ.get("GMAIL_NEWER_THAN", "30d"),
        help='backfill window as a Gmail "newer_than" span (default 30d)',
    )
    parser.add_argument(
        "--interval", type=float, default=300.0, help="poll interval in seconds (without --once)"
    )
    args = parser.parse_args(argv)

    query = args.query or f"newer_than:{args.newer_than}"
    config = GmailConfig(
        tenant_id=args.tenant_id, delegated_subject=args.subject, query=query
    )
    credentials = load_gmail_credentials(config.delegated_subject)
    connector = GmailConnector(HttpGmailTransport(credentials), config)

    api_key = os.environ.get("VERITY_API_KEY")
    registry: PrincipalRegistry
    if args.principal_map:
        registry = StaticRegistry(json.loads(args.principal_map.read_text()))
    else:
        registry = HttpRegistry(args.verity_url, tenant_id=config.tenant_id, api_key=api_key)
    sink: DocumentSink = (
        DryRunSink() if args.dry_run else VerityDocumentSink(args.verity_url, api_key=api_key)
    )

    if args.backfill:
        # A backfill is a one-shot job, not a loop. Dry runs have no server to
        # report to, so the reporter is omitted (its posts would no-op anyway).
        reporter = (
            None
            if args.dry_run
            else BackfillReporter(
                args.verity_url, config.tenant_id, connector.name, api_key=api_key
            )
        )
        delivered = run_backfill(connector, registry, sink, reporter)
        print(f"gmail: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(connector, registry, sink, args.state_file)
        print(f"gmail: delivered {delivered} request(s); cursor -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
