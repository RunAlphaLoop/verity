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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator, Mapping, Protocol, Sequence

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
    "DEBEZIUM_PATH",
    "DOCUMENTS_PATH",
    "PRINCIPALS_PATH",
    "DocumentSink",
    "DryRunFactSink",
    "DryRunSink",
    "FactSink",
    "GmailConfig",
    "GmailConnector",
    "GmailDocumentEvent",
    "HttpGmailTransport",
    "HttpRegistry",
    "PrincipalRegistry",
    "StaticRegistry",
    "VerityDocumentSink",
    "VerityFactSink",
    "build_document_request",
    "build_org_envelope",
    "build_person_envelope",
    "deliver_facts",
    "extract_body",
    "map_participants",
    "message_document_id",
    "parse_valid_from",
    "run_backfill",
    "run_once",
    "select_org_facts",
    "select_person_facts",
]

# users/me resolves to the impersonated (delegated) subject under DWD, so the
# mailbox owner is baked into the base URL and every path is mailbox-relative.
GMAIL_BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

SOURCE_NAME = "gmail"

# The fact lane (selective identity-keyed org/person records) posts here, NOT
# to /v1/ingest/documents. Debezium-shaped envelopes; verity_acl is a TOP-LEVEL
# sibling of op/source/after (verity-server ingest.rs::parse_inline_acl).
DEBEZIUM_PATH = "/v1/ingest/debezium"

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
    # Fact lane toggles (the document lane is always on and unchanged).
    emit_facts: bool = True  # --facts/--no-facts
    emit_people: bool = True  # --emit-people/--no-people (orgs-only when False)
    strict_people: bool = True  # --strict-people/--no-strict-people (two-way only)
    # Exclude the mailbox owner's own registrable domain from the ORG lane
    # (default ON — the owner's employer is not an "org we deal with").
    exclude_owner_domain: bool = True


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
# Selective fact emission: the identity bar (§4.2 denylist parity + heuristics)
# ---------------------------------------------------------------------------
#
# The document lane above emits participant tags + mirrored visibility on every
# body/attachment (per-person retrieval + ACL — correct, unchanged). This
# SECOND lane ADDS selective identity-keyed facts so entity RESOLUTION has
# something to fold: every external corporate DOMAIN becomes an organization
# entity (high value, near-zero noise), and ONLY addresses that clear the
# identity bar (real two-way human correspondents) become person entities. Bots,
# lists, no-reply and role mailboxes never become entities — no "127 bots", no
# merge-review flood.
#
# The Python bar MUST equal the Rust resolver bar, so the three denylist tables
# below are copied VERBATIM from crates/verity-storage/src/resolve/canon.rs
# (FREEMAIL_DOMAINS / PLACEHOLDER_DOMAINS / ROLE_LOCALS). If canon.rs changes,
# these change with it — a fact shipped here that Rust would drop is wasted, a
# fact dropped here that Rust would keep is a silent resolution loss.

# canon.rs:110 — free-mail / consumer domains (a shared gmail.com is NOT shared
# identity). Two strangers at gmail.com therefore never become entities and so
# CAN NEVER weld — the freemail trap is avoided by construction.
_FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "ymail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "pm.me",
    }
)

# canon.rs:134 — placeholder / reserved domains (RFC 2606 + common test values).
_PLACEHOLDER_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "example.edu",
        "test.com",
        "localhost",
        "invalid",
        "none.com",
        "noemail.com",
        "no-reply.com",
        "noreply.com",
    }
)

# canon.rs:150 — role-based / shared-mailbox local-parts (a mailbox, not a
# person). info@/sales@/no-reply@/notifications@… never form a person edge.
_ROLE_LOCALS = frozenset(
    {
        "info",
        "sales",
        "support",
        "admin",
        "administrator",
        "contact",
        "hello",
        "help",
        "office",
        "team",
        "marketing",
        "billing",
        "accounts",
        "accounting",
        "finance",
        "hr",
        "jobs",
        "careers",
        "press",
        "media",
        "legal",
        "privacy",
        "security",
        "abuse",
        "postmaster",
        "webmaster",
        "noreply",
        "no-reply",
        "donotreply",
        "do-not-reply",
        "mailer-daemon",
        "notifications",
        "notification",
        "newsletter",
        "enquiries",
        "inquiries",
        "service",
        "customerservice",
        "orders",
        "hi",
    }
)

# Connector-side EXTRA selectivity (NOT in canon.rs — pure NARROWING, never
# widening): ESP / bulk-sender infrastructure domains whose mail is machine
# blast, not a person we correspond with. Subtracted from the PERSON lane only;
# the ORG lane is unaffected (these are not corporate identities we deal with).
_LIST_DOMAINS = frozenset(
    {
        "sendgrid.net",
        "mailgun.org",
        "amazonses.com",
        "mcsv.net",
        "mailchimpapp.com",
        "sparkpostmail.com",
        "sendinblue.com",
        "postmarkapp.com",
        "mailchimp.com",
        "cmail19.com",
    }
)

# List-ish local-parts for the person lane's automation gate (a superset-flavored
# subset of the role locals plus common bot/build/digest words).
_LIST_LOCALS = frozenset(
    {
        "team",
        "notifications",
        "notification",
        "updates",
        "newsletter",
        "digest",
        "alerts",
        "alert",
        "noreply",
        "no-reply",
        "donotreply",
        "do-not-reply",
        "mailer",
        "mailer-daemon",
        "bot",
        "ci",
        "builds",
        "build",
        "robot",
        "automated",
    }
)

# Automation / list markers in a display name (a "real name" must not be one of
# these). Case-insensitive; anchored where it matters.
_VIA_RE = re.compile(r"(?i)\b(via|through)\b")
_AUTOMATION_TAIL_RE = re.compile(
    r"(?i)(team|notifications?|bot|ci|cd|updates?|digest|alerts?|reports?|"
    r"mailer|daemon|jobs?|jenkins|deploy|tickets?|support|newsletter|noreply|"
    r"no-?reply)\s*$"
)
# The eTLD+1 multi-part public-suffix table, mirrored (minimally) from canon.rs
# registrable_domain's MULTI_PART_SUFFIXES so a `mail.acme.co.uk` collapses to
# `acme.co.uk`, not `co.uk`. A plain last-two-labels fallback covers the rest.
_MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "sch.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "ac.nz",
        "school.nz",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "co.in",
        "net.in",
        "org.in",
        "gen.in",
        "firm.in",
        "ind.in",
        "co.za",
        "net.za",
        "org.za",
        "gov.za",
        "com.mx",
        "com.sg",
        "com.hk",
        "com.cn",
        "com.tr",
        "com.ar",
        "com.tw",
        "com.my",
        "co.kr",
        "co.il",
        "co.id",
        "co.th",
        "com.pl",
        "com.ua",
        "com.ph",
        "com.vn",
    }
)


def _is_denylisted_domain(domain: str) -> bool:
    """canon.rs is_denied_domain: free-mail or placeholder → never an org, never
    a person's org."""
    return domain in _FREEMAIL_DOMAINS or domain in _PLACEHOLDER_DOMAINS


def _is_denylisted_email(local: str, domain: str) -> bool:
    """canon.rs is_denylisted(Email): role-based local (after +tag strip) OR a
    denylisted domain. Fail closed."""
    local_base = local.split("+", 1)[0]
    return local_base in _ROLE_LOCALS or _is_denylisted_domain(domain)


def _canonicalize_email(raw: str | None) -> str | None:
    """Port of canon.rs::canonicalize_email (identity bar parity).

    trim; lowercase; strip a leading ``mailto:``; split on a SINGLE ``@``
    (None if 0 or >1); strip the ``+tag`` sub-address (None if the local then
    empties); trim ``.`` off the domain; require the domain to contain ``.`` and
    no space; drop if denylisted (free-mail / placeholder / role-local). Returns
    the canonical ``local@domain`` or None. Fail closed on anything malformed."""
    if not raw:
        return None
    s = raw.strip().lower()
    if s.startswith("mailto:"):
        s = s[len("mailto:") :].strip()
    if s.count("@") != 1:
        return None
    local_raw, domain_raw = s.split("@", 1)
    if not local_raw or not domain_raw:
        return None
    local = local_raw.split("+", 1)[0] if "+" in local_raw else local_raw
    if not local:
        return None
    domain = domain_raw.strip(".")
    if "." not in domain or " " in domain:
        return None
    if _is_denylisted_email(local, domain):
        return None
    return f"{local}@{domain}"


def _registrable_domain(host: str | None) -> str | None:
    """Port of canon.rs::registrable_domain (eTLD+1) over a bare host or a URL.

    Strip scheme/path/query/fragment/port/userinfo down to the bare host, drop a
    leading ``www.``, then reduce to the registrable domain using the multi-part
    suffix table (``mail.acme.co.uk`` → ``acme.co.uk``), else the last two
    labels. None on empty / single-label."""
    if not host:
        return None
    s = host.strip().lower()
    if not s:
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    elif s.startswith("mailto:"):
        s = s[len("mailto:") :]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    if ":" in s:
        head, _, port = s.rpartition(":")
        if head and port.isdigit():
            s = head
    if s.startswith("www."):
        s = s[len("www.") :]
    s = s.strip(".")
    if not s or "." not in s or " " in s:
        return None
    labels = [label for label in s.split(".") if label]
    if len(labels) < 2:
        return None
    last_two = f"{labels[-2]}.{labels[-1]}"
    if last_two in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return f"{labels[-3]}.{last_two}"
    return last_two


_ORG_MARKER_RE = re.compile(
    r"(?i)\b(inc|llc|ltd|corp|co|gmbh|team|support|notifications?|"
    r"labs?|technologies|software|systems|group|holdings)\b"
)


def _looks_org_ish(name: str) -> bool:
    """Whether a From display name reads like an ORGANIZATION / brand rather
    than a person's full name — a DISPLAY-name chooser only, NEVER a merge key.

    Accepts: a single brand token (``Stripe``, ``GitHub``) or a name carrying an
    org marker (``Acme Inc``, ``Redis Labs``, ``GitHub Notifications``). Rejects
    an empty string and a plain two-token human name (``Jane Roe``) so a real
    person's name never becomes an org's display label."""
    stripped = name.strip()
    if not stripped:
        return False
    if _ORG_MARKER_RE.search(stripped):
        return True
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9'\-]*", stripped)
    # A single token is treated as a brand (Stripe); 2+ alpha tokens with no org
    # marker read as a personal name, so decline (the domain label is used).
    return len(tokens) == 1


def _is_person_display(name: str | None, address: str) -> bool:
    """Whether a display name reads like a REAL human name (a quality gate for
    admitting a person and for choosing an org's display name — NEVER a merge
    key). Rejects: empty; name == the address or its local-part; only role/list
    words; a ``via``/``through`` byline; an automation tail ("… Team",
    "… Notifications", "… Bot", "… CI", "… Updates")."""
    if not name:
        return False
    stripped = name.strip()
    if not stripped:
        return False
    low = stripped.lower()
    addr_low = address.strip().lower()
    local = addr_low.split("@", 1)[0] if "@" in addr_low else addr_low
    if low == addr_low or low == local:
        return False
    if _VIA_RE.search(stripped) or _AUTOMATION_TAIL_RE.search(stripped):
        return False
    # A real human name reads as at least two alpha tokens (given + family),
    # none of them a role/list word. This deliberately rejects a single brand
    # token ("GitHub", "Stripe") — that is an ORG display, not a person — so a
    # brand never sneaks past the person quality gate.
    tokens = re.findall(r"[A-Za-z][A-Za-z'\-]*", stripped)
    real = [t for t in tokens if t.lower() not in _ROLE_LOCALS and t.lower() not in _LIST_LOCALS]
    return len(real) >= 2


def _looks_like_list(address: str) -> bool:
    """Whether an address is bulk/list/automation infrastructure (person lane
    only): a list-ish local-part OR an ESP/bulk-sender registrable domain."""
    addr = address.strip().lower()
    if "@" not in addr:
        return True
    local, domain = addr.split("@", 1)
    local_base = local.split("+", 1)[0]
    if local_base in _LIST_LOCALS:
        return True
    reg = _registrable_domain(domain)
    return bool(reg and reg in _LIST_DOMAINS)


@dataclass
class _CorrespondentStat:
    """Crawl-scoped, per-address accumulation of correspondence direction and
    display/domain evidence. Two-way (both inbound and outbound with the owner)
    is the primary person-admission signal."""

    inbound: bool = False  # X was the From of a message NOT from the owner (owner received)
    outbound: bool = False  # X was in To∪Cc of a message the owner SENT (owner wrote to X)
    display_names: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    first_seen_ms: int | None = None

    def note_seen(self, ms: int | None) -> None:
        if ms is None:
            return
        if self.first_seen_ms is None or ms < self.first_seen_ms:
            self.first_seen_ms = ms


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
        # Fact lane (§4.2) accumulators — crawl/batch-scoped, filled as a SIDE
        # EFFECT of the document pass, drained by the runner AFTER the message
        # loop. The document lane (tags + visibility on bodies) is unchanged;
        # this is a strictly additive second lane.
        self._owner = (self.config.delegated_subject or "").strip().lower()
        self._corr: dict[str, _CorrespondentStat] = {}
        self._org_domains: dict[str, str] = {}
        self._org_first_seen: dict[str, int] = {}

    def _reset_fact_accumulators(self) -> None:
        self._owner = (self.config.delegated_subject or "").strip().lower()
        self._corr = {}
        self._org_domains = {}
        self._org_first_seen = {}

    def _observe_correspondents(
        self, headers: Iterable[Mapping[str, Any]], internal_date: str
    ) -> None:
        """Accumulate correspondence direction + org-domain evidence from one
        message's participant headers. Wrapped by the caller's skip-and-count so
        a single malformed header never corrupts the accumulator or aborts the
        crawl. Owner-as-participant is never recorded as a correspondent."""
        headers = list(headers)
        try:
            ms: int | None = int(internal_date) if internal_date else None
        except (TypeError, ValueError):
            ms = None
        from_values = [v for name in ("From",) if (v := _header(headers, name))]
        to_cc_values = [v for name in ("To", "Cc") if (v := _header(headers, name))]
        from_pairs = email.utils.getaddresses(from_values)
        to_cc_pairs = email.utils.getaddresses(to_cc_values)

        # Owner is the sender iff a raw From address canonicalizes to the owner,
        # OR (owner may be freemail/denylisted, e.g. a personal gmail inbox) its
        # lowercased raw address equals the owner.
        from_raw = {(a or "").strip().lower() for _n, a in from_pairs}
        owner_is_sender = self._owner in from_raw or any(
            _canonicalize_email(a) == self._owner for _n, a in from_pairs
        )

        # ORG accumulation runs off the RAW sender domain even when the address
        # itself fails the person bar (notifications@github.com still proves the
        # org github.com). Exclude the owner's own domain later, in select.
        for _display, addr in from_pairs:
            raw = (addr or "").strip().lower()
            if not raw or "@" not in raw:
                continue
            reg = _registrable_domain(raw.rsplit("@", 1)[1])
            if reg is None or _is_denylisted_domain(reg):
                continue
            display = (_display or "").strip()
            candidate = display if _is_person_display(display, raw) else ""
            org_name = candidate if _looks_org_ish(candidate) else _title_case_label(
                reg.split(".", 1)[0]
            )
            existing = self._org_domains.get(reg)
            # Prefer a real org-ish display over the title-cased label; otherwise
            # keep the first one seen (deterministic).
            if existing is None or (
                existing == _title_case_label(reg.split(".", 1)[0]) and _looks_org_ish(candidate)
            ):
                self._org_domains[reg] = org_name
            if ms is not None:
                prev = self._org_first_seen.get(reg)
                if prev is None or ms < prev:
                    self._org_first_seen[reg] = ms

        # PERSON stats: direction + display + domain per canonical address.
        for pairs, is_from in ((from_pairs, True), (to_cc_pairs, False)):
            for display, addr in pairs:
                canon = _canonicalize_email(addr)
                if canon is None or canon == self._owner:
                    continue
                stat = self._corr.get(canon)
                if stat is None:
                    stat = _CorrespondentStat()
                    self._corr[canon] = stat
                if is_from and not owner_is_sender:
                    stat.inbound = True
                if not is_from and owner_is_sender:
                    stat.outbound = True
                display = (display or "").strip()
                if _is_person_display(display, canon):
                    stat.display_names.add(display)
                reg = _registrable_domain(canon.rsplit("@", 1)[1])
                if reg:
                    stat.domains.add(reg)
                stat.note_seen(ms)

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
        self._reset_fact_accumulators()
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
        self._reset_fact_accumulators()
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

        # Fact lane (additive): accumulate correspondence + org-domain evidence
        # off the same headers. One malformed header must never corrupt the
        # accumulator or abort the crawl, hence the skip-and-count guard.
        try:
            self._observe_correspondents(headers, internal_date)
        except (ValueError, KeyError, TypeError) as exc:
            # One malformed header must never corrupt the accumulator or abort
            # the crawl — skip-and-count-and-log, same as the doc lane.
            print(f"gmail: fact-observe skipped on {message_id}: {exc}", file=sys.stderr)

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
# Fact lane: selective org/person envelopes → POST /v1/ingest/debezium
# ---------------------------------------------------------------------------
#
# ORG: one SINGLETON per surviving external registrable domain. The `after` has
# only descriptive fields (domain/name/kind) — NONE named email/AccountId/
# associatedcompanyid/*_id — so the resolver's producers see NO merge evidence
# and the org materializes as its own canonical (fold.rs: a singleton is
# implicitly its own canonical). No welding, no domain-star fan-out.
#
# PERSON: only addresses that clear the identity bar. The `after` carries a BARE
# `email` field → EMAIL_FIELDS → the tier-1 email-within-namespace producer in
# namespace customer_contact (source is "gmail", not "linear", and the field is
# "email"). So this person can weld cross-source to a future CRM contact at the
# same address WITHOUT welding to any internal actor (§4.4 fence) and WITHOUT
# merging two freemail strangers (they never reach here — gate 1 drops them).


def _title_case_label(label: str) -> str:
    """A domain's leading label as a display name: `stripe` → `Stripe`,
    `redis-labs` → `Redis Labs`. Display-only; NEVER a merge key."""
    return " ".join(part.capitalize() for part in re.split(r"[-_]+", label) if part) or label


def build_org_envelope(
    domain: str, name: str, owner_token: int | None, ts_ms: int | None
) -> dict | None:
    """One Debezium ORG envelope (a singleton canonical). Returns None when the
    owner principal did not resolve (fail closed: no resolvable visibility →
    no fact). `verity_acl` is a TOP-LEVEL sibling of op/source/after."""
    if owner_token is None:
        return None
    source: dict[str, Any] = {"connector": SOURCE_NAME, "db": "accounts", "table": "org"}
    if ts_ms is not None:
        source["ts_ms"] = ts_ms
    return {
        "op": "c",
        "source": source,
        # Descriptive-only: no field named email/AccountId/associatedcompanyid/
        # *_id → no merge evidence → singleton → its own canonical.
        "after": {"id": domain, "domain": domain, "name": name, "kind": "organization"},
        "verity_acl": {"visibility": [owner_token], "confidentiality": "internal"},
    }


def build_person_envelope(
    email: str,
    name: str | None,
    domain: str | None,
    correspondence: str,
    owner_token: int | None,
    ts_ms: int | None,
) -> dict | None:
    """One Debezium PERSON envelope (welds cross-source by `email` within the
    customer_contact namespace). Returns None when the owner principal did not
    resolve (fail closed). `verity_acl` is a TOP-LEVEL sibling."""
    if owner_token is None:
        return None
    source: dict[str, Any] = {"connector": SOURCE_NAME, "db": "contacts", "table": "person"}
    if ts_ms is not None:
        source["ts_ms"] = ts_ms
    after: dict[str, Any] = {
        "id": email,
        # BARE `email` → EMAIL_FIELDS → tier-1 email-within-namespace producer.
        "email": email,
        "correspondence": correspondence,
    }
    if name:
        after["name"] = name  # display/blocking only, never a lone merge key
    if domain:
        after["domain"] = domain  # descriptive; NOT re-emitted as a merge key
    return {
        "op": "c",
        "source": source,
        "after": after,
        "verity_acl": {"visibility": [owner_token], "confidentiality": "internal"},
    }


def select_org_facts(
    org_domains: Mapping[str, str],
    org_first_seen: Mapping[str, int],
    owner_token: int | None,
    *,
    owner_domain: str | None = None,
) -> list[dict]:
    """Build the deduped ORG envelopes (one per surviving external registrable
    domain). Permissive on orgs — high value, near-zero noise:
    - drop denylisted (free-mail / placeholder) domains;
    - drop the owner's own registrable domain;
    - role-local-ness does NOT disqualify (notifications@github.com still proves
      github.com is an org we deal with).
    Empty list when the owner token is unresolvable (fail closed)."""
    if owner_token is None:
        return []
    owner_reg = _registrable_domain(owner_domain) if owner_domain else None
    envelopes: list[dict] = []
    for domain in sorted(org_domains):
        if _is_denylisted_domain(domain):
            continue
        if owner_reg and domain == owner_reg:
            continue
        name = org_domains[domain] or _title_case_label(domain.split(".", 1)[0])
        env = build_org_envelope(domain, name, owner_token, org_first_seen.get(domain))
        if env is not None:
            envelopes.append(env)
    return envelopes


def select_person_facts(
    corr: Mapping[str, _CorrespondentStat],
    owner_token: int | None,
    *,
    strict: bool = True,
) -> list[dict]:
    """Build the PERSON envelopes for addresses that clear the identity bar.

    ALL of 1-3, then 4a OR (when ``strict`` is False) 4b:
      1. canonicalizes (kills every free-mail / placeholder / role-local — the
         "127 bots" case);
      2. is not the owner (owner is never accumulated as a correspondent);
      3. is not a list/ESP/bot address;
      4a. TWO-WAY (default): both inbound and outbound → correspondence
          "two_way"; OR
      4b. NAMED-SINGLE-DIRECTION (only when ``strict`` is False): exactly one
          direction AND a real display name AND a non-freemail business domain
          → "inbound_named" / "outbound_named".
    Empty list when the owner token is unresolvable (fail closed)."""
    if owner_token is None:
        return []
    envelopes: list[dict] = []
    for addr in sorted(corr):
        stat = corr[addr]
        # addr is already the canonical key (gate 1 ran during accumulation),
        # but re-assert the bar so a caller-built stat can't smuggle one past.
        canon = _canonicalize_email(addr)
        if canon is None or canon != addr:
            continue
        if _looks_like_list(addr):
            continue
        two_way = stat.inbound and stat.outbound
        if two_way:
            # A real correspondent, not an automation address the owner merely
            # reply-all'd or CC'd a bot on. Two-way is necessary but NOT
            # sufficient: require a real human display name (mirrors the
            # single-direction branch below). This rejects CI/ticketing/list
            # bots on ordinary hosts (ci_activity@noreply.github.com,
            # tickets@zendesk-corp.io, jenkins@ci.internal-corp.com, …) that
            # evade _looks_like_list because their local-part is not a known
            # list-local and their host is not a known ESP domain.
            if not any(_is_person_display(n, addr) for n in stat.display_names):
                continue
            correspondence = "two_way"
        elif not strict and (stat.inbound ^ stat.outbound):
            reg = _registrable_domain(addr.split("@", 1)[1])
            if reg is None or reg in _FREEMAIL_DOMAINS:
                continue
            if not stat.display_names:
                continue
            correspondence = "inbound_named" if stat.inbound else "outbound_named"
        else:
            continue
        name = _best_display_name(stat.display_names, addr)
        domain = _registrable_domain(addr.split("@", 1)[1])
        env = build_person_envelope(
            addr, name, domain, correspondence, owner_token, stat.first_seen_ms
        )
        if env is not None:
            envelopes.append(env)
    return envelopes


def _best_display_name(names: set[str], address: str) -> str | None:
    """Pick the longest real display name seen for an address (already filtered
    to real names by the accumulator), or None."""
    real = sorted((n for n in names if _is_person_display(n, address)), key=len, reverse=True)
    return real[0] if real else None


class FactSink(Protocol):
    def deliver(self, envelopes: list[dict], *, pk: str = "id") -> None: ...


class VerityFactSink:
    """POSTs a JSON ARRAY of Debezium envelopes to ``{base}/v1/ingest/debezium``.

    Same httpx.Client + Bearer auth as VerityDocumentSink. The inline
    ``verity_acl`` block on each envelope supplies visibility — there is NO
    ``visibility=`` query param (that would be a bound-policy fallback, which the
    fact lane forbids). ``tenant_id`` + ``pk`` are query params. The response's
    ``facts_refused_no_acl`` count is surfaced for a fail-VISIBLE post-run
    assertion — a mis-shaped ACL shows up as a refusal, never a silent leak."""

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
        self.refused = 0

    def deliver(self, envelopes: list[dict], *, pk: str = "id") -> None:
        if not envelopes:
            return
        response = self._client.post(
            f"{self._base_url}{DEBEZIUM_PATH}",
            params={"tenant_id": self._tenant_id, "pk": pk},
            json=envelopes,
        )
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError:
            body = {}
        refused = body.get("facts_refused_no_acl")
        if isinstance(refused, int):
            self.refused += refused


class DryRunFactSink:
    """Collects and prints the would-be Debezium envelopes instead of POSTing.

    Person locals are REDACTED to ``•••@domain`` (domains are org identity, not
    PII, so they print in clear); org domains print whole. No full addresses,
    names, tokens, or bodies ever reach the output."""

    def __init__(self, stream: Any = None) -> None:
        self.envelopes: list[dict] = []
        self.refused = 0
        self._stream = stream if stream is not None else sys.stdout

    def deliver(self, envelopes: list[dict], *, pk: str = "id") -> None:
        self.envelopes.extend(envelopes)
        for env in envelopes:
            print(f"[dry-run] POST {DEBEZIUM_PATH}\n{_redact_envelope(env)}", file=self._stream)


def _redact_local(email: str) -> str:
    """`jane@supabase.io` → `•••@supabase.io`. Domain in clear (org identity)."""
    domain = email.split("@", 1)[1] if "@" in email else "?"
    return f"•••@{domain}"


def _redact_envelope(env: Mapping[str, Any]) -> str:
    """A PII-free one-line shape of an envelope for dry-run output."""
    after = env.get("after") or {}
    table = (env.get("source") or {}).get("table")
    acl = env.get("verity_acl") or {}
    vis_present = bool(acl.get("visibility"))
    if table == "person":
        ident = _redact_local(str(after.get("id", "")))
        extra = f" correspondence={after.get('correspondence')}"
    else:
        ident = str(after.get("id", ""))  # a domain — org identity, not PII
        extra = f" name={after.get('name')!r}"
    return (
        f"  op={env.get('op')} table={table} id={ident}{extra} "
        f"acl.visibility={'set' if vis_present else 'MISSING'}"
    )


def deliver_facts(
    connector: GmailConnector,
    registry: PrincipalRegistry,
    fact_sink: FactSink,
) -> tuple[int, int]:
    """Drain the crawl-scoped fact accumulators into the fact sink and return
    ``(orgs, persons)`` emitted. Call AFTER the message loop.

    Fail closed: resolve the owner principal ONCE; if it does not resolve to an
    int token, the fact lane is DISABLED for this run — NO org and NO person
    envelopes are built or posted (a count-only line is logged). The document
    lane is unaffected."""
    if not connector.config.emit_facts:
        return (0, 0)
    owner = connector._owner
    owner_token: int | None = None
    if owner:
        principal = f"user:{owner}"
        owner_token = registry.resolve([principal]).get(principal)
    if owner_token is None:
        print("gmail: fact lane disabled — owner principal did not resolve")
        return (0, 0)

    owner_domain = owner.rsplit("@", 1)[1] if "@" in owner else None
    org_envelopes = select_org_facts(
        connector._org_domains,
        connector._org_first_seen,
        owner_token,
        owner_domain=owner_domain if connector.config.exclude_owner_domain else None,
    )
    person_envelopes: list[dict] = []
    if connector.config.emit_people:
        person_envelopes = select_person_facts(
            connector._corr, owner_token, strict=connector.config.strict_people
        )
    fact_sink.deliver([*org_envelopes, *person_envelopes], pk="id")
    return (len(org_envelopes), len(person_envelopes))


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
    fact_sink: FactSink | None = None,
) -> int:
    """One poll cycle: load cursor, poll, deliver, checkpoint. Returns the
    number of delivered requests. The cursor is checkpointed only after
    delivery, so a crash replays the window (at-least-once).

    When ``fact_sink`` is given, the selective org/person facts accumulated over
    this poll batch are delivered AFTER the documents (an additive second lane;
    a contact that reaches two-way only across polls lands on the poll where the
    second direction arrives, or on the next backfill)."""
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
    if fact_sink is not None:
        orgs, persons = deliver_facts(connector, registry, fact_sink)
        if orgs or persons:
            print(f"gmail: emitted {orgs} org, {persons} person fact(s)")
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
    fact_sink: FactSink | None = None,
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
    # Fact lane (additive): after the whole crawl has drained, resolve the owner
    # token once and deliver the deduped org/person envelopes. A delivery
    # failure here must not fail the (already-delivered) document backfill.
    if fact_sink is not None:
        try:
            orgs, persons = deliver_facts(connector, registry, fact_sink)
        except httpx.HTTPError as exc:
            print(f"gmail: fact delivery failed ({exc}); document backfill unaffected")
        else:
            if orgs or persons:
                print(f"gmail: emitted {orgs} org, {persons} person fact(s)")
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
    # Fact lane toggles (document lane always on and unchanged).
    parser.add_argument(
        "--facts",
        dest="facts",
        action="store_true",
        default=True,
        help="emit selective org/person entity facts (default on)",
    )
    parser.add_argument(
        "--no-facts", dest="facts", action="store_false", help="disable the fact lane entirely"
    )
    parser.add_argument(
        "--emit-people",
        dest="emit_people",
        action="store_true",
        default=True,
        help="emit person facts for real correspondents (default on; orgs-only with --no-people)",
    )
    parser.add_argument("--no-people", dest="emit_people", action="store_false")
    parser.add_argument(
        "--strict-people",
        dest="strict_people",
        action="store_true",
        default=True,
        help="require two-way correspondence for a person fact (default on)",
    )
    parser.add_argument(
        "--no-strict-people",
        dest="strict_people",
        action="store_false",
        help="also admit a NAMED single-direction business human (relaxed)",
    )
    args = parser.parse_args(argv)

    query = args.query or f"newer_than:{args.newer_than}"
    config = GmailConfig(
        tenant_id=args.tenant_id,
        delegated_subject=args.subject,
        query=query,
        emit_facts=args.facts,
        emit_people=args.emit_people,
        strict_people=args.strict_people,
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
    fact_sink: FactSink | None = None
    if config.emit_facts:
        fact_sink = (
            DryRunFactSink()
            if args.dry_run
            else VerityFactSink(args.verity_url, config.tenant_id, api_key=api_key)
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
        delivered = run_backfill(connector, registry, sink, reporter, fact_sink=fact_sink)
        print(f"gmail: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(connector, registry, sink, args.state_file, fact_sink=fact_sink)
        print(f"gmail: delivered {delivered} request(s); cursor -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
