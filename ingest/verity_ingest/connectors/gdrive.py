"""Google Drive native connector — the Tier-A ACL-mirroring proof (SPEC.md §5, §5e.2).

Auth (BYOT doctrine, §5e.2): the customer's *own* service account with
domain-wide delegation, configured in their admin console. The key file path
comes from ``GOOGLE_APPLICATION_CREDENTIALS``. No vendor OAuth app, ever
(§5e.8 refusal #1). We speak plain Drive v3 REST over httpx; google-auth is
used only to mint/refresh the service-account token (lazy import, so fixture
tests never need it).

Truth lane (§5): ``poll(cursor)`` drives ``changes.list`` with an opaque
pageToken cursor (``changes.getStartPageToken`` on first run). Per changed
file: ``files.get`` for metadata, ``permissions.list`` for the ACL, then —
and only if the ACL is resolvable (ACL-before-content, §5a) — content:

- Google Docs → ``files.export`` as ``text/plain``
- ``text/*`` and ``application/json`` → direct download (``alt=media``),
  delivered inline as ``content`` text
- PDF / PPTX / XLS(X) → direct download (``alt=media``), delivered as raw
  bytes in ``content_base64`` (+ ``filename``); the SERVER runs the Tier-1
  extractor (verity-server extract.rs: Rust-native, deterministic, no OCR).
  This was chosen over posting bytes to ``POST /v1/files`` because /v1/files
  writes under a scope handle whose principals would REPLACE the mirrored
  per-file ACL this connector computed — the whole point of a Tier-A
  connector. Riding the existing documents endpoint keeps one sink, the same
  visibility/entity mapping, and ACL-before-content ordering; the smallest
  honest change. Typed extraction failures (encrypted PDF, scanned/image PDF
  with no text layer, parse failure) land METADATA-ONLY server-side with the
  reason disclosed on the stored record — never silently indexed as empty.
- everything else → metadata + ACL only, no content bytes

ACL mapping (fail-closed, §5e.6 / §6b):

- ``type=user``   → principal ``user:<email>``
- ``type=group``  → group ``group:<email>`` (nested-group closure is the
  Identity Plane's job via the Admin SDK directory sync, §6a — never ours)
- ``type=domain`` → group ``domain:<domain>``
- ``type=anyone`` → ``AclEnvelope(resolvable=False)`` (quarantine) unless the
  operator explicitly sets ``anyone_maps_to`` (e.g. ``org:everyone``)
- unknown/unmappable entries → ``AclEnvelope(resolvable=False)``

Folder ACL inheritance (§6c ACL-mapping conformance) — deliberately NOT a
parent-walk. Drive's ``permissions.list`` on a file already returns the
EFFECTIVE ACL, inheritance included: **My Drive** copies a shared folder's
grants down onto every descendant (each file carries its own direct grant),
and **Shared Drives** list inherited grants on the item (``permissionDetails``
flags which are inherited). So the fetched ``parents`` field is intentionally
unused: walking it to re-fetch and merge ancestor ACLs would be redundant, and
worse — because a file whose ancestor folder ACL is unreadable would then
fail-closed-quarantine even though its own ``permissions.list`` is already
complete, i.e. it would OVER-hide files that index correctly today. Empirically
verified 2026-07-14 against this workspace (137 folders scanned, 0 shared beyond
the owner — no copy-down/inherited case to observe). Residual: the Shared-Drive
inherited-listing behavior could not be exercised here (no shared drive present);
revisit with a Shared-Drive corpus before claiming Shared-Drive conformance.

Deletions and trashed files emit a removal marker event
(``GDriveDocumentEvent(removed=True)``); the sink posts it with
``{"removed": true}``. TODO(server): wire to the server-side retire path —
§8c source hard-deletes must propagate to tombstone + purge, not merely to
invalidation. Until that endpoint exists the marker is delivered to the same
documents endpoint and the server treats it as invalidate-only.

Push lane: ``changes.watch`` needs a public HTTPS endpoint plus channel
renewal before the 7-day expiry (§5). Poll is the truth lane and always
sufficient; the watch lane is a later optimization. ``push_events`` is a
documented no-op here.

Server contracts coded against (principals endpoint verified against the
server as built; the documents endpoint's fixture tests pin the request
bodies, integration lands later):

- ``POST /v1/admin/principals``  body ``{"tenant_id": "<uuid>",
  "principals": ["user:a@x", ...]}`` → response ``{"mappings": {"user:a@x":
  101, "group:g@x": 202, ...}}`` — tokens nested under ``mappings``; a
  ``null``/absent/non-int token means the crosswalk cannot resolve the
  principal (fail-closed: it confers nothing).
- ``POST /v1/ingest/documents``  body::

      {
        "tenant_id":      "<tenant>",
        "source":         "gdrive",
        "document_id":    "<drive file id>",
        "content":        "<extracted text>" | null,   # null = metadata-only
        # binary lane (PDF/PPTX/XLS(X)): raw bytes for server-side Tier-1
        # extraction; mutually exclusive with "content", filename is the
        # detection hint (magic bytes win server-side):
        "content_base64": "<base64 bytes>",            # instead of "content"
        "filename":       "<drive file name>",
        "entities":       ["<entity tag>", ...],       # optional, may be []
        "visibility":     [<int token>, ...],          # only when mirrored
        "acl_provenance": "mirrored" | "quarantined",
        "valid_from":     "<RFC 3339 modifiedTime>"
      }

  Quarantined items carry NO ``visibility`` field — the server's structural
  choke point (§5e) holds them, never indexes them. Removal markers are
  ``{"tenant_id", "source", "document_id", "removed": true, "valid_from"}``.

Runner: ``python -m verity_ingest.connectors.gdrive --once [--dry-run]``
with a JSON cursor state file. ``--dry-run`` prints the would-be request
bodies instead of POSTing.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Mapping, Protocol, Sequence

import httpx

from verity_ingest import crosswalk
from verity_ingest.acl_diff import AclDiffLane
from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

DRIVE_BASE_URL = "https://www.googleapis.com/drive/v3"
DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"

GOOGLE_DOC_MIME = "application/vnd.google-apps.document"
DOC_EXPORT_MIME = "text/plain"

PRINCIPALS_PATH = "/v1/admin/principals"
DOCUMENTS_PATH = "/v1/ingest/documents"
CONNECTOR_STATUS_PATH = "/v1/admin/connector-status"

# The fact lane (selective identity-keyed org/person records) posts here, NOT
# to /v1/ingest/documents. Debezium-shaped envelopes; verity_acl is a TOP-LEVEL
# sibling of op/source/after (verity-server ingest.rs::parse_inline_acl).
DEBEZIUM_PATH = "/v1/ingest/debezium"

# Field masks: ask Google for exactly what we consume, nothing more.
_CHANGES_FIELDS = "kind,nextPageToken,newStartPageToken,changes(changeType,time,removed,fileId)"
_FILE_FIELDS = "id,name,mimeType,modifiedTime,parents,trashed,version"
_PERMISSIONS_FIELDS = "nextPageToken,permissions(id,type,emailAddress,domain,role,deleted)"


# ---------------------------------------------------------------------------
# Config & events
# ---------------------------------------------------------------------------


@dataclass
class GDriveConfig:
    """Connector configuration. No default widens visibility (§5e.8 #9)."""

    tenant_id: str = "default"
    # If set (e.g. "org:everyone"), type=anyone permissions map to this group
    # principal instead of quarantining. Default None: anyone-links quarantine.
    anyone_maps_to: str | None = None
    # Domain-wide delegation subject (the user to impersonate). Optional: a
    # service account can also be granted access directly on shared drives.
    delegated_subject: str | None = None
    page_size: int = 100
    # Fact lane toggles (the document lane is always on and unchanged).
    emit_facts: bool = True  # --facts/--no-facts
    emit_people: bool = True  # --emit-people/--no-people (orgs-only when False)
    # Exclude the crawl owner's own registrable domain from the ORG lane
    # (default ON — the owner's employer is not an "org we deal with").
    exclude_owner_domain: bool = True


@dataclass
class GDriveDocumentEvent(DocumentEvent):
    """DocumentEvent + the Drive timestamp, file name, and removal marker.

    ``removed=True`` means the file was hard-deleted at the source or moved
    to trash; content/mime/acl are empty and the sink emits a removal body.
    ``name`` rides along for the binary lane's ``filename`` detection hint.
    """

    modified_time: str = ""
    name: str = ""
    removed: bool = False


# Binary formats the server's Tier-1 extractor handles (verity-server
# extract.rs): text-based PDF, PPTX, XLS(X). Deliberately NOT .doc/.docx or
# legacy .ppt — Google Docs already export as text, and anything else stays
# honestly metadata-only until a later tier.
BINARY_EXTRACTABLE_MIMES = frozenset(
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
    }
)


def is_extractable(mime_type: str) -> bool:
    """Mimetypes whose content we deliver as inline text."""
    return (
        mime_type == GOOGLE_DOC_MIME
        or mime_type.startswith("text/")
        or mime_type == "application/json"
    )


def is_binary_extractable(mime_type: str) -> bool:
    """Mimetypes delivered as raw bytes for SERVER-side Tier-1 extraction."""
    return mime_type in BINARY_EXTRACTABLE_MIMES


# ---------------------------------------------------------------------------
# Selective fact emission: the identity bar (§4.2 denylist parity + heuristics)
# ---------------------------------------------------------------------------
#
# The document lane above emits participant tags + mirrored visibility on every
# file (per-person retrieval + ACL — correct, unchanged). This SECOND lane ADDS
# selective identity-keyed facts so entity RESOLUTION has something to fold:
# every external corporate DOMAIN that shares a file becomes an organization
# entity (high value, near-zero noise), and ONLY type=user permissions whose
# address clears the identity bar become person entities. Groups, domain-wide,
# anyone, service accounts, no-reply/role mailboxes never become entities — no
# "127 bots", no merge-review flood. The PERSON `after.email` is the weld key:
# a Drive sharer and a Gmail correspondent at the SAME address resolve to ONE
# canonical (gdrive:contacts.person + gmail:contacts.person share the
# customer_contact namespace in canon.rs — the resolver welds them for free).
#
# NOTE: gmail.py imports gdrive.py at module load, so gdrive.py MUST NOT import
# from gmail.py (circular import). The denylist tables + canonicalization below
# are therefore MIRRORED VERBATIM from gmail.py (which in turn mirrors
# crates/verity-storage/src/resolve/canon.rs) so the identity bar is provably
# identical across both connectors and the Rust resolver.

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

# Connector-side EXTRA selectivity (NOT in canon.rs — pure NARROWING, never
# widening): Google service-account domains are machines, not people. A file
# shared to / owned by a service account (e.g. a pipeline robot) must never
# become a person OR an org entity. Applied to both lanes below.
_SERVICE_ACCOUNT_DOMAINS = frozenset({"gserviceaccount.com"})


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


def _title_case_label(label: str) -> str:
    """A domain's leading label as a display name: `stripe` → `Stripe`,
    `redis-labs` → `Redis Labs`. Display-only; NEVER a merge key."""
    return " ".join(part.capitalize() for part in re.split(r"[-_]+", label) if part) or label


def _modified_time_to_ms(modified_time: str) -> int | None:
    """Parse an RFC3339 ``modifiedTime`` to epoch-millis, or None if unparseable.
    ts_ms is optional in the Debezium envelopes, so a malformed timestamp simply
    omits the field rather than aborting anything."""
    if not modified_time:
        return None
    try:
        dt = datetime.fromisoformat(modified_time.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


# ---------------------------------------------------------------------------
# ACL mapping (fail-closed)
# ---------------------------------------------------------------------------


def map_permissions(
    permissions: Iterable[Mapping[str, Any]], anyone_maps_to: str | None = None
) -> AclEnvelope:
    """Map a Drive ``permissions.list`` result to an AclEnvelope.

    Fail closed: any entry we cannot faithfully mirror poisons the whole
    envelope (``resolvable=False`` → quarantine). A partially-mapped ACL is
    never emitted, because dropping the entry we didn't understand could
    *widen* effective visibility relative to intent (e.g. an unknown grant
    type that Google later narrows).
    """
    principals: list[str] = []
    groups: list[str] = []
    for perm in permissions:
        if perm.get("deleted"):
            continue  # tombstoned grant on a shared-drive item: confers nothing
        ptype = perm.get("type")
        if ptype == "user":
            email = perm.get("emailAddress")
            if not email:
                return AclEnvelope(resolvable=False)
            principals.append(f"user:{email.lower()}")
        elif ptype == "group":
            email = perm.get("emailAddress")
            if not email:
                return AclEnvelope(resolvable=False)
            groups.append(f"group:{email.lower()}")
        elif ptype == "domain":
            domain = perm.get("domain")
            if not domain:
                return AclEnvelope(resolvable=False)
            groups.append(f"domain:{domain.lower()}")
        elif ptype == "anyone":
            if anyone_maps_to:
                groups.append(anyone_maps_to)
            else:
                return AclEnvelope(resolvable=False)
        else:
            # Unknown permission type: never guess.
            return AclEnvelope(resolvable=False)
    return AclEnvelope(resolvable=True, principals=principals, groups=groups)


# ---------------------------------------------------------------------------
# Principal registry: principal strings -> int visibility tokens
# ---------------------------------------------------------------------------


class PrincipalRegistry(Protocol):
    """Resolves principal strings to Verity int visibility tokens.

    Principals absent from the returned mapping are unresolved and confer no
    visibility (§6b). If nothing resolves, the item quarantines.
    """

    def resolve(self, principals: Sequence[str]) -> dict[str, int]: ...


class StaticRegistry:
    """Fixed mapping, from config or fixtures. Missing keys stay unresolved."""

    def __init__(self, mapping: Mapping[str, int]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, principals: Sequence[str]) -> dict[str, int]:
        return {p: self._mapping[p] for p in principals if p in self._mapping}


class HttpRegistry:
    """Resolves via the Verity server's admin principals endpoint.

    Contract (server as built — ``admin_principals`` in verity-server):
    ``POST {base}/v1/admin/principals`` → ``{"mappings": {"<canonical>": <int
    token>, ...}, "quarantined": <bool>}``. Null/absent/non-int → unresolved
    (fail-closed). The upsert is idempotent; existing principals keep their token.

    M2 2b — the identity crosswalk (fail-closed, no blind ``user:<email>``):
    a Google-native ``user:<email>`` grant is routed through the request's
    ``emails`` field so the server resolves it against the directory-vouched
    ``idp_subject`` (an UNVOUCHED address resolves to nothing — no implicit
    weld). Its canonical is ``user:<email>`` BY IDENTITY, so the server echoes
    the same string back keyed by canonical and :meth:`resolve` still returns
    ``{input_string: token}``. ``group:``/``domain:`` principals are already
    canonical and ride the ``principals`` field unchanged.
    """

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

    def resolve(self, principals: Sequence[str]) -> dict[str, int]:
        """Resolve principal strings → int tokens, routing ``user:<email>``
        grants through the registry ``emails`` gate (fail-closed on an unvouched
        address). Returns ``{canonical_string: token}``; for Google-native users
        canonical == the input string, so callers key back on their input."""
        if not principals:
            return {}
        emails, others = crosswalk.split_google_principals(principals)
        request = crosswalk.ResolveRequest(principals=others, emails=emails)
        return crosswalk.resolve_via(
            self._client, self._base_url, self._tenant_id, request
        ).mappings


# ---------------------------------------------------------------------------
# Drive transport (real HTTP vs fixtures)
# ---------------------------------------------------------------------------


class DriveTransport(Protocol):
    """Minimal surface over Drive v3 REST, so tests run on recorded fixtures."""

    def get_json(self, path: str, params: Mapping[str, str]) -> dict: ...

    def get_bytes(self, path: str, params: Mapping[str, str]) -> bytes: ...


def load_service_account_credentials(
    delegated_subject: str | None = None,
    scopes: Sequence[str] = (DRIVE_READONLY_SCOPE,),
):
    """BYOT: load the customer's service-account key (google-auth, lazy).

    Reads the JSON key path from ``GOOGLE_APPLICATION_CREDENTIALS``. With
    domain-wide delegation, pass ``delegated_subject`` (the workspace user to
    impersonate); without DWD the service account itself must be granted
    access (e.g. added to shared drives).
    """
    try:
        from google.oauth2 import service_account  # noqa: PLC0415 (lazy by design)
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "google-auth is required for live Drive access: pip install 'verity-ingest[gdrive]'"
        ) from exc

    key_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not key_path:
        raise RuntimeError(
            "GOOGLE_APPLICATION_CREDENTIALS is not set. BYOT: create a service "
            "account in YOUR OWN Google Cloud project, enable domain-wide "
            "delegation for scope drive.readonly, and point this env var at "
            "the downloaded JSON key."
        )
    credentials = service_account.Credentials.from_service_account_file(
        key_path, scopes=list(scopes)
    )
    if delegated_subject:
        credentials = credentials.with_subject(delegated_subject)
    return credentials


class _HttpxAuthResponse:
    """Adapts an httpx response to google.auth.transport.Response."""

    def __init__(self, response: httpx.Response) -> None:
        self.status = response.status_code
        self.headers = response.headers
        self.data = response.content


class _HttpxAuthRequest:
    """google.auth.transport.Request implemented over httpx (no `requests`)."""

    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> _HttpxAuthResponse:
        response = httpx.request(
            method, url, content=body, headers=dict(headers or {}), timeout=timeout or 30.0
        )
        return _HttpxAuthResponse(response)


class HttpDriveTransport:
    """Live Drive v3 REST transport with service-account bearer auth."""

    def __init__(self, credentials: Any, client: httpx.Client | None = None) -> None:
        self._credentials = credentials
        self._client = client or httpx.Client(base_url=DRIVE_BASE_URL, timeout=60.0)
        self._auth_request = _HttpxAuthRequest()

    def _headers(self) -> dict[str, str]:
        if not self._credentials.valid:
            self._credentials.refresh(self._auth_request)
        return {"Authorization": f"Bearer {self._credentials.token}"}

    def _get(self, path: str, params: Mapping[str, str]) -> httpx.Response:
        response = self._client.get(path, params=dict(params), headers=self._headers())
        response.raise_for_status()
        return response

    def get_json(self, path: str, params: Mapping[str, str]) -> dict:
        return self._get(path, params).json()

    def get_bytes(self, path: str, params: Mapping[str, str]) -> bytes:
        return self._get(path, params).content


# ---------------------------------------------------------------------------
# The connector
# ---------------------------------------------------------------------------


class GDriveConnector(Connector):
    name = "gdrive"

    def __init__(self, transport: DriveTransport, config: GDriveConfig | None = None) -> None:
        self._transport = transport
        self.config = config or GDriveConfig()
        # Fact lane (§4.2) accumulators — crawl/batch-scoped, filled as a SIDE
        # EFFECT of the document pass, drained by the runner AFTER the file
        # loop. The document lane (map_permissions → mirrored visibility) is
        # unchanged; this is a strictly additive second lane.
        self._owner = (self.config.delegated_subject or "").strip().lower()
        # canonical_email -> {"is_owner": bool, "domain": str|None, "first_seen_ms": int|None}
        self._corr: dict[str, dict] = {}
        self._org_domains: dict[str, str] = {}  # registrable_domain -> display name
        self._org_first_seen: dict[str, int] = {}

    def _reset_fact_accumulators(self) -> None:
        self._owner = (self.config.delegated_subject or "").strip().lower()
        self._corr = {}
        self._org_domains = {}
        self._org_first_seen = {}

    def _observe_permissions(
        self, permissions: Iterable[Mapping[str, Any]], modified_time: str
    ) -> None:
        """Accumulate person + org-domain evidence from one file's permission
        list. Wrapped by the caller's skip-and-count so a single malformed
        permission never corrupts the accumulator or aborts the crawl. The file
        owner (self) is never recorded as a correspondent.

        Signal (permissions-only — Drive has no display-name / direction data):
        - PERSON lane: type=user with a canonicalizable, non-denylisted,
          non-service-account email that is not the owner. role=owner →
          ``correspondence="owner"``; sharers → ``"shared_with"``.
        - ORG lane: the registrable domain of any type=user email (even a
          role-local one — notifications@github.com still proves github.com) and
          any type=domain permission, minus freemail/placeholder/service-account.
        - type=group / anyone contribute NOTHING (shared mailboxes / public
          links are not identities we deal with — the more selective choice)."""
        ts_ms = _modified_time_to_ms(modified_time)
        for perm in permissions:
            if perm.get("deleted"):
                continue  # tombstoned grant confers nothing (matches map_permissions)
            ptype = perm.get("type")
            if ptype == "user":
                email_raw = perm.get("emailAddress")
                if not email_raw:
                    continue
                # ORG lane runs off the RAW user-email domain, even when the
                # address itself fails the person bar for role-local reasons
                # (parity with gmail: notifications@github.com still proves the
                # org github.com). Service accounts are machines — never an org.
                reg_raw = _registrable_domain(str(email_raw).rsplit("@", 1)[1]) if "@" in str(
                    email_raw
                ) else None
                if (
                    reg_raw is not None
                    and reg_raw not in _SERVICE_ACCOUNT_DOMAINS
                    and not _is_denylisted_domain(reg_raw)
                ):
                    self._org_domains.setdefault(
                        reg_raw, _title_case_label(reg_raw.split(".", 1)[0])
                    )
                    if ts_ms is not None:
                        prev = self._org_first_seen.get(reg_raw)
                        if prev is None or ts_ms < prev:
                            self._org_first_seen[reg_raw] = ts_ms

                # PERSON lane: strict canonical gate.
                canon = _canonicalize_email(email_raw)
                if canon is None:
                    continue  # freemail / placeholder / role-local drops here
                if canon == self._owner:
                    continue  # self is not a correspondent
                reg = _registrable_domain(canon.rsplit("@", 1)[1])
                if reg is not None and reg in _SERVICE_ACCOUNT_DOMAINS:
                    continue  # service accounts are machines, not people
                stat = self._corr.setdefault(
                    canon, {"is_owner": False, "domain": reg, "first_seen_ms": None}
                )
                if perm.get("role") == "owner":
                    stat["is_owner"] = True
                if ts_ms is not None:
                    prev_ms = stat["first_seen_ms"]
                    if prev_ms is None or ts_ms < prev_ms:
                        stat["first_seen_ms"] = ts_ms
            elif ptype == "domain":
                dom = perm.get("domain")
                if not dom:
                    continue
                reg = _registrable_domain(dom)
                if (
                    reg is not None
                    and reg not in _SERVICE_ACCOUNT_DOMAINS
                    and not _is_denylisted_domain(reg)
                ):
                    self._org_domains.setdefault(reg, _title_case_label(reg.split(".", 1)[0]))
                    if ts_ms is not None:
                        prev = self._org_first_seen.get(reg)
                        if prev is None or ts_ms < prev:
                            self._org_first_seen[reg] = ts_ms
            # type=group / anyone: contribute nothing (design choice above).

    # -- push lane ----------------------------------------------------------

    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """No-op: the changes.watch push lane needs a public HTTPS endpoint
        and 7-day channel renewal (SPEC §5); poll is the truth lane and is
        always sufficient. TODO: optional watch lane once the minted-URL
        receiver ships."""
        return
        yield  # pragma: no cover - makes this an async generator

    # -- truth lane ---------------------------------------------------------

    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """Incremental changes.list from `cursor`.

        First run (cursor None): fetch a start page token and return it with
        no events — history before the token is the job of `full_crawl`
        (backfill protocol, §5a), not the change feed.
        """
        self._reset_fact_accumulators()
        if cursor is None:
            data = self._transport.get_json("changes/startPageToken", {"supportsAllDrives": "true"})
            return [], data["startPageToken"]

        events: list[FactEvent | DocumentEvent] = []
        page_token: str | None = cursor
        next_cursor = cursor
        while page_token:
            page = self._transport.get_json(
                "changes",
                {
                    "pageToken": page_token,
                    "pageSize": str(self.config.page_size),
                    "includeRemoved": "true",
                    "supportsAllDrives": "true",
                    "includeItemsFromAllDrives": "true",
                    "fields": _CHANGES_FIELDS,
                },
            )
            for change in page.get("changes", []):
                event = self._event_for_change(change)
                if event is not None:
                    events.append(event)
            if page.get("newStartPageToken"):
                next_cursor = page["newStartPageToken"]
            page_token = page.get("nextPageToken")
        return events, next_cursor

    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl over files.list: content + ACL for every
        non-trashed file (permission drift shows up as re-emitted envelopes;
        the server diffs). Deletions are reconciled by the change feed."""
        self._reset_fact_accumulators()
        page_token: str | None = None
        while True:
            params: dict[str, str] = {
                "pageSize": str(self.config.page_size),
                "q": "trashed = false",
                "fields": f"nextPageToken,files({_FILE_FIELDS})",
                "supportsAllDrives": "true",
                "includeItemsFromAllDrives": "true",
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._transport.get_json("files", params)
            for meta in page.get("files", []):
                yield self._document_event(meta)
            page_token = page.get("nextPageToken")
            if not page_token:
                return

    # -- per-change plumbing --------------------------------------------------

    def _event_for_change(self, change: Mapping[str, Any]) -> GDriveDocumentEvent | None:
        # changeType="drive" entries are shared-drive membership changes;
        # those feed the Identity Plane's directory sync (§6a), not this
        # content connector. Skip anything that is not a file change.
        if change.get("changeType", "file") != "file":
            return None
        file_id = change["fileId"]
        if change.get("removed"):
            return self._removal_event(file_id, change.get("time", ""))
        meta = self._transport.get_json(
            f"files/{file_id}", {"fields": _FILE_FIELDS, "supportsAllDrives": "true"}
        )
        if meta.get("trashed"):
            return self._removal_event(file_id, meta.get("modifiedTime") or change.get("time", ""))
        return self._document_event(meta)

    def _removal_event(self, file_id: str, when: str) -> GDriveDocumentEvent:
        return GDriveDocumentEvent(
            source=self.name,
            document_id=file_id,
            content=b"",
            mime_type="",
            version="",
            acl=AclEnvelope(resolvable=True),  # nothing indexed; grants nothing
            modified_time=when,
            removed=True,
        )

    def _document_event(self, meta: Mapping[str, Any]) -> GDriveDocumentEvent:
        file_id = meta["id"]
        # Reading a file's full sharing list requires writer/owner on that
        # file; a file shared TO us as a reader/commenter returns 403 (and a
        # since-deleted file 404). We cannot mirror an ACL we cannot read, so
        # the file quarantines fail-closed (§5a ACL-before-content, §5e.6) —
        # its content is never pulled or indexed — and the crawl continues
        # instead of dying on one unreadable file.
        try:
            raw_permissions = self._list_permissions(file_id)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                acl = AclEnvelope(resolvable=False)
            else:
                raise
        else:
            acl = map_permissions(raw_permissions, self.config.anyone_maps_to)
            # Fact lane (additive): accumulate person + org-domain evidence off
            # the SAME permissions we just read. Only here — the 403/404
            # quarantine path has nothing to observe. One malformed permission
            # must never corrupt the accumulator or abort the crawl, hence the
            # skip-and-count-and-log guard (mirrors gmail's _observe_*).
            try:
                self._observe_permissions(raw_permissions, meta.get("modifiedTime", ""))
            except (ValueError, KeyError, TypeError) as exc:
                print(f"gdrive: fact-observe skipped on {file_id}: {exc}", file=sys.stderr)
        mime_type = meta.get("mimeType", "")
        content = b""
        # ACL before content (§5a): never pull bytes for an item we already
        # know will quarantine. Binary-extractable formats (PDF/PPTX/XLS(X))
        # download the same alt=media way; extraction happens server-side.
        if acl.resolvable and (is_extractable(mime_type) or is_binary_extractable(mime_type)):
            if mime_type == GOOGLE_DOC_MIME:
                content = self._transport.get_bytes(
                    f"files/{file_id}/export", {"mimeType": DOC_EXPORT_MIME}
                )
            else:
                content = self._transport.get_bytes(f"files/{file_id}", {"alt": "media"})
        return GDriveDocumentEvent(
            source=self.name,
            document_id=file_id,
            content=content,
            mime_type=mime_type,
            version=str(meta.get("version", "")),
            acl=acl,
            modified_time=meta.get("modifiedTime", ""),
            name=meta.get("name", ""),
        )

    def _list_permissions(self, file_id: str) -> list[dict]:
        permissions: list[dict] = []
        page_token: str | None = None
        while True:
            params: dict[str, str] = {
                "fields": _PERMISSIONS_FIELDS,
                "pageSize": str(self.config.page_size),
                "supportsAllDrives": "true",
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._transport.get_json(f"files/{file_id}/permissions", params)
            permissions.extend(page.get("permissions", []))
            page_token = page.get("nextPageToken")
            if not page_token:
                return permissions


# ---------------------------------------------------------------------------
# Sink: POST /v1/ingest/documents (contract; server endpoint in flight)
# ---------------------------------------------------------------------------


def build_document_request(
    event: GDriveDocumentEvent, registry: PrincipalRegistry, tenant_id: str
) -> dict:
    """Build the /v1/ingest/documents body for one event.

    Fail-closed ladder:
    - removal marker → ``{"removed": true}`` body (no visibility needed);
    - unresolvable envelope → quarantine body (no ``visibility`` field);
    - resolvable but zero principals resolve to tokens → quarantine (§6b:
      unmappable principals confer nothing; all-unmappable → quarantine);
    - otherwise → mirrored body with int visibility tokens.
    """
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
    }
    if event.acl.resolvable and is_binary_extractable(event.mime_type):
        # Binary lane: raw bytes, extracted SERVER-side (extract.rs, Tier 1).
        # Mutually exclusive with "content"; filename is the detection hint.
        body["content_base64"] = base64.b64encode(event.content).decode("ascii")
        if event.name:
            body["filename"] = event.name
    else:
        body["content"] = (
            event.content.decode("utf-8", errors="replace")
            if event.acl.resolvable and is_extractable(event.mime_type)
            else None
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


class DocumentSink(Protocol):
    def deliver(self, request: dict) -> None: ...


class VerityDocumentSink:
    """POSTs each request body to ``{base}/v1/ingest/documents``.

    The endpoint is being built in a parallel task; this client codes to the
    contract in the module docstring. Removal markers go to the same endpoint
    with ``removed: true`` — TODO(server): switch to the retire/purge path
    (§8c) when it lands.
    """

    def __init__(
        self,
        base_url: str,
        client: httpx.Client | None = None,
        api_key: str | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=120.0, headers=headers)
        self._base_url = base_url.rstrip("/")
        # Heartbeat accumulators (task 28): what this sink delivered since the
        # last heartbeat() call — tenant/source come from the request bodies.
        self._delivered = 0
        self._tenant_id: str | None = None
        self._source: str | None = None
        self._last_event_at: str | None = None

    def deliver(self, request: dict) -> None:
        response = self._client.post(f"{self._base_url}{DOCUMENTS_PATH}", json=request)
        response.raise_for_status()
        self._delivered += 1
        self._tenant_id = request.get("tenant_id", self._tenant_id)
        self._source = request.get("source", self._source)
        valid_from = request.get("valid_from")
        if valid_from and (self._last_event_at is None or valid_from > self._last_event_at):
            self._last_event_at = valid_from

    def heartbeat(self, cursor: str | None = None) -> None:
        """Best-effort heartbeat to ``POST /v1/admin/connector-status`` after
        a delivery batch; resets the accumulators. Never raises — a heartbeat
        failure must never fail (or replay) a sync that already delivered."""
        if not self._delivered or not self._tenant_id or not self._source:
            return
        try:
            body: dict[str, Any] = {
                "tenant_id": self._tenant_id,
                "source": self._source,
                "items_synced": self._delivered,
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


class DryRunSink:
    """Collects and prints the would-be requests instead of POSTing them."""

    def __init__(self, stream: Any = None) -> None:
        self.requests: list[dict] = []
        self._stream = stream if stream is not None else sys.stdout

    def deliver(self, request: dict) -> None:
        self.requests.append(request)
        print(
            f"[dry-run] POST {DOCUMENTS_PATH}\n{json.dumps(request, indent=2, sort_keys=True)}",
            file=self._stream,
        )


# ---------------------------------------------------------------------------
# Fact lane: selective org/person envelopes → POST /v1/ingest/debezium
# ---------------------------------------------------------------------------
#
# ORG: one SINGLETON per surviving external registrable domain. The `after` has
# only descriptive fields (domain/name/kind) — NONE named email/AccountId/*_id —
# so the resolver's producers see NO merge evidence and the org materializes as
# its own canonical (fold.rs: a singleton is implicitly its own canonical). No
# welding, no domain-star fan-out.
#
# PERSON: only type=user addresses that clear the identity bar. The `after`
# carries a BARE `email` field → EMAIL_FIELDS → the tier-1 email-within-
# namespace producer in namespace customer_contact (source "gdrive", field
# "email"). So a Drive sharer welds cross-source to a Gmail correspondent at the
# same address (gmail:contacts.person, same namespace) WITHOUT welding to any
# internal actor (§4.4 fence) and WITHOUT merging two freemail strangers (they
# never reach here — the freemail gate drops them).
#
# NOTE: connector must be hard-coded "gdrive" here (NOT the module `name`); these
# functions are gdrive-local and must never import gmail (circular import).


def build_org_envelope(
    domain: str, name: str, owner_token: int | None, ts_ms: int | None
) -> dict | None:
    """One Debezium ORG envelope (a singleton canonical). Returns None when the
    owner principal did not resolve (fail closed: no resolvable visibility →
    no fact). `verity_acl` is a TOP-LEVEL sibling of op/source/after."""
    if owner_token is None:
        return None
    source: dict[str, Any] = {"connector": "gdrive", "db": "accounts", "table": "org"}
    if ts_ms is not None:
        source["ts_ms"] = ts_ms
    return {
        "op": "c",
        "source": source,
        # Descriptive-only: no field named email/AccountId/*_id → no merge
        # evidence → singleton → its own canonical.
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
    source: dict[str, Any] = {"connector": "gdrive", "db": "contacts", "table": "person"}
    if ts_ms is not None:
        source["ts_ms"] = ts_ms
    after: dict[str, Any] = {
        "id": email,
        # BARE `email` → EMAIL_FIELDS → tier-1 email-within-namespace producer.
        # This is the weld key: a gmail:contacts.person of the same email folds
        # to the same canonical.
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


def select_person_facts(corr: Mapping[str, dict], owner_token: int | None) -> list[dict]:
    """Build the PERSON envelopes for accumulated Drive correspondents.

    Permissions-only: no display name, no direction logic — the accumulator has
    already applied the identity bar (canonicalize → drop freemail/placeholder/
    role-local; drop the owner; drop service accounts). Re-assert the canonical
    gate belt-and-suspenders so a caller-built stat can't smuggle one past.
    ``correspondence`` is ``"owner"`` (the file owner) or ``"shared_with"`` (a
    sharer). Empty list when the owner token is unresolvable (fail closed)."""
    if owner_token is None:
        return []
    envelopes: list[dict] = []
    for email in sorted(corr):
        canon = _canonicalize_email(email)
        if canon is None or canon != email:
            continue
        stat = corr[email]
        correspondence = "owner" if stat.get("is_owner") else "shared_with"
        name = None  # permissions-only: no display name; the bare email welds fine
        domain = stat.get("domain") or _registrable_domain(email.split("@", 1)[1])
        env = build_person_envelope(
            email, name, domain, correspondence, owner_token, stat.get("first_seen_ms")
        )
        if env is not None:
            envelopes.append(env)
    return envelopes


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
    """`jane@vendor.io` → `•••@vendor.io`. Domain in clear (org identity)."""
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
    connector: GDriveConnector,
    registry: PrincipalRegistry,
    fact_sink: FactSink,
) -> tuple[int, int]:
    """Drain the crawl-scoped fact accumulators into the fact sink and return
    ``(orgs, persons)`` emitted. Call AFTER the document loop.

    Fail closed: resolve the owner principal ONCE; if it does not resolve to an
    int token (or there is no delegated subject at all — a shared-drive crawl),
    the fact lane is DISABLED for this run — NO org and NO person envelopes are
    built or posted (a count-only line is logged). The document lane is
    unaffected."""
    if not connector.config.emit_facts:
        return (0, 0)
    owner = connector._owner
    owner_token: int | None = None
    if owner:
        principal = f"user:{owner}"
        owner_token = registry.resolve([principal]).get(principal)
    if owner_token is None:
        print("gdrive: fact lane disabled — owner principal did not resolve")
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
        person_envelopes = select_person_facts(connector._corr, owner_token)
    fact_sink.deliver([*org_envelopes, *person_envelopes], pk="id")
    return (len(org_envelopes), len(person_envelopes))


# ---------------------------------------------------------------------------
# Runner: python -m verity_ingest.connectors.gdrive --once [--dry-run]
# ---------------------------------------------------------------------------


def _load_cursor(state_file: Path) -> str | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text()).get("cursor")


def _save_cursor(state_file: Path, cursor: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"cursor": cursor}, indent=2) + "\n")


def _is_indexable_body(body: Mapping[str, Any]) -> bool:
    """Whether a document body is one the ``/v1/ingest/documents`` endpoint
    accepts. A quarantine marker (an ACL we could not read or map — fail
    closed, §5a/§5e.6) and a removal marker are NOT accepted there; they are
    skipped so an unscopable or deleted file never aborts a whole-Drive crawl.
    An unscopable file is simply not indexed — nothing leaks — and the skip is
    counted and reported, never silent."""
    if body.get("removed"):
        return False
    if body.get("acl_provenance") == "quarantined":
        return False
    return True


def run_once(
    connector: GDriveConnector,
    registry: PrincipalRegistry,
    sink: DocumentSink,
    state_file: Path,
    fact_sink: FactSink | None = None,
    acl_lane: AclDiffLane | None = None,
) -> int:
    """One poll cycle: load cursor, poll, deliver, checkpoint. Returns the
    number of delivered requests. The cursor is checkpointed only after
    delivery succeeds, so a crash replays the window (at-least-once).

    When ``fact_sink`` is given, the selective org/person facts accumulated over
    this poll batch (a side-effect of the document pass) are delivered AFTER the
    documents — an additive second lane that never affects the document count.

    When ``acl_lane`` is given, each delivered document's effective principal set
    is diffed against its last-seen set; a TIGHTENING (a reader lost access)
    emits ``/v1/ingest/acl-change`` so the server retracts the derived chunks.
    Purely additive — never affects the document count or the cursor."""
    cursor = _load_cursor(state_file)
    events, next_cursor = asyncio.run(connector.poll(cursor))
    delivered = 0
    skipped = 0
    for event in events:
        assert isinstance(event, GDriveDocumentEvent)
        body = build_document_request(event, registry, connector.config.tenant_id)
        if not _is_indexable_body(body):
            skipped += 1
            continue
        sink.deliver(body)
        delivered += 1
        # ACL-diff lane (additive): only for resolvable ACLs — an unresolvable
        # one quarantines and confers no principals, so it has no diff baseline.
        if acl_lane is not None and event.acl.resolvable:
            acl_lane.observe(
                event.document_id,
                [*event.acl.principals, *event.acl.groups],
                source=event.source,
                document_id=event.document_id,
            )
    if acl_lane is not None:
        acl_lane.flush()
        if acl_lane.emitted:
            print(f"gdrive: emitted {acl_lane.emitted} acl-change (tightening) retraction(s)")
    if skipped:
        print(f"gdrive: skipped {skipped} file(s) (unreadable/unmappable ACL or removed)")
    if fact_sink is not None:
        orgs, persons = deliver_facts(connector, registry, fact_sink)
        if orgs or persons:
            print(f"gdrive: emitted {orgs} org, {persons} person fact(s)")
    _save_cursor(state_file, next_cursor)
    # Best-effort connector heartbeat (task 28): sinks that support it
    # (VerityDocumentSink) report the batch; DryRunSink et al. just skip.
    heartbeat = getattr(sink, "heartbeat", None)
    if heartbeat is not None:
        heartbeat(cursor=next_cursor)
    return delivered


def run_backfill(
    connector: GDriveConnector,
    registry: PrincipalRegistry,
    sink: DocumentSink,
    reporter: BackfillReporter | None = None,
    *,
    flush_every: int = 20,
    fact_sink: FactSink | None = None,
) -> int:
    """§5a reconciliation backfill: drive :meth:`GDriveConnector.full_crawl`
    (``files.list`` over every non-trashed file) into the sink, reporting
    progress to the backfill dashboard.

    ``files.list`` gives no cheap up-front count, so the run is opened with an
    indeterminate total (``total=None``) and a live processed count — honest
    about what Drive can and can't tell us in advance. Progress is flushed every
    ``flush_every`` deliveries so the bar moves without a post per item. A crash
    mid-crawl is reported as a ``failed`` run (with the error) and then
    re-raised; a clean finish marks the run ``completed``. Returns the number of
    delivered requests."""
    if reporter is not None:
        reporter.start(total=None)
    delivered = 0
    pending = 0
    skipped = 0
    failed = 0

    async def _drive() -> None:
        nonlocal delivered, pending, skipped, failed
        async for event in connector.full_crawl():
            assert isinstance(event, GDriveDocumentEvent)
            body = build_document_request(event, registry, connector.config.tenant_id)
            # Fail-closed skip: a file whose ACL we couldn't read/map, or that
            # was removed, isn't sent to the index endpoint (it wouldn't be
            # accepted and shouldn't be indexed) — counted, not fatal.
            if not _is_indexable_body(body):
                skipped += 1
                continue
            # One file's ingest failure never aborts a whole-Drive backfill:
            # record it and press on, so a single malformed/oversized/rejected
            # document can't cost the other 1,400.
            try:
                sink.deliver(body)
            except httpx.HTTPError:
                # HTTPError is the base class: status errors, timeouts, and
                # transport failures all get skipped-and-counted so one slow or
                # rejected document can't abort the whole-Drive backfill.
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
    if skipped or failed:
        print(
            f"gdrive: skipped {skipped} file(s) (unreadable/unmappable ACL or "
            f"removed), {failed} ingest failure(s)"
        )
    # Fact lane (additive): after the whole crawl has drained, resolve the owner
    # token once and deliver the deduped org/person envelopes. A delivery
    # failure here must not fail the (already-delivered) document backfill.
    if fact_sink is not None:
        try:
            orgs, persons = deliver_facts(connector, registry, fact_sink)
        except httpx.HTTPError as exc:
            print(f"gdrive: fact delivery failed ({exc}); document backfill unaffected")
        else:
            if orgs or persons:
                print(f"gdrive: emitted {orgs} org, {persons} person fact(s)")
    return delivered


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.connectors.gdrive",
        description="Verity Google Drive connector (truth lane, Tier-A ACL mirroring).",
    )
    parser.add_argument("--once", action="store_true", help="run a single poll cycle and exit")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="run the §5a full reconciliation crawl (files.list) once, reporting "
        "progress to the backfill dashboard, then exit",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print request bodies instead of POSTing"
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.environ.get("GDRIVE_STATE_FILE", ".verity/gdrive_cursor.json")),
        help="JSON cursor checkpoint file",
    )
    parser.add_argument("--tenant-id", default=os.environ.get("VERITY_TENANT_ID", "default"))
    parser.add_argument(
        "--verity-url",
        default=os.environ.get("VERITY_URL", "http://localhost:8080"),
        help="Verity server base URL (sink + principal resolution)",
    )
    parser.add_argument(
        "--principal-map",
        type=Path,
        default=None,
        help="JSON file {principal: int token} -> StaticRegistry instead of the server endpoint",
    )
    parser.add_argument(
        "--anyone-maps-to",
        default=os.environ.get("GDRIVE_ANYONE_MAPS_TO"),
        help='map type=anyone permissions to this principal (e.g. "org:everyone"); '
        "default: anyone-shared items quarantine",
    )
    parser.add_argument(
        "--subject",
        default=os.environ.get("GDRIVE_DELEGATED_SUBJECT"),
        help="domain-wide-delegation subject (workspace user to impersonate)",
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
        help="emit person facts for real sharers (default on; orgs-only with --no-people)",
    )
    parser.add_argument("--no-people", dest="emit_people", action="store_false")
    args = parser.parse_args(argv)

    config = GDriveConfig(
        tenant_id=args.tenant_id,
        anyone_maps_to=args.anyone_maps_to,
        delegated_subject=args.subject,
        emit_facts=args.facts,
        emit_people=args.emit_people,
    )
    credentials = load_service_account_credentials(delegated_subject=config.delegated_subject)
    connector = GDriveConnector(HttpDriveTransport(credentials), config)

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
        # A server-triggered backfill pre-mints the run_id and passes it via
        # VERITY_BACKFILL_RUN_ID so the console panel can poll GET
        # /v1/admin/backfill keyed on THIS run; a CLI backfill leaves it unset and
        # the reporter self-mints (uuid4).
        run_id = os.environ.get("VERITY_BACKFILL_RUN_ID") or None
        reporter = (
            None
            if args.dry_run
            else BackfillReporter(
                args.verity_url,
                config.tenant_id,
                connector.name,
                api_key=api_key,
                run_id=run_id,
            )
        )
        delivered = run_backfill(connector, registry, sink, reporter, fact_sink=fact_sink)
        print(f"gdrive: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(connector, registry, sink, args.state_file, fact_sink=fact_sink)
        print(f"gdrive: delivered {delivered} request(s); cursor -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
