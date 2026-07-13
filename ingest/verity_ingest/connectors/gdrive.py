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
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Mapping, Protocol, Sequence

import httpx

from verity_ingest.connector import AclEnvelope, Connector, DocumentEvent, FactEvent
from verity_ingest.connectors.backfill import BackfillReporter

DRIVE_BASE_URL = "https://www.googleapis.com/drive/v3"
DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"

GOOGLE_DOC_MIME = "application/vnd.google-apps.document"
DOC_EXPORT_MIME = "text/plain"

PRINCIPALS_PATH = "/v1/admin/principals"
DOCUMENTS_PATH = "/v1/ingest/documents"
CONNECTOR_STATUS_PATH = "/v1/admin/connector-status"

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
    ``POST {base}/v1/admin/principals`` with ``{"tenant_id": "<uuid>",
    "principals": [...]}`` → ``{"mappings": {"<principal>": <int token>,
    ...}}``. Null/absent/non-int → unresolved (fail-closed). The upsert is
    idempotent server-side; existing principals keep their token forever.
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
        if not principals:
            return {}
        response = self._client.post(
            f"{self._base_url}{PRINCIPALS_PATH}",
            json={"tenant_id": self._tenant_id, "principals": list(principals)},
        )
        response.raise_for_status()
        return {
            principal: token
            for principal, token in response.json().get("mappings", {}).items()
            if isinstance(token, int)
        }


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
) -> int:
    """One poll cycle: load cursor, poll, deliver, checkpoint. Returns the
    number of delivered requests. The cursor is checkpointed only after
    delivery succeeds, so a crash replays the window (at-least-once)."""
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
    if skipped:
        print(f"gdrive: skipped {skipped} file(s) (unreadable/unmappable ACL or removed)")
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
    args = parser.parse_args(argv)

    config = GDriveConfig(
        tenant_id=args.tenant_id,
        anyone_maps_to=args.anyone_maps_to,
        delegated_subject=args.subject,
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
        print(f"gdrive: backfill delivered {delivered} request(s)")
        return 0

    while True:
        delivered = run_once(connector, registry, sink, args.state_file)
        print(f"gdrive: delivered {delivered} request(s); cursor -> {args.state_file}")
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
