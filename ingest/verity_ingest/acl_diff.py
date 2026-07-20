"""Connector ACL-diff lane (M1 build #5): turn a source ACL TIGHTENING into a
server-side retraction.

On each sync, a connector already fetches every record's effective principal
set (gdrive: ``map_permissions``; hubspot: ``record_principals``). This module
diffs that set against the LAST-SEEN set persisted per record; when a principal
is REMOVED (a tightening), it emits an ``AclChange`` that the server turns into
``correct_chunk_acl`` / ``correct_fact_acl`` (``POST /v1/ingest/acl-change``),
retracting the lost principal from every derived chunk/fact — including behind
``?as_of=`` (the value-history carve-out).

Precision + fail-closed rules (SPEC §7b rule 3):

- Only TIGHTENINGS emit. A GRANT (a principal ADDED) never emits here — grants
  take effect on the next mint, via the normal ingest path that re-materializes
  the record's visibility. Emitting on a grant would be a no-op at best (REPLACE
  semantics already carry the new set) and risks racing the content write.
- A record with NO prior state never emits (its first sync is not a change).
- The emitted ``verity_acl.visibility`` is the NEW FULL principal set (REPLACE
  semantics — the server does not diff). ``removed_principals`` is carried for
  observability/audit only.
- The last-seen set is always written back (grant or tighten) so the next sync
  diffs against current truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any, Protocol, Sequence

# The server route the server-side handler (main.rs `ingest_acl_change`) serves.
ACL_CHANGE_PATH = "/v1/ingest/acl-change"


@dataclass
class AclChange:
    """One record's ACL tightening, ready to POST to ``/v1/ingest/acl-change``.

    Exactly one of ``document_id`` (→ ``correct_chunk_acl``) or the
    ``entity_id``/``field`` fact key (→ ``correct_fact_acl``) is set, matching
    the object the connector materialized the record as.
    """

    source: str
    # Object identity — a document lineage (gdrive) OR a fact key (hubspot).
    document_id: str | None = None
    entity_id: str | None = None
    field: str | None = None
    # The NEW FULL principal set after the tightening (REPLACE semantics).
    new_principals: list[str] = dc_field(default_factory=list)
    # The principals that LOST access (observability/audit only).
    removed_principals: list[str] = dc_field(default_factory=list)

    def to_request(self, tenant_id: str, visibility: list[int]) -> dict[str, Any]:
        """Build the ``/v1/ingest/acl-change`` body. ``visibility`` is the
        server-resolved int-token form of ``new_principals`` (REPLACE)."""
        if self.document_id is not None:
            target: dict[str, Any] = {"object": {"document_id": self.document_id}}
        else:
            target = {"fact": {"entity_id": self.entity_id, "field": self.field}}
        return {
            "tenant_id": tenant_id,
            "source": self.source,
            **target,
            "verity_acl": {
                "visibility": visibility,
                "confidentiality": "internal",
                "acl_provenance": "mirrored",
            },
            "reason": "source_unshare",
        }


class AclState:
    """Per-record last-seen principal-set store, persisted as a JSON sidecar.

    Keyed by ``record_id`` (the connector's stable object id: a Drive file id or
    a HubSpot ``{object}:{id}``). Values are sorted principal-string lists.
    Written 0600 (a decrypted-adjacent sharing map must not be group/world
    readable), mirroring the connector cursor files.
    """

    def __init__(self, state_file: Path) -> None:
        self._path = Path(state_file)
        self._seen: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text())
        except FileNotFoundError:
            return
        except json.JSONDecodeError:
            # A corrupt sidecar means we lose the diff baseline; treat every
            # record as first-seen (no spurious tighten). The next write heals it.
            return
        if isinstance(raw, dict):
            self._seen = {
                str(k): sorted(str(p) for p in v)
                for k, v in raw.items()
                if isinstance(v, list)
            }

    def last_seen(self, record_id: str) -> list[str] | None:
        return self._seen.get(record_id)

    def remember(self, record_id: str, principals: list[str]) -> None:
        self._seen[record_id] = sorted(set(principals))

    def flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._seen, sort_keys=True))
        # 0600: owner-only, like the connector cursor/credential files.
        self._path.chmod(0o600)


def diff_acl(
    state: AclState,
    record_id: str,
    current_principals: list[str],
    *,
    source: str,
    document_id: str | None = None,
    entity_id: str | None = None,
    field: str | None = None,
) -> AclChange | None:
    """Diff a record's current principal set against its last-seen set.

    Returns an ``AclChange`` iff the set TIGHTENED (some principal was removed);
    ``None`` for a first sync, a grant-only change, or no change. Always writes
    the current set back into ``state`` (caller flushes once per sync).
    """
    current = sorted(set(current_principals))
    prior = state.last_seen(record_id)
    # Always update the baseline to current truth.
    state.remember(record_id, current)

    if prior is None:
        return None  # first sight of this record — not a change
    removed = [p for p in prior if p not in set(current)]
    if not removed:
        return None  # grant-only or unchanged — grants take effect on next mint
    return AclChange(
        source=source,
        document_id=document_id,
        entity_id=entity_id,
        field=field,
        new_principals=current,
        removed_principals=sorted(removed),
    )


class _Resolver(Protocol):
    """Principal-string → int-token resolver (the connectors' PrincipalRegistry
    surface). Missing keys stay unresolved (fail closed)."""

    def resolve(self, principals: Sequence[str]) -> dict[str, int]: ...


class _Poster(Protocol):
    """Minimal httpx.Client surface (real or fixture transport)."""

    def post(self, url: str, json: Any) -> Any: ...  # noqa: A002 — httpx kwarg name


def emit_acl_change(
    change: AclChange,
    *,
    tenant_id: str,
    registry: _Resolver,
    client: _Poster,
    base_url: str,
) -> dict[str, Any]:
    """Resolve the change's NEW FULL principal set to int tokens and POST it to
    ``/v1/ingest/acl-change`` (REPLACE semantics).

    Fail-closed on resolution: only principals the registry maps become tokens;
    the server's ``correct_*_acl`` then makes the object visible to EXACTLY that
    resolved set. An un-shared principal that no longer maps simply isn't in the
    new set — precisely the intended retraction.
    """
    mapping = registry.resolve(change.new_principals)
    visibility = sorted({mapping[p] for p in change.new_principals if p in mapping})
    body = change.to_request(tenant_id, visibility)
    response = client.post(f"{base_url.rstrip('/')}{ACL_CHANGE_PATH}", json=body)
    # httpx.Response has raise_for_status; fixture transports may not.
    raise_for_status = getattr(response, "raise_for_status", None)
    if callable(raise_for_status):
        raise_for_status()
    return body


class AclDiffLane:
    """Per-sync ACL-diff lane: bundles the last-seen store, the principal
    registry, and the emit client so a connector can drive it per record with a
    single ``observe(...)`` call, then ``flush()`` once at the end.

    Additive and best-effort by construction: a connector wires it only when a
    server URL + registry are available; a run without it behaves exactly as
    before. On a TIGHTENING it POSTs ``/v1/ingest/acl-change`` (the server
    retracts the derived chunks/facts); otherwise it only updates the baseline.
    Returns the emitted-change count so the runner can log it.
    """

    def __init__(
        self,
        state: AclState,
        *,
        tenant_id: str,
        registry: _Resolver,
        client: _Poster,
        base_url: str,
    ) -> None:
        self._state = state
        self._tenant_id = tenant_id
        self._registry = registry
        self._client = client
        self._base_url = base_url
        self.emitted = 0

    def observe(
        self,
        record_id: str,
        current_principals: list[str],
        *,
        source: str,
        document_id: str | None = None,
        entity_id: str | None = None,
        field: str | None = None,
    ) -> AclChange | None:
        change = diff_acl(
            self._state,
            record_id,
            current_principals,
            source=source,
            document_id=document_id,
            entity_id=entity_id,
            field=field,
        )
        if change is None:
            return None
        emit_acl_change(
            change,
            tenant_id=self._tenant_id,
            registry=self._registry,
            client=self._client,
            base_url=self._base_url,
        )
        self.emitted += 1
        return change

    def flush(self) -> None:
        self._state.flush()
