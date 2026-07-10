"""Thin HTTP client for the Verity REST plane (crates/verity-server).

Writes go to the trusted connector plane (``POST /v1/ingest/documents``,
admin-token gated); reads mint a scope handle (``POST /v1/scopes``) from the
sink's visibility policy and call ``POST /v1/recall`` — the same mandatory
pre-filtered path every other caller gets. Nothing here can widen visibility:
the policy the constructor demanded is the ceiling of everything the sink
writes and reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

#: The SPEC §5e.4 doctrine, verbatim enough to teach at the constructor:
#: ecosystem loaders strip source ACLs by construction, so the sink lane is
#: always policy-based and a missing policy can only ever quarantine.
VISIBILITY_TEACHING = (
    "visibility_policy is required and has no default (SPEC §5e.4): ecosystem "
    "loaders strip source ACLs by construction, so this sink lane is always "
    "policy-based (acl_provenance=admin-assigned). Pass the materialized "
    "principal tokens allowed to read what you write, e.g. "
    "visibility_policy=[1]. Anything arriving without a policy is "
    "quarantined, never permissively indexed."
)

#: Re-mint a cached scope handle when it has less than this long to live.
SCOPE_EXPIRY_MARGIN = timedelta(seconds=60)


def require_visibility_policy(value: object, owner: str) -> list[int]:
    """Fail closed with the teaching message unless ``value`` is a non-empty
    list of materialized principal tokens (ints; bools rejected)."""
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"{owner}: {VISIBILITY_TEACHING}")
    tokens: list[int] = []
    for token in value:
        if isinstance(token, bool) or not isinstance(token, int):
            raise ValueError(f"{owner}: {VISIBILITY_TEACHING}")
        tokens.append(token)
    return tokens


def parse_timestamp(value: str) -> datetime:
    """The server emits RFC 3339 with a Z suffix (chrono `DateTime<Utc>`)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class VerityClient:
    """Synchronous REST client: document ingest, scope minting (cached per
    entity scope), scoped recall/brief, and forget."""

    def __init__(
        self,
        verity_url: str,
        tenant_id: str,
        *,
        admin_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._admin_token = admin_token
        self._http = httpx.Client(
            base_url=verity_url.rstrip("/"), timeout=timeout, transport=transport
        )
        # entity-scope tuple -> (scope_handle, expires_at)
        self._scopes: dict[tuple[str, ...], tuple[str, datetime]] = {}

    # ---------- write plane (admin-token gated) ----------

    def _admin_headers(self) -> dict[str, str]:
        if self._admin_token:
            return {"Authorization": f"Bearer {self._admin_token}"}
        return {}

    def ingest_document(
        self,
        *,
        source: str,
        document_id: str,
        content: str,
        entities: list[str],
        visibility: list[int],
    ) -> dict:
        """POST /v1/ingest/documents: one document version in -> one L0
        episode + deterministic chunks out, under the admin-assigned policy.
        Returns ``{"episode_id": ..., "chunks_indexed": ...}``."""
        response = self._http.post(
            "/v1/ingest/documents",
            json={
                "tenant_id": self.tenant_id,
                "source": source,
                "document_id": document_id,
                "content": content,
                "entities": entities,
                "visibility": visibility,
                "acl_provenance": "admin-assigned",
            },
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        return response.json()

    # ---------- read plane (scope-handle gated) ----------

    def mint_scope(
        self,
        principals: list[int],
        *,
        entity_scope: list[str] | None = None,
        ttl_seconds: int = 3600,
    ) -> str:
        """POST /v1/scopes, cached per entity scope until near expiry. The
        principals are the sink's visibility policy — the scope can read
        exactly what the sink may write, nothing more."""
        key = tuple(entity_scope or [])
        cached = self._scopes.get(key)
        now = datetime.now(timezone.utc)
        if cached and cached[1] - SCOPE_EXPIRY_MARGIN > now:
            return cached[0]
        body: dict = {
            "tenant_id": self.tenant_id,
            "principals": principals,
            "ttl_seconds": ttl_seconds,
        }
        if entity_scope:
            body["entity_scope"] = entity_scope
        response = self._http.post("/v1/scopes", json=body)
        response.raise_for_status()
        payload = response.json()
        handle = payload["scope_handle"]
        self._scopes[key] = (handle, parse_timestamp(payload["expires_at"]))
        return handle

    def recall(
        self,
        *,
        scope_handle: str,
        k: int,
        text: str | None = None,
        embedding: list[float] | None = None,
    ) -> list[dict]:
        """POST /v1/recall: scoped hybrid recall. At least one query leg is
        required — the server encodes ``text`` locally for the dense leg."""
        body: dict = {"scope_handle": scope_handle, "k": k}
        if text is not None:
            body["text"] = text
        if embedding is not None:
            body["embedding"] = embedding
        response = self._http.post("/v1/recall", json=body)
        response.raise_for_status()
        return response.json()

    def brief(self, *, scope_handle: str, entity: str) -> dict:
        """GET /v1/briefs/{entity}: newest memory for one entity tag, no
        query leg needed (recency-ordered, currently capped at 10 chunks)."""
        response = self._http.get(
            f"/v1/briefs/{quote(entity, safe='')}",
            params={"scope_handle": scope_handle},
        )
        response.raise_for_status()
        return response.json()

    def forget(self, *, scope_handle: str, kind: str, id: str, reason: str) -> dict:
        """POST /v1/forget: invalidate-don't-delete retirement of one chunk
        or one episode (plus everything derived from it)."""
        response = self._http.post(
            "/v1/forget",
            json={
                "scope_handle": scope_handle,
                "ref": {"kind": kind, "id": id},
                "reason": reason,
            },
        )
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._http.close()
