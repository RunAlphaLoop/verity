"""Identity crosswalk client (M2 slice 2b).

The canonical-principal registry lives server-side (migration 0039:
``canonical_principal`` + ``principal_sso_alias`` + ``principal_crosswalk``).
A connector never mints ``user:<sourceEmail>`` blind anymore: it hands the
INGEST boundary the *directory-unverified* owner id it actually holds and lets
the server resolve it to the ONE canonical principal string
(``user:<primaryEmail.lower()>``) the directory vouched — or drop it.

Three typed inputs, one round-trip to ``POST /v1/admin/principals`` (the shared
token allocator, extended by B1 to resolve at the ingest boundary):

- ``principals`` — already-canonical strings (groups, domains, gdirectory self
  rows). Stamped as-is; no crosswalk step. The Google-native user email is
  canonical BY IDENTITY (``user:<email>`` is exactly what the directory
  vouched), so it too can ride ``principals`` when the connector already knows
  it is directory-native — but gdrive/gmail route it through ``emails`` so an
  UNVOUCHED address (never in the directory) fails closed instead of minting a
  fresh token.
- ``emails`` — Google-native grant/header addresses AND Salesforce
  ``FederationIdentifier`` values. Resolved via ``idp_subject`` or a declared
  ``principal_sso_alias``. An unvouched value → dropped (no implicit weld).
- ``resolvable`` — ``(source, local_id)`` owners (HubSpot ``ownerId``,
  Salesforce ``005…`` UserId) resolved via ``principal_crosswalk``. A miss or an
  ``active=false`` row → dropped.

Fail-closed everywhere: every ``None`` the server returns is a DROP, never a
guess. When the caller declared owners to resolve (``emails``/``resolvable``
non-empty) but NONE survived, the server replies ``{"quarantined": true}`` and
the connector must quarantine the record rather than index it open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

# The shared token allocator + ingest-boundary crosswalk resolver (B1).
PRINCIPALS_PATH = "/v1/admin/principals"

#: Group-edge member MARKERS (M2 2b): a nested group-membership edge may carry a
#: member that is NOT yet canonical — the sink resolves the marker through the
#: registry before mirroring the edge (an unresolved marker DROPS the edge, fail
#: closed; never a blind ``user:<sourceEmail>`` weld).
#: - ``fed:<subject>`` — a Salesforce group-member 005's ``FederationIdentifier``
#:   SSO subject, resolved via the ``emails`` gate (idp_subject/SSO-alias match).
#: - ``hubspot-owner:<id>`` — a HubSpot team member's ``ownerId``, resolved via
#:   the ``(hubspot, ownerId)`` crosswalk.
FEDERATION_MEMBER_PREFIX = "fed:"
CROSSWALK_MEMBER_PREFIX = "hubspot-owner:"


@dataclass(frozen=True)
class CrosswalkOwner:
    """One source-local owner id needing a ``principal_crosswalk`` resolution."""

    source: str
    local_id: str


@dataclass
class ResolveRequest:
    """Typed principals to resolve in one ``/v1/admin/principals`` round-trip.

    ``principals`` are already-canonical; ``emails`` resolve via ``idp_subject``/
    SSO-alias; ``resolvable`` via the ``(source, local_id)`` crosswalk. All three
    fold into the same token allocation; every unresolved input is dropped.
    """

    principals: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    resolvable: list[CrosswalkOwner] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.principals or self.emails or self.resolvable)

    def declared_resolvable(self) -> bool:
        """True iff the caller asked the server to resolve owners (so a
        zero-survivor response is a fail-closed quarantine, not a plain miss)."""
        return bool(self.emails or self.resolvable)

    def to_body(self, tenant_id: str) -> dict[str, Any]:
        body: dict[str, Any] = {"tenant_id": tenant_id}
        if self.principals:
            body["principals"] = list(self.principals)
        if self.emails:
            body["emails"] = list(self.emails)
        if self.resolvable:
            body["resolvable"] = [
                {"source": o.source, "local_id": o.local_id} for o in self.resolvable
            ]
        return body


@dataclass(frozen=True)
class ResolveResult:
    """The server's response to a typed resolve.

    ``mappings`` is canonical-string → int token for every SURVIVING principal.
    ``quarantined`` is the server's fail-closed signal: owners were declared but
    none resolved, so the record must be quarantined (never indexed open).
    """

    mappings: dict[str, int]
    quarantined: bool

    def tokens(self) -> list[int]:
        """Conferred tokens, sorted + deduped — the visibility set to stamp.

        A connector that does NOT know the canonical string (Salesforce divergent
        login, HubSpot ownerId) stamps exactly these tokens: each surviving owner
        contributes its canonical's token, an unresolved owner contributes
        nothing. Sorting makes the stamped set deterministic across runs."""
        return sorted(set(self.mappings.values()))


class _Poster(Protocol):
    """Minimal ``httpx.Client`` surface (real client or a fixture transport)."""

    def post(self, url: str, json: Any) -> Any: ...  # noqa: A002 — httpx kwarg


def resolve_via(
    client: _Poster,
    base_url: str,
    tenant_id: str,
    request: ResolveRequest,
) -> ResolveResult:
    """POST a typed ``ResolveRequest`` to ``/v1/admin/principals`` and parse the
    ``{mappings, quarantined}`` response.

    An empty request short-circuits (no round-trip). Only int tokens survive the
    parse (a null/absent/non-int mapping value stays unresolved — fail closed).
    """
    if request.is_empty():
        return ResolveResult(mappings={}, quarantined=False)
    response = client.post(
        f"{base_url.rstrip('/')}{PRINCIPALS_PATH}",
        json=request.to_body(tenant_id),
    )
    raise_for_status = getattr(response, "raise_for_status", None)
    if callable(raise_for_status):
        raise_for_status()
    payload = response.json()
    mappings = {
        principal: token
        for principal, token in (payload.get("mappings") or {}).items()
        if isinstance(token, int)
    }
    return ResolveResult(mappings=mappings, quarantined=bool(payload.get("quarantined")))


def split_google_principals(principals: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split canonical principal strings into (emails, non_user_principals).

    A ``user:<email>`` grant is Google-native and MUST resolve through the
    registry ``emails`` path (so an unvouched address fails closed instead of
    minting a fresh token); its canonical is ``user:<email>`` by identity, so the
    server echoes the same string back keyed by canonical. Everything else
    (``group:``/``domain:``) is already canonical and rides ``principals``.
    """
    emails: list[str] = []
    others: list[str] = []
    for principal in principals:
        if principal.startswith("user:"):
            emails.append(principal[len("user:") :])
        else:
            others.append(principal)
    return emails, others
