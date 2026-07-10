"""Credential lifecycle abstraction (SPEC.md §5e.2, engineering consequence 1).

BYOT doctrine: every connector authenticates with a credential the customer
created in their *own* tenant — never a vendor-hosted OAuth app. The July 2026
survey shows those credentials come in exactly four shapes, so the lifecycle
machinery (caching, refresh, expiry telemetry, 401 recovery) is absorbed ONCE
here rather than reimplemented per connector:

- :class:`StaticKey` — API key / PAT / private-app token from an env var.
  Optional ``expiry`` enables telemetry: a warning is logged when the key is
  within 7 days of its configured expiry (Zendesk/Atlassian-style token
  sunsets are how connectors die silently).
- :class:`ClientCredentials` — self-registered OAuth client, machine grant
  (``grant_type=client_credentials``). Caches the access token until 60s
  before expiry. Some issuers (Salesforce) omit ``expires_in`` entirely; the
  token is then cached until :func:`request_with_auth_retry` hits a 401 and
  calls :meth:`invalidate`.
- :class:`RefreshToken` — ``grant_type=refresh_token`` rotation (Dropbox
  et al.). Rotated refresh tokens returned by the issuer are adopted.
- :class:`ServiceAccountJwt` — JWT-bearer flows behind a *signer callback
  seam*: the ingest core takes no crypto/JWT dependency; the operator (or an
  optional extra) supplies a callable that mints ``(token, expires_at)``.
  The Google Drive connector deliberately keeps its google-auth path instead
  of this class: google-auth already implements the Google-specific JWT
  grant, domain-wide-delegation subject impersonation, and clock-skew
  handling, and it is an optional extra (``verity-ingest[gdrive]``) that
  fixture tests never import. This seam exists for every *other* JWT-bearer
  source — and google-auth itself can be adapted through it.

The **401-retry-once hook** is :func:`request_with_auth_retry`: on a 401 the
cached token is invalidated and the request retried exactly once with a
freshly minted token. A second 401 is returned to the caller — retrying
further would spin on a genuinely revoked credential.

``on_refresh`` is the webhook-health re-establishment hook (§5e.2: Asana's
webhooks die with their token): it is called with each newly minted token so
a connector can re-register delivery.
"""

from __future__ import annotations

import inspect
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol, runtime_checkable

import httpx

logger = logging.getLogger(__name__)

#: Static-key expiry telemetry window: warn when this close to expiry.
EXPIRY_WARNING_WINDOW = timedelta(days=7)

#: Refresh this many seconds *before* the token's stated expiry.
REFRESH_SKEW_SECONDS = 60.0

OnRefresh = Callable[[str], None]


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


@runtime_checkable
class Credential(Protocol):
    """One credential of any of the four §5e.2 shapes.

    ``expires_at`` is the current token's expiry (None = unknown/never).
    ``on_refresh`` is called with each newly minted token (webhook-health
    re-establishment); ``invalidate()`` drops any cached token so the next
    ``token()`` mints a fresh one — the 401-recovery path.
    """

    expires_at: datetime | None
    on_refresh: OnRefresh | None

    async def token(self) -> str: ...

    def invalidate(self) -> None: ...


class StaticKey:
    """A static API key / PAT, from an env var or passed directly.

    ``value`` (if given) wins over the env var. Missing both fails
    immediately — fail closed, and at startup rather than mid-poll.
    """

    def __init__(
        self,
        env_var: str | None = None,
        *,
        value: str | None = None,
        expiry: datetime | None = None,
        missing_hint: str = "a static API key/token (BYOT — created in your own tenant)",
    ) -> None:
        key = value if value is not None else (os.environ.get(env_var) if env_var else None)
        if not key:
            raise RuntimeError(f"no static credential: set {env_var} to {missing_hint}")
        self.value = key
        self.expires_at = expiry
        self.on_refresh: OnRefresh | None = None
        self._env_var = env_var
        self._warned = False
        self._warn_if_expiring()

    def _warn_if_expiring(self) -> None:
        if self.expires_at is None or self._warned:
            return
        remaining = self.expires_at - _utcnow()
        if remaining > EXPIRY_WARNING_WINDOW:
            return
        self._warned = True
        name = self._env_var or "static credential"
        if remaining.total_seconds() <= 0:
            logger.warning(
                "static credential %s EXPIRED at %s — rotate it now",
                name,
                self.expires_at.isoformat(),
            )
        else:
            logger.warning(
                "static credential %s expires at %s (within %d days) — rotate it soon",
                name,
                self.expires_at.isoformat(),
                EXPIRY_WARNING_WINDOW.days,
            )

    async def token(self) -> str:
        self._warn_if_expiring()
        return self.value

    def invalidate(self) -> None:
        """No-op: a static key cannot be re-minted. A 401 on a static key
        surfaces to the operator (rotate the key) instead of retrying."""


class _OAuthTokenClient:
    """Shared machinery for the two token-endpoint shapes (client_credentials
    and refresh_token): mint, cache until ``expires_at - skew``, invalidate."""

    def __init__(
        self,
        token_url: str,
        *,
        refresh_skew: float = REFRESH_SKEW_SECONDS,
        on_refresh: OnRefresh | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.token_url = token_url
        self.expires_at: datetime | None = None
        self.on_refresh = on_refresh
        self._refresh_skew = refresh_skew
        self._client = client
        self._owns_client = client is None
        self._token: str | None = None

    def _grant_data(self) -> dict[str, str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _adopt_extra(self, payload: dict) -> None:
        """Subclass hook for extra response fields (e.g. rotated refresh_token)."""

    def _stale(self) -> bool:
        if self._token is None:
            return True
        if self.expires_at is None:
            # Issuer stated no expiry (e.g. Salesforce client_credentials):
            # cache until a 401 invalidates.
            return False
        return _utcnow() >= self.expires_at - timedelta(seconds=self._refresh_skew)

    async def token(self) -> str:
        if not self._stale():
            assert self._token is not None
            return self._token
        return await self._mint()

    async def _mint(self) -> str:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        response = await self._client.post(self.token_url, data=self._grant_data())
        response.raise_for_status()
        payload = response.json()
        self._token = payload["access_token"]
        expires_in = payload.get("expires_in")
        self.expires_at = (
            _utcnow() + timedelta(seconds=float(expires_in)) if expires_in is not None else None
        )
        self._adopt_extra(payload)
        if self.on_refresh is not None:
            self.on_refresh(self._token)
        return self._token

    def invalidate(self) -> None:
        self._token = None
        self.expires_at = None

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


class ClientCredentials(_OAuthTokenClient):
    """Self-registered OAuth client, ``grant_type=client_credentials``.

    The §5e.2 trend absorbed once: "API key" → "self-registered OAuth client
    with machine grants" (Salesforce Connected Apps, Zendesk post-2026, Box).
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        refresh_skew: float = REFRESH_SKEW_SECONDS,
        on_refresh: OnRefresh | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(token_url, refresh_skew=refresh_skew, on_refresh=on_refresh, client=client)
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

    def _grant_data(self) -> dict[str, str]:
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope
        return data


class RefreshToken(_OAuthTokenClient):
    """``grant_type=refresh_token`` rotation (Dropbox-style short-lived
    access tokens). If the issuer rotates the refresh token in the response,
    the new one is adopted."""

    def __init__(
        self,
        token_url: str,
        refresh_token: str,
        client_id: str,
        client_secret: str | None = None,
        *,
        refresh_skew: float = REFRESH_SKEW_SECONDS,
        on_refresh: OnRefresh | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(token_url, refresh_skew=refresh_skew, on_refresh=on_refresh, client=client)
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.client_secret = client_secret

    def _grant_data(self) -> dict[str, str]:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret is not None:
            data["client_secret"] = self.client_secret
        return data

    def _adopt_extra(self, payload: dict) -> None:
        rotated = payload.get("refresh_token")
        if rotated:
            self.refresh_token = rotated


#: A signer mints ``(access_token, expires_at)``; expires_at None = unknown.
JwtSigner = Callable[[], "tuple[str, datetime | None] | Awaitable[tuple[str, datetime | None]]"]


class ServiceAccountJwt:
    """Service-account JWT-bearer credential behind a signer callback seam.

    The ingest core carries no JWT/crypto dependency; ``signer`` (sync or
    async) does the vendor-specific assertion signing and token exchange and
    returns ``(token, expires_at)``. See the module docstring for why the
    Google Drive connector keeps its google-auth transport instead of this —
    and how google-auth plugs into this seam for any future caller::

        creds = load_service_account_credentials(...)
        def signer():
            creds.refresh(request)          # google-auth signs + exchanges
            return creds.token, creds.expiry
    """

    def __init__(
        self,
        signer: JwtSigner,
        *,
        refresh_skew: float = REFRESH_SKEW_SECONDS,
        on_refresh: OnRefresh | None = None,
    ) -> None:
        self.expires_at: datetime | None = None
        self.on_refresh = on_refresh
        self._signer = signer
        self._refresh_skew = refresh_skew
        self._token: str | None = None

    def _stale(self) -> bool:
        if self._token is None:
            return True
        if self.expires_at is None:
            return False
        return _utcnow() >= self.expires_at - timedelta(seconds=self._refresh_skew)

    async def token(self) -> str:
        if not self._stale():
            assert self._token is not None
            return self._token
        minted: Any = self._signer()
        if inspect.isawaitable(minted):
            minted = await minted
        self._token, self.expires_at = minted
        if self.on_refresh is not None:
            self.on_refresh(self._token)
        return self._token

    def invalidate(self) -> None:
        self._token = None
        self.expires_at = None


async def request_with_auth_retry(
    client: httpx.AsyncClient,
    credential: Credential,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """Send with ``Authorization: Bearer <token>``; on a 401, invalidate the
    cached token and retry **exactly once** with a freshly minted one.

    This is the §5e.2 401-retry-once hook, shared by every connector whose
    issuer states no ``expires_in`` (Salesforce) or drifts its clock. A second
    401 is *returned* (not raised): the credential itself is bad and the
    caller's ``raise_for_status`` surfaces it to the operator.
    """
    base_headers = dict(kwargs.pop("headers", None) or {})
    for attempt in (1, 2):
        headers = {**base_headers, "Authorization": f"Bearer {await credential.token()}"}
        response = await client.request(method, url, headers=headers, **kwargs)
        if response.status_code == 401 and attempt == 1:
            credential.invalidate()
            continue
        return response
    raise RuntimeError("unreachable")  # pragma: no cover
