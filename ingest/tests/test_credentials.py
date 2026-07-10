"""Tests for the shared credential lifecycle (SPEC.md §5e.2).

All HTTP is exercised through ``httpx.MockTransport``; no live token
endpoints. The four credential shapes are covered plus the shared
401-retry-once hook and the static-key expiry telemetry.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from verity_ingest.credentials import (
    ClientCredentials,
    Credential,
    RefreshToken,
    ServiceAccountJwt,
    StaticKey,
    request_with_auth_retry,
)

TOKEN_URL = "https://issuer.test/oauth2/token"


def make_token_transport(
    minted: list[dict], *, expires_in: float | None = None, rotate_refresh: bool = False
) -> httpx.MockTransport:
    """Serves the token endpoint; records each grant request; mints
    ``token-1``, ``token-2``, ... in order."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == TOKEN_URL
        minted.append({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        payload: dict = {"access_token": f"token-{len(minted)}", "token_type": "Bearer"}
        if expires_in is not None:
            payload["expires_in"] = expires_in
        if rotate_refresh:
            payload["refresh_token"] = f"rotated-{len(minted)}"
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handler)


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------- StaticKey ----------


def test_static_key_value_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_KEY", "from-env")
    assert asyncio.run(StaticKey("SOME_KEY").token()) == "from-env"
    assert asyncio.run(StaticKey("SOME_KEY", value="direct").token()) == "direct"


def test_static_key_missing_fails_closed_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOME_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SOME_KEY"):
        StaticKey("SOME_KEY")


def test_static_key_invalidate_is_noop_and_satisfies_protocol() -> None:
    key = StaticKey(value="k")
    key.invalidate()
    assert asyncio.run(key.token()) == "k"
    assert isinstance(key, Credential)


def test_static_key_expiry_telemetry_warns_once_inside_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="verity_ingest.credentials"):
        key = StaticKey(value="k", expiry=utcnow() + timedelta(days=3))
        asyncio.run(key.token())  # second check must not re-warn
    warnings = [r for r in caplog.records if "rotate it soon" in r.message]
    assert len(warnings) == 1


def test_static_key_expiry_telemetry_expired(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="verity_ingest.credentials"):
        StaticKey(value="k", expiry=utcnow() - timedelta(seconds=1))
    assert any("EXPIRED" in r.message for r in caplog.records)


def test_static_key_no_warning_outside_window(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="verity_ingest.credentials"):
        StaticKey(value="k", expiry=utcnow() + timedelta(days=30))
    assert caplog.records == []


# ---------- ClientCredentials ----------


def test_client_credentials_grant_shape_and_caching() -> None:
    minted: list[dict] = []
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        scope="api",
        client=httpx.AsyncClient(transport=make_token_transport(minted, expires_in=3600)),
    )

    async def run() -> tuple[str, str]:
        return await cred.token(), await cred.token()

    first, second = asyncio.run(run())
    assert first == second == "token-1"
    assert minted == [
        {
            "grant_type": "client_credentials",
            "client_id": "cid",
            "client_secret": "csec",
            "scope": "api",
        }
    ]
    assert cred.expires_at is not None
    remaining = cred.expires_at - utcnow()
    assert timedelta(seconds=3500) < remaining <= timedelta(seconds=3600)


def test_client_credentials_refreshes_within_60s_skew() -> None:
    minted: list[dict] = []
    # expires_in=30 < the 60s skew: the token is stale the moment it is minted,
    # so a second token() call mints again.
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        client=httpx.AsyncClient(transport=make_token_transport(minted, expires_in=30)),
    )

    async def run() -> tuple[str, str]:
        return await cred.token(), await cred.token()

    assert asyncio.run(run()) == ("token-1", "token-2")
    assert len(minted) == 2


def test_client_credentials_no_expires_in_caches_until_invalidate() -> None:
    # Salesforce's documented shape: no expires_in at all.
    minted: list[dict] = []
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        client=httpx.AsyncClient(transport=make_token_transport(minted)),
    )

    async def run() -> list[str]:
        tokens = [await cred.token(), await cred.token()]
        cred.invalidate()
        tokens.append(await cred.token())
        return tokens

    assert asyncio.run(run()) == ["token-1", "token-1", "token-2"]
    assert cred.expires_at is None


def test_client_credentials_on_refresh_hook_fires_per_mint() -> None:
    refreshed: list[str] = []
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        on_refresh=refreshed.append,
        client=httpx.AsyncClient(transport=make_token_transport([])),
    )

    async def run() -> None:
        await cred.token()
        await cred.token()  # cached: no second hook call
        cred.invalidate()
        await cred.token()

    asyncio.run(run())
    assert refreshed == ["token-1", "token-2"]


# ---------- RefreshToken ----------


def test_refresh_token_grant_shape_and_rotation_adoption() -> None:
    minted: list[dict] = []
    cred = RefreshToken(
        TOKEN_URL,
        refresh_token="rt-original",
        client_id="cid",
        client_secret="csec",
        client=httpx.AsyncClient(transport=make_token_transport(minted, rotate_refresh=True)),
    )

    async def run() -> None:
        await cred.token()
        cred.invalidate()
        await cred.token()

    asyncio.run(run())
    # The second mint must use the refresh token rotated in by the first.
    assert [m["refresh_token"] for m in minted] == ["rt-original", "rotated-1"]
    assert all(m["grant_type"] == "refresh_token" for m in minted)
    assert cred.refresh_token == "rotated-2"


def test_refresh_token_public_client_omits_secret() -> None:
    minted: list[dict] = []
    cred = RefreshToken(
        TOKEN_URL,
        refresh_token="rt",
        client_id="cid",
        client=httpx.AsyncClient(transport=make_token_transport(minted)),
    )
    asyncio.run(cred.token())
    assert "client_secret" not in minted[0]


# ---------- ServiceAccountJwt (signer-callback seam) ----------


def test_service_account_jwt_sync_signer_caches_and_refreshes() -> None:
    calls: list[int] = []

    def signer() -> tuple[str, datetime | None]:
        calls.append(1)
        return f"jwt-token-{len(calls)}", utcnow() + timedelta(hours=1)

    refreshed: list[str] = []
    cred = ServiceAccountJwt(signer, on_refresh=refreshed.append)

    async def run() -> list[str]:
        tokens = [await cred.token(), await cred.token()]
        cred.invalidate()
        tokens.append(await cred.token())
        return tokens

    assert asyncio.run(run()) == ["jwt-token-1", "jwt-token-1", "jwt-token-2"]
    assert refreshed == ["jwt-token-1", "jwt-token-2"]
    assert isinstance(cred, Credential)


def test_service_account_jwt_async_signer() -> None:
    async def signer() -> tuple[str, datetime | None]:
        return "async-jwt", None

    cred = ServiceAccountJwt(signer)
    assert asyncio.run(cred.token()) == "async-jwt"
    assert cred.expires_at is None


# ---------- the shared 401-retry-once hook ----------


def make_api_transport(
    api_log: list[str], *, reject: set[str] = frozenset(), always_401: bool = False
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers["Authorization"]
        api_log.append(auth)
        if always_401 or auth in reject:
            return httpx.Response(401, json=[{"errorCode": "INVALID_SESSION_ID"}])
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


def test_401_invalidates_and_retries_exactly_once() -> None:
    minted: list[dict] = []
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        client=httpx.AsyncClient(transport=make_token_transport(minted)),
    )
    api_log: list[str] = []

    async def run() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=make_api_transport(api_log, reject={"Bearer token-1"})
        ) as client:
            return await request_with_auth_retry(client, cred, "GET", "https://api.test/x")

    response = asyncio.run(run())
    assert response.status_code == 200
    assert api_log == ["Bearer token-1", "Bearer token-2"]
    assert len(minted) == 2


def test_second_401_is_returned_not_retried() -> None:
    minted: list[dict] = []
    cred = ClientCredentials(
        TOKEN_URL,
        client_id="cid",
        client_secret="csec",
        client=httpx.AsyncClient(transport=make_token_transport(minted)),
    )
    api_log: list[str] = []

    async def run() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=make_api_transport(api_log, always_401=True)
        ) as client:
            return await request_with_auth_retry(client, cred, "GET", "https://api.test/x")

    response = asyncio.run(run())
    assert response.status_code == 401  # surfaced to the caller, not raised here
    assert api_log == ["Bearer token-1", "Bearer token-2"]  # exactly one retry
    assert len(minted) == 2


def test_401_on_static_key_retries_with_same_key_then_surfaces() -> None:
    cred = StaticKey(value="static-k")
    api_log: list[str] = []

    async def run() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=make_api_transport(api_log, always_401=True)
        ) as client:
            return await request_with_auth_retry(client, cred, "GET", "https://api.test/x")

    response = asyncio.run(run())
    assert response.status_code == 401
    # invalidate() is a no-op on a static key: same key both attempts.
    assert api_log == ["Bearer static-k", "Bearer static-k"]


def test_retry_preserves_caller_headers_and_params() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(401 if len(seen) == 1 else 200, json={})

    cred = StaticKey(value="k")

    async def run() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await request_with_auth_retry(
                client,
                cred,
                "GET",
                "https://api.test/q",
                params={"q": "SELECT Id FROM Account"},
                headers={"X-Extra": "yes"},
            )

    assert asyncio.run(run()).status_code == 200
    for request in seen:
        assert request.url.params["q"] == "SELECT Id FROM Account"
        assert request.headers["X-Extra"] == "yes"
        assert request.headers["Authorization"] == "Bearer k"
