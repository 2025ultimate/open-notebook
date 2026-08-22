"""Tests for the optional Firebase auth mode.

Tokens here are signed with a real generated RSA key and verified through the
real code path — only the JWKS *fetch* is stubbed. Mocking the verification
itself would test nothing: the whole point of this module is that a token is
rejected unless its signature, audience, issuer, expiry and email all hold.
"""

import time
from typing import Any, Dict, Optional

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from open_notebook.exceptions import AuthenticationError, ConfigurationError
from open_notebook.utils.firebase_auth import (
    FirebaseAuthConfig,
    FirebaseJwksCache,
    load_firebase_config,
    verify_firebase_token,
)

PROJECT_ID = "demo-notebook"
KID = "test-key-1"
ALLOWED = "owner@example.com"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwk_set(rsa_key):
    jwk = RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


@pytest.fixture
def config():
    return FirebaseAuthConfig(
        project_id=PROJECT_ID,
        allowed_emails=frozenset({ALLOWED}),
        api_key="web-api-key",
    )


def make_token(
    rsa_key,
    *,
    kid: str = KID,
    algorithm: str = "RS256",
    **overrides: Any,
) -> str:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": f"https://securetoken.google.com/{PROJECT_ID}",
        "aud": PROJECT_ID,
        "sub": "firebase-uid-123",
        "iat": now,
        "exp": now + 3600,
        "auth_time": now,
        "email": ALLOWED,
        "email_verified": True,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not _OMIT}
    return jwt.encode(claims, rsa_key, algorithm=algorithm, headers={"kid": kid})


class _Omit:
    """Sentinel so a test can remove a claim rather than blank it."""


_OMIT = _Omit()


def fake_jwks_client(jwk_set, *, calls: Optional[list] = None, max_age: int = 3600):
    """An httpx.AsyncClient stand-in that serves the JWK set."""

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url, **kwargs):
            if calls is not None:
                calls.append(url)
            return httpx.Response(
                200,
                json=jwk_set,
                headers={"cache-control": f"public, max-age={max_age}"},
                request=httpx.Request("GET", url),
            )

    return FakeAsyncClient


@pytest.fixture
def cache(monkeypatch, jwk_set):
    from open_notebook.utils import firebase_auth

    monkeypatch.setattr(firebase_auth.httpx, "AsyncClient", fake_jwks_client(jwk_set))
    return FirebaseJwksCache()


class TestConfigLoading:
    def test_requires_project_id(self, monkeypatch):
        monkeypatch.delenv("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID", raising=False)
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS", ALLOWED)
        with pytest.raises(ConfigurationError, match="PROJECT_ID"):
            load_firebase_config()

    def test_requires_a_non_empty_allowlist(self, monkeypatch):
        """An empty allowlist would let any Google account in — refuse it."""
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID", PROJECT_ID)
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS", "   ,  ")
        with pytest.raises(ConfigurationError, match="ALLOWED_EMAILS"):
            load_firebase_config()

    def test_parses_and_normalises_the_allowlist(self, monkeypatch):
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID", PROJECT_ID)
        monkeypatch.setenv(
            "OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS",
            " Owner@Example.com , second@example.com ",
        )
        monkeypatch.delenv("OPEN_NOTEBOOK_FIREBASE_API_KEY", raising=False)
        monkeypatch.delenv("OPEN_NOTEBOOK_FIREBASE_AUTH_DOMAIN", raising=False)

        config = load_firebase_config()

        assert config.allowed_emails == frozenset(
            {"owner@example.com", "second@example.com"}
        )
        assert config.issuer == f"https://securetoken.google.com/{PROJECT_ID}"
        assert config.resolved_auth_domain() == f"{PROJECT_ID}.firebaseapp.com"

    def test_web_config_exposes_only_public_fields(self, config):
        assert config.web_config() == {
            "project_id": PROJECT_ID,
            "api_key": "web-api-key",
            "auth_domain": f"{PROJECT_ID}.firebaseapp.com",
        }


class TestTokenVerification:
    @pytest.mark.asyncio
    async def test_accepts_a_valid_token(self, rsa_key, config, cache):
        claims = await verify_firebase_token(
            make_token(rsa_key), config, jwks_cache=cache
        )
        assert claims["email"] == ALLOWED
        assert claims["sub"] == "firebase-uid-123"

    @pytest.mark.asyncio
    async def test_rejects_expired_token(self, rsa_key, config, cache):
        now = int(time.time())
        token = make_token(rsa_key, iat=now - 7200, exp=now - 3600)
        with pytest.raises(AuthenticationError, match="expired"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_wrong_audience(self, rsa_key, config, cache):
        token = make_token(rsa_key, aud="someone-elses-project")
        with pytest.raises(AuthenticationError):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_wrong_issuer(self, rsa_key, config, cache):
        token = make_token(rsa_key, iss="https://evil.example.com/")
        with pytest.raises(AuthenticationError):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_token_signed_by_another_key(self, config, cache):
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = make_token(attacker_key)
        with pytest.raises(AuthenticationError):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_unsigned_token(self, rsa_key, config, cache):
        """`alg: none` must never be accepted."""
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": config.issuer,
                "aud": PROJECT_ID,
                "sub": "uid",
                "iat": now,
                "exp": now + 3600,
                "email": ALLOWED,
                "email_verified": True,
            },
            key="",
            algorithm="none",
            headers={"kid": KID},
        )
        with pytest.raises(AuthenticationError, match="algorithm"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_unverified_email(self, rsa_key, config, cache):
        token = make_token(rsa_key, email_verified=False)
        with pytest.raises(AuthenticationError, match="not verified"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_email_outside_the_allowlist(self, rsa_key, config, cache):
        token = make_token(rsa_key, email="stranger@example.com")
        with pytest.raises(AuthenticationError, match="not authorized"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_allowlist_match_is_case_insensitive(self, rsa_key, config, cache):
        token = make_token(rsa_key, email="Owner@Example.COM")
        claims = await verify_firebase_token(token, config, jwks_cache=cache)
        assert claims["sub"] == "firebase-uid-123"

    @pytest.mark.asyncio
    async def test_rejects_missing_email(self, rsa_key, config, cache):
        token = make_token(rsa_key, email=_OMIT)
        with pytest.raises(AuthenticationError, match="no email"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_unknown_key_id(self, rsa_key, config, cache):
        token = make_token(rsa_key, kid="rotated-away")
        with pytest.raises(AuthenticationError, match="unrecognised key"):
            await verify_firebase_token(token, config, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_rejects_garbage(self, config, cache):
        with pytest.raises(AuthenticationError, match="Malformed"):
            await verify_firebase_token("not-a-jwt", config, jwks_cache=cache)


class TestJwksCache:
    @pytest.mark.asyncio
    async def test_keys_are_fetched_once_and_reused(self, monkeypatch, jwk_set):
        from open_notebook.utils import firebase_auth

        calls: list = []
        monkeypatch.setattr(
            firebase_auth.httpx, "AsyncClient", fake_jwks_client(jwk_set, calls=calls)
        )
        cache = FirebaseJwksCache()

        await cache.get_key(KID)
        await cache.get_key(KID)

        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_ttl_is_clamped_to_the_floor(self, monkeypatch, jwk_set):
        from open_notebook.utils import firebase_auth

        monkeypatch.setattr(
            firebase_auth.httpx,
            "AsyncClient",
            fake_jwks_client(jwk_set, max_age=1),
        )
        cache = FirebaseJwksCache()
        await cache.get_key(KID)

        # A one-second max-age must not turn every request into a fetch.
        assert (
            cache._expires_at - time.monotonic() >= firebase_auth._MIN_TTL_SECONDS - 1
        )

    @pytest.mark.asyncio
    async def test_fetch_failure_surfaces_as_auth_error(self, monkeypatch):
        from open_notebook.utils import firebase_auth

        class BoomClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def get(self, url, **kwargs):
                raise httpx.ConnectError("network down")

        monkeypatch.setattr(firebase_auth.httpx, "AsyncClient", BoomClient)

        with pytest.raises(AuthenticationError, match="signing keys"):
            await FirebaseJwksCache().get_key(KID)


def build_app(monkeypatch, jwk_set, **env: str) -> TestClient:
    """A minimal app wired with the real middleware and the given env."""
    from open_notebook.utils import firebase_auth

    monkeypatch.setattr(firebase_auth.httpx, "AsyncClient", fake_jwks_client(jwk_set))
    for key in (
        "OPEN_NOTEBOOK_AUTH_MODE",
        "OPEN_NOTEBOOK_PASSWORD",
        "OPEN_NOTEBOOK_FIREBASE_PROJECT_ID",
        "OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS",
        "OPEN_NOTEBOOK_FIREBASE_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    from api.auth import PasswordAuthMiddleware

    app = FastAPI()
    app.add_middleware(PasswordAuthMiddleware, excluded_paths=["/health"])

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/api/notebooks")
    async def notebooks():
        return []

    return TestClient(app)


class TestMiddleware:
    def test_password_mode_still_works(self, monkeypatch, jwk_set):
        client = build_app(monkeypatch, jwk_set, OPEN_NOTEBOOK_PASSWORD="hunter2")

        assert client.get("/api/notebooks").status_code == 401
        assert (
            client.get(
                "/api/notebooks", headers={"Authorization": "Bearer wrong"}
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/notebooks", headers={"Authorization": "Bearer hunter2"}
            ).status_code
            == 200
        )

    def test_password_mode_disabled_without_a_password(self, monkeypatch, jwk_set):
        client = build_app(monkeypatch, jwk_set)
        assert client.get("/api/notebooks").status_code == 200

    def test_firebase_mode_accepts_a_valid_token(self, monkeypatch, jwk_set, rsa_key):
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="firebase",
            OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=PROJECT_ID,
            OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS=ALLOWED,
        )
        response = client.get(
            "/api/notebooks",
            headers={"Authorization": f"Bearer {make_token(rsa_key)}"},
        )
        assert response.status_code == 200

    def test_firebase_mode_rejects_a_password(self, monkeypatch, jwk_set):
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="firebase",
            OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=PROJECT_ID,
            OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS=ALLOWED,
            OPEN_NOTEBOOK_PASSWORD="hunter2",
        )
        response = client.get(
            "/api/notebooks", headers={"Authorization": "Bearer hunter2"}
        )
        assert response.status_code == 401

    def test_firebase_mode_is_always_enforced_even_without_a_password(
        self, monkeypatch, jwk_set
    ):
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="firebase",
            OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=PROJECT_ID,
            OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS=ALLOWED,
        )
        assert client.get("/api/notebooks").status_code == 401

    def test_misconfigured_firebase_fails_closed(self, monkeypatch, jwk_set, rsa_key):
        """No allowlist means deny everything, not allow everything."""
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="firebase",
            OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=PROJECT_ID,
        )
        response = client.get(
            "/api/notebooks",
            headers={"Authorization": f"Bearer {make_token(rsa_key)}"},
        )
        assert response.status_code == 401
        assert "not configured" in response.json()["detail"]

    def test_excluded_paths_bypass_firebase(self, monkeypatch, jwk_set):
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="firebase",
            OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=PROJECT_ID,
            OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS=ALLOWED,
        )
        assert client.get("/health").status_code == 200

    def test_unknown_mode_falls_back_to_password(self, monkeypatch, jwk_set):
        client = build_app(
            monkeypatch,
            jwk_set,
            OPEN_NOTEBOOK_AUTH_MODE="oauth-something",
            OPEN_NOTEBOOK_PASSWORD="hunter2",
        )
        assert (
            client.get(
                "/api/notebooks", headers={"Authorization": "Bearer hunter2"}
            ).status_code
            == 200
        )


class TestAuthStatusEndpoint:
    @pytest.mark.asyncio
    async def test_password_mode_shape(self, monkeypatch):
        from api.routers.auth import get_auth_status

        monkeypatch.delenv("OPEN_NOTEBOOK_AUTH_MODE", raising=False)
        monkeypatch.setenv("OPEN_NOTEBOOK_PASSWORD", "hunter2")

        status = await get_auth_status()

        assert status["auth_enabled"] is True
        assert status["auth_mode"] == "password"
        assert "firebase" not in status

    @pytest.mark.asyncio
    async def test_firebase_mode_returns_public_web_config_only(self, monkeypatch):
        from api.routers.auth import get_auth_status

        monkeypatch.setenv("OPEN_NOTEBOOK_AUTH_MODE", "firebase")
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID", PROJECT_ID)
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS", ALLOWED)
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_API_KEY", "web-api-key")

        status = await get_auth_status()

        assert status["auth_enabled"] is True
        assert status["auth_mode"] == "firebase"
        assert status["configured"] is True
        assert status["firebase"] == {
            "project_id": PROJECT_ID,
            "api_key": "web-api-key",
            "auth_domain": f"{PROJECT_ID}.firebaseapp.com",
        }
        # The allowlist must never leave the server.
        assert ALLOWED not in str(status)

    @pytest.mark.asyncio
    async def test_misconfigured_firebase_reports_unconfigured(self, monkeypatch):
        from api.routers.auth import get_auth_status

        monkeypatch.setenv("OPEN_NOTEBOOK_AUTH_MODE", "firebase")
        monkeypatch.setenv("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID", PROJECT_ID)
        monkeypatch.delenv("OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS", raising=False)

        status = await get_auth_status()

        assert status["auth_enabled"] is True
        assert status["configured"] is False
        assert "firebase" not in status
