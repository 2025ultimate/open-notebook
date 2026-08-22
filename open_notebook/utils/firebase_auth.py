"""Firebase ID token verification for the optional `firebase` auth mode.

Open Notebook is a single-workspace tool (see
docs/7-DEVELOPMENT/decisions/PDR-001-single-user-first.md): this module
authenticates *who is at the door*, it does not scope data per user. Everyone
who passes the allowlist shares the same notebooks, exactly as everyone who
knows the shared password does today.

Verification follows Google's published rules for Firebase ID tokens, without
the `firebase-admin` SDK — that package pulls in grpc and google-cloud for what
is an RS256 signature check against a public JWKS, and it wants a
service-account file on disk. We fetch the JWKS over httpx (async, so the
middleware never blocks the event loop) and verify with PyJWT.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from loguru import logger

from open_notebook.exceptions import AuthenticationError, ConfigurationError
from open_notebook.utils.encryption import get_secret_from_env

# Google's public keys for Firebase ID tokens, in JWK form.
FIREBASE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/"
    "securetoken@system.gserviceaccount.com"
)

# Firebase always signs ID tokens with RS256. Pinning the algorithm list is what
# stops an attacker swapping in `none` or an HMAC alg keyed on the public cert.
_ALGORITHMS = ["RS256"]

# Bounds for the JWKS cache TTL taken from the response's Cache-Control.
_MIN_TTL_SECONDS = 300
_MAX_TTL_SECONDS = 86_400
_DEFAULT_TTL_SECONDS = 3_600

# An unknown `kid` normally means Google rotated its signing keys, so we refetch.
# Bogus tokens can carry an unknown kid too, so refetching is rate-limited to
# stop a stream of junk requests turning into a stream of outbound fetches.
_REFRESH_COOLDOWN_SECONDS = 300

_CACHE_CONTROL_MAX_AGE = re.compile(r"max-age=(\d+)")


@dataclass(frozen=True)
class FirebaseAuthConfig:
    """Resolved Firebase settings for this instance.

    `api_key` and `auth_domain` are the *web* config the browser SDK needs.
    They are public identifiers, not secrets — Firebase web apps ship them in
    client bundles — which is why /api/auth/status may hand them out.
    """

    project_id: str
    allowed_emails: FrozenSet[str]
    api_key: Optional[str] = None
    auth_domain: Optional[str] = None

    @property
    def issuer(self) -> str:
        return f"https://securetoken.google.com/{self.project_id}"

    def resolved_auth_domain(self) -> str:
        return self.auth_domain or f"{self.project_id}.firebaseapp.com"

    def web_config(self) -> Dict[str, str]:
        """The subset the frontend needs to initialise the Firebase JS SDK."""
        return {
            "project_id": self.project_id,
            "api_key": self.api_key or "",
            "auth_domain": self.resolved_auth_domain(),
        }


def _parse_allowed_emails(raw: Optional[str]) -> FrozenSet[str]:
    if not raw:
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def load_firebase_config() -> FirebaseAuthConfig:
    """Build the Firebase config from the environment.

    Raises ConfigurationError when the instance asks for firebase mode but the
    settings are unusable. The allowlist is mandatory on purpose: a Firebase
    project with Google sign-in enabled accepts *any* Google account, so an
    empty allowlist would publish the workspace to the entire internet. Failing
    to start is the safe reading of an ambiguous config.
    """
    project_id = (
        get_secret_from_env("OPEN_NOTEBOOK_FIREBASE_PROJECT_ID") or ""
    ).strip()
    if not project_id:
        raise ConfigurationError(
            "OPEN_NOTEBOOK_AUTH_MODE=firebase requires "
            "OPEN_NOTEBOOK_FIREBASE_PROJECT_ID to be set."
        )

    allowed_emails = _parse_allowed_emails(
        get_secret_from_env("OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS")
    )
    if not allowed_emails:
        raise ConfigurationError(
            "OPEN_NOTEBOOK_AUTH_MODE=firebase requires "
            "OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS to list at least one address. "
            "Without it every Google account on the internet could sign in."
        )

    api_key = (get_secret_from_env("OPEN_NOTEBOOK_FIREBASE_API_KEY") or "").strip()
    auth_domain = (
        get_secret_from_env("OPEN_NOTEBOOK_FIREBASE_AUTH_DOMAIN") or ""
    ).strip()

    return FirebaseAuthConfig(
        project_id=project_id,
        allowed_emails=allowed_emails,
        api_key=api_key or None,
        auth_domain=auth_domain or None,
    )


class FirebaseJwksCache:
    """Async, TTL-cached fetcher for Google's Firebase signing keys."""

    def __init__(self, url: str = FIREBASE_JWKS_URL) -> None:
        self._url = url
        self._keys: Dict[str, Any] = {}
        self._expires_at: float = 0.0
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()

    def _ttl_from_headers(self, headers: httpx.Headers) -> int:
        match = _CACHE_CONTROL_MAX_AGE.search(headers.get("cache-control", ""))
        if not match:
            return _DEFAULT_TTL_SECONDS
        return max(_MIN_TTL_SECONDS, min(_MAX_TTL_SECONDS, int(match.group(1))))

    async def _refresh(self) -> None:
        async with self._lock:
            # Another coroutine may have refreshed while we waited for the lock.
            if self._keys and time.monotonic() < self._expires_at:
                return
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(self._url)
                    response.raise_for_status()
                    payload = response.json()
            except Exception as e:
                raise AuthenticationError(
                    f"Could not fetch Firebase signing keys: {e}"
                ) from e

            keys = {
                jwk["kid"]: RSAAlgorithm.from_jwk(jwk)
                for jwk in payload.get("keys", [])
                if jwk.get("kid")
            }
            if not keys:
                raise AuthenticationError(
                    "Firebase signing key endpoint returned no usable keys"
                )
            self._keys = keys
            self._expires_at = time.monotonic() + self._ttl_from_headers(
                response.headers
            )
            self._last_refresh = time.monotonic()
            logger.debug(f"Cached {len(keys)} Firebase signing keys")

    async def get_key(self, kid: str) -> Any:
        if not self._keys or time.monotonic() >= self._expires_at:
            await self._refresh()

        key = self._keys.get(kid)
        if key is not None:
            return key

        # Unknown kid: Google may have rotated early. Refetch, but not more
        # often than the cooldown, so junk tokens can't drive outbound traffic.
        if time.monotonic() - self._last_refresh >= _REFRESH_COOLDOWN_SECONDS:
            self._expires_at = 0.0
            await self._refresh()
            key = self._keys.get(kid)

        if key is None:
            raise AuthenticationError("Token signed with an unrecognised key")
        return key


# Module-level cache so keys are shared across requests.
_jwks_cache = FirebaseJwksCache()


async def verify_firebase_token(
    token: str,
    config: FirebaseAuthConfig,
    jwks_cache: Optional[FirebaseJwksCache] = None,
) -> Dict[str, Any]:
    """Verify a Firebase ID token and return its claims.

    Raises AuthenticationError for anything that fails — signature, audience,
    issuer, expiry, unverified email, or an address outside the allowlist.
    """
    cache = jwks_cache or _jwks_cache

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise AuthenticationError(f"Malformed token: {e}") from e

    if header.get("alg") not in _ALGORITHMS:
        raise AuthenticationError("Unsupported token signing algorithm")

    kid = header.get("kid")
    if not kid:
        raise AuthenticationError("Token is missing a key id")

    key = await cache.get_key(kid)

    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=_ALGORITHMS,
            audience=config.project_id,
            issuer=config.issuer,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise AuthenticationError("Token has expired") from e
    except jwt.PyJWTError as e:
        raise AuthenticationError(f"Token verification failed: {e}") from e

    if not str(claims.get("sub", "")).strip():
        raise AuthenticationError("Token has no subject")

    # Firebase requires auth_time to be in the past; a future value means the
    # token was minted for a sign-in that hasn't happened.
    auth_time = claims.get("auth_time")
    if isinstance(auth_time, (int, float)) and auth_time > time.time() + 60:
        raise AuthenticationError("Token auth_time is in the future")

    email = str(claims.get("email", "")).strip().lower()
    if not email:
        raise AuthenticationError("Token carries no email address")
    if not claims.get("email_verified", False):
        raise AuthenticationError("Email address is not verified")
    if email not in config.allowed_emails:
        # Logged, not returned: the caller gets a generic message so the
        # endpoint can't be used to enumerate who is on the allowlist.
        logger.warning(f"Rejected Firebase sign-in for non-allowlisted email: {email}")
        raise AuthenticationError("This account is not authorized for this instance")

    return claims
