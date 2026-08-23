import os
import secrets
from typing import Optional

from fastapi import Request
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from open_notebook.exceptions import AuthenticationError, ConfigurationError
from open_notebook.utils.encryption import get_secret_from_env
from open_notebook.utils.firebase_auth import (
    FirebaseAuthConfig,
    load_firebase_config,
    verify_firebase_token,
)

AUTH_MODE_PASSWORD = "password"
AUTH_MODE_FIREBASE = "firebase"
VALID_AUTH_MODES = (AUTH_MODE_PASSWORD, AUTH_MODE_FIREBASE)


def get_auth_mode() -> str:
    """Resolve the configured auth mode, defaulting to the shared password.

    An unrecognised value falls back to password mode rather than failing
    closed: mistyping the variable should not lock an operator out of their own
    instance when the password path still works.
    """
    mode = (os.environ.get("OPEN_NOTEBOOK_AUTH_MODE") or "").strip().lower()
    if not mode:
        return AUTH_MODE_PASSWORD
    if mode not in VALID_AUTH_MODES:
        logger.warning(
            f"Unknown OPEN_NOTEBOOK_AUTH_MODE={mode!r}; falling back to "
            f"{AUTH_MODE_PASSWORD!r}. Valid modes: {', '.join(VALID_AUTH_MODES)}"
        )
        return AUTH_MODE_PASSWORD
    return mode


def _unauthorized(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


class PasswordAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to check authentication for all API requests.

    Two modes, selected by OPEN_NOTEBOOK_AUTH_MODE:

    - ``password`` (default): a single shared password compared against the
      Bearer credential. Auth is fully disabled (no hardcoded default password)
      if OPEN_NOTEBOOK_PASSWORD is not set. Supports Docker secrets via
      OPEN_NOTEBOOK_PASSWORD_FILE.
    - ``firebase``: the Bearer credential is a Firebase ID token, verified
      against Google's public keys and gated on an email allowlist. Both modes
      authenticate access to one shared workspace — neither scopes data per
      user (PDR-001).

    The class name is kept for backwards compatibility with existing imports.
    """

    def __init__(
        self, app: ASGIApp, excluded_paths: Optional[list[str]] = None
    ) -> None:
        super().__init__(app)
        self.auth_mode = get_auth_mode()
        self.password = get_secret_from_env("OPEN_NOTEBOOK_PASSWORD")
        self.firebase_config: Optional[FirebaseAuthConfig] = None
        self.firebase_config_error: Optional[str] = None

        if self.auth_mode == AUTH_MODE_FIREBASE:
            try:
                self.firebase_config = load_firebase_config()
                logger.info(
                    "Firebase auth enabled for project "
                    f"{self.firebase_config.project_id} "
                    f"({len(self.firebase_config.allowed_emails)} allowlisted "
                    "address(es))"
                )
            except ConfigurationError as e:
                # Fail closed: every request 401s until this is fixed. Logged
                # loudly at startup because the UI can only report "denied".
                self.firebase_config_error = str(e)
                logger.error(
                    f"Firebase auth is misconfigured, denying all requests: {e}"
                )

        self.excluded_paths: list[str] = excluded_paths or [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
        ]

    def _auth_required(self) -> bool:
        if self.auth_mode == AUTH_MODE_FIREBASE:
            return True
        return bool(self.password)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip authentication if this mode has nothing to enforce
        if not self._auth_required():
            return await call_next(request)

        # Skip authentication for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Skip authentication for CORS preflight requests (OPTIONS)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Check authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return _unauthorized("Missing authorization header")

        # Expected format: "Bearer {credential}"
        try:
            scheme, credentials = auth_header.split(" ", 1)
            if scheme.lower() != "bearer":
                raise ValueError("Invalid authentication scheme")
        except ValueError:
            return _unauthorized("Invalid authorization header format")

        if self.auth_mode == AUTH_MODE_FIREBASE:
            return await self._dispatch_firebase(request, call_next, credentials)

        # Check password (constant-time to avoid a timing side-channel)
        assert self.password is not None  # guaranteed by _auth_required()
        if not secrets.compare_digest(
            credentials.encode("utf-8"), self.password.encode("utf-8")
        ):
            return _unauthorized("Invalid password")

        # Password is correct, proceed with the request
        response = await call_next(request)
        return response

    async def _dispatch_firebase(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
        credentials: str,
    ) -> Response:
        if self.firebase_config is None:
            return _unauthorized(
                "Firebase authentication is not configured on this server"
            )

        try:
            claims = await verify_firebase_token(credentials, self.firebase_config)
        except AuthenticationError as e:
            return _unauthorized(str(e))
        except Exception as e:  # defensive: never leak a 500 from the auth path
            logger.error(f"Unexpected error verifying Firebase token: {e}")
            return _unauthorized("Could not verify credentials")

        # Attach the identity for downstream handlers/logging. Data is still
        # shared across every allowlisted user (PDR-001) — this is provenance,
        # not a scoping key.
        request.state.auth_email = claims.get("email")
        request.state.auth_subject = claims.get("sub")

        return await call_next(request)
