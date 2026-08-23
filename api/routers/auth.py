"""
Authentication router for Grasp API.
Provides endpoints to check authentication status.
"""

from fastapi import APIRouter
from loguru import logger

from api.auth import AUTH_MODE_FIREBASE, get_auth_mode
from open_notebook.exceptions import ConfigurationError
from open_notebook.utils.encryption import get_secret_from_env
from open_notebook.utils.firebase_auth import load_firebase_config

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status")
async def get_auth_status():
    """
    Report how (and whether) this instance authenticates callers.

    Unauthenticated by design — the login screen needs it before it can
    authenticate. It therefore returns only what the client must know to build
    the right login form: the mode, and in firebase mode the *public* Firebase
    web config (project id, web API key, auth domain — the same values a
    Firebase web app ships in its client bundle). No password, no allowlist,
    no service-account material.

    Supports Docker secrets via OPEN_NOTEBOOK_PASSWORD_FILE.
    """
    auth_mode = get_auth_mode()

    if auth_mode == AUTH_MODE_FIREBASE:
        try:
            config = load_firebase_config()
        except ConfigurationError as e:
            # Mirrors the middleware, which denies every request in this state.
            logger.error(f"Firebase auth is misconfigured: {e}")
            return {
                "auth_enabled": True,
                "auth_mode": auth_mode,
                "configured": False,
                "message": (
                    "Firebase authentication is enabled but not configured "
                    "correctly on the server"
                ),
            }

        return {
            "auth_enabled": True,
            "auth_mode": auth_mode,
            "configured": True,
            "firebase": config.web_config(),
            "message": "Authentication is required",
        }

    auth_enabled = bool(get_secret_from_env("OPEN_NOTEBOOK_PASSWORD"))

    return {
        "auth_enabled": auth_enabled,
        "auth_mode": auth_mode,
        "configured": True,
        "message": "Authentication is required"
        if auth_enabled
        else "Authentication is disabled",
    }
