"""API authentication with HMAC comparison and audit trail."""

import hmac
import os
import re
import time
from collections import deque
from urllib.parse import quote

from fastapi import Request, Response
from logging_config import get_logger

logger = get_logger("alertflow.auth")

API_KEY = os.environ.get("ALERTFLOW_API_KEY", "")
AUTH_ENABLED = os.environ.get("ALERTFLOW_AUTH_ENABLED", "true").lower() == "true"
AUDIT_MAX_ENTRIES = 10000
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

_auth_audit: deque = deque(maxlen=AUDIT_MAX_ENTRIES)


def _hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def _check_api_key(request: Request) -> bool:
    """Validate API key from request headers."""
    if not AUTH_ENABLED or not API_KEY:
        return True

    path = request.url.path
    if path in ("/api/health", "/metrics", "/docs", "/openapi.json", "/redoc"):
        return True

    if request.method == "OPTIONS":
        return True

    auth_header = request.headers.get("Authorization", "")
    x_api_key = request.headers.get("X-API-Key", "")

    if auth_header.startswith("Bearer ") and _hmac_compare(auth_header[7:], API_KEY):
        return True
    if x_api_key and _hmac_compare(x_api_key, API_KEY):
        return True

    return False


def record_auth_event(request: Request, allowed: bool) -> None:
    """Record an authentication attempt for audit trail."""
    _auth_audit.append({
        "timestamp": time.time(),
        "path": request.url.path,
        "method": request.method,
        "ip": request.client.host if request.client else "unknown",
        "allowed": allowed,
        "user_agent": request.headers.get("user-agent", ""),
    })


def get_auth_audit(limit: int = 100) -> list[dict]:
    """Get recent auth audit entries."""
    entries = list(_auth_audit)
    return entries[-limit:]


def sanitize_username(username: str) -> str:
    """URL-encode a username to prevent path traversal."""
    return quote(username, safe="")


def is_valid_username(username: str) -> bool:
    """Check if username matches expected pattern."""
    return bool(_USERNAME_RE.match(username))


def create_api_key_auth_middleware():
    """Create the API key auth middleware function."""

    async def api_key_auth(request: Request, call_next):
        allowed = _check_api_key(request)
        record_auth_event(request, allowed)

        if not allowed:
            logger.warning(
                "auth.denied",
                path=request.url.path,
                method=request.method,
                ip=request.client.host if request.client else "unknown",
            )
            return Response(status_code=401, content="Unauthorized")

        return await call_next(request)

    return api_key_auth
