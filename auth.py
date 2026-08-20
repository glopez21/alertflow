"""API authentication with HMAC comparison and audit trail.

Implements lightweight API-key authentication for the AlertFlow REST API.
Keys are delivered via the ``Authorization: Bearer <key>`` header or the
``X-API-Key`` header.  Comparison is performed using HMAC constant-time
operations to prevent timing side-channel attacks.

Health-check, metrics, and documentation endpoints are exempt from
authentication so that monitoring systems and Swagger UI can function without
configuring credentials.

All authentication decisions (allowed and denied) are recorded in an
in-memory circular buffer for audit purposes.  The buffer is bounded to
``AUDIT_MAX_ENTRIES`` entries to cap memory usage; older entries are
silently discarded.

Configuration
-------------
* ``ALERTFLOW_API_KEY`` — the expected API key (empty string disables auth).
* ``ALERTFLOW_AUTH_ENABLED`` — set to ``"false"`` to disable all auth checks
  (useful for local development only; **never** set this in production).
"""

import hmac
import os
import re
import time
from collections import deque
from urllib.parse import quote

from fastapi import Request, Response
from logging_config import get_logger

logger = get_logger("alertflow.auth")

# The expected API key.  If empty, authentication is effectively disabled.
API_KEY = os.environ.get("ALERTFLOW_API_KEY", "")
# Master switch — when ``false``, all requests are allowed regardless of key.
AUTH_ENABLED = os.environ.get("ALERTFLOW_AUTH_ENABLED", "true").lower() == "true"
# Maximum audit entries kept in memory before the oldest is evicted.
AUDIT_MAX_ENTRIES = 10000
# Alphanumeric plus dot, underscore, hyphen — conservative safe set for
# usernames that may appear in filesystem paths or URL segments.
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

# Bounded in-memory audit log; oldest entries are automatically evicted.
_auth_audit: deque = deque(maxlen=AUDIT_MAX_ENTRIES)


def _hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    Standard ``==`` on secrets leaks information about the length of the
    shared prefix through response-time variation.  ``hmac.compare_digest``
    runs in time proportional to the *full* length of the inputs, regardless
    of where they differ.

    Returns ``False`` immediately if either argument is empty to avoid
    short-circuiting on missing credentials.
    """
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def _check_api_key(request: Request) -> bool:
    """Validate the API key on an incoming request.

    Checks are performed in the following order:
    1. If auth is disabled or no key is configured, allow immediately.
    2. Exempt paths (health, metrics, docs) are always allowed.
    3. ``OPTIONS`` requests are always allowed (CORS preflight).
    4. ``Authorization: Bearer <key>`` header is compared via constant-time
       equality.
    5. ``X-API-Key`` header is compared via constant-time equality.

    Returns:
        ``True`` if the request should be allowed, ``False`` otherwise.
    """
    if not AUTH_ENABLED or not API_KEY:
        return True

    # Exempt infrastructure endpoints — monitoring probes and API docs
    # must work without credentials.
    path = request.url.path
    if path in ("/api/health", "/metrics", "/docs", "/openapi.json", "/redoc"):
        return True

    # CORS preflight must not be blocked by auth.
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
    """Record an authentication attempt for the in-memory audit trail.

    The audit entry includes a timestamp, request path, HTTP method, client
    IP, result (allowed/denied), and user-agent.  This is useful for
    security monitoring and incident response — denied attempts in
    particular should be monitored for brute-force activity.

    The underlying ``deque`` automatically evicts the oldest entry when
    ``AUDIT_MAX_ENTRIES`` is reached, so memory usage is bounded.
    """
    _auth_audit.append({
        "timestamp": time.time(),
        "path": request.url.path,
        "method": request.method,
        "ip": request.client.host if request.client else "unknown",
        "allowed": allowed,
        "user_agent": request.headers.get("user-agent", ""),
    })


def get_auth_audit(limit: int = 100) -> list[dict]:
    """Return the most recent auth audit entries.

    Args:
        limit: Maximum number of entries to return (most recent first).

    Returns:
        List of audit dicts ordered from oldest to newest within the
        returned window.
    """
    entries = list(_auth_audit)
    return entries[-limit:]


def sanitize_username(username: str) -> str:
    """URL-encode a username to prevent path traversal or injection.

    Unsafe characters (``/``, ``..``, ``%2F``, etc.) are percent-encoded so
    the result can be safely embedded in filesystem paths or URL segments
    without risk of directory traversal attacks.
    """
    return quote(username, safe="")


def is_valid_username(username: str) -> bool:
    """Check if ``username`` matches the allowed character pattern.

    Only alphanumeric characters, dots, underscores, and hyphens are
    permitted.  This is intentionally restrictive — it prevents injection
    of shell metacharacters, path separators, and whitespace that could
    cause issues downstream.
    """
    return bool(_USERNAME_RE.match(username))


def create_api_key_auth_middleware():
    """Create the API key auth middleware function.

    Returns an async middleware compatible with FastAPI's
    ``app.middleware("http")`` interface.  The middleware validates the API
    key on every request, records the outcome, and short-circuits with
    ``401 Unauthorized`` on failure.
    """

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
