"""AdminFlow integration client for Active Directory automation.

Provides a programmatic interface to AdminFlow's REST API for executing
AD security response actions: disabling compromised accounts, resetting
passwords, and querying account status. Designed for use in automated
alert triage workflows where analysts need to contain threats quickly.

All methods return dicts with a consistent shape: success responses
contain API data, failures return ``{"status": "error", "detail": ...}``
so callers can branch without catching exceptions.

Usage::

    with AdminFlowClient("https://adminflow.corp", api_key="...") as client:
        client.disable_user("jsmith")
        info = client.get_user("jsmith")
"""

import logging
import re
from typing import Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

# Allowed characters in AD usernames for the allowlist check.
# AD samAccountName values typically contain only alphanumerics, dots,
# hyphens, and underscores. This regex is used for early validation
# before the value reaches the URL path.
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


class AdminFlowClient:
    """Client for AdminFlow AD automation API.

    Wraps the AdminFlow REST interface and exposes high-level methods for
    common SOC response actions (disable/enable user, reset password, etc.).

    Implements the context-manager protocol so it can be used with ``with``
    statements, guaranteeing the underlying ``httpx.Client`` is closed.

    Attributes:
        base_url: Root URL of the AdminFlow deployment (trailing slash stripped).
        api_key: Bearer token for API authentication.
    """

    def __init__(self, base_url: str, api_key: str = "", verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": api_key} if api_key else {},
            verify=verify_ssl,
            timeout=30.0,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def disable_user(self, username: str) -> dict:
        """Disable an AD user account.

        Triggers an immediate account lockout via AdminFlow.  Typically the
        first containment step when a compromised account is identified.

        Args:
            username: sAMAccountName or UPN of the target user.

        Returns:
            JSON response body on success, or an error dict.
        """
        """Disable an AD user account."""
        try:
            resp = self._client.put(f"/api/users/{_safe_url_path(username)}/disable")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow disable user failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def enable_user(self, username: str) -> dict:
        """Re-enable a previously disabled AD user account.

        Args:
            username: sAMAccountName or UPN of the target user.

        Returns:
            JSON response body on success, or an error dict.
        """
        try:
            resp = self._client.put(f"/api/users/{_safe_url_path(username)}/enable")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow enable user failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def reset_password(self, username: str) -> dict:
        """Force a password reset for an AD user account.

        AdminFlow generates a random temporary password and returns it
        in the response so the analyst can securely communicate it.

        Args:
            username: sAMAccountName or UPN of the target user.

        Returns:
            JSON response body (includes new temporary password) on success,
            or an error dict.
        """
        try:
            resp = self._client.put(f"/api/users/{_safe_url_path(username)}/reset-password")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow password reset failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def get_user(self, username: str) -> Optional[dict]:
        """Retrieve AD user details from AdminFlow.

        Args:
            username: sAMAccountName or UPN to look up.

        Returns:
            User detail dict if found, ``None`` on error or 404.
        """
        try:
            resp = self._client.get(f"/api/users/{_safe_url_path(username)}")
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow get user failed for %s: %s", username, e)
        return None

    def get_inactive_users(self, days: int = 90) -> dict:
        """List AD accounts that have not logged on within *days* days.

        Useful for periodic access reviews and detecting dormant accounts
        that could be targets for credential theft.

        Args:
            days: Inactivity threshold in days (default 90).

        Returns:
            JSON response with list of inactive accounts, or an error dict.
        """
        try:
            resp = self._client.get(f"/api/security/inactive/{days}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow inactive users query failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def get_privileged_accounts(self) -> dict:
        """Enumerate privileged (Domain Admin, etc.) AD accounts.

        Returns:
            JSON response listing privileged accounts, or an error dict.
        """
        try:
            resp = self._client.get("/api/security/privileged")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow privileged accounts query failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def health_check(self) -> dict:
        """Check AdminFlow API availability.

        Returns:
            Health status dict; ``{"status": "unhealthy", ...}`` on failure.
        """
        try:
            resp = self._client.get("/api/health")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow health check failed: %s", e)
            return {"status": "unhealthy", "detail": str(e)}

    def close(self):
        """Close the underlying HTTP transport."""
        self._client.close()


def _safe_url_path(username: str) -> str:
    """Sanitize and URL-encode a username for safe use in URL path segments.

    Even though the AdminFlow API expects a username in the URL, we must
    ensure special characters cannot break the URL structure (path traversal,
    injection, etc.).  ``quote(username, safe="")`` percent-encodes every
    character that is not unreserved, which is a defense-in-depth measure
    on top of the allowlist check.

    Args:
        username: Raw username string.

    Returns:
        Percent-encoded string safe for embedding in a URL path.
    """
    if not _USERNAME_RE.match(username):
        logger.warning("Invalid username format: %s", username)
    return quote(username, safe="")