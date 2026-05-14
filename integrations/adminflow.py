"""AdminFlow integration client.

Automates AD response actions via the AdminFlow REST API.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class AdminFlowClient:
    """Client for AdminFlow AD automation API."""

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
        """Disable an AD user account."""
        try:
            resp = self._client.put(f"/api/users/{username}/disable")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow disable user failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def enable_user(self, username: str) -> dict:
        """Enable an AD user account."""
        try:
            resp = self._client.put(f"/api/users/{username}/enable")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow enable user failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def reset_password(self, username: str) -> dict:
        """Reset an AD user password."""
        try:
            resp = self._client.put(f"/api/users/{username}/reset-password")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow password reset failed for %s: %s", username, e)
            return {"status": "error", "detail": str(e)}

    def get_user(self, username: str) -> Optional[dict]:
        """Get AD user details."""
        try:
            resp = self._client.get(f"/api/users/{username}")
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow get user failed for %s: %s", username, e)
        return None

    def get_inactive_users(self, days: int = 90) -> dict:
        """Get inactive AD users."""
        try:
            resp = self._client.get(f"/api/security/inactive/{days}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow inactive users query failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def get_privileged_accounts(self) -> dict:
        """Find privileged AD accounts."""
        try:
            resp = self._client.get("/api/security/privileged")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow privileged accounts query failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def health_check(self) -> dict:
        """Check AdminFlow API health."""
        try:
            resp = self._client.get("/api/health")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("AdminFlow health check failed: %s", e)
            return {"status": "unhealthy", "detail": str(e)}

    def close(self):
        self._client.close()