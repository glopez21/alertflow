"""ThreatPulse integration client for SOC webhook and IOC enrichment.

ThreatPulse is the central SOC orchestration platform.  This module
provides two core capabilities:

1. **Webhook delivery** -- forwards triaged alerts from AlertFlow to
   ThreatPulse so they appear in the SOC dashboard for analyst review.
2. **IOC enrichment** -- queries ThreatPulse's threat-intelligence
   aggregation API to retrieve reputation data for IPs, hashes, domains,
   and URLs before tickets are created.

All public methods return plain dicts so downstream consumers (playbooks,
dashboards, etc.) can serialise them without a dependency on this module.

Usage::

    with ThreatPulseClient("https://threatpulse.corp", api_key="...") as tp:
        tp.send_webhook(payload)
        intel = tp.lookup_ioc("8.8.8.8", "ip")
"""

import logging
from typing import Optional

import httpx

from models import ThreatPulseWebhookPayload

logger = logging.getLogger(__name__)


class ThreatPulseClient:
    """Client for ThreatPulse SOC platform integration.

    Authenticates via a Bearer token supplied at construction time.
    Uses the context-manager pattern to ensure the HTTP connection pool
    is released even when exceptions occur.

    Attributes:
        base_url: Root URL of the ThreatPulse instance (trailing slash stripped).
        api_key: Bearer token for API authentication.
    """

    def __init__(self, base_url: str, api_key: str = "", verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            verify=verify_ssl,
            timeout=30.0,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_webhook(self, payload: ThreatPulseWebhookPayload) -> dict:
        """Post a triaged alert to the ThreatPulse webhook endpoint.

        The payload is serialised from a Pydantic model so field
        validation happens before the HTTP call is made.

        Args:
            payload: Structured alert data conforming to the
                ``ThreatPulseWebhookPayload`` schema.

        Returns:
            JSON response body on success, or an error dict with the
            exception message for logging/debugging.
        """
        try:
            resp = self._client.post(
                "/api/v1/webhooks",
                json=payload.model_dump(),
                headers={
                    "X-Webhook-Source": "alertflow",
                    "X-Webhook-Event": payload.event,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("ThreatPulse webhook failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def lookup_ioc(self, ioc: str, ioc_type: str = "ip") -> Optional[dict]:
        """Query ThreatPulse enrichment API for a specific IOC.

        Retrieves aggregated reputation data from ThreatPulse's
        multi-source intel backend.

        Args:
            ioc: The indicator value (IP, hash, domain, URL).
            ioc_type: One of ``"ip"``, ``"domain"``, ``"hash"``, ``"url"``.

        Returns:
            Enrichment dict if the IOC is found, ``None`` on error or 404.
            A non-200 status is logged but does not raise, allowing the
            caller to gracefully degrade.
        """
        try:
            resp = self._client.get(f"/api/v1/enrich/{ioc_type}/{ioc}")
            if resp.status_code == 200:
                return resp.json()
            logger.warning("ThreatPulse IOC lookup returned %d for %s", resp.status_code, ioc)
        except httpx.HTTPError as e:
            logger.warning("ThreatPulse IOC lookup failed: %s", e)
        return None

    def create_incident(self, title: str, severity: str, description: str = "", ioc: str = "") -> dict:
        """Create a new incident record in ThreatPulse.

        Automatically tags the incident with ``"source": "alertflow"`` so
        SOC analysts can filter for AlertFlow-originated incidents.

        Args:
            title: Short incident title.
            severity: Severity level string (e.g. ``"critical"``, ``"high"``).
            description: Optional longer description of the incident.
            ioc: Optional primary IOC to associate with the incident.

        Returns:
            JSON response body containing the new incident ID, or an
            error dict.
        """
        try:
            resp = self._client.post(
                "/api/v1/incidents",
                json={
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "source": "alertflow",
                    "indicators": [ioc] if ioc else [],
                },
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("ThreatPulse incident creation failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def close(self):
        """Close the underlying HTTP transport."""
        self._client.close()