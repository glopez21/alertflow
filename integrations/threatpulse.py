"""ThreatPulse integration client.

Sends triaged alerts to ThreatPulse via webhook and queries
ThreatPulse threat intel for IOC enrichment.
"""

import logging
from typing import Optional

import httpx

from models import ThreatPulseWebhookPayload

logger = logging.getLogger(__name__)


class ThreatPulseClient:
    """Client for ThreatPulse SOC platform integration."""

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
        """Send triaged alert to ThreatPulse webhook endpoint."""
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
        """Query ThreatPulse enrichment API for an IOC."""
        try:
            resp = self._client.get(f"/api/v1/enrich/{ioc_type}/{ioc}")
            if resp.status_code == 200:
                return resp.json()
            logger.warning("ThreatPulse IOC lookup returned %d for %s", resp.status_code, ioc)
        except httpx.HTTPError as e:
            logger.warning("ThreatPulse IOC lookup failed: %s", e)
        return None

    def create_incident(self, title: str, severity: str, description: str = "", ioc: str = "") -> dict:
        """Create an incident in ThreatPulse."""
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
        self._client.close()