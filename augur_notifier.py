"""Augur hub notifier — push AlertFlow triage results to the Augur SOC platform."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from n3xuslib import N3xusClient
from n3xuslib.config import N3xusConfig

logger = logging.getLogger("alertflow.augur")


class AugurNotifier:
    """Push AlertFlow triage results to the Augur hub as events."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._client: Any = None
        cfg = config or {}
        self._hub_url = cfg.get("hub_url") or os.environ.get("AUGUR_URL", "")
        self._agent_name = cfg.get("agent_name") or os.environ.get("AUGUR_AGENT_NAME", "alertflow")
        self._agent_type = cfg.get("agent_type") or os.environ.get("AUGUR_AGENT_TYPE", "alertflow")
        self._api_key = cfg.get("api_key") or os.environ.get("AUGUR_API_KEY", "")
        self._init_client()

    def _init_client(self) -> None:
        if not self._hub_url:
            return
        try:
            from augur_client import AugurClient

            self._client = AugurClient(
                hub_url=self._hub_url,
                agent_name=self._agent_name,
                agent_type=self._agent_type,
                api_key=self._api_key,
                heartbeat_interval=os.environ.get("AUGUR_HEARTBEAT_INTERVAL", "30"),
            )
            logger.info("Augur client initialized (hub: %s)", self._hub_url)
        except ImportError:
            logger.warning("augur-client not installed — install with: pip install 'alertflow[augur]'")
            self._client = None
        except Exception as e:
            logger.warning("Augur client init failed: %s", e)
            self._client = None

    def start(self) -> None:
        if not self._client:
            return
        try:
            self._client.register(name=self._agent_name, agent_type=self._agent_type)
            self._client.start_heartbeat()
            logger.info("Registered with Augur hub, heartbeat started")
        except Exception as e:
            logger.warning("Augur registration/heartbeat failed: %s", e)

    def stop(self) -> None:
        if not self._client:
            return
        try:
            self._client.stop_heartbeat()
        except Exception:
            pass

    def push_triage_result(self, alert: dict, enrichment: dict | None = None) -> bool:
        if not self._client:
            return False
        try:
            self._client.push_event(
                event_type="triage",
                severity=alert.get("severity", "medium"),
                source="alertflow",
                title=alert.get("title", "AlertFlow Triage"),
                payload={
                    "alert_id": alert.get("id", ""),
                    "title": alert.get("title", ""),
                    "status": alert.get("status", ""),
                    "analyst": alert.get("analyst", ""),
                    "source_ip": alert.get("src_ip", ""),
                    "destination_ip": alert.get("dst_ip", ""),
                    "user": alert.get("user", ""),
                    "iocs": (
                        {
                            "ips": enrichment.get("iocs", {}).get("ips", []),
                            "domains": enrichment.get("iocs", {}).get("domains", []),
                            "hashes": enrichment.get("iocs", {}).get("hashes", {}),
                            "emails": enrichment.get("iocs", {}).get("emails", []),
                        }
                        if enrichment
                        else {}
                    ),
                },
                tags=["alertflow", f"severity:{alert.get('severity', 'medium')}"],
            )
            self._emit_n3xus(alert, enrichment)
            return True
        except Exception as e:
            logger.warning("Augur push failed: %s", e)
            return False

    def _emit_n3xus(self, alert: dict, enrichment: dict | None = None) -> None:
        config = N3xusConfig.from_env()

        async def _emit():
            async with N3xusClient(config) as client:
                await client.emit(
                    source="alertflow",
                    source_instance=config.source_instance or "alertflow",
                    event_type="triage",
                    severity=alert.get("severity", "medium"),
                    title=alert.get("title", "AlertFlow Triage"),
                    payload={
                        "alert_id": alert.get("id", ""),
                        "status": alert.get("status", ""),
                        "analyst": alert.get("analyst", ""),
                        "source_ip": alert.get("src_ip", ""),
                        "destination_ip": alert.get("dst_ip", ""),
                        "user": alert.get("user", ""),
                        "iocs": (
                            {
                                "ips": enrichment.get("iocs", {}).get("ips", []),
                                "domains": enrichment.get("iocs", {}).get("domains", []),
                                "hashes": enrichment.get("iocs", {}).get("hashes", {}),
                                "emails": enrichment.get("iocs", {}).get("emails", []),
                            }
                            if enrichment
                            else {}
                        ),
                    },
                    tags=["alertflow", f"severity:{alert.get('severity', 'medium')}"],
                )

        try:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_emit())
            except RuntimeError:
                asyncio.run(_emit())
        except Exception as e:
            logger.warning("n3xuslib emit failed: %s", e)
