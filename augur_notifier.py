"""Augur hub notifier — push AlertFlow triage results to the Augur SOC platform.

This module bridges AlertFlow's local triage workflow with the centralised
Augur SOC hub and the n3xus telemetry bus.  After an analyst (or automation)
triages an alert, ``AugurNotifier.push_triage_result`` publishes a structured
event that Augur can correlate with detections, threat-intel, and other
agents' outputs.

Design notes
~~~~~~~~~~~~
* **Graceful degradation.**  If ``augur-client`` or ``n3xuslib`` are not
  installed the notifier silently becomes a no-op.  This lets AlertFlow
  operate standalone without requiring the full Augur stack.
* **Configuration precedence.**  Explicit ``config`` dict values win over
  environment variables, which win over hardcoded defaults.
* **Thread-safety for n3xus emission.**  ``_emit_n3xus`` detects whether an
  asyncio event loop is already running (common in ASGI servers) and either
  schedules a coroutine via ``create_task`` or falls back to ``asyncio.run``
  for synchronous callers.  This avoids ``RuntimeError: This event loop
  is already running`` in mixed sync/async call sites.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from n3xuslib import N3xusClient
from n3xuslib.config import N3xusConfig

logger = logging.getLogger("alertflow.augur")


class AugurNotifier:
    """Push AlertFlow triage results to the Augur hub as events.

    Lifecycle
    ~~~~~~~~~
    1. Instantiate with an optional ``config`` dict (or rely on env vars).
    2. Call :meth:`start` to register with the hub and begin heartbeats.
    3. Call :meth:`push_triage_result` for each triaged alert.
    4. Call :meth:`stop` on shutdown to cleanly deregister.

    All public methods are safe to call even when the Augur client is
    unavailable — they silently return ``False`` / do nothing.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self._client: Any = None
        cfg = config or {}
        self._hub_url = cfg.get("hub_url") or os.environ.get("AUGUR_URL", "")
        self._agent_name = cfg.get("agent_name") or os.environ.get("AUGUR_AGENT_NAME", "alertflow")
        self._agent_type = cfg.get("agent_type") or os.environ.get("AUGUR_AGENT_TYPE", "alertflow")
        self._api_key = cfg.get("api_key") or os.environ.get("AUGUR_API_KEY", "")
        self._init_client()

    def _init_client(self) -> None:
        """Lazily import and configure the ``augur_client`` SDK.

        The import is deferred so that environments without the optional
        dependency do not fail at module load time.  ``ImportError`` is
        expected in standalone deployments; other exceptions indicate a
        configuration or connectivity problem at init time.
        """
        if not self._hub_url:
            return
        try:
            # Deferred import keeps the module importable when augur-client
            # is not installed (e.g. in lightweight Docker images).
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
        """Register this agent with the Augur hub and start heartbeats.

        Heartbeats allow the hub to detect agent liveness.  Registration is
        idempotent — calling ``start`` more than once is safe.
        """
        if not self._client:
            return
        try:
            self._client.register(name=self._agent_name, agent_type=self._agent_type)
            self._client.start_heartbeat()
            logger.info("Registered with Augur hub, heartbeat started")
        except Exception as e:
            logger.warning("Augur registration/heartbeat failed: %s", e)

    def stop(self) -> None:
        """Stop the heartbeat loop.  Safe to call if never started."""
        if not self._client:
            return
        try:
            self._client.stop_heartbeat()
        except Exception:
            # Best-effort shutdown; swallow errors to avoid interfering
            # with the calling code's own teardown sequence.
            pass

    def push_triage_result(self, alert: dict, enrichment: dict | None = None) -> bool:
        """Publish a triage result to the Augur hub and the n3xus bus.

        Args:
            alert: Alert record containing at least ``id``, ``title``,
                ``severity``, and ``status`` fields.
            enrichment: Optional enrichment payload with ``iocs`` sub-dict
                (keys: ``ips``, ``domains``, ``hashes``, ``emails``).

        Returns:
            ``True`` if the Augur push succeeded, ``False`` otherwise
            (including when the client is unavailable).
        """
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
            # Emit a parallel event to the n3xus telemetry bus for
            # cross-agent correlation (fire-and-forget; failures are logged
            # but do not affect the Augur push result).
            self._emit_n3xus(alert, enrichment)
            return True
        except Exception as e:
            logger.warning("Augur push failed: %s", e)
            return False

    def _emit_n3xus(self, alert: dict, enrichment: dict | None = None) -> None:
        """Emit a triage event to the n3xus event bus.

        This is a best-effort, fire-and-forget operation.  The n3xus client
        requires an async context, so we detect whether a loop is running:

        * **Loop running** (typical inside ASGI servers) — schedule the
          coroutine as a background task so we don't block the caller.
        * **No loop** (CLI scripts, tests) — use ``asyncio.run`` to drive
          the coroutine to completion synchronously.

        Errors are caught and logged; they must never propagate to the caller.
        """
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
                # If an event loop is already running (e.g. inside uvicorn),
                # schedule the coroutine without blocking the current thread.
                loop = asyncio.get_running_loop()
                loop.create_task(_emit())
            except RuntimeError:
                # No running loop — drive the coroutine synchronously.
                asyncio.run(_emit())
        except Exception as e:
            logger.warning("n3xuslib emit failed: %s", e)
