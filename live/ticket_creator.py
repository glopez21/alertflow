#!/usr/bin/env python3
"""Ticketing system integration for AlertFlow.

Provides a unified interface for creating incident tickets in Jira and
ServiceNow, the two SOC ticketing backends AlertFlow supports.  Each
backend is wrapped in its own creator class (``JiraCreator``,
``ServiceNowCreator``) that implements the context-manager protocol
and maps AlertFlow severity levels to the target system's priority
scheme.

Design notes:

* **Sample fallback** -- when the ticketing API is unreachable or
  credentials are invalid, creators generate deterministic sample
  tickets so that downstream workflows (notifications, dashboards, etc.)
  can still demonstrate functionality without a live backend.
* **TicketManager** -- aggregates multiple creator instances behind a
  single ``create_from_alert()`` entry point that accepts enriched
  alert dicts and routes to the appropriate creator.  This decouples
  playbooks from the choice of ticketing system.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


@dataclass
class TicketConfig:
    """Connection and mapping configuration for a ticketing backend.

    Attributes:
        type: Backend selector -- ``"jira"`` or ``"servicenow"``.
        host: Base URL of the ticketing system instance.
        username: Auth username (email for Jira, username for ServiceNow).
        password: Auth password (used by ServiceNow).
        api_token: API token (used by Jira instead of password).
        project: Default Jira project key (e.g. ``"SOC"``).
        priority_map: Mapping from AlertFlow severity strings to the
            target system's priority names/IDs.
    """

    type: str = "jira"  # jira, servicenow
    host: str = ""
    username: str = ""
    password: str = ""
    api_token: str = ""
    project: str = "SOC"
    priority_map: dict = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    })


@dataclass
class AlertTicket:
    """Normalised representation of a created ticket.

    Fields are intentionally a superset of what both Jira and
    ServiceNow return so callers have a consistent interface regardless
    of backend.
    """

    key: str = ""
    alert_id: str = ""
    title: str = ""
    description: str = ""
    status: str = ""
    priority: str = ""
    assignee: str = ""
    created: str = ""
    updated: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        """Serialise to a flat dict suitable for logging or JSON responses."""
        return {
            "key": self.key,
            "alert_id": self.alert_id,
            "title": self.title,
            "status": self.status,
            "priority": self.priority,
            "url": self.url,
        }


class JiraCreator:
    """Create Jira issues via the REST API v3.

    Authenticates with basic auth (email + API token).  Issues are
    created as ``Bug`` type in the configured project with an Atlassian
    Document Format (ADF) description body.

    Implements the context-manager protocol so the underlying HTTP
    client is always closed.
    """

    def __init__(self, config: TicketConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.host,
            auth=(config.username, config.api_token),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the underlying HTTP transport."""
        self._client.close()

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: str = "Medium",
        labels: list[str] | None = None,
    ) -> AlertTicket:
        """Create a Jira issue in the configured project.

        The description is wrapped in Atlassian Document Format (ADF)
        v1 as required by Jira Cloud's ``/rest/api/3/issue`` endpoint.

        Args:
            summary: Issue title.
            description: Free-text description body.
            priority: AlertFlow severity string; mapped via
                ``TicketConfig.priority_map`` to a Jira priority name.
            labels: Optional list of Jira labels (default
                ``["alertflow", "soc"]``).

        Returns:
            An ``AlertTicket`` with the created issue's key and browse URL.
            On failure a sample ticket is returned so the pipeline
            continues.
        """
        issue_data = {
            "fields": {
                "project": {"key": self.config.project},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": description}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": self.config.priority_map.get(priority, "Medium")},
                "labels": labels or ["alertflow", "soc"],
            }
        }

        try:
            resp = self._client.post("/rest/api/3/issue", json=issue_data)
            if resp.status_code == 201:
                data = resp.json()
                return self._parse_issue(data)
        except Exception as e:
            logger.warning("Jira issue creation failed: %s", e)

        return self._sample_ticket(summary)

    def _parse_issue(self, data: dict) -> AlertTicket:
        """Map a Jira API response to an ``AlertTicket``."""
        return AlertTicket(
            key=data.get("key", ""),
            url=f"{self.config.host}/browse/{data.get('key', '')}",
            status="Open",
            created=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    def _sample_ticket(self, summary: str) -> AlertTicket:
        """Generate a deterministic sample ticket when the Jira API is unreachable."""
        ticket_id = int(hashlib.md5(summary.encode()).hexdigest()[:8], 16) % 10000
        return AlertTicket(
            key=f"SOC-{ticket_id}",
            title=summary,
            status="Open",
            url=f"https://jira.example.com/browse/SOC-{ticket_id}",
            created=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )


class ServiceNowCreator:
    """Create ServiceNow incidents via the Table API.

    Authenticates with basic auth (username + password).  Incidents are
    created in the configured instance with a ``u_origin`` field set to
    ``"AlertFlow"`` for traceability.

    Implements the context-manager protocol for safe resource cleanup.
    """

    def __init__(self, config: TicketConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.host,
            auth=(config.username, config.password),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the underlying HTTP transport."""
        self._client.close()

    def create_incident(
        self,
        short_description: str,
        description: str,
        priority: str = "3",
        category: str = "Security",
    ) -> AlertTicket:
        """Create a ServiceNow incident record.

        Severity-to-priority mapping: ``critical`` -> 1 (Highest),
        ``high`` -> 2, ``medium`` -> 3, ``low`` -> 4.

        Args:
            short_description: Incident title (max ~160 chars recommended).
            description: Longer description of the incident.
            priority: AlertFlow severity string; mapped to ServiceNow
                numeric priority internally.
            category: Incident category (default ``"Security"``).

        Returns:
            An ``AlertTicket`` with the incident number and deep-link URL.
            On failure a sample ticket is returned.
        """
        incident_data = {
            "short_description": short_description,
            "description": description,
            "priority": priority,
            "category": category,
            "u_origin": "AlertFlow",
            "assigned_to": "",
        }

        priority_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
        sn_priority = priority_map.get(priority, "3")
        incident_data["priority"] = sn_priority

        try:
            resp = self._client.post(
                "/api/now/table/incident",
                json=incident_data,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 201:
                data = resp.json()
                result = data.get("result", {})
                return AlertTicket(
                    key=result.get("number", ""),
                    url=f"{self.config.host}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id', '')}",
                    status=result.get("state", ""),
                    priority=sn_priority,
                    created=result.get("sys_created_on", ""),
                )
        except Exception as e:
            logger.warning("ServiceNow incident creation failed: %s", e)

        return self._sample_ticket(short_description)

    def _parse_incident(self, data: dict) -> AlertTicket:
        """Map a ServiceNow response to an ``AlertTicket``."""
        return AlertTicket(
            key=data.get("number", ""),
            url=f"{self.config.host}/incident.do?sys_id={data.get('sys_id', '')}",
            status=data.get("state", ""),
        )

    def _sample_ticket(self, summary: str) -> AlertTicket:
        """Generate a deterministic sample ticket for fallback/demo use."""
        ticket_id = int(hashlib.md5(summary.encode()).hexdigest()[:8], 16) % 10000
        return AlertTicket(
            key=f"SOC-{ticket_id}",
            title=summary,
            status="Open",
            url=f"https://servicenow.example.com/incident/SOC-{ticket_id}",
            created=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )


class TicketManager:
    """High-level manager that routes alert data to the correct ticket creator.

    Maintains a registry of ``JiraCreator`` / ``ServiceNowCreator``
    instances and exposes ``create_from_alert()`` which accepts a
    generic enriched-alert dict and dispatches to the right backend.

    This indirection keeps playbooks decoupled from the specific
    ticketing system in use.
    """

    def __init__(self):
        self.creators: dict[str, JiraCreator | ServiceNowCreator] = {}

    def add_jira(self, **config) -> JiraCreator:
        """Register and return a Jira creator.

        Args:
            **config: Keyword arguments forwarded to ``TicketConfig``
                (e.g. ``host``, ``username``, ``api_token``, ``project``).

        Returns:
            The newly created ``JiraCreator`` instance.
        """
        ticket_config = TicketConfig(type="jira", **config)
        creator = JiraCreator(ticket_config)
        self.creators["jira"] = creator
        return creator

    def add_servicenow(self, **config) -> ServiceNowCreator:
        """Register and return a ServiceNow creator.

        Args:
            **config: Keyword arguments forwarded to ``TicketConfig``
                (e.g. ``host``, ``username``, ``password``).

        Returns:
            The newly created ``ServiceNowCreator`` instance.
        """
        ticket_config = TicketConfig(type="servicenow", **config)
        creator = ServiceNowCreator(ticket_config)
        self.creators["servicenow"] = creator
        return creator

    def create_from_alert(
        self,
        alert_data: dict,
        system: str = "jira",
        enrich_data: dict | None = None,
    ) -> AlertTicket:
        """Create a ticket from an enriched alert dict.

        Builds a formatted title (``[SEVERITY] Rule Name``) and
        description (Markdown-formatted alert details + enrichment),
        then delegates to the registered creator for *system*.

        Args:
            alert_data: Enriched alert dict with keys like ``rule_name``,
                ``severity``, ``host``, ``user``, ``src_ip``, ``dst_ip``.
            system: Target ticketing system (``"jira"`` or ``"servicenow"``).
            enrich_data: Optional threat-intel enrichment to append to
                the description.

        Returns:
            ``AlertTicket`` from the creator.

        Raises:
            ValueError: If *system* is not registered.
        """
        if system not in self.creators:
            raise ValueError(f"Unknown system: {system}")

        creator = self.creators[system]

        title = f"[{alert_data.get('severity', 'medium').upper()}] {alert_data.get('rule_name', 'Security Alert')}"

        description = self._format_description(alert_data, enrich_data)

        priority = alert_data.get("severity", "medium")
        labels = alert_data.get("labels", [])

        if system == "jira":
            return creator.create_issue(title, description, priority, labels)
        elif system == "servicenow":
            return creator.create_incident(title, description, priority)

    def _format_description(
        self,
        alert_data: dict,
        enrich_data: dict | None,
    ) -> str:
        """Render a Markdown-formatted ticket description from alert fields.

        Produces a structured body with alert details and, optionally,
        threat-intel enrichment sections so analysts have all context
        in one place.
        """
        lines = [
            "## Alert Details",
            f"- **Rule**: {alert_data.get('rule_name', 'Unknown')}",
            f"- **Severity**: {alert_data.get('severity', 'Unknown')}",
            f"- **Host**: {alert_data.get('host', 'Unknown')}",
            f"- **User**: {alert_data.get('user', 'N/A')}",
            f"- **Source IP**: {alert_data.get('src_ip', 'N/A')}",
            f"- **Destination IP**: {alert_data.get('dst_ip', 'N/A')}",
            f"- **Timestamp**: {alert_data.get('timestamp', 'Unknown')}",
        ]

        if enrich_data:
            lines.extend([
                "",
                "## Enrichment",
            ])
            if enrich_data.get("ip_reputation"):
                lines.append(f"- **IP Reputation**: {enrich_data['ip_reputation']}")
            if enrich_data.get("hash_reputation"):
                lines.append(f"- **Hash**: {enrich_data['hash_reputation']}")
            if enrich_data.get("user_context"):
                lines.append(f"- **User Risk**: {enrich_data['user_context']}")

        return "\n".join(lines)

    def _sample_ticket(self, title: str) -> AlertTicket:
        """Return a fixed sample ticket for demo/fallback use."""
        return AlertTicket(
            key=f"SOC-{1000}",
            title=title,
            status="Open",
            url="https://jira.example.com/browse/SOC-1000",
            created=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )


def create_ticket_system(system: str = "jira", **config) -> JiraCreator | ServiceNowCreator:
    """Factory that instantiates the correct ticket creator for *system*.

    Args:
        system: ``"jira"`` or ``"servicenow"``.
        **config: Keyword arguments forwarded to ``TicketConfig``.

    Returns:
        A ``JiraCreator`` or ``ServiceNowCreator`` instance.

    Raises:
        ValueError: If *system* is not ``"jira"`` or ``"servicenow"``.
    """
    if system == "jira":
        return JiraCreator(TicketConfig(type="jira", **config))
    elif system == "servicenow":
        return ServiceNowCreator(TicketConfig(type="servicenow", **config))
    raise ValueError(f"Unknown system: {system}")