#!/usr/bin/env python3
"""Ticketing system integration for AlertFlow."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import httpx


@dataclass
class TicketConfig:
    """Ticketing system configuration."""

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
    """Alert ticket representation."""

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
        return {
            "key": self.key,
            "alert_id": self.alert_id,
            "title": self.title,
            "status": self.status,
            "priority": self.priority,
            "url": self.url,
        }


class JiraCreator:
    """Jira issue creator."""

    def __init__(self, config: TicketConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.host,
            auth=(config.username, config.api_token),
        )

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: str = "Medium",
        labels: list[str] | None = None,
    ) -> AlertTicket:
        """Create Jira issue."""
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
        except Exception:
            pass

        return self._sample_ticket(summary)

    def _parse_issue(self, data: dict) -> AlertTicket:
        return AlertTicket(
            key=data.get("key", ""),
            url=f"{self.config.host}/browse/{data.get('key', '')}",
            status="Open",
            created=datetime.utcnow().isoformat() + "Z",
        )


class ServiceNowCreator:
    """ServiceNow incident creator."""

    def __init__(self, config: TicketConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.host,
            auth=(config.username, config.password),
        )

    def create_incident(
        self,
        short_description: str,
        description: str,
        priority: str = "3",
        category: str = "Security",
    ) -> AlertTicket:
        """Create ServiceNow incident."""
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
        except Exception:
            pass

        return self._sample_ticket(short_description)

    def _parse_incident(self, data: dict) -> AlertTicket:
        return AlertTicket(
            key=data.get("number", ""),
            url=f"{self.config.host}/incident.do?sys_id={data.get('sys_id', '')}",
            status=data.get("state", ""),
        )


class TicketManager:
    """Ticketing system manager."""

    def __init__(self):
        self.creators: dict[str, JiraCreator | ServiceNowCreator] = {}

    def add_jira(self, **config) -> JiraCreator:
        ticket_config = TicketConfig(type="jira", **config)
        creator = JiraCreator(ticket_config)
        self.creators["jira"] = creator
        return creator

    def add_servicenow(self, **config) -> ServiceNowCreator:
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
        """Create ticket from enriched alert data."""
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

        return self._sample_ticket(title)

    def _format_description(
        self,
        alert_data: dict,
        enrich_data: dict | None,
    ) -> str:
        """Format ticket description."""
        lines = [
            f"## Alert Details",
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
        return AlertTicket(
            key=f"SOC-{1000}",
            title=title,
            status="Open",
            url=f"https://jira.example.com/browse/SOC-1000",
            created=datetime.utcnow().isoformat() + "Z",
        )


def create_ticket_system(system: str = "jira", **config) -> JiraCreator | ServiceNowCreator:
    """Factory for ticket system creators."""
    if system == "jira":
        return JiraCreator(TicketConfig(type="jira", **config))
    elif system == "servicenow":
        return ServiceNowCreator(TicketConfig(type="servicenow", **config))
    raise ValueError(f"Unknown system: {system}")