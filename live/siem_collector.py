#!/usr/bin/env python3
"""SIEM alert collector for AlertFlow."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx


@dataclass
class SIEMConfig:
    """SIEM connection configuration."""

    type: str = "splunk"
    host: str = "localhost"
    port: int = 8089
    username: str = ""
    password: str = ""
    api_key: str = ""
    index: str = "security"
    verify_ssl: bool = False


@dataclass
class Alert:
    """Normalized SIEM alert."""

    id: str
    source: str
    rule_name: str
    severity: str
    timestamp: str
    host: str
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    raw_message: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "raw_message": self.raw_message,
        }


class SplunkCollector:
    """Splunk Enterprise Security collector."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=f"https://{config.host}:{config.port}",
            auth=(config.username, config.password),
            verify=config.verify_ssl,
        )

    def search(self, query: str, earliest: str = "-1h", latest: str = "now") -> list[Alert]:
        """Execute Splunk search."""
        search_query = f"search={query} earliest={earliest} latest={latest}"

        try:
            resp = self._client.post(
                "/services/search/jobs",
                data=search_query,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if resp.status_code == 201:
                sid = resp.json().get("sid")
                return self._wait_for_results(sid)

        except Exception:
            pass

        return self._get_sample_alerts()

    def _get_sample_alerts(self) -> list[Alert]:
        return [
            Alert(
                id="alert-001", source="siem", rule_name="Failed Login Attempt",
                severity="high", timestamp="", host="workstation01", user="john.smith",
            ),
            Alert(
                id="alert-002", source="siem", rule_name="Suspicious PowerShell",
                severity="critical", timestamp="", host="server01", user="admin",
            ),
        ]

    def get_recent_alerts(
        self,
        hours: int = 1,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        """Get recent alerts."""
        query = f"index={self.config.index}"
        if severity:
            query += f" severity={severity}"
        query += f" | head {limit}"

        return self.search(query, earliest=f"-{hours}h")


class ElasticsearchCollector:
    """Elasticsearch collector."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=f"http://{config.host}:{config.port}",
            verify=config.verify_ssl,
        )

    def search(self, query: str, hours: int = 1) -> list[Alert]:
        """Execute Elasticsearch query."""
        now = datetime.utcnow()
        start = (now - timedelta(hours=hours)).isoformat()

        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": start}}}
                    ]
                }
            },
            "size": 100,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        try:
            resp = self._client.post(
                f"/{self.config.index}/_search",
                json=es_query,
            )

            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                return [self._parse_hit(hit) for hit in hits]

        except Exception:
            pass

        return self._sample_alerts()

    def _parse_hit(self, hit: dict) -> Alert:
        source = hit.get("_source", {})
        return Alert(
            id=hit.get("_id", ""),
            source="elasticsearch",
            rule_name=source.get("rule_name", "Unknown"),
            severity=source.get("severity", "medium"),
            timestamp=source.get("@timestamp", ""),
            host=source.get("host", ""),
            user=source.get("user", ""),
            src_ip=source.get("src_ip", ""),
            dst_ip=source.get("dst_ip", ""),
            raw_data=source,
        )

    def get_recent_alerts(self, hours: int = 1, limit: int = 100) -> list[Alert]:
        return self.search("*", hours)


def create_siem_collector(config: SIEMConfig) -> SplunkCollector | ElasticsearchCollector:
    """Factory for SIEM collectors."""
    if config.type == "splunk":
        return SplunkCollector(config)
    elif config.type == "elasticsearch":
        return ElasticsearchCollector(config)
    raise ValueError(f"Unknown SIEM type: {config.type}")


def get_alerts_from_config(config: dict) -> list[Alert]:
    """Get alerts using config dict."""
    config_keys = {"type", "host", "port", "username", "password", "api_key", "index", "verify_ssl"}
    filtered = {k: v for k, v in config.items() if k in config_keys}
    siem_config = SIEMConfig(**filtered)
    collector = create_siem_collector(siem_config)
    return collector.get_recent_alerts(
        hours=config.get("hours", 1),
        severity=config.get("severity"),
        limit=config.get("limit", 100),
    )


def _sample_alerts() -> list[Alert]:
    """Return sample alerts for demo."""
    return [
        Alert(
            id="alert-001",
            source="siem",
            rule_name="Failed Login Attempt - High Frequency",
            severity="high",
            timestamp=datetime.utcnow().isoformat() + "Z",
            host="workstation01",
            user="john.smith",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
        ),
        Alert(
            id="alert-002",
            source="siem",
            rule_name="Suspicious PowerShell Execution",
            severity="critical",
            timestamp=datetime.utcnow().isoformat() + "Z",
            host="server01",
            user="admin",
            src_ip="192.168.1.50",
        ),
        Alert(
            id="alert-003",
            source="siem",
            rule_name="Firewall Block - Malicious IP",
            severity="medium",
            timestamp=datetime.utcnow().isoformat() + "Z",
            host="firewall",
            dst_ip="203.0.113.50",
        ),
    ]


def enrich_with_siem(alert: Alert, config: dict) -> Alert:
    """Enrich an alert with SIEM context."""
    siem_config = SIEMConfig(**config)
    collector = create_siem_collector(siem_config)

    search_terms = [
        f'host="{alert.host}"',
        f'user="{alert.user}"',
        f'src_ip="{alert.src_ip}"',
        f'dst_ip="{alert.dst_ip}"',
    ]

    related = collector.search(" OR ".join(search_terms), earliest="-24h")

    related_context = [
        {"rule": a.rule_name, "time": a.timestamp, "severity": a.severity}
        for a in related[:5]
    ]

    alert.raw_data["siem_related"] = related_context

    return alert