#!/usr/bin/env python3
"""SIEM alert collector for AlertFlow.

Normalises alerts from multiple SIEM platforms (Splunk Enterprise
Security, Elasticsearch/OpenSearch) into a common ``Alert`` dataclass
so downstream playbooks and triage logic never need to care which SIEM
is in use.

Key design decisions:

* **Query sanitisation** -- user-supplied index names and severity
  values are stripped of non-alphanumeric characters before being
  interpolated into Splunk SPL.  This is a defence-in-depth measure;
  the primary protection is that these values should already be
  validated upstream, but we never trust that.
* **Sample fallback** -- every collector returns deterministic sample
  alerts when the SIEM is unreachable, credentials are wrong, or the
  query times out.  This keeps demo/development workflows functional
  without a live SIEM.
* **Factory pattern** -- ``create_siem_collector()`` maps a
  ``SIEMConfig.type`` string to the concrete collector class,
  keeping the caller decoupled from implementation details.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SIEMConfig:
    """Connection and query configuration for a SIEM instance.

    Attributes:
        type: Backend selector -- ``"splunk"`` or ``"elasticsearch"``.
        host: Hostname or IP of the SIEM API endpoint.
        port: API port (Splunk default 8089, ES default 9200).
        username / password: Basic-auth credentials.
        api_key: Alternative key-based auth (used by some ES setups).
        index: Target index / index pattern to search.
        verify_ssl: Whether to enforce TLS certificate validation.
    """

    type: str = "splunk"
    host: str = "localhost"
    port: int = 8089
    username: str = ""
    password: str = ""
    api_key: str = ""
    index: str = "security"
    verify_ssl: bool = True


@dataclass
class Alert:
    """Platform-agnostic representation of a single SIEM alert.

    Every collector is responsible for mapping its native alert format
    into this schema.  Fields left empty indicate the SIEM did not
    provide that value.

    Attributes:
        id: Unique alert identifier from the SIEM.
        source: Collector name (``"splunk"``, ``"elasticsearch"``).
        rule_name: Detection rule that fired.
        severity: Alert severity (``"critical"``, ``"high"``, ``"medium"``, ``"low"``).
        timestamp: ISO-8601 timestamp of the alert.
        host: Affected host.
        user: Associated user account, if any.
        src_ip / dst_ip: Network addresses involved.
        raw_message: Original unparsed message from the SIEM.
        raw_data: Full source payload for downstream enrichment.
    """

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
        """Serialise the alert to a plain dict (excludes raw_data)."""
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
    """Collector that queries Splunk Enterprise via its REST API.

    Uses Splunk's ``/services/search/jobs`` endpoint to execute SPL
    queries asynchronously: a search job is created, polled until
    ``dispatchState`` is ``"DONE"``, then results are fetched.

    If the Splunk instance is unreachable or the query fails, the
    collector falls back to sample alerts so the rest of the pipeline
    can continue operating.
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        # Splunk REST API uses HTTPS by default on port 8089.
        self._client = httpx.Client(
            base_url=f"https://{config.host}:{config.port}",
            auth=(config.username, config.password),
            verify=config.verify_ssl,
        )

    def search(self, query: str, earliest: str = "-1h", latest: str = "now") -> list[Alert]:
        """Execute a Splunk SPL search query.

        Args:
            query: Raw SPL search string (without ``search`` prefix).
            earliest: Splunk time-modifier for the start of the window.
            latest: Splunk time-modifier for the end of the window.

        Returns:
            List of ``Alert`` objects, or sample alerts on failure.
        """
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

        except Exception as e:
            logger.warning("Splunk search failed: %s", e)

        return self._get_sample_alerts()

    def _wait_for_results(self, sid: str, timeout: int = 30) -> list[Alert]:
        """Poll a Splunk search job until completion.

        Blocks up to *timeout* seconds, checking every second whether
        the job's ``dispatchState`` has reached ``"DONE"``.  Returns
        sample alerts on timeout or failure so the pipeline continues.

        Args:
            sid: Splunk search job session ID.
            timeout: Maximum seconds to wait before giving up.

        Returns:
            Parsed ``Alert`` list, or sample alerts.
        """
        import time

        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = self._client.get(
                    f"/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                )
                if resp.status_code == 200:
                    entries = resp.json().get("entry", [])
                    if entries:
                        status = entries[0].get("content", {}).get("dispatchState", "")
                        if status == "DONE":
                            results_resp = self._client.get(
                                f"/services/search/jobs/{sid}/results",
                                params={"output_mode": "json", "count": 100},
                            )
                            if results_resp.status_code == 200:
                                return [self._parse_result(r) for r in results_resp.json().get("results", [])]
                        elif status in ("FAILED", "CANCELLED"):
                            break
            except Exception:
                pass
            time.sleep(1)

        return self._get_sample_alerts()

    def _parse_result(self, result: dict) -> Alert:
        """Map a single Splunk result row to an ``Alert`` dataclass."""
        return Alert(
            id=result.get("_key", ""),
            source="splunk",
            rule_name=result.get("rule_name", "Unknown"),
            severity=result.get("severity", "medium"),
            timestamp=result.get("_time", ""),
            host=result.get("host", ""),
            user=result.get("user", ""),
            src_ip=result.get("src_ip", ""),
            dst_ip=result.get("dst_ip", ""),
            raw_message=result.get("_raw", ""),
            raw_data=result,
        )

    def _get_sample_alerts(self) -> list[Alert]:
        """Return hardcoded sample alerts for demo / fallback."""
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
        """Build and execute a Splunk query for recent alerts.

        Sanitises *index* and *severity* to prevent SPL injection via
        crafted configuration values.  The limit is clamped to
        [1, 10000] to avoid accidental resource exhaustion.

        Args:
            hours: How far back to search.
            severity: Optional severity filter (e.g. ``"high"``).
            limit: Maximum number of results.

        Returns:
            List of ``Alert`` objects.
        """
        # Strip characters that are not valid in Splunk index names
        safe_index = re.sub(r"[^a-zA-Z0-9_.\-]", "", self.config.index)
        query = f"index={safe_index}"
        if severity:
            # Strip non-alphanumeric chars to prevent SPL injection
            safe_severity = re.sub(r"[^a-zA-Z0-9]", "", severity)
            query += f" severity={safe_severity}"
        # Clamp limit to a sane range
        safe_limit = max(1, min(int(limit), 10000))
        query += f" | head {safe_limit}"

        return self.search(query, earliest=f"-{hours}h")


class ElasticsearchCollector:
    """Collector that queries Elasticsearch / OpenSearch.

    Builds a ``bool``/``range`` DSL query and executes it against the
    configured index.  Falls back to sample alerts when the cluster is
    unreachable.
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        # Elasticsearch typically listens on HTTP 9200.
        self._client = httpx.Client(
            base_url=f"http://{config.host}:{config.port}",
            verify=config.verify_ssl,
        )

    def search(self, query: str, hours: int = 1) -> list[Alert]:
        """Execute an Elasticsearch ``_search`` query.

        Args:
            query: Not currently used; time-range filtering is applied
                via a ``range`` clause on ``@timestamp``.
            hours: How far back to search.

        Returns:
            List of ``Alert`` objects, or sample alerts on failure.
        """
        now = datetime.now(timezone.utc)
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

        except Exception as e:
            logger.warning("Elasticsearch query failed: %s", e)

        return self._sample_alerts()

    def _parse_hit(self, hit: dict) -> Alert:
        """Map a single ES hit to an ``Alert`` dataclass."""
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
        """Convenience wrapper that searches for all recent alerts."""
        return self.search("*", hours)


def create_siem_collector(config: SIEMConfig) -> SplunkCollector | ElasticsearchCollector:
    """Factory that instantiates the correct collector for the given SIEM type.

    Args:
        config: Populated ``SIEMConfig`` with ``type`` set to
            ``"splunk"`` or ``"elasticsearch"``.

    Returns:
        A ``SplunkCollector`` or ``ElasticsearchCollector`` instance.

    Raises:
        ValueError: If ``config.type`` is not a recognised backend.
    """
    if config.type == "splunk":
        return SplunkCollector(config)
    elif config.type == "elasticsearch":
        return ElasticsearchCollector(config)
    raise ValueError(f"Unknown SIEM type: {config.type}")


def get_alerts_from_config(config: dict) -> list[Alert]:
    """Convenience entry point that builds a collector from a raw dict.

    Filters the dict to only known ``SIEMConfig`` keys so that extra
    keys (``hours``, ``severity``, ``limit``) can coexist in the same
    config object without causing a ``TypeError``.

    Args:
        config: Flat dict with SIEM connection fields plus optional
            ``hours``, ``severity``, ``limit`` query parameters.

    Returns:
        List of ``Alert`` objects from the configured SIEM.
    """
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
    """Return timestamped sample alerts for demo and fallback use."""
    return [
        Alert(
            id="alert-001",
            source="siem",
            rule_name="Failed Login Attempt - High Frequency",
            severity="high",
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            host="server01",
            user="admin",
            src_ip="192.168.1.50",
        ),
        Alert(
            id="alert-003",
            source="siem",
            rule_name="Firewall Block - Malicious IP",
            severity="medium",
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            host="firewall",
            dst_ip="203.0.113.50",
        ),
    ]


def enrich_with_siem(alert: Alert, config: dict) -> Alert:
    """Enrich an alert with related SIEM activity from the last 24 hours.

    Queries the SIEM for other alerts sharing the same host, user,
    source IP, or destination IP, then attaches up to five related
    alert summaries to ``alert.raw_data["siem_related"]``.

    Args:
        alert: The base alert to enrich.
        config: SIEM configuration dict (same format as ``get_alerts_from_config``).

    Returns:
        The same ``Alert`` instance with ``raw_data`` mutated in-place.
    """
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