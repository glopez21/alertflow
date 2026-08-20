#!/usr/bin/env python3
"""Threat feed poller for AlertFlow.

Aggregates IOC (Indicator of Compromise) lookups across multiple
commercial and open-source threat intelligence platforms:

* **VirusTotal** -- file-hash and IP reputation from 70+ AV engines.
* **AbuseIPDB** -- community-sourced IP abuse reporting.
* **AlienVault OTX** -- open pulse-based threat intelligence.

Each feed is wrapped in its own client class that normalises the
platform-specific API response into a common ``IOC`` dataclass.  The
``FeedPoller`` orchestrator fans out a single IOC check across all
configured feeds and collects results, while convenience functions
(``enrich_alert_with_feeds``, ``check_ioc_with_feeds``) provide
stateless one-shot entry points for playbooks.

All client classes implement the context-manager protocol to ensure
the underlying ``httpx.Client`` connection pool is properly closed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FeedConfig:
    """Configuration for a single threat intelligence feed.

    Attributes:
        type: Feed selector (``"virustotal"``, ``"abuseipdb"``,
            ``"alienvault"``, ``"misp"``).
        api_key: API key or token for the feed provider.
        host: Optional custom endpoint URL override.
        verify_ssl: Whether to enforce TLS certificate validation.
    """

    type: str = ""  # virustotal, abuseipdb, alienvault, misp
    api_key: str = ""
    host: str = ""
    verify_ssl: bool = True


@dataclass
class IOC:
    """Normalised indicator of compromise from any feed provider.

    All feed clients map their platform-specific responses into this
    common schema so downstream logic (enrichment, ticketing, scoring)
    does not need to know which provider supplied the data.

    Attributes:
        value: The indicator value (IP address, hash, domain, URL).
        type: Indicator type (``"ip"``, ``"domain"``, ``"hash"``, ``"url"``).
        source: Feed name that produced this IOC (``"virustotal"``, etc.).
        confidence: Normalised score in [0.0, 1.0].
        severity: Derived severity (``"critical"``, ``"high"``, ``"medium"``).
        tags: Free-form classification tags from the feed.
        first_seen / last_seen: ISO-8601 timestamps.
        metadata: Arbitrary platform-specific extra fields.
    """

    value: str
    type: str  # ip, domain, hash, url
    source: str
    confidence: float = 0.0
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "source": self.source,
            "confidence": self.confidence,
            "severity": self.severity,
            "tags": self.tags,
        }


class VirusTotalClient:
    """VirusTotal v3 API client for IP and file-hash reputation checks.

    Authenticates via the ``x-apikey`` header.  Results are cached in
    ``_reports`` so that ``recent_reports()`` can return all IOCs
    looked up during a session.
    """

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://www.virustotal.com/api/v3"
        self._client = httpx.Client(
            headers={"x-apikey": config.api_key},
            verify=config.verify_ssl,
        )
        self._reports: list[IOC] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._client.close()

    def recent_reports(self) -> list[IOC]:
        """Return all IOCs looked up during this client's lifetime."""
        return list(self._reports)

    def check_ip(self, ip: str) -> IOC | None:
        """Query VirusTotal for IP address reputation.

        The confidence score is computed as the ratio of AV engines
        that flagged the IP as malicious.  Severity thresholds:
        >50% malicious -> critical, >20% -> high, otherwise medium.

        Args:
            ip: IPv4 or IPv6 address to check.

        Returns:
            ``IOC`` with reputation data, or ``None`` on error.
        """
        try:
            resp = self._client.get(f"{self.base_url}/ip_addresses/{ip}")
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                confidence = malicious / total if total > 0 else 0
                severity = "critical" if confidence > 0.5 else "high" if confidence > 0.2 else "medium"

                result = IOC(
                    value=ip,
                    type="ip",
                    source="virustotal",
                    confidence=confidence,
                    severity=severity,
                    last_seen=data.get("last_analysis_date", ""),
                    metadata={"stats": stats},
                )
                self._reports.append(result)
                return result
        except Exception as e:
            logger.warning("VirusTotal IP check failed for %s: %s", ip, e)
        return None

    def check_hash(self, hash_value: str) -> IOC | None:
        """Query VirusTotal for file-hash reputation.

        Severity is derived from the absolute count of AV detections
        rather than the ratio, because even a single detection on a
        rare file is significant: >20 detections -> critical,
        >5 detections -> high, otherwise medium.

        Args:
            hash_value: MD5, SHA-1, or SHA-256 hash.

        Returns:
            ``IOC`` with reputation data, or ``None`` on error.
        """
        try:
            resp = self._client.get(f"{self.base_url}/files/{hash_value}")
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                confidence = malicious / total if total > 0 else 0

                result = IOC(
                    value=hash_value,
                    type="hash",
                    source="virustotal",
                    confidence=confidence,
                    severity="critical" if malicious > 20 else "high" if malicious > 5 else "medium",
                    metadata={"stats": stats},
                )
                self._reports.append(result)
                return result
        except Exception as e:
            logger.warning("VirusTotal hash check failed: %s", e)
        return None


class AbuseIPDBClient:
    """AbuseIPDB v2 API client for IP reputation checks.

    Uses the ``/check`` endpoint with a 90-day lookback window.  The
    ``abuseConfidenceScore`` (0-100) is normalised to a 0-1 confidence
    value.  Severity thresholds: >80 -> critical, >50 -> high,
    otherwise medium.
    """

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self._client = httpx.Client(
            headers={"Key": config.api_key, "Accept": "application/json"},
            verify=config.verify_ssl,
        )
        self._reports: list[IOC] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._client.close()

    def recent_reports(self) -> list[IOC]:
        """Return all IOCs looked up during this client's lifetime."""
        return list(self._reports)

    def check_ip(self, ip: str) -> IOC | None:
        """Check IP against AbuseIPDB.

        Args:
            ip: IPv4 address to check.

        Returns:
            ``IOC`` with reputation data, or ``None`` on error.
        """
        try:
            params = {"ip": ip, "maxAgeInDays": 90, "verbose": ""}
            resp = self._client.get(f"{self.base_url}/check", params=params)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_confidence = data.get("abuseConfidenceScore", 0)

                result = IOC(
                    value=ip,
                    type="ip",
                    source="abuseipdb",
                    confidence=abuse_confidence / 100,
                    severity="critical" if abuse_confidence > 80 else "high" if abuse_confidence > 50 else "medium",
                    last_seen=data.get("lastReportedAt", ""),
                    metadata={
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "usage_type": data.get("usageType"),
                    },
                )
                self._reports.append(result)
                return result
        except Exception as e:
            logger.warning("AbuseIPDB check failed for %s: %s", ip, e)
        return None


class AlienVaultOTXClient:
    """AlienVault OTX API client for IP reputation via pulse count.

    Confidence is derived from the number of OTX pulses containing the
    indicator, capped at 1.0 (10+ pulses).  Any pulses -> high
    severity, none -> medium.
    """

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://otx.alienvault.com/api/v1"
        self._client = httpx.Client(
            headers={"X-OTX-API-KEY": config.api_key},
            verify=config.verify_ssl,
        )
        self._reports: list[IOC] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._client.close()

    def recent_reports(self) -> list[IOC]:
        """Return all IOCs looked up during this client's lifetime."""
        return list(self._reports)

    def check_ip(self, ip: str) -> IOC | None:
        """Check IP against AlienVault OTX pulse data.

        Args:
            ip: IPv4 address to check.

        Returns:
            ``IOC`` with reputation data, or ``None`` on error.
        """
        try:
            resp = self._client.get(f"{self.base_url}/indicators/IPv4/{ip}")
            if resp.status_code == 200:
                data = resp.json().get("pulse_info", {})
                pulses = data.get("count", 0)

                result = IOC(
                    value=ip,
                    type="ip",
                    source="alienvault_otx",
                    confidence=min(pulses / 10, 1.0),
                    severity="high" if pulses > 0 else "medium",
                    last_seen=data.get("modified", ""),
                    metadata={"pulses": pulses},
                )
                self._reports.append(result)
                return result
        except Exception as e:
            logger.warning("AlienVault OTX check failed for %s: %s", ip, e)
        return None


class FeedPoller:
    """Orchestrator that checks IOCs across multiple threat feeds.

    Maintains a registry of feed clients and provides ``check_ioc()``
    which fans out a single indicator lookup to every registered feed
    that supports the given IOC type.  Results are aggregated into a
    flat list for downstream consumption.
    """

    def __init__(self):
        self.feeds: dict[str, VirusTotalClient | AbuseIPDBClient | AlienVaultOTXClient] = {}

    def add_virustotal(self, **config) -> VirusTotalClient:
        """Register a VirusTotal feed.

        Args:
            **config: Keyword args for ``FeedConfig`` (e.g. ``api_key``).

        Returns:
            The created ``VirusTotalClient``.
        """
        feed = VirusTotalClient(FeedConfig(type="virustotal", **config))
        self.feeds["virustotal"] = feed
        return feed

    def add_abuseipdb(self, **config) -> AbuseIPDBClient:
        """Register an AbuseIPDB feed.

        Args:
            **config: Keyword args for ``FeedConfig`` (e.g. ``api_key``).

        Returns:
            The created ``AbuseIPDBClient``.
        """
        feed = AbuseIPDBClient(FeedConfig(type="abuseipdb", **config))
        self.feeds["abuseipdb"] = feed
        return feed

    def add_alienvault(self, **config) -> AlienVaultOTXClient:
        """Register an AlienVault OTX feed.

        Args:
            **config: Keyword args for ``FeedConfig`` (e.g. ``api_key``).

        Returns:
            The created ``AlienVaultOTXClient``.
        """
        feed = AlienVaultOTXClient(FeedConfig(type="alienvault", **config))
        self.feeds["alienvault"] = feed
        return feed

    def check_ioc(self, value: str, ioc_type: str = "ip") -> list[IOC]:
        """Check an IOC against all registered feeds.

        Uses duck-typing (``hasattr``) to call ``check_ip`` or
        ``check_hash`` on each feed, skipping feeds that do not support
        the requested IOC type.

        Args:
            value: Indicator value (IP address or file hash).
            ioc_type: ``"ip"`` or ``"hash"``.

        Returns:
            List of ``IOC`` results (one per feed that responded).
        """
        results = []

        for feed_name, feed in self.feeds.items():
            if ioc_type == "ip" and hasattr(feed, "check_ip"):
                result = feed.check_ip(value)
                if result:
                    results.append(result)
            elif ioc_type == "hash" and hasattr(feed, "check_hash"):
                result = feed.check_hash(value)
                if result:
                    results.append(result)

        return results

    def get_high_confidence(self, threshold: float = 0.5) -> list[IOC]:
        """Retrieve IOCs from recent checks that exceed a confidence threshold.

        Args:
            threshold: Minimum confidence score (0.0-1.0) to include.

        Returns:
            List of high-confidence ``IOC`` objects across all feeds.
        """
        high_confidence = []
        for feed in self.feeds.values():
            if hasattr(feed, "recent_reports"):
                reports = feed.recent_reports()  # type: ignore[arg-type]
                for report in reports:
                    if report.confidence >= threshold:
                        high_confidence.append(report)
        return high_confidence


def check_ioc_with_feeds(ioc: str, feeds_config: list[dict]) -> list[dict]:
    """Stateless one-shot IOC check across multiple feeds.

    Builds a ``FeedPoller`` from *feeds_config*, auto-detects whether
    the IOC is a hash or IP, and returns serialised results.

    Args:
        ioc: Indicator value to check.
        feeds_config: List of feed config dicts (each must have a
            ``"type"`` key and provider-specific fields).

    Returns:
        List of serialised ``IOC`` dicts.
    """
    poller = create_feed_poller(feeds_config)
    ioc_type = "hash" if _is_probably_hash(ioc) else "ip"
    results = poller.check_ioc(ioc, ioc_type)
    return [r.to_dict() for r in results]


def _is_probably_hash(value: str) -> bool:
    """Heuristic to distinguish file hashes from IP addresses.

    File hashes are hex strings of fixed, known lengths (MD5=32,
    SHA-1=40, SHA-256=64, SHA-512=128).  This is intentionally a
    loose check; the feed API itself will reject invalid values.
    """
    return len(value) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in value)


def enrich_alert_with_feeds(alert: dict, feeds_config: list[dict]) -> dict:
    """Enrich an alert dict with threat-intelligence context.

    Extracts ``src_ip``, ``dst_ip``, and ``hash`` fields from the alert,
    checks each against all configured feeds, and attaches any results
    as a ``"threat_intel"`` list on the returned dict.

    Args:
        alert: Alert dict (at minimum should contain IP or hash fields).
        feeds_config: Feed configuration list for ``check_ioc_with_feeds``.

    Returns:
        A *new* dict with an optional ``"threat_intel"`` key added.
    """
    result = dict(alert)
    iocs_to_check = []

    if result.get("src_ip"):
        iocs_to_check.append((result["src_ip"], "ip"))
    if result.get("dst_ip"):
        iocs_to_check.append((result["dst_ip"], "ip"))
    if result.get("hash"):
        iocs_to_check.append((result["hash"], "hash"))

    threat_intel = []
    for ioc, ioc_type in iocs_to_check:
        results = check_ioc_with_feeds(ioc, feeds_config)
        if results:
            threat_intel.extend(results)

    if threat_intel:
        result["threat_intel"] = threat_intel

    return result


def create_feed_poller(configs: list[dict]) -> FeedPoller:
    """Build a ``FeedPoller`` from a list of feed config dicts.

    Args:
        configs: List of dicts, each with a ``"type"`` key matching
            one of the supported feed identifiers.

    Returns:
        A fully configured ``FeedPoller`` instance.
    """
    poller = FeedPoller()

    for config in configs:
        feed_type = config.get("type", "")

        if feed_type == "virustotal":
            poller.add_virustotal(api_key=config.get("api_key", ""))
        elif feed_type == "abuseipdb":
            poller.add_abuseipdb(api_key=config.get("api_key", ""))
        elif feed_type == "alienvault":
            poller.add_alienvault(api_key=config.get("api_key", ""))

    return poller