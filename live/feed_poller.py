#!/usr/bin/env python3
"""Threat feed poller for AlertFlow."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx


@dataclass
class FeedConfig:
    """Threat feed configuration."""

    type: str = ""  # virustotal, abuseipdb, alienvault, misp
    api_key: str = ""
    host: str = ""
    verify_ssl: bool = False


@dataclass
class IOC:
    """Threat indicator."""

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
    """VirusTotal API client."""

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://www.virustotal.com/api/v3"
        self._client = httpx.Client(
            headers={"x-apikey": config.api_key},
            verify=config.verify_ssl,
        )

    def check_ip(self, ip: str) -> IOC | None:
        """Check IP reputation."""
        try:
            resp = self._client.get(f"{self.base_url}/ip_addresses/{ip}")
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                confidence = malicious / total if total > 0 else 0
                severity = "critical" if confidence > 0.5 else "high" if confidence > 0.2 else "medium"

                return IOC(
                    value=ip,
                    type="ip",
                    source="virustotal",
                    confidence=confidence,
                    severity=severity,
                    last_seen=data.get("last_analysis_date", ""),
                    metadata={"stats": stats},
                )
        except Exception:
            pass
        return None

    def check_hash(self, hash_value: str) -> IOC | None:
        """Check hash reputation."""
        try:
            resp = self._client.get(f"{self.base_url}/files/{hash_value}")
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                confidence = malicious / total if total > 0 else 0

                return IOC(
                    value=hash_value,
                    type="hash",
                    source="virustotal",
                    confidence=confidence,
                    severity="critical" if malicious > 20 else "high" if malicious > 5 else "medium",
                    metadata={"stats": stats},
                )
        except Exception:
            pass
        return None


class AbuseIPDBClient:
    """AbuseIPDB API client."""

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self._client = httpx.Client(
            headers={"Key": config.api_key, "Accept": "application/json"},
            verify=config.verify_ssl,
        )

    def check_ip(self, ip: str) -> IOC | None:
        """Check IP against AbuseIPDB."""
        try:
            params = {"ip": ip, "maxAgeInDays": 90, "verbose": ""}
            resp = self._client.get(f"{self.base_url}/check", params=params)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_confidence = data.get("abuseConfidenceScore", 0)

                return IOC(
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
        except Exception:
            pass
        return None


class AlienVaultOTXClient:
    """AlienVault OTX client."""

    def __init__(self, config: FeedConfig):
        self.config = config
        self.base_url = "https://otx.alienvault.com/api/v1"
        self._client = httpx.Client(
            headers={"X-OTX-API-KEY": config.api_key},
            verify=config.verify_ssl,
        )

    def check_ip(self, ip: str) -> IOC | None:
        """Check IP with OTX."""
        try:
            resp = self._client.get(f"{self.base_url}/indicators/IPv4/{ip}")
            if resp.status_code == 200:
                data = resp.json().get("pulse_info", {})
                pulses = data.get("count", 0)

                return IOC(
                    value=ip,
                    type="ip",
                    source="alienvault_otx",
                    confidence=min(pulses / 10, 1.0),
                    severity="high" if pulses > 0 else "medium",
                    last_seen=data.get("modified", ""),
                    metadata={"pulses": pulses},
                )
        except Exception:
            pass
        return None


class FeedPoller:
    """Poll multiple threat feeds."""

    def __init__(self):
        self.feeds: dict[str, VirusTotalClient | AbuseIPDBClient | AlienVaultOTXClient] = {}

    def add_virustotal(self, **config) -> VirusTotalClient:
        feed = VirusTotalClient(FeedConfig(type="virustotal", **config))
        self.feeds["virustotal"] = feed
        return feed

    def add_abuseipdb(self, **config) -> AbuseIPDBClient:
        feed = AbuseIPDBClient(FeedConfig(type="abuseipdb", **config))
        self.feeds["abuseipdb"] = feed
        return feed

    def add_alienvault(self, **config) -> AlienVaultOTXClient:
        feed = AlienVaultOTXClient(FeedConfig(type="alienvault", **config))
        self.feeds["alienvault"] = feed
        return feed

    def check_ioc(self, value: str, ioc_type: str = "ip") -> list[IOC]:
        """Check IOC against all configured feeds."""
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
        """Get high confidence IOCs."""
        high_confidence = []
        for feed in self.feeds.values():
            if hasattr(feed, "recent_reports"):
                reports = feed.recent_reports()
                for report in reports:
                    if report.confidence >= threshold:
                        high_confidence.append(report)
        return high_confidence


def check_ioc_with_feeds(ioc: str, feeds_config: list[dict]) -> list[dict]:
    """Check IOC against multiple feeds using config."""
    results = []

    for config in feeds_config:
        feed_type = config.get("type", "")

        if feed_type == "virustotal":
            client = VirusTotalClient(FeedConfig(api_key=config.get("api_key", "")))
            if "." in ioc and len(ioc) > 40:
                result = client.check_hash(ioc)
            else:
                result = client.check_ip(ioc)
            if result:
                results.append(result.to_dict())

        elif feed_type == "abuseipdb":
            client = AbuseIPDBClient(FeedConfig(api_key=config.get("api_key", "")))
            result = client.check_ip(ioc)
            if result:
                results.append(result.to_dict())

        elif feed_type == "alienvault":
            client = AlienVaultOTXClient(FeedConfig(api_key=config.get("api_key", "")))
            result = client.check_ip(ioc)
            if result:
                results.append(result.to_dict())

    return results


def enrich_alert_with_feeds(alert: dict, feeds_config: list[dict]) -> dict:
    """Enrich alert with threat intelligence."""
    iocs_to_check = []

    if alert.get("src_ip"):
        iocs_to_check.append((alert["src_ip"], "ip"))
    if alert.get("dst_ip"):
        iocs_to_check.append((alert["dst_ip"], "ip"))
    if alert.get("hash"):
        iocs_to_check.append((alert["hash"], "hash"))

    threat_intel = []
    for ioc, ioc_type in iocs_to_check:
        results = check_ioc_with_feeds(ioc, feeds_config)
        if results:
            threat_intel.extend(results)

    if threat_intel:
        alert["threat_intel"] = threat_intel

    return alert


def create_feed_poller(configs: list[dict]) -> FeedPoller:
    """Create feed poller from configs."""
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