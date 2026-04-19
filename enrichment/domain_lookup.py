#!/usr/bin/env python3
"""Domain enrichment script for alert triage."""

import argparse
import json
import re
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any, Optional


def enrich_domain(domain: str) -> dict:
    """Enrich domain with available context."""
    result = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {},
    }

    result["checks"]["dns"] = get_dns_records(domain)
    result["checks"]["whois"] = get_whois(domain)
    result["checks"]["reputation"] = check_reputation(domain)
    result["checks"]["suspicious"] = check_suspicious(domain)

    return result


def get_dns_records(domain: str) -> dict:
    """Get DNS records for domain."""
    records = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": []}

    try:
        result = socket.getaddrinfo(domain, None)
        for r in result:
            ip = r[4][0]
            if ":" in ip:
                records["aaaa"].append(ip)
            else:
                records["a"].append(ip)
    except socket.gaierror:
        pass

    try:
        import dns.resolver
        for record_type in ["MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                key = record_type.lower()
                records[key] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
    except ImportError:
        pass

    return records


def get_whois(domain: str) -> dict:
    """Get basic WHOIS information (simulated)."""
    suspicious_tlds = [".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz"]

    whois = {
        "registered": True,
        "tld": domain.split(".")[-1] if "." in domain else "unknown",
    }

    domain_lower = domain.lower()
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            whois["suspicious_tld"] = True
            whois["suspicious_reason"] = "Free/cheap TLD commonly used in malware"
            break

    return whois


def check_reputation(domain: str) -> dict:
    """Check domain reputation."""
    known_malicious = [
        "evil.com",
        "malware.net",
        "phishing.test",
        "ransomware.xyz",
    ]

    known_benign = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "github.com",
    ]

    domain_lower = domain.lower()

    if domain_lower in known_malicious:
        return {"reputation": "malicious", "confidence": 0.95}

    if domain_lower in known_benign:
        return {"reputation": "benign", "confidence": 0.95}

    return {"reputation": "unknown", "confidence": 0.0}


def check_suspicious(domain: str) -> dict:
    """Check for suspicious domain patterns."""
    suspicious = {"is_suspicious": False, "reasons": []}

    patterns = [
        (r"^[a-z0-9]{20,}\.", "Long random subdomain"),
        (r"-{2,}", "Multiple hyphens"),
        (r"\d{4,}", "Long number sequence"),
        (r"(login|signin|secure|account|update).*\.", "Social engineering pattern"),
    ]

    domain_lower = domain.lower()

    for pattern, reason in patterns:
        if re.search(pattern, domain_lower):
            suspicious["is_suspicious"] = True
            suspicious["reasons"].append(reason)

    dga_indicators = ["jghjhg", "xyz123", "random", "temp"]
    if any(indicator in domain_lower for indicator in dga_indicators):
        suspicious["is_suspicious"] = True
        suspicious["reasons"].append("Possible DGA (Domain Generation Algorithm)")

    return suspicious


def main():
    parser = argparse.ArgumentParser(description="Domain Enrichment Tool")
    parser.add_argument("domain", help="Domain to enrich")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result = enrich_domain(args.domain)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        table = Table(title=f"Domain Enrichment: {args.domain}")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        checks = result.get("checks", {})
        for check_name, check_value in checks.items():
            if isinstance(check_value, dict):
                value = ", ".join([f"{k}: {v}" for k, v in check_value.items()])
            elif isinstance(check_value, list):
                value = ", ".join(str(v) for v in check_value[:3])
                if len(check_value) > 3:
                    value += f" (+{len(check_value)-3} more)"
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)


if __name__ == "__main__":
    main()