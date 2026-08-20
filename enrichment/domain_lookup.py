#!/usr/bin/env python3
"""Domain enrichment module for alert triage.

Resolves DNS records, performs lightweight WHOIS analysis (TLD reputation),
checks the domain against known malicious/benign lists, and flags suspicious
naming patterns such as DGA-like strings and social-engineering keywords.

Design notes:
    - DNS resolution uses ``socket.getaddrinfo`` for A/AAAA records and
      optionally ``dnspython`` for MX/NS/TXT/CNAME when the library is
      installed.  The import is guarded so the module remains usable without it.
    - WHOIS and reputation checks are simulated with static lookup tables.
      Production deployments should query live WHOIS/Threat-Intel APIs.
"""

import argparse
import json
import re
import socket
import warnings

from utils import utcnow_iso


def enrich_domain(domain: str) -> dict:
    """Run all available enrichment checks against *domain*.

    Args:
        domain: A fully-qualified domain name to enrich.

    Returns:
        A dict with a ``checks`` sub-dict containing DNS, WHOIS, reputation,
        and suspicious-pattern results.
    """
    result = {
        "domain": domain,
        "timestamp": utcnow_iso(),
        "checks": {},
    }

    result["checks"]["dns"] = get_dns_records(domain)
    result["checks"]["whois"] = get_whois(domain)
    result["checks"]["reputation"] = check_reputation(domain)
    result["checks"]["suspicious"] = check_suspicious(domain)

    return result


def get_dns_records(domain: str) -> dict:
    """Resolve common DNS record types for *domain*.

    A and AAAA records are always resolved via ``socket.getaddrinfo``.
    MX, NS, TXT, and CNAME are resolved only when ``dnspython`` is
    available; a warning is emitted otherwise.

    Args:
        domain: The domain to resolve.

    Returns:
        A dict mapping record-type keys (``a``, ``aaaa``, ``mx``, …)
        to lists of string values.
    """
    records = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": []}

    try:
        result = socket.getaddrinfo(domain, None)
        for r in result:
            ip = r[4][0]
            # Distinguish IPv4 from IPv6 by the presence of a colon.
            if ":" in ip:
                records["aaaa"].append(ip)
            else:
                records["a"].append(ip)
    except socket.gaierror:
        pass

    try:
        import dns.resolver  # type: ignore[import-untyped]
        for record_type in ["MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                key = record_type.lower()
                records[key] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
    except ImportError:
        # dnspython is an optional dependency — advanced record types are
        # silently skipped with a deprecation-style warning.
        warnings.warn("dnspython not installed — advanced DNS records unavailable (install with: uv add dnspython)")

    return records


def get_whois(domain: str) -> dict:
    """Perform lightweight WHOIS-style analysis on *domain*.

    Extracts the TLD and checks it against a curated list of suspicious
    free/cheap TLDs frequently abused by threat actors (e.g. .xyz, .tk, .ml).

    Args:
        domain: The domain to analyse.

    Returns:
        A dict with ``registered``, ``tld``, and optionally ``suspicious_tld``
        and ``suspicious_reason`` keys.
    """
    suspicious_tlds = [".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz"]

    whois = {
        "registered": True,
        "tld": domain.split(".")[-1] if "." in domain else "unknown",
    }

    # Flag free/cheap TLDs commonly associated with phishing and malware.
    domain_lower = domain.lower()
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            whois["suspicious_tld"] = True
            whois["suspicious_reason"] = "Free/cheap TLD commonly used in malware"
            break

    return whois


def check_reputation(domain: str) -> dict:
    """Match *domain* against static known-malicious and known-benign lists.

    In production this should be replaced with a live threat-intelligence
    feed (e.g. VirusTotal, AbuseIPDB, URLhaus).

    Args:
        domain: The domain to look up.

    Returns:
        A dict with ``reputation`` (``malicious`` | ``benign`` | ``unknown``)
        and ``confidence`` (0.0–1.0).
    """
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
    """Analyse *domain* for suspicious naming patterns.

    Checks for:
        - Unusually long random-looking subdomains (potential DGA output).
        - Multiple consecutive hyphens.
        - Long numeric sequences.
        - Social-engineering keywords (login, secure, update, etc.).
        - Known DGA indicator substrings.

    Args:
        domain: The domain to analyse.

    Returns:
        A dict with ``is_suspicious`` (bool) and ``reasons`` (list of str).
    """
    suspicious = {"is_suspicious": False, "reasons": []}

    # Each pattern is paired with a human-readable reason for the flag.
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

    # Simple substring heuristic for DGA-like domains.
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
                # Truncate long lists to keep the table readable.
                value = ", ".join(str(v) for v in check_value[:3])
                if len(check_value) > 3:
                    value += f" (+{len(check_value)-3} more)"
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)


if __name__ == "__main__":
    main()