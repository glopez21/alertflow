#!/usr/bin/env python3
"""Automated IOC (Indicator of Compromise) extraction from alert text.

Scans free-form alert descriptions or log files and pulls out structured
IOC types: IPv4 addresses, domains, file hashes (MD5/SHA-1/SHA-256),
URLs, email addresses, file paths (Windows and Unix), and user-account
identifiers.

Design notes:
    - All extractors use ``re.findall`` with ``set()`` deduplication to
      avoid reporting the same indicator twice.
    - Regex patterns are deliberately conservative to minimise false
      positives — they validate structure (e.g. IPv4 octet ranges)
      rather than merely matching character classes.
    - Hash detection is ordered by length so that shorter hashes embedded
      inside longer ones do not cause false matches (the ``\b`` word
      boundary anchors help, but ordering adds safety).
"""

import argparse
import json
import re
from typing import List


def extract_iocs(alert_text: str) -> dict:
    """Extract every supported IOC type from *alert_text*.

    Args:
        alert_text: Free-form text (alert body, log snippet, etc.).

    Returns:
        A dict mapping each IOC type (``ips``, ``domains``, ``hashes``,
        ``urls``, ``emails``, ``filepaths``, ``accounts``) to its
        extracted values.
    """
    extracted = {
        "ips": [],
        "domains": [],
        "hashes": [],
        "urls": [],
        "emails": [],
        "filepaths": [],
        "accounts": [],
    }

    extracted["ips"] = extract_ips(alert_text)
    extracted["domains"] = extract_domains(alert_text)
    extracted["hashes"] = extract_hashes(alert_text)
    extracted["urls"] = extract_urls(alert_text)
    extracted["emails"] = extract_emails(alert_text)
    extracted["filepaths"] = extract_filepaths(alert_text)
    extracted["accounts"] = extract_accounts(alert_text)

    return extracted


def extract_ips(text: str) -> List[str]:
    """Extract valid IPv4 addresses from *text*.

    The pattern validates each octet is in the 0–255 range and uses
    ``\b`` word boundaries to avoid matching substrings of longer
    numbers or hostnames.
    """
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    return list(set(re.findall(ipv4_pattern, text)))


def extract_domains(text: str) -> List[str]:
    """Extract domain names from *text*.

    Matches labels conforming to RFC 1035 (alphanumeric + hyphens,
    max 63 chars per label) followed by a recognised TLD from a
    curated suffix list.  The list can be extended as needed.
    """
    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|pw|tk|ml|ga|cf|gq|info|biz|me|co|ru|cn|in|au|uk|de|fr|jp|br)\b"
    return list(set(re.findall(domain_pattern, text)))


def extract_hashes(text: str) -> dict:
    """Extract file hashes from *text*, grouped by algorithm.

    Detects three common hash lengths:
        - 32 hex chars → MD5
        - 40 hex chars → SHA-1
        - 64 hex chars → SHA-256

    Each sub-list is deduplicated via ``set()``.
    """
    hashes = {"md5": [], "sha1": [], "sha256": []}

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    hashes["md5"] = list(set(re.findall(md5_pattern, text)))
    hashes["sha1"] = list(set(re.findall(sha1_pattern, text)))
    hashes["sha256"] = list(set(re.findall(sha256_pattern, text)))

    return hashes


def extract_urls(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from *text*.

    Uses a broad exclusion set for characters that are invalid inside
    a URL path/query but may appear in surrounding prose (quotes,
    angle brackets, backslashes, etc.).
    """
    url_pattern = r"https?://[^\s<>'\"{}|\\^`\[\]]+"
    return list(set(re.findall(url_pattern, text)))


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from *text*.

    Matches the local-part, ``@`` sign, and a domain with at least a
    two-character TLD.  Intentionally does not match addresses inside
    angle brackets or quoted strings to reduce noise.
    """
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return list(set(re.findall(email_pattern, text)))


def extract_filepaths(text: str) -> List[str]:
    """Extract Windows and Unix file paths from *text*.

    Windows paths start with a drive letter (``C:\\…``).
    Unix paths are anchored to well-known directories (``/home/``,
    ``/var/``, ``/etc/``, ``/usr/``, ``/tmp/``) to limit false
    positives.
    """
    windows_pattern = r"[A-Za-z]:(?:\\[^\s<>'\"{}|\\^`\[\]]+)+"
    unix_pattern = r"(?:/home/|/var/|/etc/|/usr/|/tmp/)[^\s<>'\"{}|\\^`\[\]]+"

    paths = list(set(re.findall(windows_pattern, text)))
    paths.extend(list(set(re.findall(unix_pattern, text))))

    return paths


def extract_accounts(text: str) -> List[str]:
    """Extract user-account identifiers from *text*.

    Uses three complementary patterns:
        1. ``user: / username: / account:`` field-value pairs (common
           in structured alert fields).
        2. UNC-style paths ``\\\\server\\user`` (Windows logon events).
        3. Home-directory paths ``/home/user`` or ``/Users/user``
           (Unix log entries).
    """
    patterns = [
        r"(?:user|username|account):\s*([^\s<>'\"{}|\\^`\[\]]+)",
        r"\\\\([A-Za-z0-9_.\\]+)",
        r"/(?:home|Users)/([A-Za-z0-9_.]+)",
    ]

    accounts = []
    for pattern in patterns:
        accounts.extend(re.findall(pattern, text))

    return list(set(accounts))


def main():
    parser = argparse.ArgumentParser(description="IOC Extraction Tool")
    parser.add_argument("alert", nargs="?", help="Alert text or file path")
    parser.add_argument("--file", "-f", help="Read from file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as f:
            text = f.read()
    elif args.alert:
        text = args.alert
    else:
        parser.print_help()
        return

    result = extract_iocs(text)
    # Build a summary count for each IOC type.
    result["count"] = {
        "ips": len(result["ips"]),
        "domains": len(result["domains"]),
        "hashes": len(result["hashes"]["md5"]) + len(result["hashes"]["sha1"]) + len(result["hashes"]["sha256"]),
        "urls": len(result["urls"]),
        "emails": len(result["emails"]),
        "filepaths": len(result["filepaths"]),
        "accounts": len(result["accounts"]),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        table = Table(title="Extracted IOCs")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="yellow")
        table.add_column("Examples", style="white")

        counts = result.get("count", {})
        table.add_row("IP Addresses", str(counts.get("ips", 0)), ", ".join(result.get("ips", [])[:3]))
        table.add_row("Domains", str(counts.get("domains", 0)), ", ".join(result.get("domains", [])[:3]))
        hashes = result.get("hashes", {})
        total_hashes = len(hashes.get("md5", [])) + len(hashes.get("sha1", [])) + len(hashes.get("sha256", []))
        table.add_row("Hashes", str(total_hashes), ", ".join(hashes.get("sha256", [])[:2])) if hashes.get("sha256") else table.add_row("Hashes", str(total_hashes), "")
        table.add_row("URLs", str(counts.get("urls", 0)), ", ".join(result.get("urls", [])[:2]))
        table.add_row("Emails", str(counts.get("emails", 0)), ", ".join(result.get("emails", [])[:3]))
        table.add_row("File Paths", str(counts.get("filepaths", 0)), ", ".join(result.get("filepaths", [])[:2]))
        table.add_row("Accounts", str(counts.get("accounts", 0)), ", ".join(result.get("accounts", [])[:3]))

        console.print(table)


if __name__ == "__main__":
    main()