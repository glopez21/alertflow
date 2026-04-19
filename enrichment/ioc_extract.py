#!/usr/bin/env python3
"""Automated IOC extraction from alerts."""

import argparse
import json
import re
from datetime import datetime
from typing import Any, List, Set


def extract_iocs(alert_text: str) -> dict:
    """Extract IOCs from alert text."""
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
    """Extract IP addresses."""
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    return list(set(re.findall(ipv4_pattern, text)))


def extract_domains(text: str) -> List[str]:
    """Extract domain names."""
    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|pw|tk|ml|ga|cf|gq|info|biz|me|co|ru|cn|in|au|uk|de|fr|jp|br)\b"
    return list(set(re.findall(domain_pattern, text)))


def extract_hashes(text: str) -> dict:
    """Extract file hashes."""
    hashes = {"md5": [], "sha1": [], "sha256": []}

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    hashes["md5"] = list(set(re.findall(md5_pattern, text)))
    hashes["sha1"] = list(set(re.findall(sha1_pattern, text)))
    hashes["sha256"] = list(set(re.findall(sha256_pattern, text)))

    return hashes


def extract_urls(text: str) -> List[str]:
    """Extract URLs."""
    url_pattern = r"https?://[^\s<>'\"{}|\\^`\[\]]+"
    return list(set(re.findall(url_pattern, text)))


def extract_emails(text: str) -> List[str]:
    """Extract email addresses."""
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return list(set(re.findall(email_pattern, text)))


def extract_filepaths(text: str) -> List[str]:
    """Extract file paths."""
    windows_pattern = r"[A-Za-z]:\\[^\s<>'\"{}|\\^`\[\]]+"
    unix_pattern = r"(?:/home/|/var/|/etc/|/usr/|/tmp/)[^\s<>'\"{}|\\^`\[\]]+"

    paths = list(set(re.findall(windows_pattern, text)))
    paths.extend(list(set(re.findall(unix_pattern, text))))

    return paths


def extract_accounts(text: str) -> List[str]:
    """Extract user accounts."""
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