#!/usr/bin/env python3
"""Hash reputation lookup for alert triage."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional


def enrich_hash(hash_value: str) -> dict:
    """Enrich hash with available context."""
    result = {
        "hash": hash_value,
        "hash_type": detect_hash_type(hash_value),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {},
    }

    result["checks"]["reputation"] = check_reputation(hash_value)
    result["checks"]["vt_lookup"] = check_virustotal(hash_value)
    result["checks"]["file_info"] = get_file_info(hash_value)

    return result


def detect_hash_type(hash_value: str) -> str:
    """Detect hash type based on length."""
    length = len(hash_value)

    if re.match(r"^[a-fA-F0-9]{32}$", hash_value):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{32}$", hash_value):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{40}$", hash_value):
        return "sha1"
    elif re.match(r"^[a-fA-F0-9]{64}$", hash_value):
        return "sha256"
    elif re.match(r"^[a-fA-F0-9]{128}$", hash_value):
        return "sha512"
    else:
        return "unknown"


def check_reputation(hash_value: str) -> dict:
    """Check hash against known database."""
    malicious_patterns = {
        "aadea647": {"name": "mimikatz", "family": "credential_theft", "reputation": "malicious"},
        "bebecacd": {"name": "mimikatz", "family": "credential_theft", "reputation": "malicious"},
        "cafecafe": {"name": "pwdump", "family": "credential_theft", "reputation": "malicious"},
        "deadbeef": {"name": "meterpreter", "family": "reverse_shell", "reputation": "malicious"},
        "badc0de": {"name": "cobalt_strike", "family": " RAT", "reputation": "malicious"},
    }

    hash_prefix = hash_value[:8].lower()
    if hash_prefix in malicious_patterns:
        return malicious_patterns[hash_prefix]

    benign_patterns = {
        "e3b0c44": {"name": "windows_system32", "reputation": "benign"},
        "d41d8cd": {"name": "empty_file", "reputation": "benign"},
    }

    if hash_prefix in benign_patterns:
        return benign_patterns[hash_prefix]

    return {"reputation": "unknown", "confidence": 0.0}


def check_virustotal(hash_value: str) -> dict:
    """Simulate VirusTotal lookup."""
    suspicious_hashes = {
        "aadea647": {"malicious": 45, "undetected": 5, "total": 50},
        "bebecacd": {"malicious": 38, "undetected": 12, "total": 50},
    }

    hash_prefix = hash_value[:8].lower()
    if hash_prefix in suspicious_hashes:
        return {
            "detection": suspicious_hashes[hash_prefix],
            "vendors": [
                "CrowdStrike",
                "Microsoft",
                "Symantec",
                "Kaspersky",
                "McAfee",
            ],
        }

    return {
        "detection": {"malicious": 0, "undetected": 0, "total": 0},
        "note": "Not found in database",
    }


def get_file_info(hash_value: str) -> dict:
    """Get file information based on hash."""
    file_signatures = {
        "aadea647": {"format": "PE32", "size": "358KB", "description": "Executable"},
        "bebecacd": {"format": "DLL", "size": "1.2MB", "description": "Dynamic Link Library"},
    }

    hash_prefix = hash_value[:8].lower()
    if hash_prefix in file_signatures:
        return file_signatures[hash_prefix]

    return {"format": "unknown", "size": "unknown"}


def main():
    parser = argparse.ArgumentParser(description="Hash Reputation Lookup")
    parser.add_argument("hash", help="Hash to look up (MD5/SHA1/SHA256)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result = enrich_hash(args.hash)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        table = Table(title=f"Hash Lookup: {args.hash[:16]}...")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        checks = result.get("checks", {})
        for check_name, check_value in checks.items():
            if isinstance(check_value, dict):
                value = ", ".join([f"{k}: {v}" for k, v in check_value.items()])
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)
        console.print(f"[dim]Hash type: {result.get('hash_type', 'unknown')}[/dim]")


if __name__ == "__main__":
    main()