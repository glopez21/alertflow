#!/usr/bin/env python3
"""Hash reputation lookup module for alert triage.

Detects common file-hash types (MD5, SHA-1, SHA-256, SHA-512), matches the
leading hex prefix against a static reputation database of known-malicious
and known-benign samples, and provides a simulated VirusTotal detection
summary.

Design notes:
    - Reputation matching uses the first 8 hex characters as a prefix key.
      This is a lightweight stand-in for a real hash-reputation API (VirusTotal,
      MalwareBazaar, etc.).
    - All lookup tables are static demo data — swap them for live API calls
      in production.
"""

import argparse
import json
import re

from utils import utcnow_iso


def enrich_hash(hash_value: str) -> dict:
    """Enrich a file hash with type detection, reputation, and file metadata.

    Args:
        hash_value: A hex-encoded hash string.

    Returns:
        A dict containing ``hash_type``, a ``checks`` sub-dict with
        ``reputation``, ``vt_lookup``, and ``file_info`` results.
    """
    result = {
        "hash": hash_value,
        "hash_type": detect_hash_type(hash_value),
        "timestamp": utcnow_iso(),
        "checks": {},
    }

    result["checks"]["reputation"] = check_reputation(hash_value)
    result["checks"]["vt_lookup"] = check_virustotal(hash_value)
    result["checks"]["file_info"] = get_file_info(hash_value)

    return result


def detect_hash_type(hash_value: str) -> str:
    """Identify the hash algorithm from the hex string length.

    Supported lengths: 32 (MD5), 40 (SHA-1), 64 (SHA-256), 128 (SHA-512).

    Args:
        hash_value: A hex-encoded hash string.

    Returns:
        A lowercase algorithm name or ``"unknown"``.
    """
    if re.match(r"^[a-fA-F0-9]{32}$", hash_value):
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
    """Look up *hash_value* in the static reputation database.

    Matching is done on the first 8 hex characters (the "prefix").  This
    trades precision for speed and mirrors how real-world prefix-based
    reputation feeds (e.g. Imphash/SSDEEP partial matches) work.

    Args:
        hash_value: A hex-encoded hash string.

    Returns:
        A dict with ``reputation``, ``name``, and optionally ``family``
        and ``confidence`` keys.
    """
    malicious_patterns = {
        "aadea647": {"name": "mimikatz", "family": "credential_theft", "reputation": "malicious"},
        "bebecacd": {"name": "mimikatz", "family": "credential_theft", "reputation": "malicious"},
        "cafecafe": {"name": "pwdump", "family": "credential_theft", "reputation": "malicious"},
        "deadbeef": {"name": "meterpreter", "family": "reverse_shell", "reputation": "malicious"},
        "badc0de": {"name": "cobalt_strike", "family": " RAT", "reputation": "malicious"},
    }

    # Use the leading 8 hex chars as the lookup key.
    hash_prefix = hash_value[:8].lower()
    if hash_prefix in malicious_patterns:
        return malicious_patterns[hash_prefix]

    benign_patterns = {
        "e3b0c442": {"name": "windows_system32", "reputation": "benign"},
        "d41d8cd9": {"name": "empty_file", "reputation": "benign"},
    }

    if hash_prefix in benign_patterns:
        return benign_patterns[hash_prefix]

    return {"reputation": "unknown", "confidence": 0.0}


def check_virustotal(hash_value: str) -> dict:
    """Return a simulated VirusTotal detection summary for *hash_value*.

    In production, replace with a real ``requests.get`` call to the
    VirusTotal /v3/files endpoint.

    Args:
        hash_value: A hex-encoded hash string.

    Returns:
        A dict with ``detection`` counts and ``vendors`` list (or a
        ``note`` when the hash is not in the simulated database).
    """
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
    """Retrieve basic file metadata associated with *hash_value*.

    Maps known hash prefixes to static file-format information.  Extend
    the ``file_signatures`` dict to cover more samples.

    Args:
        hash_value: A hex-encoded hash string.

    Returns:
        A dict with ``format``, ``size``, and optionally ``description``.
    """
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