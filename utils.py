"""Shared utilities for AlertFlow."""

import ipaddress
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def detect_ioc_type(target: str) -> str:
    """Detect the type of an IOC string.

    Returns one of: 'ip', 'domain', 'hash', 'email', 'url', 'unknown'.
    """
    target = target.strip()
    if not target:
        return "unknown"

    if "@" in target:
        return "email"

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    if all(c in "0123456789abcdefABCDEF" for c in target) and len(target) in (32, 40, 64, 128):
        return "hash"

    if "." in target and not target.replace(".", "").replace("-", "").isdigit() and len(target) < 253:
        if any(target.endswith(tld) for tld in (".com", ".net", ".org", ".io", ".xyz", ".top",
                                                ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
                                                ".info", ".biz", ".me", ".co", ".ru", ".cn",
                                                ".in", ".au", ".uk", ".de", ".fr", ".jp", ".br")):
            return "domain"
        if not target[0].isdigit():
            return "domain"

    if "://" in target:
        return "url"

    return "unknown"


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate an IPv4 address string."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4
    except ValueError:
        return False
