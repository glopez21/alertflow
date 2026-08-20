"""Shared utilities for AlertFlow.

Provides helper functions for timestamp formatting and indicator-of-compromise
(IOC) classification used across the API, DB, and enrichment layers.
"""

import ipaddress
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string with Z suffix.

    Produces a uniform timestamp format (``2025-07-10T14:30:00Z``) used for
    ``created_at`` / ``updated_at`` columns and audit records.  The ``+00:00``
    produced by ``isoformat()`` is replaced with the conventional ``Z`` suffix.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def detect_ioc_type(target: str) -> str:
    """Classify an indicator-of-compromise (IOC) string by type.

    Uses a heuristic cascade: the first matching rule wins.  Order matters —
    ``@`` is tested before IP to avoid mis-classifying email addresses that
    happen to contain IP-like tokens; IP is tested before hash to avoid
    hex-only strings being misclassified.

    Args:
        target: Raw IOC string to classify.

    Returns:
        One of: ``'ip'``, ``'domain'``, ``'hash'``, ``'email'``, ``'url'``,
        or ``'unknown'``.
    """
    target = target.strip()
    if not target:
        return "unknown"

    # Email detection — tested first because addresses can contain digits
    # and other characters that later heuristics might match.
    if "@" in target:
        return "email"

    # IP detection — uses the stdlib validator, covers both v4 and v6.
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    # Hash detection — hex characters only, at lengths matching common
    # digest algorithms: MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128).
    if all(c in "0123456789abcdefABCDEF" for c in target) and len(target) in (32, 40, 64, 128):
        return "hash"

    # Domain detection — must contain a dot, must not be purely numeric
    # (which would be an IP that failed validation above), and must be
    # within the DNS label length limit of 253 characters.
    if "." in target and not target.replace(".", "").replace("-", "").isdigit() and len(target) < 253:
        # Fast-path: known TLDs are always domains.
        if any(target.endswith(tld) for tld in (".com", ".net", ".org", ".io", ".xyz", ".top",
                                                ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
                                                ".info", ".biz", ".me", ".co", ".ru", ".cn",
                                                ".in", ".au", ".uk", ".de", ".fr", ".jp", ".br")):
            return "domain"
        # Fallback: any dot-separated string not starting with a digit
        # is treated as a domain (e.g. "example.xyz").
        if not target[0].isdigit():
            return "domain"

    # URL detection — scheme prefix present.
    if "://" in target:
        return "url"

    return "unknown"


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate that ``ip_str`` is a well-formed IPv4 address.

    Unlike ``detect_ioc_type`` which accepts any IP version, this function
    explicitly rejects IPv6 addresses — useful for contexts that only
    support IPv4 (e.g. legacy firewall rules).

    Args:
        ip_str: Candidate IP address string.

    Returns:
        ``True`` if the string parses as IPv4, ``False`` otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4
    except ValueError:
        return False
