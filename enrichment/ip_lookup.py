#!/usr/bin/env python3
"""IP enrichment module for alert triage.

Provides IP address enrichment capabilities including reverse DNS lookups,
GeoIP classification, and private/reserved address detection. Supports both
IPv4 and IPv6 addresses. Used as a building block in the AlertFlow pipeline
to add network context to alerts involving IP indicators.

Design notes:
    - GeoIP is intentionally simplified (no external DB) — only classifies
      public vs reserved for IPv4. Production use should integrate MaxMind
      or a similar GeoIP database.
    - Private IP detection uses both the stdlib ``ipaddress`` module and a
      manual fallback for environments where the module may behave differently.
"""

import argparse
import json
import socket
from typing import Optional

import ipaddress

from utils import is_valid_ipv4


def _is_valid_ipv6(ip_str: str) -> bool:
    """Validate whether *ip_str* is a syntactically correct IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 6
    except ValueError:
        return False


def enrich_ip(ip: str) -> dict:
    """Enrich an IP address with reverse-DNS, privacy, and GeoIP context.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A dict keyed by check name (``reverse_dns``, ``is_private``,
        ``geoip``) with an ``error`` key when the IP is invalid.
    """
    # Validate input early so downstream checks never operate on garbage.
    if not is_valid_ipv4(ip) and not _is_valid_ipv6(ip):
        return {"ip": ip, "error": f"Invalid IP address: {ip}", "checks": {}}

    result = {"ip": ip, "checks": {}}

    result["checks"]["reverse_dns"] = get_reverse_dns(ip)
    result["checks"]["is_private"] = is_private_ip(ip)

    # GeoIP is only implemented for IPv4 — IPv6 gets a stub response.
    if is_valid_ipv4(ip):
        result["checks"]["geoip"] = get_geoip(ip)
    else:
        result["checks"]["geoip"] = {"country": "Unknown", "region": "IPv6", "type": "IPv6"}

    return result


def get_reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform a reverse-DNS lookup for *ip* with a hard timeout.

    The global default socket timeout is temporarily overridden so that
    slow or unresponsive DNS servers cannot block the entire pipeline.

    Args:
        ip: The IP address to resolve.
        timeout: Seconds to wait before aborting the lookup.

    Returns:
        The hostname string on success, or ``None`` on any DNS error.
    """
    # Save the process-wide default timeout so we can restore it afterward.
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_geoip(ip: str) -> dict:
    """Classify an IPv4 address into public/reserved/private categories.

    This is a *simplified* lookup that does not require an external GeoIP
    database. It only distinguishes public addresses (first octet 1–223)
    from reserved ranges.

    Args:
        ip: A valid IPv4 address string.

    Returns:
        A dict with ``country``, ``region``, and ``type`` keys.
    """
    if is_private_ip(ip):
        return {"country": "Private", "region": "Internal"}

    geo = {"country": "Unknown", "region": "Unknown"}

    parts = ip.split(".")
    if len(parts) != 4:
        return geo

    first_octet = int(parts[0])
    # Class A–C unicast ranges (1–223) are publicly routable; 224+ are
    # multicast/reserved.
    if 1 <= first_octet < 224:
        geo["type"] = "Public"
    else:
        geo["type"] = "Reserved"

    return geo


def is_private_ip(ip: str) -> bool:
    """Detect whether *ip* belongs to a private, loopback, or reserved range.

    Covers RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    loopback (127.0.0.0/8), and the broadcast/reserved 255.0.0.0/8 block.
    IPv6 private/link-local addresses are also detected via ``ipaddress``.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        ``True`` if the address is private/reserved/loopback.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        # Manual fallback for IPv4 when ipaddress fails — checks RFC 1918
        # and common reserved blocks by octet inspection.
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first in (127, 255):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="IP Enrichment Tool")
    parser.add_argument("ip", help="IP address to enrich")
    args = parser.parse_args()

    result = enrich_ip(args.ip)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
