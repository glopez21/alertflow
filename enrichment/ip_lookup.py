#!/usr/bin/env python3
"""IP enrichment script for alert triage."""

import argparse
import json
import socket
from typing import Optional

import ipaddress

from utils import is_valid_ipv4


def _is_valid_ipv6(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 6
    except ValueError:
        return False


def enrich_ip(ip: str) -> dict:
    """Enrich IP with available context."""
    if not is_valid_ipv4(ip) and not _is_valid_ipv6(ip):
        return {"ip": ip, "error": f"Invalid IP address: {ip}", "checks": {}}

    result = {"ip": ip, "checks": {}}

    result["checks"]["reverse_dns"] = get_reverse_dns(ip)
    result["checks"]["geoip"] = get_geoip(ip)
    result["checks"]["is_private"] = is_private_ip(ip)

    return result


def get_reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Get reverse DNS for IP with configurable timeout."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        return None


def get_geoip(ip: str) -> dict:
    """Get basic geo information (simple lookup)."""
    if is_private_ip(ip):
        return {"country": "Private", "region": "Internal"}

    geo = {"country": "Unknown", "region": "Unknown"}

    first_octet = int(ip.split(".")[0])
    if first_octet in range(1, 224):
        geo["type"] = "Public"
    elif first_octet == 10:
        geo["type"] = "Private (10.x)"
    elif first_octet == 172:
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            geo["type"] = "Private (172.16-31.x)"
        else:
            geo["type"] = "Public"
    elif first_octet == 192:
        second = int(ip.split(".")[1])
        if second == 168:
            geo["type"] = "Private (192.168.x)"
        else:
            geo["type"] = "Public"

    return geo


def is_private_ip(ip: str) -> bool:
    """Check if IP is private."""
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