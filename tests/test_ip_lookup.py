"""Tests for IP address enrichment and lookup utilities.

Covers private IP detection across RFC 1918 ranges, IP enrichment with
reverse DNS and GeoIP checks, and reverse DNS resolution behavior.
"""

from enrichment.ip_lookup import enrich_ip, get_reverse_dns, is_private_ip


class TestIsPrivateIP:
    """Tests for is_private_ip RFC 1918 and loopback detection."""

    def test_10_dot(self):
        """Verifies 10.x.x.x is detected as private."""
        assert is_private_ip("10.0.0.1") is True

    def test_172_dot_16(self):
        """Verifies 172.16.x.x (range start) is detected as private."""
        assert is_private_ip("172.16.0.1") is True

    def test_172_dot_31(self):
        """Verifies 172.31.x.x (range end) is detected as private."""
        assert is_private_ip("172.31.0.1") is True

    def test_172_dot_32(self):
        """Verifies 172.32.x.x (outside range) is not private."""
        assert is_private_ip("172.32.0.1") is False

    def test_192_dot_168(self):
        """Verifies 192.168.x.x is detected as private."""
        assert is_private_ip("192.168.1.1") is True

    def test_127_dot(self):
        """Verifies 127.x.x.x loopback is detected as private."""
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        """Verifies a public IP (8.8.8.8) is not classified as private."""
        assert is_private_ip("8.8.8.8") is False

    def test_invalid(self):
        """Verifies a non-IP string returns False."""
        assert is_private_ip("not-an-ip") is False


class TestEnrichIP:
    """Tests for enrich_ip returning comprehensive check results."""

    def test_enrich_public(self):
        """Verifies public IP enrichment includes reverse_dns, geoip, and is_private checks."""
        result = enrich_ip("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        assert "checks" in result
        assert "reverse_dns" in result["checks"]
        assert "geoip" in result["checks"]
        assert "is_private" in result["checks"]
        assert result["checks"]["is_private"] is False

    def test_enrich_private(self):
        """Verifies private IP enrichment marks is_private and uses 'Private' country."""
        result = enrich_ip("10.0.0.1")
        assert result["checks"]["is_private"] is True
        assert result["checks"]["geoip"]["country"] == "Private"

    def test_enrich_localhost(self):
        """Verifies localhost is detected as private during enrichment."""
        result = enrich_ip("127.0.0.1")
        assert result["checks"]["is_private"] is True


class TestGetReverseDNS:
    """Tests for reverse DNS resolution."""

    def test_known_ip(self):
        """Verifies reverse DNS returns a result for a well-known public IP."""
        result = get_reverse_dns("8.8.8.8")
        assert result is not None

    def test_private_ip(self):
        """Verifies reverse DNS returns None for a private IP."""
        result = get_reverse_dns("10.0.0.1")
        assert result is None
