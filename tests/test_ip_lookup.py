from enrichment.ip_lookup import enrich_ip, get_reverse_dns, is_private_ip


class TestIsPrivateIP:
    def test_10_dot(self):
        assert is_private_ip("10.0.0.1") is True

    def test_172_dot_16(self):
        assert is_private_ip("172.16.0.1") is True

    def test_172_dot_31(self):
        assert is_private_ip("172.31.0.1") is True

    def test_172_dot_32(self):
        assert is_private_ip("172.32.0.1") is False

    def test_192_dot_168(self):
        assert is_private_ip("192.168.1.1") is True

    def test_127_dot(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_invalid(self):
        assert is_private_ip("not-an-ip") is False


class TestEnrichIP:
    def test_enrich_public(self):
        result = enrich_ip("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        assert "checks" in result
        assert "reverse_dns" in result["checks"]
        assert "geoip" in result["checks"]
        assert "is_private" in result["checks"]
        assert result["checks"]["is_private"] is False

    def test_enrich_private(self):
        result = enrich_ip("10.0.0.1")
        assert result["checks"]["is_private"] is True
        assert result["checks"]["geoip"]["country"] == "Private"

    def test_enrich_localhost(self):
        result = enrich_ip("127.0.0.1")
        assert result["checks"]["is_private"] is True


class TestGetReverseDNS:
    def test_known_ip(self):
        result = get_reverse_dns("8.8.8.8")
        assert result is not None

    def test_private_ip(self):
        result = get_reverse_dns("10.0.0.1")
        assert result is None
