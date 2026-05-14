from enrichment.domain_lookup import (
    check_reputation,
    check_suspicious,
    enrich_domain,
    get_whois,
)


class TestGetWhois:
    def test_suspicious_tld(self):
        result = get_whois("evil.xyz")
        assert result.get("suspicious_tld") is True

    def test_normal_tld(self):
        result = get_whois("google.com")
        assert result.get("suspicious_tld") is None


class TestCheckReputation:
    def test_malicious(self):
        result = check_reputation("evil.com")
        assert result["reputation"] == "malicious"

    def test_benign(self):
        result = check_reputation("google.com")
        assert result["reputation"] == "benign"

    def test_unknown(self):
        result = check_reputation("unknown-site.com")
        assert result["reputation"] == "unknown"


class TestCheckSuspicious:
    def test_random_subdomain(self):
        result = check_suspicious("abcdefghijklmnopqrstuvwxyz123456.evil.com")
        assert result["is_suspicious"] is True
        assert any("random" in r.lower() for r in result["reasons"])

    def test_dga_indicators(self):
        result = check_suspicious("jghjhg.xyz")
        assert result["is_suspicious"] is True

    def test_benign_domain(self):
        result = check_suspicious("google.com")
        assert result["is_suspicious"] is False

    def test_login_phishing(self):
        result = check_suspicious("login-secure.example.com")
        assert result["is_suspicious"] is True


class TestEnrichDomain:
    def test_enrich_returns_all_keys(self):
        result = enrich_domain("google.com")
        assert result["domain"] == "google.com"
        assert "checks" in result
        assert "dns" in result["checks"]
        assert "whois" in result["checks"]
        assert "reputation" in result["checks"]
        assert "suspicious" in result["checks"]

    def test_enrich_malicious_domain(self):
        result = enrich_domain("evil.com")
        assert result["checks"]["reputation"]["reputation"] == "malicious"
