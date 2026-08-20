"""Tests for domain enrichment and reputation lookup.

Covers WHOIS TLD analysis, domain reputation classification, suspicious
subdomain/DGA detection, and full domain enrichment output structure.
"""

from enrichment.domain_lookup import (
    check_reputation,
    check_suspicious,
    enrich_domain,
    get_whois,
)


class TestGetWhois:
    """Tests for WHOIS-based TLD suspicion analysis."""

    def test_suspicious_tld(self):
        """Verifies .xyz TLD is flagged as suspicious."""
        result = get_whois("evil.xyz")
        assert result.get("suspicious_tld") is True

    def test_normal_tld(self):
        """Verifies .com TLD is not flagged as suspicious."""
        result = get_whois("google.com")
        assert result.get("suspicious_tld") is None


class TestCheckReputation:
    """Tests for domain reputation classification."""

    def test_malicious(self):
        """Verifies evil.com is classified as malicious."""
        result = check_reputation("evil.com")
        assert result["reputation"] == "malicious"

    def test_benign(self):
        """Verifies google.com is classified as benign."""
        result = check_reputation("google.com")
        assert result["reputation"] == "benign"

    def test_unknown(self):
        """Verifies an unlisted domain is classified as unknown."""
        result = check_reputation("unknown-site.com")
        assert result["reputation"] == "unknown"


class TestCheckSuspicious:
    """Tests for suspicious subdomain and DGA detection."""

    def test_random_subdomain(self):
        """Verifies a long random subdomain is flagged as suspicious with reason."""
        result = check_suspicious("abcdefghijklmnopqrstuvwxyz123456.evil.com")
        assert result["is_suspicious"] is True
        assert any("random" in r.lower() for r in result["reasons"])

    def test_dga_indicators(self):
        """Verifies a domain with DGA-like pattern is flagged as suspicious."""
        result = check_suspicious("jghjhg.xyz")
        assert result["is_suspicious"] is True

    def test_benign_domain(self):
        """Verifies a normal domain is not flagged as suspicious."""
        result = check_suspicious("google.com")
        assert result["is_suspicious"] is False

    def test_login_phishing(self):
        """Verifies a domain with 'login-secure' pattern is flagged as suspicious."""
        result = check_suspicious("login-secure.example.com")
        assert result["is_suspicious"] is True


class TestEnrichDomain:
    """Tests for the full domain enrichment pipeline."""

    def test_enrich_returns_all_keys(self):
        """Verifies enrichment output includes dns, whois, reputation, and suspicious checks."""
        result = enrich_domain("google.com")
        assert result["domain"] == "google.com"
        assert "checks" in result
        assert "dns" in result["checks"]
        assert "whois" in result["checks"]
        assert "reputation" in result["checks"]
        assert "suspicious" in result["checks"]

    def test_enrich_malicious_domain(self):
        """Verifies enrichment of a malicious domain surfaces the correct reputation."""
        result = enrich_domain("evil.com")
        assert result["checks"]["reputation"]["reputation"] == "malicious"
