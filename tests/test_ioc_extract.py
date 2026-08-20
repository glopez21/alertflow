"""Tests for IOC (Indicator of Compromise) extraction from text.

Covers extraction of IP addresses, domains, file hashes (MD5/SHA1/SHA256),
URLs, email addresses, file paths, and user accounts, plus the combined
extract_iocs aggregator.
"""

from enrichment.ioc_extract import (
    extract_accounts,
    extract_domains,
    extract_emails,
    extract_filepaths,
    extract_hashes,
    extract_iocs,
    extract_ips,
    extract_urls,
)


class TestExtractIPs:
    """Tests for IPv4 address extraction from text."""

    def test_single_ip(self):
        """Verifies extraction of a single IPv4 address from surrounding text."""

    def test_multiple_ips(self):
        """Verifies extraction of multiple IPs from text, returned as a set."""
        result = extract_ips("from 10.0.0.1 to 10.0.0.2")
        assert set(result) == {"10.0.0.1", "10.0.0.2"}

    def test_no_ips(self):
        """Verifies empty list returned when no IPs are present."""
        assert extract_ips("no ip addresses here") == []

    def test_invalid_ip(self):
        """Verifies out-of-range octets are not extracted as valid IPs."""
        assert extract_ips("999.999.999.999") == []


class TestExtractDomains:
    """Tests for domain name extraction from text."""

    def test_known_domain(self):
        """Verifies extraction of a well-known domain from text."""
        assert "google.com" in extract_domains("visit google.com")

    def test_no_domains(self):
        """Verifies empty list returned when no domains are present."""
        assert extract_domains("nothing here") == []


class TestExtractHashes:
    """Tests for file hash extraction by algorithm type."""

    def test_md5(self):
        """Verifies extraction of an MD5 hash (32 hex chars)."""
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_hashes(f"hash {h}")
        assert h in result["md5"]

    def test_sha256(self):
        """Verifies extraction of a SHA-256 hash (64 hex chars)."""
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_hashes(f"hash {h}")
        assert h in result["sha256"]

    def test_no_hashes(self):
        """Verifies empty lists for all hash types when no hashes are present."""
        result = extract_hashes("plain text")
        assert result["md5"] == []
        assert result["sha1"] == []
        assert result["sha256"] == []


class TestExtractURLs:
    """Tests for URL extraction from text."""

    def test_http_url(self):
        """Verifies extraction of an HTTP URL."""

    def test_https_url(self):
        """Verifies extraction of an HTTPS URL with path."""
        assert "https://evil.com/path" in extract_urls("https://evil.com/path")

    def test_no_urls(self):
        """Verifies empty list returned when no URLs are present."""
        assert extract_urls("no urls") == []


class TestExtractEmails:
    """Tests for email address extraction from text."""

    def test_simple_email(self):
        """Verifies extraction of a standard email address."""

    def test_no_emails(self):
        """Verifies empty list returned when no emails are present."""
        assert extract_emails("no email") == []


class TestExtractFilepaths:
    """Tests for file path extraction from text."""

    def test_windows_path(self):
        """Verifies extraction of a Windows-style backslash file path."""
        assert "C:\\Windows\\System32" in extract_filepaths("file at C:\\Windows\\System32")

    def test_unix_path(self):
        """Verifies extraction of a Unix-style forward-slash file path."""
        assert "/var/log/syslog" in extract_filepaths("check /var/log/syslog")

    def test_no_paths(self):
        """Verifies empty list returned when no file paths are present."""
        assert extract_filepaths("no paths") == []


class TestExtractAccounts:
    """Tests for user account extraction from text."""

    def test_user_prefix(self):
        """Verifies account extraction from 'user:' prefix pattern."""
        result = extract_accounts("user: jsmith logged in")
        assert "jsmith" in result

    def test_no_accounts(self):
        """Verifies empty list returned when no account patterns are present."""
        assert extract_accounts("no accounts") == []


class TestExtractIocs:
    """Tests for the combined IOC extraction aggregator."""

    def test_full_extraction(self):
        """Verifies extraction of multiple IOC types (IP, account, URL, hash, email) from a single text."""
        text = "Alert: user: admin from 192.168.1.1 visited https://evil.com and hash d41d8cd98f00b204e9800998ecf8427e contact admin@evil.com"
        result = extract_iocs(text)
        assert "192.168.1.1" in result["ips"]
        assert "admin" in result["accounts"]
        assert "https://evil.com" in result["urls"]
        assert "admin@evil.com" in result["emails"]

    def test_empty_text(self):
        """Verifies empty input returns empty lists for all IOC types."""
        result = extract_iocs("")
        assert all(len(v) == 0 for v in result.values() if isinstance(v, list))
