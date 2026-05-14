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
    def test_single_ip(self):
        assert extract_ips("src IP 192.168.1.1") == ["192.168.1.1"]

    def test_multiple_ips(self):
        result = extract_ips("from 10.0.0.1 to 10.0.0.2")
        assert set(result) == {"10.0.0.1", "10.0.0.2"}

    def test_no_ips(self):
        assert extract_ips("no ip addresses here") == []

    def test_invalid_ip(self):
        assert extract_ips("999.999.999.999") == []


class TestExtractDomains:
    def test_known_domain(self):
        assert "google.com" in extract_domains("visit google.com")

    def test_no_domains(self):
        assert extract_domains("nothing here") == []


class TestExtractHashes:
    def test_md5(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_hashes(f"hash {h}")
        assert h in result["md5"]

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_hashes(f"hash {h}")
        assert h in result["sha256"]

    def test_no_hashes(self):
        result = extract_hashes("plain text")
        assert result["md5"] == []
        assert result["sha1"] == []
        assert result["sha256"] == []


class TestExtractURLs:
    def test_http_url(self):
        assert "http://example.com" in extract_urls("visit http://example.com")

    def test_https_url(self):
        assert "https://evil.com/path" in extract_urls("https://evil.com/path")

    def test_no_urls(self):
        assert extract_urls("no urls") == []


class TestExtractEmails:
    def test_simple_email(self):
        assert "user@example.com" in extract_emails("contact user@example.com")

    def test_no_emails(self):
        assert extract_emails("no email") == []


class TestExtractFilepaths:
    def test_windows_path(self):
        assert "C:\\Windows\\System32" in extract_filepaths("file at C:\\Windows\\System32")

    def test_unix_path(self):
        assert "/var/log/syslog" in extract_filepaths("check /var/log/syslog")

    def test_no_paths(self):
        assert extract_filepaths("no paths") == []


class TestExtractAccounts:
    def test_user_prefix(self):
        result = extract_accounts("user: jsmith logged in")
        assert "jsmith" in result

    def test_no_accounts(self):
        assert extract_accounts("no accounts") == []


class TestExtractIocs:
    def test_full_extraction(self):
        text = "Alert: user: admin from 192.168.1.1 visited https://evil.com and hash d41d8cd98f00b204e9800998ecf8427e contact admin@evil.com"
        result = extract_iocs(text)
        assert "192.168.1.1" in result["ips"]
        assert "admin" in result["accounts"]
        assert "https://evil.com" in result["urls"]
        assert "admin@evil.com" in result["emails"]

    def test_empty_text(self):
        result = extract_iocs("")
        assert all(len(v) == 0 for v in result.values() if isinstance(v, list))
