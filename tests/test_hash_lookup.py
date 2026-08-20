"""Tests for file hash enrichment and lookup utilities.

Covers hash type detection by length, reputation checking against known
malware/benign databases, VirusTotal simulation lookups, file info
retrieval, and full hash enrichment output structure.
"""

from enrichment.hash_lookup import (
    check_reputation,
    check_virustotal,
    detect_hash_type,
    enrich_hash,
    get_file_info,
)


class TestDetectHashType:
    """Tests for detect_hash_type length-based classification."""

    def test_md5(self):
        """Verifies a 32-char hex string is detected as md5."""
        assert detect_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        """Verifies a 40-char hex string is detected as sha1."""
        assert detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        """Verifies a 64-char hex string is detected as sha256."""
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_hash_type(h) == "sha256"

    def test_sha512(self):
        """Verifies a 128-char hex string is detected as sha512."""
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        assert detect_hash_type(h) == "sha512"

    def test_unknown(self):
        assert detect_hash_type("not-a-hash") == "unknown"

    def test_empty(self):
        """Verifies an empty string is classified as unknown."""
        assert detect_hash_type("") == "unknown"


class TestCheckReputation:
    """Tests for hash reputation lookup against known malware/benign databases."""

    def test_known_malicious(self):
        """Verifies a known mimikatz hash prefix is classified as malicious."""
        result = check_reputation("aadea647deadbeefcafe12345678901234567890")
        assert result["reputation"] == "malicious"
        assert result["name"] == "mimikatz"

    def test_malicious_prefix_match(self):
        """Verifies reputation matching works on hash prefixes (not just full hashes)."""
        result = check_reputation("aadea64712345678901234567890abcdef12345678")
        assert result["reputation"] == "malicious"

    def test_known_benign(self):
        """Verifies the empty-file SHA-256 hash is classified as benign."""
        result = check_reputation("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result["reputation"] == "benign"

    def test_unknown(self):
        """Verifies an unlisted hash is classified as unknown."""
        result = check_reputation("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["reputation"] == "unknown"

    def test_short_hash_no_prefix(self):
        """Verifies a very short string is classified as unknown (no prefix match)."""
        result = check_reputation("zz")
        assert result["reputation"] == "unknown"


class TestCheckVirusTotal:
    """Tests for simulated VirusTotal hash lookup."""

    def test_known_suspicious(self):
        """Verifies a known malicious hash returns a high detection count."""
        result = check_virustotal("aadea647deadbeefcafe12345678901234567890")
        assert result["detection"]["malicious"] == 45

    def test_unknown_hash(self):
        """Verifies an unknown hash returns zero detections."""
        result = check_virustotal("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["detection"]["malicious"] == 0


class TestGetFileInfo:
    """Tests for file format detection from hash lookup."""

    def test_known_file(self):
        """Verifies a known hash returns the correct file format (PE32)."""
        result = get_file_info("aadea647deadbeefcafe12345678901234567890")
        assert result["format"] == "PE32"

    def test_unknown_file(self):
        """Verifies an unknown hash returns 'unknown' format."""
        result = get_file_info("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["format"] == "unknown"


class TestEnrichHash:
    """Tests for the full hash enrichment pipeline."""

    def test_enrich_returns_all_keys(self):
        """Verifies enrichment output includes hash_type, reputation, vt_lookup, and file_info."""
        result = enrich_hash("aadea647deadbeefcafe12345678901234567890")
        assert "hash" in result
        assert "hash_type" in result
        assert "checks" in result
        assert result["hash_type"] == "sha1"
        assert "reputation" in result["checks"]
        assert "vt_lookup" in result["checks"]
        assert "file_info" in result["checks"]

    def test_enrich_unknown_is_md5(self):
        """Verifies a 32-char hash is identified as md5 type during enrichment."""
        result = enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["hash_type"] == "md5"
