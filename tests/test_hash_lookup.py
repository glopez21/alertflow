from enrichment.hash_lookup import (
    check_reputation,
    check_virustotal,
    detect_hash_type,
    enrich_hash,
    get_file_info,
)


class TestDetectHashType:
    def test_md5(self):
        assert detect_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_hash_type(h) == "sha256"

    def test_sha512(self):
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        assert detect_hash_type(h) == "sha512"

    def test_unknown(self):
        assert detect_hash_type("not-a-hash") == "unknown"

    def test_empty(self):
        assert detect_hash_type("") == "unknown"


class TestCheckReputation:
    def test_known_malicious(self):
        result = check_reputation("aadea647deadbeefcafe12345678901234567890")
        assert result["reputation"] == "malicious"
        assert result["name"] == "mimikatz"

    def test_malicious_prefix_match(self):
        result = check_reputation("aadea64712345678901234567890abcdef12345678")
        assert result["reputation"] == "malicious"

    def test_known_benign(self):
        result = check_reputation("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result["reputation"] == "benign"

    def test_unknown(self):
        result = check_reputation("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["reputation"] == "unknown"

    def test_short_hash_no_prefix(self):
        result = check_reputation("zz")
        assert result["reputation"] == "unknown"


class TestCheckVirusTotal:
    def test_known_suspicious(self):
        result = check_virustotal("aadea647deadbeefcafe12345678901234567890")
        assert result["detection"]["malicious"] == 45

    def test_unknown_hash(self):
        result = check_virustotal("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["detection"]["malicious"] == 0


class TestGetFileInfo:
    def test_known_file(self):
        result = get_file_info("aadea647deadbeefcafe12345678901234567890")
        assert result["format"] == "PE32"

    def test_unknown_file(self):
        result = get_file_info("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        assert result["format"] == "unknown"


class TestEnrichHash:
    def test_enrich_returns_all_keys(self):
        result = enrich_hash("aadea647deadbeefcafe12345678901234567890")
        assert "hash" in result
        assert "hash_type" in result
        assert "checks" in result
        assert result["hash_type"] == "sha1"
        assert "reputation" in result["checks"]
        assert "vt_lookup" in result["checks"]
        assert "file_info" in result["checks"]

    def test_enrich_unknown_is_md5(self):
        result = enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["hash_type"] == "md5"
