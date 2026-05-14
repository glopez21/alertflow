"""Tests for the pipeline module."""

from unittest.mock import MagicMock, patch

from pipeline import auto_detect_ioc_type, enrich_target, extract_and_enrich, push_to_threatpulse, disable_user_in_adminflow


def _mock_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


class TestAutoDetectIocType:
    def test_detect_ip(self):
        assert auto_detect_ioc_type("192.168.1.1") == "ip"
        assert auto_detect_ioc_type("8.8.8.8") == "ip"
        assert auto_detect_ioc_type("10.0.0.1") == "ip"

    def test_detect_email(self):
        assert auto_detect_ioc_type("admin@example.com") == "email"
        assert auto_detect_ioc_type("user@corp.io") == "email"

    def test_detect_hash(self):
        assert auto_detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
        assert auto_detect_ioc_type("a" * 40) == "hash"
        assert auto_detect_ioc_type("b" * 64) == "hash"

    def test_detect_domain(self):
        assert auto_detect_ioc_type("google.com") == "domain"
        assert auto_detect_ioc_type("evil-domain.xyz") == "domain"

    def test_detect_unknown(self):
        assert auto_detect_ioc_type("just-text") == "unknown"
        assert auto_detect_ioc_type("short") == "unknown"


class TestEnrichTarget:
    def test_enrich_ip(self):
        result = enrich_target("8.8.8.8")
        assert result["type"] == "ip"
        assert result["ip"] == "8.8.8.8"
        assert "checks" in result

    def test_enrich_domain(self):
        result = enrich_target("google.com", "domain")
        assert result["type"] == "domain"
        assert result["domain"] == "google.com"
        assert "checks" in result

    def test_enrich_hash(self):
        result = enrich_target("d41d8cd98f00b204e9800998ecf8427e", "hash")
        assert result["type"] == "hash"
        assert "checks" in result

    def test_enrich_user(self):
        result = enrich_target("admin", "user")
        assert result["type"] == "user"
        assert "checks" in result

    def test_enrich_email_extracts_username(self):
        result = enrich_target("admin@example.com", "email")
        assert result["type"] == "user"
        assert "checks" in result

    def test_enrich_unknown_type(self):
        result = enrich_target("unknown-target", "unknown")
        assert result["type"] == "unknown"
        assert result["target"] == "unknown-target"

    def test_auto_detect_ip(self):
        result = enrich_target("10.0.0.1")
        assert result["type"] == "ip"


class TestExtractAndEnrich:
    def test_text_with_ip(self):
        result = extract_and_enrich("Connection from 8.8.8.8 detected")
        assert "iocs" in result
        assert "enrichment" in result
        assert "8.8.8.8" in result["iocs"]["ips"]

    def test_text_with_domain(self):
        result = extract_and_enrich("Visit google.com for info")
        assert "google.com" in result["iocs"]["domains"]

    def test_text_with_hash(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_and_enrich(f"File hash: {md5}")
        assert md5 in result["iocs"]["hashes"]["md5"]

    def test_text_with_email(self):
        result = extract_and_enrich("Email: admin@example.com")
        assert "admin@example.com" in result["iocs"]["emails"]

    def test_empty_text(self):
        result = extract_and_enrich("")
        assert result["iocs"]["ips"] == []
        assert result["enrichment"] == {}

    def test_multiple_iocs(self):
        result = extract_and_enrich("IPs: 8.8.8.8, domain: google.com, email: admin@example.com")
        assert len(result["iocs"]["ips"]) >= 1
        assert len(result["iocs"]["domains"]) >= 1


class TestPushToThreatPulse:
    def test_push_success(self):
        client = _mock_client()
        client.send_webhook.return_value = {"status": "ok", "id": 123}
        with patch("integrations.threatpulse.ThreatPulseClient", return_value=client):
            result = push_to_threatpulse(
                {"title": "Test Alert", "severity": "P1"},
                {"iocs": {"ips": ["8.8.8.8"], "domains": [], "hashes": {"md5": [], "sha1": [], "sha256": []}}},
                "http://threatpulse.example.com",
                "api-key",
            )
        assert result is not None
        assert result["status"] == "ok"

    def test_push_failure_returns_none(self):
        client = _mock_client()
        client.send_webhook.side_effect = Exception("connection error")
        with patch("integrations.threatpulse.ThreatPulseClient", return_value=client):
            result = push_to_threatpulse(
                {"title": "Test", "severity": "P3"},
                {"iocs": {"ips": [], "domains": [], "hashes": {"md5": [], "sha1": [], "sha256": []}}},
                "http://threatpulse.example.com",
            )
        assert result is None

    def test_push_severity_mapping(self):
        client = _mock_client()
        client.send_webhook.return_value = {"status": "ok"}
        with patch("integrations.threatpulse.ThreatPulseClient", return_value=client):
            push_to_threatpulse(
                {"title": "Critical Alert", "severity": "P1", "status": "escalated", "analyst": "jsmith"},
                {"iocs": {"ips": ["10.0.0.1"], "domains": [], "hashes": {"md5": [], "sha1": [], "sha256": []}}},
                "http://tp.example.com",
                "key",
            )
            call_args = client.send_webhook.call_args[0][0]
            assert call_args.severity == "critical"
            assert call_args.title == "Critical Alert"


class TestDisableUserInAdminFlow:
    def test_disable_success(self):
        client = _mock_client()
        client.disable_user.return_value = {"status": "ok", "username": "jdoe"}
        with patch("integrations.adminflow.AdminFlowClient", return_value=client):
            result = disable_user_in_adminflow("jdoe", "http://adminflow.example.com", "key")
        assert result is not None
        assert result["username"] == "jdoe"

    def test_disable_failure_returns_none(self):
        client = _mock_client()
        client.disable_user.side_effect = Exception("timeout")
        with patch("integrations.adminflow.AdminFlowClient", return_value=client):
            result = disable_user_in_adminflow("jdoe", "http://adminflow.example.com")
        assert result is None

    def test_disable_client_context_manager(self):
        client = _mock_client()
        client.disable_user.return_value = {"status": "ok"}
        with patch("integrations.adminflow.AdminFlowClient", return_value=client):
            disable_user_in_adminflow("jdoe", "http://adminflow.example.com", "key")
        client.__exit__.assert_called_once()