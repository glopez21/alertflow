"""Tests for ticket creation and management across ITSM platforms.

Covers AlertTicket creation from alert data with varying detail levels,
enrichment metadata, ServiceNow vs Jira system selection, and error
handling for unknown ticketing systems.
"""

from live.ticket_creator import AlertTicket, TicketManager


class TestTicketManager:
    """Tests for TicketManager alert-to-ticket creation."""

    def setup_method(self):
        self.tm = TicketManager()

    def test_create_from_alert_minimal(self):
        """Verifies ticket creation with minimal alert data produces SOC-prefixed key and Open status."""
        self.tm.add_jira(host="")
        alert_data = {"severity": "high", "rule_name": "Test Alert", "host": "server01"}
        ticket = self.tm.create_from_alert(alert_data)
        assert isinstance(ticket, AlertTicket)
        assert ticket.key.startswith("SOC-")
        assert ticket.status == "Open"

    def test_create_from_alert_with_full_data(self):
        """Verifies ticket creation with complete alert fields including user, IPs, timestamp, and labels."""
        self.tm.add_jira(host="")
        alert_data = {
            "severity": "critical",
            "rule_name": "Malware Detected",
            "host": "ws-001",
            "user": "jsmith",
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.50",
            "timestamp": "2026-05-14T12:00:00Z",
            "labels": ["malware", "soc"],
        }
        ticket = self.tm.create_from_alert(alert_data)
        assert isinstance(ticket, AlertTicket)

    def test_create_from_alert_with_enrichment(self):
        """Verifies ticket creation accepts enrichment metadata alongside alert data."""
        self.tm.add_jira(host="")
        alert_data = {"severity": "medium", "rule_name": "Suspicious Login"}
        enrich_data = {"ip_reputation": "malicious", "user_context": "admin"}
        ticket = self.tm.create_from_alert(alert_data, enrich_data=enrich_data)
        assert isinstance(ticket, AlertTicket)

    def test_create_from_alert_servicenow(self):
        """Verifies ticket creation targets ServiceNow when system is specified."""
        self.tm.add_servicenow(host="")
        alert_data = {"severity": "low", "rule_name": "Info Alert"}
        ticket = self.tm.create_from_alert(alert_data, system="servicenow")
        assert isinstance(ticket, AlertTicket)

    def test_unknown_system(self):
        """Verifies ValueError is raised for an unregistered ticketing system."""
        self.tm.add_jira(host="")
        import pytest
        with pytest.raises(ValueError, match="Unknown system"):
            self.tm.create_from_alert({}, system="nonexistent")

    def test_multiple_creators(self):
        """Verifies both Jira and ServiceNow tickets can be created from the same alert data."""
        self.tm.add_jira(host="")
        self.tm.add_servicenow(host="")
        alert_data = {"severity": "high"}
        jira_ticket = self.tm.create_from_alert(alert_data, system="jira")
        sn_ticket = self.tm.create_from_alert(alert_data, system="servicenow")
        assert isinstance(jira_ticket, AlertTicket)
        assert isinstance(sn_ticket, AlertTicket)
