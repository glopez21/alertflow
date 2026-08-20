"""Tests for user account enrichment and risk assessment.

Covers account info retrieval, recent activity tracking, group membership
analysis, risk score calculation, and full user enrichment output structure.
"""

from enrichment.user_lookup import (
    calculate_risk_score,
    enrich_user,
    get_account_info,
    get_group_membership,
    get_recent_activity,
)


class TestGetAccountInfo:
    """Tests for account metadata retrieval."""

    def test_admin(self):
        """Verifies admin account is enabled with administrative type."""
        result = get_account_info("admin")
        assert result["enabled"] is True
        assert result["account_type"] == "administrative"

    def test_unknown_user(self):
        """Verifies an unrecognized user returns enabled with Unknown department."""
        result = get_account_info("nobody")
        assert result["enabled"] is True
        assert result["department"] == "Unknown"


class TestGetRecentActivity:
    """Tests for recent login and session activity retrieval."""

    def test_admin_activity(self):
        """Verifies admin shows elevated logon count and privileged session flag."""
        result = get_recent_activity("admin")
        assert result["logons_today"] == 5
        assert result["privileged_session"] is True

    def test_unknown_activity(self):
        """Verifies a non-admin user shows baseline single logon activity."""
        result = get_recent_activity("nobody")
        assert result["logons_today"] == 1


class TestGetGroupMembership:
    """Tests for group membership and privilege detection."""

    def test_admin_groups(self):
        """Verifies admin belongs to privileged groups including Domain Admins."""
        result = get_group_membership("admin")
        assert result["privileged"] is True
        assert "Domain Admins" in result["groups"]

    def test_unknown_groups(self):
        """Verifies a non-privileged user has no privileged group membership."""
        result = get_group_membership("nobody")
        assert result["privileged"] is False


class TestCalculateRiskScore:
    """Tests for user risk score calculation."""

    def test_admin_risk(self):
        """Verifies admin user returns a valid risk level and non-negative score."""
        result = calculate_risk_score("admin")
        assert result["level"] in ("Low", "Medium", "High", "Critical")
        assert result["score"] >= 0

    def test_disabled_user_risk(self):
        """Verifies a disabled/terminated account has positive risk score with factor."""
        result = calculate_risk_score("terminated_user")
        assert "Disabled account" in result["factors"]
        assert result["score"] > 0

    def test_unknown_user_low_risk(self):
        """Verifies a new or low-activity user returns a non-negative risk score."""
        result = calculate_risk_score("new_user")
        assert result["score"] >= 0


class TestEnrichUser:
    """Tests for the full user enrichment pipeline."""

    def test_enrich_returns_all_keys(self):
        """Verifies enrichment output includes account_info, recent_activity, group_membership, and risk_score."""
        result = enrich_user("admin")
        assert result["username"] == "admin"
        assert "checks" in result
        assert "account_info" in result["checks"]
        assert "recent_activity" in result["checks"]
        assert "group_membership" in result["checks"]
        assert "risk_score" in result["checks"]

    def test_enrich_unknown(self):
        """Verifies enrichment of an unknown user still returns correct username key."""
        result = enrich_user("nobody")
        assert result["username"] == "nobody"
