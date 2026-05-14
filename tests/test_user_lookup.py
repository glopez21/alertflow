from enrichment.user_lookup import (
    calculate_risk_score,
    enrich_user,
    get_account_info,
    get_group_membership,
    get_recent_activity,
)


class TestGetAccountInfo:
    def test_admin(self):
        result = get_account_info("admin")
        assert result["enabled"] is True
        assert result["account_type"] == "administrative"

    def test_unknown_user(self):
        result = get_account_info("nobody")
        assert result["enabled"] is True
        assert result["department"] == "Unknown"


class TestGetRecentActivity:
    def test_admin_activity(self):
        result = get_recent_activity("admin")
        assert result["logons_today"] == 5
        assert result["privileged_session"] is True

    def test_unknown_activity(self):
        result = get_recent_activity("nobody")
        assert result["logons_today"] == 1


class TestGetGroupMembership:
    def test_admin_groups(self):
        result = get_group_membership("admin")
        assert result["privileged"] is True
        assert "Domain Admins" in result["groups"]

    def test_unknown_groups(self):
        result = get_group_membership("nobody")
        assert result["privileged"] is False


class TestCalculateRiskScore:
    def test_admin_risk(self):
        result = calculate_risk_score("admin")
        assert result["level"] in ("Low", "Medium", "High", "Critical")
        assert result["score"] >= 0

    def test_disabled_user_risk(self):
        result = calculate_risk_score("terminated_user")
        assert "Disabled account" in result["factors"]
        assert result["score"] > 0

    def test_unknown_user_low_risk(self):
        result = calculate_risk_score("new_user")
        assert result["score"] >= 0


class TestEnrichUser:
    def test_enrich_returns_all_keys(self):
        result = enrich_user("admin")
        assert result["username"] == "admin"
        assert "checks" in result
        assert "account_info" in result["checks"]
        assert "recent_activity" in result["checks"]
        assert "group_membership" in result["checks"]
        assert "risk_score" in result["checks"]

    def test_enrich_unknown(self):
        result = enrich_user("nobody")
        assert result["username"] == "nobody"
