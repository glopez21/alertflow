#!/usr/bin/env python3
"""User context lookup module for alert triage.

Gathers account metadata, recent login activity, group/role membership,
and computes a composite risk score for a given username.  All data sources
are currently backed by demo lookup tables — swap them for LDAP/AD/IdP
APIs in production.

Risk-score formula:
    Each detected risk factor adds 25 points, capped at 100.
    Levels: 0–24  Low  |  25–49  Medium  |  50–74  High  |  75–100  Critical.
"""

import argparse
import json

from datetime import datetime

from utils import utcnow_iso


def enrich_user(username: str) -> dict:
    """Run all enrichment checks against *username*.

    Args:
        username: The account name to look up.

    Returns:
        A dict with a ``checks`` sub-dict containing ``account_info``,
        ``recent_activity``, ``group_membership``, and ``risk_score``.
    """
    result = {
        "username": username,
        "timestamp": utcnow_iso(),
        "checks": {},
    }

    result["checks"]["account_info"] = get_account_info(username)
    result["checks"]["recent_activity"] = get_recent_activity(username)
    result["checks"]["group_membership"] = get_group_membership(username)
    result["checks"]["risk_score"] = calculate_risk_score(username)

    return result


def get_account_info(username: str) -> dict:
    """Retrieve account metadata for *username*.

    Looks up a hardcoded demo directory that models the kind of data an
    Active Directory or LDAP query would return.

    Args:
        username: The account name (case-insensitive).

    Returns:
        A dict with keys such as ``enabled``, ``account_type``,
        ``department``, ``last_password_change``, and ``account_created``.
    """
    demo_users = {
        "admin": {
            "enabled": True,
            "account_type": "administrative",
            "department": "IT",
            "last_password_change": "2026-04-01",
            "account_created": "2024-01-15",
            "password_expires": "2026-07-01",
        },
        "john.smith": {
            "enabled": True,
            "account_type": "standard",
            "department": "Engineering",
            "last_password_change": "2026-03-15",
            "account_created": "2025-06-01",
            "password_expires": "2026-06-15",
        },
        "jdoe": {
            "enabled": True,
            "account_type": "standard",
            "department": "Sales",
            "last_password_change": "2026-02-28",
            "account_created": "2024-03-10",
            "password_expires": "2026-05-28",
        },
        "terminated_user": {
            "enabled": False,
            "account_type": "standard",
            "department": "Unknown",
            "last_password_change": "2025-12-01",
            "account_created": "2023-01-01",
            "password_expires": "N/A",
            "notes": "Account disabled 2026-01-15",
        },
    }

    username_lower = username.lower()
    if username_lower in demo_users:
        return demo_users[username_lower]

    # Unknown users get a safe default — enabled=True avoids false-positive
    # alerts on legitimate but unseen accounts.
    return {
        "enabled": True,
        "account_type": "standard",
        "department": "Unknown",
        "last_password_change": "unknown",
        "account_created": "unknown",
    }


def get_recent_activity(username: str) -> dict:
    """Retrieve recent login activity for *username*.

    Returns logon counts, failure counts, last-seen timestamp, and
    whether the session carried elevated privileges.

    Args:
        username: The account name (case-insensitive).

    Returns:
        A dict with ``logons_today``, ``failed_logons_today``,
        ``last_logon``, ``last_logon_location``, and ``privileged_session``.
    """
    demo_activity = {
        "admin": {
            "logons_today": 5,
            "failed_logons_today": 0,
            "last_logon": "2026-04-18T14:30:00Z",
            "last_logon_location": "DC01",
            "privileged_session": True,
        },
        "john.smith": {
            "logons_today": 3,
            "failed_logons_today": 2,
            "last_logon": "2026-04-18T12:15:00Z",
            "last_logon_location": "WORKSTATION05",
            "privileged_session": False,
        },
    }

    username_lower = username.lower()
    if username_lower in demo_activity:
        return demo_activity[username_lower]

    return {
        "logons_today": 1,
        "failed_logons_today": 0,
        "last_logon": "unknown",
        "last_logon_location": "unknown",
        "privileged_session": False,
    }


def get_group_membership(username: str) -> dict:
    """Retrieve AD/LDAP group membership for *username*.

    Flags privileged groups (Domain Admins, Enterprise Admins, etc.)
    so downstream risk scoring can weigh membership appropriately.

    Args:
        username: The account name (case-insensitive).

    Returns:
        A dict with ``primary_group``, ``groups`` (list), and
        ``privileged`` (bool).
    """
    group_map = {
        "admin": {
            "primary_group": "Domain Admins",
            "groups": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
            "privileged": True,
        },
        "john.smith": {
            "primary_group": "Domain Users",
            "groups": ["Domain Users", "Engineering", "VPN Users"],
            "privileged": False,
        },
        "jdoe": {
            "primary_group": "Domain Users",
            "groups": ["Domain Users", "Sales", "CRM Users"],
            "privileged": False,
        },
    }

    username_lower = username.lower()
    if username_lower in group_map:
        return group_map[username_lower]

    return {
        "primary_group": "Domain Users",
        "groups": ["Domain Users"],
        "privileged": False,
    }


def calculate_risk_score(username: str) -> dict:
    """Compute a composite risk score (0–100) for *username*.

    Factors checked:
        - Disabled account → +25
        - >5 failed logons today → +25
        - Active privileged session → +25
        - Membership in a privileged group → +25
        - Password not changed in >90 days → +25

    The raw total is capped at 100 and mapped to a severity level.

    Args:
        username: The account name (case-insensitive).

    Returns:
        A dict with ``score`` (int), ``level`` (str), and ``factors``
        (list of human-readable risk-factor descriptions).
    """
    risk_factors = []

    account = get_account_info(username)
    activity = get_recent_activity(username)
    groups = get_group_membership(username)

    if not account.get("enabled", True):
        risk_factors.append("Disabled account")

    if activity.get("failed_logons_today", 0) > 5:
        risk_factors.append("High failed logons")

    if activity.get("privileged_session"):
        risk_factors.append("Privileged session")

    if groups.get("privileged"):
        risk_factors.append("Privileged group membership")

    # Check password age — stale passwords increase credential-theft risk.
    try:
        last_change = account.get("last_password_change", "unknown")
        if last_change != "unknown":
            last_change_date = datetime.strptime(last_change, "%Y-%m-%d")
            days_since_change = (datetime.utcnow() - last_change_date).days
            if days_since_change > 90:
                risk_factors.append(f"Password not changed in {days_since_change} days")
    except (ValueError, TypeError):
        pass

    # Each factor contributes 25 points; the score is hard-capped at 100.
    score = min(len(risk_factors) * 25, 100)

    return {
        "score": score,
        "level": "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low",
        "factors": risk_factors,
    }


def main():
    parser = argparse.ArgumentParser(description="User Context Lookup")
    parser.add_argument("username", help="Username to look up")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result = enrich_user(args.username)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        account = result.get("checks", {}).get("account_info", {})
        table = Table(title=f"User Context: {args.username}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Account Type", account.get("account_type", "unknown"))
        table.add_row("Enabled", str(account.get("enabled", "unknown")))
        table.add_row("Department", account.get("department", "unknown"))
        table.add_row("Last Password Change", account.get("last_password_change", "unknown"))

        activity = result.get("checks", {}).get("recent_activity", {})
        table.add_row("Logons Today", str(activity.get("logons_today", 0)))
        table.add_row("Failed Logons Today", str(activity.get("failed_logons_today", 0)))
        table.add_row("Last Logon", activity.get("last_logon", "unknown"))

        groups = result.get("checks", {}).get("group_membership", {})
        table.add_row("Groups", ", ".join(groups.get("groups", [])[:3]))

        risk = result.get("checks", {}).get("risk_score", {})
        risk_style = "red" if risk.get("level") == "Critical" else "yellow" if risk.get("level") == "High" else "green"
        table.add_row("Risk Level", f"[{risk_style}]{risk.get('level', 'unknown')}[/{risk_style}]")

        console.print(table)


if __name__ == "__main__":
    main()