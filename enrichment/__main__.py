#!/usr/bin/env python3
"""Unified enrichment CLI for AlertFlow.

Exposes a single ``typer`` application with sub-commands for every enrichment
type (IP, domain, hash, user) plus an ``all`` command that auto-detects the
IOC kind and dispatches accordingly.

Usage examples::

    python -m enrichment ip 8.8.8.8
    python -m enrichment domain evil.com --json
    python -m enrichment hash aadea647...
    python -m enrichment all <any-ioc>

Design notes:
    - Rich console output is the default; ``--json`` produces machine-readable
      JSON for pipeline integration.
    - Sub-command imports are deferred (inside the function body) so that
      ``python -m enrichment ip …`` does not pull in unrelated modules.
"""

import json as json_mod

import typer
from rich.console import Console
from rich.table import Table

from utils import detect_ioc_type

app = typer.Typer(name="enrich", help="AlertFlow Enrichment Tools")
console = Console()


def _render_checks_table(title: str, result: dict, console: Console = console):
    """Render a Rich ``Table`` from a standard enrichment result dict.

    Walks the ``checks`` sub-dict and formats each entry as a
    "Check | Result" row.  Dicts are flattened to ``k: v`` pairs;
    lists are truncated to three items to keep the table compact.

    Args:
        title: Table caption shown at the top.
        result: The enrichment result dict (must contain a ``checks`` key).
        console: The Rich Console to print to (module-level default).
    """
    checks = result.get("checks", {})
    table = Table(title=title)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="white")

    for check_name, check_value in checks.items():
        if isinstance(check_value, dict):
            value = ", ".join(f"{k}: {v}" for k, v in check_value.items())
        elif isinstance(check_value, list):
            # Show at most three items; append a overflow indicator.
            value = ", ".join(str(v) for v in check_value[:3])
            if len(check_value) > 3:
                value += f" (+{len(check_value) - 3} more)"
        else:
            value = str(check_value)
        table.add_row(check_name, value)

    console.print(table)


@app.command()
def ip(address: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich an IP address."""
    from enrichment.ip_lookup import enrich_ip

    result = enrich_ip(address)
    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        _render_checks_table(f"IP Enrichment: {address}", result)


@app.command()
def domain(address: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a domain."""
    from enrichment.domain_lookup import enrich_domain

    result = enrich_domain(address)
    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        _render_checks_table(f"Domain Enrichment: {address}", result)


@app.command("hash")
def hash_lookup(file_hash: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a file hash."""
    from enrichment.hash_lookup import enrich_hash

    result = enrich_hash(file_hash)
    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        _render_checks_table(f"Hash Lookup: {file_hash[:16]}...", result)
        console.print(f"[dim]Hash type: {result.get('hash_type', 'unknown')}[/dim]")


@app.command()
def user(username: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a user account."""
    from enrichment.user_lookup import enrich_user

    result = enrich_user(username)

    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        account = result.get("checks", {}).get("account_info", {})
        table = Table(title=f"User Context: {username}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Account Type", account.get("account_type", "unknown"))
        table.add_row("Enabled", str(account.get("enabled", "unknown")))
        table.add_row("Department", account.get("department", "unknown"))
        table.add_row("Last Password Change", account.get("last_password_change", "unknown"))

        activity = result.get("checks", {}).get("recent_activity", {})
        table.add_row("Logons Today", str(activity.get("logons_today", 0)))
        table.add_row("Failed Logons Today", str(activity.get("failed_logons_today", 0)))

        groups = result.get("checks", {}).get("group_membership", {})
        table.add_row("Groups", ", ".join(groups.get("groups", [])[:3]))

        risk = result.get("checks", {}).get("risk_score", {})
        risk_style = "red" if risk.get("level") == "Critical" else "yellow" if risk.get("level") == "High" else "green"
        table.add_row("Risk Level", f"[{risk_style}]{risk.get('level', 'unknown')}[/{risk_style}]")

        console.print(table)


@app.command("all")
def enrich_all(target: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Auto-detect and enrich any IOC (IP, domain, hash, or user).

    Uses ``utils.detect_ioc_type`` to classify the input, then
    dispatches to the appropriate enrichment function.  URLs are
    handled by extracting IOCs from the URL text itself.
    """
    from pipeline import enrich_target

    target_type = detect_ioc_type(target)
    console.print(f"[cyan]Auto-detected type:[/cyan] {target_type}")

    if target_type in ("ip", "domain", "hash", "user", "email"):
        if target_type == "email":
            result = enrich_target(target, "email")
        else:
            result = enrich_target(target, target_type)
    elif target_type == "url":
        from enrichment.ioc_extract import extract_iocs
        result = extract_iocs(target)
    else:
        console.print(f"[red]Unknown IOC type for: {target}[/red]")
        raise SystemExit(1)

    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        _render_checks_table(f"Enrichment: {target}", result)


if __name__ == "__main__":
    app()