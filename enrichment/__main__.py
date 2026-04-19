#!/usr/bin/env python3
"""Unified enrichment CLI for AlertFlow."""

import sys
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(name="enrich", help="AlertFlow Enrichment Tools")
console = Console()


@app.command()
def ip(address: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich an IP address."""
    from enrichment.ip_lookup import enrich_ip

    result = enrich_ip(address)
    if json:
        import json as json_mod
        print(json_mod.dumps(result, indent=2))
    else:
        from rich.table import Table

        table = Table(title=f"IP Enrichment: {address}")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        checks = result.get("checks", {})
        for check_name, check_value in checks.items():
            if isinstance(check_value, dict):
                value = ", ".join(f"{k}: {v}" for k, v in check_value.items())
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)


@app.command()
def domain(address: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a domain."""
    from enrichment.domain_lookup import enrich_domain

    result = enrich_domain(address)
    if json:
        import json as json_mod
        print(json_mod.dumps(result, indent=2))
    else:
        from rich.table import Table

        table = Table(title=f"Domain Enrichment: {address}")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        checks = result.get("checks", {})
        for check_name, check_value in checks.items():
            if isinstance(check_value, dict):
                value = ", ".join(f"{k}: {v}" for k, v in check_value.items())
            elif isinstance(check_value, list):
                value = ", ".join(str(v) for v in check_value[:3])
                if len(check_value) > 3:
                    value += f" (+{len(check_value)-3} more)"
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)


@app.command()
def hash(file_hash: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a file hash."""
    from enrichment.hash_lookup import enrich_hash

    result = enrich_hash(file_hash)
    table = Table(title=f"Hash Lookup: {file_hash[:16]}...")
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="white")

    checks = result.get("checks", {})
    for check_name, check_value in checks.items():
        if isinstance(check_value, dict):
            value = ", ".join(f"{k}: {v}" for k, v in check_value.items())
        else:
            value = str(check_value)
        table.add_row(check_name, value)

    console.print(table)
    console.print(f"[dim]Hash type: {result.get('hash_type', 'unknown')}[/dim]")


@app.command()
def user(username: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Enrich a user account."""
    from enrichment.user_lookup import enrich_user

    result = enrich_user(username)

    if json:
        import json as json_mod
        print(json_mod.dumps(result, indent=2))
    else:
        from rich.table import Table

        account = result.get("checks", {}).get("account_info", {})
        table = Table(title=f"User Context: {username}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Account Type", account.get("account_type", "unknown"))
        table.add_row("Enabled", str(account.get("enabled", "unknown")))
        table.add_row("Department", account.get("department", "unknown"))

        activity = result.get("checks", {}).get("recent_activity", {})
        table.add_row("Logons Today", str(activity.get("logons_today", 0)))
        table.add_row("Failed Logons Today", str(activity.get("failed_logons_today", 0)))

        groups = result.get("checks", {}).get("group_membership", {})
        table.add_row("Groups", ", ".join(groups.get("groups", [])[:3]))

        risk = result.get("checks", {}).get("risk_score", {})
        risk_style = "red" if risk.get("level") == "Critical" else "yellow" if risk.get("level") == "High" else "green"
        table.add_row("Risk Level", f"[{risk_style}]{risk.get('level', 'unknown')}[/{risk_style}]")

        console.print(table)


@app.command()
def all(target: str, json: bool = typer.Option(False, "--json", help="Output as JSON")):
    """Auto-detect and enrich any IOC (IP, domain, hash, or user)."""
    import json as json_mod

    if "@" in target:
        target_type = "email"
    elif target.count(".") >= 1 and not target.replace(".", "").replace("-", "").isdigit():
        target_type = "domain"
    elif ":" in target:
        target_type = "url"
    elif target.replace("-", "").replace(":", "").isalnum() and len(target) in (32, 40, 64, 128):
        target_type = "hash"
    elif target.count(".") == 3 and all(part.isdigit() for part in target.split(".")):
        target_type = "ip"
    else:
        target_type = "unknown"

    console.print(f"[cyan]Auto-detected type:[/cyan] {target_type}")

    if target_type == "ip":
        from enrichment.ip_lookup import enrich_ip
        result = enrich_ip(target)
    elif target_type == "domain":
        from enrichment.domain_lookup import enrich_domain
        result = enrich_domain(target)
    elif target_type == "hash":
        from enrichment.hash_lookup import enrich_hash
        result = enrich_hash(target)
    else:
        console.print(f"[red]Unknown IOC type for: {target}[/red]")
        sys.exit(1)

    if json:
        print(json_mod.dumps(result, indent=2))
    else:
        from rich.table import Table

        table = Table(title=f"Enrichment: {target}")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        checks = result.get("checks", {})
        for check_name, check_value in checks.items():
            if isinstance(check_value, dict):
                value = ", ".join(f"{k}: {v}" for k, v in check_value.items())
            elif isinstance(check_value, list):
                value = ", ".join(str(v) for v in check_value[:3])
                if len(check_value) > 3:
                    value += f" (+{len(check_value)-3} more)"
            else:
                value = str(check_value)
            table.add_row(check_name, value)

        console.print(table)


if __name__ == "__main__":
    app()