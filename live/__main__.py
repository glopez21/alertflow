#!/usr/bin/env python3
"""Live integration CLI for AlertFlow.

Exposes Typer CLI commands for day-to-day SOC operations:

* ``siem``   -- pull recent alerts from Splunk or Elasticsearch.
* ``ticket`` -- create a Jira/ServiceNow ticket from the command line.
* ``check``  -- look up an IOC (IP, hash) across threat intel feeds.
* ``triage`` -- end-to-end triage: load an alert JSON, enrich it with
  threat intel, and optionally open a ticket.

Run as a module: ``python -m live <command> [OPTIONS]``.
"""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="live", help="AlertFlow Live Integration")
console = Console()


@app.command()
def siem(
    hours: int = typer.Option(1, "--hours", "-h", help="Hours to look back"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    limit: int = typer.Option(10, "--limit", "-l", help="Max results"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="SIEM config file"),
) -> None:
    """Fetch recent alerts from the configured SIEM (Splunk or Elasticsearch).

    When ``--config`` is omitted a default local-Splunk configuration
    is used.  The output is rendered as a Rich table with colour-coded
    severity.
    """
    from live.siem_collector import get_alerts_from_config

    if config_file:
        # Load SIEM connection details from a JSON config file.
        import json
        with open(config_file) as f:
            config = json.load(f)
    else:
        config = {"type": "splunk", "host": "localhost", "index": "security"}

    # Merge query options into the config dict so they reach the collector.
    alerts = get_alerts_from_config({**config, "hours": hours, "severity": severity, "limit": limit})

    if not alerts:
        console.print("[yellow]No alerts found (or using sample data)[/yellow]")

    # Map severity to Rich console styles for colour-coded output.
    table = Table(title=f"SIEM Alerts (Last {hours}h)")
    table.add_column("ID", style="cyan")
    table.add_column("Rule", style="white")
    table.add_column("Severity", style="yellow")
    table.add_column("Host", style="white")
    table.add_column("User", style="dim")

    for alert in alerts:
        severity_style = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(alert.severity, "white")

        table.add_row(
            alert.id,
            alert.rule_name[:40],
            f"[{severity_style}]{alert.severity}[/{severity_style}]",
            alert.host,
            alert.user,
        )

    console.print(table)


@app.command()
def ticket(
    summary: str = typer.Argument(..., help="Ticket summary"),
    description: str = typer.Option("", "--description", "-d", help="Ticket description"),
    priority: str = typer.Option("medium", "--priority", "-p", help="Priority"),
    system: str = typer.Option("jira", "--system", "-s", help="Ticketing system"),
    host: Optional[str] = typer.Option(None, "--host", help="Jira/ServiceNow host"),
) -> None:
    """Create an incident ticket in Jira or ServiceNow.

    Without ``--host`` a sample ticket is generated so the command
    can be used for quick demos without a live ticketing backend.
    """
    from live.ticket_creator import create_ticket_system

    config = {"host": host} if host else {}

    if system == "jira" and host:
        creator = create_ticket_system("jira", **config)
        ticket = creator.create_issue(summary, description or summary, priority)
    elif system == "servicenow" and host:
        creator = create_ticket_system("servicenow", **config)
        ticket = creator.create_incident(summary, description or summary, priority)
    else:
        # No host configured -- fall back to a sample ticket for demo purposes.
        console.print("[yellow]Using sample (configure for real ticketing)[/yellow]")
        from live.ticket_creator import AlertTicket
        ticket = AlertTicket(key="SOC-1001", url="https://jira.example.com/SOC-1001", status="Open")

    console.print(f"[green]Created: {ticket.key}[/green]")
    console.print(f"[cyan]URL: {ticket.url}[/cyan]")


@app.command()
def check(
    ioc: str = typer.Argument(..., help="IOC to check (IP, hash, domain)"),
    feeds: str = typer.Option("virustotal,abuseipdb", "--feeds", "-f", help="Feeds to check"),
    api_keys: str = typer.Option("", "--keys", "-k", help="Comma-separated API keys"),
) -> None:
    """Check an IOC against one or more threat intelligence feeds.

    API keys are positional: the first key maps to the first feed,
    the second key to the second feed, etc.  Without keys the feeds
    will use empty tokens (useful only against sandboxes or mocks).
    """
    from live.feed_poller import check_ioc_with_feeds

    # Pair each feed type with its corresponding API key by position.
    api_key_list = api_keys.split(",") if api_keys else [""]

    feeds_config = []
    for feed_type in feeds.split(","):
        feeds_config.append({
            "type": feed_type.strip(),
            "api_key": api_key_list[0] if api_key_list else "",
        })

    results = check_ioc_with_feeds(ioc, feeds_config)

    if not results:
        console.print(f"[yellow]No results found for {ioc}[/yellow]")
        return

    table = Table(title=f"Threat Intel: {ioc}")
    table.add_column("Source", style="cyan")
    table.add_column("Confidence", style="yellow")
    table.add_column("Severity", style="red")

    for result in results:
        table.add_row(
            result.get("source", "unknown"),
            f"{result.get('confidence', 0)*100:.0f}%",
            result.get("severity", "unknown"),
        )

    console.print(table)


@app.command()
def triage(
    alert_file: str = typer.Argument(..., help="Alert JSON file"),
    create_ticket: bool = typer.Option(True, "--ticket/--no-ticket", help="Create ticket"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Config file"),
) -> None:
    """End-to-end triage workflow: load alert, enrich with feeds, open ticket.

    Reads a JSON alert file, runs IOC enrichment via configured threat
    feeds, displays a summary table, and optionally creates a Jira
    ticket with the enriched data.
    """
    import json

    with open(alert_file) as f:
        alert = json.load(f)

    from live.feed_poller import enrich_alert_with_feeds
    feeds_config = [{"type": "virustotal", "api_key": ""}]
    enriched = enrich_alert_with_feeds(alert, feeds_config)

    table = Table(title=f"Triage: {enriched.get('rule_name', 'Unknown')}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Severity", enriched.get("severity", "unknown"))
    table.add_row("Host", enriched.get("host", "unknown"))
    table.add_row("User", enriched.get("user", "unknown"))
    table.add_row("Source IP", enriched.get("src_ip", "N/A"))

    if enriched.get("threat_intel"):
        table.add_row("Threat Intel", f"{len(enriched['threat_intel'])} findings")
    else:
        table.add_row("Threat Intel", "None")

    console.print(table)

    if create_ticket:
        from live.ticket_creator import TicketManager

        tm = TicketManager()
        tm.add_jira(host="")
        ticket = tm.create_from_alert(enriched)
        console.print(f"[green]Created ticket: {ticket.key}[/green]")
        console.print(f"[cyan]{ticket.url}[/cyan]")


if __name__ == "__main__":
    app()