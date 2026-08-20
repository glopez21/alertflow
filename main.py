#!/usr/bin/env python3
"""AlertFlow - SOC Alert Triage Workflow CLI.

Command-line interface for security operations centre (SOC) analysts to
triage, enrich, and respond to security alerts.  Built on Typer with
Rich for terminal formatting.

Subcommands
-----------
- ``triage``   Interactive workflow: review -> validate -> enrich -> document -> escalate.
- ``create``   Manually create a new alert.
- ``list``     List stored alerts, optionally filtered by status.
- ``close``    Close an alert.
- ``fp``       Mark an alert as False Positive with a reason.
- ``delete``   Remove an alert from the store.
- ``migrate``  Import alerts from a legacy JSON file into SQLite.
- ``note``     Attach a note / timeline entry to an alert.
- ``timeline`` Display the full timeline for an alert.

Integration points
------------------
- **ThreatPulse** -- Webhook destination for triaged alerts.
- **AdminFlow** -- Identity provider used to disable compromised accounts.
- **Augur**     -- Hub for aggregating triage results across the SOC.
- **Live**      -- Optional real-time monitoring sub-app (loaded if available).
"""

import json
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from db import AlertStore
from pipeline import extract_and_enrich, push_to_threatpulse, disable_user_in_adminflow
from augur_notifier import AugurNotifier

app = typer.Typer(name="alertflow", help="AlertFlow - SOC Alert Triage")

# Optionally mount the real-time monitoring sub-app under ``alertflow live``.
# The import is guarded so the CLI remains functional when the live module
# is not installed.
try:
    from live.__main__ import app as live_app
    app.add_typer(live_app, name="live")
except ImportError:
    pass
console = Console()


# Canonical status and severity vocabularies used across the triage
# workflow and persisted to the database.
ALERT_STATUS = ["Open", "In Progress", "Escalated", "Closed - FP", "Closed - Benign", "Closed - Responded"]
SEVERITY_LEVELS = ["P1", "P2", "P3", "P4"]


store = AlertStore()


@app.command()
def triage(
    alert_file: str,
    enrich: bool = typer.Option(True, "--enrich/--no-enrich", help="Run IOC enrichment"),
    push: bool = typer.Option(False, "--push/--no-push", help="Push results to ThreatPulse"),
    disable_user: str = typer.Option("", "--disable-user", help="Disable user in AdminFlow (e.g. compromised account)"),
    threatpulse_url: str = typer.Option("", "--tp-url", help="ThreatPulse base URL", envvar="THREATPULSE_URL"),
    threatpulse_key: str = typer.Option("", "--tp-key", help="ThreatPulse API key", envvar="THREATPULSE_API_KEY"),
    adminflow_url: str = typer.Option("", "--af-url", help="AdminFlow base URL", envvar="ADMINFLOW_URL"),
    adminflow_key: str = typer.Option("", "--af-key", help="AdminFlow API key", envvar="ADMINFLOW_API_KEY"),
    augur_url: str = typer.Option("", "--augur-url", help="Augur hub URL", envvar="AUGUR_URL"),
):
    """Run interactive alert triage workflow with enrichment and integrations.

    Orchestrates the full analyst triage lifecycle:

    1. **REVIEW**   -- Parse and display alert fields (title, severity, IPs, user).
    2. **VALIDATE** -- Analyst confirms the alert is a true positive.
    3. **ENRICH**   -- Extract IOCs from raw text, look up each one in parallel
                       via the enrichment pipeline, and display results in tables.
    4. **DOCUMENT** -- Analyst adds free-form notes.
    5. **ESCALATE** -- Analyst chooses an action: escalate, close, mark FP,
                       or disable the compromised user account.

    After triage the alert is persisted to SQLite, optionally pushed to
    ThreatPulse, and forwarded to the Augur hub.

    Environment variables ``THREATPULSE_URL``, ``THREATPULSE_API_KEY``,
    ``ADMINFLOW_URL``, ``ADMINFLOW_API_KEY``, and ``AUGUR_URL`` are used
    as fallback defaults for the corresponding CLI options.
    """
    console.print("[bold blue]AlertFlow Triage Workflow[/bold blue]")
    console.print("[dim]REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE[/dim]\n")

    # Load alerts from file
    try:
        with open(alert_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(f"[red]Alert file not found: {alert_file}[/red]")
        raise SystemExit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON in alert file: {e}[/red]")
        raise SystemExit(1)

    title = data.get("title", "Unknown Alert")
    severity = data.get("severity", "P3")
    raw_data = data.get("raw", "")
    src_ip = data.get("src_ip", "")
    dst_ip = data.get("dst_ip", "")
    user = data.get("user", "")

    # REVIEW
    console.print(f"[bold]Alert:[/bold] {title}")
    console.print(f"[bold]Severity:[/bold] {severity}")
    if src_ip:
        console.print(f"[bold]Source IP:[/bold] {src_ip}")
    if dst_ip:
        console.print(f"[bold]Destination IP:[/bold] {dst_ip}")
    if user:
        console.print(f"[bold]User:[/bold] {user}")
    if raw_data:
        console.print(f"[bold]Raw:[/bold] {raw_data[:200]}...\n" if len(raw_data) > 200 else f"[bold]Raw:[/bold] {raw_data}\n")

    # VALIDATE
    console.print("[cyan]1. VALIDATE[/cyan] - Is this a legitimate alert?")
    is_legitimate = Prompt.ask(
        "Is this alert legitimate?",
        choices=["y", "n"],
        default="y",
    )

    if is_legitimate == "n":
        console.print("\n[green]Alert dismissed as false positive - no action needed[/green]")
        return

    enrichment_data = {}

    # -- Phase 2: ENRICH --
    # Fall back to concatenating structured fields when raw_data is empty,
    # so the IOC extractor still has something to work with.
    console.print("\n[cyan]2. ENRICH[/cyan] - Gathering context...")
    if enrich:
        enrichment_data = extract_and_enrich(raw_data or " ".join(filter(None, [src_ip, dst_ip, user])))

        iocs = enrichment_data.get("iocs", {})
        enrichment = enrichment_data.get("enrichment", {})

        if iocs:
            table = Table(title="Extracted IOCs")
            table.add_column("Type", style="cyan")
            table.add_column("Count", style="yellow")
            table.add_column("Values", style="white")
            if iocs.get("ips"):
                table.add_row("IPs", str(len(iocs["ips"])), ", ".join(iocs["ips"][:5]))
            if iocs.get("domains"):
                table.add_row("Domains", str(len(iocs["domains"])), ", ".join(iocs["domains"][:5]))
            hashes_total = sum(len(iocs.get("hashes", {}).get(k, [])) for k in ("md5", "sha1", "sha256"))
            if hashes_total:
                table.add_row("Hashes", str(hashes_total), ", ".join(iocs.get("hashes", {}).get("sha256", [])[:2]))
            if iocs.get("emails"):
                table.add_row("Emails", str(len(iocs["emails"])), ", ".join(iocs["emails"][:3]))
            console.print(table)

        if enrichment:
            table = Table(title="Enrichment Results")
            table.add_column("Target", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Key Findings", style="white")
            for key, result in enrichment.items():
                rtype = result.get("type", "unknown")
                target = result.get("ip", result.get("domain", result.get("hash", result.get("username", key))))
                findings = ""
                checks = result.get("checks", {})
                if isinstance(checks, dict):
                    items = []
                    for k, v in list(checks.items())[:3]:
                        if isinstance(v, dict):
                            items.append(f"{k}: {v.get('reputation', v.get('type', str(v)))}")
                        else:
                            items.append(f"{k}: {v}")
                    findings = ", ".join(items)
                table.add_row(str(target)[:30], rtype, findings[:50])
            console.print(table)
    else:
        console.print("[dim]Enrichment skipped[/dim]")

    # DOCUMENT
    console.print("\n[cyan]3. DOCUMENT[/cyan] - Document findings...")
    notes = Prompt.ask("Add notes (or press Enter to skip)", default="")

    # -- Phase 4: ESCALATE / CLOSE / DISABLE --
    # Analyst chooses the disposition; this drives the final alert status
    # and may trigger a side-effect (e.g. account disable via AdminFlow).
    console.print("\n[cyan]4. ESCALATE[/cyan]")
    action = Prompt.ask(
        "Action to take",
        choices=["escalate", "fp", "close", "disable"],
        default="close",
    )

    alert_status = "Closed"
    fp_reason = ""
    analyst = Prompt.ask("Analyst name", default="")

    if action == "fp":
        fp_reason = Prompt.ask("Why is this a FP?")
        alert_status = "Closed - FP"
        console.print("\n[green]✓ Alert marked as False Positive[/green]")
        console.print(f"[dim]FP Reason: {fp_reason}[/dim]")
    elif action == "escalate":
        alert_status = "Escalated"
        console.print("\n[yellow]⚠ Alert escalated to Tier 2[/yellow]")
    elif action == "disable":
        if user:
            console.print(f"\n[red]⚠ Disabling user: {user}[/red]")
            if adminflow_url:
                result = disable_user_in_adminflow(user, adminflow_url, adminflow_key)
                if result and result.get("status") != "error":
                    console.print(f"[green]✓ User {user} disabled in AdminFlow[/green]")
                else:
                    console.print("[yellow]⚠ AdminFlow disable failed (check URL/key)[/yellow]")
            else:
                console.print("[dim]No AdminFlow URL configured - user disable skipped[/dim]")
            alert_status = "Escalated"
        else:
            console.print("[yellow]No username in alert - cannot disable[/yellow]")
            alert_status = "Escalated"
    else:
        alert_status = "Closed"
        console.print("\n[blue]✓ Alert closed[/blue]")

    # Persist the triage result -- add_alert creates the row; subsequent
    # calls enrich it with status, enrichment data, and analyst notes.
    saved = store.add_alert(title, severity, data.get("source", "triage"), ioc=src_ip or "")
    store.update_status(saved["id"], alert_status, analyst, fp_reason)
    if enrichment_data:
        store.update_enrichment(saved["id"], enrichment_data)
    if notes:
        store.add_note(saved["id"], notes, analyst)

    # -- Phase 5: NOTIFY --
    # Forward the triaged alert to ThreatPulse when the operator opts in
    # via --push and provides a valid base URL.
    if push and threatpulse_url:
        console.print("\n[cyan]5. NOTIFY[/cyan] - Pushing to ThreatPulse...")
        result = push_to_threatpulse(
            {**data, "status": alert_status, "analyst": analyst},
            enrichment_data,
            threatpulse_url,
            threatpulse_key,
        )
        if result and result.get("status") != "error":
            console.print("[green]✓ Alert pushed to ThreatPulse[/green]")
        else:
            console.print("[yellow]⚠ ThreatPulse push failed (check URL/key)[/yellow]")
    elif push and not threatpulse_url:
        console.print("\n[yellow]⚠ --push enabled but no --tp-url configured[/yellow]")

    # Summary
    console.print("\n[bold]Triage Summary[/bold]")
    console.print(f"  Alert: {title}")
    console.print(f"  Status: {alert_status}")
    console.print(f"  Analyst: {analyst or 'unknown'}")
    if fp_reason:
        console.print(f"  FP Reason: {fp_reason}")
    if enrichment_data.get("iocs"):
        iocs = enrichment_data["iocs"]
        console.print(f"  IOCs: {sum(len(v) if isinstance(v, list) else sum(len(v2) for v2 in v.values()) for v in iocs.values())} found")
    console.print(f"  Saved as alert #{saved['id']}")

    # Aggregate triage results to the Augur hub for cross-SOC visibility.
    # This is fire-and-forget; failures are logged but do not block the CLI.
    if augur_url:
        augur = AugurNotifier({"hub_url": augur_url})
        triage_data = {**data, "id": saved["id"], "status": alert_status, "analyst": analyst}
        if augur.push_triage_result(triage_data, enrichment_data):
            console.print("[green]✓ Pushed to Augur hub[/green]")
        else:
            console.print("[dim]Augur push skipped or failed[/dim]")


@app.command()
def create(title: str, severity: str = "P3", source: str = "manual", ioc: str = ""):
    """Create a new alert directly without the interactive triage flow.

    Useful for ingesting alerts from external sources or scripting bulk
    alert creation.
    """
    alert = store.add_alert(title, severity, source, ioc)
    console.print(f"[green]✓ Created alert #{alert['id']}: {title}[/green]")


@app.command("list")
def list_alerts(status: Optional[str] = None):
    """List alerts stored in the database.

    Args:
        status: Optional status filter (e.g. ``"Open"``, ``"Escalated"``).
                When ``None`` all alerts are returned.
    """
    alerts, total = store.list_alerts(status)
    
    table = Table(title=f"Alerts{' - ' + status if status else ''}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Created")
    
    for alert in alerts:
        severity_style = "red" if alert["severity"] == "P1" else "yellow" if alert["severity"] == "P2" else "green"
        table.add_row(
            str(alert["id"]),
            alert["title"][:30],
            f"[{severity_style}]{alert['severity']}[/{severity_style}]",
            alert["status"],
            alert["created_at"][:10]
        )
    
    console.print(table)


@app.command()
def close(alert_id: int, reason: str = "", analyst: str = ""):
    """Close an alert, optionally marking it as a False Positive.

    Args:
        alert_id: Database ID of the alert to close.
        reason: Optional reason string (stored as the FP reason field).
        analyst: Name of the analyst closing the alert.
    """
    alert = store.update_status(alert_id, "Closed", analyst, reason)
    if alert:
        console.print(f"[green]✓ Alert #{alert_id} closed[/green]")
    else:
        console.print(f"[red]Alert #{alert_id} not found[/red]")


@app.command()
def fp(alert_id: int, reason: str):
    """Mark an alert as False Positive with a required reason.

    Sets the alert status to ``"Closed - FP"`` and records *reason* for
    audit purposes.
    """
    alert = store.update_status(alert_id, "Closed - FP", fp_reason=reason)
    if alert:
        console.print(f"[green]✓ Alert #{alert_id} marked as FP[/green]")
        console.print(f"[dim]Reason: {reason}[/dim]")
    else:
        console.print(f"[red]Alert #{alert_id} not found[/red]")


@app.command()
def delete(alert_id: int):
    """Permanently delete an alert from the database.

    This operation is irreversible.  Prefer ``close`` or ``fp`` for
    normal workflow disposition.
    """
    if store.delete_alert(alert_id):
        console.print(f"[green]✓ Alert #{alert_id} deleted[/green]")
    else:
        console.print(f"[red]Alert #{alert_id} not found[/red]")


@app.command()
def migrate(json_file: str = "alerts.json"):
    """Migrate alerts from a legacy JSON file to the SQLite database.

    Reads each alert from *json_file*, inserts it into the store, and
    reports the count of successfully migrated records.
    """
    count = store.migrate_from_json(json_file)
    if count:
        console.print(f"[green]✓ Migrated {count} alerts from {json_file} to SQLite[/green]")
    else:
        console.print(f"[yellow]No alerts found in {json_file}[/yellow]")


@app.command()
def note(alert_id: int, note: str, analyst: str = ""):
    """Add a note / timeline entry to an alert.

    Notes are append-only and timestamped; they appear in the ``timeline``
    view and provide an audit trail of analyst actions.
    """
    alert = store.add_note(alert_id, note, analyst)
    if not alert:
        console.print(f"[red]Alert #{alert_id} not found[/red]")
        return

    console.print(f"[green]✓ Added note to alert #{alert_id}[/green]")


@app.command()
def timeline(alert_id: int):
    """Show the full timeline / history for an alert.

    Reconstructs a chronological view from the alert's creation event,
    all attached notes, and the most recent status update, then displays
    them in a Rich table sorted by timestamp.
    """
    alert = store.get_alert(alert_id)
    if not alert:
        console.print(f"[red]Alert #{alert_id} not found[/red]")
        return
    
    console.print(f"\n[bold blue]Alert #{alert_id} Timeline[/bold blue]")
    console.print(f"[cyan]{alert['title']}[/cyan]\n")
    
    # Build a chronological timeline from structured alert data.
    # Three sources: creation event, analyst notes, and the final
    # status update (if it differs from creation time).
    timeline = []
    
    # Seed the timeline with the alert creation event.
    timeline.append({
        "time": alert.get("created_at", ""),
        "action": "Alert created",
        "analyst": "system"
    })
    
    # Append each analyst note as a timeline entry.
    for note in alert.get("notes", []):
        timeline.append({
            "time": note.get("timestamp", ""),
            "action": note.get("note", ""),
            "analyst": note.get("analyst", "")
        })
    
    # Only add the status-update entry when it differs from creation,
    # avoiding a duplicate line for freshly created alerts.
    if alert.get("updated_at") != alert.get("created_at"):
        timeline.append({
            "time": alert.get("updated_at", ""),
            "action": f"Status: {alert.get('status', '')}",
            "analyst": alert.get("analyst", "")
        })
    
    # Display
    table = Table()
    table.add_column("Time", style="cyan")
    table.add_column("Action", style="white")
    table.add_column("Analyst", style="dim")
    
    for entry in sorted(timeline, key=lambda x: x["time"]):
        table.add_row(
            entry["time"][:19],
            entry["action"][:40],
            entry["analyst"]
        )
    
    console.print(table)


if __name__ == "__main__":
    app()