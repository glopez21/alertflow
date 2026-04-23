#!/usr/bin/env python3
"""AlertFlow - SOC Alert Triage Workflow CLI."""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

app = typer.Typer(name="alertflow", help="AlertFlow - SOC Alert Triage")
console = Console()


ALERT_STATUS = ["Open", "In Progress", "Escalated", "Closed - FP", "Closed - Benign", "Closed - Responded"]
SEVERITY_LEVELS = ["P1", "P2", "P3", "P4"]


class AlertStore:
    """Simple alert storage (JSON file)."""
    
    def __init__(self, store_file: str = "alerts.json"):
        self.store_file = Path(store_file)
        self.alerts = self._load()
    
    def _load(self) -> dict:
        if self.store_file.exists():
            return json.loads(self.store_file.read_text())
        return {"alerts": []}
    
    def _save(self):
        self.store_file.write_text(json.dumps(self.alerts, indent=2))
    
    def add_alert(self, title: str, severity: str, source: str, ioc: str = "") -> dict:
        alert = {
            "id": len(self.alerts["alerts"]) + 1,
            "title": title,
            "severity": severity,
            "source": source,
            "ioc": ioc,
            "status": "Open",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "analyst": "",
            "notes": [],
            "fp_reason": "",
            "enrichment": {}
        }
        self.alerts["alerts"].append(alert)
        self._save()
        return alert
    
    def update_status(self, alert_id: int, status: str, analyst: str = "", fp_reason: str = "") -> Optional[dict]:
        for alert in self.alerts["alerts"]:
            if alert["id"] == alert_id:
                alert["status"] = status
                alert["updated_at"] = datetime.now().isoformat()
                if analyst:
                    alert["analyst"] = analyst
                if fp_reason:
                    alert["fp_reason"] = fp_reason
                self._save()
                return alert
        return None
    
    def get_alert(self, alert_id: int) -> Optional[dict]:
        for alert in self.alerts["alerts"]:
            if alert["id"] == alert_id:
                return alert
        return None
    
    def list_alerts(self, status: Optional[str] = None) -> list:
        if status:
            return [a for a in self.alerts["alerts"] if a["status"] == status]
        return self.alerts["alerts"]


store = AlertStore()


@app.command()
def triage(alert_file: str):
    """Run interactive alert triage workflow."""
    console.print("[bold blue]AlertFlow Triage Workflow[/bold blue]")
    console.print("[dim]REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE[/dim]\n")
    
    # Load alerts from file
    try:
        with open(alert_file) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading alert: {e}[/red]")
        sys.exit(1)
    
    title = data.get("title", "Unknown Alert")
    severity = data.get("severity", "P3")
    raw_data = data.get("raw", "")
    
    console.print(f"[bold]Alert:[/bold] {title}")
    console.print(f"[bold]Severity:[/bold] {severity}")
    console.print(f"[bold]Raw:[/bold] {raw_data[:100]}...\n")
    
    # VALIDATE
    console.print("[cyan]1. VALIDATE[/cyan] - Is this a legitimate alert?")
    is_legitimate = Prompt.ask(
        "Is this alert legitimate?",
        choices=["y", "n"],
        default="y"
    )
    
    if is_legitimate == "n":
        # ENRICH  
        console.print("\n[cyan]2. ENRICH[/cyan] - Gathering context...")
        
        # Try to extract IOC
        ioc = ""
        for word in raw_data.split():
            if "." in word and not word.startswith("["):
                ioc = word.strip().rstrip(",.")
                break
        
        if ioc:
            console.print(f"[dim]Found IOC: {ioc}[/dim]")
        
        # DOCUMENT  
        console.print("\n[cyan]3. DOCUMENT[/cyan] - Document findings...")
        notes = Prompt.ask("Add notes (or press Enter to skip)", default="")
        
        # ESCALATE or CLOSE
        console.print("\n[cyan]4. ESCALATE[/cyan]")
        action = Prompt.ask(
            "Action to take",
            choices=["escalate", "fp", "close"],
            default="close"
        )
        
        if action == "fp":
            fp_reason = Prompt.ask("Why is this a FP?")
            console.print(f"\n[green]✓ Alert marked as False Positive[/green]")
            console.print(f"[dim]FP Reason: {fp_reason}[/dim]")
        elif action == "escalate":
            console.print(f"\n[yellow]⚠ Alert escalated to Tier 2[/yellow]")
        else:
            console.print(f"\n[blue]✓ Alert closed[/blue]")
    else:
        console.print("\n[green]Alert verified as legitimate - no action needed[/green]")


@app.command()
def create(title: str, severity: str = "P3", source: str = "manual", ioc: str = ""):
    """Create a new alert."""
    alert = store.add_alert(title, severity, source, ioc)
    console.print(f"[green]✓ Created alert #{alert['id']}: {title}[/green]")


@app.command()
def list(status: Optional[str] = None):
    """List alerts."""
    alerts = store.list_alerts(status)
    
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
    """Close an alert (optionally as False Positive)."""
    alert = store.update_status(alert_id, "Closed", analyst, reason)
    if alert:
        console.print(f"[green]✓ Alert #{alert_id} closed[/green]")
    else:
        console.print(f"[red]Alert #{alert_id} not found[/red]")


@app.command()
def fp(alert_id: int, reason: str):
    """Mark an alert as False Positive with reason."""
    alert = store.update_status(alert_id, "Closed - FP", fp_reason=reason)
    if alert:
        console.print(f"[green]✓ Alert #{alert_id} marked as FP[/green]")
        console.print(f"[dim]Reason: {reason}[/dim]")
    else:
        console.print(f"[red]Alert #{alert_id} not found[/red]")


@app.command()
def note(alert_id: int, note: str, analyst: str = ""):
    """Add a note/timeline entry to an alert."""
    alert = store.get_alert(alert_id)
    if not alert:
        console.print(f"[red]Alert #{alert_id} not found[/red]")
        return
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "analyst": analyst or "unknown",
        "note": note
    }
    
    if "notes" not in alert:
        alert["notes"] = []
    alert["notes"].append(entry)
    store._save()
    
    console.print(f"[green]✓ Added note to alert #{alert_id}[/green]")


@app.command()
def timeline(alert_id: int):
    """Show alert timeline/history."""
    alert = store.get_alert(alert_id)
    if not alert:
        console.print(f"[red]Alert #{alert_id} not found[/red]")
        return
    
    console.print(f"\n[bold blue]Alert #{alert_id} Timeline[/bold blue]")
    console.print(f"[cyan]{alert['title']}[/cyan]\n")
    
    # Build timeline
    timeline = []
    
    # Creation
    timeline.append({
        "time": alert.get("created_at", ""),
        "action": "Alert created",
        "analyst": "system"
    })
    
    # Notes
    for note in alert.get("notes", []):
        timeline.append({
            "time": note.get("timestamp", ""),
            "action": note.get("note", ""),
            "analyst": note.get("analyst", "")
        })
    
    # Updated
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