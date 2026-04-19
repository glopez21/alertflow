#!/usr/bin/env python3
"""AlertFlow Demo - Complete triage workflow demonstration."""

import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def demo_header(title: str):
    console.print(Panel.fit(f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))


def demo_section(title: str):
    console.print(f"\n[bold yellow]{'='*50}[/bold yellow]")
    console.print(f"[bold yellow]{title}[/bold yellow]")
    console.print(f"[bold yellow]{'='*50}[/bold yellow]\n")


def step(text: str):
    console.print(f"[dim]Step:[/dim] {text}")
    time.sleep(0.3)


def run_command(text: str):
    console.print(f"[cyan]$ {text}[/cyan]")


def demo_enrichment():
    """Demo enrichment tools."""
    demo_section("1. ENRICHMENT TOOLS")
    
    step("IP Enrichment")
    run_command("python enrichment/ip_lookup.py 8.8.8.8")
    console.print("[green]✓ Public IP - dns.google - Google DNS server[/green]\n")
    
    step("Hash Lookup")
    run_command("python enrichment/hash_lookup.py deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")
    console.print("[red]✓ Known malware: meterpreter (reverse_shell)[/red]\n")
    
    step("User Context")
    run_command("python enrichment/user_lookup.py admin")
    console.print("[yellow]✓ High risk score - Privileged group membership[/yellow]\n")
    
    step("Auto-detect IOC")
    run_command("python enrichment/all 192.168.1.100")
    console.print("[green]✓ Auto-detected as IP[/green]\n")


def demo_siem():
    """Demo SIEM fetching."""
    demo_section("2. SIEM ALERTS")
    
    step("Fetch recent alerts")
    run_command("python -m live siem --hours 1 --limit 5")
    
    table = Table(title="SIEM Alerts (Last 1h)")
    table.add_column("ID", style="cyan")
    table.add_column("Rule", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Host")
    
    table.add_row("alert-001", "Failed Login Attempt", "high", "workstation01")
    table.add_row("alert-002", "Suspicious PowerShell", "critical", "server01")
    table.add_row("alert-003", "Firewall Block", "medium", "firewall")
    
    console.print(table)


def demo_ticket():
    """Demo ticket creation."""
    demo_section("3. TICKET CREATION")
    
    step("Create Jira ticket")
    run_command("python -m live ticket 'Suspicious PowerShell on server01' --priority critical")
    
    console.print("[green]✓ Created: SOC-1001[/green]")
    console.print("[cyan]URL: https://company.atlassian.net/browse/SOC-1001[/cyan]\n")


def demo_ioc_extraction():
    """Demo IOC extraction."""
    demo_section("4. IOC EXTRACTION")
    
    step("Extract IOCs from alert text")
    alert_text = """
    Alert: Suspicious connection detected
    Source IP: 192.168.1.50
    Destination: evil-domain.xyz
    Hash: deadbeef1234567890abcdef1234567890
    User: administrator
    """
    run_command("python enrichment/ioc_extract.py 'Alert text...'")
    
    table = Table(title="Extracted IOCs")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="yellow")
    table.add_column("Examples", style="white")
    
    table.add_row("IP Addresses", "1", "192.168.1.50")
    table.add_row("Domains", "1", "evil-domain.xyz")
    table.add_row("Hashes", "1", "deadbeef...")
    table.add_row("Users", "1", "administrator")
    
    console.print(table)


def demo_check():
    """Demo IOC check against feeds."""
    demo_section("5. THREAT INTELLIGENCE")
    
    step("Check IOC against threat feeds")
    run_command("python -m live check 203.0.113.50 --feeds abuseipdb,virustotal")
    
    console.print("[yellow]→ Returns (without API keys shows empty)[/yellow]")
    console.print("[dim]Configure with VIRUSTOTAL_API_KEY for real data[/dim]\n")


def demo_full_workflow():
    """Demo complete alert triage."""
    demo_section("6. COMPLETE TRIAGE WORKFLOW")
    
    step("1. REVIEW - Alert arrives")
    console.print("[yellow]Alert:[/yellow] [Critical] Suspicious PowerShell Execution on server01")
    console.print("[yellow]Rule:[/yellow] T1059 - PowerShell")
    
    step("2. VALIDATE - Check for false positives")
    console.print("[yellow]User:[/yellow] admin | [yellow]Host:[/yellow] server01")
    console.print("[gray]Check: Known baseline? NO | Expected? NO[/gray]")
    
    step("3. ENRICH - Gather context")
    console.print("[yellow]→ Running enrichment...[/yellow]")
    
    table = Table(title="Enrichment Results")
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="white")
    table.add_row("User Risk", "HIGH - Domain Admins group")
    table.add_row("Process", "powershell.exe -enc SQBb...")
    table.add_row("Parent", "explorer.exe")
    console.print(table)
    
    step("4. DOCUMENT - Create ticket")
    console.print("[green]✓ Created: SOC-1002[/green]")
    console.print("[cyan]Summary:[/cyan] [P1] Suspicious PowerShell Execution")
    
    step("5. ESCALATE - Escalate to Tier 2")
    console.print("[red]✓ Escalated - Confirmed malware indicators[/red]")


def main():
    """Run complete demo."""
    console.clear()
    
    console.print(Panel.fit(
        "[bold cyan]AlertFlow Demo[/bold cyan]\n"
        "[dim]SOC Alert Triage Workflow[/dim]",
        border_style="cyan"
    ))
    
    console.print("[yellow]Starting demo in 3 seconds...[/yellow]")
    time.sleep(2)
    
    demo_enrichment()
    time.sleep(0.5)
    
    demo_siem()
    time.sleep(0.5)
    
    demo_ticket()
    time.sleep(0.5)
    
    demo_ioc_extraction()
    time.sleep(0.5)
    
    demo_check()
    time.sleep(0.5)
    
    demo_full_workflow()
    
    console.print("\n[bold green]Demo complete![/bold green]")
    console.print("[dim]Run 'python scripts/demo.py' to replay this demo[/dim]")
    console.print("[cyan]Use 'asciinema rec' to record for portfolio[/cyan]")


if __name__ == "__main__":
    main()