# AlertFlow

**Standardized alert triage workflow system for Tier 1 SOC operations**  - A complete toolkit for Tier 1 analysts.

AlertFlow is my standardized alert triage system.  I built AlertFlow to understand the structured approach required for consistent, efficient alert handling and to ensure I follow consistent handling procedures for every alert—never missing enrichment steps or skipping documentation. Every alert gets validated, enriched with available context, and properly closed with reasoning. . It implements the 5-phase triage workflow used in production SOCs—ensuring every alert gets proper validation, enrichment, and documentation.

**What it demonstrates:**
- **SOC workflow understanding** - I know the standard alert handling process (REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE)
- **Enrichment capability** - I can investigate IOCs using multiple sources (IP reputation, domain analysis, hash checking)
- **Documentation skills** - I understand the importance of timeline tracking and evidence preservation
- **False positive handling** - I know how to identify and properly close FP alerts with documentation

---

## For SOC Analysts

A production-ready alert handling system with:
- **5-Phase Workflow**: REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE
- **Enrichment Tools**: IP, domain, hash, user investigation
- **Runbooks**: Phishing, malware, ransomware procedures
- **Live Integration**: SIEM queries, ticketing, threat feeds


**Key Skills Demonstrated:**
- SOC workflow understanding
- CLI tool development (Python/Typer)
- API integration patterns
- Documentation for operations
- Realistic simulation of analyst tasks

---

## Quick Demo

```bash
cd projects/alertflow
uv sync

# Demo workflow (no setup needed)
uv run scripts/demo.py
```

---

## Features

### Enrichment Tools
- **IP Lookup**: Reverse DNS, GeoIP, private IP detection
- **Domain Lookup**: WHOIS, suspicious patterns, reputation
- **Hash Lookup**: MD5/SHA256 reputation check
- **User Lookup**: Account info, activity, risk scoring
- **IOC Extract**: Auto-extract IOCs from alert text

### Runbooks
- **Tier 1 Alert Flow** - General alert handling
- **Phishing Alert** - Email investigation
- **Malware Alert** - Detection response

### Live Integration
- **SIEM Connector**: Splunk/Elasticsearch queries
- **Ticketing**: Jira/ServiceNow integration
- **Threat Feeds**: VirusTotal, AbuseIPDB, AlienVault OTX

---

## Usage Examples

### Enrichment (Offline)
```bash
# IP investigation
uv run enrichment/ip_lookup.py 192.168.1.100

# Domain reputation
uv run enrichment/domain_lookup.py suspicious-domain.xyz

# Hash check
uv run enrichment/hash_lookup.py aadea647deadbeef...

# User context
uv run enrichment/user_lookup.py admin

# Auto-detect IOC type
uv run enrichment/all 192.168.1.1
```

### Live Integration
```bash
# Fetch recent SIEM alerts
uv run -m live siem --hours 1 --limit 10

# Check IOC against threat feeds
uv run -m live check 192.168.1.1 --feeds abuseipdb,virustotal

# Create ticket
uv run -m live ticket "Alert title" --priority critical
```

### Full Triage
```bash
# Example: triage an alert file
uv run -m live triage alert.json --ticket
```

---

## Workflow

```
┌───────────────────────────────────────────────────────────┐
│                    AlertFlow                              │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│   REVIEW    │   VALIDATE  │   ENRICH    │   DOCUMENT      │
│ 2 minutes   │   5 minutes │ 10 minutes  │   5 minutes     │
├─────────────┴─────────────┴─────────────┴─────────────────┤
│  - Confirm    - Check FP    - IP/Domain   - Timeline      │
│  - Severity   - Allowlist   - Hash/User   - IOCs          │
│  - Categorize - Baseline   - Threat Feeds- Evidence       │
└───────────────────────────────────────────────────────────┘
                          │
                    ┌─────┴────┐
                    │ ESCALATE │
                    │  Close   │
                    └──────────┘
```

---

## Escalation Criteria

| Severity | Definition | Example |
|----------|------------|---------|
| **P1** | Active compromise | Malware, lateral movement, data exfil |
| **P2** | Suspected compromise | Failed logins burst, privilege escalation |
| **P3** | Suspicious activity | Single failed login, policy violation |
| **Close** | False positive | Maintenance, authorized user |

---

## Project Structure

```
alertflow/
├── enrichment/         # Offline enrichment tools (6 scripts)
│   ├── ip_lookup.py
│   ├── domain_lookup.py
│   ├── hash_lookup.py
│   ├── user_lookup.py
│   ├── ioc_extract.py
│   └── __main__.py     # Unified CLI
├── live/              # Live integration (4 scripts)
│   ├── siem_collector.py
│   ├── ticket_creator.py
│   ├── feed_poller.py
│   └── __main__.py
├── runbooks/          # Alert handling procedures
│   ├── tier1_alert_flow.md
│   ├── tier2_phishing_alert.md
│   └── tier3_malware_alert.md
├── templates/         # Ticket templates
├── checklists/        # Quick references
├── scripts/
│   └── demo.py       # Demo workflow
└── docs/
    └── INTEGRATION.md  # ThreatPulse integration plan
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `typer` | CLI framework |
| `rich` | Terminal UI |
| `httpx` | HTTP client |
| `requests` | API calls |

---

Or run the automated demo:

```bash
uv run python scripts/demo.py
```

## Tech Stack

- **Python 3.11+**
- **Typer** - CLI
- **Rich** - Terminal UI
- **HTTPX** - API client
- **SQLite** option for persistence

---

## License

MIT
