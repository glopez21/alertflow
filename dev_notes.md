# AlertFlow - Development Notes

## Project Overview

- **Project Name**: AlertFlow
- **Type**: Documentation and runbook system
- **Purpose**: Tier 1 alert handling workflow for consistent SOC operations
- **Format**: Markdown documentation + Python enrichment scripts

## Architecture

### Directory Structure

```
alertflow/
├── README.md              # Quick reference
├── runbooks/
│   └── tier1_alert_flow.md  # Detailed runbook
├── enrichment/
│   └── ip_lookup.py      # IP enrichment CLI
├── templates/
│   └── ticket_template.md  # Ticket documentation
├── checklists/
│   └── triage_checklist.md  # Quick reference
└── .venv/               # Python environment (uv)
```

### Components

1. **Runbooks** - Step-by-step procedures for alert handling
2. **Templates** - Standardized ticket format
3. **Checklists** - Quick reference checklists
4. **Enrichment Scripts** - Python tools for investigation

## Development History

### Initial Build
- Created "Alert Triage Playbook" for SOC Tier 1 operations
- Structured around REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE flow
- Added basic IP enrichment script

### Key Decisions
- Markdown format for easy SIEM integration
- Ticket template includes all required fields for clean handoffs
- Clear escalation criteria with severity matrix
- Common false positive reference table

## Dependencies

```
rich>=13.0
```

Managed via `uv` - see `pyproject.toml` and `uv.lock`

## Usage

### IP Enrichment
```bash
.venv/bin/python enrichment/ip_lookup.py 192.168.1.1
```

### Workflow Integration
- Import markdown files into ticketing system
- Use ticket_template.md as base for new tickets
- Reference checklists during triage

## Extending

### Adding Enrichment Scripts
1. Create script in `enrichment/`
2. Make CLI-friendly with argparse
3. Output JSON for easy integration

### Adding Runbooks
1. Add markdown file to `runbooks/`
2. Follow tier1_alert_flow.md structure
3. Include specific commands and checks

## Future Improvements ✅ EXPANDED (v0.2.0)

- [x] **Domain enrichment script** - `enrichment/domain_lookup.py`
  - DNS record lookup
  - WHOIS (simulated)
  - Reputation check
  - Suspicious pattern detection (DGA, long random subdomains)
- [x] **User context lookup script** - `enrichment/user_lookup.py`
  - Account info (type, department, enabled)
  - Recent activity (logons, failed logons)
  - Group membership
  - Risk score calculation
- [x] **Hash reputation lookup** - `enrichment/hash_lookup.py`
  - MD5/SHA1/SHA256 detection
  - Known malicious/benign database
  - VirusTotal simulation
  - File info
- [x] **Automated IOC extraction** - `enrichment/ioc_extract.py`
  - IP/Domain/Hash/URL/Email/FilePath extraction
  - Regex patterns for common IOCs
- [x] **Unified enrichment CLI** - `enrichment/__main__.py`
  - `enrich ip <target>`
  - `enrich domain <target>`
  - `enrich hash <target>`
  - `enrich user <target>`
  - `enrich all <auto-detect>`
- [x] **Additional Runbooks**
  - `runbooks/tier2_phishing_alert.md` - Phishing handling
  - `runbooks/tier3_malware_alert.md` - Malware/Ransomware

## Current Enrichment Scripts

| Script | Purpose |
|--------|---------|
| `ip_lookup.py` | IP enrichment (DNS, GeoIP, private check) |
| `domain_lookup.py` | Domain enrichment (WHOIS, reputation, DGA) |
| `hash_lookup.py` | Hash reputation (VT, known malware) |
| `user_lookup.py` | User context (activity, groups, risk) |
| `ioc_extract.py` | Auto-extract IOCs from text |
| `__main__.py` | Unified CLI (`python -m enrichment`) |

## Live Integration (v0.3.0) ✅ NEW

### Live Modules

| Module | Description |
|--------|-------------|
| `live/siem_collector.py` | Fetch alerts from Splunk/Elasticsearch |
| `live/ticket_creator.py` | Create tickets in Jira/ServiceNow |
| `live/feed_poller.py` | Poll VirusTotal, AbuseIPDB, AlienVault OTX |
| `live/__main__.py` | Live CLI (`python -m live`) |

### Live CLI Commands

```bash
# Fetch SIEM alerts
python -m live siem --hours 1 --limit 10

# Create ticket
python -m live ticket "Alert summary" --priority high

# Check IOC against threat feeds
python -m live check 192.168.1.100 --feeds virustotal,abuseipdb

# Full triage workflow
python -m live triage alert.json --ticket
```