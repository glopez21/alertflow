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

## Future Improvements

- [ ] Domain enrichment script
- [ ] User context lookup script
- [ ] Hash reputation lookup
- [ ] Automated IOC extraction
- [ ] Integration with MISP/STIX