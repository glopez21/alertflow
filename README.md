# AlertFlow

A standardized alert triage workflow for SOC Tier 1 analysts. AlertFlow provides structured runbooks, templates, and enrichment tools for consistent alert handling and clean ticket handoffs.

## Features

- **Tier 1 Workflow** - Structured REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE process
- **Runbook System** - Detailed step-by-step procedures for each triage phase
- **Standardized Templates** - Complete ticket format with all required fields
- **Enrichment Tools** - IP investigation CLI for context gathering
- **Escalation Criteria** - Clear severity matrix and escalation guidelines

## Quick Start

```bash
# IP enrichment
python enrichment/ip_lookup.py 192.168.1.1

# Use ticket template from templates/ticket_template.md
# Reference runbooks/tier1_alert_flow.md for procedures
```

## Workflow Phases

| Phase | Target Time | Key Actions |
|-------|------------|-------------|
| Review | 2 min | Confirm alert, check severity |
| Validate | 5 min | False positive check |
| Enrich | 10 min | Gather context (IP, user, asset) |
| Document | 5 min | Complete ticket |
| **Total** | **~22 min** | Per alert |

## Escalation Criteria

| Severity | Trigger |
|----------|----------|
| **P1 - Immediate** | Active compromise, data exfil, malware, lateral movement |
| **P2 - Urgent** | Failed login burst, unauthorized account, privilege escalation |
| **P3 - Standard** | Single failed login, minor policy violation |
| **Close** | Confirmed FP, known maintenance, user authorized |

## Project Structure

```
alertflow/
├── runbooks/           # Detailed procedures
├── templates/          # Ticket templates
├── checklists/        # Quick reference
└── enrichment/       # Investigation tools
```

## Components

- **tier1_alert_flow.md** - Complete runbook with commands and checks
- **ticket_template.md** - Standardized ticket format
- **triage_checklist.md** - Quick reference checklist
- **ip_lookup.py** - IP enrichment CLI tool

## Usage in Operations

1. Use `templates/ticket_template.md` when creating new tickets
2. Follow procedures in `runbooks/tier1_alert_flow.md`
3. Reference checklists during triage
4. Use enrichment scripts for context
5. Apply escalation criteria when determining disposition