# Tier 1 Alert Handling Runbook

## Phase 1: Review (2 minutes)

1. **Confirm alert details**
   - Read alert summary and triggering rule
   - Note alert ID and timestamp
   - Identify affected asset(s)

2. **Check severity**
   - Critical: Active attack in progress
   - High: Likely compromise indicators
   - Medium: Suspicious, needs investigation
   - Low: Anomalous, may be benign

3. **Initial classification**
   - Known good (expected activity)
   - Suspected false positive
   - Needs investigation

## Phase 2: Validate (5 minutes)

### False Positive Checks

- [ ] Is this expected activity for the user/asset?
- [ ] Is there recent maintenance or changes?
- [ ] Is this a known noisy system?
- [ ] Check allowlists/denylists
- [ ] Verify against baseline behavior

### Validation Commands

```bash
# Check user recent activity
grep <username> /var/log/auth.log | tail -20

# Check asset baseline
aws ec2 describe-instances --instance-ids <id>

# Check alert rules
grep -r "<rule>" /etc/suricata/rules/
```

## Phase 3: Enrich (10 minutes)

### IP/Domain Enrichment

- [ ] IP reputation lookup (AbuseIPDB, VT)
- [ ] Domain age and registration
- [ ] GeoIP location
- [ ] ASN information

### User/Device Context

- [ ] User account details (department, manager)
- [ ] Last known good login location
- [ ] Device compliance status
- [ ] Recent ticket history

### Evidence Collection

- [ ] Screenshot alert details
- [ ] Export relevant logs
- [ ] Note relevant IOCs
- [ ] Document timeline

## Phase 4: Document (5 minutes)

### Required Ticket Fields

- **Timeline**: Chronological event sequence
- **Affected Asset**: Hostname, IP, user
- **IOCs**: IPs, domains, hashes
- **Evidence**: Log paths, screenshots
- **Actions Taken**: What you did
- **Rationale**: Why you escalat/closed

## Phase 5: Escalate/Close

### Escalate When

- Confirmed threat indicator
- Severity P1-P2
- Needs Tier 2 expertise
- Legal/compliance implications

### Close When

- Confirmed false positive
- Benign explanation found
- User confirmed authorized
- Duplicate alert

### Escalation Template

```
## Alert Information
Alert ID: [ID]
Rule: [Rule Name]
Severity: [P1/P2/P3]

## Summary
[Brief description of alert]

## Investigation
[What you did and found]

## Evidence
[List evidence and IOCs]

## Recommendation
[Escalate / Close with rationale]
```