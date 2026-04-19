# Phishing Alert Handling Runbook

## Alert Type: Phishing Email / Credential Harvesting

## Severity: P1-P2 (Urgent)

---

## Phase 1: Review (2 minutes)

### Confirm Alert Details

- [ ] Source: Email gateway / Sandbox / User report
- [ ] Email metadata: Sender, subject, timestamp
- [ ] Attachments: Count, file types
- [ ] Links: Count, destinations

### Initial Classification

- [ ] **Phishing** - Credential harvesting attempt
- [ ] **Spear phishing** - Targeted, known user
- [ ] **Whaling** - Executive targeting
- [ ] ** BEC** - Business email compromise
- [ ] **False positive** - Marketing email, etc.

---

## Phase 2: Validate (5 minutes)

### Email Analysis Checklist

- [ ] Check sender domain reputation
- [ ] Verify sender via SPF/DKIM/DMARC
- [ ] Check against known phishing DB
- [ ] Verify links (don't click!)
- [ ] Check attachments in sandbox
- [ ] Search for other recipients

### Commands

```bash
# Check sender domain
python -m enrichment.domain_lookup <sender_domain>

# Check for other recipients in SIEM
index=email sender="<sender_email>"
count distinct recipient

# Check link destinations
# DO NOT CLICK - use: https://urlscan.io/
curl -I <suspicious_link>  # Check headers only
```

---

## Phase 3: Enrich (10 minutes)

### Domain Enrichment

```bash
python -m enrichment.domain_lookup malicious-domain.com
```

### Link Analysis

- [ ] URLScan results
- [ ] Hybrid Analysis results
- [ ] AbuseIPDB listing

### Hash Enrichment

```bash
python -m enrichment.hash_lookup <attachment_hash>
```

### User Context

```bash
python -m enrichment.user_lookup <target_user>
```

---

## Phase 4: Document (5 minutes)

### Required Ticket Fields

- **Email Headers**: Full headers
- **Sender**: Email, domain, IP
- **Subject**: Exact subject line
- **Links**: All URLs (categorized safe/suspicious/malicious)
- **Attachments**: Filenames, hashes, analysis
- **Recipients**: Count, list
- **Impact Assessment**: What data accessed?

### Evidence to Collect

- [ ] Screenshot of email
- [ ] Email headers (full)
- [ ] Link analysis (urlscan.io screenshots)
- [ ] Attachment analysis
- [ ] SIEM search results

---

## Phase 5: Response Actions

### Immediate Actions Needed

- [ ] **Block sender** in email gateway
- [ ] **Remove** from all mailboxes
- [ ] **Block URLs** in proxy
- [ ] **Quarantine** attachments
- [ ] **Reset credentials** if clicked

### Escalation Criteria

**P1 - ESCALATE IMMEDIATELY:**
- [ ] Credentials used / compromised
- [ ] Malware delivered
- [ ] Multiple users clicked
- [ ] Executive targeted
- [ ] Data exfiltration observed

**P2 - ESCALATE WITHIN 1 HOUR:**
- [ ] External recipients found
- [ ] Active campaign suspected
- [ ] Needs threat hunting

**P3 - MONITOR:**
- [ ] No user interaction
- [ ] Blocked at gateway
- [ ] Isolated attempt

### Close When

- [ ] Confirmed Marketing/Internal email
- [ ] User confirmed safe (not clicked)
- [ ] Test email from authorized sender
- [ ] Duplicate alert

---

## Common IOCs for Phishing

| Type | Example | Action |
|------|---------|--------|
| Sender Domain | @malicious-phishing.xyz | Block domain |
| Attachment Hash | abc123... | Quarantine hash |
| Malicious URL | hxxp://evil.com/payload.exe | Block URL |
| C2 Domain | update-service-malware.net | Block domain |
| Dropper URL | https://bit.ly/xxxxx | Block shortener |

---

## Response Playbook

```
## Response Actions Taken
- [ ] Sender blocked in M365/Google
- [ ] URLs added to block list
- [ ] Hashes added to YARA/Snort
- [ ] User credentials reset
- [ ] User device quarantined
- [ ] Ticket created in JIRA/ServiceNow
```