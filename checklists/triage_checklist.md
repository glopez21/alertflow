# Alert Triage Checklist

## Quick Checklist

- [ ] Alert ID noted
- [ ] Severity assigned
- [ ] False positive check done
- [ ] IP/domain enrichment done
- [ ] User context gathered
- [ ] Asset context gathered
- [ ] Timeline documented
- [ ] IOCs extracted
- [ ] Evidence links saved
- [ ] Ticket completed
- [ ] Escalated/Closed with rationale

## Common False Positives

| Alert | Common FP Cause | Verification |
|-------|-----------------|---------------|
| Failed login | User typo | Check recent success |
| New process | Software update | Verify checksum |
| Outbound conn | Regular backup | Check schedule |
| Large upload | User upload to cloud | Verify with user |

## Escalation Quick Flags

**ALWAYS ESCALATE if:**
- [ ] User reports compromise
- [ ] Malware detected
- [ ] Data exfil detected
- [ ] Lateral movement
- [ ] Privilege escalation
- [ ] Unknown malware
- [ ] Ransomware indicators