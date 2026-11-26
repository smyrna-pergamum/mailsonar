---
name: triage
description: First-look triage of a whole mail case. Use when the task is general ("what happened?", "summarize", "özetle", "analiz et") or no other skill fits.
triggers: triage, summary, summarize, overview, what happened, özet, özetle, analiz, genel, zusammenfassung, überblick
preload:
  - event_stats
  - severity_summary
  - findings {"limit": 25}
  - aggregate_events {"field": "action", "limit": 20}
---
# Case triage playbook

Goal: in a few tool calls, tell the analyst what is most likely going on and what to look at next.

## Plan
1. Call `update_plan` with 3-5 short steps before you start.
2. Read the preloaded `event_stats`, `severity_summary` and `findings` (already in context). Do not call them again.
3. Pick the 1-3 strongest findings (highest severity, most evidence). For each, call `evidence_inspect` on one or two of its evidence IDs.
4. Look for links between those findings: `filter_events` on the same sender or IP, `trace_email` on the message_id.
5. If a specialised pattern appears, call `load_skill` and follow it:
   - phishing, spoofing, SPF/DKIM/DMARC failures -> `phishing-triage`
   - failed logins, password spray, impossible travel, MFA/OAuth -> `account-takeover`
   - inbox rules, forwarding -> `mailbox-rule-abuse`
   - invoice, payment, CEO impersonation -> `bec-fraud`
   - bulk export, large outbound volume -> `data-exfiltration`

## Answer format
- **Summary** (2-3 sentences)
- **Key findings** - each with severity and exact evidence IDs
- **Entities involved** - accounts, IPs, message IDs (aliases for cloud providers)
- **Benign explanations** worth ruling out
- **Missing data**
- **Next steps** (max 5, concrete)

Never present a finding as a confirmed incident. Rule hits are leads.
