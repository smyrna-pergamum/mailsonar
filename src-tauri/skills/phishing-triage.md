---
name: phishing-triage
description: Investigate phishing, spoofing and credential-harvest mail. Use when the task mentions phishing, oltalama, spoof, malicious link, SPF/DKIM/DMARC failure or a suspicious sender.
triggers: phishing, phish, oltalama, spoof, spoofing, sahte, dmarc, dkim, spf, credential harvest, malicious link, zararlı link, link, sender
preload:
  - findings {"severity": "high", "limit": 25}
  - search_events {"query": "fail", "limit": 40}
  - aggregate_events {"field": "sender", "limit": 15}
---
# Phishing triage playbook

## Questions to answer
1. Which sender(s) delivered the suspicious mail, and from which IPs?
2. How many recipients received it? (blast radius)
3. Did authentication fail (SPF/DKIM/DMARC) or does the display name mismatch?
4. Did any recipient interact afterwards: a login from a new IP, an inbox rule, a forward, a reply?

## Steps
1. `update_plan` with the four questions above.
2. From the preloaded findings, take phishing/spoofing rules (MAIL-011..014, MAIL-019) and `evidence_inspect` one record each.
3. `filter_events` with `field: "sender"` on the suspicious sender to list every delivery. Count distinct recipients.
4. For each recipient (max 5), `filter_events` with `field: "recipient"` or `"sender"` and look for later `login`, `new-inboxrule`, `forward` actions. Use `timeline` if ordering matters.
5. `ioc_matches` to see whether sender domain or IPs match loaded threat intel.

## Answer format
- Campaign summary: sender, first/last seen, number of recipients
- Authentication evidence (which checks failed, evidence IDs)
- Recipients with follow-up activity (highest risk first)
- Containment suggestions: block sender/domain, purge messages, reset credentials of users who interacted
- What cannot be concluded (e.g. no URL click telemetry in mail logs)
