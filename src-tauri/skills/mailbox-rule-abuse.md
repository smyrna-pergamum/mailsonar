---
name: mailbox-rule-abuse
description: Investigate malicious inbox rules and mail forwarding (New-InboxRule, Set-InboxRule, forward-to, external forwarding). Use when the task mentions rules, forwarding, yönlendirme or kural.
triggers: inbox rule, inboxrule, rule, kural, forward, forwarding, yönlendirme, weiterleitung, redirect, delete rule
preload:
  - search_events {"query": "rule", "limit": 40}
  - search_events {"query": "forward", "limit": 40}
---
# Mailbox rule abuse playbook

Attackers create rules to hide replies (move to RSS/Archive, mark as read, delete) or to forward copies externally.

## Steps
1. `update_plan`.
2. List every rule/forward record from the preloaded results. For each, `evidence_inspect` to read rule name, action and destination.
3. Classify each rule: external forwarding / hiding / deleting / benign-looking.
4. For each account that created a rule: `filter_events` `field: "sender"` to find the login that preceded it (same IP? new IP?).
5. Check whether forwarded destinations appear as recipients elsewhere (`filter_events` `field: "recipient"`).

## Answer format
- Table: account | rule action | destination | created at | evidence ID | preceding login IP
- Which rules look malicious and why
- Remediation: remove rules, disable external auto-forwarding, review sent items
