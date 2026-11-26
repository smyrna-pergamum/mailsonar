---
name: account-takeover
description: Investigate account takeover - brute force, password spray, impossible travel, MFA bypass, suspicious OAuth consent. Use when the task mentions logins, hesap ele geçirme, brute force, password spray or compromised account.
triggers: account takeover, ato, takeover, ele geçirme, compromised, brute force, kaba kuvvet, password spray, login, giriş, oturum, mfa, oauth, impossible travel, anmeldung
preload:
  - search_events {"query": "login", "limit": 60}
  - aggregate_events {"field": "ip", "limit": 15}
  - findings {"limit": 25}
---
# Account takeover playbook

## Pattern library
- **Brute force**: many failures for one account from one IP in minutes (COR-001, MAIL-007).
- **Password spray**: one IP, many accounts, few attempts each (MAIL-008).
- **Success after failures**: the critical signal - a successful login following a failure burst.
- **Impossible travel / new location** (MAIL-017).
- **Post-compromise**: new inbox rule, forwarding, OAuth consent, outbound spike from the account.

## Steps
1. `update_plan`.
2. From preloaded login records, group by IP and by account. Identify bursts.
3. For each suspicious IP (max 3): `filter_events` `field: "ip"` and check whether the same IP also has a success.
4. For each suspected compromised account (max 3): `filter_events` `field: "sender"` and look at activity AFTER the first successful suspicious login. Use `timeline` for ordering.
5. Optionally `load_skill mailbox-rule-abuse` if rules or forwards appear.

## Answer format
- Timeline of the attack (timestamp - action - evidence ID)
- Accounts: likely compromised / targeted only / unclear
- Attacker infrastructure (IPs), IOC matches
- Containment: revoke sessions, reset password, enforce MFA, remove rules, block IPs
- Gaps (sign-in logs from IdP missing, timezone ambiguity, etc.)
