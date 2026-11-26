---
name: bec-fraud
description: Investigate business email compromise - invoice/payment fraud, CEO or vendor impersonation, thread hijacking. Use when the task mentions BEC, invoice, fatura, payment, ödeme, wire transfer or impersonation.
triggers: bec, business email compromise, invoice, fatura, payment, ödeme, wire, havale, iban, ceo, impersonation, taklit, vendor, tedarikçi, rechnung, zahlung
preload:
  - findings {"limit": 25}
  - search_events {"query": "payment", "limit": 30}
  - search_events {"query": "invoice", "limit": 30}
---
# BEC fraud playbook

## Typical chain
1. Access: phishing or account takeover of an internal or vendor mailbox.
2. Recon: reading threads about invoices.
3. Concealment: inbox rule hiding replies.
4. Fraud: a reply in an existing thread or a look-alike domain asking to change bank details.

## Steps
1. `update_plan`.
2. Identify payment/invoice-themed messages and their senders from preloaded data; `evidence_inspect` them.
3. Check whether the sender is internal (compromised) or a look-alike external domain.
4. Look for concealment: `load_skill mailbox-rule-abuse` if rules exist.
5. Check preceding logins of the sending account (`filter_events` `field: "sender"`).

## Answer format
- Fraud attempt(s): who asked whom for what, when, evidence IDs
- Compromise path (if visible)
- Financial risk: which recipients may act on it
- Immediate actions: call-back verification with vendor, hold payments, reset accounts
