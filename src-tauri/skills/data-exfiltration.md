---
name: data-exfiltration
description: Investigate possible data exfiltration over mail - bulk export, high outbound volume, mail to personal or unknown external recipients. Use when the task mentions exfiltration, sızıntı, data leak, bulk export or outbound spike.
triggers: exfiltration, exfil, sızıntı, sızdırma, leak, data loss, bulk export, outbound, dışarı, external recipient, datenabfluss
preload:
  - aggregate_events {"field": "recipient", "limit": 20}
  - aggregate_events {"field": "sender", "limit": 20}
  - search_events {"query": "export", "limit": 30}
---
# Data exfiltration playbook

## Steps
1. `update_plan`.
2. From preloaded aggregates, find senders with unusually high volume and recipients that are external/personal.
3. For the top 3 senders: `filter_events` `field: "sender"` and look at time clustering (COR-002 = 50 sends in 5 minutes).
4. `evidence_inspect` records mentioning export, attachment size or archive.
5. Check whether the activity followed an account takeover signal (new IP login just before).

## Answer format
- Who sent what volume to whom, and when (evidence IDs)
- Business-justified vs suspicious
- Data at risk (only what logs show - do not guess content)
- Next steps: DLP review, mailbox audit export, interview data owner
