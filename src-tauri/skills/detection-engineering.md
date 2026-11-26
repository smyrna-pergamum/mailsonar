---
name: detection-engineering
description: Write and test MailSonar detection rules from a plain-language description. Use when the task asks to create, write, improve or tune a rule (kural yaz, tespit kuralı, detection rule, Regel).
triggers: rule, kural, detection rule, tespit kuralı, kural yaz, write a rule, create rule, sigma, regel, detect
preload:
  - aggregate_events {"field": "action", "limit": 30}
  - aggregate_events {"field": "source", "limit": 10}
  - list_events {"limit": 8}
---
# Detection engineering playbook

You write **MailSonar custom rules**. A rule is JSON:

```json
{"id": "CUSTOM-XYZ-001", "field": "action", "contains": "inboxrule", "severity": "high", "description": "Mailbox rule created; verify authorization."}
```

- `field`: one of `sender`, `recipient`, `ip`, `action`, `message_id`, `source`, `timestamp`
- `contains`: case-insensitive substring (no regex, no wildcards)
- `severity`: `low`, `medium` or `high`
- `id`: unique, uppercase, starts with `CUSTOM-`

## Steps
1. `update_plan`: understand intent -> pick field and value -> test -> refine -> answer.
2. Use the preloaded `action` and `source` distributions to choose real values that exist in this case. Prefer the most specific substring that still matches the intended behaviour.
3. Call `test_rule` with your candidate. It returns the match count and sample matches.
4. If 0 matches: try a different substring or field. If it matches most of the case (> 50 %), make it more specific. Max 4 test iterations.
5. You may propose up to 5 rules when the intent covers several behaviours.

## Answer format
End your answer with exactly one fenced block:

```json
[ { "id": "...", "field": "...", "contains": "...", "severity": "...", "description": "..." } ]
```

Before the block, explain in 2-4 lines what each rule detects, its match count from `test_rule`, and likely false positives.
