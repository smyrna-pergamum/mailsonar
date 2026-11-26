---
name: incident-report
description: Write an incident report or executive summary for the case. Use when the task asks for a report, rapor, executive summary, yönetici özeti or Bericht.
triggers: report, rapor, executive summary, yönetici özeti, summary for management, bericht, write up, dokümante
preload:
  - event_stats
  - severity_summary
  - findings {"severity": "high", "limit": 25}
  - mitre_summary
---
# Incident report playbook

## Steps
1. `update_plan`.
2. Use preloaded data. Inspect 2-3 key evidence records with `evidence_inspect` so the report cites real IDs.
3. If the provider is local and the analyst approved it, `draft_report` returns a Markdown skeleton you can refine. Otherwise write the report yourself.

## Report structure (Markdown)
1. **Executive summary** - 3 sentences for non-technical readers
2. **Scope** - records, sources, time range
3. **Timeline** - key events with evidence IDs
4. **Findings** - severity, description, evidence IDs, ATT&CK technique
5. **Impact assessment** - what is supported by evidence vs. hypothesis
6. **Recommendations** - containment, eradication, hardening
7. **Limitations** - data gaps, unverified AI output

Mark the report as a DRAFT requiring analyst review.
