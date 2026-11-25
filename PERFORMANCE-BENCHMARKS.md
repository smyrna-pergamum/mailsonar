# MailSonar — Performance and Limits

## Purpose

This document records hard limits and the performance numbers actually observed. It deliberately does **not** extrapolate throughput or claim a 1,000,000-event capability.

## Hard limits

| Limit | Value | Source |
|-------|-------|--------|
| Input file size | 32 MiB | `MAX_BYTES` |
| Records per import | 20,000 | `MAX_ROWS` |
| Expanded archive budget | 96 MiB (`MAX_BYTES * 3`) | `import_file` |
| Single record (MSG property) | 64 KiB | `MAX_RECORD` |
| Archive nesting | 3 levels (depth 0–2) | `parse` |
| Archive members | 128 | `parse` |
| AI records per request | 1–25 | `AI_MAX_EVIDENCE` |
| AI question (backend) | 64,000 characters | `AI_MAX_QUESTION` |
| AI question (frontend) | 16,000 characters | `privacy.js` |
| AI context | 100,000 bytes | `AI_MAX_CONTEXT` |
| AI response | 2 MiB | `AI_MAX_RESPONSE` |
| AI timeout | 120 s | `ask_ai` |
| AI attempts | 3 | `AI_ATTEMPTS` |
| Agent iterations | 12 | `agent.rs` |
| Agent tool calls | 24 total, 6 per turn | `agent.rs` |
| Agent tool result | 12,000 characters | `agent.rs` |
| Agent response | 2 MiB | `agent.rs` |
| Workflow nodes | 32 | `workflow.rs` |
| Workflow document | 512 KiB | `workflow.rs` |
| Workflow trace steps | 80 | `workflow.rs` |
| Graph events | 2,000 | relationship graph |

## Why 1,000,000 events is unsupported

The import path caps a single file at 32 MiB and a session at 20,000 records. A 1,000,000-event import is rejected by design, not merely slow. Any benchmark claiming 1M events would require raising those caps and reworking memory use, storage and the UI. That work has not been done.

## Measured timings

Single runs on the development machine. These are observations, not guarantees.

| Operation | Observed |
|-----------|----------|
| Frontend production build | 4.42 s, 608 modules |
| Rust release compile (incremental) | 43.17 s |
| Rust debug test suite | 0.33 s |
| Python unit suite (12 tests) | 0.557 s |
| Node test suite (61 tests) | ~0.2 s |
| Bundled engine ready | 1,610 ms |
| First local completion (4 tokens) | 268 ms |
| Standalone engine smoke | 365 ms (42 tokens) |

## Bundle sizes

| Artifact | Size |
|----------|------|
| Main frontend JS | 126.17 kB (40.35 kB gzip) |
| Main CSS | 24.66 kB (5.61 kB gzip) |
| Cytoscape chunk | 451.17 kB (144.50 kB gzip) |
| ECharts chunk | 592.91 kB (202.41 kB gzip) |
| Windows MSI | 24.66 MiB |
| Windows NSIS installer | 14.73 MiB |
| Bundled engine | 45,675,616 bytes, 26 files |

## Not measured

- Import throughput for 1k, 10k or 20k records.
- Peak memory per import or per graph size.
- Detection and correlation time on realistic corpora.
- Report generation time for large cases.
- Vault verification time as the journal grows.
- Sustained AI request throughput or provider rate-limit behaviour.
- UI frame timing with the maximum graph.

## How to measure next

1. Generate synthetic CSV/JSONL fixtures at 1k, 5k, 10k and 20k records.
2. Record wall time, peak RSS and record count for import, detection, correlation and report generation.
3. Record graph render time at 500, 1,000 and 2,000 events.
4. Run each measurement at least five times and report median and spread.
5. Record hardware, OS build, Rust/Node versions and input hashes.
6. Publish failures and limit errors, not only successful runs.

Until then, treat the numbers above as smoke-test observations.
