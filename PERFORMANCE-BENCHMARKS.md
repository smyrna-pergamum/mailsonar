# MailSonar — Performance and Limits

## Purpose

This document records hard limits and the performance numbers actually observed. It reports what was measured and does not extrapolate beyond it.

## Hard limits

| Limit | Value | Source |
|-------|-------|--------|
| In-memory workspace, per file | 64 MiB | `MAX_BYTES` |
| In-memory workspace, records | 100,000 | `MAX_ROWS`, `case-state.js` |
| Large investigation, records | not capped by design (tested to 1,000,000) | `inv_ingest.rs` |
| Large investigation batch | 2,000–20,000 (adaptive to free RAM) | `adaptive_batch_size` |
| Large investigation, non-streamable file (EML, JSON array, EVTX, XLSX, XML) | 256 MiB | `IN_MEMORY_LIMIT` |
| Streamed line / MBOX message | 4 MiB / 32 MiB | `MAX_LINE`, `MAX_MBOX_MESSAGE` |
| Expanded archive budget (workspace) | 192 MiB (`MAX_BYTES * 3`) | `import_file` |
| Single record (MSG property) | 64 KiB | `MAX_RECORD` |
| Archive nesting | 3 levels (depth 0–2) | `parse` |
| Archive members | 128 | `parse` |
| AI records per request | 1–25 | `AI_MAX_EVIDENCE` |
| AI question (backend) | 64,000 characters | `AI_MAX_QUESTION` |
| AI context | 100,000 bytes | `AI_MAX_CONTEXT` |
| AI response | 2 MiB | `AI_MAX_RESPONSE` |
| Agent iterations | 12 | `agent.rs` |
| Agent tool calls | 24 total, 6 per turn | `agent.rs` |
| Agent tool result | min(12,000 chars, token budget × 4 / 8) | `agent.rs` |
| Agent request timeout | 900 s loopback, 180 s remote | `agent.rs` |
| Workflow nodes | 32 | `workflow.rs` |
| Relationship graph overview | 100–500 nodes (filter) | `graph-filters.js` |

## Large-investigation ingest benchmark (1k – 1M events)

Command: `cargo test --release --manifest-path src-tauri/Cargo.toml bench_ingest_scales -- --ignored --nocapture`
Machine: Windows 11 x64, 8 logical cores, 32 GB RAM, NVMe SSD, release build, single run (2026-11-26). Synthetic multi-source JSONL with 0.5 % exact duplicates and 0.1 % malformed lines; 4 workers; adaptive batch 20,000.

| Events | Stored (unique) | Dup. detected | Failed | Batches | Time | EPS | Batch p50/p95/p99 ms | Peak RSS MB | Correlation | DB MB | Integrity |
|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---|
| 1000 | 994 | 5 | 1 | 1 | 0.0 s | 20408 | 8/8/8 | 15 | 0.0 s | 1.4 | ✓ |
| 10000 | 9940 | 50 | 10 | 1 | 0.4 s | 22624 | 81/81/81 | 59 | 0.1 s | 13.6 | ✓ |
| 20000 | 19880 | 100 | 20 | 1 | 0.9 s | 23175 | 176/176/176 | 107 | 0.1 s | 27.1 | ✓ |
| 100000 | 99401 | 499 | 100 | 5 | 4.3 s | 23202 | 260/317/317 | 355 | 1.0 s | 136.2 | ✓ |
| 500000 | 497004 | 2495 | 501 | 25 | 35.9 s | 13945 | 246/382/387 | 1278 | 6.1 s | 686.5 | ✓ |
| 1000000 | 994007 | 4990 | 1003 | 50 | 105.0 s | 9524 | 188/323/350 | 1290 | 12.1 s | 1370.2 | ✓ |

**Integrity:** for every size the stored count equals the number of unique events, every injected duplicate was detected and every malformed line was recorded in the failures table with its record number. No event was lost.

**Crash recovery (1,000,000 events):** the import was stopped after the 25th committed batch. Reading stops immediately; batches already queued (at most 2 × workers per queue) are still committed, so 915,405 events were stored with checkpoint 920,923. Adding the same file again resumed at record 920,924, finished in 16.1 s and ended with 994,007 events: lossless, no duplicates.

**Observations (not guarantees):**
- Throughput is ~23,000 events/s up to 100k and falls to ~9,500 events/s at 1M because SQLite index maintenance (content-hash unique index plus six lookup indexes) grows with the table. The whole 1M file takes 105 s.
- Peak process memory plateaus at ~1.3 GB from 500k upward: bounded queues keep it flat regardless of input size. Lowering the batch size (the adaptive rule does this on machines with less free RAM) reduces it roughly proportionally.
- Cross-batch correlation over 1M events takes 12 s; an indexed lookup by sender takes ~15 ms.
- The store needs ~1.4 KB per event on disk (1M events → 1.37 GB) because raw records are kept for evidence and HELM.
- 5,000,000 events were not run in this measurement (`MAILDFIR_BENCH_SIZES=5000000` runs it).

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

- Repeated runs (the ingest table is a single run; report median and spread next time).
- Ingest of real vendor exports (the benchmark uses synthetic JSONL; CSV, MBOX and EVTX paths are tested for correctness only).
- 5,000,000-event stress run and multi-file imports at that scale.
- Peak memory per graph size.
- Report generation time for large cases.
- Vault verification time as the journal grows.
- Sustained AI request throughput or provider rate-limit behaviour.
- UI frame timing with the maximum graph.

## How to measure next

1. Repeat `bench_ingest_scales` five times per size and report median and spread; add `MAILDFIR_BENCH_SIZES=5000000`.
2. Record report generation and vault verification time for large cases.
3. Record graph render time at 500, 1,000 and 2,000 events.
4. Run each measurement at least five times and report median and spread.
5. Record hardware, OS build, Rust/Node versions and input hashes.
6. Publish failures and limit errors, not only successful runs.

Until then, treat the numbers above as smoke-test observations.
