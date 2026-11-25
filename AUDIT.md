# MailSonar — Audit Report

## Scope

This report records engineering issues found while building MailSonar V1.0 (the MailSonar/BEACON rebrand of Mail DFIR RC4), their remediation, and the gaps that remain. It is an engineering audit, not an independent forensic or security certification.

Last updated for the V1.0 working tree.

## Fixed in this release

### [FIXED / HIGH] Workflow engine did not compile

- **Affected:** `src-tauri/src/workflow.rs`
- **Issue:** A type error in the workflow report node blocked `cargo build` and every downstream test.
- **Remediation:** Corrected the expression and ran `cargo fmt --all`.
- **Verification:** `cargo fmt --all`, `cargo clippy --all-targets` and `cargo test` all exit 0.

### [FIXED / HIGH] calamine 0.26 incompatible with the current toolchain

- **Affected:** `src-tauri/Cargo.toml`, XLSX parser in `src-tauri/src/main.rs`
- **Remediation:** Updated to calamine 0.38 and rewrote the parse call for its API.
- **Verification:** XLSX parser tests and the full Rust suite pass; installers build.

### [FIXED / HIGH] Duplicate floating assistant risk during the BEACON integration

- **Affected:** `src/main.js`, `src/beacon/panel.js`
- **Issue:** A second assistant mount would have produced two floating launchers and two competing consent flows.
- **Remediation:** BEACON is the only floating assistant. It refuses to mount twice (`#beacon-root` guard). The HELM workspace is a normal tab and does not mount a floating panel. No LUMEN mount or LUMEN reference remains in `src/` or `tests/`.
- **Verification:** Browser preview shows exactly one `#beacon-root`, one `.beacon-launch`, and no LUMEN strings.

### [FIXED / MEDIUM] `cargo deny` had no policy and failed

- **Affected:** `src-tauri/deny.toml`, `src-tauri/Cargo.toml`
- **Remediation:** Added an explicit license allow-list, documented advisory exceptions (chrono, proc-macro-error, glib), denied unknown registries/git sources, denied OpenSSL duplicates, and set `publish = false` on the application crate.
- **Verification:** `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`.

### [FIXED / MEDIUM] Vite watcher crashed with EBUSY

- **Affected:** `vite.config.js`
- **Remediation:** The watcher ignores `src-tauri` and `dist`, so Rust build output no longer triggers a reload storm.

### [FIXED / MEDIUM] Documentation drift and broken links

- **Affected:** `README.md`, `AUDIT.md`, `ROADMAP.md`, `SECURITY-AUDIT.md`, `CHANGELOG.md`
- **Issue:** The previous documents still described Mail DFIR, 25 Node tests, 11 Rust tests, a non-compiling Rust source and missing reports.
- **Remediation:** Rewrote the affected documents, added the missing reports, and replaced unverified claims with measured results or explicit "not measured" statements.
- **Verification:** Every document linked from `README.md` exists.

### [FIXED / MEDIUM] Stale "main.rs cannot be rebuilt" note

- **Affected:** `AUDIT.md`
- **Issue:** An earlier note claimed the Rust source could not be rebuilt and that only an old binary worked. That was no longer true and contradicted the successful builds.
- **Remediation:** Removed the claim. The source builds, tests, lints and produces installers.

### [FIXED / LOW] Missing build provenance for the bundled engine

- **Affected:** `src-tauri/engine/ENGINE-VERSION.txt`
- **Remediation:** Recorded the upstream release, archive SHA-256, platform, included files, omitted tools and security properties. The provenance caveat is recorded below.

## Open and accepted issues

| # | Severity | Status | Issue |
|---|----------|--------|-------|
| 1 | HIGH | Accepted | The evidence vault is not encrypted and the hash chain is not externally anchored. It detects accidental or local tampering, not a determined local attacker. |
| 2 | HIGH | Open | No independent forensic validation or accreditation has been performed. Detection rules are heuristics, not validated signatures. |
| 3 | HIGH | Open | Linux and macOS builds were not produced or tested in this environment. |
| 4 | MEDIUM | By design | The 1,000,000-event benchmark is unsupported: imports are capped at 20,000 records and 32 MiB per file. |
| 5 | MEDIUM | Open | No live cloud AI provider was contacted. Gateway behaviour is covered by mock HTTP servers and a local loopback engine only. |
| 6 | MEDIUM | Open | `pip-audit` reports two `diskcache 5.6.3` findings (PYSEC-2026-2447) in `integrations/requirements.txt`. The dependency is optional and not shipped in the desktop app. |
| 7 | MEDIUM | Open | No vendor-specific parsers or automatic vendor detection (Exchange, M365, Proofpoint, Mimecast, etc.). |
| 8 | MEDIUM | Open | The bundled engine archive was taken from a local build cache; its SHA-256 was not re-downloaded from GitHub in this session. Compare with upstream release notes before redistributing. |
| 9 | MEDIUM | Open | BEACON UI flows were verified in the Vite preview with the synthetic mock. The Tauri WebView2 surface was not driven by an automated UI test. |
| 10 | LOW | Open | The workflow editor uses a custom SVG canvas, not a typed-port React Flow-style editor. |
| 11 | LOW | Open | Multi-role autonomous investigation, vector/embedding search, live remote threat-intelligence enrichment and a plugin editor are unimplemented. |
| 12 | LOW | Accepted | HELM is a bounded single-agent loop. It does not provide independent multi-agent verification of its own conclusions. |
| 13 | LOW | Open | Documentation can drift from code between releases; the test suite does not assert documentation content. |

## Issue counts

| Severity | Open | Accepted / by design | Fixed in V1.0 |
|----------|------|----------------------|---------------|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 2 | 1 | 3 |
| MEDIUM | 5 | 1 | 4 |
| LOW | 3 | 1 | 1 |

## Verification summary

| Check | Result |
|-------|--------|
| `npm test` | 61 pass, 0 fail |
| `cargo fmt --all --check` | pass |
| `cargo clippy --all-targets` | pass, no warnings |
| `cargo test` | 35 pass, 0 fail, 2 ignored |
| Python `unittest` | 12 pass |
| `cargo audit` | 0 vulnerabilities, 3 documented warnings |
| `cargo deny check` | pass |
| `npm run build` | pass |
| `npm run tauri build` | pass; binary, MSI and NSIS produced |
| Browser preview | BEACON help, consent denial/approval and HELM mode exercised; no console errors |

Measured details are in `TEST-RESULTS.md`. Test data is listed in `DATASET-MANIFEST.md`.

## Notes on evidence

The vault stores original bytes and a SHA-256 digest, re-reads the file on preserve, and maintains a local hash-chained journal. Verification re-hashes stored bytes and checks the chain. These controls do **not** prove authenticity, prove who collected the data, or provide an immutable chain of custody. Treat exported cases and reports as analyst work product, not certified evidence.
