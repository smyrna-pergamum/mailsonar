# MailSonar — Test Results

Measured on Windows x64 in this working tree. Commands were run from the repository root unless noted. Results are reproduced verbatim from the local runs; timings vary by machine.

## Summary

| Suite | Command | Result |
|-------|---------|--------|
| Node frontend | `npm test` | **78 passed, 0 failed** |
| Rust | `cargo test` (in `src-tauri`) | **35 passed, 0 failed, 2 ignored** |
| Python integrations | `python -m unittest discover -s tests -p "test_*.py" -v` | **13 passed, 0 failed** |
| Rust formatting | `cargo fmt --all --check` | pass |
| Rust lint | `cargo clippy --all-targets` | pass, no warnings |
| Rust advisories | `cargo audit` | 0 vulnerabilities, 3 documented warnings |
| Rust policy | `cargo deny check` | advisories, bans, licenses, sources pass |
| Frontend build | `npm run build` | pass, 608 modules transformed |
| Desktop build | `npm run tauri build` | pass, exit 0, MSI + NSIS produced |

## V1.1 additions — status

- Analyst feedback memory, review panel, case-state validation, smart HELM task builder and local JSONL fine-tuning export added in `src/feedback.js`, `src/review-panel.js`, `src/case-state.js`, `src/rules-workbench.js` and `src/training.js`; new tests in `tests/learning.test.js`, `tests/workspace.test.js` and `tests/browser-smoke.html`.
- Time handling helpers in `src/event-time.js` reject timezone-less timestamps.
- PDF report generator (`src-tauri/src/pdf_report.py`) gained case analysis, severity bars, hourly timeline bars and relationship charts; canonical writer shared through `integrations/pdf_report.py`.
- PDF verification generated reports for English, German and Turkish: 5 pages each, all sections and charts present, MAILSONAR header present; no console errors.

## Node tests

`npm test` runs `node --test tests/*.test.js`.

```
tests 78
suites 0
pass 78
fail 0
cancelled 0
skipped 0
todo 0
```

Files: `advanced.test.js`, `analysis.test.js`, `assistant.test.js`, `beacon.test.js`, `investigation.test.js`, `learning.test.js`, `nightwire.test.js`, `privacy.test.js`, `workspace.test.js`.

Python: `test_pdf_report.py`, `test_logai_features.py`, `test_sigma_execute.py`, `test_threat_fetch.py`.

BEACON coverage (16 tests) includes:

- offline topic routing and unknown-topic fallback
- case-summary counts
- HELM help routing to the agent tab
- empty and over-limit selections rejected
- remote HTTP, URL credentials and missing endpoint rejected
- consent denial makes no request
- approved request reaches the host adapter
- selection snapshot is isolated from changes made during approval
- agent mode requires imported evidence
- agent mode rejects remote HTTP
- agent consent denial prevents execution
- approved agent task reaches the host adapter

## Rust tests

`cargo test` in `src-tauri`:

```
test result: ok. 35 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
```

Ignored tests:

1. `benchmark_large_import` — pre-existing performance benchmark, run explicitly in release mode.
2. `bundled_engine_serves_a_real_completion` — real inference through the production `spawn_engine` path; requires `MAILDFIR_TEST_GGUF`.

### Real inference (ignored test, run manually)

Environment: bundled llama.cpp b11934 CPU build, `qwen2.5-0.5b-instruct` GGUF.

```
engine ready: 1,610 ms
completion:    268 ms
content:       ENGINE-OK
usage:         36 prompt + 4 completion = 40 tokens
```

A separate standalone check of the slimmed engine directory returned `SLIM-OK` in 365 ms (42 tokens) with the health endpoint responding. These numbers describe one local run, not a benchmark.

## Python tests

```
Ran 12 tests in 0.557s
OK
```

Files: `test_logai_features.py`, `test_pdf_report.py`, `test_sigma_execute.py`, `test_threat_fetch.py`.

## Supply chain

`cargo audit`:

- 0 vulnerabilities.
- 3 warnings, all documented and ignored in `src-tauri/deny.toml`:
  - `RUSTSEC-2026-0543` chrono unmaintained
  - `RUSTSEC-2024-0370` proc-macro-error unmaintained
  - `RUSTSEC-2024-0429` glib unsoundness (Linux-only transitive dependency)

`cargo deny check`:

```
advisories ok, bans ok, licenses ok, sources ok
```

`pip-audit` (optional integrations): 2 findings for `diskcache 5.6.3` (`PYSEC-2026-2447`). Not fixed in this release.

## Frontend build

```
✓ 608 modules transformed.
dist/index.html                    0.84 kB │ gzip:   0.45 kB
dist/assets/index-*.css           24.66 kB │ gzip:   5.61 kB
dist/assets/index-*.js           126.17 kB │ gzip:  40.35 kB
dist/assets/cytoscape-*.js       451.17 kB │ gzip: 144.50 kB
dist/assets/echarts-*.js         592.91 kB │ gzip: 202.41 kB
✓ built in 4.42s
```

The production bundle was checked for dev-only hooks (`__maildfirDev`, `__maildfirMock`); they are excluded.

## Desktop build

```
Finished `release` profile [optimized] target(s) in 43.17s
Built application at: src-tauri/target/release/mail-dfir.exe
MSI:  src-tauri/target/release/bundle/msi/MailSonar_1.0.0_x64_en-US.msi (24.66 MiB)
NSIS: src-tauri/target/release/bundle/nsis/MailSonar_1.0.0_x64-setup.exe (14.73 MiB)
TAURI_EXIT=0
```

Installer SHA-256:

```
MailSonar_1.0.0_x64_en-US.msi     0EFEA06F7A6A305963AFB1151556E829DA7CE93EEB0CCCF980716CD7593F7F80
MailSonar_1.0.0_x64-setup.exe     2E993E989E775FF88BE709B68A5403DA56C1D4EB71B323862DF982BA83FAA7B1
```

The built application was launched without a configured model. The process stayed running and its window title was `MailSonar | Investigation Workbench`.

An administrative MSI extraction (`msiexec /a`) confirmed the package installs to `PFiles\MailSonar\` with `mail-dfir.exe` and all 26 bundled engine files, including `llama-server.exe`, the `ggml` DLLs and both license files. The MSI, NSIS installer and executable are unsigned (`NotSigned`).

The bundled engine is included as a Tauri resource (`engine/*`, 26 files, 45,675,616 bytes).

## Interface verification

Verified in the Vite preview at `http://127.0.0.1:1420/` using the DEV-only synthetic mock:

- Document title: `MailSonar | Investigation Workbench`.
- Sidebar brand: `MAILSONAR` / `DETECT THREATS BENEATH THE SURFACE`, emblem `/mailsonar-mark.svg`.
- Exactly one `#beacon-root` and one `.beacon-launch`.
- Nav labels include `HELM agent`; HELM tabs read `Agent console`, `Model center`, `WAYPOINT`, `Tool registry`, `Sessions`, `Execution monitor`.
- BEACON offline guide returned `20 events, 18 findings, 1 evidence files`.
- Selected-evidence mode with consent denied: 0 `ask_ai` calls.
- Selected-evidence mode with consent approved: 1 `ask_ai` call, synthetic preview text displayed as unverified.
- HELM agent mode returned the synthetic preview outcome with iteration/tool-call counts.
- No console errors during these flows.
- Layout checked at the minimum window width: brand text fits without overflow; BEACON panel does not overlap the launcher.

## Not tested

- Automated UI interaction inside the Tauri WebView2 window. The same bundle was verified in the Vite preview; the Rust side is covered by unit tests.
- Live cloud or self-hosted remote AI providers. Only mock HTTP servers and a loopback llama.cpp engine were used.
- Linux and macOS builds.
- The 1,000,000-event benchmark. The import cap is 20,000 records by design.
- Live MISP/TAXII servers.
- Installer installation, upgrade and uninstall on a clean Windows machine.
