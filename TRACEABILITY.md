# MailSonar — Traceability Matrix

Requirement-to-implementation map for the current working tree. "Verified by" lists automated tests or recorded manual checks. A mapped requirement is not automatically certified; see `AUDIT.md` and `SECURITY-AUDIT.md` for open gaps.

## Product requirements

| ID | Requirement | Implementation | Verified by |
|----|-------------|----------------|-------------|
| P-01 | Product name MailSonar, slogan "Detect threats beneath the surface" | `src/main.js` brand block, `index.html`, `src-tauri/tauri.conf.json`, `package.json` | `TEST-RESULTS.md` interface verification |
| P-02 | Assistant named BEACON | `src/beacon/*`, `src/main.js` mount | `tests/beacon.test.js`; browser preview |
| P-03 | Agent named HELM | `src/assistant.js`, `src-tauri/src/agent.rs` prompt | `tests/assistant.test.js`; Rust tests |
| P-04 | Workflow studio named WAYPOINT | `src/assistant.js`, `src/assistant-data.js` | `tests/assistant.test.js`; browser preview |
| P-05 | NIGHTWIRE theme | `src/nightwire.css`, `src/nightwire.js` | `tests/nightwire.test.js` |
| P-06 | Preserve identifier and storage paths | `tauri.conf.json` identifier; storage keys unchanged | Code review; migration note in `README.md` |
| P-07 | New emblem and icons | `public/mailsonar-mark.svg`, `src/beacon/beacon.svg`, `src-tauri/icons/*` | Browser preview; `npx tauri icon` exit 0 |
| P-08 | No duplicate floating assistant | `#beacon-root` guard in `src/beacon/panel.js`; no LUMEN mount | Browser preview: 1 root, 1 launcher |

## Functional requirements

| ID | Requirement | Implementation | Verified by |
|----|-------------|----------------|-------------|
| F-01 | Multi-format import | `src-tauri/src/main.rs` `parse` | Rust tests |
| F-02 | Import limits | `MAX_BYTES`, `MAX_ROWS`, `MAX_RECORD`, archive checks | Rust tests; `PERFORMANCE-BENCHMARKS.md` |
| F-03 | SHA-256 evidence preservation | `vault.rs`, `main.rs` `hash` | Rust tests |
| F-04 | Local hash-chained journal | `vault.rs` | Rust tests |
| F-05 | 20 detection rules | `main.rs` `RULES`, `src/analysis.js` | Node and Rust tests |
| F-06 | Correlation rules | `src/analysis.js` | `tests/analysis.test.js` |
| F-07 | Sigma subset | `src/advanced.js` | `tests/advanced.test.js` |
| F-08 | OCSF draft export | `src/investigation.js` `ocsfDraft` | `tests/investigation.test.js` |
| F-09 | HTML/JSON/CSV/PDF reports | `src/analysis.js`, `src-tauri/src/pdf.rs` | Node tests; `tests/test_pdf_report.py` |
| F-10 | Case export/import | `src/main.js`, `src-tauri/src/main.rs` | Rust tests |
| F-11 | Timeline and graph | `src/nightwire.js`, `src/investigation.js` | `tests/nightwire.test.js`, `tests/investigation.test.js` |
| F-12 | MITRE ATT&CK view | `src/nightwire.js` | `tests/nightwire.test.js` |
| F-13 | Threat-intelligence import | `src/main.js`, `integrations/threat_fetch.py` | Node tests; `tests/test_threat_fetch.py` |

## AI requirements

| ID | Requirement | Implementation | Verified by |
|----|-------------|----------------|-------------|
| A-01 | One backend AI gateway | `ask_ai` in `main.rs`; `src/privacy.js` | `tests/privacy.test.js`; Rust review |
| A-02 | OpenAI-compatible providers | `ask_ai`, provider presets | Node tests; mock servers |
| A-03 | Endpoint policy | `validate_endpoint`, `src/beacon/core.js` | `tests/beacon.test.js`; Rust review |
| A-04 | Minimization and aliasing | `src/investigation.js` `minimized`, `validate_ai_request` | `tests/privacy.test.js`; `tests/investigation.test.js` |
| A-05 | Consent before transfer | `src/main.js`, `src/beacon/panel.js` | `tests/beacon.test.js`; browser preview |
| A-06 | Session-only keys | `src/main.js`, `src/assistant.js` | Code review |
| A-07 | Bundled local engine | `src-tauri/engine`, `embedded_ai.rs` | Ignored real-inference test; `MODEL-BENCHMARKS.md` |
| A-08 | Engine path override | `MAILDFIR_LLAMA_SERVER`, discovery order | `embedded_ai.rs` review |
| A-09 | Model download policy | `allowed_download_host`, SHA-256 from HF LFS | `embedded_ai.rs` review |
| A-10 | HELM read-only tools | `agent.rs` tool registry | Rust tests |
| A-11 | HELM budgets and approvals | `agent.rs` validation | Rust tests |
| A-12 | BEACON agent mode | `src/beacon/core.js` `askAgent`; `src/main.js` | `tests/beacon.test.js`; browser preview |
| A-13 | Unverified output labelling | `src/beacon/panel.js`, `src/assistant.js` | Browser preview |
| A-14 | AI evaluation honesty | `src/nightwire.js`, `AI-EVALUATION.md` | `tests/nightwire.test.js` |

## Security requirements

| ID | Requirement | Implementation | Verified by |
|----|-------------|----------------|-------------|
| S-01 | No shell/filesystem/SQL plugin in webview | `tauri.conf.json`, `main.rs` builder | Code review |
| S-02 | CSP restricts network | `tauri.conf.json` | Code review |
| S-03 | No redirects or URL credentials | `ask_ai`, `src/beacon/core.js` | `tests/beacon.test.js`; Rust review |
| S-04 | Bounded AI request and response | `AI_MAX_*` constants | Rust tests |
| S-05 | Cloud withholds IOC values | `agent.rs` `compact_event`/`minimize_findings` | Rust tests |
| S-06 | HTML escaping | `src/analysis.js` | `tests/analysis.test.js` |
| S-07 | Parameterized SQL | `vault.rs` | Code review |
| S-08 | Dependency policy | `deny.toml`, lockfiles | `cargo audit`, `cargo deny`, `npm audit` |
| S-09 | Dev hooks excluded from production | `src/main.js`, Vite build | `dist` inspection |
| S-10 | Documented residual risks | `SECURITY-AUDIT.md` | Review |

## Release requirements

| ID | Requirement | Implementation | Verified by |
|----|-------------|----------------|-------------|
| R-01 | Node tests | `tests/*.test.js` | 61 pass |
| R-02 | Rust tests | `src-tauri/src/*` test modules | 35 pass, 2 ignored |
| R-03 | Python tests | `tests/test_*.py` | 12 pass |
| R-04 | Formatting and lint | `cargo fmt`, `cargo clippy` | pass |
| R-05 | Frontend build | `npm run build` | pass |
| R-06 | Desktop build | `npm run tauri build` | pass, MSI + NSIS |
| R-07 | Documentation set | `README.md` and linked reports | All links resolve |
| R-08 | Honest reporting | `TEST-RESULTS.md`, `AI-EVALUATION.md`, `PERFORMANCE-BENCHMARKS.md` | Review |

## Unmapped or open requirements

- Independent forensic validation — no implementation; tracked in `AUDIT.md`.
- Linux/macOS packaging — no implementation; tracked in `ROADMAP.md`.
- Live remote-provider and live MISP/TAXII tests — not performed.
- 1,000,000-event benchmark — rejected by design; see `PERFORMANCE-BENCHMARKS.md`.
- Multi-role autonomous investigation, vector search, typed-port workflow editor — not implemented.
