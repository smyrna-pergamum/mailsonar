# MailSonar — V1.0

**Detect threats beneath the surface.**

MailSonar is a local-first email forensics and incident-response workbench built with Rust, Tauri 2 and a local web UI. Deterministic parsing, detection and correlation work without any AI provider. AI analysis is optional, opt-in, and always routed through one backend privacy gateway.

The interface uses the **NIGHTWIRE** theme. The floating investigation assistant is **BEACON**, the bounded DFIR agent is **HELM**, and the workflow studio is **WAYPOINT**.

**Status: source builds and tests pass on Windows; the Windows installer builds locally. Not independently validated as a forensic product.** See `TEST-RESULTS.md`, `AUDIT.md`, `SECURITY-AUDIT.md` and `AI-EVALUATION.md` for measured results and open gaps.

## Rebranding and data migration

This release renames the visible product from Mail DFIR to MailSonar. The following identifiers are intentionally unchanged so existing installations keep working:

- Tauri identifier: `org.maildfir.desktop`
- Application-data directory and model, workflow, session and vault paths
- Local-storage keys such as `maildfir.theme` and `maildfir.copilot.provider`
- Case-file schema IDs (`mail-dfir/1.0`), parser manifest schema (`mail-dfir.parser/1`) and the Cargo/binary name `mail-dfir`
- Evidence file names, hashes and case exports

Only product strings, window titles, installer display names and icons changed. No evidence, model, workflow, session or vault data is moved or rewritten. An older installation can therefore be upgraded in place.

## Build from source

Prerequisites: Rust stable (tested with 1.99.1), Node.js 22+ (tested with 24.20.0), and the Tauri 2 platform prerequisites — on Windows: Visual Studio C++ Build Tools and WebView2.

```sh
npm install
npm test                                              # 61 Node tests
cargo test --manifest-path src-tauri/Cargo.toml        # 35 pass, 2 ignored
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
cargo fmt --manifest-path src-tauri/Cargo.toml --all --check
npm run tauri build                                   # release binary + MSI/NSIS installers
```

Artifacts (product name MailSonar, binary name from the Cargo package):

- `src-tauri/target/release/mail-dfir.exe`
- `src-tauri/target/release/bundle/msi/MailSonar_*.msi`
- `src-tauri/target/release/bundle/nsis/MailSonar_*-setup.exe`

## What works

- **Import:** CSV, JSON, JSONL, XML, TXT, LOG, EML, MSG, EVTX, ZIP, GZIP, XLSX. Size limits: 32 MiB per file, 20,000 records, 64 KiB per MSG property, archive nesting depth 3, 128 archive members, 96 MiB expanded-data budget.
- **Evidence handling:** original bytes re-read, SHA-256 verified, stored in SQLite, local hash-chained journal, integrity re-verification from the UI. The vault is **not encrypted** and the chain is **not externally anchored**.
- **Detection:** 20 built-in keyword rules (MAIL-001 to MAIL-020), custom rules, Sigma subset (fail-closed), IOC matching, anomaly rule ANOM-001.
- **Correlation:** COR-001 authentication-failure window, COR-002 outbound-volume spike, COR-003 message trace, relationship graph (2,000-event cap).
- **OCSF 1.3.0 draft export:** classes 4009, 4010, 4012, 4013, 4014, 4015, 4016 with class/category/activity/type IDs. Draft only — not schema-validated against the official JSON schema.
- **AI:** OpenAI-compatible chat-completions endpoint (llama.cpp, Ollama, LM Studio, vLLM, OpenAI, OpenRouter, private gateways). Backend enforces HTTPS (loopback HTTP allowed), no URL credentials, no redirects, 120 s timeout, 2 MiB response cap, 100 KB context cap, 1–25 minimized records, bounded retries on 429/5xx with `Retry-After`.
- **Bundled local engine:** llama.cpp b11934 CPU `llama-server` (Windows x64) in `src-tauri/engine`, bundled as a Tauri resource. The app starts it on loopback with a per-run random API key. Model files are not bundled; import a GGUF into the app-data model directory.
- **HELM agent:** 15 read-only case tools in the Rust backend, 12 iterations, 24 tool calls, 6 calls per turn, 12k characters per tool result, 2 MiB response cap. The model proposes calls; Rust validates names and arguments and executes them. No shell, SQL, filesystem or production-email capability is exposed. Sensitive tools require an explicit approval list.
- **WAYPOINT workflows:** validated DAG execution with 9 node kinds (tool, filter, aggregate, detect, evidence check, visualize, branch, agent, approval, report), version history, run traces and cancellation. Limits: 32 nodes, 512 KiB workflow, 80 trace steps.
- **Reports:** HTML (escaped), JSON, CSV, OCSF draft, PDF through a fixed embedded ReportLab script run locally by Python 3 (no bundled runtime).

## BEACON, HELM and WAYPOINT

**BEACON** is the only floating assistant. It has three modes:

1. **Offline product guide** — deterministic keyword help. No network request, no model, no LLM. It answers product questions and links to the relevant workspace tab.
2. **Selected evidence AI** — sends only the 1–25 records selected in Log Explorer through the existing `ask_ai` gateway. A consent dialog names the destination, model, record count and the question exactly as entered. Denial makes no request. The frontend clones the selection before approval, minimizes it, and the Rust gateway re-validates every field.
3. **HELM agent** — sends a task to the bounded read-only agent. Requires imported evidence and explicit consent. BEACON itself never executes tools and never changes evidence; the Rust backend authorizes and runs every tool.

**HELM** is the full agent workspace tab: agent console, model center, WAYPOINT, tool registry, sessions and execution monitor. **WAYPOINT** is the workflow studio inside that tab.

## AI privacy model

All AI workflows call `ask_ai`; there is no second AI command. Before transfer, the frontend replaces sender, recipient, IP and message ID with stable `entity-N` aliases, drops source names and raw records, and keeps only an allow-listed action label and an RFC 3339 timestamp. The Rust gateway re-checks every field and rejects anything that is not minimized.

This is **minimization and pseudonymization, not anonymization**. Timestamps, action labels, hash-derived evidence IDs and the analyst's own question or knowledge notes can still identify a person or incident. Do not send confidential questions or notes to a third-party service; prefer a local or private endpoint.

`agent_run` additionally withholds IOC values and minimizes findings when the provider is not loopback. API keys are held in memory for the session only and are never persisted or placed in a URL. Remote AI is off by default; consent resets when settings change.

## Limits and non-goals

- Session and per-file record cap is 20,000; the 1,000,000-event benchmark is therefore **not supported** in one import (see `PERFORMANCE-BENCHMARKS.md`).
- EML: headers only. MSG: selected MAPI properties only. Attachments are never executed or scanned.
- No vendor-specific parsers or collectors yet; no automatic vendor detection.
- RAG is TF-IDF only; no embeddings or vector database.
- HELM is a bounded single-agent loop, not a multi-role autonomous investigation system. All AI output is unverified and requires analyst review.
- No live MISP/TAXII/AI provider tests were run; mock-server tests only.
- Windows installers were built; Linux and macOS were not built or tested here.
- Real inference was verified only with the bundled Windows CPU engine and a small local test GGUF. No model-quality claims are made.

## Documentation

- `AUDIT.md` — issue log and current status
- `SECURITY-AUDIT.md` — threat model, controls and findings
- `TEST-RESULTS.md` — measured test and build results
- `AI-EVALUATION.md` — what was and was not evaluated
- `AI-QUALITY-GATES.md` — release gates for AI features
- `MODEL-BENCHMARKS.md` — engine/model measurements
- `DATASET-MANIFEST.md` — test data provenance
- `PERFORMANCE-BENCHMARKS.md` — limits and measured timings
- `TRACEABILITY.md` — requirement-to-implementation map
- `ROADMAP.md` — milestone status
- `CHANGELOG.md` — release history
- `THIRD-PARTY-NOTICES.md` — licenses and bundled engine provenance

## Optional integrations

Separate virtual environments are recommended. Never run untrusted rule or plugin code.

```sh
python -m venv .venv
pip install -r integrations/requirements.txt
python integrations/worker.py drain case.json
python integrations/worker.py sigma rule.yml
python integrations/worker.py pdf case.json --output report.pdf
```

`integrations/sigma_execute.py` uses pySigma + a read-only SQLite backend (separate requirements file, Python 3.11+). `integrations/logai_anomaly.py` prepares features for LogAI. `integrations/threat_fetch.py` fetches MISP/TAXII over HTTPS with no redirects and writes indicator JSON for import into Developer Rules. Mock pagination tests pass; no live server was contacted.

## Tests

```sh
npm test
cargo test --manifest-path src-tauri/Cargo.toml
python -m unittest discover -s tests -p "test_*.py" -v
cargo test --manifest-path src-tauri/Cargo.toml --release -- --ignored --nocapture   # benchmark
```

The real-inference test is ignored by default. Supply a GGUF path:

```powershell
$env:MAILDFIR_TEST_GGUF = "C:\path\to\model.gguf"
cargo test --manifest-path src-tauri/Cargo.toml bundled_engine_serves_a_real_completion -- --ignored --nocapture
```

## License

See `LICENSE` and `THIRD-PARTY-NOTICES.md`. Review upstream licenses before redistribution.
