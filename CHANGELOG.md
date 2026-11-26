# MailSonar Changelog

All notable changes are recorded here. This project does not use semantic-version tags beyond the release labels in `ROADMAP.md`.

## V1.3 — Large investigations

- **Large investigations**: per-case SQLite stores for millions of events; streaming parsers (CSV, JSONL, LOG/TXT, MBOX, inside GZIP/ZIP), adaptive batches of 2,000–20,000 records, parallel workers with bounded queues, ordered writer with per-batch checkpoint and resume, content-hash de-duplication, failures table, per-file source profiles.
- **Global correlation** across batches and files (COR-001/002/003, COR-004 kill chain).
- **HELM on large investigations**: SQL-backed tools with the same names and schemas; cloud providers receive per-run aliases and aliases are mapped back locally.
- **UI**: Large investigations view with live import progress (bytes, records, EPS, duplicates, failures), overview, paged findings and records, log sources, HELM and copy-to-workspace.
- In-memory workspace limit raised from 20,000 to **100,000** records and 64 MiB per file.
- **Benchmark** `bench_ingest_scales` (1k … 1M, optional 5M) with integrity and crash-recovery checks.
- **Relationship graph filters**: scope (findings, attack chains, high priority, all), entity types, time range, minimum connections, node cap and entity search; node detail with records.
- **VirusTotal links** for URLs, domains, origin IPs and attachment hashes (manual, opens the system browser, validated `virustotal.com` addresses only).
- **Deep analysis redesign**: the old "selected records / batch / two-stage" section is now three guided methods with selection helpers (high-priority evidence, attack-chain evidence), question templates and a readable result view with evidence validation counts; exports moved to Case & report.

## V1.2 — Simplified workbench, e-mail forensics, skill-driven HELM

### Training, saved queries, provider identification, releases

- **Training mode**: 9 lessons / 20 questions on the synthetic BEC case and the labelled repository dataset (`dataset/formats`, now bundled as the *github-baseline* sample). Answers are computed from the parsed data; hints, "show me" navigation, explanations, HELM help and progress tracking.
- **Saved analyst queries**: add, edit and delete one-click AI questions (optional skill); stored in `<app data>/analysis-queries.json`.
- **Skill import**: add `.md` skill files from disk in the HELM Skills tab (`skill_import` / file picker).
- **Log-source and mail-provider identification** (`sources.rs`): per-file fingerprint with breakdown, confidence and reason; per-message sending/relay/gateway/receiving platforms; HELM tool `log_sources`.
- **Release workflow** (`.github/workflows/release.yml`): Windows, Linux and macOS (arm64 + x64) installers with the matching llama.cpp engine, uploaded to a draft GitHub release.
- Review fixes: conversation history is never sent to remote providers; every native tool call gets a reply when the tool budget ends; context-window overflow on local engines triggers a trimmed final answer; tool results are capped relative to the token budget; text-protocol fallback only on 400/422/500; capped response bodies and proxy-aware self-test; reserved Windows names rejected for skills; regexes compiled once.


### Simpler to use

- New **Start** page: three steps (load evidence → connect an AI model → investigate) and an attack-chain panel.
- Sidebar reduced to ten views in investigation order; specialist views moved to a collapsible **Expert tools** group.
- **One AI connection** for every AI feature (AI analysis, HELM, rule writing, BEACON). Legacy endpoint fields stay in sync.
- Consent: loopback (on-device) providers no longer need a checkbox per run; remote providers get a per-run confirmation naming the host.
- **Sample case**: a synthetic BEC kill chain (gateway CSV, Entra ID JSONL, mailbox audit JSON, EML, MBOX, Postfix log, IOCs) is compiled into the app and loads with one click (`dataset/generators/demo_scenario.py`).
- Turkish and German translations for all new UI.

### Local AI models

- **AI model** page: recommended Hugging Face GGUF models with one-click *Download & start* (single-file Q4_K_M picked from the repository listing, SHA-256 verified when published), Hugging Face search or pasted repository link, installed models, engine settings and other providers.
- **Automatic discovery** (`discover_local_ai`): probes loopback ports of Ollama, LM Studio, llama.cpp, vLLM, KoboldCpp, text-generation-webui, Jan, GPT4All and LocalAI, and scans known model folders (LM Studio, Hugging Face cache, Jan, GPT4All, `~/models`, Downloads) for GGUF files (signature checked, split shards and projectors skipped).
- **Self-test** (`ai_selftest`): synthetic prompts only; reports chat, latency, tokens/s, native or text tool calling and whether the model is ready for HELM.
- Bundled engine starts with `--jinja`; default context 8–16k tokens; the UI reconnects to a running engine after a reload (`embedded_connection`).
- Local reasoning models get `chat_template_kwargs.enable_thinking=false` (loopback only) and a 15-minute timeout.

### HELM: agentic, skill-driven

- **Markdown skills** (`src-tauri/skills/*.md`, front matter: name, description, triggers, preload, always), in the style of Claude Code / Codex / OpenCode skills. Ten built-in skills: triage, phishing-triage, email-header-forensics, malware-delivery, account-takeover, mailbox-rule-abuse, bec-fraud, data-exfiltration, detection-engineering, incident-report.
- User skills in `<app data>/skills/*.md` override built-ins; Skills tab to view, duplicate, edit, create and delete.
- Skill activation by `/skill-name`, explicit request field or deterministic trigger routing; preload tools run in the backend before the first model turn so small models start grounded.
- New tools: `list_skills`, `load_skill`, `update_plan` (live plan shown to the analyst), `test_rule` (dry-run a detection rule).
- Follow-up questions carry bounded conversation history; trace steps stream live (`helm://step`).
- Text tool-call protocol (`<tool_call>{...}</tool_call>`, fenced or bare JSON) for models without native function calling, with automatic fallback when a server rejects `tools`.
- When iterations, tool calls or the token budget run out, HELM asks once for a final answer from the evidence gathered.
- Loopback providers now see a short `summary` of each record and the full record in `evidence_inspect`; cloud providers still get minimized aliases only.

### AI analysis and rule writing

- **One-click AI analysis**: nine investigation profiles, each a HELM skill, plus a free question box; cited answers with clickable evidence IDs.
- **Write detection rules with AI**: describe the behaviour; HELM tests candidates with `test_rule` and returns JSON; proposals show live match counts and are added only on request. A no-AI quick-rule form is included.

### E-mail forensics

- EML parsing now covers bodies and attachments statically: Received chain (origin IP, time-order and unknown-relay anomalies), SPF/DKIM/DMARC, From vs Return-Path vs Reply-To vs display name, look-alike sender domains, URLs (anchor-text mismatch, punycode, homoglyphs, typosquatting, shorteners, IP literals, open redirects) and attachments (SHA-256, magic-byte type, double extension, RTL override, macros, encrypted ZIP). Nothing is executed, rendered or fetched.
- **MBOX** import.
- New rules MAIL-021 … MAIL-030 (Reply-To redirection, risky attachment, look-alike domain, Received anomaly, payment-change request, mailbox delegation, deletion, mass access, new device/MFA change, mail flood) with ATT&CK mapping.
- **COR-004 kill-chain correlation** per account: phishing received → suspicious sign-in → mailbox manipulation → fraud/exfiltration, ordered within 24 h.
- E-mail analysis view sorted by risk.

## V1.0 — MailSonar / BEACON release (unreleased)

### Rebranding

- Product renamed from Mail DFIR to **MailSonar**; slogan **"Detect threats beneath the surface."**
- AI assistant renamed to **BEACON**; bounded agent workspace renamed to **HELM**; workflow studio renamed to **WAYPOINT**.
- New BEACON emblem used in the sidebar, the floating launcher and the application icons.
- Window title, installer display name, package metadata and documentation updated.
- Application identifier `org.maildfir.desktop`, storage paths, storage keys and case/parser schema IDs are unchanged so existing data upgrades in place.

### Added

- Floating BEACON assistant (`src/beacon/`) with three modes: deterministic offline guide, selected-evidence AI, and HELM agent.
- Consent dialogs that name destination, model, record count and the exact question before any request.
- Selected-evidence mode is capped at 1–25 records, clones the selection before approval and routes through the existing `ask_ai` gateway.
- HELM agent mode forwards a task to `agent_run` with the current case snapshot; BEACON never executes tools itself.
- 16 BEACON unit tests covering topic routing, URL policy, consent denial, selection bounds, snapshot isolation and agent gating.
- Bundled llama.cpp b11934 CPU `llama-server` under `src-tauri/engine` (26 files, 45,675,616 bytes) declared as a Tauri resource.
- Engine discovery order: Tauri resource dir, app-data engine dir, executable-relative dir, debug-only `CARGO_MANIFEST_DIR/engine`, then `MAILDFIR_LLAMA_SERVER`.
- Ignored real-inference test `bundled_engine_serves_a_real_completion`.
- `src-tauri/deny.toml` license/advisory policy; `publish = false` for the application crate.

### Changed

- HELM system prompt and default report titles updated to MailSonar naming.
- Sidebar branding and footer use the MailSonar name and slogan.
- `index.html` gained description, theme-color and SVG favicon metadata.
- Brand layout adjusted so the longer product name and slogan fit the sidebar at the minimum window width.

### Verified

- 61 Node tests pass; 35 Rust tests pass with 2 ignored; 12 Python tests pass.
- `cargo fmt --check`, `cargo clippy --all-targets`, `cargo audit` and `cargo deny check` pass.
- Frontend production build passes; BEACON flows verified in the Vite preview with the synthetic mock and no console errors.
- Windows release build with the bundled engine produced the binary, MSI and NSIS installer.

### Known gaps

- Linux and macOS were not built or tested.
- No live cloud AI provider was contacted; only mock servers and a local loopback engine were exercised.
- `pip-audit` reports two `diskcache 5.6.3` advisories in `integrations/requirements.txt`.
- Multi-role autonomous investigation, vector search, live threat-intelligence enrichment and a typed-port workflow editor remain unimplemented.

## V1.1 — Analyst workflow additions

### Added

- Analyst feedback memory (`src/feedback.js`) with verdicts `supported`, `false_positive` and `insufficient`.
- Analyst review panel (`src/review-panel.js`) bound to findings; reviews are persisted in the case state and never feed training automatically.
- Case state validation (`src/case-state.js`) shared by JSON export/import and SQLite load.
- Time handling helpers that require explicit timezone offsets (`src/event-time.js`).
- Smart investigation task builder for HELM profiles (general, takeover, delivery).
- Local fine-tuning JSONL export from analyst-reviewed feedback; no upload, training job or automatic model activation.
- Severity filter on the findings list.
- Application operation log and workflow navigation steps on the dashboard.

### Changed

- PDF report generator (`src-tauri/src/pdf_report.py`) extended with case analysis, severity bars, hourly timeline bars and relationship charts; canonical writer is now shared through the `integrations/pdf_report.py` CLI.
- AI questions are annotated with aggregate analyst feedback context where available.

### Verified

- New Node tests: learning, workspace, review, rules, i18n and report analysis coverage pass.
- Frontend production build passes; PDF reports generate in English, German and Turkish with charts on all tested samples.

## RC4

- calamine 0.26 to 0.38 XLSX parsing compatibility.
- 20 detection rules (MAIL-001 to MAIL-020) and correlation rules COR-001 to COR-003.
- OCSF draft export with multiple event classes.
- NIGHTWIRE theme, data-driven dashboards, timeline, MITRE ATT&CK view, threat-intelligence view, evaluation center and relationship graph.
- HELM/agent runtime, model center, workflow engine, sessions and execution monitor.
- SQLite evidence vault with SHA-256 hashing and local hash-chained journal.
- Windows MSI and NSIS installers.

## RC3 and earlier

- Initial parsing, detection and correlation engine.
- SQLite evidence vault with SHA-256 hashing.
- Tauri 2 desktop framework and local web UI.
