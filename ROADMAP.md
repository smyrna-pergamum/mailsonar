# MailSonar — Development Roadmap

Status reflects this working tree. A checked item is implemented and covered by at least one test or a recorded manual verification. It does not imply independent validation.

## V0.1 — Foundation

- [x] Rust/Tauri 2 desktop application
- [x] SQLite evidence vault with SHA-256
- [x] CSV/JSON import
- [x] Startup without an AI provider
- [x] Windows MSI/NSIS packaging

## V0.2 — Parsing

- [x] CSV, JSON, JSONL, XML, TXT, LOG
- [x] EML (headers), MSG (selected MAPI properties)
- [x] EVTX
- [x] ZIP/GZIP with nesting, member and expansion limits
- [x] XLSX (calamine 0.38)
- [x] Import warnings and per-record limits
- [ ] Vendor-specific parsers (Exchange, M365, Entra ID, Defender, Postfix, Exim, Dovecot, Zimbra, Proofpoint, Mimecast, Barracuda, Cisco, FortiMail, Rspamd, SES)
- [ ] Automatic format and vendor detection
- [ ] Encoding and timezone normalization
- [ ] Streaming parsing beyond the 20k/32 MiB caps

## V0.3 — Detection and correlation

- [x] 20 built-in rules (MAIL-001 to MAIL-020)
- [x] Custom rules and Sigma subset (fail-closed)
- [x] IOC matching
- [x] Anomaly rule ANOM-001
- [x] COR-001 authentication-failure window
- [x] COR-002 outbound-volume spike
- [x] COR-003 message trace
- [x] MITRE ATT&CK view
- [ ] Validated BEC/account-takeover detections with labelled data
- [ ] Precision/recall measurement

## V0.4 — Evidence and reporting

- [x] Original-byte preservation and SHA-256 verification
- [x] Local hash-chained journal
- [x] Vault re-verification from the UI
- [x] Case export/import
- [x] HTML report with escaping
- [x] JSON, CSV and OCSF draft export
- [x] PDF through a local ReportLab script
- [ ] Encrypted vault
- [ ] Externally anchored or signed journal
- [ ] Signed installer and published checksums

## V0.5 — AI provider management

- [x] OpenAI-compatible gateway (`ask_ai`)
- [x] llama.cpp, Ollama, LM Studio, vLLM, OpenAI, OpenRouter presets
- [x] HTTPS/loopback policy, no credentials in URLs, no redirects
- [x] Timeouts, response cap, retries with `Retry-After`
- [x] Provider connectivity test
- [x] Model center with local model import and hash
- [x] Bundled llama.cpp b11934 CPU engine
- [x] Hugging Face model search/download restricted to HTTPS HF hosts with SHA-256
- [ ] Live remote-provider interoperability test
- [ ] Engine hash re-verification at release time

## V0.6 — Privacy and consent

- [x] One backend gateway for all AI
- [x] Sender/recipient/IP/message-ID aliasing
- [x] Raw-field removal and backend re-validation
- [x] Explicit consent with destination, model and record count
- [x] Consent reset on settings change
- [x] Session-only API keys
- [x] Non-loopback minimization of findings and withholding of IOC values
- [ ] Formal data-retention policy per provider
- [ ] Configurable per-case privacy profiles

## V0.7 — HELM agent and WAYPOINT

- [x] 15 read-only tools
- [x] Iteration, call, size and response budgets
- [x] Sensitive-tool approvals
- [x] Session persistence and cancellation
- [x] Execution monitor
- [x] 9 workflow node kinds with DAG validation
- [x] Workflow versions, traces and cancellation
- [ ] Multi-role autonomous investigation with independent verification
- [ ] Typed-port visual workflow editor
- [ ] Vector/embedding retrieval

## V0.8 — Threat intelligence and plugins

- [x] MISP/TAXII fetch script with pagination and HTTPS-only policy
- [x] IOC import and local matching
- [x] Versioned declarative parser manifests
- [ ] Live MISP/TAXII integration in the UI
- [ ] Remote enrichment scheduler
- [ ] Plugin editor and sample plugin pack

## V0.9 — Interface

- [x] NIGHTWIRE theme with light/dark toggle
- [x] Data-driven dashboards
- [x] Timeline and correlation view
- [x] Relationship graph
- [x] MITRE ATT&CK matrix
- [x] Threat-intelligence view
- [x] AI evaluation center
- [x] BEACON floating assistant (offline guide, selected-evidence AI, HELM agent)
- [x] HELM/WAYPOINT branding and MailSonar identity
- [ ] Automated WebView-level UI tests
- [ ] Accessibility audit

## V1.0 — MailSonar / BEACON release

- [x] Rebrand product, assistant, agent and workflow studio
- [x] New emblem and application icons
- [x] Preserve identifier, storage paths and case schemas
- [x] 61 Node tests, 35 Rust tests (2 ignored), 12 Python tests
- [x] `cargo fmt`, `cargo clippy`, `cargo audit`, `cargo deny`
- [x] Frontend production build
- [x] Windows release build with bundled engine
- [x] Documentation set completed
- [ ] Linux and macOS builds
- [ ] Independent forensic review
- [ ] Live provider and cross-platform validation

## Explicit non-goals for V1.0

- 1,000,000-event single-import benchmarking.
- A certified chain of custody.
- Autonomous remediation or production-mailbox access.
- A claim of measured AI accuracy.
