# MailSonar Changelog

All notable changes are recorded here. This project does not use semantic-version tags beyond the release labels in `ROADMAP.md`.

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
