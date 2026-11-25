# MailSonar — Contributing

## Development setup

1. Install prerequisites:
   - Rust stable: `rustup install stable` (tested with 1.99.1)
   - Node.js 22+ (tested with 24.20.0)
   - Tauri 2 platform prerequisites
   - Python 3.11+ only for the optional integrations and PDF export

2. Install dependencies:

   ```sh
   npm install
   ```

3. Run the development app:

   ```sh
   npm run tauri dev
   ```

   For frontend-only work, `npm run dev` serves the UI at `http://127.0.0.1:1420/`. The browser preview uses a DEV-only synthetic mock; it does not exercise the Rust backend or a real model.

4. Run the checks before submitting:

   ```sh
   npm test
   npm run build
   cargo fmt --manifest-path src-tauri/Cargo.toml --all --check
   cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
   cargo test --manifest-path src-tauri/Cargo.toml
   python -m unittest discover -s tests -p "test_*.py" -v
   ```

## Adding features

### Rust/Tauri backend

1. Keep commands in the existing modules (`main.rs`, `agent.rs`, `workflow.rs`, `embedded_ai.rs`, `vault.rs`, `pdf.rs`).
2. Register new commands in `main.rs` `generate_handler!`.
3. Validate every argument at the command boundary; never trust the webview.
4. Add unit tests in the same module.
5. Run `cargo fmt`, `cargo clippy --all-targets` and `cargo test`.

### JavaScript frontend

1. Put UI modules in `src/`. BEACON lives in `src/beacon/`.
2. Keep AI traffic on the existing `ask_ai` gateway or `agent_run`; do not add a second network path.
3. Add tests in `tests/*.test.js` and run `npm test`.
4. Run `npm run build` and confirm the production bundle has no dev-only hooks.

### BEACON changes

- `src/beacon/core.js` holds pure request builders and must stay host-agnostic.
- `src/beacon/panel.js` owns the single floating mount. Do not add a second floating assistant.
- Any change to selection bounds, URL policy or consent requires new tests in `tests/beacon.test.js`.
- The offline guide is deterministic keyword matching. Do not describe it as an LLM.

### Python integrations

1. Add code under `integrations/` and pin requirements in `integrations/requirements*.txt`.
2. Add tests under `tests/`.
3. Never run untrusted rule or plugin code.

## Parser development

1. Add format handling to `parse()` in `src-tauri/src/main.rs`.
2. Enforce size, record, nesting and expansion limits.
3. Use maintained open-source libraries where possible.
4. Add a declarative manifest under `plugins/` if the format is configurable.
5. Add tests for valid, malformed and over-limit inputs.

### Field mapping

1. Add a declarative mapping under `plugins/`.
2. Match `plugins/parser.schema.json`.
3. Fields: `schema`, `id`, `name`, `fields` (target to source mapping).
4. Targets: `timestamp`, `sender`, `recipient`, `ip`, `message_id`, `action`.
5. Length constraints: 1–128 characters.

## Reporting issues

1. Check `AUDIT.md`, `ROADMAP.md` and `SECURITY-AUDIT.md` first.
2. Include clear reproduction steps.
3. Include version and platform (Windows/macOS/Linux).
4. Include error messages and relevant logs. Redact case data.

## Pull requests

1. Create a feature branch.
2. Keep changes focused and consistent with surrounding code.
3. Run the full check list above.
4. Describe what was tested and what was not. Do not claim untested builds or metrics.
5. Submit the pull request.

## Code style

- Rust: rustfmt defaults; no clippy warnings.
- JavaScript: existing project style, no framework.
- Python: PEP 8.
- Commit messages: clear, present tense.

## Documentation

If a change affects behaviour, limits, privacy or measured results, update the matching document:

- `README.md`, `CHANGELOG.md`, `ROADMAP.md`
- `AUDIT.md`, `SECURITY-AUDIT.md`
- `TEST-RESULTS.md`, `AI-EVALUATION.md`, `AI-QUALITY-GATES.md`
- `MODEL-BENCHMARKS.md`, `DATASET-MANIFEST.md`, `PERFORMANCE-BENCHMARKS.md`, `TRACEABILITY.md`

## License

All contributions must be original work or properly licensed. Contributions must be compatible with the MIT License used for this project.
