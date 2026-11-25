# MailSonar — Third-Party Notices

MailSonar is distributed under the MIT License (see `LICENSE`). Third-party components retain their own licenses. This file summarizes direct dependencies and the bundled engine; transitive dependency licenses are validated by `cargo deny` against `src-tauri/deny.toml`.

## Bundled inference engine

### llama.cpp

- **Component:** `llama-server` and required DLLs, build b11934, Windows x64 CPU
- **Upstream:** https://github.com/ggml-org/llama.cpp
- **License:** MIT
- **Files:** `src-tauri/engine/llama-server.exe`, `llama-server-impl.dll`, `llama-common.dll`, `llama.dll`, `mtmd.dll`, `ggml*.dll`, `ggml-cpu-*.dll`
- **License text:** `src-tauri/engine/LICENSE-llama.cpp`
- **Provenance:** `src-tauri/engine/ENGINE-VERSION.txt` (archive SHA-256 `A66878DDF32A2D9349BB66D3FB8A1D6D2A8187C249900276693EE105B66B2DC1`)

### LLVM OpenMP runtime

- **Component:** `libomp.dll`
- **License:** Apache-2.0 WITH LLVM-exception
- **License text:** `src-tauri/engine/LICENSE-LLVM-OpenMP`

The engine is started only as a local loopback process with a per-run random API key. The application does not download or execute inference binaries at runtime.

## Rust dependencies

Direct dependencies from `src-tauri/Cargo.toml`:

| Crate | Purpose | License |
|-------|---------|---------|
| tauri | Desktop shell | MIT or Apache-2.0 |
| tauri-build | Build integration | MIT or Apache-2.0 |
| tauri-plugin-dialog | Native open/save dialogs | MIT or Apache-2.0 |
| serde, serde_json | Serialization | MIT or Apache-2.0 |
| csv | CSV parsing | MIT or Unlicense |
| sha2 | SHA-256 | MIT or Apache-2.0 |
| flate2 | GZIP | MIT or Apache-2.0 |
| zip | ZIP | MIT |
| mailparse | EML parsing | 0BSD |
| calamine | XLSX | MIT |
| evtx | Windows event logs | Apache-2.0 or MIT |
| cfb | MSG compound files | MIT |
| roxmltree | XML | MIT or Apache-2.0 |
| reqwest | HTTP client | MIT or Apache-2.0 |
| regex | Pattern matching | MIT or Apache-2.0 |
| chrono | Timestamps | MIT or Apache-2.0 |
| rusqlite | SQLite | MIT |
| tokio | Async runtime | MIT |
| sysinfo | Hardware detection | MIT |

`cargo deny check` validates the full transitive graph against this allow-list: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Zlib, Unicode-3.0, Unlicense, 0BSD, CC0-1.0, MIT-0, CDLA-Permissive-2.0, BSL-1.0.

## Node dependencies

| Package | Purpose | License |
|---------|---------|---------|
| @tauri-apps/api | Webview API | MIT or Apache-2.0 |
| @tauri-apps/plugin-dialog | Dialog API | MIT or Apache-2.0 |
| @tauri-apps/cli | Build tooling | MIT or Apache-2.0 |
| vite | Build tooling | MIT |
| cytoscape | Relationship graph | MIT |
| echarts | Charts | Apache-2.0 |

## Python integration dependencies

Optional; not shipped in the desktop binary.

| Package | Purpose | License |
|---------|---------|---------|
| reportlab | PDF generation | BSD-3-Clause |
| pysigma | Sigma evaluation | MIT or Apache-2.0 |
| drain3 | Log clustering | MIT |
| logai | Anomaly features | Apache-2.0 |
| diskcache | Cache for integrations | Apache-2.0 |

`pip-audit` reports two advisories for `diskcache 5.6.3` (PYSEC-2026-2447). Upgrade or isolate this optional dependency before use.

## Models

No model is bundled. The test GGUF (Qwen2.5-0.5B-Instruct) is operator-supplied and is not redistributed. Upstream Qwen models are published under Apache-2.0. Any model imported by a user remains subject to its own license.

## Standards and data references

- **OCSF v1.3.0** — Open Cybersecurity Schema Framework; draft export only, not schema-validated.
- **MITRE ATT&CK** — registered trademark of The MITRE Corporation. Mappings are references, not endorsements.
- **Sigma** — open detection-rule format; only a fail-closed subset is supported.

## Attribution and compliance

- Lockfiles are maintained (`Cargo.lock`, `package-lock.json`).
- No proprietary source code is copied into this package.
- Upstream repositories are used for all integrations.
- The bundled engine archive was supplied from a local build cache; verify its hash against the upstream release before public redistribution.
