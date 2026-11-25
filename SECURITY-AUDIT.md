# MailSonar — Security Audit

## Scope and method

This is a design and code review of the MailSonar desktop application (Rust/Tauri backend plus local web UI), its AI gateway, the HELM agent, the WAYPOINT workflow engine and the bundled llama.cpp engine. It combines manual review with `cargo audit`, `cargo deny`, `npm audit`, Python unit tests and targeted Rust tests.

It is **not** a penetration test, a formal verification, or an independent certification. No live cloud provider, live MISP/TAXII server or hostile network was used.

## Threat model

MailSonar is a single-user desktop workbench. The relevant adversaries and failure modes are:

1. **Untrusted evidence** — imported mail logs, EML/MSG files, archives and spreadsheets may contain malicious strings, malformed structures or prompt-injection text.
2. **Untrusted model output** — an AI provider or local model can return misleading, unsafe or adversarial text.
3. **Accidental disclosure** — a user may send sensitive case data or questions to a remote provider.
4. **Local tampering** — a local process or user may alter stored evidence or the journal.
5. **Supply chain** — a dependency, installer or bundled binary may be compromised or vulnerable.
6. **Network interception** — a remote AI endpoint may redirect, downgrade or capture traffic.

Out of scope: a compromised operating system or WebView2 runtime, a malicious local administrator, physical access, and multi-tenant server deployment.

## Controls

### Process and capability surface

- The Tauri app registers only the dialog plugin. There is no shell, filesystem, HTTP or SQL plugin exposed to the webview.
- File paths enter through native open/save dialogs. Import reads a file once, enforces a 32 MiB cap and parser-specific limits, and never executes attachments.
- The Rust backend exposes a fixed command list: import, analyze, `ask_ai`, case export/load, HTML/PDF export, vault operations, embedded-engine operations, Hugging Face model listing/download, provider test, agent operations and workflow operations.
- The CSP is `default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src ipc: http://ipc.localhost; img-src 'self' data:`. The webview cannot open arbitrary network connections; AI traffic goes through Rust.

### AI gateway (`ask_ai`)

- One AI command for all workflows; there is no second network path for model calls.
- Endpoint must parse as a URL, use HTTPS, or use HTTP only on `127.0.0.1`, `localhost` or `[::1]`. URL credentials are rejected.
- Redirects are disabled; timeout is 120 s; response body is capped at 2 MiB; context is capped at 100 KB.
- Requests contain 1–25 events. Event IDs must match `^[0-9a-f]{64}:[0-9a-f]{64}:[0-9]{1,6}$`; timestamps must be RFC 3339; unknown fields are rejected.
- The frontend minimizes records before sending; the backend re-validates rather than trusting the frontend.
- Retries are bounded and honour `Retry-After` (maximum 5 s).
- API keys are kept in memory for the session and are never written to disk or placed in a URL.

### HELM agent

- 15 read-only tools with fixed names; unknown tools and unknown arguments are rejected.
- Limits: 12 iterations, 24 tool calls, 6 calls per turn, 12,000 characters per tool result, 2 MiB response.
- Sensitive tools require an explicit approval list; the backend rejects approving an unknown or non-sensitive tool.
- For non-loopback providers the case snapshot is minimized, findings are minimized and IOC values are withheld. Loopback providers receive the raw snapshot.
- The system prompt treats evidence as data, forbids claiming command execution or evidence modification, and requires evidence IDs.
- BEACON's agent mode adds a consent checkpoint and forwards the task; it does not execute tools itself.
- Cancellation is supported per session.

### WAYPOINT workflow engine

- Declarative nodes only; no user-supplied code execution.
- Limits: 32 nodes, 512 KiB workflow document, 80 trace steps, validated DAG and node arguments.
- Agent and approval nodes inherit the agent controls; workflow runs can be cancelled.
- Saved workflows are versioned and stored under the application-data directory.

### Evidence vault

- Original bytes are re-read and SHA-256 hashed on preserve; SQLite writes use parameterized statements.
- A local hash-chained journal records vault operations; verification re-hashes stored bytes and checks the chain.
- Case export/import is explicit and user-driven.

### Model and engine handling

- The bundled engine is a fixed llama.cpp b11934 Windows CPU build shipped as a Tauri resource.
- The app never downloads or executes an inference binary at runtime. It runs the bundled binary, an operator-placed binary in the app-data `engine/` directory, or a path named by `MAILDFIR_LLAMA_SERVER`.
- Engine arguments are validated: port 1024–65535, context 512–32768, threads 1–64, GPU layers ≤200, model path inside the app-data model directory.
- The engine binds `127.0.0.1` and receives a per-run random API key.
- Model downloads are restricted to HTTPS Hugging Face hosts; filenames are validated; SHA-256 is taken from Hugging Face LFS metadata.

### Output handling

- HTML reports escape `&`, `<`, `>`, `"` and `'`.
- Markdown/plain-text AI output is rendered as text, not injected as HTML.
- BEACON messages are inserted with `textContent`.

## Supply chain

| Check | Result |
|-------|--------|
| `cargo audit` | 0 vulnerabilities; 3 documented warnings |
| `cargo deny check` | advisories, bans, licenses and sources pass |
| `npm audit` | 0 vulnerabilities reported at install time |
| `pip-audit` | 2 `diskcache 5.6.3` findings (PYSEC-2026-2447) in optional integration requirements |

Documented Rust advisory exceptions:

- `RUSTSEC-2026-0543` — `chrono` unmaintained; used for local timestamp formatting, not parsing untrusted input.
- `RUSTSEC-2024-0370` — `proc-macro-error` build-time only.
- `RUSTSEC-2024-0429` — `glib` transitive Linux/WebKitGTK dependency; Windows builds do not include it.

The engine archive was supplied from a local build cache. Its SHA-256 is recorded in `src-tauri/engine/ENGINE-VERSION.txt`, but it was not re-downloaded from GitHub during this session. Verify it against the upstream b11934 release before redistribution.

## Findings

### HIGH — Vault confidentiality and custody

The vault is not encrypted at rest and the hash chain is not externally anchored or signed. A local attacker with write access can delete or replace data; the chain detects some tampering but cannot prevent it. This is acceptable only for a local analyst workbench with OS-level access controls. Do not describe vault output as certified evidence.

### HIGH — No independent validation

Detection rules, correlation rules and AI output are unvalidated heuristics. No labelled corpus, third-party review or accreditation exists. Reports must be reviewed by a qualified analyst.

### HIGH — Linux/macOS untested

Only Windows x64 was built and exercised. Platform-specific path, WebView and packaging behaviour is unverified.

### MEDIUM — Live providers untested

Gateway and agent behaviour was tested against mock HTTP servers and a loopback llama.cpp engine. TLS, provider-specific error handling and real rate limits were not exercised.

### MEDIUM — Optional Python dependency advisories

`integrations/requirements.txt` pins `diskcache 5.6.3`, which has two current advisories. The integration is optional and not part of the desktop binary. Upgrade or isolate it before use.

### MEDIUM — No installer code signing

The MSI/NSIS artifacts are unsigned. Windows SmartScreen and enterprise policy may block or warn. Verify hashes out of band if distributing.

### LOW — Prompt injection remains possible

Minimization and system-prompt rules reduce exposure, but a model can still be influenced by crafted evidence. Output is always labelled unverified and requires analyst review. There is no automated output sanitizer beyond text rendering.

### LOW — Local denial of service

Very large or adversarial inputs are bounded by size and record limits, but CPU/memory exhaustion within those bounds is still possible. Parsing runs in blocking tasks; a stuck import can be cancelled only by restarting the operation.

## Security-relevant defaults

- Remote AI is off until the user configures an endpoint and authorizes a request.
- Consent resets when settings change.
- BEACON's offline guide performs no network request.
- The app starts and performs deterministic analysis with no model installed.
- Dev-only hooks (`window.__maildfirDev`, `window.__maildfirMock`) are excluded from production builds; `dist` is checked for their absence.

## Recommendations before production use

1. Encrypt the vault or document OS-level controls as a prerequisite.
2. Add external anchoring or signed export for the journal.
3. Obtain an independent review of detection logic and a labelled evaluation corpus.
4. Sign Windows installers and publish checksums.
5. Re-verify the bundled engine hash against upstream and add a reproducible-build note.
6. Build and test Linux and macOS packages, or state Windows-only support explicitly.
7. Upgrade or remove the vulnerable optional Python dependency.
8. Add an automated WebView-level UI test for consent flows.
