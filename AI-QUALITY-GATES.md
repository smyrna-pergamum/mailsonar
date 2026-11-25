# MailSonar — AI Quality Gates

These gates apply to any release that advertises AI features. A gate is either **PASS**, **CONDITIONAL** (documented limitation accepted) or **FAIL** (must be fixed before release).

## Release gates

| # | Gate | Requirement | Status |
|---|------|-------------|--------|
| 1 | Single gateway | All model traffic uses `ask_ai` or `agent_run`; no alternate network path in the webview | PASS |
| 2 | Endpoint policy | HTTPS, or HTTP only on loopback; no URL credentials; redirects disabled | PASS |
| 3 | Minimization | Raw sender/recipient/IP/message ID never leave the frontend; backend re-validates | PASS |
| 4 | Cloud withholding | Non-loopback requests minimize findings and withhold IOC values | PASS |
| 5 | Consent | Every transfer or agent run requires an explicit, named confirmation | PASS |
| 6 | Consent reset | Changing provider settings clears prior consent | PASS |
| 7 | Selection bounds | AI mode accepts 1–25 records; empty or over-limit selections are rejected | PASS |
| 8 | Snapshot isolation | The selection is cloned before approval; later edits do not alter the request | PASS |
| 9 | Agent allow-list | Only fixed read-only tools; unknown tools and arguments rejected | PASS |
| 10 | Agent budgets | Iterations, tool calls, per-result size and response size are bounded | PASS |
| 11 | Sensitive tools | Approval is explicit and validated against the sensitive-tool list | PASS |
| 12 | No autonomous action | No shell, SQL, filesystem, email-send or evidence-modification capability | PASS |
| 13 | Output labelling | AI and agent output is displayed as unverified and never as a finding | PASS |
| 14 | Offline path | The product guide works with no model, no network and no provider | PASS |
| 15 | Key handling | API keys stay in memory for the session and are not persisted or placed in URLs | PASS |
| 16 | Deterministic core | Parsing, detection, correlation, vault and reports work without AI | PASS |
| 17 | Test coverage | Gateway, consent, bounds and agent gating have automated tests | PASS (61 Node, 35 Rust, 12 Python) |
| 18 | Real inference smoke | At least one real local completion through the production spawn path | PASS (bundled CPU engine, test GGUF) |
| 19 | Provider interoperability | At least one live remote provider tested with TLS | **FAIL** — mock servers only |
| 20 | Quality evaluation | Labelled dataset with precision/recall and citation accuracy | **FAIL** — not evaluated |
| 21 | Prompt-injection evaluation | Fixed adversarial set with measured success rate | **FAIL** — design review only |
| 22 | Cross-platform | AI paths tested on Windows, Linux and macOS | **FAIL** — Windows only |
| 23 | Reproducible engine provenance | Engine hash re-verified against upstream at release time | **CONDITIONAL** — hash recorded, not re-downloaded |

## Gate interpretation

- Gates 1–18 are enforced by code and automated tests in this tree.
- Gate 19 is the main release risk for remote providers. Until it passes, documentation must say that remote-provider behaviour is untested.
- Gates 20–22 block any claim of measured accuracy, robustness or cross-platform support.
- Gate 23 is acceptable for internal use but should be closed before public redistribution.

## Regression rules

A change to any of the following requires the corresponding gate to be re-run:

- `src/privacy.js`, `src/investigation.js` — gates 3, 4, 8, 17
- `src/beacon/core.js` — gates 5, 7, 8, 17
- `src-tauri/src/main.rs` `validate_ai_request` — gates 2, 3, 4, 17
- `src-tauri/src/agent.rs` — gates 9, 10, 11, 12, 17
- `src-tauri/src/embedded_ai.rs` — gates 18, 23
- `src-tauri/engine/*` — gate 23

## Release statement template

> MailSonar V1.0 ships deterministic parsing, detection and correlation plus optional assistive AI. All AI traffic is consent-gated and minimized through one backend gateway. AI output is unverified. Model quality, prompt-injection resistance and live remote-provider behaviour were not independently evaluated. Windows x64 was built and tested; Linux and macOS were not.

Do not remove or soften this statement without closing the failing gates.
