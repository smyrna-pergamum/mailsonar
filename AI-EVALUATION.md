# MailSonar — AI Evaluation

## Purpose

This document separates what was **measured** about MailSonar's AI paths from what was **not evaluated**. It exists to prevent unverified quality claims.

## Evaluation status

**No model-quality evaluation was performed.** There is no labelled forensic corpus, no ground-truth incident set, and no independent review of model answers. The in-app AI Evaluation Center reports session metrics (requests, latency, token usage when the provider returns it, errors) and marks quality benchmarks as **Not Evaluated** when no dataset is configured. That behaviour is intentional.

## What was verified

| Area | Method | Result |
|------|--------|--------|
| Gateway minimization | Node tests + Rust validation review | Raw sender, recipient, IP and message ID are replaced with stable aliases; unknown fields are rejected |
| Alias consistency | Node test across batches | The same entity keeps the same alias within one request |
| Gateway bounds | Node test | 1–25 records, question length limit, 16,000-character frontend cap |
| Endpoint policy | Node tests + Rust review | HTTPS or loopback HTTP only; URL credentials rejected; redirects disabled |
| Consent | BEACON tests | Denial makes no host call; approval forwards the exact question and a cloned selection |
| Agent gating | BEACON tests + Rust review | Requires imported evidence; denial prevents `agent_run`; empty tool policy means the fixed read-only allow-list |
| Agent limits | Rust review + unit tests | 12 iterations, 24 tool calls, 6 per turn, 12k characters per result, 2 MiB response |
| Cloud minimization | Rust review | Non-loopback requests minimize the case snapshot, minimize findings and withhold IOC values |
| Local inference | Ignored Rust test with a real GGUF | Engine started, served a completion and returned usage |

## What was not evaluated

- Detection precision, recall, false-positive rate or calibration.
- Hallucination rate, citation accuracy or refusal quality of any model.
- Prompt-injection resistance against adversarial evidence beyond design review.
- Answer quality across providers, models, quantizations or context lengths.
- Latency, throughput or cost under sustained load.
- Multilingual behaviour.
- Whether AI findings correspond to real incidents.
- Any comparison against analyst ground truth.

## Session metrics shown in the app

The AI Evaluation Center derives its numbers from the current workspace only:

- Number of AI requests and errors observed in this session.
- Round-trip latency per request when measured.
- Token usage when the provider returns a `usage` object.
- Agent iterations and tool-call counts from HELM outcomes.

These are operational counters, not quality scores. They are not persisted as a benchmark and are not comparable across machines.

## Honest reporting rules

1. Do not describe AI output as a finding, conclusion or attribution. It is unverified analyst assistance.
2. Do not claim a model was evaluated unless a labelled dataset and a reproducible procedure exist.
3. Do not present token counts or latency as quality evidence.
4. Do not claim cloud-provider behaviour was tested when only mock servers were used.
5. Keep the "unverified" label on AI output in the UI and in reports.

## Recommended evaluation work

1. Build a labelled corpus of synthetic and consented email incidents with per-event ground truth.
2. Measure rule precision/recall separately from model performance.
3. Define a citation-accuracy metric: does every concrete claim reference an existing evidence ID?
4. Measure prompt-injection success rate with a fixed adversarial set.
5. Evaluate at least one local GGUF and one remote provider with identical prompts.
6. Record hardware, model hash, quantization, context size and sampling parameters for every run.
7. Publish failures, not only successes.

Until these exist, MailSonar's AI features should be described as **assistive and unverified**.
