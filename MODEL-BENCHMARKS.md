# MailSonar — Model and Engine Benchmarks

## Scope

This document records the bundled inference engine, the model used for the smoke test, and the timings observed in one local run. It is **not** a model-quality or throughput benchmark.

## Bundled engine

| Property | Value |
|----------|-------|
| Engine | llama.cpp `llama-server` |
| Build | b11934 |
| Archive | `llama-b11934-bin-win-cpu-x64.zip` |
| Platform | Windows x64, CPU build (runtime CPU dispatch via `ggml-cpu-*.dll`) |
| Archive SHA-256 | `A66878DDF32A2D9349BB66D3FB8A1D6D2A8187C249900276693EE105B66B2DC1` |
| Bundled size | 45,675,616 bytes, 26 files |
| License | llama.cpp MIT; LLVM OpenMP runtime under the LLVM exception |
| Upstream | https://github.com/ggml-org/llama.cpp/releases/tag/b11934 |

Only files required by `llama-server` are bundled. `llama-cli`, `llama-bench`, quantization tools and the RPC server are omitted.

The archive came from a local build cache. The hash was computed from the archive at packaging time but was not re-downloaded from GitHub in this session. Verify it against the upstream release before redistribution.

## Engine discovery order

1. Tauri resource directory (`engine/` next to the installed app)
2. Application-data `engine/` directory
3. Directory containing the executable
4. `CARGO_MANIFEST_DIR/engine` (debug builds only)
5. `MAILDFIR_LLAMA_SERVER` environment variable

The engine is started on `127.0.0.1` with a per-run random API key. It never binds a public interface.

## Test model

| Property | Value |
|----------|-------|
| Model | Qwen2.5-0.5B-Instruct GGUF |
| File size | 491,400,032 bytes |
| SHA-256 | `74A4DA8C9FDBCD15BD1F6D01D621410D31C6FC00986F5EB687824E7B93D7A9DB` |
| Bundled with the app | No |
| Source | Local test file; upstream model is published by the Qwen project under Apache-2.0 |

The model is **not** shipped in the installer. Users import their own GGUF into the app-data model directory.

## Measured smoke test

Run through the production `spawn_engine` path with the bundled engine and the test GGUF:

| Metric | Value |
|--------|-------|
| Engine ready | 1,610 ms |
| Completion wall time | 268 ms |
| Prompt tokens | 36 |
| Completion tokens | 4 |
| Output | `ENGINE-OK` |
| Test | `bundled_engine_serves_a_real_completion` (`#[ignore]`, run manually) |

A separate standalone check of the slimmed engine directory returned `SLIM-OK` in 365 ms with 42 tokens.

These are single-run smoke measurements on an unrecorded host CPU. They show that the engine starts, accepts an authenticated request and returns a completion. They do **not** establish throughput, memory use, context-scaling behaviour or quality.

## Not benchmarked

- Tokens per second under sustained load.
- Prompt-processing throughput at 4k, 8k, 16k or 32k context.
- Memory footprint per model size or quantization.
- GPU offload (the bundled build is CPU-only; GPU layers are configurable but no GPU backend is bundled).
- Multi-model concurrency.
- Model quality, instruction following, citation accuracy or hallucination rate.
- Comparison with other engines or providers.

## Configuration limits

| Setting | Allowed range |
|---------|---------------|
| Port | 1024–65535 |
| Context size | 512–32768 |
| Threads | 1–64 |
| GPU layers | 0–200 |

## Reproduction

```powershell
$env:MAILDFIR_TEST_GGUF = "C:\path\to\qwen2.5-0.5b-instruct.gguf"
cargo test --manifest-path src-tauri/Cargo.toml bundled_engine_serves_a_real_completion -- --ignored --nocapture
```

Record the host CPU, RAM, model hash, quantization, context size and sampling parameters with any future result.
