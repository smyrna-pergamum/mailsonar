//! Automatic discovery and self-test of local AI models.
//!
//! Discovery only reads: it probes well-known loopback ports of local inference
//! servers (`GET /v1/models`) and scans well-known model folders for GGUF files
//! (checking the GGUF signature). Nothing is downloaded, started or modified.
//!
//! The self-test sends fixed synthetic prompts (never case evidence) to measure
//! whether a model answers, how fast, and whether it can call tools for HELM.

use serde::Serialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

use super::err;

type Res<T> = Result<T, String>;

const MAX_FILES: usize = 200;
const MAX_DEPTH: usize = 6;
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// (display name, port, managed-by-MailSonar)
const SERVERS: &[(&str, u16, bool)] = &[
    ("Ollama", 11434, false),
    ("LM Studio", 1234, false),
    ("llama.cpp server", 8080, false),
    ("vLLM", 8000, false),
    ("KoboldCpp", 5001, false),
    ("text-generation-webui", 5000, false),
    ("Jan", 1337, false),
    ("GPT4All", 4891, false),
    ("LocalAI", 8081, false),
    ("MailSonar engine", 18081, true),
];

#[derive(Serialize, Clone)]
pub struct LocalServer {
    name: String,
    endpoint: String,
    port: u16,
    reachable: bool,
    needs_key: bool,
    managed: bool,
    models: Vec<String>,
    latency_ms: u64,
    detail: String,
}

#[derive(Serialize, Clone)]
pub struct LocalFile {
    name: String,
    path: String,
    folder: String,
    source: String,
    bytes: u64,
    managed: bool,
}

#[derive(Serialize)]
pub struct Discovery {
    servers: Vec<LocalServer>,
    files: Vec<LocalFile>,
    scanned_folders: Vec<String>,
    duration_ms: u64,
}

fn client(timeout: Duration, loopback: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    // Loopback probes must not go through a corporate proxy; remote tests must.
    let builder = if loopback {
        builder.no_proxy()
    } else {
        builder
    };
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// Read a response body with a hard size cap (a non-AI service on a probed
/// port could stream an unbounded body).
async fn capped(mut response: reqwest::Response, limit: usize) -> Res<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(err)? {
        if body.len() + chunk.len() > limit {
            return Err("response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn model_ids(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(rows) = value.get("data").and_then(Value::as_array) {
        out.extend(
            rows.iter()
                .filter_map(|r| r.get("id").and_then(Value::as_str))
                .map(str::to_string),
        );
    }
    if let Some(rows) = value.get("models").and_then(Value::as_array) {
        out.extend(
            rows.iter()
                .filter_map(|r| {
                    r.get("name")
                        .or_else(|| r.get("model"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string),
        );
    }
    out.sort();
    out.dedup();
    out.truncate(200);
    out
}

async fn probe(name: &str, port: u16, managed: bool) -> LocalServer {
    let endpoint = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let started = Instant::now();
    let mut server = LocalServer {
        name: name.into(),
        endpoint,
        port,
        reachable: false,
        needs_key: false,
        managed,
        models: Vec::new(),
        latency_ms: 0,
        detail: "not running".into(),
    };
    let http = client(PROBE_TIMEOUT, true);
    let result = http
        .get(format!("http://127.0.0.1:{port}/v1/models"))
        .header("Accept", "application/json")
        .send()
        .await;
    server.latency_ms = started.elapsed().as_millis() as u64;
    let Ok(response) = result else {
        return server;
    };
    server.reachable = true;
    let status = response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        server.needs_key = true;
        server.detail = "running; API key required".into();
        return server;
    }
    if !status.is_success() {
        server.detail = format!("running; /v1/models returned HTTP {}", status.as_u16());
        return server;
    }
    let Ok(bytes) = capped(response, 1024 * 1024).await else {
        server.detail = "model list too large or unreadable".into();
        return server;
    };
    let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    server.models = model_ids(&value);
    // Ollama also lists pulled models here, with friendlier names.
    if port == 11434 && server.models.is_empty() {
        if let Ok(r) = http.get("http://127.0.0.1:11434/api/tags").send().await {
            if let Ok(body) = capped(r, 1024 * 1024).await {
                if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                    server.models = model_ids(&v);
                }
            }
        }
    }
    server.detail = format!("running; {} model(s)", server.models.len());
    server
}

fn is_gguf(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|_| &magic == b"GGUF")
        .unwrap_or(false)
}

fn scan(dir: &Path, source: &str, managed: bool, depth: usize, out: &mut Vec<LocalFile>) {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if (name.starts_with('.') && depth > 0) || name == "node_modules" {
                continue;
            }
            scan(&path, source, managed, depth + 1, out);
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let lower = name.to_lowercase();
        if !lower.ends_with(".gguf") || lower.contains("mmproj") {
            continue;
        }
        // Only the first shard of a split model can be loaded.
        if lower.contains("-of-0") && !lower.contains("-00001-of-") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() < 1024 * 1024 || !is_gguf(&path) {
            continue;
        }
        if out.iter().any(|f| Path::new(&f.path) == path) {
            continue;
        }
        out.push(LocalFile {
            name,
            path: path.to_string_lossy().to_string(),
            folder: path
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            source: source.into(),
            bytes: meta.len(),
            managed,
        });
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

/// Well-known model folders of popular local AI apps, plus the user's own.
pub fn candidate_folders(app_models: Option<PathBuf>) -> Vec<(String, PathBuf, bool)> {
    let home = env_path("USERPROFILE").or_else(|| env_path("HOME"));
    let mut out: Vec<(String, PathBuf, bool)> = Vec::new();
    if let Some(dir) = app_models {
        out.push(("MailSonar".into(), dir, true));
    }
    if let Some(hf) = env_path("HF_HOME") {
        out.push(("Hugging Face cache".into(), hf.join("hub"), false));
    }
    if let Some(home) = &home {
        for (source, rel) in [
            ("LM Studio", ".lmstudio/models"),
            ("LM Studio", ".cache/lm-studio/models"),
            ("Hugging Face cache", ".cache/huggingface/hub"),
            ("Jan", "jan/models"),
            ("llama.cpp", ".cache/llama.cpp"),
            ("Models folder", "models"),
            ("Downloads", "Downloads"),
        ] {
            out.push((source.into(), home.join(rel), false));
        }
    }
    if let Some(roaming) = env_path("APPDATA") {
        out.push(("Jan".into(), roaming.join("Jan/data/models"), false));
    }
    if let Some(local) = env_path("LOCALAPPDATA") {
        out.push(("GPT4All".into(), local.join("nomic.ai/GPT4All"), false));
    }
    out.retain(|(_, p, _)| p.is_dir());
    out
}

#[tauri::command]
pub async fn discover_local_ai(app: AppHandle) -> Res<Discovery> {
    let started = Instant::now();
    let probes = SERVERS
        .iter()
        .map(|(name, port, managed)| probe(name, *port, *managed));
    let servers: Vec<LocalServer> = futures_join(probes.collect()).await;
    let app_models = app.path().app_data_dir().ok().map(|d| d.join("models"));
    let folders = candidate_folders(app_models);
    let scanned: Vec<String> = folders
        .iter()
        .map(|(_, p, _)| p.to_string_lossy().to_string())
        .collect();
    let files = tauri::async_runtime::spawn_blocking(move || {
        let mut files = Vec::new();
        for (source, dir, managed) in &folders {
            scan(dir, source, *managed, 0, &mut files);
        }
        files.sort_by(|a, b| {
            a.managed
                .cmp(&b.managed)
                .reverse()
                .then(a.name.cmp(&b.name))
        });
        files
    })
    .await
    .map_err(err)?;
    Ok(Discovery {
        servers: servers.into_iter().filter(|s| s.reachable).collect(),
        files,
        scanned_folders: scanned,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Run probes concurrently without pulling in the `futures` crate.
async fn futures_join<F: std::future::Future<Output = LocalServer> + Send + 'static>(
    futures: Vec<F>,
) -> Vec<LocalServer> {
    let handles: Vec<_> = futures
        .into_iter()
        .map(tauri::async_runtime::spawn)
        .collect();
    let mut out = Vec::new();
    for handle in handles {
        if let Ok(server) = handle.await {
            out.push(server);
        }
    }
    out
}

fn strip_thinking(text: &str) -> String {
    let mut out = text.to_string();
    while let (Some(s), Some(e)) = (out.find("<think>"), out.find("</think>")) {
        if e < s {
            break;
        }
        out.replace_range(s..e + 8, "");
    }
    out.trim().to_string()
}

async fn chat(
    http: &reqwest::Client,
    url: &reqwest::Url,
    key: &str,
    body: &Value,
) -> Res<(Value, u64)> {
    let started = Instant::now();
    let mut request = http.post(url.clone()).json(body);
    if !key.is_empty() {
        request = request.bearer_auth(key);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = response.status();
    let bytes = capped(response, 2 * 1024 * 1024).await?;
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    let value = serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok((value, started.elapsed().as_millis() as u64))
}

/// Self-test with synthetic prompts only. Reports chat, speed and tool calling.
#[tauri::command]
pub async fn ai_selftest(endpoint: String, model: String, key: String) -> Res<Value> {
    let url = super::validate_endpoint(&endpoint)?;
    if model.trim().is_empty() || model.len() > 200 {
        return Err("Model name is required".into());
    }
    let loopback = matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("::1")
    );
    let http = client(
        Duration::from_secs(if loopback { 600 } else { 120 }),
        loopback,
    );
    let mut report = json!({
        "endpoint_host": url.host_str().unwrap_or_default(),
        "model": model,
        "chat_ok": false,
        "native_tools": false,
        "text_tools": false,
        "helm_ready": false,
    });

    let chat_body = json!({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a test probe. Answer with the requested text only. /no_think"},
            {"role": "user", "content": "Reply with exactly: MAILSONAR-OK"}
        ],
        "max_tokens": 256,
        "temperature": 0,
        "stream": false,
    });
    match chat(&http, &url, &key, &chat_body).await {
        Ok((value, ms)) => {
            let content = strip_thinking(
                value
                    .pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            let tokens = value
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            report["chat_ok"] = json!(!content.is_empty());
            report["chat_exact"] = json!(content.contains("MAILSONAR-OK"));
            report["chat_ms"] = json!(ms);
            report["reply"] = json!(content.chars().take(120).collect::<String>());
            if tokens > 0 && ms > 0 {
                report["tokens_per_second"] =
                    json!(((tokens as f64) / (ms as f64 / 1000.0) * 10.0).round() / 10.0);
            }
        }
        Err(e) => {
            report["error"] = json!(e);
            return Ok(report);
        }
    }

    let tool_body = json!({
        "model": model,
        "messages": [
            {"role": "system", "content": "You can call tools. /no_think"},
            {"role": "user", "content": "How many records does the case have? Use the tool."}
        ],
        "tools": [{"type": "function", "function": {
            "name": "event_stats",
            "description": "Count records in the current case.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": false}
        }}],
        "tool_choice": "auto",
        "max_tokens": 512,
        "temperature": 0,
        "stream": false,
    });
    match chat(&http, &url, &key, &tool_body).await {
        Ok((value, ms)) => {
            let message = value
                .pointer("/choices/0/message")
                .cloned()
                .unwrap_or_default();
            let native = message
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| {
                    calls.iter().any(|c| {
                        c.pointer("/function/name").and_then(Value::as_str) == Some("event_stats")
                    })
                });
            let text = message.get("content").and_then(Value::as_str).unwrap_or("");
            report["native_tools"] = json!(native);
            report["text_tools"] = json!(!native && text.contains("event_stats"));
            report["tools_ms"] = json!(ms);
        }
        Err(e) => report["tools_error"] = json!(e),
    }
    let ready = report["chat_ok"] == true
        && (report["native_tools"] == true || report["text_tools"] == true);
    report["helm_ready"] = json!(ready);
    report["verdict"] = json!(if report["native_tools"] == true {
        "Ready for HELM: native tool calling works."
    } else if report["text_tools"] == true {
        "Usable for HELM via the text tool protocol; native tool calling not detected."
    } else if report["chat_ok"] == true {
        "Chat works, but no tool calls: HELM relies on skill preloads; use a larger or tool-capable model for best results."
    } else {
        "The model did not answer."
    });
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_ids_from_openai_and_ollama_shapes() {
        assert_eq!(
            model_ids(&json!({"data":[{"id":"b"},{"id":"a"}]})),
            vec!["a", "b"]
        );
        assert_eq!(
            model_ids(&json!({"models":[{"name":"qwen3:4b"}]})),
            vec!["qwen3:4b"]
        );
        assert!(model_ids(&json!({})).is_empty());
    }

    #[test]
    fn scan_finds_only_real_gguf_files() {
        let dir = std::env::temp_dir().join(format!("ms-scan-{}", std::process::id()));
        let nested = dir.join("org").join("repo");
        std::fs::create_dir_all(&nested).unwrap();
        let mut good = b"GGUF".to_vec();
        good.resize(2 * 1024 * 1024, 0);
        std::fs::write(nested.join("model-Q4_K_M.gguf"), &good).unwrap();
        std::fs::write(nested.join("fake.gguf"), vec![0u8; 2 * 1024 * 1024]).unwrap();
        std::fs::write(nested.join("mmproj-f16.gguf"), &good).unwrap();
        std::fs::write(nested.join("big-00002-of-00002.gguf"), &good).unwrap();
        let mut out = Vec::new();
        scan(&dir, "test", false, 0, &mut out);
        let names: Vec<_> = out.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["model-Q4_K_M.gguf"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn strip_thinking_removes_reasoning() {
        assert_eq!(
            strip_thinking("<think>x</think>\nMAILSONAR-OK"),
            "MAILSONAR-OK"
        );
    }
}
