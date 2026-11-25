//! Managed local inference engine and model management.
//!
//! The application never downloads or executes an inference binary on its own.
//! A trusted, version-pinned `llama-server` must be placed in the application
//! resource directory (`engine/`) or the user model directory (`engine/`).
//! All process arguments are fixed and bounded; no shell is used.
//!
//! Process status is not inference readiness. Readiness is probed separately.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

use super::err;

type Res<T> = Result<T, String>;

const MAX_MODEL_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MODEL_SCAN_LIMIT: usize = 500;
const HF_API_MAX: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub struct Engine(pub Mutex<EngineInner>);

#[derive(Default)]
pub struct EngineInner {
    child: Option<Child>,
    endpoint: Option<String>,
    key: Option<String>,
    model: Option<String>,
    port: Option<u16>,
    started_at: Option<String>,
    model_path: Option<String>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Ok(slot) = self.0.get_mut() {
            if let Some(mut child) = slot.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct Downloads(pub Arc<Mutex<HashMap<String, Arc<AtomicU8>>>>);

#[derive(Serialize)]
pub struct HardwareInfo {
    os: String,
    arch: String,
    logical_cores: usize,
    total_ram_mb: u64,
    accelerators: Vec<String>,
    recommended_threads: u32,
    recommended_context: u32,
    recommended_gpu_layers: u32,
    notes: Vec<String>,
}

#[derive(Serialize)]
pub struct ModelFile {
    id: String,
    name: String,
    path: String,
    bytes: u64,
    modified: u64,
}

#[derive(Serialize)]
pub struct EngineStart {
    endpoint: String,
    key: String,
    model: String,
    port: u16,
    ready: bool,
}

#[derive(Serialize)]
pub struct EngineStatus {
    running: bool,
    ready: bool,
    endpoint: Option<String>,
    model: Option<String>,
    port: Option<u16>,
    started_at: Option<String>,
    detail: String,
}

#[derive(Serialize)]
pub struct Readiness {
    ready: bool,
    running: bool,
    elapsed_ms: u64,
    detail: String,
}

#[derive(Serialize)]
pub struct EngineInfo {
    resource_dir: String,
    app_data_dir: String,
    expected_resource_binary: String,
    expected_user_binary: String,
    binary_found: bool,
    binary_path: Option<String>,
    version: Option<String>,
    notes: Vec<String>,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn app_models_dir(app: &AppHandle) -> Res<PathBuf> {
    let dir = app.path().app_data_dir().map_err(err)?.join("models");
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir)
}

fn engine_binary(app: &AppHandle) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    let mut candidates = Vec::new();
    if let Ok(root) = app.path().resource_dir() {
        candidates.push(root.join("engine").join(name));
    }
    if let Ok(data) = app.path().app_data_dir() {
        candidates.push(data.join("engine").join(name));
    }
    // `tauri dev` runs the binary from target/debug and does not stage the
    // resource directory, so also look next to the executable and in the
    // crate's own engine/ folder while debugging.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("engine").join(name));
        }
    }
    #[cfg(debug_assertions)]
    {
        candidates.push(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("engine")
                .join(name),
        );
    }
    if let Ok(explicit) = std::env::var("MAILDFIR_LLAMA_SERVER") {
        if !explicit.trim().is_empty() {
            candidates.push(PathBuf::from(explicit));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn valid_port(port: u16) -> bool {
    (1024..=65535).contains(&port)
}

fn valid_key(key: &str) -> bool {
    (32..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn valid_model_path(path: &Path) -> Res<()> {
    if !path.is_file() {
        return Err("Select an existing GGUF file".into());
    }
    if path.extension().and_then(|s| s.to_str()) != Some("gguf") {
        return Err("Model must have a .gguf extension".into());
    }
    let bytes = std::fs::metadata(path).map_err(err)?.len();
    if bytes == 0 || bytes > MAX_MODEL_BYTES {
        return Err("Model file size is not supported".into());
    }
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(err)?;
    if &magic != b"GGUF" {
        return Err("Invalid GGUF signature".into());
    }
    Ok(())
}

fn scan_models(dir: &Path, root: &Path, out: &mut Vec<ModelFile>, depth: usize) {
    if depth > 4 || out.len() >= MODEL_SCAN_LIMIT {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= MODEL_SCAN_LIMIT {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            scan_models(&path, root, out, depth + 1);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("gguf") {
            continue;
        }
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let modified = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(ModelFile {
            id: relative.clone(),
            name: path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or(relative),
            path: path.to_string_lossy().to_string(),
            bytes: meta.len(),
            modified,
        });
    }
}

fn detect_accelerators() -> (Vec<String>, Vec<String>) {
    let mut found = Vec::new();
    let mut notes = Vec::new();
    if cfg!(target_os = "macos") {
        found.push("metal".into());
        notes.push("Metal is the only supported macOS acceleration path.".into());
    }
    if let Ok(path) = std::env::var("CUDA_PATH") {
        if Path::new(&path).exists() {
            found.push("cuda".into());
        }
    }
    if let Ok(path) = std::env::var("VULKAN_SDK") {
        if Path::new(&path).exists() {
            found.push("vulkan".into());
        }
    }
    #[cfg(windows)]
    {
        if Path::new(r"C:\Windows\System32\vulkan-1.dll").is_file()
            && !found.iter().any(|v| v == "vulkan")
        {
            found.push("vulkan".into());
        }
        if Path::new(r"C:\Windows\System32\nvml.dll").is_file()
            && !found.iter().any(|v| v == "cuda")
        {
            found.push("cuda".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        if Path::new("/dev/nvidia0").exists() {
            found.push("cuda".into());
        }
        if Path::new("/usr/lib/x86_64-linux-gnu/libvulkan.so.1").exists() {
            found.push("vulkan".into());
        }
    }
    if found.is_empty() {
        notes.push("No accelerator library detected; CPU inference remains available.".into());
    } else {
        notes.push("Accelerator libraries are detected, not benchmarked. The bundled llama-server build must include the matching backend.".into());
    }
    (found, notes)
}

#[tauri::command]
pub fn embedded_hardware() -> HardwareInfo {
    let logical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let total_ram_mb = match sysinfo::System::new() {
        Ok(mut system) => {
            system.refresh_memory();
            system.total_memory() / (1024 * 1024)
        }
        Err(_) => 0,
    };
    let (accelerators, notes) = detect_accelerators();
    HardwareInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        logical_cores,
        total_ram_mb,
        accelerators,
        recommended_threads: ((logical_cores / 2).max(1) as u32).min(32),
        recommended_context: 4096,
        recommended_gpu_layers: 0,
        notes,
    }
}

#[tauri::command]
pub fn embedded_engine_info(app: AppHandle) -> Res<EngineInfo> {
    let resource_dir = app.path().resource_dir().map_err(err)?;
    let app_data_dir = app.path().app_data_dir().map_err(err)?;
    let name = if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    let binary = engine_binary(&app);
    let version = binary
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.join("VERSION.txt"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(EngineInfo {
        resource_dir: resource_dir.to_string_lossy().to_string(),
        app_data_dir: app_data_dir.to_string_lossy().to_string(),
        expected_resource_binary: resource_dir.join("engine").join(name).to_string_lossy().to_string(),
        expected_user_binary: app_data_dir.join("engine").join(name).to_string_lossy().to_string(),
        binary_found: binary.is_some(),
        binary_path: binary.map(|p| p.to_string_lossy().to_string()),
        version,
        notes: vec![
            "The application launches without an inference engine or model.".into(),
            "Only a trusted, version-pinned llama-server binary is accepted; the app does not download executables.".into(),
            "Place the binary and its required libraries under engine/ as documented in AI-ENGINE.md.".into(),
        ],
    })
}

#[tauri::command]
pub fn embedded_models(app: AppHandle) -> Res<Vec<ModelFile>> {
    let dir = app_models_dir(&app)?;
    let mut out = Vec::new();
    scan_models(&dir, &dir, &mut out, 0);
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

#[tauri::command]
pub fn embedded_model_hash(path: String) -> Res<String> {
    let path = PathBuf::from(path);
    if path.extension().and_then(|s| s.to_str()) != Some("gguf") {
        return Err("Only GGUF files can be hashed".into());
    }
    let meta = std::fs::metadata(&path).map_err(err)?;
    if meta.len() > MAX_MODEL_BYTES {
        return Err("Model file is too large to hash".into());
    }
    let mut file = std::fs::File::open(&path).map_err(err)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[tauri::command]
pub fn embedded_delete_model(app: AppHandle, path: String) -> Res<()> {
    let root = app_models_dir(&app)?.canonicalize().map_err(err)?;
    let target = PathBuf::from(&path).canonicalize().map_err(err)?;
    if !target.starts_with(&root) || target.extension().and_then(|s| s.to_str()) != Some("gguf") {
        return Err("Only models inside the managed model directory can be deleted".into());
    }
    std::fs::remove_file(target).map_err(err)
}

/// Starts the managed llama.cpp server with the fixed argument set used by the
/// application. Kept separate from `embedded_start` so the real engine can be
/// exercised by a test without a Tauri `AppHandle`.
fn spawn_engine(
    exe: &Path,
    model: &Path,
    key: &str,
    port: u16,
    context: u32,
    threads: u32,
    gpu_layers: u32,
) -> Res<std::process::Child> {
    Command::new(exe)
        .arg("--model")
        .arg(model)
        .arg("--alias")
        .arg("local")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--api-key")
        .arg(key)
        .arg("--ctx-size")
        .arg(context.to_string())
        .arg("--threads")
        .arg(threads.to_string())
        .arg("--n-gpu-layers")
        .arg(gpu_layers.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start llama-server: {e}"))
}

#[tauri::command]
pub fn embedded_start(
    app: AppHandle,
    engine: State<'_, Engine>,
    model_path: String,
    port: u16,
    context: u32,
    threads: u32,
    gpu_layers: u32,
) -> Res<EngineStart> {
    if !valid_port(port) {
        return Err("Port must be between 1024 and 65535".into());
    }
    if !(512..=32768).contains(&context) {
        return Err("Context must be between 512 and 32768".into());
    }
    if !(1..=64).contains(&threads) {
        return Err("Threads must be between 1 and 64".into());
    }
    if gpu_layers > 200 {
        return Err("GPU layers must be at most 200".into());
    }
    let path = PathBuf::from(&model_path)
        .canonicalize()
        .map_err(|e| format!("Model path is not accessible: {e}"))?;
    valid_model_path(&path)?;
    let exe = engine_binary(&app).ok_or_else(|| {
        "Bundled llama-server is missing. Install a trusted engine under the application engine/ directory. See AI-ENGINE.md.".to_string()
    })?;

    let key = {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in Sha256::digest(
            format!(
                "{}:{}:{}",
                now_rfc3339(),
                std::process::id(),
                path.to_string_lossy()
            )
            .as_bytes(),
        )
        .iter()
        {
            let _ = write!(s, "{b:02x}");
        }
        s
    };
    if !valid_key(&key) {
        return Err("Generated engine key failed validation".into());
    }

    let mut slot = engine.0.lock().map_err(|_| "Engine lock failed")?;
    if let Some(child) = slot.child.as_mut() {
        if child.try_wait().map_err(err)?.is_none() {
            return Err("Stop the current model before loading another".into());
        }
    }
    slot.child = None;
    slot.endpoint = None;
    slot.key = None;
    slot.model = None;
    slot.port = None;
    slot.started_at = None;
    slot.model_path = None;

    if let Some(parent) = path.parent() {
        if !parent.is_dir() {
            return Err("Model directory is not accessible".into());
        }
    }

    // Fixed argument set. The upstream binary must support --api-key and --alias.
    let child = spawn_engine(&exe, &path, &key, port, context, threads, gpu_layers)?;

    let endpoint = format!("http://127.0.0.1:{port}/v1/chat/completions");
    slot.child = Some(child);
    slot.endpoint = Some(endpoint.clone());
    slot.key = Some(key.clone());
    slot.model = Some("local".into());
    slot.port = Some(port);
    slot.started_at = Some(now_rfc3339());
    slot.model_path = Some(path.to_string_lossy().to_string());
    Ok(EngineStart {
        endpoint,
        key,
        model: "local".into(),
        port,
        ready: false,
    })
}

async fn probe_engine(endpoint: &str, key: &str) -> (bool, String) {
    let base = endpoint
        .trim_end_matches("/v1/chat/completions")
        .trim_end_matches('/');
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => return (false, e.to_string()),
    };
    let health = format!("{base}/health");
    match client.get(&health).send().await {
        Ok(response) => {
            if response.status().is_success() {
                return (true, "health endpoint ready".into());
            }
            let status = response.status().as_u16();
            if status == 401 || status == 403 {
                // Some builds protect every endpoint. A 401 proves the listener is up.
                return (
                    true,
                    "engine is listening; health endpoint requires authentication".into(),
                );
            }
        }
        Err(e) => return (false, format!("engine is not ready: {e}")),
    }
    // Some builds expose /v1/models but not /health.
    let models = format!("{base}/v1/models");
    let mut request = client.get(&models);
    if !key.is_empty() {
        request = request.bearer_auth(key);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            (true, "model listing endpoint ready".into())
        }
        Ok(response) => (
            false,
            format!("engine not ready: HTTP {}", response.status().as_u16()),
        ),
        Err(e) => (false, format!("engine is not ready: {e}")),
    }
}

#[tauri::command]
pub async fn embedded_status(engine: State<'_, Engine>) -> Res<EngineStatus> {
    let (running, endpoint, key) = {
        let mut slot = engine.0.lock().map_err(|_| "Engine lock failed")?;
        let running = match slot.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    slot.child = None;
                    slot.endpoint = None;
                    slot.key = None;
                    slot.model = None;
                    slot.port = None;
                    slot.started_at = None;
                    slot.model_path = None;
                    return Ok(EngineStatus {
                        running: false,
                        ready: false,
                        endpoint: None,
                        model: None,
                        port: None,
                        started_at: None,
                        detail: format!("engine exited with {status}"),
                    });
                }
                Err(e) => return Err(err(e)),
            },
            None => false,
        };
        (running, slot.endpoint.clone(), slot.key.clone())
    };
    let (ready, detail) = if running {
        match (&endpoint, &key) {
            (Some(endpoint), Some(key)) => probe_engine(endpoint, key).await,
            _ => (
                false,
                "engine process is running; endpoint unavailable".into(),
            ),
        }
    } else {
        (false, "engine is not running".into())
    };
    let slot = engine.0.lock().map_err(|_| "Engine lock failed")?;
    Ok(EngineStatus {
        running,
        ready,
        endpoint: slot.endpoint.clone(),
        model: slot.model.clone(),
        port: slot.port,
        started_at: slot.started_at.clone(),
        detail,
    })
}

#[tauri::command]
pub async fn embedded_wait_ready(
    engine: State<'_, Engine>,
    timeout_ms: Option<u64>,
) -> Res<Readiness> {
    let timeout = timeout_ms.unwrap_or(90_000).clamp(1_000, 180_000);
    let started = Instant::now();
    loop {
        let (running, endpoint, key) = {
            let mut slot = engine.0.lock().map_err(|_| "Engine lock failed")?;
            let running = match slot.child.as_mut() {
                Some(child) => child.try_wait().map_err(err)?.is_none(),
                None => false,
            };
            (running, slot.endpoint.clone(), slot.key.clone())
        };
        if !running {
            return Ok(Readiness {
                ready: false,
                running: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
                detail: "engine process is not running".into(),
            });
        }
        if let (Some(endpoint), Some(key)) = (endpoint, key) {
            let (ready, detail) = probe_engine(&endpoint, &key).await;
            if ready {
                return Ok(Readiness {
                    ready: true,
                    running: true,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    detail,
                });
            }
            if started.elapsed() >= Duration::from_millis(timeout) {
                return Ok(Readiness {
                    ready: false,
                    running: true,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    detail,
                });
            }
        }
        if started.elapsed() >= Duration::from_millis(timeout) {
            return Ok(Readiness {
                ready: false,
                running,
                elapsed_ms: started.elapsed().as_millis() as u64,
                detail: "timed out waiting for the engine health endpoint".into(),
            });
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tauri::command]
pub fn embedded_stop(engine: State<'_, Engine>) -> Res<()> {
    let mut slot = engine.0.lock().map_err(|_| "Engine lock failed")?;
    if let Some(mut child) = slot.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    slot.endpoint = None;
    slot.key = None;
    slot.model = None;
    slot.port = None;
    slot.started_at = None;
    slot.model_path = None;
    Ok(())
}

fn allowed_download_host(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    host == "huggingface.co"
        || host.ends_with(".huggingface.co")
        || host == "hf.co"
        || host.ends_with(".hf.co")
}

fn valid_download_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && name.ends_with(".gguf")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn valid_sha256(value: &str) -> bool {
    value.is_empty() || (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Serialize, Clone)]
struct DownloadProgress {
    id: String,
    state: String,
    downloaded: u64,
    total: u64,
    percent: f64,
    message: String,
}

fn emit_progress(app: &AppHandle, progress: DownloadProgress) {
    let _ = app.emit("model://progress", progress);
}

fn hash_file(path: &Path) -> Res<String> {
    let mut file = std::fs::File::open(path).map_err(err)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[tauri::command]
pub fn model_download_control(
    downloads: State<'_, Downloads>,
    id: String,
    action: String,
) -> Res<()> {
    let map = downloads.0.lock().map_err(|_| "Download lock failed")?;
    let control = map.get(&id).ok_or("Unknown download")?;
    match action.as_str() {
        "pause" => control.store(1, Ordering::SeqCst),
        "cancel" => control.store(2, Ordering::SeqCst),
        _ => return Err("Unknown download action".into()),
    }
    Ok(())
}

#[tauri::command]
pub fn model_download_start(
    app: AppHandle,
    downloads: State<'_, Downloads>,
    id: String,
    url: String,
    filename: String,
    expected_sha256: Option<String>,
) -> Res<()> {
    if id.is_empty()
        || id.len() > 120
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err("Invalid download identifier".into());
    }
    let parsed = reqwest::Url::parse(&url).map_err(err)?;
    if !allowed_download_host(&parsed) {
        return Err("Only HTTPS Hugging Face downloads are allowed".into());
    }
    if !valid_download_filename(&filename) {
        return Err("Invalid model filename".into());
    }
    let expected = expected_sha256.unwrap_or_default();
    if !valid_sha256(&expected) {
        return Err("Expected SHA-256 must be 64 hexadecimal characters".into());
    }
    let dir = app_models_dir(&app)?;
    let target = dir.join(&filename);
    if target.exists() && expected.is_empty() {
        return Err("A model with this name already exists".into());
    }

    let control = Arc::new(AtomicU8::new(0));
    {
        let mut map = downloads.0.lock().map_err(|_| "Download lock failed")?;
        if map.contains_key(&id) {
            return Err("This download is already active".into());
        }
        map.insert(id.clone(), control.clone());
    }
    let downloads = downloads.0.clone();
    let app_for_task = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = download_file(&app_for_task, &parsed, &target, &expected, &id, &control).await;
        if let Err(message) = result {
            emit_progress(
                &app_for_task,
                DownloadProgress {
                    id: id.clone(),
                    state: "error".into(),
                    downloaded: std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0),
                    total: 0,
                    percent: 0.0,
                    message,
                },
            );
        }
        if let Ok(mut map) = downloads.lock() {
            map.remove(&id);
        }
    });
    Ok(())
}

async fn download_file(
    app: &AppHandle,
    url: &reqwest::Url,
    target: &Path,
    expected: &str,
    id: &str,
    control: &AtomicU8,
) -> Res<()> {
    if target.exists() && !expected.is_empty() {
        let existing_hash = hash_file(target)?;
        if existing_hash.eq_ignore_ascii_case(expected) {
            let bytes = std::fs::metadata(target).map_err(err)?.len();
            emit_progress(
                app,
                DownloadProgress {
                    id: id.into(),
                    state: "complete".into(),
                    downloaded: bytes,
                    total: bytes,
                    percent: 100.0,
                    message: "existing file matches the expected SHA-256".into(),
                },
            );
            return Ok(());
        }
        // Resume from the current byte count.
    }
    let mut existing = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 6 {
                attempt.error("too many redirects")
            } else if allowed_download_host(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("blocked download redirect")
            }
        }))
        .build()
        .map_err(err)?;
    let mut request = client.get(url.clone());
    if existing > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={existing}-"));
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    let status = response.status();
    if !(status.is_success() || status.as_u16() == 206) {
        return Err(format!("download returned HTTP {}", status.as_u16()));
    }
    if status.as_u16() == 200 && existing > 0 {
        existing = 0;
        std::fs::File::create(target).map_err(err)?;
    }
    let total = response
        .content_length()
        .map(|n| n + existing)
        .unwrap_or(existing);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(target)
        .map_err(err)?;
    let mut downloaded = existing;
    let mut last_emit = Instant::now();
    let mut response = response;
    loop {
        match control.load(Ordering::SeqCst) {
            1 => {
                emit_progress(
                    app,
                    DownloadProgress {
                        id: id.into(),
                        state: "paused".into(),
                        downloaded,
                        total,
                        percent: percent(downloaded, total),
                        message: "paused; press resume to continue".into(),
                    },
                );
                return Ok(());
            }
            2 => {
                drop(file);
                let _ = std::fs::remove_file(target);
                emit_progress(
                    app,
                    DownloadProgress {
                        id: id.into(),
                        state: "cancelled".into(),
                        downloaded: 0,
                        total,
                        percent: 0.0,
                        message: "cancelled; partial file removed".into(),
                    },
                );
                return Ok(());
            }
            _ => {}
        }
        let chunk = response
            .chunk()
            .await
            .map_err(|e| format!("download stream failed: {e}"))?;
        let Some(chunk) = chunk else {
            break;
        };
        use std::io::Write as _;
        file.write_all(&chunk)
            .map_err(|e| format!("write failed: {e}"))?;
        downloaded += chunk.len() as u64;
        if last_emit.elapsed() >= Duration::from_millis(350) {
            emit_progress(
                app,
                DownloadProgress {
                    id: id.into(),
                    state: "downloading".into(),
                    downloaded,
                    total,
                    percent: percent(downloaded, total),
                    message: format!("downloading {downloaded} of {total} bytes"),
                },
            );
            last_emit = Instant::now();
        }
    }
    drop(file);
    if !expected.is_empty() {
        let actual = hash_file(target)?;
        if !actual.eq_ignore_ascii_case(expected) {
            let _ = std::fs::remove_file(target);
            return Err("SHA-256 mismatch; downloaded file was removed".into());
        }
    }
    let bytes = std::fs::metadata(target)
        .map(|m| m.len())
        .unwrap_or(downloaded);
    emit_progress(
        app,
        DownloadProgress {
            id: id.into(),
            state: "complete".into(),
            downloaded: bytes,
            total: bytes.max(total),
            percent: 100.0,
            message: if expected.is_empty() {
                "download complete; no expected checksum was published".into()
            } else {
                "download complete; SHA-256 verified".into()
            },
        },
    );
    Ok(())
}

fn percent(done: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        ((done as f64 / total as f64) * 1000.0).round() / 10.0
    }
}

fn valid_repo(repo: &str) -> bool {
    !repo.is_empty()
        && repo.len() <= 120
        && repo.split('/').count() <= 2
        && repo.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 96
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
}

async fn http_json(url: reqwest::Url) -> Res<Value> {
    if url.scheme() != "https" {
        return Err("Hugging Face API requires HTTPS".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(err)?;
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("catalogue request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "catalogue returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(err)? {
        if body.len() + chunk.len() > HF_API_MAX {
            return Err("catalogue response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(err)
}

#[tauri::command]
pub async fn hf_search(query: String, limit: Option<u32>) -> Res<Value> {
    if query.len() > 100 {
        return Err("Search query is too long".into());
    }
    let limit = limit.unwrap_or(20).clamp(1, 30);
    let mut url = reqwest::Url::parse("https://huggingface.co/api/models").map_err(err)?;
    {
        let mut pairs = url.query_pairs_mut();
        if !query.trim().is_empty() {
            pairs.append_pair("search", query.trim());
        }
        pairs.append_pair("filter", "gguf");
        pairs.append_pair("sort", "downloads");
        pairs.append_pair("direction", "-1");
        pairs.append_pair("limit", &limit.to_string());
    }
    let value = http_json(url).await?;
    let mut items = Vec::new();
    if let Some(rows) = value.as_array() {
        for row in rows.iter().take(limit as usize) {
            let id = row.get("id").and_then(Value::as_str).unwrap_or_default();
            if !valid_repo(id) {
                continue;
            }
            items.push(json!({
                "id": id,
                "downloads": row.get("downloads").and_then(Value::as_u64).unwrap_or(0),
                "likes": row.get("likes").and_then(Value::as_u64).unwrap_or(0),
                "lastModified": row.get("lastModified").and_then(Value::as_str),
                "tags": row.get("tags").cloned().unwrap_or_else(|| json!([])),
            }));
        }
    }
    Ok(json!({"items": items, "source": "huggingface", "query": query}))
}

#[tauri::command]
pub async fn hf_files(repo: String) -> Res<Value> {
    if !valid_repo(&repo) {
        return Err("Invalid Hugging Face repository identifier".into());
    }
    let url = reqwest::Url::parse(&format!(
        "https://huggingface.co/api/models/{repo}/tree/main?recursive=true"
    ))
    .map_err(err)?;
    let value = http_json(url).await?;
    let mut files = Vec::new();
    if let Some(rows) = value.as_array() {
        for row in rows {
            if row.get("type").and_then(Value::as_str) != Some("file") {
                continue;
            }
            let path = row.get("path").and_then(Value::as_str).unwrap_or_default();
            if !path.to_ascii_lowercase().ends_with(".gguf") || path.contains("..") {
                continue;
            }
            let size = row
                .pointer("/lfs/size")
                .and_then(Value::as_u64)
                .or_else(|| row.get("size").and_then(Value::as_u64))
                .unwrap_or(0);
            let sha256 = row
                .pointer("/lfs/oid")
                .and_then(Value::as_str)
                .filter(|s| valid_sha256(s))
                .unwrap_or_default();
            files.push(json!({
                "path": path,
                "bytes": size,
                "sha256": sha256,
                "downloadUrl": format!("https://huggingface.co/{repo}/resolve/main/{path}?download=true"),
            }));
        }
    }
    files.sort_by(|a, b| {
        a.get("bytes")
            .and_then(Value::as_u64)
            .cmp(&b.get("bytes").and_then(Value::as_u64))
    });
    Ok(json!({"repo": repo, "files": files}))
}

#[tauri::command]
pub async fn provider_test(endpoint: String, model: String, key: String) -> Res<Value> {
    let url = super::validate_endpoint(&endpoint)?;
    if model.len() > 200 {
        return Err("Model name is too long".into());
    }
    let models_url = models_url(&url)?;
    let started = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(err)?;
    let mut request = client
        .get(models_url.clone())
        .header("Accept", "application/json");
    if !key.is_empty() {
        request = request.bearer_auth(&key);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("provider connection failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Ok(json!({
            "ok": false,
            "status": status.as_u16(),
            "latencyMs": started.elapsed().as_millis() as u64,
            "host": url.host_str().unwrap_or_default(),
            "models": [],
            "detail": format!("HTTP {}", status.as_u16()),
        }));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(err)? {
        if body.len() + chunk.len() > 1024 * 1024 {
            return Err("Provider model list too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let mut models = Vec::new();
    if let Some(rows) = value.get("data").and_then(Value::as_array) {
        for row in rows.iter().take(2000) {
            if let Some(id) = row.get("id").and_then(Value::as_str) {
                models.push(id.to_string());
            }
        }
    } else if let Some(rows) = value.get("models").and_then(Value::as_array) {
        for row in rows.iter().take(2000) {
            if let Some(id) = row.get("name").and_then(Value::as_str) {
                models.push(id.to_string());
            }
        }
    }
    let listed = models.iter().any(|m| m == &model);
    Ok(json!({
        "ok": true,
        "status": status.as_u16(),
        "latencyMs": started.elapsed().as_millis() as u64,
        "host": url.host_str().unwrap_or_default(),
        "models": models,
        "modelListed": listed,
        "detail": "provider reachable",
    }))
}

fn models_url(endpoint: &reqwest::Url) -> Res<reqwest::Url> {
    let mut url = endpoint.clone();
    let path = url.path().trim_end_matches('/').to_string();
    let base = if let Some(prefix) = path.strip_suffix("/chat/completions") {
        prefix.to_string()
    } else if path.ends_with("/v1") {
        path
    } else if let Some(index) = path.rfind("/v1/") {
        path[..index + 3].to_string()
    } else {
        path
    };
    url.set_path(&format!("{base}/models"));
    url.set_query(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_download_names() {
        assert!(valid_download_filename("model.Q4_K_M.gguf"));
        assert!(!valid_download_filename("../model.gguf"));
        assert!(!valid_download_filename("folder\\model.gguf"));
        assert!(!valid_download_filename("model.bin"));
    }

    #[test]
    fn accepts_only_https_huggingface_hosts() {
        assert!(allowed_download_host(
            &reqwest::Url::parse("https://huggingface.co/a/b/resolve/main/x.gguf").unwrap()
        ));
        assert!(allowed_download_host(
            &reqwest::Url::parse("https://cdn-lfs.huggingface.co/x").unwrap()
        ));
        assert!(!allowed_download_host(
            &reqwest::Url::parse("http://huggingface.co/x").unwrap()
        ));
        assert!(!allowed_download_host(
            &reqwest::Url::parse("https://evil.test/x").unwrap()
        ));
    }

    #[test]
    fn engine_settings_are_bounded() {
        assert!(!valid_port(80));
        assert!(valid_port(18081));
        assert!(!valid_key("short"));
        assert!(valid_key(&"a".repeat(64)));
        assert!(!valid_key(&("a".repeat(64) + "-")));
    }

    #[test]
    fn download_percent_is_bounded() {
        assert_eq!(percent(0, 0), 0.0);
        assert_eq!(percent(50, 100), 50.0);
        assert_eq!(percent(100, 100), 100.0);
    }

    #[test]
    fn provider_models_url_is_derived() {
        let url = reqwest::Url::parse("http://127.0.0.1:11434/v1/chat/completions").unwrap();
        assert_eq!(
            models_url(&url).unwrap().as_str(),
            "http://127.0.0.1:11434/v1/models"
        );
        let url = reqwest::Url::parse("https://api.openai.com/v1").unwrap();
        assert_eq!(
            models_url(&url).unwrap().as_str(),
            "https://api.openai.com/v1/models"
        );
    }

    #[test]
    fn valid_repo_rejects_traversal() {
        assert!(valid_repo("Qwen/Qwen2.5-7B-Instruct-GGUF"));
        assert!(!valid_repo("../etc"));
        assert!(!valid_repo("a/b/c"));
    }

    #[test]
    fn hardware_detection_returns_positive_cores() {
        let info = embedded_hardware();
        assert!(info.logical_cores >= 1);
        assert!(info.recommended_threads >= 1);
    }

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Real inference smoke test against the bundled engine. Ignored by
    /// default because it needs a GGUF file:
    ///   $env:MAILDFIR_TEST_GGUF = "C:\models\model.gguf"
    ///   cargo test bundled_engine_serves_a_real_completion -- --ignored --nocapture
    #[test]
    #[ignore = "needs the bundled llama.cpp engine and a real GGUF model (MAILDFIR_TEST_GGUF)"]
    fn bundled_engine_serves_a_real_completion() {
        let model = std::env::var("MAILDFIR_TEST_GGUF")
            .expect("set MAILDFIR_TEST_GGUF to a real GGUF file");
        let model = PathBuf::from(model).canonicalize().expect("model path");
        valid_model_path(&model).expect("valid model");
        let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("engine")
            .join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
        assert!(exe.is_file(), "bundled engine missing at {}", exe.display());

        let port = 18117u16;
        let key = "testenginekey0000000000000000000001";
        let child = spawn_engine(&exe, &model, key, port, 512, 4, 0).expect("engine start");
        let mut guard = ChildGuard(child);
        let endpoint = format!("http://127.0.0.1:{port}/v1/chat/completions");

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async {
            let started = Instant::now();
            let mut ready = false;
            while started.elapsed() < Duration::from_secs(180) {
                if guard.0.try_wait().expect("wait").is_some() {
                    panic!("engine exited before becoming ready");
                }
                if probe_engine(&endpoint, key).await.0 {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert!(ready, "engine did not become ready within 180 s");
            eprintln!("engine ready after {} ms", started.elapsed().as_millis());

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("client");
            let body = serde_json::json!({
                "model": "local",
                "messages": [{"role": "user", "content": "Reply with exactly: ENGINE-OK"}],
                "max_tokens": 16,
                "temperature": 0,
                "stream": false
            });
            let chat_started = Instant::now();
            let response = client
                .post(&endpoint)
                .bearer_auth(key)
                .json(&body)
                .send()
                .await
                .expect("completion request");
            assert!(response.status().is_success(), "HTTP {}", response.status());
            let value: serde_json::Value = response.json().await.expect("json");
            let content = value["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_string();
            assert!(!content.is_empty(), "empty completion");
            assert!(value["usage"]["total_tokens"].as_u64().unwrap_or(0) > 0);
            eprintln!(
                "completion in {} ms: {content} | usage {}",
                chat_started.elapsed().as_millis(),
                value["usage"]
            );
        });
    }
}
