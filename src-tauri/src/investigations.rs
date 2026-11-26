//! Tauri commands for large investigations (streamed SQLite stores).

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

use super::inv_store::{self, InvSummary};
use super::{err, inv_correlate, inv_ingest};

type Res<T> = Result<T, String>;

/// Running imports, by investigation id.
#[derive(Default)]
pub struct InvJobs(pub Mutex<HashMap<String, Arc<AtomicBool>>>);

fn path_for(app: &AppHandle, id: &str) -> Res<std::path::PathBuf> {
    let path = inv_store::db_path(&inv_store::dir(app)?, id)?;
    if !path.exists() {
        return Err("Investigation not found".into());
    }
    Ok(path)
}

#[tauri::command]
pub fn inv_list(app: AppHandle) -> Res<Vec<InvSummary>> {
    let dir = inv_store::dir(&app)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(err)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sqlite3") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if inv_store::valid_id(&id) {
            if let Ok(summary) = inv_store::summary_of(&path, &id) {
                out.push(summary);
            }
        }
    }
    out.sort_by(|a, b| b.created.cmp(&a.created));
    Ok(out)
}

#[tauri::command]
pub fn inv_create(app: AppHandle, name: String) -> Res<InvSummary> {
    let name = name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err("Name must be 1-120 characters".into());
    }
    let slug: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(40)
        .collect();
    let id = format!(
        "{}-{}",
        if slug.is_empty() { "case".into() } else { slug },
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    let path = inv_store::db_path(&inv_store::dir(&app)?, &id)?;
    let conn = inv_store::open(&path)?;
    inv_store::set_meta(&conn, "name", name)?;
    inv_store::set_meta(&conn, "created", &chrono::Utc::now().to_rfc3339())?;
    drop(conn);
    inv_store::summary_of(&path, &id)
}

#[tauri::command]
pub fn inv_delete(app: AppHandle, jobs: State<'_, InvJobs>, id: String) -> Res<()> {
    if jobs.0.lock().map_err(|_| "lock")?.contains_key(&id) {
        return Err("Stop the running import first".into());
    }
    let path = path_for(&app, &id)?;
    for suffix in ["", "-wal", "-shm"] {
        let p = std::path::PathBuf::from(format!("{}{suffix}", path.to_string_lossy()));
        if p.exists() {
            std::fs::remove_file(p).map_err(err)?;
        }
    }
    Ok(())
}

/// Start a background import of several files; progress arrives as
/// `inv://progress` events and completion as `inv://done`.
#[tauri::command]
pub fn inv_import(
    app: AppHandle,
    jobs: State<'_, InvJobs>,
    id: String,
    paths: Vec<String>,
    batch_size: Option<usize>,
) -> Res<Value> {
    let path = path_for(&app, &id)?;
    if paths.is_empty() || paths.len() > 500 {
        return Err("Select 1-500 files".into());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut map = jobs.0.lock().map_err(|_| "lock")?;
        if map.contains_key(&id) {
            return Err("An import is already running for this investigation".into());
        }
        map.insert(id.clone(), cancel.clone());
    }
    let size = batch_size
        .unwrap_or_else(inv_ingest::adaptive_batch_size)
        .clamp(inv_ingest::MIN_BATCH, inv_ingest::MAX_BATCH);
    let workers = inv_ingest::worker_count();
    let app2 = app.clone();
    let id2 = id.clone();
    std::thread::spawn(move || {
        let emit = |v: Value| {
            let _ = app2.emit(
                "inv://progress",
                json!({"investigation": id2, "progress": v}),
            );
        };
        let mut reports = Vec::new();
        let mut error = None;
        match inv_store::open(&path) {
            Ok(mut conn) => {
                for (i, file) in paths.iter().enumerate() {
                    if cancel.load(Ordering::SeqCst) {
                        break;
                    }
                    emit(
                        json!({"state": "starting", "file": file, "index": i + 1, "files": paths.len(), "batch_size": size, "workers": workers}),
                    );
                    match inv_ingest::import_file(
                        &mut conn,
                        std::path::Path::new(file),
                        size,
                        workers,
                        &cancel,
                        &emit,
                    ) {
                        Ok(report) => reports.push(report),
                        Err(e) => {
                            emit(json!({"state": "failed", "file": file, "error": e}));
                            error = Some(e);
                        }
                    }
                }
                emit(json!({"state": "correlating"}));
                let started = std::time::Instant::now();
                let correlated = inv_correlate::correlate(&mut conn);
                emit(
                    json!({"state": "correlated", "findings": correlated.as_ref().ok(), "ms": started.elapsed().as_millis() as u64}),
                );
                if let Err(e) = correlated {
                    error = Some(e);
                }
            }
            Err(e) => error = Some(e),
        }
        if let Some(state) = app2.try_state::<InvJobs>() {
            if let Ok(mut map) = state.0.lock() {
                map.remove(&id2);
            }
        }
        let _ = app2.emit("inv://done", json!({"investigation": id2, "reports": reports, "error": error, "cancelled": cancel.load(Ordering::SeqCst)}));
    });
    Ok(json!({"started": true, "batch_size": size, "workers": workers}))
}

#[tauri::command]
pub fn inv_cancel(jobs: State<'_, InvJobs>, id: String) -> Res<bool> {
    let map = jobs.0.lock().map_err(|_| "lock")?;
    Ok(map
        .get(&id)
        .map(|c| c.store(true, Ordering::SeqCst))
        .is_some())
}

#[tauri::command]
pub fn inv_running(jobs: State<'_, InvJobs>) -> Res<Vec<String>> {
    Ok(jobs.0.lock().map_err(|_| "lock")?.keys().cloned().collect())
}

#[tauri::command]
pub async fn inv_overview(app: AppHandle, id: String) -> Res<Value> {
    let path = path_for(&app, &id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let conn = inv_store::open(&path)?;
        let mut overview = inv_store::overview(&conn)?;
        overview["id"] = json!(id);
        overview["name"] = json!(inv_store::meta(&conn, "name"));
        Ok(overview)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn inv_search(
    app: AppHandle,
    id: String,
    q: String,
    field: String,
    deep: bool,
    offset: i64,
    limit: i64,
) -> Res<Value> {
    let path = path_for(&app, &id)?;
    tauri::async_runtime::spawn_blocking(move || {
        inv_store::search(
            &inv_store::open(&path)?,
            &q,
            &field,
            deep,
            offset.max(0),
            limit,
        )
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn inv_findings(
    app: AppHandle,
    id: String,
    severity: String,
    rule: String,
    offset: i64,
    limit: i64,
) -> Res<Value> {
    let path = path_for(&app, &id)?;
    tauri::async_runtime::spawn_blocking(move || {
        inv_store::findings_page(
            &inv_store::open(&path)?,
            &severity,
            &rule,
            offset.max(0),
            limit,
        )
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn inv_events(app: AppHandle, id: String, ids: Vec<String>) -> Res<Value> {
    let path = path_for(&app, &id)?;
    tauri::async_runtime::spawn_blocking(move || {
        Ok(json!(inv_store::events_by_ids(
            &inv_store::open(&path)?,
            &ids
        )?))
    })
    .await
    .map_err(err)?
}

/// Copy a subset (search result, up to 100,000 records) into the regular
/// workspace so the e-mail view, graph and other tools can be used on it.
#[tauri::command]
pub async fn inv_subset(
    app: AppHandle,
    id: String,
    q: String,
    field: String,
    limit: i64,
) -> Res<Value> {
    let path = path_for(&app, &id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let conn = inv_store::open(&path)?;
        let limit = limit.clamp(1, 100_000);
        let mut events = Vec::new();
        let mut offset = 0;
        while (events.len() as i64) < limit {
            let page = inv_store::search(&conn, &q, &field, true, offset, 500)?;
            let rows = page["events"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                break;
            }
            offset += rows.len() as i64;
            events.extend(rows);
        }
        events.truncate(limit as usize);
        Ok(json!({"events": events, "name": inv_store::meta(&conn, "name")}))
    })
    .await
    .map_err(err)?
}
