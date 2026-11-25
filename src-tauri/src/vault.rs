use super::{err, hash, read_limited, Res, MAX_BYTES};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tauri::Manager;
fn db(app: &tauri::AppHandle) -> Res<Connection> {
    let dir = app.path().app_data_dir().map_err(err)?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    let c = Connection::open(dir.join("cases.sqlite3")).map_err(err)?;
    c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS evidence(hash TEXT PRIMARY KEY, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL);").map_err(err)?;
    Ok(c)
}
fn journal(c: &Connection, payload: &str) -> Res<()> {
    let previous = c
        .query_row(
            "SELECT digest FROM journal ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    let digest = hash(format!("{previous}\n{payload}").as_bytes());
    c.execute(
        "INSERT INTO journal(previous,payload,digest) VALUES (?1,?2,?3)",
        params![previous, payload, digest],
    )
    .map_err(err)?;
    Ok(())
}
#[tauri::command]
pub fn preserve(app: tauri::AppHandle, path: String, expected: String) -> Res<()> {
    let bytes = read_limited(std::fs::File::open(path).map_err(err)?, MAX_BYTES)?;
    if hash(&bytes) != expected {
        return Err("Evidence changed since parsing".into());
    }
    let mut c = db(&app)?;
    let tx = c.transaction().map_err(err)?;
    tx.execute(
        "INSERT OR IGNORE INTO evidence VALUES (?1,?2)",
        params![expected, bytes],
    )
    .map_err(err)?;
    journal(
        &tx,
        &json!({"action":"preserve","hash":expected,"time":chrono::Utc::now().to_rfc3339()})
            .to_string(),
    )?;
    tx.commit().map_err(err)
}
#[tauri::command]
pub fn store_case(app: tauri::AppHandle, id: String, body: Value) -> Res<()> {
    if id.trim().is_empty() || id.len() > 200 {
        return Err("Invalid case ID".into());
    }
    let s = body.to_string();
    if s.len() > 128 * 1024 * 1024 {
        return Err("Case too large".into());
    }
    let mut c = db(&app)?;
    let tx = c.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO cases VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
        params![id, s],
    )
    .map_err(err)?;
    journal(&tx,&json!({"action":"save_case","id":id,"body_hash":hash(s.as_bytes()),"time":chrono::Utc::now().to_rfc3339()}).to_string())?;
    tx.commit().map_err(err)
}
#[tauri::command]
pub fn get_case(app: tauri::AppHandle, id: String) -> Res<Value> {
    let c = db(&app)?;
    let s: String = c
        .query_row("SELECT body FROM cases WHERE id=?1", [id], |r| r.get(0))
        .map_err(err)?;
    serde_json::from_str(&s).map_err(err)
}
#[tauri::command]
pub fn verify_vault(app: tauri::AppHandle) -> Res<Value> {
    let c = db(&app)?;
    let mut stmt = c.prepare("SELECT hash,bytes FROM evidence").map_err(err)?;
    let mut rows = stmt.query([]).map_err(err)?;
    let mut bad = Vec::new();
    let mut count = 0;
    while let Some(r) = rows.next().map_err(err)? {
        let h: String = r.get(0).map_err(err)?;
        let b: Vec<u8> = r.get(1).map_err(err)?;
        count += 1;
        if hash(&b) != h {
            bad.push(h)
        }
    }
    let mut stmt = c
        .prepare("SELECT previous,payload,digest FROM journal ORDER BY seq")
        .map_err(err)?;
    let mut rows = stmt.query([]).map_err(err)?;
    let mut last = String::new();
    let mut valid = true;
    let mut entries = 0;
    while let Some(r) = rows.next().map_err(err)? {
        let p: String = r.get(0).map_err(err)?;
        let v: String = r.get(1).map_err(err)?;
        let d: String = r.get(2).map_err(err)?;
        entries += 1;
        if p != last || hash(format!("{p}\n{v}").as_bytes()) != d {
            valid = false
        }
        last = d;
    }
    Ok(
        json!({"evidence_count":count,"mismatched_hashes":bad,"journal_entries":entries,"journal_consistent":valid,"journal_head":last,"warning":"Local hash chain is not immutable; externally anchor the head."}),
    )
}
