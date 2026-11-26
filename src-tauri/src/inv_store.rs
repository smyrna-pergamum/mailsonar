//! Investigation store: one SQLite database per large investigation.
//!
//! The in-memory workspace keeps up to `MAX_ROWS` events in the webview. Large
//! cases (hundreds of thousands to millions of events) live here instead: the
//! UI and HELM query them page by page, so memory use stays flat. Original
//! evidence bytes are never modified; every file is hashed before ingest.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

use super::{err, Event, Finding};

type Res<T> = Result<T, String>;

pub const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -65536;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(
  file_id INTEGER PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE,
  bytes INTEGER NOT NULL, profile TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL,
  records INTEGER NOT NULL DEFAULT 0, duplicates INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
  checkpoint INTEGER NOT NULL DEFAULT 0, batches INTEGER NOT NULL DEFAULT 0, batch_size INTEGER NOT NULL DEFAULT 0,
  started TEXT, finished TEXT, ms INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS events(
  rid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, file_id INTEGER NOT NULL, record INTEGER NOT NULL,
  batch INTEGER NOT NULL, ts INTEGER, timestamp TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
  ip TEXT NOT NULL, message_id TEXT NOT NULL, action TEXT NOT NULL, source TEXT NOT NULL,
  content_hash TEXT NOT NULL, data TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ev_hash ON events(content_hash);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_sender ON events(sender);
CREATE INDEX IF NOT EXISTS ev_recipient ON events(recipient);
CREATE INDEX IF NOT EXISTS ev_ip ON events(ip);
CREATE INDEX IF NOT EXISTS ev_mid ON events(message_id);
CREATE INDEX IF NOT EXISTS ev_action ON events(action);
CREATE TABLE IF NOT EXISTS findings(
  fid INTEGER PRIMARY KEY, rule TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL,
  evidence TEXT NOT NULL, event_id TEXT, scope TEXT NOT NULL, batch INTEGER);
CREATE INDEX IF NOT EXISTS f_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS f_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS f_event ON findings(event_id);
CREATE TABLE IF NOT EXISTS failures(file_id INTEGER NOT NULL, record INTEGER NOT NULL, error TEXT NOT NULL);
";

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn dir(app: &AppHandle) -> Res<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(err)?
        .join("investigations");
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir)
}

pub fn db_path(root: &Path, id: &str) -> Res<PathBuf> {
    if !valid_id(id) {
        return Err("Invalid investigation id".into());
    }
    Ok(root.join(format!("{id}.sqlite3")))
}

pub fn open(path: &Path) -> Res<Connection> {
    let conn = Connection::open(path).map_err(err)?;
    conn.execute_batch(SCHEMA).map_err(err)?;
    Ok(conn)
}

pub fn epoch(timestamp: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|d| d.timestamp())
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|d| d.and_utc().timestamp())
        })
}

/// Hash of the normalized fields and raw data: identical events imported twice
/// (the same export loaded again, overlapping exports) are stored once.
pub fn content_hash(e: &Event) -> String {
    super::hash(
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            e.timestamp, e.sender, e.recipient, e.ip, e.message_id, e.action, e.data
        )
        .as_bytes(),
    )
}

pub fn row_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    let data: String = row.get("data")?;
    Ok(Event {
        id: row.get("id")?,
        source: row.get("source")?,
        record: row.get::<_, i64>("record")? as usize,
        timestamp: row.get("timestamp")?,
        sender: row.get("sender")?,
        recipient: row.get("recipient")?,
        ip: row.get("ip")?,
        message_id: row.get("message_id")?,
        action: row.get("action")?,
        data: serde_json::from_str(&data).unwrap_or(Value::Null),
    })
}

pub const EVENT_COLUMNS: &str =
    "id, source, record, timestamp, sender, recipient, ip, message_id, action, data";

#[derive(Serialize)]
pub struct InvSummary {
    pub id: String,
    pub name: String,
    pub created: String,
    pub events: i64,
    pub findings: i64,
    pub files: i64,
    pub bytes: u64,
}

pub fn meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Res<()> {
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )
    .map_err(err)?;
    Ok(())
}

pub fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0)
}

pub fn summary_of(path: &Path, id: &str) -> Res<InvSummary> {
    let conn = open(path)?;
    Ok(InvSummary {
        id: id.to_string(),
        name: meta(&conn, "name").unwrap_or_else(|| id.to_string()),
        created: meta(&conn, "created").unwrap_or_default(),
        events: count(&conn, "SELECT COUNT(*) FROM events"),
        findings: count(&conn, "SELECT COUNT(*) FROM findings"),
        files: count(&conn, "SELECT COUNT(*) FROM files"),
        bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    })
}

pub fn insert_findings(
    tx: &rusqlite::Transaction<'_>,
    findings: &[Finding],
    scope: &str,
    batch: Option<i64>,
) -> Res<()> {
    let mut stmt = tx
        .prepare_cached("INSERT INTO findings(rule,severity,description,evidence,event_id,scope,batch) VALUES(?1,?2,?3,?4,?5,?6,?7)")
        .map_err(err)?;
    for f in findings {
        let evidence = serde_json::to_string(&f.evidence).map_err(err)?;
        stmt.execute(params![
            f.rule,
            f.severity,
            f.description,
            evidence,
            f.evidence.first(),
            scope,
            batch
        ])
        .map_err(err)?;
    }
    Ok(())
}

/// Overview used by the dashboard: totals, severities, top entities, timeline.
pub fn overview(conn: &Connection) -> Res<Value> {
    let top = |column: &str| -> Res<Vec<Value>> {
        let sql = format!(
            "SELECT {column}, COUNT(*) c FROM events WHERE {column} <> '' GROUP BY {column} ORDER BY c DESC LIMIT 10"
        );
        let mut stmt = conn.prepare(&sql).map_err(err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(json!({"value": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?}))
            })
            .map_err(err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(err)
    };
    let mut sev = conn
        .prepare("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        .map_err(err)?;
    let severities: Vec<Value> = sev
        .query_map([], |r| {
            Ok(json!({"severity": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?}))
        })
        .map_err(err)?
        .collect::<Result<_, _>>()
        .map_err(err)?;
    let mut rules = conn
        .prepare("SELECT rule, severity, COUNT(*) c FROM findings GROUP BY rule, severity ORDER BY c DESC LIMIT 40")
        .map_err(err)?;
    let rules: Vec<Value> = rules
        .query_map([], |r| Ok(json!({"rule": r.get::<_, String>(0)?, "severity": r.get::<_, String>(1)?, "count": r.get::<_, i64>(2)?})))
        .map_err(err)?
        .collect::<Result<_, _>>()
        .map_err(err)?;
    let mut hours = conn
        .prepare("SELECT ts/3600*3600 h, COUNT(*) FROM events WHERE ts IS NOT NULL GROUP BY h ORDER BY h LIMIT 5000")
        .map_err(err)?;
    let timeline: Vec<Value> = hours
        .query_map([], |r| {
            Ok(json!([r.get::<_, i64>(0)?, r.get::<_, i64>(1)?]))
        })
        .map_err(err)?
        .collect::<Result<_, _>>()
        .map_err(err)?;
    let mut files = conn
        .prepare("SELECT file_id,name,sha256,bytes,profile,status,records,duplicates,failed,batches,batch_size,ms,error FROM files ORDER BY file_id")
        .map_err(err)?;
    let files: Vec<Value> = files
        .query_map([], |r| {
            Ok(json!({
                "file_id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "sha256": r.get::<_, String>(2)?,
                "bytes": r.get::<_, i64>(3)?, "profile": serde_json::from_str::<Value>(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
                "status": r.get::<_, String>(5)?, "records": r.get::<_, i64>(6)?, "duplicates": r.get::<_, i64>(7)?,
                "failed": r.get::<_, i64>(8)?, "batches": r.get::<_, i64>(9)?, "batch_size": r.get::<_, i64>(10)?,
                "ms": r.get::<_, i64>(11)?, "error": r.get::<_, Option<String>>(12)?,
            }))
        })
        .map_err(err)?
        .collect::<Result<_, _>>()
        .map_err(err)?;
    let range: (Option<i64>, Option<i64>) = conn
        .query_row("SELECT MIN(ts), MAX(ts) FROM events", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(err)?;
    Ok(json!({
        "events": count(conn, "SELECT COUNT(*) FROM events"),
        "dated": count(conn, "SELECT COUNT(*) FROM events WHERE ts IS NOT NULL"),
        "findings": count(conn, "SELECT COUNT(*) FROM findings"),
        "global_findings": count(conn, "SELECT COUNT(*) FROM findings WHERE scope='global'"),
        "failures": count(conn, "SELECT COUNT(*) FROM failures"),
        "severities": severities,
        "rules": rules,
        "top_senders": top("sender")?,
        "top_recipients": top("recipient")?,
        "top_ips": top("ip")?,
        "top_actions": top("action")?,
        "timeline": timeline,
        "files": files,
        "first": range.0,
        "last": range.1,
    }))
}

/// Free-text and field search with paging. `q` matches normalized fields and,
/// when `deep` is set, the raw record JSON (slower on very large cases).
pub fn search(
    conn: &Connection,
    q: &str,
    field: &str,
    deep: bool,
    offset: i64,
    limit: i64,
) -> Res<Value> {
    let limit = limit.clamp(1, 500);
    let fields = [
        "sender",
        "recipient",
        "ip",
        "message_id",
        "action",
        "source",
        "id",
    ];
    let (clause, needle) = if q.trim().is_empty() {
        ("1=1".to_string(), String::new())
    } else if fields.contains(&field) {
        (format!("{field} = ?1 COLLATE NOCASE"), q.trim().to_string())
    } else {
        let mut parts: Vec<String> = fields.iter().map(|f| format!("{f} LIKE ?1")).collect();
        if deep {
            parts.push("data LIKE ?1".into());
        }
        (
            format!("({})", parts.join(" OR ")),
            format!("%{}%", q.trim().replace('%', "\\%")),
        )
    };
    let total: i64 = if needle.is_empty() {
        count(conn, "SELECT COUNT(*) FROM events")
    } else {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE {clause} LIMIT 100001)"),
            [&needle],
            |r| r.get(0),
        )
        .map_err(err)?
    };
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM events WHERE {clause} ORDER BY ts IS NULL, ts, rid LIMIT {limit} OFFSET {offset}"
    );
    let mut stmt = conn.prepare(&sql).map_err(err)?;
    let rows: Vec<Event> = if needle.is_empty() {
        stmt.query_map([], row_event)
            .map_err(err)?
            .collect::<Result<_, _>>()
            .map_err(err)?
    } else {
        stmt.query_map([&needle], row_event)
            .map_err(err)?
            .collect::<Result<_, _>>()
            .map_err(err)?
    };
    Ok(json!({"total": total, "total_capped": total > 100_000, "offset": offset, "events": rows}))
}

pub fn findings_page(
    conn: &Connection,
    severity: &str,
    rule: &str,
    offset: i64,
    limit: i64,
) -> Res<Value> {
    let limit = limit.clamp(1, 500);
    let mut stmt = conn
        .prepare(
            "SELECT rule,severity,description,evidence,scope FROM findings
             WHERE (?1='' OR severity=?1) AND (?2='' OR rule=?2)
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, fid
             LIMIT ?3 OFFSET ?4",
        )
        .map_err(err)?;
    let rows: Vec<Value> = stmt
        .query_map(params![severity, rule, limit, offset], |r| {
            Ok(json!({
                "rule": r.get::<_, String>(0)?, "severity": r.get::<_, String>(1)?, "description": r.get::<_, String>(2)?,
                "evidence": serde_json::from_str::<Value>(&r.get::<_, String>(3)?).unwrap_or(Value::Null),
                "scope": r.get::<_, String>(4)?,
            }))
        })
        .map_err(err)?
        .collect::<Result<_, _>>()
        .map_err(err)?;
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE (?1='' OR severity=?1) AND (?2='' OR rule=?2)",
            params![severity, rule],
            |r| r.get(0),
        )
        .map_err(err)?;
    Ok(json!({"total": total, "offset": offset, "findings": rows}))
}

pub fn events_by_ids(conn: &Connection, ids: &[String]) -> Res<Vec<Event>> {
    let mut stmt = conn
        .prepare_cached(&format!("SELECT {EVENT_COLUMNS} FROM events WHERE id=?1"))
        .map_err(err)?;
    let mut out = Vec::new();
    for id in ids.iter().take(1000) {
        if let Some(e) = stmt.query_row([id], row_event).optional().map_err(err)? {
            out.push(e);
        }
    }
    Ok(out)
}
