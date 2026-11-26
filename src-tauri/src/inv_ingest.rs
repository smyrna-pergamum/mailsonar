//! Streaming, chunked, checkpointed ingest of very large evidence files into an
//! investigation store (millions of events per investigation).
//!
//! Pipeline per file:
//!
//! ```text
//! reader thread ──batches──▶ N worker threads ──processed──▶ ordered writer (SQLite)
//!   streaming parse            normalize + detect              dedupe, insert, checkpoint
//! ```
//!
//! * Readers never load a whole line-oriented file into memory (CSV, JSONL, LOG/TXT,
//!   MBOX, and the same inside GZIP/ZIP). Container formats that cannot be streamed
//!   (EML, MSG, EVTX, XLSX, XML, JSON arrays) are parsed in memory up to 256 MiB.
//! * Batch size adapts to free memory (2,000 … 20,000 records). Bounded channels
//!   give backpressure: a slow disk slows the reader instead of filling RAM.
//! * The writer commits batches strictly in order, so `checkpoint` (last committed
//!   record number) is always contiguous. A cancelled or crashed import resumes
//!   from the checkpoint when the same file (same SHA-256) is imported again.
//! * `INSERT OR IGNORE` on a content hash removes duplicate events across files and
//!   repeated imports; malformed records are stored in `failures`, never dropped silently.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::inv_store::{self, content_hash, epoch};
use super::{err, Event, Finding};

type Res<T> = Result<T, String>;

pub const MIN_BATCH: usize = 2_000;
pub const MAX_BATCH: usize = 20_000;
const IN_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;
const MAX_MBOX_MESSAGE: usize = 32 * 1024 * 1024;
const MAX_LINE: usize = 4 * 1024 * 1024;

/// Reader result: (malformed records, warnings, records seen).
type ReadOutcome = (Vec<(usize, String)>, Vec<String>, usize);

/// Batch size from available memory; the upper bound stays the 20,000 guard.
pub fn adaptive_batch_size() -> usize {
    let free_mb = match sysinfo::System::new() {
        Ok(mut sys) => {
            sys.refresh_memory();
            sys.available_memory() / (1024 * 1024)
        }
        Err(_) => 0,
    };
    match free_mb {
        0..=2047 => 2_000,
        2048..=4095 => 5_000,
        4096..=8191 => 10_000,
        _ => MAX_BATCH,
    }
}

pub fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() / 2)
        .unwrap_or(2)
        .clamp(1, 4)
}

struct RawBatch {
    no: i64,
    rows: Vec<(usize, Value)>,
}

struct Processed {
    no: i64,
    events: Vec<Event>,
    hashes: Vec<String>,
    findings: Vec<Finding>,
    last_record: usize,
    ms: u64,
}

/// Counts bytes read so progress can be reported as a share of the file size.
struct Counting<R> {
    inner: R,
    read: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Collects parsed records into batches and applies resume skipping.
struct Emitter<'a> {
    next: usize,
    skip_until: usize,
    batch_size: usize,
    batch_no: i64,
    current: Vec<(usize, Value)>,
    tx: &'a std::sync::mpsc::SyncSender<RawBatch>,
    cancel: &'a AtomicBool,
    failures: Vec<(usize, String)>,
}

impl Emitter<'_> {
    fn record(&mut self, value: Result<Value, String>) -> Res<()> {
        self.next += 1;
        let n = self.next;
        if n <= self.skip_until {
            return Ok(());
        }
        match value {
            Ok(v) => self.current.push((n, v)),
            Err(e) => self.failures.push((n, e.chars().take(300).collect())),
        }
        if self.current.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Res<()> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        if self.current.is_empty() {
            return Ok(());
        }
        self.batch_no += 1;
        let rows = std::mem::take(&mut self.current);
        self.tx
            .send(RawBatch {
                no: self.batch_no,
                rows,
            })
            .map_err(|_| "processing pipeline stopped".to_string())
    }
}

fn ext_of(name: &str) -> String {
    name.rsplit('.').next().unwrap_or("").to_ascii_lowercase()
}

fn log_line(line: &str) -> Value {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new("(?i)(from|to|status|client|sasl_username|message-id)=([^,; ]+)")
            .expect("static regex")
    });
    let mut o = serde_json::Map::new();
    o.insert("raw".into(), json!(line));
    for c in RE.captures_iter(line) {
        o.insert(c[1].to_lowercase(), json!(&c[2]));
    }
    Value::Object(o)
}

fn read_line_bounded(reader: &mut dyn BufRead, buf: &mut Vec<u8>) -> Res<usize> {
    buf.clear();
    let n = reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)
        .map_err(err)?;
    if buf.len() > MAX_LINE {
        // Skip the rest of an oversized line.
        let mut sink = Vec::new();
        reader.read_until(b'\n', &mut sink).map_err(err)?;
    }
    Ok(n)
}

/// Stream one logical file (possibly a member of an archive) into the emitter.
fn stream(
    name: &str,
    ext: &str,
    reader: &mut dyn Read,
    size_hint: u64,
    em: &mut Emitter<'_>,
    warnings: &mut Vec<String>,
) -> Res<()> {
    match ext {
        "jsonl" | "ndjson" => {
            let mut r = BufReader::with_capacity(1 << 20, reader);
            let mut buf = Vec::new();
            while read_line_bounded(&mut r, &mut buf)? > 0 {
                if buf.len() > MAX_LINE {
                    em.record(Err("line exceeds 4 MiB".into()))?;
                    continue;
                }
                let line = String::from_utf8_lossy(&buf);
                if line.trim().is_empty() {
                    continue;
                }
                em.record(serde_json::from_str(line.trim()).map_err(|e| format!("JSON: {e}")))?;
            }
        }
        "csv" => {
            let mut r = csv::ReaderBuilder::new()
                .flexible(true)
                .from_reader(BufReader::with_capacity(1 << 20, reader));
            for row in r.deserialize::<BTreeMap<String, String>>() {
                em.record(row.map(|m| json!(m)).map_err(|e| format!("CSV: {e}")))?;
            }
        }
        "txt" | "log" => {
            let mut r = BufReader::with_capacity(1 << 20, reader);
            let mut buf = Vec::new();
            while read_line_bounded(&mut r, &mut buf)? > 0 {
                let line = String::from_utf8_lossy(&buf);
                let line = line.trim_end();
                if !line.trim().is_empty() {
                    em.record(Ok(log_line(line)))?;
                }
            }
        }
        "mbox" | "mbx" => {
            let mut r = BufReader::with_capacity(1 << 20, reader);
            let mut buf = Vec::new();
            let mut message: Vec<u8> = Vec::new();
            let mut started = false;
            let finish = |message: &mut Vec<u8>,
                          em: &mut Emitter<'_>,
                          warnings: &mut Vec<String>|
             -> Res<()> {
                if !message.is_empty() {
                    let result = super::email::analyze_message(message, warnings);
                    em.record(result)?;
                    message.clear();
                }
                Ok(())
            };
            while read_line_bounded(&mut r, &mut buf)? > 0 {
                if buf.starts_with(b"From ") {
                    finish(&mut message, em, warnings)?;
                    started = true;
                    continue;
                }
                if !started {
                    started = true;
                }
                // mboxrd: un-escape quoted From lines.
                let line: &[u8] = if buf.starts_with(b">From ") {
                    &buf[1..]
                } else {
                    &buf
                };
                if message.len() + line.len() <= MAX_MBOX_MESSAGE {
                    message.extend_from_slice(line);
                }
            }
            finish(&mut message, em, warnings)?;
        }
        "gz" | "gzip" => {
            let inner = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
            let mut decoder = flate2::read::MultiGzDecoder::new(BufReader::new(reader));
            stream(inner, &ext_of(inner), &mut decoder, 0, em, warnings)?;
        }
        _ => {
            // Not line-oriented: parse in memory with the regular parser (bounded).
            if size_hint > IN_MEMORY_LIMIT {
                return Err(format!("{name}: {ext} files larger than 256 MiB cannot be streamed; convert to JSONL or CSV"));
            }
            let mut bytes = Vec::new();
            reader
                .take(IN_MEMORY_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(err)?;
            if bytes.len() as u64 > IN_MEMORY_LIMIT {
                return Err(format!("{name}: larger than 256 MiB"));
            }
            let mut budget = (IN_MEMORY_LIMIT * 3) as usize;
            for row in super::parse_unbounded(name, &bytes, 0, &mut budget, warnings)? {
                em.record(Ok(row))?;
            }
        }
    }
    Ok(())
}

fn stream_path(
    path: &Path,
    name: &str,
    em: &mut Emitter<'_>,
    read: Arc<AtomicU64>,
    warnings: &mut Vec<String>,
) -> Res<()> {
    let file = std::fs::File::open(path).map_err(err)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let ext = ext_of(name);
    if ext == "zip" {
        let mut archive = zip::ZipArchive::new(file).map_err(err)?;
        for i in 0..archive.len() {
            let mut member = archive.by_index(i).map_err(err)?;
            if member.is_dir() {
                continue;
            }
            let member_name = format!("{name}!{}", member.name().map_err(err)?);
            let member_size = member.size();
            read.fetch_add(member.compressed_size(), Ordering::Relaxed);
            let member_ext = ext_of(&member_name);
            if let Err(e) = stream(
                &member_name,
                &member_ext,
                &mut member,
                member_size,
                em,
                warnings,
            ) {
                if e == "cancelled" {
                    return Err(e);
                }
                warnings.push(format!("{member_name}: {e}"));
            }
        }
        return Ok(());
    }
    let mut counting = Counting { inner: file, read };
    stream(name, &ext, &mut counting, size, em, warnings)
}

#[derive(Clone, Default, serde::Serialize)]
pub struct FileReport {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub status: String,
    pub records: u64,
    pub inserted: u64,
    pub duplicates: u64,
    pub failed: u64,
    pub batches: u64,
    pub batch_size: usize,
    pub resumed_from: u64,
    pub ms: u64,
    pub events_per_second: f64,
    pub batch_ms: Vec<u64>,
    pub warnings: Vec<String>,
}

fn sha256_file(path: &Path) -> Res<String> {
    use sha2::{Digest, Sha256};
    let mut file = BufReader::with_capacity(1 << 20, std::fs::File::open(path).map_err(err)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Import one file into an open store. Resumes from the stored checkpoint when
/// the same file (by SHA-256) was imported partially before.
pub fn import_file(
    conn: &mut Connection,
    path: &Path,
    batch_size: usize,
    workers: usize,
    cancel: &AtomicBool,
    progress: &dyn Fn(Value),
) -> Res<FileReport> {
    let started = Instant::now();
    let name = path
        .file_name()
        .ok_or("Invalid file name")?
        .to_string_lossy()
        .to_string();
    let bytes = std::fs::metadata(path).map_err(err)?.len();
    let digest = sha256_file(path)?;
    let batch_size = batch_size.clamp(MIN_BATCH.min(batch_size.max(1)), MAX_BATCH);
    let existing: Option<(i64, String, i64)> = conn
        .query_row(
            "SELECT file_id, status, checkpoint FROM files WHERE sha256=?1",
            [&digest],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (file_id, resume_from) = match existing {
        Some((_, status, _)) if status == "complete" => {
            return Ok(FileReport {
                name,
                sha256: digest,
                bytes,
                status: "already imported".into(),
                ..Default::default()
            });
        }
        Some((id, _, checkpoint)) => (id, checkpoint as usize),
        None => {
            conn.execute(
                "INSERT INTO files(name,path,sha256,bytes,status,started,batch_size) VALUES(?1,?2,?3,?4,'importing',?5,?6)",
                params![name, path.to_string_lossy(), digest, bytes as i64, chrono::Utc::now().to_rfc3339(), batch_size as i64],
            )
            .map_err(err)?;
            (conn.last_insert_rowid(), 0)
        }
    };
    conn.execute(
        "UPDATE files SET status='importing', error=NULL WHERE file_id=?1",
        [file_id],
    )
    .map_err(err)?;

    let read = Arc::new(AtomicU64::new(0));
    let (raw_tx, raw_rx) = sync_channel::<RawBatch>(workers * 2);
    let (done_tx, done_rx) = sync_channel::<Processed>(workers * 2);
    let raw_rx: Arc<Mutex<Receiver<RawBatch>>> = Arc::new(Mutex::new(raw_rx));
    let mut report = FileReport {
        name: name.clone(),
        sha256: digest.clone(),
        bytes,
        batch_size,
        resumed_from: resume_from as u64,
        ..Default::default()
    };

    let outcome: Res<ReadOutcome> = std::thread::scope(|scope| {
        // Workers: normalize + detect, in parallel.
        for _ in 0..workers {
            let rx = Arc::clone(&raw_rx);
            let tx = done_tx.clone();
            let name = name.clone();
            let digest = digest.clone();
            scope.spawn(move || loop {
                let batch = {
                    let guard = match rx.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    match guard.recv() {
                        Ok(b) => b,
                        Err(_) => return,
                    }
                };
                let t = Instant::now();
                let last_record = batch.rows.last().map(|(n, _)| *n).unwrap_or(0);
                let events: Vec<Event> = batch
                    .rows
                    .into_iter()
                    .map(|(n, v)| super::event(&name, &digest, n, v))
                    .collect();
                let hashes = events.iter().map(content_hash).collect();
                let findings = super::detect(&events);
                if tx
                    .send(Processed {
                        no: batch.no,
                        events,
                        hashes,
                        findings,
                        last_record,
                        ms: t.elapsed().as_millis() as u64,
                    })
                    .is_err()
                {
                    return;
                }
            });
        }
        drop(done_tx);
        // Reader: streaming parse into bounded batches.
        let reader = {
            let read = Arc::clone(&read);
            let name = name.clone();
            scope.spawn(move || {
                let mut warnings = Vec::new();
                let mut em = Emitter {
                    next: 0,
                    skip_until: resume_from,
                    batch_size,
                    batch_no: 0,
                    current: Vec::new(),
                    tx: &raw_tx,
                    cancel,
                    failures: Vec::new(),
                };
                let result =
                    stream_path(path, &name, &mut em, read, &mut warnings).and_then(|_| em.flush());
                let total = em.next;
                let failures = std::mem::take(&mut em.failures);
                drop(em);
                drop(raw_tx);
                result.map(|_| (failures, warnings, total))
            })
        };
        // Ordered writer: commits batch n only after 1..n-1.
        let mut pending: BTreeMap<i64, Processed> = BTreeMap::new();
        let mut next_no = 1i64;
        let mut write_error: Option<String> = None;
        for processed in done_rx.iter() {
            if write_error.is_some() {
                continue;
            }
            pending.insert(processed.no, processed);
            while let Some(batch) = pending.remove(&next_no) {
                match write_batch(conn, file_id, &batch) {
                    Ok((inserted, duplicates)) => {
                        report.inserted += inserted;
                        report.duplicates += duplicates;
                        report.records += batch.events.len() as u64;
                        report.batches += 1;
                        report.batch_ms.push(batch.ms);
                        let elapsed = started.elapsed().as_secs_f64().max(0.001);
                        progress(json!({
                            "file": name, "state": "importing", "batch": batch.no, "records": report.records + resume_from as u64,
                            "inserted": report.inserted, "duplicates": report.duplicates,
                            "bytes": bytes, "bytes_read": read.load(Ordering::Relaxed).min(bytes),
                            "eps": (report.records as f64 / elapsed).round(), "batch_size": batch_size,
                        }));
                    }
                    Err(e) => write_error = Some(e),
                }
                next_no += 1;
            }
        }
        let read_result = reader
            .join()
            .map_err(|_| "reader thread panicked".to_string())?;
        if let Some(e) = write_error {
            return Err(e);
        }
        read_result
    });

    report.ms = started.elapsed().as_millis() as u64;
    report.events_per_second = if report.ms > 0 {
        (report.records as f64 / (report.ms as f64 / 1000.0)).round()
    } else {
        0.0
    };
    match outcome {
        Ok((failures, warnings, _total)) => {
            let tx = conn.transaction().map_err(err)?;
            {
                let mut stmt = tx
                    .prepare_cached("INSERT INTO failures(file_id,record,error) VALUES(?1,?2,?3)")
                    .map_err(err)?;
                for (n, e) in failures.iter().take(100_000) {
                    stmt.execute(params![file_id, *n as i64, e]).map_err(err)?;
                }
            }
            tx.execute(
                "UPDATE files SET status='complete', failed=failed+?2, finished=?3, ms=ms+?4 WHERE file_id=?1",
                params![file_id, failures.len() as i64, chrono::Utc::now().to_rfc3339(), report.ms as i64],
            )
            .map_err(err)?;
            tx.commit().map_err(err)?;
            report.failed = failures.len() as u64;
            report.warnings = warnings.into_iter().take(50).collect();
            report.status = "complete".into();
        }
        Err(e) => {
            let status = if e == "cancelled" {
                "cancelled"
            } else {
                "failed"
            };
            conn.execute(
                "UPDATE files SET status=?2, error=?3, ms=ms+?4 WHERE file_id=?1",
                params![file_id, status, e, report.ms as i64],
            )
            .map_err(err)?;
            report.status = status.into();
            report.warnings.push(e);
        }
    }
    // Profile from a bounded sample of the stored records (cheap even for 1M).
    let sample: Vec<Value> = {
        let mut stmt = conn
            .prepare("SELECT data FROM events WHERE file_id=?1 LIMIT 5000")
            .map_err(err)?;
        let rows = stmt
            .query_map([file_id], |r| r.get::<_, String>(0))
            .map_err(err)?;
        rows.filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect()
    };
    let profile = super::sources::profile(&name, &sample);
    conn.execute(
        "UPDATE files SET profile=?2 WHERE file_id=?1",
        params![file_id, profile.to_string()],
    )
    .map_err(err)?;
    progress(
        json!({"file": name, "state": report.status, "records": report.records + resume_from as u64, "inserted": report.inserted,
                    "duplicates": report.duplicates, "failed": report.failed, "bytes": bytes, "bytes_read": bytes, "eps": report.events_per_second}),
    );
    Ok(report)
}

fn write_batch(conn: &mut Connection, file_id: i64, batch: &Processed) -> Res<(u64, u64)> {
    let tx = conn.transaction().map_err(err)?;
    let mut inserted_ids = std::collections::HashSet::new();
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO events(id,file_id,record,batch,ts,timestamp,sender,recipient,ip,message_id,action,source,content_hash,data)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            )
            .map_err(err)?;
        for (e, h) in batch.events.iter().zip(&batch.hashes) {
            let changed = stmt
                .execute(params![
                    e.id,
                    file_id,
                    e.record as i64,
                    batch.no,
                    epoch(&e.timestamp),
                    e.timestamp,
                    e.sender,
                    e.recipient,
                    e.ip,
                    e.message_id,
                    e.action,
                    e.source,
                    h,
                    e.data.to_string()
                ])
                .map_err(err)?;
            if changed > 0 {
                inserted_ids.insert(e.id.as_str());
            }
        }
    }
    let findings: Vec<Finding> = batch
        .findings
        .iter()
        .filter(|f| {
            f.evidence
                .iter()
                .all(|id| inserted_ids.contains(id.as_str()))
        })
        .cloned()
        .collect();
    inv_store::insert_findings(&tx, &findings, "local", Some(batch.no))?;
    let inserted = inserted_ids.len() as u64;
    let duplicates = batch.events.len() as u64 - inserted;
    tx.execute(
        "UPDATE files SET records=records+?2, duplicates=duplicates+?3, checkpoint=?4, batches=batches+1 WHERE file_id=?1",
        params![file_id, batch.events.len() as i64, duplicates as i64, batch.last_record as i64],
    )
    .map_err(err)?;
    tx.commit().map_err(err)?;
    Ok((inserted, duplicates))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Synthetic multi-source JSONL with attack patterns, a share of exact
    /// duplicates and a few malformed lines. Returns (path, unique, duplicates, malformed).
    pub(crate) fn synth(dir: &Path, n: usize) -> (std::path::PathBuf, usize, usize, usize) {
        let path = dir.join(format!("synthetic-{n}.jsonl"));
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let (mut unique, mut dups, mut bad) = (0, 0, 0);
        let sources = [
            "exchange-online-audit",
            "entra-id",
            "postfix",
            "google-workspace",
            "exim",
        ];
        let actions = [
            "Send",
            "Receive",
            "sign-in",
            "New-InboxRule",
            "Failed Login",
            "MailItemsAccessed",
        ];
        for i in 0..n {
            if i % 997 == 996 {
                writeln!(f, "{{broken json").unwrap();
                bad += 1;
                continue;
            }
            if i % 200 == 199 {
                // Exact duplicate of the previous record.
                let j = i - 1;
                writeln!(f, "{}", line(j, &sources, &actions)).unwrap();
                dups += 1;
                continue;
            }
            writeln!(f, "{}", line(i, &sources, &actions)).unwrap();
            unique += 1;
        }
        (path, unique, dups, bad)
    }

    fn line(i: usize, sources: &[&str], actions: &[&str]) -> String {
        let user = format!("user{}@corp.test", i % 2000);
        let details = match i % 50 {
            0 => "spf=fail dkim=fail; phishing link",
            1 => "failed login: invalid credentials",
            2 => "forward-to external",
            _ => "delivered normally",
        };
        json!({
            "timestamp": chrono::DateTime::from_timestamp(1_795_000_000 + (i as i64) * 3, 0).unwrap().to_rfc3339(),
            "source": sources[i % sources.len()],
            "sender": user,
            "recipient": format!("peer{}@partner.test", i % 777),
            "ip": format!("198.51.{}.{}", (i / 250) % 250, i % 250),
            "message_id": if i % 100 < 4 { format!("<thread{}@corp.test>", i / 100) } else { format!("<m{i}@corp.test>") },
            "action": actions[i % actions.len()],
            "details": details,
            "seq": i,
        })
        .to_string()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ms-inv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn streaming_import_dedupes_and_records_failures() {
        let dir = temp_dir("basic");
        let (path, unique, dups, bad) = synth(&dir, 25_000);
        let mut conn = inv_store::open(&dir.join("case.sqlite3")).unwrap();
        let cancel = AtomicBool::new(false);
        let report = import_file(&mut conn, &path, 4_000, 3, &cancel, &|_| {}).unwrap();
        assert_eq!(report.status, "complete");
        assert_eq!(report.failed as usize, bad);
        assert_eq!(report.duplicates as usize, dups);
        assert_eq!(
            inv_store::count(&conn, "SELECT COUNT(*) FROM events") as usize,
            unique
        );
        assert!(report.batches >= 6);
        // Same file again: skipped as already imported.
        let again = import_file(&mut conn, &path, 4_000, 3, &cancel, &|_| {}).unwrap();
        assert_eq!(again.status, "already imported");
        assert!(inv_store::count(&conn, "SELECT COUNT(*) FROM findings") > 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cancelled_import_resumes_from_checkpoint_without_loss_or_duplicates() {
        let dir = temp_dir("resume");
        let (path, unique, _, _) = synth(&dir, 30_000);
        let mut conn = inv_store::open(&dir.join("case.sqlite3")).unwrap();
        let cancel = AtomicBool::new(false);
        let batches = std::cell::Cell::new(0);
        // Simulate a crash: stop after the second committed batch.
        let report = import_file(&mut conn, &path, 2_000, 2, &cancel, &|p| {
            if p["state"] == "importing" {
                batches.set(batches.get() + 1);
                if batches.get() == 2 {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
        })
        .unwrap();
        assert_eq!(report.status, "cancelled");
        let partial = inv_store::count(&conn, "SELECT COUNT(*) FROM events") as usize;
        assert!(partial > 0 && partial < unique, "partial {partial}");
        let checkpoint: i64 = conn
            .query_row("SELECT checkpoint FROM files", [], |r| r.get(0))
            .unwrap();
        assert!(checkpoint > 0);
        cancel.store(false, Ordering::SeqCst);
        let resumed = import_file(&mut conn, &path, 2_000, 2, &cancel, &|_| {}).unwrap();
        assert_eq!(resumed.status, "complete");
        assert_eq!(resumed.resumed_from as i64, checkpoint);
        assert_eq!(
            inv_store::count(&conn, "SELECT COUNT(*) FROM events") as usize,
            unique
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn streams_gzip_mbox_and_log_lines() {
        let dir = temp_dir("formats");
        let gz = dir.join("events.jsonl.gz");
        {
            let mut enc = flate2::write::GzEncoder::new(
                std::fs::File::create(&gz).unwrap(),
                flate2::Compression::fast(),
            );
            for i in 0..3000 {
                writeln!(
                    enc,
                    "{}",
                    json!({"action": "Send", "sender": format!("u{i}@x.test"), "seq": i})
                )
                .unwrap();
            }
            enc.finish().unwrap();
        }
        let mbox = dir.join("box.mbox");
        std::fs::write(&mbox, "From a@b Wed Nov 25 10:00:00 2026\nSubject: one\nFrom: a@b.test\n\nhello\n>From quoted\nFrom c@d Wed Nov 25 10:01:00 2026\nSubject: two\nFrom: c@d.test\n\nbye\n").unwrap();
        let log = dir.join("mail.log");
        std::fs::write(&log, "Nov 25 09:30:04 mx1 postfix/smtpd[1]: A: client=x\nNov 25 09:30:05 mx1 postfix/qmgr[2]: A: from=<a@b.test>\n").unwrap();
        let mut conn = inv_store::open(&dir.join("case.sqlite3")).unwrap();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            import_file(&mut conn, &gz, 2_000, 2, &cancel, &|_| {})
                .unwrap()
                .records,
            3000
        );
        assert_eq!(
            import_file(&mut conn, &mbox, 2_000, 2, &cancel, &|_| {})
                .unwrap()
                .records,
            2
        );
        assert_eq!(
            import_file(&mut conn, &log, 2_000, 2, &cancel, &|_| {})
                .unwrap()
                .records,
            2
        );
        let profile: String = conn
            .query_row("SELECT profile FROM files WHERE name='mail.log'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(profile.contains("Postfix"), "{profile}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
