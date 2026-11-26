//! Ingest benchmark for large investigations (ignored by default).
//!
//! ```sh
//! cargo test --release --manifest-path src-tauri/Cargo.toml bench_ingest_scales -- --ignored --nocapture
//! MAILDFIR_BENCH_SIZES=1000,10000,20000,100000,500000,1000000,5000000
//! ```
//!
//! For every size: generate synthetic multi-source JSONL with 0.5 % exact
//! duplicates and 0.1 % malformed lines, stream it into a fresh store, run global
//! correlation and verify integrity (stored = unique, failed = malformed,
//! duplicates = injected). Also measures crash recovery: cancel at ~50 % and
//! resume. Results: `target/bench-ingest.json` and `target/bench-ingest.md`.

#[cfg(test)]
mod tests {
    use crate::{inv_correlate, inv_ingest, inv_store};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    fn rss_mb(sys: &mut sysinfo::System, pid: sysinfo::Pid) -> u64 {
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), false);
        sys.process(pid)
            .map(|p| p.memory() / (1024 * 1024))
            .unwrap_or(0)
    }

    fn percentile(sorted: &[u64], p: f64) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
    }

    #[test]
    #[ignore = "benchmark: generates up to millions of events on disk"]
    fn bench_ingest_scales() {
        let sizes: Vec<usize> = std::env::var("MAILDFIR_BENCH_SIZES")
            .unwrap_or_else(|_| "1000,10000,20000,100000,500000,1000000".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let root = std::env::temp_dir().join(format!("ms-bench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let pid = sysinfo::get_current_pid().unwrap();
        let mut sys = sysinfo::System::new().unwrap();
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let mut results = Vec::new();
        for &n in &sizes {
            let dir = root.join(n.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let gen_started = Instant::now();
            let (path, unique, dups, bad) = inv_ingest::tests::synth(&dir, n);
            let gen_ms = gen_started.elapsed().as_millis();
            let file_mb = std::fs::metadata(&path).unwrap().len() as f64 / 1_048_576.0;
            let db = dir.join("case.sqlite3");
            let mut conn = inv_store::open(&db).unwrap();
            let batch = inv_ingest::adaptive_batch_size();
            let workers = inv_ingest::worker_count();
            let base_rss = rss_mb(&mut sys, pid);
            let peak = AtomicU64::new(base_rss);
            let sys_cell = std::sync::Mutex::new(sysinfo::System::new().unwrap());
            let started = Instant::now();
            let report = inv_ingest::import_file(
                &mut conn,
                &path,
                batch,
                workers,
                &AtomicBool::new(false),
                &|_| {
                    let mut s = sys_cell.lock().unwrap();
                    let now = rss_mb(&mut s, pid);
                    peak.fetch_max(now, Ordering::Relaxed);
                },
            )
            .unwrap();
            let ingest_ms = started.elapsed().as_millis() as u64;
            let corr_started = Instant::now();
            let correlated = inv_correlate::correlate(&mut conn).unwrap();
            let corr_ms = corr_started.elapsed().as_millis() as u64;
            let stored = inv_store::count(&conn, "SELECT COUNT(*) FROM events") as usize;
            let findings = inv_store::count(&conn, "SELECT COUNT(*) FROM findings");
            let q_started = Instant::now();
            let _ = inv_store::search(&conn, "user77@corp.test", "sender", false, 0, 50).unwrap();
            let query_ms = q_started.elapsed().as_millis() as u64;
            let mut lat = report.batch_ms.clone();
            lat.sort_unstable();
            let integrity = stored == unique
                && report.failed as usize == bad
                && report.duplicates as usize == dups;
            drop(conn);
            let db_mb = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0) as f64 / 1_048_576.0;
            let row = json!({
                "events": n, "unique": unique, "stored": stored, "duplicates_injected": dups, "duplicates_detected": report.duplicates,
                "malformed_injected": bad, "failed_recorded": report.failed, "integrity_ok": integrity,
                "file_mb": (file_mb * 10.0).round() / 10.0, "db_mb": (db_mb * 10.0).round() / 10.0,
                "batch_size": batch, "workers": workers, "batches": report.batches,
                "ingest_ms": ingest_ms, "eps": (n as f64 / (ingest_ms.max(1) as f64 / 1000.0)).round(),
                "batch_p50_ms": percentile(&lat, 0.5), "batch_p95_ms": percentile(&lat, 0.95), "batch_p99_ms": percentile(&lat, 0.99),
                "peak_rss_mb": peak.load(Ordering::Relaxed), "baseline_rss_mb": base_rss,
                "correlation_ms": corr_ms, "global_findings": correlated, "findings": findings, "indexed_query_ms": query_ms,
                "generate_ms": gen_ms,
            });
            eprintln!("BENCH {row}");
            assert!(integrity, "integrity failed: {row}");
            results.push(row);
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Crash recovery at the largest size up to 1M: cancel near 50 %, then resume.
        let recovery_n = sizes
            .iter()
            .copied()
            .filter(|&n| n <= 1_000_000)
            .max()
            .unwrap_or(100_000);
        let dir = root.join("recovery");
        std::fs::create_dir_all(&dir).unwrap();
        let (path, unique, _, _) = inv_ingest::tests::synth(&dir, recovery_n);
        let mut conn = inv_store::open(&dir.join("case.sqlite3")).unwrap();
        let cancel = AtomicBool::new(false);
        // Enough batches that a cancel lands in the middle of the file.
        let batch =
            inv_ingest::adaptive_batch_size().min((recovery_n / 10).max(inv_ingest::MIN_BATCH));
        let half = (recovery_n / batch / 2).max(1) as u64;
        let seen = AtomicU64::new(0);
        let first = inv_ingest::import_file(
            &mut conn,
            &path,
            batch,
            inv_ingest::worker_count(),
            &cancel,
            &|p| {
                if p["state"] == "importing" && seen.fetch_add(1, Ordering::SeqCst) + 1 == half {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        )
        .unwrap();
        let partial = inv_store::count(&conn, "SELECT COUNT(*) FROM events");
        cancel.store(false, Ordering::SeqCst);
        let resume_started = Instant::now();
        let resumed = inv_ingest::import_file(
            &mut conn,
            &path,
            batch,
            inv_ingest::worker_count(),
            &cancel,
            &|_| {},
        )
        .unwrap();
        let recovery_ms = resume_started.elapsed().as_millis() as u64;
        let stored = inv_store::count(&conn, "SELECT COUNT(*) FROM events") as usize;
        let recovery = json!({"events": recovery_n, "cancelled_status": first.status, "stored_before_resume": partial,
                              "resumed_from_record": resumed.resumed_from, "resume_ms": recovery_ms, "stored_after": stored,
                              "unique": unique, "lossless": stored == unique});
        eprintln!("RECOVERY {recovery}");
        assert_eq!(stored, unique);
        drop(conn);
        let _ = std::fs::remove_dir_all(&root);

        let machine = json!({"os": std::env::consts::OS, "arch": std::env::consts::ARCH, "logical_cores": cores,
                             "total_ram_mb": sysinfo::System::new().map(|mut s| { s.refresh_memory(); s.total_memory() / 1_048_576 }).unwrap_or(0),
                             "profile": if cfg!(debug_assertions) { "debug" } else { "release" }});
        let out = json!({"machine": machine, "results": results, "recovery": recovery, "date": chrono::Utc::now().to_rfc3339()});
        let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        std::fs::write(
            target.join("bench-ingest.json"),
            serde_json::to_vec_pretty(&out).unwrap(),
        )
        .unwrap();
        let mut md = String::from("| Events | Stored (unique) | Dup. detected | Failed | Batches | Time | EPS | Batch p50/p95/p99 ms | Peak RSS MB | Correlation | DB MB | Integrity |\n|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---|\n");
        for r in &results {
            let v = |k: &str| r[k].clone();
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {:.1} s | {} | {}/{}/{} | {} | {:.1} s | {} | {} |\n",
                v("events"),
                v("stored"),
                v("duplicates_detected"),
                v("failed_recorded"),
                v("batches"),
                r["ingest_ms"].as_u64().unwrap_or(0) as f64 / 1000.0,
                v("eps"),
                v("batch_p50_ms"),
                v("batch_p95_ms"),
                v("batch_p99_ms"),
                v("peak_rss_mb"),
                r["correlation_ms"].as_u64().unwrap_or(0) as f64 / 1000.0,
                v("db_mb"),
                if r["integrity_ok"] == Value::Bool(true) {
                    "✓"
                } else {
                    "✗"
                }
            ));
        }
        std::fs::write(target.join("bench-ingest.md"), md).unwrap();
    }
}
