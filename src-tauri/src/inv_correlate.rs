//! Global (cross-batch) correlation over a whole investigation store.
//!
//! Local detection runs per batch during ingest. Patterns that span batches and
//! files — authentication bursts, outbound spikes, message traces and the
//! account kill chain — are computed here with time-ordered SQL scans, so a
//! phishing mail in batch 1 and a forwarding rule in batch 40 still connect.

use rusqlite::Connection;
use std::collections::HashMap;

use super::inv_store::insert_findings;
use super::{err, Finding};

type Res<T> = Result<T, String>;

/// (rule, role) per kill-chain stage; mirrors src/killchain.js.
const STAGES: &[(&str, &str, &[&str])] = &[
    (
        "delivery",
        "recipient",
        &[
            "MAIL-001", "MAIL-011", "MAIL-012", "MAIL-013", "MAIL-014", "MAIL-019", "MAIL-022",
            "MAIL-023",
        ],
    ),
    (
        "access",
        "sender",
        &["COR-001", "MAIL-003", "MAIL-007", "MAIL-017", "MAIL-029"],
    ),
    (
        "manipulation",
        "sender",
        &["MAIL-002", "MAIL-004", "MAIL-026", "MAIL-027", "MAIL-028"],
    ),
    (
        "action",
        "sender",
        &["MAIL-021", "MAIL-025", "MAIL-009", "MAIL-015", "COR-002"],
    ),
];
const STAGE_LABELS: &[&str] = &[
    "Phishing / malicious mail received",
    "Suspicious sign-in or MFA change",
    "Mailbox rule, forwarding or deletion",
    "Fraudulent request or exfiltration",
];
const WINDOW: i64 = 24 * 3600;

/// (timestamp, event id, rule) hits for one stage.
type StageHits = Vec<(i64, String, String)>;

/// Sliding window: first run of `size` items within `seconds`.
fn window(points: &[(i64, String)], size: usize, seconds: i64) -> Option<Vec<String>> {
    let mut left = 0;
    for right in 0..points.len() {
        while points[right].0 - points[left].0 > seconds {
            left += 1;
        }
        if right + 1 - left >= size {
            return Some(
                points[left..=right]
                    .iter()
                    .map(|(_, id)| id.clone())
                    .collect(),
            );
        }
    }
    None
}

fn grouped(conn: &Connection, sql: &str) -> Res<HashMap<String, Vec<(i64, String)>>> {
    let mut stmt = conn.prepare(sql).map_err(err)?;
    let mut rows = stmt.query([]).map_err(err)?;
    let mut out: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    while let Some(row) = rows.next().map_err(err)? {
        let key: String = row.get(0).map_err(err)?;
        if key.is_empty() {
            continue;
        }
        out.entry(key.to_lowercase())
            .or_default()
            .push((row.get(1).map_err(err)?, row.get(2).map_err(err)?));
    }
    Ok(out)
}

pub fn correlate(conn: &mut Connection) -> Res<usize> {
    conn.execute("DELETE FROM findings WHERE scope='global'", [])
        .map_err(err)?;
    let mut found: Vec<Finding> = Vec::new();
    let failure = "ts IS NOT NULL AND (action LIKE '%fail%' OR data LIKE '%failed login%' OR data LIKE '%authentication fail%' OR data LIKE '%invalid credentials%' OR data LIKE '%loginfailed%')";
    for (kind, column) in [("sender", "sender"), ("ip", "ip")] {
        let groups = grouped(
            conn,
            &format!("SELECT {column}, ts, id FROM events WHERE {failure} ORDER BY {column}, ts"),
        )?;
        for (value, points) in groups {
            if let Some(evidence) = window(&points, 5, 600) {
                found.push(Finding {
                    rule: "COR-001".into(),
                    severity: "high".into(),
                    description: format!("At least five authentication failure indicators in ten minutes ({kind}: {value}); investigate"),
                    evidence,
                });
            }
        }
    }
    let sends = grouped(conn, "SELECT sender, ts, id FROM events WHERE ts IS NOT NULL AND lower(action) IN ('send','sent','delivered','submit') ORDER BY sender, ts")?;
    for (value, points) in sends {
        if let Some(evidence) = window(&points, 50, 300) {
            found.push(Finding {
                rule: "COR-002".into(),
                severity: "medium".into(),
                description: format!(
                    "High outbound activity indicator: {value} (50 events in five minutes)"
                ),
                evidence,
            });
        }
    }
    {
        let mut stmt = conn
            .prepare("SELECT message_id, COUNT(*) c FROM events WHERE message_id <> '' GROUP BY message_id HAVING c >= 3 ORDER BY c DESC LIMIT 5000")
            .map_err(err)?;
        let traces: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(err)?
            .collect::<Result<_, _>>()
            .map_err(err)?;
        let mut ids = conn
            .prepare("SELECT id FROM events WHERE message_id=?1 ORDER BY ts LIMIT 50")
            .map_err(err)?;
        for (mid, count) in traces {
            let evidence: Vec<String> = ids
                .query_map([&mid], |r| r.get(0))
                .map_err(err)?
                .collect::<Result<_, _>>()
                .map_err(err)?;
            found.push(Finding {
                rule: "COR-003".into(),
                severity: "info".into(),
                description: format!(
                    "Message trace reconstructed: {mid} has {count} related events"
                ),
                evidence,
            });
        }
    }
    // Write the window findings first so the kill chain can use COR-001/002.
    let tx = conn.transaction().map_err(err)?;
    insert_findings(&tx, &found, "global", None)?;
    tx.commit().map_err(err)?;
    let chains = kill_chains(conn)?;
    let tx = conn.transaction().map_err(err)?;
    insert_findings(&tx, &chains, "global", None)?;
    tx.commit().map_err(err)?;
    Ok(found.len() + chains.len())
}

fn kill_chains(conn: &Connection) -> Res<Vec<Finding>> {
    // account -> stage index -> sorted (ts, event id, rule)
    let mut hits: HashMap<String, Vec<StageHits>> = HashMap::new();
    let mut stmt = conn
        .prepare("SELECT f.rule, e.sender, e.recipient, e.ts, e.id FROM findings f JOIN events e ON e.id = f.event_id WHERE e.ts IS NOT NULL")
        .map_err(err)?;
    let mut rows = stmt.query([]).map_err(err)?;
    while let Some(row) = rows.next().map_err(err)? {
        let rule: String = row.get(0).map_err(err)?;
        let sender: String = row.get(1).map_err(err)?;
        let recipient: String = row.get(2).map_err(err)?;
        let ts: i64 = row.get(3).map_err(err)?;
        let id: String = row.get(4).map_err(err)?;
        for (index, (_, role, rules)) in STAGES.iter().enumerate() {
            if !rules.contains(&rule.as_str()) {
                continue;
            }
            let account = if *role == "recipient" {
                &recipient
            } else {
                &sender
            }
            .trim()
            .to_lowercase();
            if !account.contains('@') {
                continue;
            }
            let stages = hits
                .entry(account)
                .or_insert_with(|| vec![Vec::new(); STAGES.len()]);
            stages[index].push((ts, id.clone(), rule.clone()));
        }
    }
    let mut out = Vec::new();
    for (account, mut stages) in hits {
        for stage in &mut stages {
            stage.sort();
        }
        let mut chain: Vec<(usize, i64, String, String)> = Vec::new();
        let mut after = i64::MIN;
        for (index, stage) in stages.iter().enumerate() {
            if let Some((ts, id, rule)) = stage.iter().find(|(ts, _, _)| *ts >= after) {
                if let Some(first) = chain.first() {
                    if ts - first.1 > WINDOW {
                        continue;
                    }
                }
                chain.push((index, *ts, id.clone(), rule.clone()));
                after = *ts;
            }
        }
        if chain.len() < 3 || !chain.iter().any(|c| c.0 == 1) {
            continue;
        }
        let hours = (chain.last().map(|c| c.1).unwrap_or(0) - chain[0].1) as f64 / 3600.0;
        out.push(Finding {
            rule: "COR-004".into(),
            severity: if chain.len() == 4 { "critical".into() } else { "high".into() },
            description: format!(
                "Possible account-takeover / BEC chain for {account}: {} ({}/4 stages in {hours:.1} h). Confirm each stage in its own log source.",
                chain.iter().map(|c| STAGE_LABELS[c.0]).collect::<Vec<_>>().join(" → "),
                chain.len()
            ),
            evidence: chain.into_iter().map(|c| c.2).collect(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inv_store;
    use serde_json::json;

    #[test]
    fn cross_batch_chain_and_bursts_are_found() {
        let dir = std::env::temp_dir().join(format!("ms-corr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chain.jsonl");
        let mut lines = Vec::new();
        let at = |m: i64| {
            chrono::DateTime::from_timestamp(1_795_000_000 + m * 60, 0)
                .unwrap()
                .to_rfc3339()
        };
        lines.push(json!({"timestamp": at(0), "sender": "bad@evil.test", "recipient": "elif@corp.test", "action": "deliver", "details": "phishing link"}));
        for i in 0..2500 {
            lines.push(json!({"timestamp": at(1), "sender": format!("u{i}@corp.test"), "action": "receive", "details": "normal"}));
        }
        for i in 0..6 {
            lines.push(json!({"timestamp": at(10 + i), "sender": "elif@corp.test", "ip": "203.0.113.66", "action": "sign-in", "details": "failed login"}));
        }
        lines.push(json!({"timestamp": at(20), "sender": "elif@corp.test", "action": "New-InboxRule", "details": "new-inboxrule"}));
        for i in 0..2500 {
            lines.push(json!({"timestamp": at(21), "sender": format!("v{i}@corp.test"), "action": "receive", "details": "normal"}));
        }
        lines.push(json!({"timestamp": at(40), "sender": "elif@corp.test", "action": "send", "details": "payment request with sender mismatch"}));
        std::fs::write(
            &path,
            lines
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        let mut conn = inv_store::open(&dir.join("c.sqlite3")).unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        // Small batches so the stages land in different batches.
        crate::inv_ingest::import_file(&mut conn, &path, 1000, 2, &cancel, &|_| {}).unwrap();
        correlate(&mut conn).unwrap();
        let chain: String = conn
            .query_row(
                "SELECT description FROM findings WHERE rule='COR-004'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            chain.contains("elif@corp.test") && chain.contains("4/4"),
            "{chain}"
        );
        let bursts = inv_store::count(&conn, "SELECT COUNT(*) FROM findings WHERE rule='COR-001'");
        assert!(bursts >= 1);
        let batches: i64 = conn
            .query_row("SELECT COUNT(DISTINCT batch) FROM events", [], |r| r.get(0))
            .unwrap();
        assert!(batches >= 5);
        let _ = std::fs::remove_dir_all(dir);
    }
}
