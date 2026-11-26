//! Built-in synthetic demo case, compiled into the binary so a first-time user
//! can try MailSonar without their own evidence. The files are written to the
//! app-data `samples/` directory and then imported through the normal parser,
//! hashing and vault pipeline. They are clearly marked as synthetic.

use serde::Serialize;
use tauri::{AppHandle, Manager};

use super::err;

type Res<T> = Result<T, String>;

pub(crate) const DEMO: &[(&str, &[u8])] = &[
    (
        "01-email-gateway.csv",
        include_bytes!("../../samples/demo/01-email-gateway.csv"),
    ),
    (
        "02-entra-signins.jsonl",
        include_bytes!("../../samples/demo/02-entra-signins.jsonl"),
    ),
    (
        "03-mailbox-audit.json",
        include_bytes!("../../samples/demo/03-mailbox-audit.json"),
    ),
    (
        "04-phishing.eml",
        include_bytes!("../../samples/demo/04-phishing.eml"),
    ),
    (
        "05-quarantine.mbox",
        include_bytes!("../../samples/demo/05-quarantine.mbox"),
    ),
    (
        "06-postfix-mail.log",
        include_bytes!("../../samples/demo/06-postfix-mail.log"),
    ),
];

/// The labelled multi-source dataset from the repository (`dataset/formats`),
/// used by training mode: every record carries `source` and `source_dataset`.
pub(crate) const BASELINE: &[(&str, &[u8])] = &[
    (
        "mail-events-labelled.jsonl",
        include_bytes!("../../dataset/formats/mail-events-normal.jsonl"),
    ),
    (
        "mail-events-labelled.log",
        include_bytes!("../../dataset/formats/mail-events-normal.log"),
    ),
];

const DEMO_IOCS: &str = include_str!("../../samples/demo/iocs.json");

#[derive(Serialize)]
pub struct SampleCase {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub files: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct MaterializedSample {
    pub paths: Vec<String>,
    pub iocs: serde_json::Value,
}

#[tauri::command]
pub fn sample_list() -> Vec<SampleCase> {
    vec![SampleCase {
        id: "github-baseline",
        title: "Labelled multi-source events (repository dataset)",
        description: "200 synthetic events from 18 log sources (Exchange Online audit, Entra ID, Google Workspace, Postfix, Exim, Dovecot, Amazon SES, ...) labelled as normal traffic, phishing, BEC, account takeover and more. Same data in JSONL and plain-text log form.",
        files: BASELINE.iter().map(|(name, _)| *name).collect(),
    }, SampleCase {
        id: "bec-demo",
        title: "Business Email Compromise (synthetic)",
        description: "Phishing -> account takeover -> inbox rule and forwarding -> fake payment request, plus a macro/executable attachment campaign and benign traffic. Six log sources: gateway CSV, Entra ID JSONL, mailbox audit JSON, EML, MBOX and Postfix log.",
        files: DEMO.iter().map(|(name, _)| *name).collect(),
    }]
}

#[tauri::command]
pub fn sample_materialize(app: AppHandle, id: String) -> Res<MaterializedSample> {
    let (files, iocs): (&[(&str, &[u8])], &str) = match id.as_str() {
        "bec-demo" => (DEMO, DEMO_IOCS),
        "github-baseline" => (BASELINE, "[]"),
        _ => return Err("Unknown sample case".into()),
    };
    let dir = app
        .path()
        .app_data_dir()
        .map_err(err)?
        .join("samples")
        .join(&id);
    std::fs::create_dir_all(&dir).map_err(err)?;
    let mut paths = Vec::new();
    for (name, bytes) in files {
        let path = dir.join(name);
        std::fs::write(&path, bytes).map_err(err)?;
        paths.push(path.to_string_lossy().to_string());
    }
    Ok(MaterializedSample {
        paths,
        iocs: serde_json::from_str(iocs).map_err(err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_files_parse_and_trigger_detections() {
        let mut events = Vec::new();
        for (name, bytes) in DEMO {
            let mut warnings = Vec::new();
            let mut budget = 96 * 1024 * 1024;
            let rows = super::super::parse(name, bytes, 0, &mut budget, &mut warnings)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!rows.is_empty(), "{name} produced no rows");
            let digest = super::super::hash(bytes);
            events.extend(
                rows.into_iter()
                    .enumerate()
                    .map(|(i, v)| super::super::event(name, &digest, i + 1, v)),
            );
        }
        let findings = super::super::detect(&events);
        let rules: std::collections::BTreeSet<&str> =
            findings.iter().map(|f| f.rule.as_str()).collect();
        for expected in [
            "MAIL-001", "MAIL-002", "MAIL-017", "MAIL-019", "MAIL-021", "MAIL-022", "MAIL-023",
            "MAIL-025", "MAIL-027", "MAIL-028", "MAIL-029",
        ] {
            assert!(
                rules.contains(expected),
                "missing {expected}; got {rules:?}"
            );
        }
        let mbox = events
            .iter()
            .filter(|e| e.source.ends_with(".mbox"))
            .count();
        assert_eq!(mbox, 18);
        assert!(serde_json::from_str::<serde_json::Value>(DEMO_IOCS)
            .unwrap()
            .is_array());
    }
}
