//! HELM skills: Markdown playbooks with YAML-style front matter, modelled on
//! Claude Code / Codex / OpenCode skill files.
//!
//! ```text
//! ---
//! name: phishing-triage
//! description: When to use this skill (shown to the model in the skill index)
//! triggers: phishing, oltalama, spoof
//! preload:
//!   - findings {"severity": "high"}
//! always: false
//! ---
//! # Markdown playbook body
//! ```
//!
//! Built-in skills are compiled into the binary. User skills live in
//! `<app data>/skills/*.md`; a user skill with the same name overrides a
//! built-in one. Skills are instructions for the model only: they cannot add
//! tools, widen permissions or bypass minimization. Preload entries may only
//! name read-only tools from the agent registry and are validated there.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

use super::err;

type Res<T> = Result<T, String>;

pub const MAX_SKILL_BYTES: usize = 32 * 1024;
const MAX_USER_SKILLS: usize = 64;
const MAX_PRELOAD: usize = 6;

const BUILTIN: &[(&str, &str)] = &[
    ("triage", include_str!("../skills/triage.md")),
    (
        "phishing-triage",
        include_str!("../skills/phishing-triage.md"),
    ),
    (
        "email-header-forensics",
        include_str!("../skills/email-header-forensics.md"),
    ),
    (
        "malware-delivery",
        include_str!("../skills/malware-delivery.md"),
    ),
    (
        "account-takeover",
        include_str!("../skills/account-takeover.md"),
    ),
    (
        "mailbox-rule-abuse",
        include_str!("../skills/mailbox-rule-abuse.md"),
    ),
    ("bec-fraud", include_str!("../skills/bec-fraud.md")),
    (
        "data-exfiltration",
        include_str!("../skills/data-exfiltration.md"),
    ),
    (
        "detection-engineering",
        include_str!("../skills/detection-engineering.md"),
    ),
    (
        "incident-report",
        include_str!("../skills/incident-report.md"),
    ),
];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Preload {
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub triggers: Vec<String>,
    pub preload: Vec<Preload>,
    pub always: bool,
    pub body: String,
    pub builtin: bool,
    pub overridden: bool,
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !is_reserved(name)
}

/// Windows device names cannot be used as file names.
fn is_reserved(name: &str) -> bool {
    matches!(name, "con" | "prn" | "aux" | "nul")
        || ((name.starts_with("com") || name.starts_with("lpt"))
            && name.len() == 4
            && name.as_bytes()[3].is_ascii_digit())
}

/// Parse a skill file. Front matter is a deliberately small YAML subset:
/// `key: value`, comma-separated lists and `- item` lists.
pub fn parse(text: &str, builtin: bool) -> Res<Skill> {
    if text.len() > MAX_SKILL_BYTES {
        return Err(format!("Skill exceeds {MAX_SKILL_BYTES} bytes"));
    }
    let text = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let rest = text
        .strip_prefix("---\n")
        .ok_or("Skill must start with a --- front matter block")?;
    let (front, body) = rest
        .split_once("\n---")
        .ok_or("Skill front matter is not closed with ---")?;
    let body = body.trim_start_matches('-').trim().to_string();
    let mut name = String::new();
    let mut description = String::new();
    let mut triggers = Vec::new();
    let mut preload = Vec::new();
    let mut always = false;
    let mut list_key = String::new();
    for line in front.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            match list_key.as_str() {
                "preload" => preload.push(parse_preload(item)?),
                "triggers" => triggers.push(item.trim().to_lowercase()),
                _ => {}
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            return Err(format!("Invalid front matter line: {trimmed}"));
        };
        let key = key.trim().to_lowercase();
        let value = value.trim().trim_matches('"').to_string();
        list_key = key.clone();
        match key.as_str() {
            "name" => name = value,
            "description" => description = value,
            "triggers" => {
                triggers.extend(
                    value
                        .split(',')
                        .map(|t| t.trim().to_lowercase())
                        .filter(|t| !t.is_empty()),
                );
            }
            "preload" => {
                if !value.is_empty() {
                    for item in value.split(';') {
                        preload.push(parse_preload(item)?);
                    }
                }
            }
            "always" => always = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    if !valid_name(&name) {
        return Err("Skill name must be 1-48 chars: lowercase letters, digits and '-'".into());
    }
    if description.len() < 10 || description.len() > 600 {
        return Err("Skill description must be 10-600 characters".into());
    }
    if body.is_empty() {
        return Err("Skill body is empty".into());
    }
    if preload.len() > MAX_PRELOAD {
        return Err(format!("At most {MAX_PRELOAD} preload entries"));
    }
    triggers.truncate(40);
    Ok(Skill {
        name,
        description,
        triggers,
        preload,
        always,
        body,
        builtin,
        overridden: false,
    })
}

fn parse_preload(item: &str) -> Res<Preload> {
    let item = item.trim();
    let (tool, args) = match item.find('{') {
        Some(i) => (item[..i].trim(), item[i..].trim()),
        None => (item, "{}"),
    };
    if tool.is_empty() || !tool.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
        return Err(format!("Invalid preload tool: {item}"));
    }
    let arguments: Value = serde_json::from_str(args)
        .map_err(|e| format!("Invalid preload arguments for {tool}: {e}"))?;
    if !arguments.is_object() {
        return Err(format!("Preload arguments for {tool} must be an object"));
    }
    Ok(Preload {
        tool: tool.to_string(),
        arguments,
    })
}

pub fn builtin() -> Vec<Skill> {
    BUILTIN
        .iter()
        .filter_map(|(_, text)| parse(text, true).ok())
        .collect()
}

pub fn user_dir(app: &AppHandle) -> Res<PathBuf> {
    let dir = app.path().app_data_dir().map_err(err)?.join("skills");
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir)
}

fn load_user(app: &AppHandle) -> Vec<Skill> {
    let Ok(dir) = user_dir(app) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten().take(MAX_USER_SKILLS * 2) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() || meta.len() as usize > MAX_SKILL_BYTES {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(skill) = parse(&text, false) {
                // The file name is the identity used by save/delete/source.
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if stem == skill.name && !out.iter().any(|s: &Skill| s.name == skill.name) {
                    out.push(skill);
                }
            }
        }
        if out.len() >= MAX_USER_SKILLS {
            break;
        }
    }
    out
}

/// Merge built-in and user skills; user skills override built-ins by name.
pub fn merge(builtin: Vec<Skill>, user: Vec<Skill>) -> Vec<Skill> {
    let mut all: Vec<Skill> = builtin
        .into_iter()
        .map(|mut s| {
            s.overridden = user.iter().any(|u| u.name == s.name);
            s
        })
        .filter(|s| !s.overridden)
        .collect();
    all.extend(user.into_iter().map(|mut s| {
        s.overridden = BUILTIN.iter().any(|(n, _)| *n == s.name);
        s
    }));
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all
}

pub fn all(app: Option<&AppHandle>) -> Vec<Skill> {
    let user = app.map(load_user).unwrap_or_default();
    merge(builtin(), user)
}

/// Deterministic router: score skills by trigger hits in the task.
/// Returns the best-matching skill name, if any trigger matched.
pub fn route(task: &str, skills: &[Skill]) -> Option<String> {
    let lower = task.to_lowercase();
    let mut best: Option<(usize, &Skill)> = None;
    for skill in skills.iter().filter(|s| !s.always) {
        let score: usize = skill
            .triggers
            .iter()
            .filter(|t| !t.is_empty() && lower.contains(t.as_str()))
            .map(|t| 1 + t.len() / 6)
            .sum();
        if score > 0 && best.is_none_or(|(s, _)| score > s) {
            best = Some((score, skill));
        }
    }
    best.map(|(_, s)| s.name.clone())
}

/// `/skill-name rest of task` -> (skill, rest)
pub fn slash(task: &str) -> Option<(String, String)> {
    let trimmed = task.trim_start();
    let rest = trimmed.strip_prefix('/')?;
    let (name, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    valid_name(name).then(|| (name.to_string(), tail.trim().to_string()))
}

#[tauri::command]
pub fn skill_list(app: AppHandle) -> Vec<Skill> {
    all(Some(&app))
}

#[tauri::command]
pub fn skill_dir(app: AppHandle) -> Res<String> {
    Ok(user_dir(&app)?.to_string_lossy().to_string())
}

#[tauri::command]
pub fn skill_save(app: AppHandle, text: String) -> Res<Skill> {
    let skill = parse(&text, false)?;
    let dir = user_dir(&app)?;
    let count = std::fs::read_dir(&dir)
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("md"))
                .count()
        })
        .unwrap_or(0);
    let path = dir.join(format!("{}.md", skill.name));
    if !path.exists() && count >= MAX_USER_SKILLS {
        return Err(format!("At most {MAX_USER_SKILLS} user skills"));
    }
    let temp = path.with_extension("md.tmp");
    std::fs::write(&temp, text.replace("\r\n", "\n")).map_err(err)?;
    std::fs::rename(temp, &path).map_err(err)?;
    Ok(skill)
}

#[tauri::command]
pub fn skill_delete(app: AppHandle, name: String) -> Res<()> {
    if !valid_name(&name) {
        return Err("Invalid skill name".into());
    }
    let path = user_dir(&app)?.join(format!("{name}.md"));
    if !path.exists() {
        return Err("Only user skills can be deleted; built-in skills are read-only".into());
    }
    std::fs::remove_file(path).map_err(err)
}

/// Import a Markdown skill file chosen by the analyst (e.g. from a team repo).
/// The file is parsed and validated exactly like an edited skill, then copied
/// into the user skills folder under its front-matter name.
#[tauri::command]
pub fn skill_import(app: AppHandle, path: String) -> Res<Skill> {
    let path = std::path::PathBuf::from(path);
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("md"))
        != Some(true)
    {
        return Err("Select a .md skill file".into());
    }
    let meta = std::fs::metadata(&path).map_err(err)?;
    if !meta.is_file() || meta.len() as usize > MAX_SKILL_BYTES {
        return Err(format!(
            "Skill files must be regular files up to {MAX_SKILL_BYTES} bytes"
        ));
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("Skill file is not UTF-8 text: {e}"))?;
    skill_save(app, text)
}

/// Source text of a skill, for "duplicate and edit" in the UI.
#[tauri::command]
pub fn skill_source(app: AppHandle, name: String) -> Res<String> {
    if !valid_name(&name) {
        return Err("Invalid skill name".into());
    }
    let path = user_dir(&app)?.join(format!("{name}.md"));
    if path.exists() {
        return std::fs::read_to_string(path).map_err(err);
    }
    BUILTIN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| t.replace("\r\n", "\n"))
        .ok_or_else(|| "Skill not found".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_skills_parse() {
        for (name, text) in BUILTIN {
            let skill = parse(text, true).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&skill.name, name);
            assert!(!skill.triggers.is_empty(), "{name} has no triggers");
        }
        assert_eq!(builtin().len(), BUILTIN.len());
    }

    #[test]
    fn parses_lists_and_preload_arguments() {
        let s = parse(
            "---\nname: demo\ndescription: A demo skill for testing\ntriggers:\n  - Foo\n  - bar\npreload:\n  - findings {\"severity\": \"high\"}\n  - event_stats\nalways: true\n---\n# Body\nstep",
            false,
        )
        .unwrap();
        assert_eq!(s.triggers, vec!["foo", "bar"]);
        assert_eq!(s.preload.len(), 2);
        assert_eq!(s.preload[0].arguments["severity"], "high");
        assert!(s.always);
    }

    #[test]
    fn rejects_bad_skills() {
        assert!(parse("no front matter", false).is_err());
        assert!(parse(
            "---\nname: Bad Name\ndescription: long enough text\n---\nbody",
            false
        )
        .is_err());
        assert!(parse(
            "---\nname: ok\ndescription: long enough text\npreload:\n  - rm -rf\n---\nbody",
            false
        )
        .is_err());
        assert!(parse("---\nname: ok\ndescription: long enough text\n---\n", false).is_err());
    }

    #[test]
    fn routing_and_slash_commands() {
        let skills = builtin();
        assert_eq!(
            route("Bu oltalama kampanyasını incele", &skills).as_deref(),
            Some("phishing-triage")
        );
        assert_eq!(
            route("Write a detection rule for forwarding", &skills).as_deref(),
            Some("detection-engineering")
        );
        assert_eq!(
            route("fatura ödeme talebi sahte mi", &skills).as_deref(),
            Some("bec-fraud")
        );
        assert_eq!(route("hmm", &skills), None);
        assert_eq!(
            slash("/bec-fraud check invoices"),
            Some(("bec-fraud".into(), "check invoices".into()))
        );
        assert_eq!(slash("no slash"), None);
    }

    #[test]
    fn user_skill_overrides_builtin() {
        let user = parse(
            "---\nname: triage\ndescription: Company specific triage\n---\nbody",
            false,
        )
        .unwrap();
        let merged = merge(builtin(), vec![user]);
        let triage: Vec<_> = merged.iter().filter(|s| s.name == "triage").collect();
        assert_eq!(triage.len(), 1);
        assert!(!triage[0].builtin);
        assert!(triage[0].overridden);
    }
}
