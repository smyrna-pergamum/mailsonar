//! Analyst-defined one-click AI analysis queries, stored as JSON in app data.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use super::err;

type Res<T> = Result<T, String>;

const MAX_QUERIES: usize = 50;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Query {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub hint: String,
    pub task: String,
    #[serde(default)]
    pub skill: String,
}

fn path(app: &AppHandle) -> Res<std::path::PathBuf> {
    let dir = app.path().app_data_dir().map_err(err)?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir.join("analysis-queries.json"))
}

pub fn validate(items: &[Query]) -> Res<()> {
    if items.len() > MAX_QUERIES {
        return Err(format!("At most {MAX_QUERIES} saved queries"));
    }
    let mut ids = std::collections::HashSet::new();
    for q in items {
        let id_ok = !q.id.is_empty()
            && q.id.len() <= 40
            && q.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !id_ok || !ids.insert(q.id.clone()) {
            return Err("Query ids must be unique, 1-40 chars of letters, digits and '-'".into());
        }
        if q.title.trim().is_empty() || q.title.len() > 80 {
            return Err("Query title must be 1-80 characters".into());
        }
        if q.hint.len() > 160 {
            return Err("Query hint must be at most 160 characters".into());
        }
        if q.task.trim().len() < 5 || q.task.len() > 4000 {
            return Err("Query text must be 5-4000 characters".into());
        }
        if !q.skill.is_empty() && !super::skills::valid_name(&q.skill) {
            return Err("Invalid skill name".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub fn queries_list(app: AppHandle) -> Res<Vec<Query>> {
    let p = path(&app)?;
    if !p.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&p).map_err(err)?;
    if bytes.len() > 1024 * 1024 {
        return Err("Saved query file is too large".into());
    }
    let items: Vec<Query> = serde_json::from_slice(&bytes).map_err(err)?;
    validate(&items)?;
    Ok(items)
}

#[tauri::command]
pub fn queries_save(app: AppHandle, items: Vec<Query>) -> Res<()> {
    validate(&items)?;
    let p = path(&app)?;
    let temp = p.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(&items).map_err(err)?).map_err(err)?;
    std::fs::rename(temp, p).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(id: &str, task: &str) -> Query {
        Query {
            id: id.into(),
            title: "T".into(),
            hint: String::new(),
            task: task.into(),
            skill: String::new(),
        }
    }

    #[test]
    fn validation() {
        assert!(validate(&[q("a-1", "Which accounts sent payment requests?")]).is_ok());
        assert!(validate(&[q("a", "x")]).is_err());
        assert!(validate(&[q("a", "valid task"), q("a", "valid task")]).is_err());
        assert!(validate(&[q("../x", "valid task")]).is_err());
        let mut bad = q("b", "valid task");
        bad.skill = "Bad Skill".into();
        assert!(validate(&[bad]).is_err());
    }
}
