use super::{err, Res};
use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};

// Fixed embedded code, no shell, no log-controlled executable or arguments.
#[tauri::command]
pub async fn export_pdf(path: String, report: Value) -> Res<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = serde_json::to_vec(&report).map_err(err)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("Report exceeds 2 MiB limit; export JSON instead".into());
        }
        let interpreter = if cfg!(windows) { "python" } else { "python3" };
        let mut child = Command::new(interpreter)
            .arg("-I")
            .arg("-c")
            .arg(include_str!("pdf_report.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                "Python 3 not available on PATH; install Python and ReportLab".to_string()
            })?;
        if let Some(mut input) = child.stdin.take() {
            if let Err(e) = input.write_all(&bytes) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err(e));
            }
        }
        let output = child.wait_with_output().map_err(err)?;
        if !output.status.success() {
            return Err(
                "PDF generator failed; check Python and ReportLab installation or use HTML export"
                    .into(),
            );
        }
        if !output.stdout.starts_with(b"%PDF-") || output.stdout.len() > 8 * 1024 * 1024 {
            return Err("Invalid or oversized PDF output".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(err)?;
        file.write_all(&output.stdout).map_err(err)
    })
    .await
    .map_err(err)?
}
