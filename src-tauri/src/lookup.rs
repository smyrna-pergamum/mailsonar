//! Manual reputation check: open an indicator on VirusTotal in the system browser.
//!
//! Nothing is queried automatically. The analyst clicks a link; the backend
//! validates the indicator, builds a fixed `https://www.virustotal.com/gui/...`
//! address and hands it to the operating system's URL handler without a shell.
//! The indicator becomes visible to VirusTotal (a third party): the UI says so.

use super::err;

type Res<T> = Result<T, String>;

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Build the VirusTotal GUI address for an indicator, or reject it.
pub fn virustotal_url(kind: &str, value: &str) -> Res<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err("Invalid indicator".into());
    }
    let base = "https://www.virustotal.com/gui";
    match kind {
        "domain" => {
            let domain = value.trim_end_matches('.').to_ascii_lowercase();
            let ok = domain.contains('.')
                && domain.len() <= 253
                && domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
            if !ok {
                return Err("Invalid domain".into());
            }
            Ok(format!("{base}/domain/{domain}"))
        }
        "ip" => {
            let ip: std::net::IpAddr = value
                .parse()
                .map_err(|_| "Invalid IP address".to_string())?;
            Ok(format!("{base}/ip-address/{ip}"))
        }
        "hash" => {
            let ok =
                matches!(value.len(), 32 | 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit());
            if !ok {
                return Err("Hash must be MD5, SHA-1 or SHA-256 hex".into());
            }
            Ok(format!("{base}/file/{}", value.to_ascii_lowercase()))
        }
        "url" => {
            let parsed = reqwest::Url::parse(value).map_err(|_| "Invalid URL".to_string())?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err("Only http(s) URLs can be looked up".into());
            }
            Ok(format!("{base}/search/{}", encode(parsed.as_str())))
        }
        _ => Err("Unknown indicator type".into()),
    }
}

fn open_in_browser(url: &str) -> Res<()> {
    // Fixed programs, one argument, no shell: the URL cannot be interpreted as a command.
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ()).map_err(err)
}

#[tauri::command]
pub fn open_lookup(kind: String, value: String) -> Res<String> {
    let url = virustotal_url(&kind, &value)?;
    open_in_browser(&url)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_only_virustotal_addresses() {
        assert_eq!(
            virustotal_url("domain", "Micr0soft-365.example.net").unwrap(),
            "https://www.virustotal.com/gui/domain/micr0soft-365.example.net"
        );
        assert_eq!(
            virustotal_url("ip", "198.51.100.20").unwrap(),
            "https://www.virustotal.com/gui/ip-address/198.51.100.20"
        );
        assert!(virustotal_url("hash", &"a".repeat(64))
            .unwrap()
            .ends_with(&"a".repeat(64)));
        let u = virustotal_url("url", "https://bad.example/login?a=1&b=2").unwrap();
        assert!(u.starts_with("https://www.virustotal.com/gui/search/https%3A%2F%2Fbad.example"));
        assert!(!u.contains('&'));
        for (kind, value) in [
            ("domain", "a b.com"),
            ("domain", "x\"&calc"),
            ("ip", "1.2.3"),
            ("hash", "xyz"),
            ("url", "file:///etc/passwd"),
            ("url", "javascript:alert(1)"),
            ("other", "x"),
        ] {
            assert!(virustotal_url(kind, value).is_err(), "{kind} {value}");
        }
    }
}
