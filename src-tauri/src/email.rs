//! Deterministic e-mail forensics: header, Received-chain, authentication, URL and
//! attachment analysis for EML and MBOX evidence.
//!
//! Everything here is static. Message bodies and attachments are untrusted data:
//! they are hashed and inspected as bytes/text, never executed, rendered or opened.
//! No network lookups are made (no DNS, WHOIS, sandbox or reputation services).

use mailparse::{MailHeaderMap, ParsedMail};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::LazyLock;

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static regex")
}

static URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r#"(?i)\bhttps?://[^\s"'<>\)\]]+"#));
static HREF_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r#"(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>"#));
static TAG_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?s)<[^>]+>"));
static RCV_FROM: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)\bfrom\s+([^\s;()\[]+)"));
static RCV_BY: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)\bby\s+([^\s;()]+)"));
static RCV_IP: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?"));
static RCV_WITH: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)\bwith\s+([A-Za-z0-9]+)"));
static AUTH_RE: LazyLock<[regex::Regex; 3]> =
    LazyLock::new(|| ["spf", "dkim", "dmarc"].map(|m| re(&format!(r"(?i)\b{m}\s*=\s*([a-z]+)"))));

const MAX_URLS: usize = 100;
const MAX_ATTACHMENTS: usize = 50;
const MAX_HOPS: usize = 30;
const MAX_MBOX_MESSAGES: usize = 5_000;
const MAX_PARTS: usize = 200;

/// Brands frequently impersonated in credential phishing. Used only for
/// look-alike detection against domains found in the message.
const BRANDS: &[&str] = &[
    "microsoft",
    "office365",
    "outlook",
    "live",
    "google",
    "gmail",
    "apple",
    "icloud",
    "paypal",
    "amazon",
    "docusign",
    "dropbox",
    "adobe",
    "linkedin",
    "dhl",
    "fedex",
    "netflix",
    "sharepoint",
    "onedrive",
    "wetransfer",
];

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
];

const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf",
    "hta", "lnk", "iso", "img", "vhd", "vhdx", "msi", "jar", "reg", "cpl", "chm", "one",
];
const MACRO_EXTENSIONS: &[&str] = &["docm", "xlsm", "pptm", "dotm", "xlam", "xlsb", "ppsm"];
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"];
const DOC_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "csv",
];

const CREDENTIAL_WORDS: &[&str] = &[
    "login", "signin", "sign-in", "verify", "account", "password", "auth", "secure", "update",
    "wallet", "invoice", "billing", "sso", "mfa",
];

const BEC_WORDS: &[&str] = &[
    "invoice",
    "payment",
    "wire transfer",
    "bank details",
    "bank account",
    "iban",
    "urgent",
    "change of account",
    "remittance",
    "fatura",
    "ödeme",
    "havale",
    "banka hesab",
    "acil",
    "rechnung",
    "zahlung",
    "bankverbindung",
    "gift card",
];

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Extract the bare address from a header such as `"Name" <a@b.c>`.
pub fn address(value: &str) -> String {
    let value = value.trim();
    if let (Some(start), Some(end)) = (value.rfind('<'), value.rfind('>')) {
        if start < end {
            return value[start + 1..end].trim().to_ascii_lowercase();
        }
    }
    value
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .find(|part| part.contains('@'))
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')')
        .to_ascii_lowercase()
}

fn display_name(value: &str) -> String {
    match value.find('<') {
        Some(i) => value[..i].trim().trim_matches('"').trim().to_string(),
        None => String::new(),
    }
}

pub fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| d.trim().trim_end_matches('>').to_ascii_lowercase())
        .unwrap_or_default()
}

/// Registrable-ish domain: last two labels (good enough for alignment heuristics
/// without a public-suffix list; documented as a heuristic).
fn base_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return domain.to_string();
    }
    let n = labels.len();
    let two_level_tld = matches!(
        labels[n - 2],
        "co" | "com" | "org" | "net" | "gov" | "ac" | "edu"
    ) && labels[n - 1].len() == 2;
    if two_level_tld && n >= 3 {
        labels[n - 3..].join(".")
    } else {
        labels[n - 2..].join(".")
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Map common homoglyph digit/letter substitutions back to letters.
fn deconfuse(label: &str) -> String {
    label
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' => 'l',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            'а' => 'a', // Cyrillic
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'х' => 'x',
            'і' => 'i',
            _ => c,
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

/// Look-alike check of a domain against impersonated brands. Returns the brand
/// and the technique when the domain imitates but is not the brand itself.
pub fn lookalike(domain: &str) -> Option<(String, &'static str)> {
    let domain = domain.to_ascii_lowercase();
    let base = base_domain(&domain);
    // Tokens of every label, split on '.' and '-': micr0soft-365.example.net
    // -> [micr0soft, 365, example, net]. Whole-token matching avoids hits such
    // as "live" inside "deliver".
    let tokens: Vec<&str> = domain.split(['.', '-']).filter(|t| !t.is_empty()).collect();
    let first = base.split('.').next().unwrap_or("");
    for &brand in BRANDS {
        let official = [
            format!("{brand}.com"),
            format!("{brand}.net"),
            format!("{brand}.de"),
        ];
        if official.contains(&base) {
            return None;
        }
        for token in &tokens {
            if *token == brand {
                return Some((
                    brand.into(),
                    if first == brand {
                        "brand name on unofficial TLD"
                    } else {
                        "brand keyword in unrelated domain"
                    },
                ));
            }
            let cleaned = deconfuse(token);
            if cleaned == brand
                || (brand.len() >= 6 && cleaned.starts_with(brand) && !token.starts_with(brand))
            {
                return Some((brand.into(), "homoglyph substitution"));
            }
            if token.len() >= 5 && brand.len() >= 5 && levenshtein(token, brand) == 1 {
                return Some((brand.into(), "typosquatting (edit distance 1)"));
            }
        }
    }
    None
}

fn is_ip_literal(host: &str) -> bool {
    host.split('.').count() == 4 && host.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    matches!(parts[0], 10 | 127)
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
}

fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    host.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// Static URL assessment. No request is made to the URL.
pub fn analyze_url(url: &str, anchor_text: Option<&str>) -> Value {
    let host = url_host(url);
    let lower = url.to_ascii_lowercase();
    let mut flags: Vec<String> = Vec::new();
    if host.starts_with("xn--") || host.contains(".xn--") {
        flags.push("punycode/IDN domain".into());
    }
    if !host.is_ascii() {
        flags.push("non-ASCII (possible homoglyph) domain".into());
    }
    if is_ip_literal(&host) {
        flags.push("IP address instead of domain".into());
    }
    if SHORTENERS
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    {
        flags.push("URL shortener".into());
    }
    if let Some((brand, technique)) = lookalike(&host) {
        flags.push(format!("look-alike of {brand}: {technique}"));
    }
    if url.contains('@')
        && url
            .split_once("://")
            .map(|(_, r)| r.split('/').next().unwrap_or("").contains('@'))
            .unwrap_or(false)
    {
        flags.push("userinfo '@' trick in URL".into());
    }
    if lower.contains("%2f%2f") || lower.matches('%').count() > 6 {
        flags.push("heavy URL encoding".into());
    }
    for key in [
        "redirect=",
        "url=",
        "next=",
        "returnurl=",
        "continue=",
        "dest=",
    ] {
        if lower.contains(key) && lower.contains("http") && lower.matches("http").count() > 1 {
            flags.push("embedded redirect target (possible open redirect)".into());
            break;
        }
    }
    if url.starts_with("http://") {
        flags.push("unencrypted HTTP".into());
    }
    let path = lower.split_once(&host).map(|(_, p)| p).unwrap_or("");
    let credential_path = CREDENTIAL_WORDS.iter().any(|w| path.contains(w));
    let mut anchor_mismatch = false;
    if let Some(text) = anchor_text {
        let text = text.trim().to_ascii_lowercase();
        if text.contains('.')
            && (text.starts_with("http") || text.starts_with("www.") || text.contains(".com"))
        {
            let shown = url_host(&text);
            if !shown.is_empty() && base_domain(&shown) != base_domain(&host) {
                anchor_mismatch = true;
                flags.push(format!(
                    "visible link text shows {shown} but target is {host}"
                ));
            }
        }
    }
    let suspicious = !flags.is_empty() && !(flags.len() == 1 && flags[0] == "unencrypted HTTP");
    if suspicious && credential_path {
        flags.push("credential-harvest style path".into());
    }
    json!({
        "url": url.chars().take(500).collect::<String>(),
        "host": host,
        "anchor_mismatch": anchor_mismatch,
        "flags": flags,
        "suspicious": suspicious,
    })
}

fn extract_urls(text: &str) -> Vec<String> {
    let re = &*URL_RE;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for m in re.find_iter(text) {
        let url = m.as_str().trim_end_matches(['.', ',', ';']).to_string();
        if seen.insert(url.clone()) {
            out.push(url);
        }
        if out.len() >= MAX_URLS {
            break;
        }
    }
    out
}

fn html_links(html: &str) -> Vec<(String, String)> {
    let re = &*HREF_RE;
    let tags = &*TAG_RE;
    re.captures_iter(html)
        .take(MAX_URLS)
        .map(|c| {
            (
                c[1].to_string(),
                tags.replace_all(&c[2], "").trim().to_string(),
            )
        })
        .collect()
}

fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, e)| e.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Static attachment assessment from name, declared MIME type and bytes.
pub fn analyze_attachment(filename: &str, mime: &str, bytes: &[u8]) -> Value {
    let ext = extension(filename);
    let mut flags: Vec<String> = Vec::new();
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() >= 3 {
        let inner = parts[parts.len() - 2].to_ascii_lowercase();
        if DOC_EXTENSIONS.contains(&inner.as_str())
            && (RISKY_EXTENSIONS.contains(&ext.as_str())
                || ARCHIVE_EXTENSIONS.contains(&ext.as_str()))
        {
            flags.push(format!("double extension (.{inner}.{ext})"));
        }
    }
    if filename.chars().any(|c| c == '\u{202e}') {
        flags.push("right-to-left override in filename".into());
    }
    if RISKY_EXTENSIONS.contains(&ext.as_str()) {
        flags.push(format!("executable or script type .{ext}"));
    }
    if MACRO_EXTENSIONS.contains(&ext.as_str()) {
        flags.push(format!("macro-enabled Office file .{ext}"));
    }
    // Magic-byte checks (type confusion).
    let magic = if bytes.starts_with(b"MZ") {
        "pe-executable"
    } else if bytes.starts_with(b"PK\x03\x04") {
        "zip-container"
    } else if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        "ole-compound"
    } else if bytes.starts_with(b"%PDF") {
        "pdf"
    } else if bytes.len() > 0x8006 && &bytes[0x8001..0x8006] == b"CD001" {
        "iso9660"
    } else if bytes.starts_with(b"Rar!") {
        "rar"
    } else {
        "unknown"
    };
    if magic == "pe-executable" && ext != "exe" && ext != "dll" {
        flags.push("executable content disguised by extension".into());
    }
    if magic == "zip-container" && ext == "zip" && bytes.len() > 8 && bytes[6] & 0x01 == 1 {
        flags.push("encrypted ZIP archive".into());
    }
    if magic == "ole-compound" && bytes.windows(4).any(|w| w == b"VBA\0" || w == b"_VBA") {
        flags.push("VBA macro stream present".into());
    }
    if magic == "zip-container" && bytes.windows(14).any(|w| w == b"vbaProject.bin") {
        flags.push("VBA macro project present".into());
    }
    let mime_lower = mime.to_ascii_lowercase();
    if ext == "pdf" && magic != "pdf" && magic != "unknown" {
        flags.push(format!("declared PDF but content is {magic}"));
    }
    if mime_lower.starts_with("application/msword") && ext == "docm" {
        flags.push("MIME/extension mismatch".into());
    }
    json!({
        "filename": filename.chars().take(255).collect::<String>(),
        "mime": mime,
        "extension": ext,
        "size": bytes.len(),
        "sha256": sha256_hex(bytes),
        "detected_type": magic,
        "flags": flags,
        "suspicious": !flags.is_empty(),
        "executed": false,
    })
}

/// One hop of the Received chain, top (newest) first.
fn parse_received(value: &str) -> Value {
    let v = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let cap = |re: &regex::Regex| -> String {
        re.captures(&v)
            .map(|c| c[1].to_string())
            .unwrap_or_default()
    };
    let from = cap(&RCV_FROM);
    let by = cap(&RCV_BY);
    let ip = cap(&RCV_IP);
    let with = cap(&RCV_WITH);
    let date_text = v.rsplit_once(';').map(|(_, d)| d.trim()).unwrap_or("");
    let ts = mailparse::dateparse(date_text).ok();
    json!({
        "from": from,
        "by": by,
        "ip": ip,
        "with": with,
        "date": ts.map(rfc3339).unwrap_or_default(),
        "epoch": ts,
    })
}

fn rfc3339(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

fn auth_result(text: &str, mech: &str) -> String {
    let index = match mech {
        "spf" => 0,
        "dkim" => 1,
        _ => 2,
    };
    AUTH_RE[index]
        .captures(text)
        .map(|c| c[1].to_ascii_lowercase())
        .unwrap_or_default()
}

struct Body {
    text: String,
    links: Vec<(String, String)>,
    attachments: Vec<Value>,
}

fn walk(part: &ParsedMail<'_>, body: &mut Body, count: &mut usize, warnings: &mut Vec<String>) {
    *count += 1;
    if *count > MAX_PARTS {
        return;
    }
    let disposition = part.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .cloned();
    let mime = part.ctype.mimetype.to_ascii_lowercase();
    let is_attachment = filename.is_some()
        || matches!(
            disposition.disposition,
            mailparse::DispositionType::Attachment
        );
    if part.subparts.is_empty() {
        if is_attachment {
            if body.attachments.len() < MAX_ATTACHMENTS {
                match part.get_body_raw() {
                    Ok(bytes) => body.attachments.push(analyze_attachment(
                        filename.as_deref().unwrap_or("unnamed"),
                        &mime,
                        &bytes,
                    )),
                    Err(e) => warnings.push(format!("attachment decode failed: {e}")),
                }
            }
        } else if mime.starts_with("text/") {
            if let Ok(text) = part.get_body() {
                if mime == "text/html" {
                    body.links.extend(html_links(&text));
                }
                body.text
                    .push_str(&text.chars().take(200_000).collect::<String>());
                body.text.push('\n');
            }
        }
    }
    for sub in &part.subparts {
        walk(sub, body, count, warnings);
    }
}

/// Full static analysis of one RFC 5322 message. Returns a JSON object whose
/// top-level keys (`timestamp`, `from`, `to`, `ip`, `message_id`, `action`) are
/// picked up by the normaliser, plus an `email_analysis` section and an
/// `indicators` list that the keyword detection rules match against.
pub fn analyze_message(bytes: &[u8], warnings: &mut Vec<String>) -> Result<Value, String> {
    let m = mailparse::parse_mail(bytes).map_err(|e| e.to_string())?;
    let h = &m.headers;
    let get = |k: &str| h.get_first_value(k).unwrap_or_default();
    let from_raw = get("From");
    let from = address(&from_raw);
    let from_domain = domain_of(&from);
    let return_path = address(&get("Return-Path"));
    let reply_to = address(&get("Reply-To"));
    let to = get("To");
    let cc = get("Cc");
    let subject = get("Subject");
    let date_epoch = mailparse::dateparse(&get("Date")).ok();
    let auth_text = h.get_all_values("Authentication-Results").join(" ; ")
        + " "
        + &h.get_all_values("ARC-Authentication-Results").join(" ; ")
        + " "
        + &get("Received-SPF");
    let spf = {
        let r = auth_result(&auth_text, "spf");
        if r.is_empty() {
            get("Received-SPF")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        } else {
            r
        }
    };
    let dkim = auth_result(&auth_text, "dkim");
    let dmarc = auth_result(&auth_text, "dmarc");

    let hops: Vec<Value> = h
        .get_all_values("Received")
        .iter()
        .take(MAX_HOPS)
        .map(|v| parse_received(v))
        .collect();
    // Originating hop: bottom-most hop with a public IP.
    let origin_ip = hops
        .iter()
        .rev()
        .filter_map(|hop| hop["ip"].as_str())
        .find(|ip| !ip.is_empty() && !is_private_ip(ip))
        .unwrap_or("")
        .to_string();

    let mut indicators: Vec<String> = Vec::new();
    let mut chain_flags: Vec<String> = Vec::new();
    // Received headers are prepended, so epochs should not increase going down.
    let epochs: Vec<i64> = hops.iter().filter_map(|x| x["epoch"].as_i64()).collect();
    for pair in epochs.windows(2) {
        if pair[1] > pair[0] + 300 {
            chain_flags
                .push("Received timestamps out of order (possible forged lower hops)".into());
            break;
        }
    }
    if let (Some(first), Some(date)) = (epochs.first(), date_epoch) {
        if (first - date).abs() > 86_400 {
            chain_flags.push("Date header differs from delivery time by more than 24h".into());
        }
    }
    if hops.iter().any(|x| {
        x["from"]
            .as_str()
            .map(|f| f.eq_ignore_ascii_case("unknown") || f.starts_with("unknown"))
            .unwrap_or(false)
    }) {
        chain_flags.push("relay without resolvable hostname (unknown)".into());
    }

    let mut mismatches: Vec<String> = Vec::new();
    if !return_path.is_empty()
        && !from_domain.is_empty()
        && base_domain(&domain_of(&return_path)) != base_domain(&from_domain)
    {
        mismatches.push(format!(
            "Return-Path domain {} differs from From domain {}",
            domain_of(&return_path),
            from_domain
        ));
        indicators.push("header from mismatch".into());
    }
    if !reply_to.is_empty()
        && !from_domain.is_empty()
        && base_domain(&domain_of(&reply_to)) != base_domain(&from_domain)
    {
        mismatches.push(format!(
            "Reply-To {} redirects replies away from From domain {}",
            reply_to, from_domain
        ));
        indicators.push("reply-to mismatch".into());
    }
    let name = display_name(&from_raw);
    if name.contains('@') && address(&name) != from {
        mismatches.push(format!("display name shows {name} but address is {from}"));
        indicators.push("display name mismatch".into());
    }
    if let Some((brand, technique)) = lookalike(&from_domain) {
        mismatches.push(format!(
            "sender domain {from_domain} imitates {brand} ({technique})"
        ));
        indicators.push("lookalike sender domain".into());
    }

    let mut body = Body {
        text: String::new(),
        links: Vec::new(),
        attachments: Vec::new(),
    };
    let mut parts = 0usize;
    walk(&m, &mut body, &mut parts, warnings);
    if parts > MAX_PARTS {
        warnings.push(format!(
            "MIME part limit {MAX_PARTS} reached; remaining parts skipped"
        ));
    }

    let mut urls: Vec<Value> = Vec::new();
    let mut seen = BTreeSet::new();
    for (href, text) in &body.links {
        if href.starts_with("http") && seen.insert(href.clone()) && urls.len() < MAX_URLS {
            urls.push(analyze_url(href, Some(text)));
        }
    }
    for url in extract_urls(&body.text) {
        if seen.insert(url.clone()) && urls.len() < MAX_URLS {
            urls.push(analyze_url(&url, None));
        }
    }
    let suspicious_urls = urls.iter().filter(|u| u["suspicious"] == true).count();
    if suspicious_urls > 0 {
        indicators.push("phishing link".into());
    }
    if urls.iter().any(|u| u["anchor_mismatch"] == true) {
        indicators.push("deceptive link text".into());
    }
    let risky_attachments = body
        .attachments
        .iter()
        .filter(|a| a["suspicious"] == true)
        .count();
    if risky_attachments > 0 {
        indicators.push("malicious attachment".into());
    }
    let corpus = format!("{subject}\n{}", body.text).to_lowercase();
    let bec_terms: Vec<&str> = BEC_WORDS
        .iter()
        .copied()
        .filter(|w| corpus.contains(w))
        .collect();
    if !bec_terms.is_empty() && (!reply_to.is_empty() || !mismatches.is_empty()) {
        indicators.push("payment request with sender mismatch".into());
    }
    for (mech, result) in [("spf", &spf), ("dkim", &dkim), ("dmarc", &dmarc)] {
        if matches!(result.as_str(), "fail" | "softfail" | "permerror") {
            indicators.push(format!("{mech}={result}"));
        }
    }
    if !chain_flags.is_empty() {
        indicators.push("received chain anomaly".into());
    }

    let risk_score = indicators.len() * 10
        + suspicious_urls * 10
        + risky_attachments * 20
        + usize::from(dmarc == "fail") * 10;
    let mut o = Map::new();
    o.insert(
        "timestamp".into(),
        json!(date_epoch.map(rfc3339).unwrap_or_default()),
    );
    o.insert("from".into(), json!(from));
    o.insert("to".into(), json!(address(&to)));
    o.insert("ip".into(), json!(origin_ip));
    o.insert("message_id".into(), json!(get("Message-ID").trim()));
    o.insert("action".into(), json!("deliver"));
    o.insert("subject".into(), json!(subject));
    o.insert(
        "email_analysis".into(),
        json!({
            "header": {
                "from": from_raw, "display_name": name, "to": to, "cc": cc,
                "return_path": return_path, "reply_to": reply_to, "subject": subject,
                "date": date_epoch.map(rfc3339).unwrap_or_default(),
                "x_mailer": get("X-Mailer"), "x_originating_ip": get("X-Originating-IP"),
            },
            "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc,
                "note": "Passing SPF/DKIM/DMARC does not prove legitimacy; a compromised real account passes all three."},
            "received_chain": hops,
            "origin_ip": origin_ip,
            "chain_flags": chain_flags,
            "mismatches": mismatches,
            "urls": urls,
            "attachments": body.attachments,
            "bec_terms": bec_terms,
            "risk_score": risk_score.min(100),
            "platforms": super::sources::message_platforms(
                &h.iter().map(|x| x.get_key()).collect::<Vec<_>>(),
                &hops,
                &h.get_all_values("Received").join("\n"),
            ),
        }),
    );
    o.insert("indicators".into(), json!(indicators));
    Ok(Value::Object(o))
}

/// Split an mboxrd/mboxo file on `From ` separator lines.
pub fn split_mbox(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut at_line_start = true;
    for (i, &b) in bytes.iter().enumerate() {
        if at_line_start && bytes[i..].starts_with(b"From ") {
            starts.push(i);
        }
        at_line_start = b == b'\n';
        if starts.len() > MAX_MBOX_MESSAGES {
            break;
        }
    }
    if starts.is_empty() {
        return vec![bytes];
    }
    let mut out = Vec::new();
    for (n, &s) in starts.iter().enumerate().take(MAX_MBOX_MESSAGES) {
        let end = starts.get(n + 1).copied().unwrap_or(bytes.len());
        let chunk = &bytes[s..end];
        // Drop the separator line itself.
        let body = chunk
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| &chunk[p + 1..])
            .unwrap_or(&[]);
        if !body.is_empty() {
            out.push(body);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHISH: &str = "Received: from mx.company.test (mx.company.test [10.0.0.5]) by inbox.company.test; Tue, 25 Nov 2026 10:15:40 +0100\r\n\
Received: from unknown (198.51.100.20) by mx.company.test with ESMTP; Tue, 25 Nov 2026 10:15:30 +0100\r\n\
Authentication-Results: mx.company.test; spf=fail smtp.mailfrom=micr0soft-support.test; dkim=none; dmarc=fail header.from=micr0soft.com\r\n\
From: \"Microsoft 365\" <no-reply@micr0soft.com>\r\n\
Reply-To: helpdesk@collector.example\r\n\
Return-Path: <bounce@micr0soft-support.test>\r\n\
To: alice@company.test\r\n\
Subject: Action required: verify your account\r\n\
Date: Tue, 25 Nov 2026 10:15:00 +0100\r\n\
Message-ID: <phish-1@micr0soft.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/html\r\n\r\n<a href=\"https://micr0soft-login.example.net/auth/login\">https://microsoft.com/login</a>\r\n\
--B\r\nContent-Type: application/octet-stream; name=\"Invoice_2026.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"Invoice_2026.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--B--\r\n";

    #[test]
    fn phishing_message_is_fully_analyzed() {
        let mut warnings = Vec::new();
        let v = analyze_message(PHISH.as_bytes(), &mut warnings).unwrap();
        let a = &v["email_analysis"];
        assert_eq!(a["authentication"]["spf"], "fail");
        assert_eq!(a["authentication"]["dmarc"], "fail");
        assert_eq!(v["ip"], "198.51.100.20");
        assert_eq!(v["from"], "no-reply@micr0soft.com");
        assert!(v["timestamp"]
            .as_str()
            .unwrap()
            .starts_with("2026-11-25T09:15:00"));
        let indicators = v["indicators"].to_string();
        for needle in [
            "reply-to mismatch",
            "header from mismatch",
            "lookalike sender domain",
            "phishing link",
            "deceptive link text",
            "malicious attachment",
            "spf=fail",
            "dmarc=fail",
        ] {
            assert!(
                indicators.contains(needle),
                "missing {needle}: {indicators}"
            );
        }
        let att = &a["attachments"][0];
        assert_eq!(att["detected_type"], "pe-executable");
        assert!(att["flags"].to_string().contains("double extension"));
        assert_eq!(att["executed"], false);
        assert!(a["urls"][0]["anchor_mismatch"].as_bool().unwrap());
    }

    #[test]
    fn benign_message_has_no_indicators() {
        let mail = "From: Bob <bob@company.test>\r\nTo: alice@company.test\r\nSubject: Lunch\r\nDate: Tue, 25 Nov 2026 12:00:00 +0000\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\nSee https://intranet.company.test/menu\r\n";
        let v = analyze_message(mail.as_bytes(), &mut Vec::new()).unwrap();
        assert_eq!(
            v["indicators"].as_array().unwrap().len(),
            0,
            "{}",
            v["indicators"]
        );
    }

    #[test]
    fn lookalike_detection() {
        assert!(lookalike("micr0soft.com").is_some());
        assert!(lookalike("microsoft-login.example.net").is_some());
        assert!(lookalike("paypa1.com").is_some());
        assert!(lookalike("microsoft.com").is_none());
        assert!(lookalike("login.microsoft.com").is_none());
        assert!(lookalike("company.test").is_none());
        assert!(lookalike("micr0soft-365.example.net").is_some());
        assert!(lookalike("deliver.example.net").is_none());
        assert!(lookalike("tedarikci-fatura.example.net").is_none());
        assert!(lookalike("paypal.example.org").is_some());
    }

    #[test]
    fn url_flags() {
        assert!(
            analyze_url("https://xn--mcrosoft-3ya.com/login", None)["suspicious"]
                .as_bool()
                .unwrap()
        );
        assert!(analyze_url("https://bit.ly/abc", None)["suspicious"]
            .as_bool()
            .unwrap());
        assert!(analyze_url("http://203.0.113.5/login", None)["suspicious"]
            .as_bool()
            .unwrap());
        assert!(
            !analyze_url("https://intranet.company.test/a", None)["suspicious"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn mbox_split() {
        let mbox = b"From a@b Tue Nov 25 10:00:00 2026\nSubject: one\n\nx\nFrom c@d Tue Nov 25 10:01:00 2026\nSubject: two\n\ny\n";
        let parts = split_mbox(mbox);
        assert_eq!(parts.len(), 2);
        assert!(parts[1].starts_with(b"Subject: two"));
    }

    #[test]
    fn attachment_flags() {
        assert!(
            analyze_attachment("report.docm", "application/msword", b"PK\x03\x04")["flags"]
                .to_string()
                .contains("macro")
        );
        assert!(
            analyze_attachment("photo.jpg.lnk", "", b"L\0\0\0")["suspicious"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !analyze_attachment("notes.pdf", "application/pdf", b"%PDF-1.7")["suspicious"]
                .as_bool()
                .unwrap()
        );
    }
}
