//! Log-source and mail-provider identification ("which system produced this?").
//!
//! Deterministic fingerprints, evaluated in order of specificity:
//! 1. An explicit source/workload field naming the product (`source`, `Workload`,
//!    `logged_by`, `reporting_mta`, `_sourceCategory`).
//! 2. The field-name signature of a known export format (e.g. `MessageTraceId`
//!    for an Exchange Online message trace, `CreationTime`+`Operation`+`Workload`
//!    for the Microsoft 365 unified audit log, `id.applicationName` for Google
//!    Workspace audit, `event-id`+`connector-id` for Exchange message tracking).
//! 3. Raw-line patterns of MTA/syslog formats (`postfix/smtpd[`, Exim `<=`,
//!    `sendmail[`, `dovecot:`, Cisco `MID n ICID`, Proofpoint `filter_instance`).
//! 4. For e-mail messages: Received hosts, provider-specific X- headers and
//!    DKIM signing domains reveal the sending and receiving platforms.
//!
//! Each result carries a confidence and the reasons that produced it, so the
//! analyst can verify the attribution. Heuristic: a re-exported or renamed log
//! can look like another product.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Source {
    pub vendor: &'static str,
    pub product: &'static str,
    pub log_type: &'static str,
    pub confidence: &'static str,
    pub reason: String,
}

fn src(
    vendor: &'static str,
    product: &'static str,
    log_type: &'static str,
    confidence: &'static str,
    reason: impl Into<String>,
) -> Source {
    Source {
        vendor,
        product,
        log_type,
        confidence,
        reason: reason.into(),
    }
}

/// Explicit product names that appear in `source`-like fields.
const NAMED: &[(&str, &str, &str, &str)] = &[
    (
        "exchange-online-audit",
        "Microsoft",
        "Exchange Online",
        "mailbox audit (unified audit log)",
    ),
    (
        "exchange online",
        "Microsoft",
        "Exchange Online",
        "audit / message trace",
    ),
    ("entra-id", "Microsoft", "Entra ID", "sign-in log"),
    ("azuread", "Microsoft", "Entra ID", "sign-in log"),
    ("azure ad", "Microsoft", "Entra ID", "sign-in log"),
    (
        "msexchange",
        "Microsoft",
        "Exchange Server",
        "message tracking / event log",
    ),
    (
        "google-workspace",
        "Google",
        "Google Workspace (Gmail)",
        "Gmail / admin audit log",
    ),
    ("gmail", "Google", "Google Workspace (Gmail)", "Gmail log"),
    ("postfix", "Postfix", "Postfix MTA", "MTA syslog"),
    ("exim", "Exim", "Exim MTA", "MTA log"),
    ("sendmail", "Sendmail", "Sendmail MTA", "MTA syslog"),
    (
        "dovecot",
        "Dovecot",
        "Dovecot IMAP/POP3",
        "mailbox access log",
    ),
    ("rspamd", "Rspamd", "Rspamd", "spam filter log"),
    ("amavis", "Amavis", "Amavis", "content filter log"),
    ("amazon-ses", "Amazon", "Amazon SES", "sending events"),
    ("ses", "Amazon", "Amazon SES", "sending events"),
    (
        "proofpoint",
        "Proofpoint",
        "Proofpoint",
        "e-mail gateway log",
    ),
    ("mimecast", "Mimecast", "Mimecast", "e-mail gateway log"),
    (
        "barracuda",
        "Barracuda",
        "Barracuda ESG",
        "e-mail gateway log",
    ),
    ("ironport", "Cisco", "Cisco Secure Email (ESA)", "mail log"),
    ("zimbra", "Synacor", "Zimbra", "mailbox log"),
    ("smtp-generic", "Generic", "SMTP server", "SMTP session log"),
];

fn lower_keys(object: &Map<String, Value>) -> Vec<String> {
    object.keys().map(|k| k.to_ascii_lowercase()).collect()
}

fn has(keys: &[String], name: &str) -> bool {
    keys.iter().any(|k| k == name)
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    object
        .iter()
        .find(|(k, _)| names.iter().any(|n| k.eq_ignore_ascii_case(n)))
        .map(|(_, v)| v)
}

fn named(value: &str, how: &str) -> Option<Source> {
    let lower = value.to_ascii_lowercase();
    NAMED
        .iter()
        .find(|(needle, ..)| {
            if needle.len() <= 4 {
                lower == *needle
            } else {
                lower.contains(needle)
            }
        })
        .map(|(needle, vendor, product, log_type)| {
            src(
                vendor,
                product,
                log_type,
                "high",
                format!("{how} names '{needle}'"),
            )
        })
}

/// Identify the product that produced one parsed record.
pub fn classify(record: &Value) -> Option<Source> {
    let object = record.as_object()?;
    if object.contains_key("email_analysis") {
        return Some(src(
            "RFC 5322",
            "E-mail message",
            "message (EML/MBOX)",
            "high",
            "parsed message headers",
        ));
    }
    for key in [
        "source",
        "workload",
        "logged_by",
        "reporting_mta",
        "_sourcecategory",
        "product",
        "log_source",
    ] {
        if let Some(value) = field(object, &[key]) {
            if let Some(found) = named(&text(value), &format!("field '{key}'")) {
                return Some(found);
            }
        }
    }
    let keys = lower_keys(object);
    if has(&keys, "messagetraceid")
        || (has(&keys, "senderaddress") && has(&keys, "recipientaddress") && has(&keys, "received"))
    {
        return Some(src(
            "Microsoft",
            "Exchange Online",
            "message trace",
            "high",
            "MessageTraceId / SenderAddress+RecipientAddress+Received columns",
        ));
    }
    if has(&keys, "creationtime")
        && has(&keys, "operation")
        && (has(&keys, "workload") || has(&keys, "recordtype") || has(&keys, "userid"))
    {
        return Some(src(
            "Microsoft",
            "Microsoft 365",
            "unified audit log (mailbox audit)",
            "high",
            "CreationTime + Operation + UserId/Workload columns",
        ));
    }
    if has(&keys, "userprincipalname")
        || has(&keys, "appdisplayname")
        || has(&keys, "conditionalaccessstatus")
        || has(&keys, "createddatetime")
    {
        return Some(src(
            "Microsoft",
            "Entra ID",
            "sign-in log",
            "high",
            "userPrincipalName / appDisplayName / conditionalAccessStatus columns",
        ));
    }
    if has(&keys, "event-id")
        && (has(&keys, "connector-id")
            || has(&keys, "client-hostname")
            || has(&keys, "source-context"))
    {
        return Some(src(
            "Microsoft",
            "Exchange Server",
            "message tracking log",
            "high",
            "event-id + connector-id/client-hostname columns",
        ));
    }
    if keys.iter().any(|k| {
        k.starts_with("id.applicationname")
            || k.starts_with("actor.email")
            || k.starts_with("message_info")
            || k.starts_with("event_info")
    }) {
        return Some(src(
            "Google",
            "Google Workspace (Gmail)",
            "audit / Gmail log export",
            "high",
            "Google Workspace export columns",
        ));
    }
    // Windows event logs exported from EVTX.
    let blob = record.to_string();
    let lower = blob.to_ascii_lowercase();
    if lower.contains("msexchange") {
        return Some(src(
            "Microsoft",
            "Exchange Server",
            "Windows event log",
            "medium",
            "MSExchange event provider",
        ));
    }
    // Raw syslog / MTA lines.
    let raw = field(object, &["raw"]).map(text).unwrap_or_default();
    let line = if raw.is_empty() {
        lower.clone()
    } else {
        raw.to_ascii_lowercase()
    };
    let patterns: &[(&str, &str, &str, &str, &str)] = &[
        (
            "postfix/",
            "Postfix",
            "Postfix MTA",
            "MTA syslog",
            "'postfix/' process tag",
        ),
        (
            "sendmail[",
            "Sendmail",
            "Sendmail MTA",
            "MTA syslog",
            "'sendmail[' process tag",
        ),
        (
            "dovecot:",
            "Dovecot",
            "Dovecot IMAP/POP3",
            "mailbox access log",
            "'dovecot:' prefix",
        ),
        (
            "amavis[",
            "Amavis",
            "Amavis",
            "content filter log",
            "'amavis[' process tag",
        ),
        (
            "rspamd",
            "Rspamd",
            "Rspamd",
            "spam filter log",
            "'rspamd' tag",
        ),
        (
            "filter_instance",
            "Proofpoint",
            "Proofpoint",
            "e-mail gateway log",
            "'filter_instance' field",
        ),
        (
            "acode",
            "Mimecast",
            "Mimecast",
            "e-mail gateway log",
            "Mimecast 'aCode' field",
        ),
        (
            "barracuda",
            "Barracuda",
            "Barracuda ESG",
            "e-mail gateway log",
            "'barracuda' tag",
        ),
        ("zimbra", "Synacor", "Zimbra", "mailbox log", "'zimbra' tag"),
    ];
    for (needle, vendor, product, log_type, why) in patterns {
        if line.contains(needle) {
            return Some(src(vendor, product, log_type, "medium", *why));
        }
    }
    // Plain-text exports often carry the product name as a column.
    if !raw.is_empty() {
        for token in raw.split_whitespace().take(4) {
            if let Some(mut found) = named(
                token.trim_matches(|c: char| !c.is_alphanumeric() && c != '-'),
                "log line",
            ) {
                found.confidence = "medium";
                return Some(found);
            }
        }
    }
    if regex::Regex::new(r"\bmid \d+ (icid|from|to|rid)\b")
        .map(|re| re.is_match(&line))
        .unwrap_or(false)
    {
        return Some(src(
            "Cisco",
            "Cisco Secure Email (ESA)",
            "mail log",
            "medium",
            "'MID n ICID/From/To' pattern",
        ));
    }
    if regex::Regex::new(r"\b[0-9a-z]{6}-[0-9a-z]{6,11}-[0-9a-z]{2,4}\s+(<=|=>|->|\*\*|==)")
        .map(|re| re.is_match(&line))
        .unwrap_or(false)
    {
        return Some(src(
            "Exim",
            "Exim MTA",
            "MTA log",
            "medium",
            "Exim message id with <= / => flag",
        ));
    }
    // Sign-in records that name a Microsoft cloud app.
    let action = field(object, &["action", "event", "operation"])
        .map(text)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if (action.contains("sign-in") || action.contains("sign_in") || action.contains("login"))
        && (lower.contains("office 365")
            || lower.contains("exchange online")
            || lower.contains("azure")
            || lower.contains("microsoft"))
    {
        return Some(src(
            "Microsoft",
            "Entra ID",
            "sign-in log",
            "medium",
            "sign-in action for a Microsoft cloud app",
        ));
    }
    if [
        "set-inboxrule",
        "new-inboxrule",
        "set-mailbox",
        "mailitemsaccessed",
        "softdelete",
        "harddelete",
        "add-mailboxpermission",
        "send as",
        "send on behalf",
    ]
    .iter()
    .any(|op| action == *op)
    {
        return Some(src(
            "Microsoft",
            "Exchange / Microsoft 365",
            "mailbox audit",
            "medium",
            format!("Exchange mailbox operation '{action}'"),
        ));
    }
    if lower.contains("spf=") || lower.contains("dmarc=") {
        return Some(src(
            "Generic",
            "Mail gateway / message trace",
            "delivery log",
            "low",
            "authentication results without a vendor marker",
        ));
    }
    None
}

/// Per-file profile: dominant source plus a breakdown of all detected sources.
pub fn profile(name: &str, rows: &[Value]) -> Value {
    let mut counts: BTreeMap<(String, String, String), (usize, String, &'static str)> =
        BTreeMap::new();
    let mut unknown = 0usize;
    for row in rows {
        match classify(row) {
            Some(s) => {
                let entry = counts
                    .entry((
                        s.vendor.to_string(),
                        s.product.to_string(),
                        s.log_type.to_string(),
                    ))
                    .or_insert((0, s.reason.clone(), s.confidence));
                entry.0 += 1;
            }
            None => unknown += 1,
        }
    }
    let mut breakdown: Vec<Value> = counts
        .into_iter()
        .map(|((vendor, product, log_type), (count, reason, confidence))| {
            json!({"vendor": vendor, "product": product, "log_type": log_type, "count": count, "confidence": confidence, "reason": reason})
        })
        .collect();
    breakdown.sort_by_key(|b| std::cmp::Reverse(b["count"].as_u64().unwrap_or(0)));
    let mut platforms: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        if let Some(list) = row
            .pointer("/email_analysis/platforms")
            .and_then(Value::as_array)
        {
            for p in list {
                let key = format!(
                    "{} ({})",
                    p["platform"].as_str().unwrap_or("?"),
                    p["role"].as_str().unwrap_or("?")
                );
                *platforms.entry(key).or_insert(0) += 1;
            }
        }
    }
    let primary = breakdown.first().cloned().unwrap_or_else(|| {
        json!({"vendor": "Unknown", "product": "Unrecognised format", "log_type": "unknown", "count": 0, "confidence": "none",
               "reason": format!("no known field signature in {name}")})
    });
    json!({
        "primary": primary,
        "breakdown": breakdown,
        "mixed": breakdown.len() > 1,
        "unclassified": unknown,
        "message_platforms": platforms,
        "note": "Heuristic fingerprint from field names, product names and line formats; verify against how the log was exported.",
    })
}

/// Mail platforms seen in one message: (platform, role, evidence).
pub fn message_platforms(header_names: &[String], received: &[Value], blob: &str) -> Vec<Value> {
    const HOSTS: &[(&str, &str)] = &[
        ("protection.outlook.com", "Microsoft 365 / Exchange Online"),
        ("outlook.com", "Microsoft 365 / Outlook.com"),
        ("google.com", "Google Workspace / Gmail"),
        ("gmail.com", "Google Workspace / Gmail"),
        ("amazonses.com", "Amazon SES"),
        ("sendgrid.net", "SendGrid"),
        ("mailgun.org", "Mailgun"),
        ("mcsv.net", "Mailchimp / Mandrill"),
        ("mandrillapp.com", "Mailchimp / Mandrill"),
        ("sparkpostmail.com", "SparkPost"),
        ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("iphmx.com", "Cisco Secure Email"),
        ("barracudanetworks.com", "Barracuda"),
        ("yahoo.com", "Yahoo Mail"),
        ("zoho.com", "Zoho Mail"),
        ("icloud.com", "Apple iCloud Mail"),
        ("protonmail.ch", "Proton Mail"),
        ("gmx.net", "GMX"),
        ("web.de", "WEB.DE"),
        ("kundenserver.de", "IONOS (1&1)"),
        ("yandex.net", "Yandex Mail"),
        ("mail.ru", "Mail.ru"),
    ];
    const HEADERS: &[(&str, &str, &str)] = &[
        (
            "x-ms-exchange-organization-",
            "Microsoft 365 / Exchange",
            "receiving",
        ),
        (
            "x-ms-exchange-crosstenant-",
            "Microsoft 365 / Exchange Online",
            "receiving",
        ),
        ("x-gm-message-state", "Google Workspace / Gmail", "sending"),
        (
            "x-google-dkim-signature",
            "Google Workspace / Gmail",
            "sending",
        ),
        ("x-ses-outgoing", "Amazon SES", "sending"),
        ("x-sg-eid", "SendGrid", "sending"),
        ("x-mailgun-", "Mailgun", "sending"),
        ("x-mandrill-", "Mailchimp / Mandrill", "sending"),
        ("x-pm-message-id", "Postmark", "sending"),
        ("x-proofpoint-", "Proofpoint", "gateway"),
        ("x-mc-unique", "Mimecast", "gateway"),
        ("x-mimecast-", "Mimecast", "gateway"),
        ("x-ironport-", "Cisco Secure Email", "gateway"),
        ("x-barracuda-", "Barracuda", "gateway"),
        ("x-ymail-osg", "Yahoo Mail", "sending"),
        (
            "x-ui-out-filterresults",
            "GMX / WEB.DE (United Internet)",
            "sending",
        ),
    ];
    let mut out: Vec<Value> = Vec::new();
    let mut add = |platform: &str, role: &str, evidence: String| {
        if !out
            .iter()
            .any(|p| p["platform"] == platform && p["role"] == role)
        {
            out.push(json!({"platform": platform, "role": role, "evidence": evidence}));
        }
    };
    for name in header_names {
        let lower = name.to_ascii_lowercase();
        for (prefix, platform, role) in HEADERS {
            if lower.starts_with(prefix) {
                add(platform, role, format!("header {name}"));
            }
        }
    }
    // Hops are newest first: the last hops are on the sender side, the first on the receiver side.
    let n = received.len();
    for (i, hop) in received.iter().enumerate() {
        let role = if n > 1 && i == 0 {
            "receiving"
        } else if i + 1 == n {
            "sending"
        } else {
            "relay"
        };
        for host in [
            hop["from"].as_str().unwrap_or(""),
            hop["by"].as_str().unwrap_or(""),
        ] {
            let host = host.to_ascii_lowercase();
            for (suffix, platform) in HOSTS {
                if host == *suffix || host.ends_with(&format!(".{suffix}")) {
                    add(platform, role, format!("Received host {host}"));
                }
            }
        }
        let with = hop["with"].as_str().unwrap_or("");
        let _ = with;
    }
    let lower = blob.to_ascii_lowercase();
    for (marker, platform) in [
        ("(postfix)", "Postfix MTA"),
        ("(exim", "Exim MTA"),
        ("sendmail", "Sendmail MTA"),
        ("microsoft smtp server", "Microsoft Exchange"),
    ] {
        if lower.contains(marker) {
            add(platform, "relay", format!("Received text '{marker}'"));
        }
    }
    out.truncate(12);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_export_formats() {
        let cases = [
            (
                json!({"CreationTime":"x","Operation":"New-InboxRule","UserId":"a","Workload":"Exchange"}),
                "Microsoft 365",
            ),
            (
                json!({"MessageTraceId":"1","SenderAddress":"a","RecipientAddress":"b","Received":"t"}),
                "Exchange Online",
            ),
            (
                json!({"createdDateTime":"x","userPrincipalName":"a","appDisplayName":"Office 365"}),
                "Entra ID",
            ),
            (
                json!({"date-time":"x","event-id":"RECEIVE","connector-id":"c","client-hostname":"h"}),
                "Exchange Server",
            ),
            (
                json!({"raw":"Nov 25 09:30:04 mx1 postfix/smtpd[4121]: 7F3A: client=x"}),
                "Postfix MTA",
            ),
            (
                json!({"raw":"2026-11-25 10:00:00 1rAbCd-000123-AB <= a@b.test H=x"}),
                "Exim MTA",
            ),
            (
                json!({"raw":"Info: MID 1234 ICID 5678 From: <a@b>"}),
                "Cisco Secure Email (ESA)",
            ),
            (
                json!({"source":"google-workspace","action":"Send"}),
                "Google Workspace (Gmail)",
            ),
            (json!({"source":"amazon-ses"}), "Amazon SES"),
            (
                json!({"user":"a","action":"sign-in","app":"Office 365 Exchange Online"}),
                "Entra ID",
            ),
        ];
        for (record, product) in cases {
            let found = classify(&record).unwrap_or_else(|| panic!("no match for {record}"));
            assert_eq!(found.product, product, "{record}");
        }
        assert!(classify(&json!({"foo":"bar"})).is_none());
    }

    #[test]
    fn profile_reports_mixed_sources() {
        let rows = vec![
            json!({"source":"postfix"}),
            json!({"source":"postfix"}),
            json!({"source":"entra-id"}),
            json!({"x":1}),
        ];
        let p = profile("f.jsonl", &rows);
        assert_eq!(p["primary"]["product"], "Postfix MTA");
        assert_eq!(p["primary"]["count"], 2);
        assert_eq!(p["mixed"], true);
        assert_eq!(p["unclassified"], 1);
    }

    #[test]
    fn message_platforms_from_headers_and_hops() {
        let hops = vec![
            json!({"from":"mail-sn1.protection.outlook.com","by":"inbox.corp.test"}),
            json!({"from":"o1.ptr.sendgrid.net","by":"mx.corp.test"}),
        ];
        let p = message_platforms(
            &[
                "X-SG-EID".into(),
                "X-MS-Exchange-Organization-AuthAs".into(),
            ],
            &hops,
            "",
        );
        let text = serde_json::to_string(&p).unwrap();
        assert!(text.contains("SendGrid"));
        assert!(text.contains("Microsoft 365"));
    }
}
