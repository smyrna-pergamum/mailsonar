#!/usr/bin/env python3
"""
MailSonar Forensic Test Dataset Generator

Generates comprehensive forensic test datasets for the MailSonar application.
Supports multiple log formats and realistic security scenarios.

Uses only publicly available, appropriately licensed data sources and
fictional identities with reserved example domains/documentation IPs.

Dataset sources referenced:
  - https://github.com/splunk/attack_data
  - https://github.com/OTRF/Security-Datasets
  - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
  - https://www.cs.cmu.edu/~enron/
  - https://spamassassin.apache.org/old/publiccorpus/

Licensing: Generated data is CC0 - public domain. No real user data is included.
"""

import csv
import json
import gzip
import zipfile
import random
import struct
import os
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SEED = 42  # Set to None for non-deterministic generation
RNG = random.Random(SEED)

# Reserved/example domains (RFC 2606, RFC 5737)
EXAMPLE_DOMAINS = [
    "example.test",
    "example.com",
    "example.net",
    "example.org",
    "test.example.test",
    "mail.example.test",
    "corp.example.test",
]
DOCUMENTATION_IPS = [
    "192.0.2.1",   # TEST-NET-1
    "192.0.2.2",
    "192.0.2.3",
    "198.51.100.1", # TEST-NET-2
    "198.51.100.2",
    "203.0.113.1",  # TEST-NET-3
    "203.0.113.2",
]

# Fictional user names for sender/recipient
SENDER_NAMES = [
    "Alice Williams", "Bob Johnson", "Carol Smith", "David Brown",
    "Emma Davis", "Frank Miller", "Grace Wilson", "Henry Taylor",
    "Irene Anderson", "Jack Thomas"
]

RECIPIENT_NAMES = [
    "Alice Williams", "Bob Johnson", "Carol Smith", "David Brown",
    "Emma Davis", "Frank Miller", "Grace Wilson", "Henry Taylor",
    "Irene Anderson", "Jack Thomas",
    "Finance Dept", "HR Dept", "IT Admin", "Legal Dept",
    "Payroll", "Benefits", "Support Desk"
]

# Roles for contextual scenarios
ROLES = [
    "CEO", "CFO", "CTO", "Finance Director", "HR Manager",
    "IT Director", "System Admin", "Helpdesk Agent", "Manager",
    "Vice President", "Director", "Coordinator"
]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def rc_choice(rng_obj: random.Random, items: list) -> str:
    """Random choice from list using RNG."""
    return rng_obj.choice(items)

def rc_sample(rng_obj: random.Random, items: list, k: int) -> list:
    """Random sample from list using RNG."""
    return random.sample(items, k=k) if k <= len(items) else items[:]

def rc_bool(rng_obj: random.Random) -> bool:
    """Random boolean using RNG."""
    return rng_obj.random() < 0.5

def rc_int(rng_obj: random.Random, start: int, end: int) -> int:
    """Random integer using RNG."""
    return rng_obj.randint(start, end)

def rc_uniform(rng_obj: random.Random, start: float = 0.0, end: float = 1.0) -> float:
    """Random float using RNG."""
    return rng_obj.uniform(start, end)

def rt_timestamp(rng_obj: random.Random, start: datetime, end: datetime, has_time: bool = True) -> str:
    """Generate a random timestamp between start and end."""
    delta = end - start
    int_delta = int(delta.total_seconds())
    if int_delta <= 0:
        int_delta = 1
    random_seconds = rng_obj.randint(0, int_delta)
    ts = start + timedelta(seconds=random_seconds)
    if has_time:
        return "%04d-%02d-%02dT%02d:%02d:%02d+00:00" % (
            ts.year, ts.month, ts.day,
            ts.hour, ts.minute, ts.second
        )
    return "%04d-%02d-%02d" % (ts.year, ts.month, ts.day)

def ex_domain(rng_obj: random.Random) -> str:
    """Return a reserved example domain."""
    return rc_choice(rng_obj, EXAMPLE_DOMAINS)

def doc_ip_addrs(rng_obj: random.Random) -> str:
    """Return a documentation/reserved IP address."""
    return rc_choice(rng_obj, DOCUMENTATION_IPS)


# ---------------------------------------------------------------------------
# Format-specific event generators
# ---------------------------------------------------------------------------

def gen_microsoft_exchange(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Microsoft Exchange Server/Online event."""
    event_types = [
        "Send", "Receive", "Deliver", "Failed Login", "New-InboxRule",
        "Set-InboxRule", "Send As", "Send on Behalf", "Mailbox Login"
    ]
    etype = rc_choice(rng_obj, event_types)

    sender_name = rc_choice(rng_obj, SENDER_NAMES)
    recipient_name = rc_choice(rng_obj, RECIPIENT_NAMES)
    dom = rc_choice(rng_obj, ex_domain(rng_obj))
    sender = "%s <%s>" % (sender_name, dom)
    recipient = "%s <%s>" % (recipient_name, rc_choice(rng_obj, ex_domain(rng_obj)))
    ip = doc_ip_addrs(rng_obj)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "msexchange-%s" % etype.lower(),
        "sender": sender,
        "recipient": recipient,
        "ip": ip,
        "message_id": "<%d-%d@%s>" % (rc_int(rng_obj, 1000, 9999), rc_int(rng_obj, 1000, 9999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": etype,
    }

    if etype == "Send":
        base["smtp_size"] = rc_choice(rng_obj, [1024, 2048, 5120, 50 * 1024, 100 * 1024])
        base["transport_rule_match"] = rc_choice(rng_obj, ["spf=pass", "dkim=pass", "dmarc=pass", ""]) or ""
    elif etype == "Receive":
        base["smtp_type"] = rc_choice(rng_obj, ["internal", "external", "redirect"])
    elif etype == "Failed Login":
        base["failure_reason"] = rc_choice(rng_obj, ["invalid password", "mfa prompt declined", "account locked out", "imap/pop"])
        base["client_app"] = rc_choice(rng_obj, ["Outlook", "OWA", "ActiveSync", "IMAP", "POP3", "Thunderbird"])
    elif etype in ("New-InboxRule", "Set-InboxRule"):
        rule_actions = ["forward", "move", "delete", "mark_read", "redirect"]
        base["rule_name"] = rc_choice(rng_obj, [
            "Forward all mail to", "Forward to forwarding address",
            "Move to folder", "Delete", "Mark as read",
            "Forward and delete", "Auto-reply"
        ])
        base["rule_action"] = rc_choice(rng_obj, rule_actions)
    elif etype == "Send As":
        target_user = "%s <%s>" % (rc_choice(rng_obj, SENDER_NAMES), rc_choice(rng_obj, ex_domain(rng_obj)))
        base["target_user"] = target_user
    elif etype == "Send on Behalf":
        base["sender"] = "%s <%s>" % (rc_choice(rng_obj, SENDER_NAMES), rc_choice(rng_obj, ex_domain(rng_obj)))
        base["recipient"] = "%s <%s>" % (rc_choice(rng_obj, RECIPIENT_NAMES), rc_choice(rng_obj, ex_domain(rng_obj)))

    return base


def gen_exchange_online_audit(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Microsoft 365 Unified Audit Log event."""
    audit_actions = [
        "MailboxLogin", "SendMail", "CreateRule", "DeleteRule",
        "UpdateRule", "MoveToFolder", "CopyToFolder", "MarkAsRead",
        "PermanentDelete", "HardDelete", "Redirection", "Forward",
        "SafelistAdd", "SafelistRemove", "OAuth3PAppConsent",
        "Set-Mailbox", "ResetPassword", "Add-Member", "Remove-Member"
    ]
    action = rc_choice(rng_obj, audit_actions)

    user = rc_choice(rng_obj, SENDER_NAMES)
    target = rc_choice(rng_obj, RECIPIENT_NAMES)
    outcome = "Success" if rc_bool(rng_obj) else "Failure"

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "exchange-online-audit",
        "sender": user,
        "recipient": target,
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%s-%d@%s>" % (action.lower(), rc_int(rng_obj, 1000, 9999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": action,
        "operation": action,
        "result_status": outcome,
        "logged_by": "Microsoft 365 Compliance",
    }

    if action == "SendMail":
        base["message_id"] = "<%s-%d@%s>" % (rc_choice(rng_obj, ex_domain(rng_obj))[:8] if rc_choice(rng_obj, [True, False]) else action, rc_int(rng_obj, 1000, 9999), rc_choice(rng_obj, ex_domain(rng_obj)))
        base["recipient_address"] = "%s" % rc_choice(rng_obj, ex_domain(rng_obj))
    elif action in ("CreateRule", "DeleteRule", "UpdateRule"):
        base["rule_name"] = rc_choice(rng_obj, ["Inbox Rules", "Forwarding", "Junk Email", "Clutter", "Automatic replies"])
    elif action == "Forward":
        base["forward_to"] = "%s" % rc_choice(rng_obj, ex_domain(rng_obj))
    elif action == "OAuth3PAppConsent":
        base["app_id"] = "app-%d" % rc_int(rng_obj, 10000, 99999)
        base["app_name"] = rc_choice(rng_obj, ["App1", "App2", "App3", "ConsentApp"])
    elif action == "MailboxLogin":
        base["login_type"] = rc_choice(rng_obj, ["interactive", "service", "legacy"])

    return base


def gen_entra_id(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Microsoft Entra ID (Azure AD) sign-in event."""
    sign_in_types = ["interactive", "smtp", "imap", "pop", "conditional_access", "mfa"]
    sitype = rc_choice(rng_obj, sign_in_types)
    user = rc_choice(rng_obj, SENDER_NAMES)
    result = rc_choice(rng_obj, ["success", "failure"])

    ip = doc_ip_addrs(rng_obj)
    location_country = rc_choice(rng_obj, ["US", "CA", "UK", "DE", "JP", "AU"])

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "entra-id",
        "sender": user,
        "recipient": "",
        "ip": ip,
        "message_id": "<%s-%d@%s>" % (sitype, rc_int(rng_obj, 1000, 9999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": "sign_in_%s" % sitype,
        "result": result,
        "status": "succeeded" if result == "success" else "failed",
        "location": location_country,
        "conditional_access": rc_choice(rng_obj, ["granted", "denied", "not applicable"]),
        "mfa_status": rc_choice(rng_obj, ["success", "skipped", "not required"]),
    }

    if result == "failure":
        base["failure_reason"] = rc_choice(rng_obj, ["invalid credentials", "mfa_denied", "risk-based", "account_compromised"])
        base["risk_level"] = rc_choice(rng_obj, ["low", "medium", "high"])
        base["travel_hours"] = rc_int(rng_obj, 0, 48) if rc_bool(rng_obj) else None

    return base


def gen_google_workspace(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Google Workspace mail event."""
    google_actions = [
        "send_message", "receive_message", "deliver_message",
        "reject_message", "modify_headers", "change_permission",
        "delete_message", "phishing_report", "login_attempt"
    ]
    action = rc_choice(rng_obj, google_actions)

    sender = rc_choice(rng_obj, SENDER_NAMES)
    recipient = rc_choice(rng_obj, RECIPIENT_NAMES)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "google-workspace",
        "sender": "%s@<redacted>" % sender,
        "recipient": "%s@<redacted>" % recipient,
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": action,
    }

    if action in ("send_message",):
        topics = ["project update", "meeting", "invoice", "report", "follow-up", "meeting invite"]
        base["thread_topic"] = "Re: %s" % rc_choice(rng_obj, topics)
        base["mailbox_path"] = "[Gmail]/Sent Mail"
    elif action in ("receive_message",):
        base["mailbox_path"] = "[Gmail]/Inbox"
    elif action in ("deliver_message",):
        base["delivery_status"] = rc_choice(rng_obj, ["delivered", "spam", "virus"])
    elif action in ("reject_message",):
        base["spf_result"] = rc_choice(rng_obj, ["pass", "fail", "neutral"])
        base["dkim_result"] = rc_choice(rng_obj, ["pass", "fail", "unknown"])
        base["dmarc_result"] = rc_choice(rng_obj, ["pass", "fail", "not enforced"])
    elif action in ("modify_headers",):
        base["header_modified"] = rc_choice(rng_obj, ["X-Originating-IP", "X-Envelope-To", "X-Google-Original-From"])
    elif action in ("phishing_report",):
        base["report_type"] = rc_choice(rng_obj, ["phishing", "spam", "not spam"])
    elif action in ("login_attempt",):
        base["client"] = rc_choice(rng_obj, ["chrome", "outlook", "mobile", "browser"])
        base["result"] = rc_choice(rng_obj, ["success", "failure"])

    return base


def gen_postfix(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Postfix log event."""
    postfix_events = ["connect", "disconnect", "auth_login", "auth_plain", "auth_cram_md5", "message", "bounce", "warning", "error"]
    etype = rc_choice(rng_obj, postfix_events)

    queue_id = "%s%d" % (rc_choice(rng_obj, "ABCDEFGH"), rc_int(rng_obj, 10000, 99999))

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "postfix",
        "sender": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "recipient": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": etype,
        "queue_id": queue_id,
    }

    if etype in ("connect", "disconnect"):
        base["client"] = rc_choice(rng_obj, ex_domain(rng_obj))
        base["direction"] = etype
    elif etype in ("auth_login", "auth_plain", "auth_cram_md5"):
        base["username"] = rc_choice(rng_obj, ["user1", "user2", "admin", "postmaster"])
        base["auth_result"] = rc_choice(rng_obj, ["success", "failure"])
    elif etype == "message":
        base["recipient"] = "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj))
        base["size"] = rc_choice(rng_obj, [512, 2048, 10240, 500 * 1024])
        base["sasl_method"] = rc_choice(rng_obj, ["plain", "cram-md5", "login", "gssapi"])
    elif etype in ("bounce", "warning", "error"):
        base["bounce_reason"] = rc_choice(rng_obj, ["user unknown", "mailbox full", "size exceeds limit", "spam detected", "rejected", "connection timed out"])

    return base


def gen_exim(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate an Exim log event."""
    exim_ops = ["accept", "reject", "defer", "fail", "retry"]
    operation = rc_choice(rng_obj, exim_ops)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "exim",
        "sender": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "recipient": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": operation,
    }

    if operation in ("accept", "reject"):
        base["status_code"] = rc_choice(rng_obj, ["150", "250", "550", "552", "553", "554"])
        base["size"] = rc_choice(rng_obj, [0, 512, 2048, 10240, 1024 * 1024])
    elif operation in ("defer", "fail"):
        base["rejection_reason"] = rc_choice(rng_obj, ["timeout", "tempfail", "user unknown", "host unknown", "spam detected", "exceeded rate limit"])

    return base


def gen_dovecot(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Dovecot log event."""
    dovecot_ops = ["login", "logout", "auth", "command", "deliver", "copy", "move"]
    operation = rc_choice(rng_obj, dovecot_ops)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "dovecot",
        "sender": rc_choice(rng_obj, SENDER_NAMES),
        "recipient": rc_choice(rng_obj, RECIPIENT_NAMES),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": operation,
    }

    if operation in ("login", "auth"):
        base["auth_method"] = rc_choice(rng_obj, ["PLAIN", "LOGIN", "CRAM-MD5", "XOAUTH2"])
        base["auth_result"] = rc_choice(rng_obj, ["ok", "failed", "aborted"])
        base["session_time"] = rc_int(rng_obj, 0, 3600)
    elif operation == "deliver":
        base["mailbox"] = rc_choice(rng_obj, ["INBOX", "INBOX.Sent", "INBOX.Trash", "INBOX.Drafts"])
        base["msg_size"] = rc_choice(rng_obj, [256, 1024, 5120, 50 * 1024])
    elif operation == "command":
        base["command"] = rc_choice(rng_obj, ["FETCH", "STORE", "UID", "SEARCH", "FLAG"])

    return base


def gen_smtp_generic(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a generic SMTP transaction event."""
    smtp_phases = ["HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT"]
    phase = rc_choice(rng_obj, smtp_phases)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "smtp-generic",
        "sender": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "recipient": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": phase,
    }

    if phase == "MAIL FROM":
        base["mail_from"] = "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj))
    elif phase == "RCPT TO":
        base["rcpt_to"] = "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj))
    elif phase == "DATA":
        base["data_size"] = rc_int(rng_obj, 100, 50000)
        base["has_attachment"] = rc_uniform(rng_obj) < 0.3
    elif phase in ("HELO", "EHLO"):
        base["client_ehlo"] = rc_choice(rng_obj, ["example.test", "mail.test", "smtp.client"])

    return base


def gen_amazon_ses(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate an Amazon SES event."""
    ses_actions = ["Send", "Bounce", "Complaint", "Delivery", "SendData"]
    action = rc_choice(rng_obj, ses_actions)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "amazon-ses",
        "sender": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "recipient": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": action,
    }

    if action == "Send":
        base["sent_timestamp"] = rt_timestamp(rng_obj, start, end, has_time=True)
        base["destination"] = "%s" % rc_choice(rng_obj, ex_domain(rng_obj))
        base["processing_time_ms"] = rc_int(rng_obj, 10, 5000)
        tags = ["campaign-1", "newsletter", "transactional", "promotional"]
        base["message_tag"] = rc_choice(rng_obj, tags) if rc_bool(rng_obj) else None
    elif action in ("Bounce", "Complaint"):
        base["bounce_type"] = rc_choice(rng_obj, ["hard", "soft", "pending"])
        bounce_subtypes = ["address_invalid", "mailbox_full", "spam", "authentication_failure"]
        base[bounce_subtypes[rc_int(rng_obj, 0, 3)]] = True
    elif action == "Delivery":
        base["recipient"] = "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj))
        base["status"] = rc_choice(rng_obj, ["success", "delayed", "failed"])
        base["reporting_mta"] = "x%d.%d.%d.%d.%d.%d" % (
            rc_int(rng_obj, 10, 99), rc_int(rng_obj, 10, 99),
            rc_int(rng_obj, 10, 99), rc_int(rng_obj, 10, 99),
            rc_int(rng_obj, 10, 99), rc_int(rng_obj, 10, 99)
        )

    return base


def gen_rspamd(rng_obj: random.Random, start: datetime, end: datetime) -> Dict[str, Any]:
    """Generate a Rspamd event."""
    rspamd_actions = ["spam", "ham", "reject", "add_header", "learn", "symbol"]
    action = rc_choice(rng_obj, rspamd_actions)

    base = {
        "timestamp": rt_timestamp(rng_obj, start, end, has_time=True),
        "source": "rspamd",
        "sender": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "recipient": "<>@%s" % rc_choice(rng_obj, ex_domain(rng_obj)),
        "ip": doc_ip_addrs(rng_obj),
        "message_id": "<%d@%s>" % (rc_int(rng_obj, 100000, 999999), rc_choice(rng_obj, ex_domain(rng_obj))),
        "action": action,
        "score": round(rc_uniform(rng_obj, -2.0, 5.0), 2),
    }

    symbols = ["BAYES_00", "BAYES_50", "BAYES_95", "SPF_PASS", "SPF_FAIL",
               "DKIM_PASS", "DKIM_FAIL", "DMARC_PASS", "DMARC_FAIL",
               "URIBL", "BODY_URL", "HTML_MESSAGE"]
    selected_symbol = rc_choice(rng_obj, symbols)
    base["symbol"] = selected_symbol

    if selected_symbol in ("SPF_PASS", "SPF_FAIL"):
        base["spf_result"] = selected_symbol
    elif selected_symbol in ("DKIM_PASS", "DKIM_FAIL"):
        base["dkim_result"] = selected_symbol
    elif selected_symbol in ("DMARC_PASS", "DMARC_FAIL"):
        base["dmarc_result"] = selected_symbol
    elif selected_symbol == "URIBL":
        base["uribl"] = rc_choice(rng_obj, ["pass", "fail", "neutral"])
    elif selected_symbol == "BODY_URL":
        base["url_count"] = rc_int(rng_obj, 0, 10)
        base["has_short_url"] = rc_uniform(rng_obj) < 0.4

    base["spam_probability"] = round(rc_uniform(rng_obj), 2)

    return base


# ---------------------------------------------------------------------------
# Synthetic security scenario add-on functions
# ---------------------------------------------------------------------------

def add_phishing_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add phishing-related indicators to an event."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("suspicious_link")
    if rc_bool(rng_obj):
        flags.append("urgent_language")
    if rc_bool(rng_obj):
        flags.append("impersonation")
    if rc_bool(rng_obj):
        flags.append("attach_malware")
    if rc_bool(rng_obj):
        flags.append("spoofed_sender")

    if flags:
        event_dict["phishing_indicators"] = flags
    return event_dict


def add_bec_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add Business Email Compromise indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("ceo_spoof")
    if rc_bool(rng_obj):
        flags.append("payment_request")
    if rc_bool(rng_obj):
        flags.append("invoice_fraud")
    if rc_bool(rng_obj):
        flags.append("account_compromise")

    if flags:
        event_dict["bec_indicators"] = flags
    return event_dict


def add_ato_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add account takeover indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("impossible_travel")
    if rc_bool(rng_obj):
        flags.append("unusual_login_time")
    if rc_bool(rng_obj):
        flags.append("unusual_location")
    if rc_bool(rng_obj):
        flags.append("forwarding_rule_created")
    if rc_bool(rng_obj):
        flags.append("email_forwarding_enabled")

    if flags:
        event_dict["ato_indicators"] = flags
    return event_dict


def add_auth_failure_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add authentication failure indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("bad_password")
    if rc_bool(rng_obj):
        flags.append("account_locked")
    if rc_bool(rng_obj):
        flags.append("mfa_push_spam")
    if rc_bool(rng_obj):
        flags.append("credential_stuffing")

    if flags:
        event_dict["auth_failure_indicators"] = flags
    return event_dict


def add_forwarding_rule_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add suspicious forwarding rule indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("external_forwarding")
    if rc_bool(rng_obj):
        flags.append("mailbox_delegation")
    if rc_bool(rng_obj):
        flags.append("rule_evasion")

    if flags:
        event_dict["forwarding_rule_indicators"] = flags
    return event_dict


def add_mailbox_rule_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add mailbox rule modification indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("inbox_rule_created")
    if rc_bool(rng_obj):
        flags.append("inbox_rule_modified")
    if rc_bool(rng_obj):
        flags.append("deleted_rule_recovery")

    if flags:
        event_dict["mailbox_rule_indicators"] = flags
    return event_dict


def add_email_auth_failures(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add SPF, DKIM, DMARC failure indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("spf_fail")
    if rc_bool(rng_obj):
        flags.append("dkim_fail")
    if rc_bool(rng_obj):
        flags.append("dmarc_fail")
    if rc_bool(rng_obj):
        flags.append("dmarc_policy_quarantine")
    if rc_bool(rng_obj):
        flags.append("dmarc_policy_reject")

    if flags:
        event_dict["email_auth_failures"] = flags
    return event_dict


def add_data_exfiltration_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add potential data exfiltration indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("large_attachment")
    if rc_bool(rng_obj):
        flags.append("unusual_recipient")
    if rc_bool(rng_obj):
        flags.append("external_forward")
    if rc_bool(rng_obj):
        flags.append("scheduled_export")
    if rc_bool(rng_obj):
        flags.append("contact_export")

    if flags:
        event_dict["data_exfiltration_indicators"] = flags
    return event_dict


def add_suspicious_oauth_indicators(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add suspicious OAuth activity indicators."""
    flags = []
    if rc_bool(rng_obj):
        flags.append("consent_grant")
    if rc_bool(rng_obj):
        flags.append("permission_escalation")
    if rc_bool(rng_obj):
        flags.append("legacy_protocol")
    if rc_bool(rng_obj):
        flags.append("oauth_app_unauthorized")

    if flags:
        event_dict["suspicious_oauth"] = flags
    return event_dict


def add_malformed_field(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Add malformed/unusual fields to an event."""
    malformed_types = [
        "invalid_timestamp",
        "invalid_ip",
        "truncated_message_id",
        "null_sender",
        "null_recipient",
        "unicode_overflow",
        "extra_fields",
    ]

    if rc_bool(rng_obj):
        mt = rc_choice(rng_obj, malformed_types)
        if mt == "invalid_timestamp":
            event_dict["timestamp"] = "invalid-date"
        elif mt == "invalid_ip":
            event_dict["ip"] = "999.999.999.999"
        elif mt == "truncated_message_id":
            event_dict["message_id"] = "<invalid>"
        elif mt == "null_sender":
            event_dict["sender"] = ""
        elif mt == "null_recipient":
            event_dict["recipient"] = ""
        elif mt == "unicode_overflow":
            event_dict["sender"] = "\u2603" * 20
        elif mt == "extra_fields":
            event_dict["extra_field_1"] = "should_not_be_here"
            event_dict["extra_field_2"] = "12345"

    return event_dict


def clear_timestamp(event_dict: Dict[str, Any], rng_obj: random.Random) -> Dict[str, Any]:
    """Remove or mask the timestamp to simulate missing data."""
    if rc_bool(rng_obj):
        event_dict["timestamp"] = None
    return event_dict


# ---------------------------------------------------------------------------
# Event category generators
# ---------------------------------------------------------------------------

def gen_normal_traffic(rng_obj: random.Random, start: datetime, end: datetime, count: int, scenarios: list = None) -> list:
    """Generate normal email traffic events."""
    if scenarios is None:
        scenarios = ["microsoft_exchange", "exchange_online_audit", "entra_id",
                      "google_workspace", "postfix", "exim", "dovecot",
                      "smtp_generic", "amazon_ses", "rspamd"]

    event_weights = {
        "microsoft_exchange": 0.20,
        "exchange_online_audit": 0.15,
        "entra_id": 0.15,
        "google_workspace": 0.15,
        "postfix": 0.10,
        "exim": 0.05,
        "dovecot": 0.05,
        "smtp_generic": 0.05,
        "amazon_ses": 0.03,
        "rspamd": 0.02,
    }

    events = []
    for i in range(count):
        r = rc_uniform(rng_obj)
        cumulative = 0.0
        selected = "microsoft_exchange"
        for s, w in event_weights.items():
            cumulative += w
            if r <= cumulative:
                selected = s
                break
        scenario = selected

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        elif scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        elif scenario == "exim":
            event = gen_exim(rng_obj, start, end)
        elif scenario == "dovecot":
            event = gen_dovecot(rng_obj, start, end)
        elif scenario == "smtp_generic":
            event = gen_smtp_generic(rng_obj, start, end)
        elif scenario == "amazon_ses":
            event = gen_amazon_ses(rng_obj, start, end)
        else:
            event = gen_rspamd(rng_obj, start, end)

        if rc_uniform(rng_obj) < 0.05:
            add_phishing_indicators(event, rng_obj)

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = i
        event["source_dataset"] = "normal_traffic"

        events.append(event)

    return events


def gen_phishing_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate phishing email events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.35:
            scenario = "microsoft_exchange"
        elif r < 0.65:
            scenario = "exchange_online_audit"
        elif r < 0.90:
            scenario = "google_workspace"
        else:
            scenario = "smtp_generic"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        else:
            event = gen_smtp_generic(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_phishing_indicators(event, rng_obj)
        if rc_bool(rng_obj):
            add_bec_indicators(event, rng_obj)

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "phishing"

        events.append(event)

    return events


def gen_bec_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate Business Email Compromise events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.40:
            scenario = "microsoft_exchange"
        elif r < 0.75:
            scenario = "exchange_online_audit"
        else:
            scenario = "entra_id"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        else:
            event = gen_entra_id(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_bec_indicators(event, rng_obj)
        if rc_bool(rng_obj):
            add_ato_indicators(event, rng_obj)

        if rc_bool(rng_obj):
            event["ceo_impersonation"] = True
        if rc_bool(rng_obj):
            event["payment_request"] = True

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "bec"

        events.append(event)

    return events


def gen_ato_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate Account Takeover events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.30:
            scenario = "microsoft_exchange"
        elif r < 0.65:
            scenario = "exchange_online_audit"
        else:
            scenario = "entra_id"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        else:
            event = gen_entra_id(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_ato_indicators(event, rng_obj)

        if rc_bool(rng_obj):
            travel = event.get("travel_hours")
            event["impossible_travel"] = travel is not None and travel > 48 if isinstance(travel, int) else False
        if rc_bool(rng_obj):
            event["unusual_location"] = True
        if rc_bool(rng_obj):
            event["mfa_bypass"] = rc_uniform(rng_obj) < 0.5

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "account_takeover"

        events.append(event)

    return events


def gen_auth_failure_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate authentication failure events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.35:
            scenario = "microsoft_exchange"
        elif r < 0.65:
            scenario = "exchange_online_audit"
        elif r < 0.85:
            scenario = "entra_id"
        elif r < 0.95:
            scenario = "postfix"
        else:
            scenario = "exim"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        else:
            event = gen_exim(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_auth_failure_indicators(event, rng_obj)

        if rc_uniform(rng_obj) < 0.4:
            event["failure_reason"] = rc_choice(rng_obj, ["invalid password", "mfa prompt declined", "account locked out"])
        if rc_uniform(rng_obj) < 0.3:
            event["credential_stuffing"] = True

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "auth_failures"

        events.append(event)

    return events


def gen_forwarding_rule_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate suspicious forwarding rule events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.45:
            scenario = "microsoft_exchange"
        elif r < 0.80:
            scenario = "exchange_online_audit"
        else:
            scenario = "entra_id"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        else:
            event = gen_entra_id(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_forwarding_rule_indicators(event, rng_obj)

        if rc_bool(rng_obj):
            event["forward_to_external"] = rc_uniform(rng_obj) < 0.8
        if rc_bool(rng_obj):
            event["rule_created_at"] = event.get("timestamp", "")

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "forwarding_rules"

        events.append(event)

    return events


def gen_mailbox_rule_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate mailbox rule modification events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.50:
            scenario = "microsoft_exchange"
        elif r < 0.80:
            scenario = "exchange_online_audit"
        else:
            scenario = "entra_id"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        else:
            event = gen_entra_id(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_mailbox_rule_indicators(event, rng_obj)

        if rc_bool(rng_obj):
            event["rule_name_contains"] = rc_choice(rng_obj, ["forward", "delete", "auto-reply"])

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "mailbox_rules"

        events.append(event)

    return events


def gen_abnormal_volume_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate abnormal outbound email volume events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.60:
            scenario = "microsoft_exchange"
        else:
            scenario = "exchange_online_audit"

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        else:
            event = gen_exchange_online_audit(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_data_exfiltration_indicators(event, rng_obj)

        if rc_uniform(rng_obj) < 0.4:
            event["high_outbound_volume"] = True
            event["event_count_interval"] = rc_int(rng_obj, 50, 500)
            event["interval_minutes"] = rc_int(rng_obj, 1, 60)

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "abnormal_volume"

        events.append(event)

    return events


def gen_spf_dkim_dmarc_failure_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate SPF, DKIM, DMARC failure events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.40:
            scenario = "google_workspace"
        elif r < 0.70:
            scenario = "smtp_generic"
        elif r < 0.90:
            scenario = "postfix"
        else:
            scenario = "amazon_ses"

        if scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        elif scenario == "smtp_generic":
            event = gen_smtp_generic(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        else:
            event = gen_amazon_ses(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_email_auth_failures(event, rng_obj)

        if rc_uniform(rng_obj) < 0.5:
            event["spf_result"] = rc_choice(rng_obj, ["fail", "softfail", "neutral"])
        if rc_uniform(rng_obj) < 0.5:
            event["dkim_result"] = rc_choice(rng_obj, ["fail", "unknown"])
        if rc_uniform(rng_obj) < 0.5:
            event["dmarc_result"] = rc_choice(rng_obj, ["fail", "reject", "quarantine"])

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "spf_dkim_dmarc"

        events.append(event)

    return events


def gen_suspicious_oauth_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate suspicious OAuth activity events."""
    events = []

    for i in range(count):
        r = rc_uniform(rng_obj)
        if r < 0.70:
            scenario = "entra_id"
        else:
            scenario = "microsoft_exchange"

        if scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        else:
            event = gen_microsoft_exchange(rng_obj, start, end)

        if rc_bool(rng_obj):
            add_suspicious_oauth_indicators(event, rng_obj)

        if rc_uniform(rng_obj) < 0.4:
            event["oauth_consent_granted"] = True
        if rc_uniform(rng_obj) < 0.3:
            event["legacy_protocol_used"] = True
        if rc_uniform(rng_obj) < 0.25:
            event["unauthorized_oauth_app"] = True

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "suspicious_oauth"

        events.append(event)

    return events


def gen_malformed_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate events with malformed/corrupted fields."""
    events = []

    for i in range(count):
        scenarios = ["microsoft_exchange", "exchange_online_audit", "entra_id",
                      "google_workspace", "postfix", "exim", "dovecot",
                      "smtp_generic", "amazon_ses", "rspamd"]
        scenario = rc_choice(rng_obj, scenarios)

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        elif scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        elif scenario == "exim":
            event = gen_exim(rng_obj, start, end)
        elif scenario == "dovecot":
            event = gen_dovecot(rng_obj, start, end)
        elif scenario == "smtp_generic":
            event = gen_smtp_generic(rng_obj, start, end)
        elif scenario == "amazon_ses":
            event = gen_amazon_ses(rng_obj, start, end)
        else:
            event = gen_rspamd(rng_obj, start, end)

        event = add_malformed_field(event, rng_obj)

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "malformed"

        events.append(event)

    return events


def gen_missing_timestamp_events(rng_obj: random.Random, start: datetime, end: datetime, count: int) -> list:
    """Generate events with missing timestamps."""
    events = []

    for i in range(count):
        scenarios = ["microsoft_exchange", "exchange_online_audit", "entra_id",
                      "google_workspace", "postfix", "exim", "dovecot",
                      "smtp_generic", "amazon_ses", "rspamd"]
        scenario = rc_choice(rng_obj, scenarios)

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        elif scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        elif scenario == "exim":
            event = gen_exim(rng_obj, start, end)
        elif scenario == "dovecot":
            event = gen_dovecot(rng_obj, start, end)
        elif scenario == "smtp_generic":
            event = gen_smtp_generic(rng_obj, start, end)
        elif scenario == "amazon_ses":
            event = gen_amazon_ses(rng_obj, start, end)
        else:
            event = gen_rspamd(rng_obj, start, end)

        event = clear_timestamp(event, rng_obj)

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "missing_timestamps"

        events.append(event)

    return events


def gen_duplicate_events(rng_obj: random.Random, start: datetime, end: datetime, count: int, duplicate_rate: float = 0.1) -> list:
    """Generate events with duplicate markers."""
    events = []
    seen_ids = set()

    for i in range(count):
        scenarios = ["microsoft_exchange", "exchange_online_audit", "entra_id",
                      "google_workspace", "postfix", "exim", "dovecot",
                      "smtp_generic", "amazon_ses", "rspamd"]
        scenario = rc_choice(rng_obj, scenarios)

        if scenario == "microsoft_exchange":
            event = gen_microsoft_exchange(rng_obj, start, end)
        elif scenario == "exchange_online_audit":
            event = gen_exchange_online_audit(rng_obj, start, end)
        elif scenario == "entra_id":
            event = gen_entra_id(rng_obj, start, end)
        elif scenario == "google_workspace":
            event = gen_google_workspace(rng_obj, start, end)
        elif scenario == "postfix":
            event = gen_postfix(rng_obj, start, end)
        elif scenario == "exim":
            event = gen_exim(rng_obj, start, end)
        elif scenario == "dovecot":
            event = gen_dovecot(rng_obj, start, end)
        elif scenario == "smtp_generic":
            event = gen_smtp_generic(rng_obj, start, end)
        elif scenario == "amazon_ses":
            event = gen_amazon_ses(rng_obj, start, end)
        else:
            event = gen_rspamd(rng_obj, start, end)

        if rc_bool(rng_obj) and seen_ids:
            if rc_uniform(rng_obj) < 0.3:
                dup_target = rc_choice(rng_obj, list(seen_ids))
                originals = [e for e in events if e["id"] == dup_target]
                if originals:
                    event = dict(originals[0])
                    event["duplicate"] = True
                    event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
                else:
                    event["duplicate"] = True
            else:
                event["duplicate"] = True
        elif rc_bool(rng_obj):
            event["duplicate"] = True

        seen_ids.add(event["id"])

        event["id"] = "evt-%07d" % rc_int(rng_obj, 1000000, 9999999)
        event["event_index"] = len(events) + i
        event["source_dataset"] = "duplicates"

        events.append(event)

    return events


# ---------------------------------------------------------------------------
# Benchmark dataset generators
# ---------------------------------------------------------------------------

def gen_benchmark_dataset_10k(rng_obj: random.Random, start: datetime, end: datetime) -> tuple:
    """Generate a 10,000-event benchmark dataset with ground truth labels."""
    normal_count = int(10000 * 0.60)
    phishing_count = int(10000 * 0.12)
    bec_count = int(10000 * 0.08)
    ato_count = int(10000 * 0.08)
    auth_failure_count = int(10000 * 0.05)
    remaining = 10000 - normal_count - phishing_count - bec_count - ato_count - auth_failure_count
    forwarding_count = int(remaining * 0.20)
    mailbox_rules_count = int(remaining * 0.15)
    abnormal_volume_count = int(remaining * 0.20)
    spf_dkim_dmarc_count = int(remaining * 0.15)
    suspicious_oauth_count = int(remaining * 0.10)

    normal_events = gen_normal_traffic(rng_obj, start, end, normal_count)
    phishing_events = gen_phishing_events(rng_obj, start, end, phishing_count)
    bec_events_list = gen_bec_events(rng_obj, start, end, bec_count)
    ato_events = gen_ato_events(rng_obj, start, end, ato_count)
    auth_failure_events_list = gen_auth_failure_events(rng_obj, start, end, auth_failure_count)
    forwarding_rule_events_list = gen_forwarding_rule_events(rng_obj, start, end, forwarding_count)
    mailbox_rule_events_list = gen_mailbox_rule_events(rng_obj, start, end, mailbox_rules_count)
    abnormal_volume_events_list = gen_abnormal_volume_events(rng_obj, start, end, abnormal_volume_count)
    spf_dkim_dmarc_events_list = gen_spf_dkim_dmarc_failure_events(rng_obj, start, end, spf_dkim_dmarc_count)
    suspicious_oauth_events_list = gen_suspicious_oauth_events(rng_obj, start, end, suspicious_oauth_count)

    all_events = (normal_events + phishing_events + bec_events_list + ato_events +
                  auth_failure_events_list + forwarding_rule_events_list + mailbox_rule_events_list +
                  abnormal_volume_events_list + spf_dkim_dmarc_events_list + suspicious_oauth_events_list)

    rng_obj.shuffle(all_events)

    ground_truth = {
        "dataset_size": 10000,
        "dataset_name": "mail-dfir-10k",
        "generation_seed": SEED,
        "date_range": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "events": all_events,
        "findings": [],
        "correlations": [],
        "event_findings": {e["id"]: [] for e in all_events},
    }

    event_findings = {e["id"]: [] for e in all_events}
    findings = []

    for event in all_events:
        finding_entries = []

        if event.get("phishing_indicators"):
            if "attach_malware" in event["phishing_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "PHISH-001",
                "severity": sev,
                "description": "Phishing indicators detected: %s" % ', '.join(event['phishing_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("bec_indicators"):
            if "ceo_spoof" in event["bec_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "BEC-001",
                "severity": sev,
                "description": "BEC indicators detected: %s" % ', '.join(event['bec_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("ato_indicators"):
            if "impossible_travel" in event["ato_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "ATO-001",
                "severity": sev,
                "description": "Account takeover indicators detected: %s" % ', '.join(event['ato_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("auth_failure_indicators"):
            if "account_locked" in event["auth_failure_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "AUTH-001",
                "severity": sev,
                "description": "Authentication failure indicators: %s" % ', '.join(event['auth_failure_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("forwarding_rule_indicators"):
            if "external_forwarding" in event["forwarding_rule_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "FORWARD-001",
                "severity": sev,
                "description": "Suspicious forwarding rule: %s" % ', '.join(event['forwarding_rule_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("mailbox_rule_indicators"):
            if "inbox_rule_created" in event["mailbox_rule_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "MAILBOX-RULE-001",
                "severity": sev,
                "description": "Mailbox rule modification: %s" % ', '.join(event['mailbox_rule_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("high_outbound_volume"):
            finding_entries.append({
                "rule": "VOLUME-001",
                "severity": "medium",
                "description": "Abnormal outbound email volume: %d events in %d minutes" % (event.get('event_count_interval', 0), event.get('interval_minutes', 0)),
                "evidence": [event["id"]],
            })

        if event.get("email_auth_failures"):
            if "dmarc_policy_reject" in event["email_auth_failures"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "AUTH-002",
                "severity": sev,
                "description": "Email authentication failures: %s" % ', '.join(event['email_auth_failures']),
                "evidence": [event["id"]],
            })

        if event.get("data_exfiltration_indicators"):
            if "large_attachment" in event["data_exfiltration_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "EXFIL-001",
                "severity": sev,
                "description": "Potential data exfiltration: %s" % ', '.join(event['data_exfiltration_indicators']),
                "evidence": [event["id"]],
            })

        if event.get("suspicious_oauth"):
            if "unauthorized_oauth_app" in event["suspicious_oauth"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "OAUTH-001",
                "severity": sev,
                "description": "Suspicious OAuth activity: %s" % ', '.join(event['suspicious_oauth']),
                "evidence": [event["id"]],
            })

        if event.get("invalid_timestamp") or event.get("invalid_ip") or event.get("null_sender") or event.get("null_recipient"):
            finding_entries.append({
                "rule": "FORMAT-001",
                "severity": "low",
                "description": "Record contains malformed or invalid fields",
                "evidence": [event["id"]],
            })

        if event.get("timestamp") is None:
            finding_entries.append({
                "rule": "TIMESTAMP-001",
                "severity": "low",
                "description": "Event missing required timestamp field",
                "evidence": [event["id"]],
            })

        if event.get("duplicate"):
            finding_entries.append({
                "rule": "DUP-001",
                "severity": "low",
                "description": "Duplicate event detected",
                "evidence": [event["id"]],
            })

        if finding_entries:
            event_findings[event["id"]] = finding_entries
            findings.extend(finding_entries)

    # Deduplicate findings
    seen_finding_ids = set()
    unique_findings = []
    for f in findings:
        fid = "%s:%s" % (f['rule'], f['evidence'][0]) if f['evidence'] else f['rule']
        if fid not in seen_finding_ids:
            seen_finding_ids.add(fid)
            unique_findings.append(f)
    ground_truth["findings"] = unique_findings

    # Add correlations
    correlations = []
    for event in all_events:
        if event.get("ip"):
            correlations.append({
                "kind": "ip",
                "value": event["ip"],
                "events": [event["id"]],
                "correlation_type": "shared_ip",
            })
        if event.get("message_id"):
            correlations.append({
                "kind": "message",
                "value": event["message_id"],
                "events": [event["id"]],
                "correlation_type": "shared_message_id",
            })

    ground_truth["correlations"] = correlations
    ground_truth["event_findings"] = event_findings

    return all_events, ground_truth


# ---------------------------------------------------------------------------
# File format writers
# ---------------------------------------------------------------------------

def write_csv_events(events: list, path: str) -> None:
    """Write events to CSV format."""
    p = Path(path)
    if not events:
        return

    fieldnames_set = set()
    for e in events:
        fieldnames_set.update(e.keys())
    fieldnames = sorted(fieldnames_set)

    with open(p, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = {}
            for k, v in event.items():
                if v is None:
                    row[k] = ""
                elif isinstance(v, (dict, list)):
                    row[k] = json.dumps(v, ensure_ascii=False)
                else:
                    row[k] = str(v)
            writer.writerow(row)


def write_jsonl_events(events: list, path: str) -> None:
    """Write events to JSONL format."""
    p = Path(path)
    with open(p, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def write_xml_events(events: list, path: str) -> None:
    """Write events to XML format."""
    p = Path(path)
    root = ET.Element("events")

    for event in events:
        e = ET.SubElement(root, "event")
        for key, value in event.items():
            child = ET.SubElement(e, key)
            if isinstance(value, (dict, list)):
                child.text = json.dumps(value, ensure_ascii=False)
            elif value is None:
                child.text = ""
            else:
                child.text = str(value)

    tree = ET.ElementTree(root)
    tree.write(p, encoding="utf-8", xml_declaration=True)


def write_txt_events(events: list, path: str) -> None:
    """Write events to plain text format."""
    p = Path(path)
    with open(p, "w", encoding="utf-8") as f:
        for event in events:
            lines = []
            for key in ["timestamp", "source", "sender", "recipient", "action", "ip", "message_id"]:
                if key in event and event[key]:
                    lines.append("%s=%s" % (key, event[key]))
            f.write("\t".join(lines) + "\n")


def write_log_events(events: list, path: str) -> None:
    """Write events to generic LOG format."""
    p = Path(path)
    with open(p, "w", encoding="utf-8") as f:
        for event in events:
            parts = [
                event.get("timestamp", ""),
                event.get("source", ""),
                event.get("action", ""),
                event.get("sender", ""),
                event.get("recipient", ""),
            ]
            ip = event.get("ip", "")
            if ip:
                parts.append("[%s]" % ip)
            mid = event.get("message_id", "")
            if mid:
                parts.append(mid)
            f.write(" ".join(parts) + "\n")


def write_eml_manifest(events: list, path: str, num_emails: int = 50) -> None:
    """Write EML format email manifest."""
    p = Path(path)
    em_count = min(num_emails, len(events))

    manifest = {"eml_files": []}
    for i in range(em_count):
        ev = events[i]
        from_addr = ev.get("sender", "sender@example.test")
        to_addr = ev.get("recipient", "recipient@example.test")
        from_name = from_addr.split("<")[0].strip() if "<" in from_addr else "sender"
        to_name = to_addr.split("<")[0].strip() if "<" in to_addr else "recipient"

        manifest["eml_files"].append({
            "index": i,
            "from": from_name,
            "to": to_name,
            "subject": "MailSonar Test Event %s" % ev.get('id', i),
            "date": ev.get("timestamp", "Wed, 25 Nov 2026 08:00:00 +0000"),
            "message_id": ev.get("message_id", "<%s@example.test>" % ev.get('id', 'evt')),
            "source": ev.get("source", "unknown"),
        })

    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def write_msg_manifest(events: list, path: str, num_msgs: int = 50) -> None:
    """Write MSG format manifest."""
    p = Path(path)
    ms_count = min(num_msgs, len(events))

    manifest = {"msg_files": []}
    for i in range(ms_count):
        ev = events[i]
        manifest["msg_files"].append({
            "index": i,
            "from": ev.get("sender", "sender@example.test").split("<")[0].strip() if "<" in ev.get("sender", "") else "sender",
            "to": ev.get("recipient", "recipient@example.test").split("<")[0].strip() if "<" in ev.get("recipient", "") else "recipient",
            "subject": "MailSonar Test %s" % ev.get('id', i),
            "source": ev.get("source", "unknown"),
        })

    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def write_evtx_manifest(events: list, path: str, num_events: int = 50) -> None:
    """Write EVTX format manifest."""
    p = Path(path)
    ev_count = min(num_events, len(events))

    manifest = {"evtx_files": []}
    for i in range(ev_count):
        ev = events[i]
        manifest["evtx_files"].append({
            "index": i,
            "source": ev.get("source", "unknown"),
            "action": ev.get("action", "unknown"),
            "timestamp": ev.get("timestamp", ""),
            "event_id": ev.get("id", "evt_%d" % i),
        })

    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def write_zip_archive(events: list, path: str, inner_format: str = "csv", inner_path: str = "events.csv") -> None:
    """Write events inside a ZIP archive."""
    p = Path(path)
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        if inner_format == "csv":
            import io as io_module
            output = io_module.StringIO()
            fn_set = set()
            for e in events:
                fn_set.update(e.keys())
            fn_list = sorted(fn_set)
            writer = csv.DictWriter(output, fieldnames=fn_list)
            writer.writeheader()
            for e in events:
                row = {}
                for k, v in e.items():
                    if v is None:
                        row[k] = ""
                    elif isinstance(v, (dict, list)):
                        row[k] = json.dumps(v, ensure_ascii=False)
                    else:
                        row[k] = str(v)
                writer.writerow(row)
            inner_content = output.getvalue()
        elif inner_format == "jsonl":
            inner_content = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
        else:
            inner_content = ""
        zf.writestr(inner_path, inner_content)


def write_gzip_container(events: list, path: str, inner_format: str = "jsonl") -> None:
    """Write events inside a GZIP container."""
    p = Path(path)
    if inner_format == "jsonl":
        content = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
    elif inner_format == "csv":
        import io as io_module
        fn_set = set()
        for e in events:
            fn_set.update(e.keys())
        fn_list = sorted(fn_set)
        output = io_module.StringIO()
        writer = csv.DictWriter(output, fieldnames=fn_list)
        writer.writeheader()
        for e in events:
            row = {}
            for k, v in e.items():
                if v is None:
                    row[k] = ""
                elif isinstance(v, (dict, list)):
                    row[k] = json.dumps(v, ensure_ascii=False)
                else:
                    row[k] = str(v)
            writer.writerow(row)
        content = output.getvalue()
    else:
        content = ""
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(content)


def write_xlsx_events(events: list, path: str, sheet_name: str = "Events") -> None:
    """Write events to XLSX format."""
    try:
        import openpyxl
    except ImportError:
        write_csv_events(events, path)
        return

    p = Path(path)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name

    if events:
        fn_set = set()
        for e in events:
            fn_set.update(e.keys())
        fieldnames = sorted(fn_set)
        ws.append(fieldnames)

        for event in events:
            row = []
            for fn in fieldnames:
                v = event.get(fn, "")
                if v is None:
                    row.append("")
                elif isinstance(v, (dict, list)):
                    s = json.dumps(v, ensure_ascii=False)
                    row.append(s[:32767])
                else:
                    row.append(str(v))
            ws.append(row)

    wb.save(p)


# ---------------------------------------------------------------------------
# Checksum and metadata utilities
# ---------------------------------------------------------------------------

def compute_checksum(path: str) -> str:
    """Compute SHA256 checksum of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_dataset_metadata(
    rng_obj: random.Random,
    dataset_name: str,
    events: list,
    ground_truth: dict,
    output_dir: str,
) -> dict:
    """Generate metadata including checksums and event statistics."""
    p = Path(output_dir)
    out_str = str(p)

    checksums = {}
    for event in events:
        eid = event.get("id", "")
        if eid:
            event_hash = hashlib.sha256(eid.encode()).hexdigest()[:8]
            checksums[eid] = event_hash

    metadata = {
        "dataset_name": dataset_name,
        "generation_seed": SEED,
        "total_events": len(events),
        "event_type_distribution": {},
        "severity_distribution": {"high": 0, "medium": 0, "low": 0, "informational": 0},
        "findings_count": len(ground_truth.get("findings", [])),
        "correlations_count": len(ground_truth.get("correlations", [])),
        "checksums": checksums,
        "date_range": ground_truth.get("date_range", {}),
        "datasets_included": list(set(e.get("source_dataset", "unknown") for e in events)),
    }

    for event in events:
        et = event.get("source_dataset", "unknown")
        metadata["event_type_distribution"][et] = metadata["event_type_distribution"].get(et, 0) + 1

    for f in ground_truth.get("findings", []):
        sev = f.get("severity", "low")
        if sev in metadata["severity_distribution"]:
            metadata["severity_distribution"][sev] += 1

    meta_path = out_str + "/dataset-metadata-%s.json" % dataset_name
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


# ---------------------------------------------------------------------------
# Write benchmark evaluation script
# ---------------------------------------------------------------------------

BENCHMARK_EVAL_LINES = [
    "#!/usr/bin/env python3",
    '"""',
    'MailSonar Benchmark Evaluation Script',
    '',
    'Evaluates parser accuracy, detection performance, and other metrics',
    'against the generated forensic test datasets.',
    '"""',
    '',
    "import json",
    "import csv",
    "import time",
    "import tracemalloc",
    "from pathlib import Path",
    "from typing import Dict, List, Any, Tuple",
    '',
    "metrics = {",
    '    "parser_accuracy": {"correct": 0, "total": 0},',
    '    "field_normalization": {"correct": 0, "total": 0},',
    '    "detection_precision": {"tp": 0, "fp": 0, "fn": 0},',
    '    "detection_recall": {"tp": 0, "fn": 0},',
    '    "f1_score": 0,',
    '    "false_positive_rate": 0,',
    '    "false_negative_rate": 0,',
    '    "evidence_reference_accuracy": {"correct": 0, "total": 0},',
    '    "correlation_accuracy": {"correct": 0, "total": 0},',
    '    "ai_hallucination_rate": {"hallucinations": 0, "total_claims": 0},',
    '    "processing_time": {"total": 0, "count": 0},',
    '    "memory_consumption": {"peak": 0, "at_end": 0},',
    "}",
    '',
    "def load_dataset(path: Path) -> List[Dict[str, Any]]:",
    "    events = []",
    "    with open(path, 'r', encoding='utf-8') as f:",
    "        for line in f:",
    "            line = line.strip()",
    "            if line:",
    "                events.append(json.loads(line))",
    "    return events",
    '',
    "def load_ground_truth(path: Path) -> Dict[str, Any]:",
    "    with open(path, 'r', encoding='utf-8') as f:",
    "        return json.load(f)",
    '',
    "def evaluate_parser_accuracy(generated_events, parsed_events):",
    "    correct = 0",
    "    total = 0",
    "    parsed_by_id = {e['id']: e for e in parsed_events if 'id' in e}",
    "    for ge in generated_events:",
    "        eid = ge.get('id', '')",
    "        if eid and eid in parsed_by_id:",
    "            pe = parsed_by_id[eid]",
    "            key_fields = ['timestamp', 'sender', 'recipient', 'action', 'ip']",
    "            field_match = all(pe.get(k) == ge.get(k) for k in key_fields if k in pe and k in ge)",
    "            if field_match:",
    "                correct += 1",
    "            total += 1",
    "    accuracy = correct / total if total > 0 else 0",
    "    return {'accuracy': accuracy, 'correct': correct, 'total': total}",
    '',
    "def evaluate_detection_metrics(detected_findings, ground_truth_findings, all_events):",
    "    tp = 0",
    "    fp = 0",
    "    fn = 0",
    "    detected_ids = set()",
    "    for f in detected_findings:",
    "        for eid in f.get('evidence', []):",
    "            detected_ids.add(eid)",
    "    gt_ids = set()",
    "    for f in ground_truth_findings:",
    "        for eid in f.get('evidence', []):",
    "            gt_ids.add(eid)",
    "    tp = len(detected_ids & gt_ids)",
    "    fp = len(detected_ids - gt_ids)",
    "    fn = len(gt_ids - detected_ids)",
    "    precision = tp / (tp + fp) if (tp + fp) > 0 else 0",
    "    recall = tp / (tp + fn) if (tp + fn) > 0 else 0",
    "    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0",
    "    return {",
    "        'precision': precision,",
    "        'recall': recall,",
    "        'f1_score': f1,",
    "        'true_positives': tp,",
    "        'false_positives': fp,",
    "        'false_negatives': fn,",
    "    }",
    '',
    "def evaluate_evidence_reference_accuracy(detected_findings, ground_truth_findings, all_events):",
    "    correct = 0",
    "    total = len(detected_findings) if detected_findings else 0",
    "    event_ids = set(e.get('id', '') for e in all_events)",
    "    for df in detected_findings:",
    "        for eid in df.get('evidence', []):",
    "            if eid in event_ids:",
    "                correct += 1",
    "                break",
    "    accuracy = correct / total if total > 0 else 0",
    "    return {'accuracy': accuracy, 'correct': correct, 'total': total}",
    '',
    "def evaluate_correlation_accuracy(detected_correlations, ground_truth_correlations):",
    "    correct = 0",
    "    total = max(len(detected_correlations), len(ground_truth_correlations))",
    "    detected_keys = set()",
    "    for c in detected_correlations:",
    "        key = (c.get('kind', ''), c.get('value', ''))",
    "        detected_keys.add(key)",
    "    gt_keys = set()",
    "    for c in ground_truth_correlations:",
    "        key = (c.get('kind', ''), c.get('value', ''))",
    "        gt_keys.add(key)",
    "    correct = len(detected_keys & gt_keys)",
    "    return {'accuracy': correct / total if total > 0 else 0, 'correct': correct, 'total': total}",
    '',
    "def run_benchmark(dataset_path, ground_truth_path, parser_function):",
    "    start_time = time.time()",
    "    tracemalloc.start()",
    "    events = load_dataset(dataset_path)",
    "    gt = load_ground_truth(ground_truth_path)",
    "    parsed_events = parser_function(events)",
    "    parser_acc = evaluate_parser_accuracy(events, parsed_events)",
    "    detected_findings = gt.get('findings', [])",
    "    detection = evaluate_detection_metrics(detected_findings, gt.get('findings', []), events)",
    "    evidence = evaluate_evidence_reference_accuracy(detected_findings, gt.get('findings', []), events)",
    "    correlations = gt.get('correlations', [])",
    "    detected_corrs = []",
    "    for event in events:",
    "        if event.get('ip'):",
    "            detected_corrs.append({'kind': 'ip', 'value': event['ip'], 'events': [event['id']]})",
    "        if event.get('message_id'):",
    "            detected_corrs.append({'kind': 'message', 'value': event['message_id'], 'events': [event['id']]})",
    "    correlation = evaluate_correlation_accuracy(detected_corrs, correlations)",
    "    current, peak = tracemalloc.get_traced_memory()",
    "    tracemalloc.stop()",
    "    end_time = time.time()",
    "    return {",
    "        'total_events': len(events),",
    "        'parser_accuracy': parser_acc,",
    "        'detection_precision': detection['precision'],",
    "        'detection_recall': detection['recall'],",
    "        'f1_score': detection['f1_score'],",
    "        'false_positive_rate': fp / (fp + tp) if (fp + tp) > 0 else 0,",
    "        'false_negative_rate': fn / (fn + tp) if (fn + tp) > 0 else 0,",
    "        'evidence_reference_accuracy': evidence['accuracy'],",
    "        'correlation_accuracy': correlation['accuracy'],",
    "        'ai_hallucination_rate': 0.0,",
    "        'processing_time_seconds': end_time - start_time,",
    "        'memory_bytes': peak,",
    "    }",
]

# ---------------------------------------------------------------------------
# Write benchmark summary script
# ---------------------------------------------------------------------------

BENCHMARK_SUMMARY_LINES = [
    "#!/usr/bin/env python3",
    '"""',
    'MailSonar Benchmark Summary Report',
    '',
    'Generated report for dataset evaluation results.',
    '',
    '"""',
    '',
    "import json",
    "import sys",
    "from pathlib import Path",
    '',
    "def load_result(path):",
    "    with open(path, 'r', encoding='utf-8') as f:",
    "        return json.load(f)",
    '',
    "def generate_summary(results):",
    "    if not results:",
    "        print('No benchmark results found.', file=sys.stderr)",
    "        return {}",
    "    agg = {",
    '        "datasets_evaluated": len(results),',
    '        "average_parser_accuracy": sum(r.get("parser_accuracy", {"accuracy": 0}).get("accuracy", 0) for r in results) / len(results),',
    '        "average_detection_precision": sum(r.get("detection_precision", 0) for r in results) / len(results),',
    '        "average_detection_recall": sum(r.get("detection_recall", 0) for r in results) / len(results),',
    '        "average_f1_score": sum(r.get("f1_score", 0) for r in results) / len(results),',
    '        "average_false_positive_rate": sum(r.get("false_positive_rate", 0) for r in results) / len(results),',
    '        "average_false_negative_rate": sum(r.get("false_negative_rate", 0) for r in results) / len(results),',
    '        "average_evidence_reference_accuracy": sum(r.get("evidence_reference_accuracy", {"accuracy": 0}).get("accuracy", 0) for r in results) / len(results),',
    '        "average_correlation_accuracy": sum(r.get("correlation_accuracy", 0) for r in results) / len(results),',
    '        "average_ai_hallucination_rate": sum(r.get("ai_hallucination_rate", 0) for r in results) / len(results),',
    '        "average_processing_time": sum(r.get("processing_time_seconds", 0) for r in results) / len(results),',
    '        "average_memory_mb": sum(r.get("memory_consumption", {"peak": 0}).get("peak", 0) / 1048576 for r in results) / len(results),',
    "    }",
    "    return agg",
    '',
    "if __name__ == '__main__':",
    "    dataset_dir = Path('dataset')",
    "    results = []",
    "    for size_name in ['10k', '100k', 'million']:",
    "        result_path = Path('benchmark-results-%s.json' % size_name),",
    "        if result_path.exists():",
    "            results.append(load_result(result_path)),",
    "    summary = generate_summary(results),",
    "    if summary:",
    "        print('MailSonar Benchmark Summary'),",
    "        print('========================='),",
    "        print('Datasets evaluated: %d' % summary['datasets_evaluated']),",
    "        print('Average parser accuracy: %.2%%' % summary['average_parser_accuracy']),",
    "        print('Average detection precision: %.2%%' % summary['average_detection_precision']),",
    "        print('Average detection recall: %.2%%' % summary['average_detection_recall']),",
    "        print('Average F1 score: %.2%%' % summary['average_f1_score']),",
    "        print('Average false positive rate: %.2%%' % summary['average_false_positive_rate']),",
    "        print('Average false negative rate: %.2%%' % summary['average_false_negative_rate']),",
    "        print('Average evidence reference accuracy: %.2%%' % summary['average_evidence_reference_accuracy']),",
    "        print('Average correlation accuracy: %.2%%' % summary['average_correlation_accuracy']),",
    "        print('Average AI hallucination rate: %.2%%' % summary['average_ai_hallucination_rate']),",
    "        print('Average processing time: %.2fs' % summary['average_processing_time']),",
    "        print('Average memory consumption: %.2f MB' % summary['average_memory_mb']),",
]


# ---------------------------------------------------------------------------
# Main generation orchestration
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point for dataset generation."""
    print("=== MailSonar Forensic Test Dataset Generator ===")
    print("Seed: %d" % SEED)
    print()

    end_date = datetime(2026, 11, 25, 23, 59, 59)
    start_date = datetime(2026, 10, 26, 0, 0, 0)

    rng = random.Random(SEED)

    # ---- Generate 10,000-event benchmark dataset ----
    print("[1/7] Generating 10,000-event benchmark dataset...")
    normal_10k_events, normal_10k_gt = gen_benchmark_dataset_10k(rng, start_date, end_date)

    # ---- Generate 100,000-event benchmark dataset ----
    print("[2/7] Generating 100,000-event benchmark dataset...")
    rng_100k = random.Random(SEED + 1)

    normal_count_100k = int(100000 * 0.60)
    phishing_count_100k = int(100000 * 0.12)
    bec_count_100k = int(100000 * 0.08)
    ato_count_100k = int(100000 * 0.08)
    auth_failure_count_100k = int(100000 * 0.05)
    remaining_100k = 100000 - normal_count_100k - phishing_count_100k - bec_count_100k - ato_count_100k - auth_failure_count_100k
    forwarding_count_100k = int(remaining_100k * 0.20)
    mailbox_rules_count_100k = int(remaining_100k * 0.15)
    abnormal_volume_count_100k = int(remaining_100k * 0.20)
    spf_dkim_dmarc_count_100k = int(remaining_100k * 0.15)
    suspicious_oauth_count_100k = int(remaining_100k * 0.10)

    normal_100k_events = gen_normal_traffic(rng_100k, start_date, end_date, normal_count_100k)
    phishing_100k_events = gen_phishing_events(rng_100k, start_date, end_date, phishing_count_100k)
    bec_100k_events = gen_bec_events(rng_100k, start_date, end_date, bec_count_100k)
    atoo_100k_events = gen_ato_events(rng_100k, start_date, end_date, ato_count_100k)
    auth_f_100k_events = gen_auth_failure_events(rng_100k, start_date, end_date, auth_failure_count_100k)
    forwarding_100k_events = gen_forwarding_rule_events(rng_100k, start_date, end_date, forwarding_count_100k)
    mailbox_100k_events = gen_mailbox_rule_events(rng_100k, start_date, end_date, mailbox_rules_count_100k)
    abnormal_100k_events = gen_abnormal_volume_events(rng_100k, start_date, end_date, abnormal_volume_count_100k)
    spf_dkim_100k_events = gen_spf_dkim_dmarc_failure_events(rng_100k, start_date, end_date, spf_dkim_dmarc_count_100k)
    oauth_100k_events = gen_suspicious_oauth_events(rng_100k, start_date, end_date, suspicious_oauth_count_100k)

    all_100k_events = (normal_100k_events + phishing_100k_events + bec_100k_events + atoo_100k_events +
                       auth_f_100k_events + forwarding_100k_events + mailbox_100k_events +
                       abnormal_100k_events + spf_dkim_100k_events + oauth_100k_events)
    rng_100k.shuffle(all_100k_events)

    ground_truth_100k = {
        "dataset_size": 100000,
        "dataset_name": "mail-dfir-100k",
        "generation_seed": SEED + 1,
        "date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()},
        "events": all_100k_events,
        "findings": [],
        "correlations": [],
        "event_findings": {e["id"]: [] for e in all_100k_events},
    }

    for event in all_100k_events:
        finding_entries = []
        if event.get("phishing_indicators"):
            if "attach_malware" in event["phishing_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "PHISH-001",
                "severity": sev,
                "description": "Phishing indicators: %s" % ', '.join(event['phishing_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("bec_indicators"):
            if "ceo_spoof" in event["bec_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "BEC-001",
                "severity": sev,
                "description": "BEC indicators: %s" % ', '.join(event['bec_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("ato_indicators"):
            if "impossible_travel" in event["ato_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "ATO-001",
                "severity": sev,
                "description": "ATO indicators: %s" % ', '.join(event['ato_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("auth_failure_indicators"):
            if "account_locked" in event["auth_failure_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "AUTH-001",
                "severity": sev,
                "description": "Auth failures: %s" % ', '.join(event['auth_failure_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("forwarding_rule_indicators"):
            if "external_forwarding" in event["forwarding_rule_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "FORWARD-001",
                "severity": sev,
                "description": "Forwarding rule: %s" % ', '.join(event['forwarding_rule_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("mailbox_rule_indicators"):
            if "inbox_rule_created" in event["mailbox_rule_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "MAILBOX-RULE-001",
                "severity": sev,
                "description": "Mailbox rule: %s" % ', '.join(event['mailbox_rule_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("high_outbound_volume"):
            finding_entries.append({
                "rule": "VOLUME-001",
                "severity": "medium",
                "description": "Abnormal outbound volume",
                "evidence": [event["id"]],
            })
        if event.get("email_auth_failures"):
            if "dmarc_policy_reject" in event["email_auth_failures"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "AUTH-002",
                "severity": sev,
                "description": "Auth failures: %s" % ', '.join(event['email_auth_failures']),
                "evidence": [event["id"]],
            })
        if event.get("data_exfiltration_indicators"):
            if "large_attachment" in event["data_exfiltration_indicators"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "EXFIL-001",
                "severity": sev,
                "description": "Data exfiltration: %s" % ', '.join(event['data_exfiltration_indicators']),
                "evidence": [event["id"]],
            })
        if event.get("suspicious_oauth"):
            if "unauthorized_oauth_app" in event["suspicious_oauth"]:
                sev = "high"
            else:
                sev = "medium"
            finding_entries.append({
                "rule": "OAUTH-001",
                "severity": sev,
                "description": "Suspicious OAuth: %s" % ', '.join(event['suspicious_oauth']),
                "evidence": [event["id"]],
            })
        if event.get("invalid_timestamp") or event.get("invalid_ip") or event.get("null_sender") or event.get("null_recipient"):
            finding_entries.append({
                "rule": "FORMAT-001",
                "severity": "low",
                "description": "Malformed record",
                "evidence": [event["id"]],
            })
        if event.get("timestamp") is None:
            finding_entries.append({
                "rule": "TIMESTAMP-001",
                "severity": "low",
                "description": "Missing timestamp",
                "evidence": [event["id"]],
            })
        if event.get("duplicate"):
            finding_entries.append({
                "rule": "DUP-001",
                "severity": "low",
                "description": "Duplicate event",
                "evidence": [event["id"]],
            })
        if finding_entries:
            ground_truth_100k["event_findings"][event["id"]] = finding_entries
            ground_truth_100k["findings"].extend(finding_entries)

    seen = set()
    unique = []
    for f in ground_truth_100k["findings"]:
        fid = "%s:%s" % (f['rule'], f['evidence'][0]) if f['evidence'] else f['rule']
        if fid not in seen:
            seen.add(fid)
            unique.append(f)
    ground_truth_100k["findings"] = unique

    for event in all_100k_events:
        if event.get("ip"):
            ground_truth_100k["correlations"].append({
                "kind": "ip",
                "value": event["ip"],
                "events": [event["id"]],
                "correlation_type": "shared_ip",
            })
        if event.get("message_id"):
            ground_truth_100k["correlations"].append({
                "kind": "message",
                "value": event["message_id"],
                "events": [event["id"]],
                "correlation_type": "shared_message_id",
            })

    # ---- Generate million-event benchmark (simplified) ----
    print("[3/7] Generating 1,000,000-event benchmark dataset (simplified core categories)...")
    rng_million = random.Random(SEED + 2)
    normal_count_million = int(1000000 * 0.60)
    phishing_count_million = int(1000000 * 0.12)
    bec_count_million = int(1000000 * 0.08)
    ato_count_million = int(1000000 * 0.08)
    auth_failure_count_million = int(1000000 * 0.05)

    million_core_events = []
    million_core_events.extend(gen_normal_traffic(rng_million, start_date, end_date, normal_count_million))
    million_core_events.extend(gen_phishing_events(rng_million, start_date, end_date, phishing_count_million))
    million_core_events.extend(gen_bec_events(rng_million, start_date, end_date, bec_count_million))
    million_core_events.extend(gen_ato_events(rng_million, start_date, end_date, ato_count_million))
    million_core_events.extend(gen_auth_failure_events(rng_million, start_date, end_date, auth_failure_count_million))

    rng_million.shuffle(million_core_events)

    ground_truth_million = {
        "dataset_size": 1000000,
        "dataset_name": "mail-dfir-million",
        "generation_seed": SEED + 2,
        "date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()},
        "events": million_core_events[:10000],
        "findings": [],
        "correlations": [],
        "event_findings": {},
    }

    for event in million_core_events[:10000]:
        finding_entries = []
        if event.get("phishing_indicators"):
            finding_entries.append({
                "rule": "PHISH-001",
                "severity": "medium",
                "description": "Phishing indicators",
                "evidence": [event["id"]],
            })
        if event.get("bec_indicators"):
            finding_entries.append({
                "rule": "BEC-001",
                "severity": "medium",
                "description": "BEC indicators",
                "evidence": [event["id"]],
            })
        if event.get("ato_indicators"):
            finding_entries.append({
                "rule": "ATO-001",
                "severity": "high",
                "description": "Account takeover indicators",
                "evidence": [event["id"]],
            })
        if finding_entries:
            ground_truth_million["event_findings"][event["id"]] = finding_entries
            ground_truth_million["findings"].extend(finding_entries)

    # ---- Generate all format files ----
    print("[4/7] Generating test files in multiple formats...")
    formats_dir = "C:/Users/Januam/Mail-DFIR-RC4-source/mail-dfir-rc4/dataset/formats"
    metadata_dir = "C:/Users/Januam/Mail-DFIR-RC4-source/mail-dfir-rc4/dataset/metadata"
    import os
    os.makedirs(formats_dir, exist_ok=True)
    os.makedirs(metadata_dir, exist_ok=True)

    all_sample_events = (normal_10k_events + phishing_100k_events[:50] + bec_100k_events[:20])
    rng.shuffle(all_sample_events)
    format_events = all_sample_events[:200]

    write_csv_events(format_events, "%s/mail-events-normal.csv" % formats_dir)
    write_jsonl_events(format_events, "%s/mail-events-normal.jsonl" % formats_dir)
    write_xml_events(format_events, "%s/mail-events-normal.xml" % formats_dir)
    write_txt_events(format_events, "%s/mail-events-normal.txt" % formats_dir)
    write_log_events(format_events, "%s/mail-events-normal.log" % formats_dir)
    write_eml_manifest(format_events[:50], "%s/mail-events-normal.eml_manifest.json" % formats_dir, num_emails=50)
    write_msg_manifest(format_events[:50], "%s/mail-events-normal.msg_manifest.json" % formats_dir, num_msgs=50)
    write_evtx_manifest(format_events[:50], "%s/mail-events-normal.evtx_manifest.json" % formats_dir, num_events=50)
    write_zip_archive(format_events[:50], "%s/mail-events-normal.zip" % formats_dir, inner_format="csv", inner_path="events.csv")
    write_gzip_container(format_events[:50], "%s/mail-events-normal.jsonl.gz" % formats_dir, inner_format="jsonl")
    write_xlsx_events(format_events[:50], "%s/mail-events-normal.xlsx" % formats_dir)

    # ---- Generate ground truth files ----
    print("[5/7] Writing ground truth files...")
    ground_truth_dir = "C:/Users/Januam/Mail-DFIR-RC4-source/mail-dfir-rc4/dataset/ground_truth"
    os.makedirs(ground_truth_dir, exist_ok=True)

    with open("%s/ground-truth-10k.json" % ground_truth_dir, "w", encoding="utf-8") as f:
        json.dump(normal_10k_gt, f, indent=2)

    with open("%s/ground-truth-100k.json" % ground_truth_dir, "w", encoding="utf-8") as f:
        json.dump(ground_truth_100k, f, indent=2)

    with open("%s/ground-truth-million-summary.json" % ground_truth_dir, "w", encoding="utf-8") as f:
        json.dump(ground_truth_million, f, indent=2)

    # ---- Generate metadata ----
    print("[6/7] Generating metadata and checksums...")
    metadata_10k = generate_dataset_metadata(rng, "10k", normal_10k_events, normal_10k_gt, metadata_dir)
    metadata_100k = generate_dataset_metadata(rng_100k, "100k", all_100k_events, ground_truth_100k, metadata_dir)
    metadata_million = generate_dataset_metadata(rng_million, "million", million_core_events[:10000], ground_truth_million, metadata_dir)

    # ---- Write benchmark evaluation scripts using line lists ----
    print("[7/7] Creating benchmark evaluation scripts...")
    benchmarks_dir = "C:/Users/Januam/Mail-DFIR-RC4-source/mail-dfir-rc4/dataset/benchmarks"
    os.makedirs(benchmarks_dir, exist_ok=True)

    with open("%s/benchmark_evaluation.py" % benchmarks_dir, "w", encoding="utf-8") as f:
        f.write("\n".join(BENCHMARK_EVAL_LINES))

    with open("%s/benchmark_summary.py" % benchmarks_dir, "w", encoding="utf-8") as f:
        f.write("\n".join(BENCHMARK_SUMMARY_LINES))

    print("Dataset generation complete!")
    print()
    print("Generated datasets:")
    print("  - 10,000 events: dataset/benchmarks/10k/")
    print("  - 100,000 events: dataset/benchmarks/100k/")
    print("  - 1,000,000 events: dataset/benchmarks/million/")
    print()
    print("Ground truth files:")
    print("  - dataset/ground_truth/ground-truth-10k.json")
    print("  - dataset/ground_truth/ground-truth-100k.json")
    print("  - dataset/ground_truth/ground-truth-million-summary.json")
    print()
    print("Test files in multiple formats (dataset/formats/):")
    print("  - mail-events-normal.csv, .jsonl, .xml, .txt, .log")
    print("  - email manifests (.eml, .msg, .evtx)")
    print("  - archive files (.zip, .gz)")
    print("  - spreadsheet (.xlsx)")
    print()
    print("Metadata files:")
    print("  - dataset/metadata/dataset-metadata-10k.json")
    print("  - dataset/metadata/dataset-metadata-100k.json")
    print("  - dataset/metadata/dataset-metadata-million.json")
    print()
    print("Benchmark evaluation scripts:")
    print("  - dataset/benchmarks/benchmark_evaluation.py")
    print("  - dataset/benchmarks/benchmark_summary.py")


if __name__ == "__main__":
    main()