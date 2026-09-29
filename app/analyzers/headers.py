"""Header anomaly checks.

This file contains ONE finished rule as a worked example. Every analyzer follows
the same pattern: take a ParsedEmail, return a list of Findings.
"""
from email.utils import parseaddr

from app.models import Finding, ParsedEmail, Severity


def _domain(address_header: str) -> str:
    _, addr = parseaddr(address_header)
    return addr.rpartition("@")[2].lower()


def check_reply_to_mismatch(email: ParsedEmail) -> list[Finding]:
    """Replies go to a different domain than the sender: common in BEC and phishing."""
    if not email.reply_to:
        return []
    from_domain, reply_domain = _domain(email.from_), _domain(email.reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        return [Finding(
            rule_id="HDR-001",
            description=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
            severity=Severity.medium,
            score=20,
            mitre="T1566",
        )]
    return []


# TODO(you): HDR-002 - Return-Path domain differs from From domain
# TODO(you): HDR-003 - display-name spoofing, e.g. From: "PayPal Support" <random@gmail.com>
#            Hint: parseaddr() gives you (display_name, address). Keep a small list of brands.


def analyze(email: ParsedEmail) -> list[Finding]:
    return check_reply_to_mismatch(email)
