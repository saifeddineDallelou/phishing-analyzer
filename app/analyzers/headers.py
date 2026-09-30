"""Header anomalies that authentication (SPF/DKIM/DMARC) cannot catch.

DMARC proves which DOMAIN sent the email. It says nothing about the NAME the sender shows,
and the name is what victims read, especially on phones.

Deliberately NOT a rule: Return-Path domain != From domain. Most legitimate newsletters and
invoices are sent through services (SendGrid, Mailchimp...) whose bounce domain differs, and
DMARC alignment already does the useful version of that check.
"""
import re
import unicodedata
from email.utils import parseaddr

from app.analyzers.urls import registrable_domain
from app.brands import BRANDS, FREE_WEBMAIL
from app.models import Finding, ParsedEmail, Severity

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
WORD_SPLIT = re.compile(r"[^\w]+")

# Headers that only phishing frameworks add (older GoPhish setups, for example).
PHISHING_KIT_HEADERS = {"x-gophish-contact", "x-gophish-signature"}
PHISHING_KIT_MAILERS = ("gophish", "king phisher")
# Scripted/bulk senders: common on small legitimate websites too, so only a weak signal.
SCRIPTED_MAILERS = ("phpmailer", "swiftmailer", "sendblaster", "atomic mail sender", "python")


def _domain(address_header: str) -> str:
    _, addr = parseaddr(address_header)
    return addr.rpartition("@")[2].lower()


def _finding(rule_id: str, severity: Severity, score: int, text: str, mitre: str = "T1566") -> Finding:
    return Finding(rule_id=rule_id, description=text, severity=severity, score=score, mitre=mitre)


def check_reply_to_mismatch(email: ParsedEmail) -> list[Finding]:
    """HDR-001: replies go to a different domain than the sender: common in BEC and phishing."""
    if not email.reply_to:
        return []
    from_domain, reply_domain = _domain(email.from_), _domain(email.reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        return [_finding("HDR-001", Severity.medium, 20,
                         f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")]
    return []


def check_brand_display_name(email: ParsedEmail) -> list[Finding]:
    """HDR-002: "PayPal Security" <someone@gmail.com>."""
    name, addr = parseaddr(email.from_)
    words = [w for w in WORD_SPLIT.split(name.lower()) if w]
    # Also join neighbours so "Pay Pal" and "Office 365" match "paypal" and "office365".
    candidates = set(words) | {a + b for a, b in zip(words, words[1:])}
    domain = registrable_domain(addr.rpartition("@")[2].lower())
    for brand, official in BRANDS.items():
        if brand not in candidates:
            continue
        if domain in FREE_WEBMAIL:
            return [_finding("HDR-002", Severity.high, 35,
                f"Display name '{name}' impersonates {brand}, but the address {addr} is a free webmail account")]
        if domain not in official:
            return [_finding("HDR-002", Severity.high, 30,
                f"Display name '{name}' impersonates {brand}, but {domain or addr} is not a {brand} domain")]
    return []


def check_address_in_display_name(email: ParsedEmail) -> list[Finding]:
    """HDR-003: "service@paypal.com" <x7@mailer-bulk.ru>: apps showing only the name show a fake address."""
    name, addr = parseaddr(email.from_)
    shown = EMAIL_IN_TEXT.search(name)
    if shown and shown.group(0).lower() != addr.lower():
        return [_finding("HDR-003", Severity.high, 30,
            f"Display name shows the address {shown.group(0)} but the real sender is {addr}")]
    return []


def check_missing_headers(email: ParsedEmail) -> list[Finding]:
    """HDR-004: every real mail program adds Date and Message-ID; crude spam scripts forget."""
    missing = [label for label, value in (("Date", email.date), ("Message-ID", email.message_id)) if not value]
    if missing:
        return [_finding("HDR-004", Severity.low, 5, f"Missing standard header(s): {', '.join(missing)}")]
    return []


def check_mailer_fingerprint(email: ParsedEmail) -> list[Finding]:
    """HDR-005: the sending software left a fingerprint."""
    names = {h.lower() for h in email.header_names}
    mailer = email.mailer.lower()
    kit_headers = sorted(names & PHISHING_KIT_HEADERS)
    if kit_headers or any(kit in mailer for kit in PHISHING_KIT_MAILERS):
        evidence = ", ".join(kit_headers) or email.mailer
        return [_finding("HDR-005", Severity.high, 30, f"Phishing framework fingerprint in headers ({evidence})",
                         mitre="T1566")]
    if any(tool in mailer for tool in SCRIPTED_MAILERS):
        return [_finding("HDR-005", Severity.low, 5, f"Sent by a scripted/bulk mailer ({email.mailer})")]
    return []


def _scripts(word: str) -> set[str]:
    """'PаyPal' (Cyrillic а) -> {'LATIN', 'CYRILLIC'}"""
    return {unicodedata.name(ch, "UNKNOWN").split()[0] for ch in word if ch.isalpha()}


def check_mixed_scripts(email: ParsedEmail) -> list[Finding]:
    """HDR-006: one word mixing Latin with look-alike letters from another alphabet."""
    name, _ = parseaddr(email.from_)
    for word in WORD_SPLIT.split(name):
        scripts = _scripts(word)
        if "LATIN" in scripts and len(scripts) > 1:
            others = ", ".join(sorted(scripts - {"LATIN"})).lower()
            return [_finding("HDR-006", Severity.high, 30,
                f"Display name word {word!r} mixes Latin with {others} look-alike letters (homoglyph)",
                mitre="T1036")]
    return []


CHECKS = [check_reply_to_mismatch, check_brand_display_name, check_address_in_display_name,
          check_missing_headers, check_mailer_fingerprint, check_mixed_scripts]


def analyze(email: ParsedEmail) -> list[Finding]:
    return [finding for check in CHECKS for finding in check(email)]
