"""URL / link analysis: catch links that lie about where they go.

Golden rule: only the HOST decides where a link goes, and only the REGISTRABLE
DOMAIN (e.g. evil.co.uk) tells you who owns it. Everything else is decoration.

Not covered yet: domain age (RDAP), following redirects, page content (e.g. Google Forms).
"""
import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

import tldextract

from app.brands import BRANDS
from app.models import Finding, Link, ParsedEmail, Severity

# Offline: use the Public Suffix List bundled with the library instead of downloading it
# at runtime. Private suffixes (github.io, blogspot.com...) count as suffixes too, because
# each user of those services owns their own subdomain.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly"}
STANDARD_PORTS = {None, 80, 443}
TOKEN_SPLIT = re.compile(r"[.\-_]+")
LOOKS_LIKE_URL = re.compile(r"^(https?://)?[\w\-]+(\.[\w\-]+)+(/\S*)?$", re.IGNORECASE)


def levenshtein(a: str, b: str) -> int:
    """Minimum number of single-character inserts, deletes or replacements to turn a into b."""
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,               # delete ca
                current[j - 1] + 1,            # insert cb
                previous[j - 1] + (ca != cb),  # replace (free if same letter)
            ))
        previous = current
    return previous[-1]


def registrable_domain(host: str) -> str:
    """'login.paypal.com.evil.co.uk' -> 'evil.co.uk'.  Empty string if there is no valid suffix."""
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _finding(rule_id: str, severity: Severity, score: int, text: str, mitre: str = "T1566.002") -> Finding:
    return Finding(rule_id=rule_id, description=text, severity=severity, score=score, mitre=mitre)


def _max_distance(brand: str) -> int:
    """How many edits still count as a lookalike. Short names need 0-1, or every word matches:
    'dhl' is 1 edit from 'del', 'amazon' is 2 edits from 'amazing'."""
    if len(brand) < 4:
        return 0
    return 1 if len(brand) < 9 else 2


def _brand_findings(host: str, domain: str) -> list[Finding]:
    """Brand in subdomains (URL-006), brand inside a foreign domain (URL-007), lookalike (URL-005)."""
    ext = _extract(host)
    sub_tokens = set(TOKEN_SPLIT.split(ext.subdomain)) - {""}
    domain_tokens = set(TOKEN_SPLIT.split(ext.domain)) - {""}
    findings = []
    for brand, official in BRANDS.items():
        if domain in official:
            continue
        if brand in sub_tokens:
            findings.append(_finding("URL-006", Severity.high, 25,
                f"'{brand}' appears only in the subdomains of {host}; the real owner is {domain}"))
        elif brand in domain_tokens:
            findings.append(_finding("URL-007", Severity.high, 25,
                f"'{brand}' is used inside {domain}, which is not an official {brand} domain (combosquatting)"))
        else:
            max_distance = _max_distance(brand)
            for token in domain_tokens:
                if 0 < levenshtein(token, brand) <= max_distance:
                    findings.append(_finding("URL-005", Severity.high, 30,
                        f"{domain} looks like '{brand}' ('{token}' is {levenshtein(token, brand)} "
                        f"character(s) away): typosquatting"))
                    break
    return findings


def _text_mismatch(link: Link, domain: str) -> Finding | None:
    """URL-001: visible text shows one domain, the href goes to another."""
    text = link.text.strip()
    if not text or " " in text or not LOOKS_LIKE_URL.match(text):
        return None  # "Click here" is not a lie about a domain
    shown_host = urlsplit(text if "://" in text else f"http://{text}").hostname or ""
    shown_domain = registrable_domain(shown_host)
    if shown_domain and shown_domain != domain:
        return _finding("URL-001", Severity.high, 30,
            f"Link text shows {shown_domain} but actually goes to {domain or link.href}")
    return None


def analyze_link(link: Link) -> list[Finding]:
    try:
        parts = urlsplit(link.href)
        port = parts.port
    except ValueError:  # malformed URL, e.g. invalid port
        return [_finding("URL-000", Severity.low, 5, f"Malformed URL: {link.href[:100]}")]
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return []  # mailto:, tel:, #anchors...

    host = parts.hostname.lower()  # .hostname already drops userinfo and port
    findings = []

    if parts.username is not None:
        findings.append(_finding("URL-003", Severity.high, 25,
            f"URL hides its real host behind '{parts.username}@': it actually goes to {host}"))

    if is_ip(host):
        findings.append(_finding("URL-002", Severity.medium, 20, f"Link points to a raw IP address ({host})"))
        domain = ""
    else:
        domain = registrable_domain(host)
        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append(_finding("URL-004", Severity.medium, 20,
                f"Punycode domain {host} (displays as '{host.encode().decode('idna')}'): possible homoglyph"))
        if domain in SHORTENERS:
            findings.append(_finding("URL-008", Severity.low, 10, f"URL shortener hides the destination ({domain})"))
        if domain:
            findings.extend(_brand_findings(host, domain))

    if port not in STANDARD_PORTS:
        findings.append(_finding("URL-010", Severity.low, 10, f"Non-standard port {port} on {host}"))

    for _, value in parse_qsl(parts.query):
        if value.lower().startswith(("http://", "https://")):
            findings.append(_finding("URL-009", Severity.medium, 15,
                f"URL on {domain or host} redirects to another URL: {value[:100]}"))
            break

    mismatch = _text_mismatch(link, domain)
    if mismatch:
        findings.append(mismatch)
    return findings


def analyze(email: ParsedEmail) -> list[Finding]:
    # Report each rule once per email: 20 links to the same shortener shouldn't score 20 times.
    seen: dict[str, Finding] = {}
    for link in email.links:
        for finding in analyze_link(link):
            seen.setdefault(finding.rule_id, finding)
    return list(seen.values())
