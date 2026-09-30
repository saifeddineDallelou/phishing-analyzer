"""Targeted impersonation of the protected organization (spear phishing / BEC).

Generic rules know PayPal. Only the organization profile knows who the director is.
"""
from email.utils import parseaddr
from urllib.parse import urlsplit

from app.analyzers.urls import brand_findings, registrable_domain
from app.brands import FREE_WEBMAIL
from app.models import Finding, ParsedEmail, Severity
from app.organization import OrganizationProfile, get_profile, normalize


def _finding(rule_id: str, severity: Severity, score: int, text: str, mitre: str) -> Finding:
    return Finding(rule_id=rule_id, description=text, severity=severity, score=score, mitre=mitre)


def _matches_vip(display: list[str], vip_name: str) -> bool:
    """Full name ('Karim Ben-Ali', 'KarimBenAli'), last name first ('BEN ALI Karim'),
    or initial + last name ('K. Ben Ali')."""
    vip = normalize(vip_name)
    if len(vip) < 2:
        return False  # a single word like "Karim" would match half the country
    compact = "".join(display)
    if "".join(vip) in compact or "".join(vip[1:] + vip[:1]) in compact:
        return True
    first_initial, last_name = vip[0][0], "".join(vip[1:])
    return first_initial in display and last_name in compact


def check_vip(email: ParsedEmail, profile: OrganizationProfile, domain: str, addr: str) -> list[Finding]:
    """ORG-001: "Karim Ben Ali" <k.benali.ceo@gmail.com>"""
    display = normalize(parseaddr(email.from_)[0])
    for vip in profile.vips:
        if _matches_vip(display, vip.name):
            role = f" ({vip.role})" if vip.role else ""
            free = domain in FREE_WEBMAIL
            return [_finding("ORG-001", Severity.high, 40 if free else 35,
                f"Display name matches {vip.name}{role}, but the address {addr} is "
                f"{'a free webmail account' if free else 'outside the organization'}", "T1656")]
    return []


def check_service_name(email: ParsedEmail, profile: OrganizationProfile, domain: str, addr: str) -> list[Finding]:
    """ORG-002: "Scolarité" <scolarite.esprit@gmail.com>.
    Service names are common words ("Direction"), so we need a second clue: free webmail,
    or the organization's own name next to it ("Direction ESPRIT")."""
    display = normalize(parseaddr(email.from_)[0])
    compact = "".join(display)
    service = next((s for s in profile.service_names if "".join(normalize(s)) in compact), None)
    if not service:
        return []
    mentions_org = any("".join(normalize(n)) in compact for n in profile.names)
    if domain in FREE_WEBMAIL or mentions_org:
        return [_finding("ORG-002", Severity.high, 30,
            f"Display name uses the internal service '{service}' but the address {addr} is outside the organization",
            "T1656")]
    return []


def check_lookalike_domains(email: ParsedEmail, profile: OrganizationProfile) -> list[Finding]:
    """ORG-003: espirt.tn, esprit-tn.com, esprit.tn.login-verify.xyz in the sender, Reply-To or links.
    Known limitation: hyphenated domains (ecole-x.fr) aren't matched, since brand matching is per word."""
    # Treat each of our domains as a brand: "esprit.tn" -> brand "esprit", official {"esprit.tn"}
    our_brands: dict[str, set[str]] = {}
    for d in profile.domains:
        our_brands.setdefault(d.split(".")[0].lower(), set()).update(x.lower() for x in profile.domains)

    hosts = [parseaddr(h)[1].rpartition("@")[2].lower() for h in (email.from_, email.reply_to) if h]
    for link in email.links:
        try:
            hosts.append((urlsplit(link.href).hostname or "").lower())
        except ValueError:
            continue

    for host in filter(None, hosts):
        domain = registrable_domain(host)
        if not domain:
            continue
        found = brand_findings(host, domain, our_brands)
        if found:
            return [_finding("ORG-003", Severity.high, 35,
                f"Lookalike of the organization's domain: {found[0].description}", "T1583.001")]
    return []


def analyze(email: ParsedEmail, profile: OrganizationProfile | None = None) -> list[Finding]:
    profile = profile or get_profile()
    if not profile.domains:
        return []
    addr = parseaddr(email.from_)[1].lower()
    domain = registrable_domain(addr.rpartition("@")[2])
    findings = []
    if domain not in {d.lower() for d in profile.domains}:
        findings += check_vip(email, profile, domain, addr)
        findings += check_service_name(email, profile, domain, addr)
    findings += check_lookalike_domains(email, profile)
    return findings
