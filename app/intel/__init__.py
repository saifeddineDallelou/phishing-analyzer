"""Threat intelligence: ask outside services whether this email's IOCs are already known as bad.

Rules catch new attacks by their tricks; threat intel catches known attacks by memory.
This layer is optional and must never break the analysis: no key, a timeout or an API
error just means fewer findings.
"""
import asyncio
import logging
import time
from collections.abc import Awaitable, Callable

import httpx

from app import config
from app.intel.cache import TTLCache
from app.intel.iocs import extract_iocs
from app.intel.providers import URLhaus, AbuseIPDB, VirusTotal
from app.models import Finding, ParsedEmail, Severity

log = logging.getLogger(__name__)
CACHE = TTLCache()
VT_BUDGET = 4  # VirusTotal free tier: 4 requests per minute. Most valuable lookups first.


async def _cached(key: tuple, fetch: Callable[[], Awaitable[dict]]) -> dict | None:
    """Return a cached answer, or fetch it. Errors return None and are NOT cached (retry next time)."""
    hit = CACHE.get(key)
    if hit is not None:
        return hit
    try:
        result = await fetch()
    except (httpx.HTTPError, KeyError, ValueError) as error:
        log.warning("Threat intel lookup %s %s failed: %s", key[0], key[1], type(error).__name__)
        return None
    CACHE.set(key, result)
    return result


def _finding(rule_id: str, severity: Severity, score: int, text: str, mitre: str) -> Finding:
    return Finding(rule_id=rule_id, description=text, severity=severity, score=score, mitre=mitre)


async def _vt_file(vt: VirusTotal, sha256: str, filename: str) -> list[Finding]:
    """INTEL-001: attachment hash known as malicious."""
    data = await _cached(("virustotal", "file", sha256), lambda: vt.file(sha256))
    if not data or not data["found"]:
        return []
    malicious, total = data["stats"].get("malicious", 0), sum(data["stats"].values())
    if malicious >= 5:
        return [_finding("INTEL-001", Severity.high, 50,
            f"VirusTotal: {malicious}/{total} engines flag attachment '{filename}' as malicious", "T1566.001")]
    if malicious >= 1:
        return [_finding("INTEL-001", Severity.medium, 20,
            f"VirusTotal: {malicious}/{total} engines flag attachment '{filename}' (weak consensus)", "T1566.001")]
    return []


async def _vt_domain(vt: VirusTotal, domain: str) -> list[Finding]:
    """INTEL-002: domain known as malicious.  INTEL-003: domain registered very recently."""
    data = await _cached(("virustotal", "domain", domain), lambda: vt.domain(domain))
    if not data or not data["found"]:
        return []
    findings = []
    malicious = data["stats"].get("malicious", 0)
    if malicious >= 3:
        findings.append(_finding("INTEL-002", Severity.high, 40,
            f"VirusTotal: {malicious} engines flag the domain {domain} as malicious", "T1566.002"))
    elif malicious >= 1:
        findings.append(_finding("INTEL-002", Severity.medium, 15,
            f"VirusTotal: {malicious} engine(s) flag the domain {domain}", "T1566.002"))
    if data.get("creation_date"):
        age_days = (time.time() - data["creation_date"]) / 86400
        if age_days < 30:
            findings.append(_finding("INTEL-003", Severity.high, 25,
                f"The domain {domain} was registered only {max(0, int(age_days))} day(s) ago", "T1583.001"))
        elif age_days < 90:
            findings.append(_finding("INTEL-003", Severity.medium, 10,
                f"The domain {domain} was registered {int(age_days)} days ago", "T1583.001"))
    return findings


async def _urlhaus(uh: URLhaus, url: str) -> list[Finding]:
    """INTEL-002: URL listed by URLhaus as distributing malware."""
    data = await _cached(("urlhaus", "url", url), lambda: uh.url(url))
    if not data or not data["found"]:
        return []
    return [_finding("INTEL-002", Severity.high, 40,
        f"URLhaus lists {url[:80]} as a {data['threat']} URL (status: {data['status']})", "T1566.002")]


async def _abuseipdb(abuse: AbuseIPDB, ip: str) -> list[Finding]:
    """INTEL-004: IP address with a bad abuse reputation."""
    data = await _cached(("abuseipdb", "ip", ip), lambda: abuse.check(ip))
    if not data or not data["found"] or data["whitelisted"]:
        return []
    if data["score"] >= 75:
        return [_finding("INTEL-004", Severity.high, 30,
            f"AbuseIPDB: {ip} has an abuse confidence of {data['score']}% ({data['reports']} reports)", "T1566")]
    if data["score"] >= 25:
        return [_finding("INTEL-004", Severity.medium, 15,
            f"AbuseIPDB: {ip} has an abuse confidence of {data['score']}% ({data['reports']} reports)", "T1566")]
    return []


async def enrich(email: ParsedEmail, settings: config.Settings | None = None,
                 client: httpx.AsyncClient | None = None) -> list[Finding]:
    settings = settings or config.get_settings()
    iocs = extract_iocs(email)
    vt_key = settings.virustotal_api_key.get_secret_value()
    abuse_key = settings.abuseipdb_api_key.get_secret_value()
    urlhaus_key = settings.urlhaus_auth_key.get_secret_value()
    if not (vt_key or abuse_key or urlhaus_key):
        return []

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.intel_timeout)
    try:
        tasks = []
        if vt_key:
            vt = VirusTotal(client, vt_key)
            names = {a.sha256: a.filename or "unnamed" for a in email.attachments}
            # Attachments first (strongest evidence), then domains, within the per-email budget.
            lookups = [_vt_file(vt, h, names.get(h, "unnamed")) for h in iocs.hashes]
            lookups += [_vt_domain(vt, d) for d in iocs.domains]
            tasks += lookups[:VT_BUDGET]
            for skipped in lookups[VT_BUDGET:]:
                skipped.close()  # never awaited: close it so Python doesn't warn
        if urlhaus_key:
            uh = URLhaus(client, urlhaus_key)
            tasks += [_urlhaus(uh, u) for u in iocs.urls]
        if abuse_key:
            abuse = AbuseIPDB(client, abuse_key)
            tasks += [_abuseipdb(abuse, ip) for ip in iocs.ips]
        results = await asyncio.gather(*tasks)  # all lookups run at the same time
    finally:
        if owns_client:
            await client.aclose()

    # Keep the strongest finding per rule, like the other analyzers keep one per rule.
    strongest: dict[str, Finding] = {}
    for finding in (f for group in results for f in group):
        if finding.rule_id not in strongest or finding.score > strongest[finding.rule_id].score:
            strongest[finding.rule_id] = finding
    return list(strongest.values())
