"""Threat intel tests use httpx.MockTransport: a fake internet that answers like the real APIs."""
import asyncio
import hashlib
import time

import httpx

from app.config import Settings
from app.intel import enrich
from app.intel.iocs import extract_iocs, sender_ip
from app.models import Attachment, Link, ParsedEmail

KEYS = Settings(virustotal_api_key="vt-test", abuseipdb_api_key="abuse-test", urlhaus_auth_key="uh-test")
DATA = b"fake attachment"
SHA = hashlib.sha256(DATA).hexdigest()


def email(**fields) -> ParsedEmail:
    base = {
        "from_": "PayPal <service@paypa1-verify.xyz>",
        "received": ["from mailer (unknown [1.2.3.4]) by mx.example.com"],
        "links": [Link(href="http://paypa1-verify.xyz/login")],
        "attachments": [Attachment(filename="invoice.pdf.html", content_type="text/html", size=len(DATA),
                                   md5=hashlib.md5(DATA).hexdigest(), sha256=SHA, data=DATA)],
    }
    return ParsedEmail(**{**base, **fields})


def fake_internet(calls: list[str]) -> httpx.AsyncClient:
    """Answers like VirusTotal, AbuseIPDB and URLhaus would for a known phishing campaign."""
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host + request.url.path)
        if request.url.host == "www.virustotal.com":
            if "/files/" in request.url.path:
                return httpx.Response(200, json={"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 12, "undetected": 58}}}})
            if "/domains/" in request.url.path:
                return httpx.Response(200, json={"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 6, "harmless": 60},
                    "creation_date": int(time.time()) - 3 * 86400}}})
        if request.url.host == "api.abuseipdb.com":
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 92, "totalReports": 41}})
        if request.url.host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online"})
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


def test_known_bad_campaign_is_flagged():
    findings = run(enrich(email(), KEYS, fake_internet([])))
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"INTEL-001", "INTEL-002", "INTEL-003", "INTEL-004"}
    assert "12/70" in by_rule["INTEL-001"].description
    assert "3 day(s)" in by_rule["INTEL-003"].description


def test_no_keys_means_no_requests():
    calls: list[str] = []
    assert run(enrich(email(), Settings(), fake_internet(calls))) == []
    assert calls == []


def test_service_down_does_not_break_analysis():
    def broken(request):
        raise httpx.ConnectTimeout("service unreachable")
    client = httpx.AsyncClient(transport=httpx.MockTransport(broken))
    assert run(enrich(email(), KEYS, client)) == []


def test_unknown_iocs_give_no_findings():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(
        200, json={"query_status": "no_results", "data": {"totalReports": 0}}) if "virustotal" not in r.url.host
        else httpx.Response(404)))
    assert run(enrich(email(), KEYS, client)) == []


def test_cache_avoids_asking_twice():
    calls: list[str] = []
    run(enrich(email(), KEYS, fake_internet(calls)))
    first = len(calls)
    run(enrich(email(), KEYS, fake_internet(calls)))
    assert first > 0 and len(calls) == first


def test_virustotal_budget_per_email():
    calls: list[str] = []
    many = email(links=[Link(href=f"http://evil{i}.xyz/") for i in range(5)], from_="a@evil9.xyz")
    run(enrich(many, Settings(virustotal_api_key="vt-test"), fake_internet(calls)))
    assert len([c for c in calls if "virustotal" in c]) == 4


def test_whitelisted_ip_is_ignored():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(
        200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 500, "isWhitelisted": True}})))
    assert run(enrich(email(), Settings(abuseipdb_api_key="k"), client)) == []


def test_extract_iocs():
    iocs = extract_iocs(email(
        reply_to="x@gmail.com",
        links=[Link(href="http://paypa1-verify.xyz/login"), Link(href="https://www.paypal.com/"),
               Link(href="http://192.168.1.10/admin"), Link(href="mailto:a@b.com")],
    ))
    assert iocs.hashes == [SHA]
    assert iocs.domains == ["paypa1-verify.xyz"]  # paypal.com and gmail.com are well known: skipped
    assert iocs.ips == ["1.2.3.4"]                 # private 192.168.x.x is skipped
    assert "mailto:a@b.com" not in iocs.urls


def test_sender_ip_only_from_our_top_header():
    forged = ParsedEmail(received=["from x by mx.example.com", "from attacker ([8.8.4.4])"])
    assert sender_ip(forged) == ""


def test_api_key_never_printed():
    assert "vt-test" not in repr(KEYS) and "vt-test" not in str(KEYS)
