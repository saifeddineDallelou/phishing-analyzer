# Phishing Analyzer

A FastAPI service that analyzes suspicious emails (SPF/DKIM/DMARC, headers, URLs,
attachments, IOC enrichment, ML scoring) and produces an explainable triage report
a SOC analyst can act on.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload   # then open http://127.0.0.1:8000
```

Drop `tests/samples/phishing_example.eml` on the page to see a triage report, or use the API at
`/docs`. The UI treats all email content as hostile: attacker text is only inserted as text (never
HTML), IOCs are defanged, nothing from the email is clickable, invisible direction characters are
revealed, and a strict Content-Security-Policy blocks injected scripts. `tests/samples/xss_example.eml`
is a harmless XSS test email for checking that.

### Threat intelligence (optional)

To check IOCs against VirusTotal, AbuseIPDB and URLhaus, copy `.env.example` to `.env` and add
your free API keys. `.env` is git-ignored: never commit it. Services without a key are skipped,
and `/analyze?intel=false` runs the local rules only. Only hashes, URLs, domains and IPs are sent,
never file contents.

### Organization profile (optional)

To detect impersonation of your own organization (VIPs, departments, lookalikes of your domain),
copy `config/organization.example.json` to `config/organization.json` and fill it in.
The real file is git-ignored because VIP names are sensitive. Use `ORG_PROFILE=<path>` to load it
from elsewhere. Without a profile, the organization rules are skipped.

## How it works

```
.eml ──> parser.py ──> ParsedEmail ──> analyzers/* ──> Findings ──> scoring.py ──> AnalysisReport
```

Every analyzer exposes `analyze(ParsedEmail) -> list[Finding]`. A Finding has a rule id,
a human-readable reason, a severity, a score and a MITRE ATT&CK technique. The reasons
are what make the report useful: "DMARC fail + lookalike domain + .html attachment",
not just "score 85".

## Detection rules

| Area | Rules | Examples |
|---|---|---|
| Authentication | AUTH-001 … AUTH-009 | DMARC fail, SPF fail/softfail, missing DKIM |
| Headers | HDR-001 … HDR-006 | Reply-To mismatch, brand display name on a foreign/free-webmail address, fake address in display name, missing Date/Message-ID, phishing-kit and bulk-mailer fingerprints, homoglyphs in display name |
| Threat intel | INTEL-001 … INTEL-004 | Attachment hash known to VirusTotal, malicious domain/URL (VirusTotal, URLhaus), newly registered domain, abusive sending IP (AbuseIPDB) |
| Organization | ORG-001 … ORG-003 | VIP name or internal service name from an outside address (BEC), lookalikes of the organization's own domain |
| URLs | URL-001 … URL-010 | Link text lies, raw IP, `@` trick, punycode, typosquatting, brand in subdomain, combosquatting, shorteners, redirects |
| Attachments | ATT-001 … ATT-007 | Dangerous extensions, double extension, RTLO, magic bytes vs extension, VBA macros (oletools), encrypted archive + password in body, programs inside ZIPs |

## Roadmap

- [x] FastAPI skeleton, .eml parsing (headers, bodies, links, attachments)
- [x] SPF/DKIM/DMARC checks from `Authentication-Results`
- [x] URL analysis (registrable domain, brand lookalikes, link-text mismatch…)
- [x] Attachment analysis (dangerous extensions, magic bytes, macros, encrypted archives)
- [x] Header rules (display-name spoofing, fake addresses, homoglyphs, mailer fingerprints)
- [x] Organization profile (VIP / internal service impersonation, own-domain lookalikes)
- [x] IOC enrichment (VirusTotal, AbuseIPDB, URLhaus) with caching, keys in `.env`
- [x] Web UI: drag-and-drop triage report (XSS-safe, CSP, defanged IOCs)
- [ ] scikit-learn model (dataset, features, precision/recall), blended with rule score
- [ ] HTML triage report, MITRE ATT&CK mapping, IOC export (JSON / MISP)
- [ ] Dockerfile, CI, screenshots, demo

## Safety

Only the harmless fake sample is committed. Keep real phishing samples in
`samples_private/` (git-ignored) and never open their links or attachments on your host.
