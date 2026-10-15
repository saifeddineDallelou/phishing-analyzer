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
- [x] scikit-learn model in shadow mode (see "Machine learning" below)
- [ ] Larger modern legitimate dataset, positive trust features, then use the model in the verdict
- [ ] HTML triage report, MITRE ATT&CK mapping, IOC export (JSON / MISP)
- [ ] Dockerfile, CI, screenshots, demo

## Safety

Only the harmless fake sample is committed. Keep real phishing samples in
`samples_private/` (git-ignored) and never open their links or attachments on your host.

## Machine learning

`models/phishing_model.json` is a logistic regression trained on our rule findings plus a few
numeric signals (links, attachments, pressure words, body length). It runs in **shadow mode**:
its probability is shown in the report but does not change the verdict yet.

```bash
python -m scripts.train_model --exclude AUTH- HDR-004 html_only   # data/phishing + data/legit
python -m scripts.score_emails data/modern_legit --model models/phishing_model.json
```

Training data (not in the repo, see `data/` in `.gitignore`): 1,303 phishing emails from the
[Nazario phishing corpus](https://monkey.org/~jose/phishing/) 2023-2025 (Jose Nazario, CC BY 4.0)
and 2,500 legitimate emails from the 2003 [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/).

**Known dataset bias.** The legitimate emails predate DKIM/DMARC and HTML-only mail, so AUTH-*
rules, HDR-004 and `html_only` fire in 0% of them. A model using those features scored 97%
precision / 96% recall on the test split but rated modern legitimate emails (an HTML-only
recruiter reply) as 99% phishing: it had learned "modern email = phishing". Those features are
excluded from the shipped model (86.5% precision / 82.8% recall, ROC AUC 0.95 on 951 held-out
emails). It still over-scores legitimate verification emails ("verify your account" + a link),
because it has no positive trust signals yet. This is why it stays in shadow mode.

The model is stored as JSON weights rather than a pickle, so loading it can never execute code.
