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
uvicorn app.main:app --reload   # then open http://127.0.0.1:8000/docs
```

Upload `tests/samples/phishing_example.eml` to `/analyze` in the docs page to try it.

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
| Headers | HDR-001 | Reply-To domain differs from From domain |
| URLs | URL-001 … URL-010 | Link text lies, raw IP, `@` trick, punycode, typosquatting, brand in subdomain, combosquatting, shorteners, redirects |

## Roadmap

- [x] FastAPI skeleton, .eml parsing (headers, bodies, links, attachments)
- [x] SPF/DKIM/DMARC checks from `Authentication-Results`
- [x] URL analysis (registrable domain, brand lookalikes, link-text mismatch…)
- [ ] Attachment analysis (dangerous extensions, magic bytes, macros, encrypted archives)
- [ ] More header rules (Return-Path mismatch, display-name spoofing)
- [ ] IOC enrichment (VirusTotal, URLscan, AbuseIPDB) with caching, keys in `.env`
- [ ] scikit-learn model (dataset, features, precision/recall), blended with rule score
- [ ] HTML triage report, MITRE ATT&CK mapping, IOC export (JSON / MISP)
- [ ] Dockerfile, CI, screenshots, demo

## Safety

Only the harmless fake sample is committed. Keep real phishing samples in
`samples_private/` (git-ignored) and never open their links or attachments on your host.
