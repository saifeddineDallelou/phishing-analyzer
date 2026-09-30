"""FastAPI entry point.  Run: uvicorn app.main:app --reload  -> http://127.0.0.1:8000/docs"""
from fastapi import FastAPI, HTTPException, UploadFile

from app.analyzers import ANALYZERS
from app.intel import enrich
from app.intel.iocs import extract_iocs
from app.models import AnalysisReport, Finding, ParsedEmail
from app.parser import parse_email
from app.scoring import score

MAX_EMAIL_SIZE = 25 * 1024 * 1024

app = FastAPI(title="Phishing Analyzer", version="0.2.0")


def _report(email: ParsedEmail, findings: list[Finding]) -> AnalysisReport:
    total, verdict = score(findings)
    return AnalysisReport(verdict=verdict, score=total, findings=findings, iocs=extract_iocs(email), email=email)


def analyze_raw(raw: bytes) -> AnalysisReport:
    """Local rules only: fast, offline, no API keys needed."""
    email = parse_email(raw)
    return _report(email, [f for analyzer in ANALYZERS for f in analyzer.analyze(email)])


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/parse", response_model=ParsedEmail, response_model_by_alias=True)
async def parse(file: UploadFile) -> ParsedEmail:
    """Debug endpoint: show what the parser extracted, without any detection."""
    return parse_email(await _read(file))


@app.post("/analyze", response_model=AnalysisReport, response_model_by_alias=True)
async def analyze(file: UploadFile, intel: bool = True) -> AnalysisReport:
    """Rules + threat intelligence. Use ?intel=false for rules only (no outside requests)."""
    email = parse_email(await _read(file))
    findings = [f for analyzer in ANALYZERS for f in analyzer.analyze(email)]
    if intel:
        findings += await enrich(email)
    return _report(email, findings)


async def _read(file: UploadFile) -> bytes:
    raw = await file.read(MAX_EMAIL_SIZE + 1)
    if len(raw) > MAX_EMAIL_SIZE:
        raise HTTPException(413, "Email too large")
    if not raw:
        raise HTTPException(400, "Empty file")
    return raw
