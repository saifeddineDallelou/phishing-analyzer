"""FastAPI entry point.  Run: uvicorn app.main:app --reload  -> http://127.0.0.1:8000/docs"""
from fastapi import FastAPI, HTTPException, UploadFile

from app.analyzers import ANALYZERS
from app.models import AnalysisReport, ParsedEmail
from app.parser import parse_email
from app.scoring import score

MAX_EMAIL_SIZE = 25 * 1024 * 1024

app = FastAPI(title="Phishing Analyzer", version="0.1.0")


def analyze_raw(raw: bytes) -> AnalysisReport:
    email = parse_email(raw)
    findings = [f for analyzer in ANALYZERS for f in analyzer.analyze(email)]
    total, verdict = score(findings)
    return AnalysisReport(verdict=verdict, score=total, findings=findings, email=email)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/parse", response_model=ParsedEmail, response_model_by_alias=True)
async def parse(file: UploadFile) -> ParsedEmail:
    """Debug endpoint: show what the parser extracted, without any detection."""
    return parse_email(await _read(file))


@app.post("/analyze", response_model=AnalysisReport, response_model_by_alias=True)
async def analyze(file: UploadFile) -> AnalysisReport:
    return analyze_raw(await _read(file))


async def _read(file: UploadFile) -> bytes:
    raw = await file.read(MAX_EMAIL_SIZE + 1)
    if len(raw) > MAX_EMAIL_SIZE:
        raise HTTPException(413, "Email too large")
    if not raw:
        raise HTTPException(400, "Empty file")
    return raw
