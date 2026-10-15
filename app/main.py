"""FastAPI entry point.  Run: uvicorn app.main:app --reload  -> http://127.0.0.1:8000"""
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analyzers import ANALYZERS
from app.intel import enrich
from app.intel.iocs import extract_iocs
from app.ml.model import phishing_probability
from app.models import AnalysisReport, Finding, ParsedEmail
from app.parser import parse_email
from app.scoring import score

MAX_EMAIL_SIZE = 25 * 1024 * 1024
STATIC_DIR = Path(__file__).parent / "static"

# The UI displays attacker-written text. If an XSS bug ever slips in, this policy makes the
# browser refuse to run it: scripts and styles only from our own files, no inline code,
# no plugins, and no other site may embed the page in a frame (clickjacking).
UI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
          "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

app = FastAPI(title="Phishing Analyzer", version="0.3.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"  # browser must trust our content types
    response.headers["Referrer-Policy"] = "no-referrer"
    path = request.url.path
    if path == "/" or path.startswith("/static/"):  # not /docs: Swagger loads its files from a CDN
        response.headers["Content-Security-Policy"] = UI_CSP
        response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _report(email: ParsedEmail, findings: list[Finding]) -> AnalysisReport:
    total, verdict = score(findings)
    return AnalysisReport(verdict=verdict, score=total, findings=findings, iocs=extract_iocs(email),
                          ml_probability=phishing_probability(email, findings), email=email)


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
