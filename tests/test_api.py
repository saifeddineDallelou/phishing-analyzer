from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SAMPLE = Path(__file__).parent / "samples" / "phishing_example.eml"


def test_analyze_returns_report():
    with SAMPLE.open("rb") as f:
        resp = client.post("/analyze", files={"file": ("sample.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    report = resp.json()
    assert {"verdict", "score", "findings", "email"} <= report.keys()
    assert any(f["rule_id"] == "HDR-001" for f in report["findings"])
    # Raw attachment bytes must never be sent back out
    assert all("data" not in a for a in report["email"]["attachments"])


def test_empty_file_rejected():
    resp = client.post("/analyze", files={"file": ("empty.eml", b"", "message/rfc822")})
    assert resp.status_code == 400
