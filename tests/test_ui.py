from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import STATIC_DIR, app

client = TestClient(app)
XSS_SAMPLE = Path(__file__).parent / "samples" / "xss_example.eml"


def test_index_is_served_with_security_headers():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", ["/static/app.js", "/static/style.css"])
def test_static_files_served(path):
    assert client.get(path).status_code == 200


def test_docs_keep_working_without_ui_csp():
    # Swagger UI loads from a CDN, so the strict UI policy must not apply to /docs.
    response = client.get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers


@pytest.mark.parametrize("dangerous", ["innerHTML", "outerHTML", "insertAdjacentHTML",
                                       "document.write", "eval(", "new Function"])
def test_ui_code_never_injects_html(dangerous):
    """The XSS rule of app.js, enforced: attacker text must only go in through textContent."""
    code = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    code_without_comments = "\n".join(line for line in code.splitlines() if not line.strip().startswith("//"))
    assert dangerous not in code_without_comments


def test_xss_sample_is_returned_as_plain_data():
    """The API returns the attacker's payload untouched, as JSON text. Safety is the UI's job."""
    with XSS_SAMPLE.open("rb") as f:
        report = client.post("/analyze?intel=false", files={"file": ("x.eml", f, "message/rfc822")}).json()
    assert report["email"]["subject"].startswith("<img src=x onerror=")
    assert "‮" in report["email"]["attachments"][0]["filename"]
