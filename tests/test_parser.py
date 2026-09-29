from pathlib import Path

from app.parser import parse_email

SAMPLE = (Path(__file__).parent / "samples" / "phishing_example.eml").read_bytes()


def test_headers():
    email = parse_email(SAMPLE)
    assert email.subject == "Urgent: your account has been limited"
    assert "paypal.com" in email.from_
    assert "paypa1-verify.xyz" in email.reply_to
    assert any("dmarc=fail" in h for h in email.authentication_results)


def test_links_keep_visible_text():
    email = parse_email(SAMPLE)
    html_link = next(l for l in email.links if "paypa1-verify" in l.href)
    assert html_link.text == "https://www.paypal.com/signin"
    assert any(l.href.startswith("http://203.0.113.45") for l in email.links)


def test_attachments_hashed():
    email = parse_email(SAMPLE)
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "invoice.pdf.html"
    assert len(att.sha256) == 64
