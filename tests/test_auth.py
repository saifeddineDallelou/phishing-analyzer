from pathlib import Path

from app.analyzers import auth
from app.models import ParsedEmail
from app.parser import parse_email

SAMPLE = (Path(__file__).parent / "samples" / "phishing_example.eml").read_bytes()


def rule_ids(email: ParsedEmail) -> set[str]:
    return {f.rule_id for f in auth.analyze(email)}


def test_sample_flags_dmarc_spf_and_missing_dkim():
    assert rule_ids(parse_email(SAMPLE)) == {"AUTH-001", "AUTH-003", "AUTH-009"}


def test_all_pass_gives_no_findings():
    email = ParsedEmail(authentication_results=[
        "mx.example.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass"
    ])
    assert rule_ids(email) == set()


def test_injected_lower_header_is_ignored():
    # The attacker adds a fake "everything passed" header; ours (the first one) says fail.
    email = ParsedEmail(authentication_results=[
        "mx.example.com; spf=fail; dkim=none; dmarc=fail",
        "fake.attacker; spf=pass; dkim=pass; dmarc=pass",
    ])
    assert "AUTH-001" in rule_ids(email)


def test_one_valid_dkim_signature_is_enough():
    email = ParsedEmail(authentication_results=["mx; dkim=fail header.d=a.com; dkim=pass header.d=b.com"])
    assert rule_ids(email) == set()


def test_no_header_gives_no_findings():
    assert rule_ids(ParsedEmail()) == set()
