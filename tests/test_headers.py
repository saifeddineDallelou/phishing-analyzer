import pytest

from app.analyzers.headers import analyze
from app.models import ParsedEmail

DEFAULTS = {"date": "Mon, 28 Sep 2026 09:12:00 +0000", "message_id": "<1@example.com>"}


def ids(**fields) -> set[str]:
    return {f.rule_id for f in analyze(ParsedEmail(**{**DEFAULTS, **fields}))}


# Exercise 6, Q1
@pytest.mark.parametrize("sender, expected", [
    ('"PayPal" <service@paypal.com>', set()),
    ('"PayPal" <paypal.support.team@gmail.com>', {"HDR-002"}),
    ('"service@paypal.com" <x7@mailer-bulk.ru>', {"HDR-002", "HDR-003"}),
    ('"Direction ESPRIT" <direction.esprit2026@outlook.fr>', set()),  # needs a VIP list: known limitation
    ('"Amazon Web Services" <no-reply@amazonaws.com>', set()),
])
def test_exercise_senders(sender, expected):
    assert ids(from_=sender) == expected


def test_brand_on_non_official_domain():
    assert ids(from_='"Microsoft 365" <admin@m365-alerts.xyz>') == {"HDR-002"}


def test_split_brand_name_still_matches():
    assert ids(from_='"Pay Pal Service" <a@evil.xyz>') == {"HDR-002"}


def test_brand_subdomain_is_official():
    assert ids(from_='"PayPal" <noreply@mail.paypal.com>') == set()


def test_free_webmail_scores_higher():
    finding = analyze(ParsedEmail(**DEFAULTS, from_='"PayPal" <pp@gmail.com>'))[0]
    assert finding.score == 35


def test_same_address_in_display_name_is_fine():
    assert ids(from_='"bob@shop.com" <bob@shop.com>') == set()


def test_missing_date_and_message_id():
    finding = analyze(ParsedEmail(from_="a@b.com"))[0]
    assert finding.rule_id == "HDR-004"
    assert "Date" in finding.description and "Message-ID" in finding.description


@pytest.mark.parametrize("fields, score", [
    ({"header_names": ["From", "X-Gophish-Contact"]}, 30),
    ({"mailer": "gophish"}, 30),
    ({"mailer": "PHPMailer 6.8.0"}, 5),
])
def test_mailer_fingerprints(fields, score):
    findings = analyze(ParsedEmail(**DEFAULTS, from_="a@b.com", **fields))
    assert [(f.rule_id, f.score) for f in findings] == [("HDR-005", score)]


def test_normal_mailer_not_flagged():
    assert ids(from_="a@b.com", mailer="Microsoft Outlook 16.0") == set()


def test_homoglyph_display_name():
    # Cyrillic "а" (U+0430) inside "PayPal"
    assert "HDR-006" in ids(from_='"PаyPal" <a@evil.xyz>')


def test_fully_non_latin_name_is_fine():
    # A real Russian name is not a homoglyph trick
    assert ids(from_='"Иван Петров" <ivan@example.ru>') == set()


def test_reply_to_mismatch_still_works():
    assert ids(from_="a@shop.com", reply_to="b@other.com") == {"HDR-001"}
