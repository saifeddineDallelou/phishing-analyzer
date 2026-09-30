import pytest

from app.analyzers.urls import analyze, analyze_link, edit_distance, registrable_domain
from app.models import Link, ParsedEmail


def ids(href: str, text: str = "") -> set[str]:
    return {f.rule_id for f in analyze_link(Link(href=href, text=text))}


# The 10 URLs from Exercise 4
@pytest.mark.parametrize("href, expected", [
    ("https://www.paypal.com.account-security.xyz/login", {"URL-006"}),
    ("https://paypal.com@198.51.100.7/verify", {"URL-003", "URL-002"}),
    ("https://login.microsoftonline.com/common/oauth2/authorize", set()),
    ("https://xn--pypal-4ve.com/signin", {"URL-004", "URL-005"}),
    ("https://accounts.google.com.evil.co.uk/", {"URL-006"}),
    ("https://secure-paypal-verify.com/update", {"URL-007"}),
    ("https://www.google.com/url?q=https://evil.xyz/login", {"URL-009"}),
    ("https://paypa1.com/", {"URL-005"}),
    ("https://docs.google.com/forms/d/e/1FAIpQL/viewform", set()),  # known limitation: needs content analysis
    ("http://192.0.2.10:8080/office365/", {"URL-002", "URL-010"}),
])
def test_exercise_urls(href, expected):
    assert ids(href) == expected


@pytest.mark.parametrize("href", [
    "https://www.purchase.com/",        # contains "chase"-like substrings: whole-word matching avoids this
    "https://pineapple.com/",           # contains "apple"
    "https://amazing-deals.com/",       # 2 edits from "amazon"
    "https://www.paypal.com/signin",
    "https://user.github.io/page",      # private suffix: owner is user.github.io, not github
    "mailto:someone@example.com",
])
def test_no_false_positive(href):
    assert ids(href) == set()


def test_link_text_lies():
    assert "URL-001" in ids("http://paypa1-verify.xyz/login", text="https://www.paypal.com/signin")


def test_link_text_not_a_url_is_ignored():
    assert "URL-001" not in ids("https://evil.xyz/", text="Click here")


def test_registrable_domain():
    assert registrable_domain("accounts.google.com.evil.co.uk") == "evil.co.uk"
    assert registrable_domain("user.github.io") == "user.github.io"


def test_edit_distance():
    assert edit_distance("paypal", "paypa1") == 1
    assert edit_distance("paypal", "paypall") == 1
    assert edit_distance("paypal", "google") == 6
    assert edit_distance("esprit", "espirt") == 1  # swapped neighbours = 1 edit
    assert edit_distance("paypal", "paypla") == 1


def test_swapped_letters_lookalike():
    assert ids("https://paypla.com/") == {"URL-005"}


def test_each_rule_reported_once_per_email():
    email = ParsedEmail(links=[Link(href=f"https://bit.ly/{i}") for i in range(5)])
    assert [f.rule_id for f in analyze(email)] == ["URL-008"]
