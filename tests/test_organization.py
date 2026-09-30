from pathlib import Path

import pytest

from app.analyzers.organization import analyze
from app.models import Link, ParsedEmail
from app.organization import OrganizationProfile, normalize

# Fictional organization, same format as config/organization.example.json
EXAMPLE = Path(__file__).parent.parent / "config" / "organization.example.json"
PROFILE = OrganizationProfile.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))


def ids(**fields) -> set[str]:
    return {f.rule_id for f in analyze(ParsedEmail(**fields), PROFILE)}


def test_normalize():
    assert normalize("Karïm BEN-ALI (Direction)") == ["karim", "ben", "ali", "direction"]


@pytest.mark.parametrize("sender", [
    '"Jane Doe" <jane.doe.director@gmail.com>',
    '"DOE Jane" <jdoe@gmail.com>',          # last name first
    '"J. Doe" <urgent.jd@outlook.fr>',       # initial
    '"Jäne Döe" <jane@evil.xyz>',            # accents
])
def test_vip_from_outside(sender):
    assert "ORG-001" in ids(from_=sender)


def test_vip_free_webmail_scores_higher():
    free = analyze(ParsedEmail(from_='"Jane Doe" <jd@gmail.com>'), PROFILE)[0]
    other = analyze(ParsedEmail(from_='"Jane Doe" <jd@other-company.com>'), PROFILE)[0]
    assert (free.score, other.score) == (40, 35)


def test_vip_from_our_domain_is_fine():
    assert ids(from_='"Jane Doe" <jane.doe@nordhaven.tn>') == set()


def test_single_first_name_does_not_match():
    assert ids(from_='"Jane" <jane@gmail.com>') == set()


@pytest.mark.parametrize("sender, expected", [
    ('"Scolarité" <scolarite.nordhaven@gmail.com>', {"ORG-002"}),               # free webmail
    ('"Direction Nordhaven" <direction@nordhaven-edu.com>', {"ORG-002", "ORG-003"}),  # mentions us
    ('"Direction Générale des Impôts" <contact@impots.gouv.fr>', set()),         # common word, legit sender
])
def test_service_names(sender, expected):
    assert ids(from_=sender) == expected


@pytest.mark.parametrize("fields", [
    {"from_": "info@nordhavne.tn"},                                               # swapped letters
    {"from_": "a@b.com", "reply_to": "direction@nordhaven-tn.com"},              # combosquatting in Reply-To
    {"from_": "a@b.com", "links": [Link(href="https://nordhaven.tn.login-check.xyz/")]},  # subdomain trick
])
def test_lookalike_domains(fields):
    assert "ORG-003" in ids(**fields)


def test_our_real_domain_in_links_is_fine():
    assert ids(from_="it@nordhaven.tn", links=[Link(href="https://portal.nordhaven.tn/login")]) == set()


def test_no_profile_means_no_findings():
    assert analyze(ParsedEmail(from_='"Jane Doe" <jd@gmail.com>'), OrganizationProfile()) == []
