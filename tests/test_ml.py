import json
import re
from pathlib import Path

import pytest

from app.ml import model as ml_model
from app.ml.dataset import iter_raw_emails
from app.ml.features import EXCLUDED_PREFIXES, FEATURE_NAMES, RULE_FEATURES, extract_features
from app.models import Finding, Link, ParsedEmail, Severity

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def finding(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, description="x", severity=Severity.high, score=10)


def test_every_rule_in_the_code_is_a_feature():
    """Guard: adding a rule without adding it to RULE_FEATURES would silently hide it from the model."""
    in_code = set()
    for path in APP_DIR.rglob("*.py"):
        in_code |= set(re.findall(r'"((?:AUTH|HDR|ORG|URL|ATT|INTEL)-\d{3})"', path.read_text(encoding="utf-8")))
    expected = {r for r in in_code if not r.startswith(EXCLUDED_PREFIXES)}
    assert expected == set(RULE_FEATURES)


def test_feature_row_matches_names():
    email = ParsedEmail(subject="URGENT: verify your account", text_body="Your password expired",
                        links=[Link(href="http://a.xyz/1"), Link(href="http://a.xyz/2"), Link(href="http://b.xyz/")])
    row = extract_features(email, [finding("URL-001"), finding("INTEL-001")])
    named = dict(zip(FEATURE_NAMES, row))
    assert len(row) == len(FEATURE_NAMES)
    assert named["URL-001"] == 1.0 and named["AUTH-001"] == 0.0
    assert named["pressure_words"] == 5.0  # urgent, verify, account, password, expired
    assert "INTEL-001" not in named


def toy_model(weight_on: str, weight: float) -> dict:
    coef = [weight if name == weight_on else 0.0 for name in FEATURE_NAMES]
    return {"features": FEATURE_NAMES, "coef": coef, "intercept": 0.0,
            "mean": [0.0] * len(FEATURE_NAMES), "scale": [1.0] * len(FEATURE_NAMES)}


def test_probability_follows_the_weights():
    model = toy_model("URL-001", 4.0)
    with_rule = ml_model.phishing_probability(ParsedEmail(), [finding("URL-001")], model)
    without = ml_model.phishing_probability(ParsedEmail(), [], model)
    assert with_rule == pytest.approx(1 / (1 + 2.718281828 ** -4), rel=1e-6)
    assert without == pytest.approx(0.5)


def test_model_with_other_features_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "model.json"
    path.write_text(json.dumps({**toy_model("URL-001", 1.0), "features": ["something", "else"]}))
    monkeypatch.setenv("ML_MODEL", str(path))
    ml_model.load_model.cache_clear()
    try:
        assert ml_model.load_model() is None
    finally:
        ml_model.load_model.cache_clear()


def test_no_model_means_no_probability(tmp_path, monkeypatch):
    monkeypatch.setenv("ML_MODEL", str(tmp_path / "missing.json"))
    ml_model.load_model.cache_clear()
    try:
        assert ml_model.phishing_probability(ParsedEmail(), []) is None
    finally:
        ml_model.load_model.cache_clear()


def test_dataset_reads_mbox_and_single_files_without_duplicates(tmp_path):
    (tmp_path / "corpus.mbox").write_bytes(
        b"From a@x Mon Jan  1 00:00:00 2024\nSubject: one\n\nbody 1\n\n"
        b"From b@x Mon Jan  1 00:00:00 2024\nSubject: two\n\nbody 2\n\n")
    (tmp_path / "mine").mkdir()
    (tmp_path / "mine" / "00001.abc").write_bytes(b"Subject: three\n\nbody 3\n")
    (tmp_path / "mine" / "copy.eml").write_bytes(b"Subject: three\n\nbody 3\n")  # duplicate
    (tmp_path / "mine" / "cmds").write_bytes(b"not an email")
    subjects = sorted(raw.split(b"Subject: ")[1].split(b"\n")[0] for raw in iter_raw_emails(tmp_path))
    assert subjects == [b"one", b"three", b"two"]
