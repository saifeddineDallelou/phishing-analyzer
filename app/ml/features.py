"""Turn an analyzed email into a row of numbers the model can learn from.

Most features are our own rules (1 if the rule fired, 0 if not), so the model stays
explainable: it learns how much to trust each rule instead of reading raw text.

Deliberately NOT features:
- INTEL-*: threat intel answers change over time and training on old datasets would
  query today's reputation of years-old IOCs (and burn API quota).
- ORG-*: they depend on one customer's profile, not on phishing in general.
"""
import math
import re
from urllib.parse import urlsplit

from app.models import Finding, ParsedEmail

RULE_FEATURES = [
    "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006", "AUTH-007", "AUTH-008", "AUTH-009",
    "HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005", "HDR-006",
    "URL-000", "URL-001", "URL-002", "URL-003", "URL-004", "URL-005", "URL-006", "URL-007", "URL-008",
    "URL-009", "URL-010",
    "ATT-001", "ATT-002", "ATT-003", "ATT-004", "ATT-005", "ATT-006", "ATT-007",
]
EXCLUDED_PREFIXES = ("INTEL-", "ORG-")

# Social-engineering vocabulary: urgency, fear, account problems (English and French).
PRESSURE_WORDS = re.compile(
    r"\b(urgent|immediately|verify|verification|suspend(ed)?|locked|limited|unusual|confirm|password|"
    r"login|log in|sign in|account|invoice|payment|expire[sd]?|security alert|"
    r"urgence|vérifie[rz]?|suspendu|bloqué|mot de passe|connexion|compte|facture|paiement)\b",
    re.IGNORECASE)

NUMERIC_FEATURES = ["log_link_count", "log_distinct_link_domains", "log_attachment_count",
                    "html_only", "log_body_length", "pressure_words"]
FEATURE_NAMES = RULE_FEATURES + NUMERIC_FEATURES


def _link_domains(email: ParsedEmail) -> set[str]:
    domains = set()
    for link in email.links:
        try:
            host = urlsplit(link.href).hostname
        except ValueError:
            continue
        if host:
            domains.add(host.lower())
    return domains


def extract_features(email: ParsedEmail, findings: list[Finding]) -> list[float]:
    """One row of numbers, always in the order of FEATURE_NAMES."""
    fired = {f.rule_id for f in findings}
    rules = [1.0 if rule in fired else 0.0 for rule in RULE_FEATURES]

    text = f"{email.subject}\n{email.text_body or email.html_body}"
    numeric = [
        math.log1p(len(email.links)),            # log: 1 vs 10 links matters more than 101 vs 110
        math.log1p(len(_link_domains(email))),
        math.log1p(len(email.attachments)),
        1.0 if email.html_body and not email.text_body.strip() else 0.0,
        math.log1p(len(text)),
        float(min(len(PRESSURE_WORDS.findall(text)), 10)),  # capped: one email can't dominate
    ]
    return rules + numeric
