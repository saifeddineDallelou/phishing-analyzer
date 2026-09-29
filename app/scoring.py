"""Combine findings into a score and a verdict.

For now this is purely rule-based. In weeks 5-6 you'll add a scikit-learn model
and blend its probability with this rule score.
"""
from app.models import Finding, Verdict

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 60


def score(findings: list[Finding]) -> tuple[int, Verdict]:
    total = min(100, sum(f.score for f in findings))
    if total >= MALICIOUS_THRESHOLD:
        return total, Verdict.malicious
    if total >= SUSPICIOUS_THRESHOLD:
        return total, Verdict.suspicious
    return total, Verdict.clean
