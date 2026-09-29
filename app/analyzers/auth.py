"""SPF / DKIM / DMARC checks, based on the receiving server's Authentication-Results header.

Step 1 (this file): trust the verdict our own mail server already wrote.
Step 2 (later): verify DKIM ourselves with `dkimpy` and look up SPF/DMARC records.
"""
import re

from app.models import Finding, ParsedEmail, Severity

# Matches "spf=fail", "dkim=none", "dmarc=pass" ... and captures (mechanism, result).
RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

# (mechanism, result) -> (rule_id, severity, score, explanation)
# Results not listed here (pass, temperror, ...) produce no finding.
RULES = {
    ("dmarc", "fail"): ("AUTH-001", Severity.high, 35,
                        "DMARC failed: nothing authenticated the visible From domain (likely spoofed)"),
    ("dmarc", "none"): ("AUTH-002", Severity.low, 5,
                        "Sender domain publishes no DMARC policy"),
    ("spf", "fail"): ("AUTH-003", Severity.medium, 15,
                      "SPF failed: the sending server is not authorized by the envelope domain"),
    ("spf", "softfail"): ("AUTH-004", Severity.low, 10,
                          "SPF softfail: the sending server is probably not authorized"),
    ("spf", "neutral"): ("AUTH-005", Severity.low, 5,
                         "SPF neutral: the envelope domain gives no opinion on this server"),
    ("spf", "none"): ("AUTH-006", Severity.low, 5,
                      "Envelope domain publishes no SPF record"),
    ("spf", "permerror"): ("AUTH-007", Severity.low, 5,
                           "Envelope domain's SPF record is broken (permerror)"),
    ("dkim", "fail"): ("AUTH-008", Severity.medium, 15,
                       "DKIM signature is invalid: message altered or signature forged"),
    ("dkim", "none"): ("AUTH-009", Severity.low, 5,
                       "Message is not DKIM-signed"),
}


def parse_results(header: str) -> dict[str, list[str]]:
    """'spf=fail ...; dkim=pass ...; dkim=fail ...' -> {'spf': ['fail'], 'dkim': ['pass', 'fail']}"""
    results: dict[str, list[str]] = {}
    for mechanism, result in RESULT_RE.findall(header):
        results.setdefault(mechanism.lower(), []).append(result.lower())
    return results


def analyze(email: ParsedEmail) -> list[Finding]:
    if not email.authentication_results:
        return []

    # Servers add headers at the TOP, so the first one is from our own server.
    # Lower ones may have been written by the attacker and must be ignored.
    results = parse_results(email.authentication_results[0])

    findings = []
    for mechanism in ("spf", "dkim", "dmarc"):
        values = results.get(mechanism)
        if not values:
            continue
        # An email can carry several DKIM signatures; one valid signature is enough.
        result = "pass" if "pass" in values else values[0]
        rule = RULES.get((mechanism, result))
        if rule:
            rule_id, severity, score, text = rule
            findings.append(Finding(
                rule_id=rule_id,
                description=f"{text} ({mechanism}={result})",
                severity=severity,
                score=score,
                mitre="T1566",
            ))
    return findings
