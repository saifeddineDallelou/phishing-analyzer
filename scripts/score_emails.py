"""Score every email in a folder with a trained model, to see how it behaves on new data.

    python -m scripts.score_emails data/modern_legit --model data/model_all.json
"""
import argparse
import json
from pathlib import Path

from app.analyzers import attachments, auth, headers, urls
from app.ml.dataset import iter_raw_emails
from app.ml.model import phishing_probability
from app.parser import parse_email

RULE_ANALYZERS = [auth, headers, urls, attachments]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))

    for raw in iter_raw_emails(args.folder):
        email = parse_email(raw)
        findings = [f for analyzer in RULE_ANALYZERS for f in analyzer.analyze(email)]
        probability = phishing_probability(email, findings, model)
        rules = ", ".join(sorted({f.rule_id for f in findings})) or "none"
        print(f"{probability:6.1%}  {email.subject[:55]:55}  rules: {rules}")


if __name__ == "__main__":
    main()
