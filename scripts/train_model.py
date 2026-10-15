"""Train and evaluate the phishing model on labeled emails.

    python -m scripts.train_model                       # all features
    python -m scripts.train_model --exclude AUTH- HDR-004  # drop features suspected of dataset bias

Reads data/phishing (label 1) and data/legit (label 0), runs our rule analyzers on every
email, trains a logistic regression, prints how good it is and what it learned, and saves
it to models/phishing_model.json.
"""
import argparse
import json
import logging
import time
from datetime import date
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.analyzers import attachments, auth, headers, urls
from app.ml.dataset import iter_raw_emails
from app.ml.features import FEATURE_NAMES, extract_features
from app.parser import parse_email

RULE_ANALYZERS = [auth, headers, urls, attachments]  # no ORG (customer-specific), no intel (online)
ROOT = Path(__file__).resolve().parent.parent


def load(folder: Path, label: int) -> tuple[list[list[float]], list[int]]:
    rows, labels, failed = [], [], 0
    started = time.perf_counter()
    for raw in iter_raw_emails(folder):
        try:
            email = parse_email(raw)
            findings = [f for analyzer in RULE_ANALYZERS for f in analyzer.analyze(email)]
            rows.append(extract_features(email, findings))
            labels.append(label)
        except Exception:  # one malformed email must not stop training on thousands
            failed += 1
    print(f"  {folder}: {len(rows)} emails ({failed} unparseable) "
          f"in {time.perf_counter() - started:.0f}s")
    return rows, labels


def prevalence_table(X: np.ndarray, y: np.ndarray, top: int = 12) -> None:
    """How often each feature fires in each class. A feature at 0% in one class and high in the
    other is either a great signal or a dataset artifact: this is where shortcut learning shows."""
    print("\nFeature prevalence (rules: % of emails where it fired)")
    rule_count = sum(1 for n in FEATURE_NAMES if "-" in n)
    rows = []
    for i, name in enumerate(FEATURE_NAMES[:rule_count]):
        phish, legit = X[y == 1, i].mean() * 100, X[y == 0, i].mean() * 100
        rows.append((abs(phish - legit), name, phish, legit))
    print(f"  {'feature':10} {'phishing':>9} {'legit':>7}")
    for _, name, phish, legit in sorted(rows, reverse=True)[:top]:
        print(f"  {name:10} {phish:8.1f}% {legit:6.1f}%")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phishing", type=Path, default=ROOT / "data" / "phishing")
    parser.add_argument("--legit", type=Path, default=ROOT / "data" / "legit")
    parser.add_argument("--exclude", nargs="*", default=[], help="feature name prefixes to leave out")
    parser.add_argument("--out", type=Path, default=ROOT / "models" / "phishing_model.json")
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)

    print("Loading and analyzing emails...")
    Xp, yp = load(args.phishing, 1)
    Xl, yl = load(args.legit, 0)
    X, y = np.array(Xp + Xl), np.array(yp + yl)
    if len(set(y)) < 2:
        raise SystemExit("Need both phishing and legitimate emails.")
    prevalence_table(X, y)

    used = [i for i, name in enumerate(FEATURE_NAMES) if not name.startswith(tuple(args.exclude))]
    # Stratified: train and test keep the same phishing/legit ratio. Test set is never seen in training.
    X_train, X_test, y_train, y_test = train_test_split(X[:, used], y, test_size=0.25, stratify=y, random_state=42)

    scaler = StandardScaler().fit(X_train)  # learned on training data only, to avoid leaking test info
    model = LogisticRegression(class_weight="balanced", max_iter=2000)
    model.fit(scaler.transform(X_train), y_train)

    probabilities = model.predict_proba(scaler.transform(X_test))[:, 1]
    predicted = (probabilities >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, predicted).ravel()
    metrics = {
        "test_emails": int(len(y_test)),
        "precision": round(float(precision_score(y_test, predicted)), 4),
        "recall": round(float(recall_score(y_test, predicted)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
        "confusion": {"true_positive": int(tp), "false_negative": int(fn),
                      "false_positive": int(fp), "true_negative": int(tn)},
    }

    print(f"\nTest set ({len(y_test)} emails never seen during training)")
    print(f"  caught phishing (TP): {tp:5}    missed phishing (FN): {fn:5}")
    print(f"  false alarms   (FP): {fp:5}    correct legit  (TN): {tn:5}")
    print(f"  precision {metrics['precision']:.3f} | recall {metrics['recall']:.3f} | "
          f"false positive rate {metrics['false_positive_rate']:.3f} | ROC AUC {metrics['roc_auc']:.3f}")

    names = [FEATURE_NAMES[i] for i in used]
    ranked = sorted(zip(model.coef_[0], names), reverse=True)
    print("\nWhat the model learned (weight on the standardized feature)")
    print("  pushes towards PHISHING:   " + ", ".join(f"{n} {w:+.2f}" for w, n in ranked[:8]))
    print("  pushes towards LEGITIMATE: " + ", ".join(f"{n} {w:+.2f}" for w, n in ranked[-6:][::-1]))

    # Save full-length vectors so the app always reads features in FEATURE_NAMES order.
    # Excluded features get weight 0 (mean 0, scale 1): they simply have no effect.
    coef, mean, scale = [0.0] * len(FEATURE_NAMES), [0.0] * len(FEATURE_NAMES), [1.0] * len(FEATURE_NAMES)
    for j, i in enumerate(used):
        coef[i], mean[i], scale[i] = float(model.coef_[0][j]), float(scaler.mean_[j]), float(scaler.scale_[j])
    args.out.parent.mkdir(exist_ok=True)
    args.out.write_text(json.dumps({
        "model": "logistic_regression",
        "trained_on": {"date": date.today().isoformat(), "phishing": len(yp), "legit": len(yl),
                       "excluded_features": args.exclude},
        "metrics": metrics,
        "features": FEATURE_NAMES,
        "coef": coef, "intercept": float(model.intercept_[0]), "mean": mean, "scale": scale,
    }, indent=2), encoding="utf-8")
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
