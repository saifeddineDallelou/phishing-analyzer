"""Use the trained model inside the app.

The model is stored as plain JSON (feature names, weights, scaling), NOT as a pickle file:
loading a pickle runs code, so a tampered model file would mean code execution on our
server (CWE-502). JSON can only ever be data. It also needs no scikit-learn at runtime.
"""
import json
import logging
import math
import os
from functools import lru_cache
from pathlib import Path

from app.ml.features import FEATURE_NAMES, extract_features
from app.models import Finding, ParsedEmail

log = logging.getLogger(__name__)
DEFAULT_MODEL = Path(__file__).resolve().parent.parent.parent / "models" / "phishing_model.json"


@lru_cache
def load_model() -> dict | None:
    path = Path(os.environ.get("ML_MODEL", DEFAULT_MODEL))
    if not path.exists():
        log.warning("No ML model at %s: ML scoring disabled", path)
        return None
    model = json.loads(path.read_text(encoding="utf-8"))
    if model["features"] != FEATURE_NAMES:
        # Trained with another feature list: its weights would be applied to the wrong columns.
        log.error("ML model features don't match this code version: retrain it. ML scoring disabled")
        return None
    return model


def phishing_probability(email: ParsedEmail, findings: list[Finding], model: dict | None = None) -> float | None:
    """Logistic regression by hand: sigmoid(intercept + sum(weight * scaled feature))."""
    model = model or load_model()
    if model is None:
        return None
    row = extract_features(email, findings)
    z = model["intercept"]
    for value, weight, mean, scale in zip(row, model["coef"], model["mean"], model["scale"]):
        z += weight * (value - mean) / scale
    return 1 / (1 + math.exp(-max(-35.0, min(35.0, z))))
