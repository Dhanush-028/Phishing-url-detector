"""
predict.py — Load trained models and run inference on a single URL.
"""
import os
import pickle
import time
import sys

import numpy as np
import pandas as pd
import tldextract

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.feature_extractor import extract_features

MODEL_DIR = os.path.dirname(__file__)


# ---------------------------------------------------------------------------
# Load artefacts once at import time (not on every request)
# ---------------------------------------------------------------------------

def _load(filename):
    path = os.path.join(MODEL_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found: {path}\n"
            "Run  python -m model.train --data data/dataset.csv  first."
        )
    with open(path, "rb") as f:
        return pickle.load(f)


_ensemble      = None
_xgb           = None
_rf            = None
_scaler        = None
_feature_names = None


def _ensure_loaded():
    global _ensemble, _xgb, _rf, _scaler, _feature_names
    if _ensemble is None:
        _ensemble      = _load("ensemble_model.pkl")
        _xgb           = _load("xgb_model.pkl")
        _rf            = _load("rf_model.pkl")
        _scaler        = _load("scaler.pkl")
        _feature_names = _load("feature_names.pkl")


# ---------------------------------------------------------------------------
# Risk level helper
# ---------------------------------------------------------------------------

def _risk_level(prob: float) -> dict:
    if prob >= 0.80:
        return {"level": "High",   "color": "#E53E3E", "emoji": "🔴"}
    elif prob >= 0.65:
        return {"level": "Medium", "color": "#DD6B20", "emoji": "🟠"}
    elif prob >= 0.40:
        return {"level": "Low",    "color": "#D69E2E", "emoji": "🟡"}
    else:
        return {"level": "Safe",   "color": "#38A169", "emoji": "🟢"}


# ---------------------------------------------------------------------------
# Top contributing features
# ---------------------------------------------------------------------------

def _top_features(features: dict, n: int = 5) -> list:
    safe_baseline = {
        "url_length": 30, "num_dots": 2, "num_hyphens": 0,
        "subdomain_depth": 0, "has_ip_hostname": 0, "has_at_sign": 0,
        "is_shortener": 0, "has_suspicious_keyword": 0,
        "suspicious_keyword_count": 0, "has_hex_encoding": 0,
        "has_punycode": 0, "digit_ratio": 0.05, "uses_https": 1,
        "has_dash_in_domain": 0, "has_double_slash_in_path": 0,
    }

    flags = []
    for feat, val in features.items():
        if feat not in safe_baseline:
            continue
        baseline = safe_baseline[feat]
        if abs(val - baseline) > 0:
            flags.append({
                "feature": feat.replace("_", " ").title(),
                "value": val,
                "suspicious": True,
            })

    flags.sort(key=lambda x: (int(x["value"] in [1, True]), x["value"]), reverse=True)
    return flags[:n]


# ---------------------------------------------------------------------------
# Main predict function
# ---------------------------------------------------------------------------

def predict_url(url: str, include_host: bool = True, include_page: bool = False) -> dict:

    _ensure_loaded()
    t0 = time.time()

    if "://" not in url:
     url = "http://" + url

    # 1. Extract features
    features = extract_features(url, include_host=include_host, include_page=include_page)

    features.pop("uses_https", None)

    # 2. Align to training feature order
    row = pd.DataFrame([features]).reindex(columns=_feature_names, fill_value=0)

    # 3. Scale
    row_sc = _scaler.transform(row)

    # 4. Individual model probabilities
    xgb_prob = float(_xgb.predict_proba(row_sc)[0][1])
    rf_prob  = float(_rf.predict_proba(row_sc)[0][1])

    # 5. Ensemble probability
    ens_prob = float(_ensemble.predict_proba(row_sc)[0][1])
    label    = "Phishing" if ens_prob >= 0.80 else "Legitimate"

    # 6. Explainability
    top_feats = _top_features(features)

    latency = round((time.time() - t0) * 1000, 1)

    return {
        "url":           url,
        "label":         label,
        "is_phishing":   label == "Phishing",
        "confidence":    round(ens_prob, 4),
        "xgb_prob":      round(xgb_prob, 4),
        "rf_prob":       round(rf_prob, 4),
        "risk":          _risk_level(ens_prob),
        "top_features":  top_feats,
        "features":      features,
        "latency_ms":    latency,
    }


# ---------------------------------------------------------------------------
# Batch prediction
# ---------------------------------------------------------------------------

def predict_batch(urls: list) -> list:
    return [predict_url(u) for u in urls]


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://claude.ai",
        "http://paypa1-secure-login.com/verify?user=test@gmail.com",
        "http://192.168.1.1/admin/login",
        "https://bit.ly/3xYzAbC",
    ]

    print(f"\n{'URL':<55} {'Label':<12} {'Confidence':>10}  {'Risk':<8}")
    print("-" * 90)

    for url in test_urls:
        r = predict_url(url)
        print(
            f"{url[:54]:<55} "
            f"{r['label']:<12} "
            f"{r['confidence']:>10.4f}  "
            f"{r['risk']['emoji']} {r['risk']['level']:<6}"
        )