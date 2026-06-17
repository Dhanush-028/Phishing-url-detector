"""
train.py — Train XGBoost + Random Forest ensemble on phishing URL dataset.

Expected CSV columns:
    url     : raw URL string
    label   : 1 = phishing, 0 = legitimate

Run:
    python model/train.py --data data/dataset.csv
"""

import argparse
import os
import pickle
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                              roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.feature_extractor import extract_features, LEXICAL_FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(__file__))


# ---------------------------------------------------------------------------
# 1. Feature extraction over dataset
# ---------------------------------------------------------------------------

def build_feature_matrix(df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
    """Extract lexical features for every URL in the dataframe."""
    print(f"Extracting features for {len(df)} URLs (lexical only)...")
    rows = []
    for i, url in enumerate(df[url_col], 1):
        try:
            feats = extract_features(str(url), include_host=False, include_page=False)
        except Exception:
            feats = {k: 0 for k in LEXICAL_FEATURE_NAMES}
        rows.append(feats)
        if i % 1000 == 0:
            print(f"  {i}/{len(df)}")
    df_features = pd.DataFrame(rows)
    # Drop uses_https — HTTPS alone is misleading, phishing sites use it too
    if "uses_https" in df_features.columns:
        df_features = df_features.drop(columns=["uses_https"])
    return df_features


# ---------------------------------------------------------------------------
# 2. Model definitions
# ---------------------------------------------------------------------------

def build_models():
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=4,
        class_weight="balanced",    # handles class imbalance
        random_state=42,
        n_jobs=-1,
    )

    # Soft voting: average predicted probabilities
    ensemble = VotingClassifier(
        estimators=[("xgb", xgb), ("rf", rf)],
        voting="soft",
        weights=[0.6, 0.4],         # XGBoost slightly favoured
    )

    return xgb, rf, ensemble


# ---------------------------------------------------------------------------
# 3. Evaluation helpers
# ---------------------------------------------------------------------------

def evaluate(name: str, model, X_test, y_test):
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print(f"\n{'='*50}")
    print(f" {name}")
    print(f"{'='*50}")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion matrix  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  ROC-AUC           {roc_auc_score(y_test, y_proba):.4f}")


# ---------------------------------------------------------------------------
# 4. Main training pipeline
# ---------------------------------------------------------------------------

def train(data_path: str, test_size: float = 0.2):

    # ---- Load data ----
    print(f"\nLoading dataset: {data_path}")
    df = pd.read_csv(data_path)

    # Normalise column names — common variants in public datasets
    df.columns = df.columns.str.strip().str.lower()
    if "result" in df.columns and "label" not in df.columns:
        df.rename(columns={"result": "label"}, inplace=True)
    if "phishing" in df.columns and "label" not in df.columns:
        df.rename(columns={"phishing": "label"}, inplace=True)

    assert "url"   in df.columns, "CSV must have a 'url' column"
    assert "label" in df.columns, "CSV must have a 'label' column (1=phishing, 0=legit)"

    # Map -1 → 0 (some UCI variants use -1 for legitimate)
    df["label"] = df["label"].replace(-1, 0).astype(int)

    print(f"  Total samples : {len(df)}")
    print(f"  Phishing      : {df['label'].sum()} ({df['label'].mean()*100:.1f}%)")
    print(f"  Legitimate    : {(df['label']==0).sum()}")

    # ---- Feature extraction ----
    X = build_feature_matrix(df, url_col="url")
    y = df["label"].values

    # ---- Train / test split ----
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    print(f"\nTrain size: {len(X_train)}  |  Test size: {len(X_test)}")

    # ---- Scale (needed mainly for RF, won't hurt XGB) ----
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # ---- Build & fit models ----
    xgb, rf, ensemble = build_models()

    print("\nTraining XGBoost...")
    xgb.fit(X_train_sc, y_train)

    print("Training Random Forest...")
    rf.fit(X_train_sc, y_train)

    print("Training ensemble (soft voting)...")
    ensemble.fit(X_train_sc, y_train)

    # ---- Evaluate ----
    evaluate("XGBoost",       xgb,      X_test_sc, y_test)
    evaluate("Random Forest", rf,       X_test_sc, y_test)
    evaluate("Ensemble",      ensemble, X_test_sc, y_test)

    # ---- Cross-validation on full data ----
    print("\nRunning 5-fold CV on ensemble (this takes a moment)...")
    X_all_sc = scaler.transform(X)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(ensemble, X_all_sc, y, cv=cv, scoring="f1", n_jobs=-1)
    print(f"  CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ---- Feature importance (XGBoost) ----
    importances = pd.Series(
        xgb.feature_importances_, index=X.columns
    ).sort_values(ascending=False)
    print("\nTop 10 features (XGBoost):")
    print(importances.head(10).to_string())

    # ---- Save artefacts ----
    os.makedirs(MODEL_DIR, exist_ok=True)

    with open(os.path.join(MODEL_DIR, "xgb_model.pkl"), "wb") as f:
        pickle.dump(xgb, f)

    with open(os.path.join(MODEL_DIR, "rf_model.pkl"), "wb") as f:
        pickle.dump(rf, f)

    with open(os.path.join(MODEL_DIR, "ensemble_model.pkl"), "wb") as f:
        pickle.dump(ensemble, f)

    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)

    # Save feature column order — predict.py must use same order
    with open(os.path.join(MODEL_DIR, "feature_names.pkl"), "wb") as f:
        pickle.dump(list(X.columns), f)

    print("\nSaved:")
    for fname in ["xgb_model.pkl", "rf_model.pkl", "ensemble_model.pkl",
                  "scaler.pkl", "feature_names.pkl"]:
        path = os.path.join(MODEL_DIR, fname)
        print(f"  {path}")

    print("\nTraining complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train phishing URL detector")
    parser.add_argument("--data",      default="data/dataset.csv",
                        help="Path to CSV with 'url' and 'label' columns")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fraction of data for test set (default: 0.2)")
    args = parser.parse_args()

    train(data_path=args.data, test_size=args.test_size)