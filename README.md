# 🛡️ Phishing URL Detector

A real-time phishing URL detection system powered by Machine Learning, built as a Final Year Project in Cybersecurity.

---

## ⚙️ Live on

Open `http://localhost:5000` in your browser.

---

## 📌 Project Overview

Phishing attacks account for over 90% of data breaches worldwide. This system uses an ensemble of **XGBoost + Random Forest** classifiers to analyse URLs and detect phishing attempts in real-time with **92%+ accuracy**.

The system uses a **3-tier feature extraction pipeline**:
- **Tier 1 — Lexical Analysis**: URL structure, entropy, consonant ratio, suspicious keywords (instant, no network)
- **Tier 2 — Host Analysis**: DNS resolution, WHOIS domain age (1–2s)
- **Tier 3 — Page Analysis**: HTML forms, password fields, redirects (3–5s)

---

## 🚀 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| ML Models | XGBoost, Random Forest (Scikit-learn) |
| Feature Extraction | tldextract, python-whois, BeautifulSoup4 |
| Frontend | HTML, CSS, JavaScript |
| Dataset | 583,000+ URLs (Kaggle + Synthetic) |
| Deployment | Gunicorn |

---

## 🔍 Features

- ✅ Real-time URL analysis
- ✅ 35+ features extracted per URL
- ✅ Shannon entropy detection (catches gibberish domains)
- ✅ Consonant ratio analysis (detects random domains)
- ✅ DNS / WHOIS domain age verification
- ✅ Page content scanning (forms, password fields)
- ✅ Ensemble ML model (XGBoost + Random Forest)
- ✅ Detailed analysis report with risk breakdown
- ✅ Flagged signals with plain English explanations
- ✅ Batch URL prediction API

---
