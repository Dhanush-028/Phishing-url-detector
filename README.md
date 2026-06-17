# 🛡️ Phishing URL Detector

A real-time phishing URL detection system powered by Machine Learning, built a simple Project in Cybersecurity.

---

## ⚙️ Live on

Open (https://phishing-url-detector-c6wb.onrender.com) in your browser.

---

## 📌 Project Overview

Phishing URL Detector is a Machine Learning-based cybersecurity system that identifies potentially malicious URLs in real time. The system uses an ensemble of XGBoost and Random Forest classifiers trained on over 580,000 URLs to distinguish phishing websites from legitimate websites.

The detector performs lexical URL analysis by extracting features such as:

* URL length
* Number of dots and hyphens
* Subdomain depth
* Presence of suspicious keywords
* IP-based hostnames
* Punycode and encoded URLs
* Digit and character patterns

The system provides:

* Real-time phishing detection
* Risk score estimation
* Confidence analysis
* Detailed security reports
* Browser extension integration
* Cloud deployment using Flask and Render

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
