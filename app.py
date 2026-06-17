"""
app.py — Flask backend for Phishing URL Detector.

Run:
    python app.py
"""

import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from model.predict import predict_url

app = Flask(__name__)
CORS(app)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL is empty"}), 400

    # Basic URL validation
    if len(url) < 4:
        return jsonify({"error": "Please enter a valid URL"}), 400

    if "." not in url and not url.startswith("http"):
        return jsonify({"error": "Please enter a valid URL (e.g. https://example.com)"}), 400

    try:
        result = predict_url(
            url,
            include_host=data.get("include_host", False),
            include_page=data.get("include_page", False),
        )
        return jsonify(result)  
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    data = request.get_json()

    if not data or "urls" not in data:
        return jsonify({"error": "No URLs provided"}), 400

    urls = data["urls"]
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "urls must be a non-empty list"}), 400

    if len(urls) > 50:
        return jsonify({"error": "Maximum 50 URLs per batch"}), 400

    results = [predict_url(u.strip()) for u in urls]
    return jsonify({"results": results, "count": len(results)})


@app.route("/report")
def report():
    return render_template("report.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)