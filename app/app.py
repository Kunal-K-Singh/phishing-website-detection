import os
import warnings
from flask import Flask, render_template, request, jsonify
import joblib

# Suppress version mismatch warnings during unpickling
warnings.filterwarnings("ignore", category=UserWarning)

# Support running directly or as module
try:
    from app.utils import validate_url, normalize_url, is_trusted_root_domain, extract_url_features
except ImportError:
    from utils import validate_url, normalize_url, is_trusted_root_domain, extract_url_features

# --------------------------------------------------
# Initialize Flask Application
# --------------------------------------------------

app = Flask(__name__)

# --------------------------------------------------
# Load Machine Learning Model and Vectorizer
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "..", "models", "vectorizer.pkl")

model = None
vectorizer = None

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    print("Machine Learning Model Loaded Successfully!")
    print("CountVectorizer Loaded Successfully!")
except Exception as e:
    print("Error Loading Model/Vectorizer Files:", e)


# --------------------------------------------------
# Prediction Function
# --------------------------------------------------

def predict_url(raw_url: str) -> dict:
    """
    Analyzes a URL using lexical heuristics and the trained ML model.
    Returns a dictionary containing classification, confidence, and features.
    """
    raw_url = raw_url.strip()
    norm_url = normalize_url(raw_url)
    features = extract_url_features(raw_url)
    is_trusted = is_trusted_root_domain(raw_url)
    
    # Vectorize normalized URL
    url_vector = vectorizer.transform([norm_url])
    
    # Probability distribution: [P(Legitimate), P(Phishing)]
    probabilities = model.predict_proba(url_vector)[0]
    p_legit = float(probabilities[0])
    p_phish = float(probabilities[1])
    
    # Safe domain adjustment for known major platforms
    if is_trusted:
        p_phish = min(p_phish, 0.05)
        p_legit = 1.0 - p_phish
    
    # Strong heuristic override for raw IP phishing
    if features["has_ip"] and not is_trusted:
        p_phish = max(p_phish, 0.95)
        p_legit = 1.0 - p_phish
        
    # Heuristic override for unauthorized brand spoofing
    if features.get("is_brand_spoofed") and not is_trusted:
        p_phish = max(p_phish, 0.88)
        p_legit = 1.0 - p_phish
        
    # Heuristic balance: If a URL has 0 structural risk flags, dampen borderline
    # statistical false positives (50%-65%) caused by historical n-gram dataset drift
    if (
        not is_trusted
        and features.get("heuristic_risk_score", 0) == 0
        and not features.get("is_brand_spoofed")
        and not features.get("has_ip")
        and not features.get("suspicious_tld")
        and features.get("hyphen_count", 0) == 0
        and features.get("dot_count", 0) <= 2
        and features.get("length", 0) <= 35
    ):
        if 0.50 <= p_phish < 0.65:
            p_phish = 0.35
            p_legit = 0.65
            
    is_phishing = p_phish >= 0.50
    
    if is_phishing:
        status = "Phishing Website"
        result_color = "#DC2626"      # Danger Red
        confidence = round(p_phish * 100, 1)
        risk_level = "High Risk"
    else:
        status = "Legitimate Website"
        result_color = "#16A34A"      # Safe Green
        confidence = round(p_legit * 100, 1)
        risk_level = "Safe / Low Risk"
        
    return {
        "url": raw_url,
        "normalized_url": norm_url,
        "prediction": status,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "p_legit": round(p_legit * 100, 1),
        "p_phish": round(p_phish * 100, 1),
        "result_color": result_color,
        "risk_level": risk_level,
        "features": features
    }


# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    user_url = request.form.get("url", "").strip()
    
    # URL Validation
    is_valid, error_msg = validate_url(user_url)
    if not is_valid:
        return render_template(
            "index.html",
            entered_url=user_url,
            error=f"\u26a0 {error_msg}"
        )
        
    if model is None or vectorizer is None:
        return render_template(
            "index.html",
            entered_url=user_url,
            error="\u26a0 ML Model not loaded on server. Please check model files."
        )
        
    analysis = predict_url(user_url)
    
    return render_template(
        "index.html",
        entered_url=user_url,
        prediction=analysis["prediction"],
        confidence=analysis["confidence"],
        p_legit=analysis["p_legit"],
        p_phish=analysis["p_phish"],
        result_color=analysis["result_color"],
        risk_level=analysis["risk_level"],
        features=analysis["features"],
        normalized_url=analysis["normalized_url"]
    )


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """REST API endpoint returning JSON prediction."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", request.form.get("url", "")).strip()
    
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400
        
    if model is None or vectorizer is None:
        return jsonify({"success": False, "error": "Model not available"}), 500
        
    analysis = predict_url(url)
    analysis["success"] = True
    return jsonify(analysis)


# --------------------------------------------------
# Run Flask Application
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
