import pytest
import os
import sys

# Add project root and app directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.utils import validate_url, normalize_url, extract_url_features, is_trusted_root_domain
from app.app import app, predict_url


def test_url_validation():
    # Valid
    valid, _ = validate_url("google.com")
    assert valid is True
    valid, _ = validate_url("https://wikipedia.org/wiki/Python")
    assert valid is True
    
    # Invalid
    valid, msg = validate_url("")
    assert valid is False
    valid, msg = validate_url("   ")
    assert valid is False
    valid, msg = validate_url("invalid_url_without_dot")
    assert valid is False
    valid, msg = validate_url("http://site with spaces.com")
    assert valid is False


def test_url_normalization():
    assert normalize_url("https://www.google.com") == "www.google.com/"
    assert normalize_url("http://Google.com") == "google.com/"
    assert normalize_url("github.com") == "github.com/"
    assert normalize_url("https://github.com/torvalds/linux") == "github.com/torvalds/linux"


def test_feature_extraction():
    feats = extract_url_features("http://192.168.1.100/login.php")
    assert feats["has_ip"] is True
    assert feats["has_redirect"] is False
    
    feats_tld = extract_url_features("http://claim-reward.free-prize.xyz")
    assert feats_tld["suspicious_tld"] is True


def test_trusted_domains():
    assert is_trusted_root_domain("https://www.google.com") is True
    assert is_trusted_root_domain("https://github.com/repo") is True
    assert is_trusted_root_domain("amazon.in") is True
    assert is_trusted_root_domain("https://swayam.gov.in/") is True
    assert is_trusted_root_domain("https://nasa.gov") is True
    assert is_trusted_root_domain("iitd.ac.in") is True
    assert is_trusted_root_domain("swayam.gov.in.attacker.xyz") is False
    assert is_trusted_root_domain("docs.google.com/spreadsheet/viewform?formkey=123") is False
    assert is_trusted_root_domain("amazon.de-register.net") is False


def test_legitimate_url_predictions():
    legit_samples = [
        "https://www.google.com",
        "https://google.com",
        "google.com",
        "https://swayam.gov.in/",
        "https://nasa.gov",
        "https://iitd.ac.in",
        "https://claude.ai/new",
        "https://chatgpt.com/",
        "https://notion.so",
        "https://github.com",
        "github.com/torvalds/linux",
        "wikipedia.org",
        "https://www.amazon.in",
        "https://www.python.org",
        "microsoft.com"
    ]
    for url in legit_samples:
        result = predict_url(url)
        assert result["is_phishing"] is False, f"Failed for legitimate URL: {url} -> {result}"
        assert result["prediction"] == "Legitimate Website"
        assert result["p_legit"] >= 50.0


def test_phishing_url_predictions():
    phish_samples = [
        "amazon.de-register.net/",
        "http://192.168.1.1/paypal/login.html",
        "http://secure-login.bank.com.phish-account.xyz/update",
        "docs.google.com/spreadsheet/viewform?formkey=test",
        "supported-amazon.net/",
        "swayam.gov.in.attacker.xyz",
        "claude.ai.attacker-login.xyz",
        "chatgpt-free-premium.net"
    ]
    for url in phish_samples:
        result = predict_url(url)
        assert result["is_phishing"] is True, f"Failed for phishing URL: {url} -> {result}"
        assert result["prediction"] == "Phishing Website"
        assert result["p_phish"] >= 50.0


def test_flask_app():
    client = app.test_client()
    
    # GET /
    res = client.get("/")
    assert res.status_code == 200
    assert b"Phishing Website Detection" in res.data
    
    # POST /predict with legitimate URL
    res = client.post("/predict", data={"url": "https://www.google.com"})
    assert res.status_code == 200
    assert b"Legitimate Website" in res.data
    
    # POST /predict with phishing URL
    res = client.post("/predict", data={"url": "amazon.de-register.net/"})
    assert res.status_code == 200
    assert b"Phishing Website" in res.data
    
    # POST /api/predict (JSON)
    res = client.post("/api/predict", json={"url": "https://wikipedia.org"})
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["is_phishing"] is False
