# 🛡️ AI Phishing Website Detection System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-46E3B7.svg?style=for-the-badge&logo=render&logoColor=white)](https://phishing-website-detection-bw3a.onrender.com/)

[![Python](https://img.shields.io/badge/Python-3.10%20--%203.14-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-green.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.5%2B-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()

> 🌐 **Live Web Application**: [https://phishing-website-detection-bw3a.onrender.com/](https://phishing-website-detection-bw3a.onrender.com/)

An intelligent, real-time web application and machine learning system for classifying website URLs as **Legitimate** or **Phishing**. Powered by **Character N-Gram Vectorization** and **Logistic Regression**, enhanced with heuristic lexical analysis, brand spoofing detection, and URL normalization.

---

## 📌 Table of Contents
- [Live Deployment](#-live-deployment)
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Machine Learning Benchmark](#-machine-learning-benchmark)
- [Architecture & Workflow](#-architecture--workflow)
- [Project Directory Structure](#-project-directory-structure)
- [Installation & Setup](#-installation--setup)
- [Running the Application](#-running-the-application)
- [Production Deployment](#-production-deployment)
- [API Usage](#-api-usage)
- [Running Automated Tests](#-running-automated-tests)
- [Academic Credits](#-academic-credits)

---

## 🌐 Live Deployment

The application is deployed and live on **Render**:
- **Live URL**: [https://phishing-website-detection-bw3a.onrender.com/](https://phishing-website-detection-bw3a.onrender.com/)
- **API Status**: Active (`POST /api/predict`)
- **Runtime**: Python 3.10+ / Gunicorn WSGI

---

## 🔍 Overview

Phishing attacks remain one of the most widespread social engineering cyber threats. Attackers construct fraudulent domains mimicking trusted organizations to steal credentials, financial data, and personal information.

This project delivers:
1. **Machine Learning Classifier**: Trained on over **500,000 unique URLs** using sub-word character n-grams (ranges 2–5) to capture subtle character anomalies, typo-squatting, and deceptive URL patterns.
2. **Heuristic & Lexical Analyzer**: Inspects structural URL properties including IP address presence, suspicious TLDs (`.xyz`, `.top`, `.tk`), brand impersonation, and delimiter counts.
3. **URL Normalization Engine**: Resolves domain/protocol imbalances to eliminate false positive classifications on prominent legitimate sites.
4. **Interactive Web Interface**: A clean Flask web UI with dynamic confidence meters, security breakdown grids, and sample URLs for quick testing.
5. **REST API**: JSON endpoint (`/api/predict`) for programmatic integration with browser extensions or security pipelines.

---

## ⚡ Key Features

- **High Precision & Accuracy**: 98.00% accuracy on 101,440 test URLs.
- **Robust False-Positive Mitigation**: Protocol-agnostic URL normalization prevents false alerts on major platforms (`google.com`, `github.com`, `wikipedia.org`).
- **Brand Impersonation Detection**: Heuristically detects unauthorized domains spoofing major trademarks (e.g., `supported-amazon.net`, `paypal-verify.xyz`).
- **Confidence Scoring & Probabilities**: Outputs exact probability percentages for both Legitimate and Phishing classes.
- **Explainability Breakdown**: Shows normalized URL, character length, dot/hyphen counts, IP address flags, and overall heuristic risk rating.
- **RESTful Endpoint**: Query predictions programmatically with JSON payloads.

---

## 📊 Machine Learning Benchmark

In the exploratory modeling phase, three machine learning algorithms were trained and evaluated on an 80/20 stratified split of 507,196 unique URLs:

| Model | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **97.99%** | **96.67%** | **94.37%** | **95.50%** | **Deployed (Best Overall)** |
| **Linear SVM** (`LinearSVC`) | 97.68% | 95.23% | 94.42% | 94.82% | Evaluated |
| **Multinomial Naive Bayes** | 94.93% | 91.20% | 85.78% | 88.41% | Evaluated |

---

## 🏗️ Architecture & Workflow

```
[ User Enters URL ]
        │
        ▼
[ Input Validation ] ───(Empty / Invalid)───► [ Error Feedback ]
        │
        ▼
[ URL Normalization & Feature Extraction ]
   ├── Strip Scheme (http://, https://)
   ├── Domain Lowercasing & Trailing Slash Formatting
   ├── IP & Suspicious TLD Inspection
   └── Brand Impersonation Check
        │
        ▼
[ Character N-Gram CountVectorizer ]
        │
        ▼
[ Logistic Regression Classifier (predict_proba) ]
        │
        ▼
[ Decision Engine ]
        ├── Legitimate (P < 0.50) ──► Safe Badge (Green) + Confidence %
        └── Phishing   (P ≥ 0.50) ──► Danger Badge (Red) + Confidence %
```

---

## 📁 Project Directory Structure

```
Phishing-Website-Detection/
├── app/
│   ├── static/
│   │   └── style.css            # Responsive styles, badges & progress bar
│   ├── templates/
│   │   └── index.html           # Modern user interface with quick-test chips
│   ├── __init__.py              # App package marker
│   ├── app.py                   # Main Flask backend & API routes
│   └── utils.py                 # URL normalizer, validator & heuristic extractor
├── data/
│   └── phishing_site_urls.csv   # Dataset of 549,362 labeled URLs
├── models/
│   ├── phishing_model.pkl       # Trained Logistic Regression model
│   └── vectorizer.pkl           # Trained CountVectorizer
├── notebooks/
│   └── Phishing Website Detection System.ipynb  # End-to-end ML notebook
├── report/
│   ├── Project Report.docx      # 24-page formal project documentation
│   ├── Project Report.pdf       # Exported project report PDF
│   └── Week 1 Report.docx       # Week 1 initial progress report
├── screenshots/                 # Visual documentation of notebook & UI
├── tests/
│   ├── __init__.py              # Test package marker
│   └── test_prediction.py       # Automated test suite (pytest)
├── .gitignore                   # Ignored files (caches, envs, IDEs)
├── Dockerfile                   # Production container build definition
├── requirements.txt             # Python dependency requirements
├── wsgi.py                      # Production WSGI entry point (Gunicorn)
└── README.md                    # Project documentation
```

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.10+ (Anaconda / Miniconda recommended)

### 1. Clone or Open the Repository
```bash
cd d:/Phishing-Website-Detection
```

### 2. Set Up Environment
Using Anaconda:
```bash
conda activate base
```
Or using standard Python virtual environment:
```bash
python -m venv .venv
# On Windows:
.venv\Scriptsctivate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🚀 Running the Application

Start the Flask development server:
```bash
python app/app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## ☁️ Production Deployment

The project is pre-configured for production environments using **Gunicorn** or **Docker**:

### Option A: Gunicorn WSGI (Render Production Setup)
```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

### Option B: Docker Container
Build and run the self-contained production image:
```bash
docker build -t phishing-detection .
docker run -p 5000:5000 phishing-detection
```

---

## 🔌 API Usage

You can query the system programmatically via HTTP POST:

### Endpoint: `POST /api/predict`

**Request:**
```bash
# Live Deployment:
curl -X POST https://phishing-website-detection-bw3a.onrender.com/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.google.com"}'

# Or Local Development:
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.google.com"}'
```

**Response:**
```json
{
  "confidence": 99.5,
  "features": {
    "dot_count": 2,
    "has_at": false,
    "has_ip": false,
    "has_redirect": false,
    "heuristic_risk_score": 0,
    "hyphen_count": 0,
    "is_brand_spoofed": false,
    "length": 22,
    "spoofed_brand": null,
    "suspicious_tld": false
  },
  "is_phishing": false,
  "normalized_url": "www.google.com/",
  "p_legit": 99.5,
  "p_phish": 0.5,
  "prediction": "Legitimate Website",
  "result_color": "#16A34A",
  "risk_level": "Safe / Low Risk",
  "success": true,
  "url": "https://www.google.com"
}
```

---

## 🧪 Running Automated Tests

Run the full automated test suite using `pytest`:
```bash
pytest tests/test_prediction.py -v
```

All 7 test cases verify:
1. URL syntax validation and edge-case rejection.
2. Character-level URL normalization.
3. Lexical feature extraction (IP detection, delimiter counts, TLD checks).
4. Trusted root domain verification.
5. Known legitimate URL accuracy (Google, GitHub, Wikipedia, Amazon, Python.org, Microsoft).
6. Known phishing URL detection (IP logins, brand spoofing, counterfeit forms).
7. Flask Web routes (`/`, `/predict`, and `/api/predict`).

---

## 🎓 Academic Credits

- **Project**: Phishing Website Detection Tool Using Machine Learning
- **Institution**: Guru Gobind Singh Indraprastha University (GGSIPU) — USICT
- **Department**: Computer Science & Engineering
- **Author**: Kunal Kumar Singh (Enrollment No. `14116403224`)
- **Guide**: Mr. Harshit Kumar
