# RansomGuard — AI Ransomware Detection System

## Quick Start

### 1. Install Requirements
```bash
pip install flask xgboost scikit-learn numpy
```

### 2. Run the Backend
```bash
python app.py
```

### 3. Open the Website
Visit: http://localhost:5000

---

## Project Structure
```
ransomguard/
├── app.py                          # Flask backend (serve website + model inference)
├── xgboost_model.pkl               # Trained XGBoost classifier (99.33% accuracy)
├── static/
│   └── index.html                  # Frontend website
├── safe_document_features.json     # ✅ SAFE test sample (expected: BENIGN ~99%)
├── malicious_ransomware_sim.json   # ☠️ MALICIOUS test sample (expected: RANSOMWARE ~98.9%)
└── README.md
```

---

## How to Test

### Option A: Click test samples in the UI
- Click **"safe_document.exe"** → loads safe features → click ANALYZE → should show BENIGN
- Click **"invoice_2024.exe"** → loads malicious features → click ANALYZE → should show RANSOMWARE

### Option B: Upload JSON files
- Upload `safe_document_features.json` → model predicts **BENIGN** (~99% confidence)
- Upload `malicious_ransomware_sim.json` → model predicts **RANSOMWARE** (~98.9% confidence)

### Option C: Manual entry
Enter any 7 numeric values (0–100) and click ANALYZE.

---

## Model Details

| Model     | Accuracy | Precision | Recall | F1     | ROC-AUC | CV Score |
|-----------|----------|-----------|--------|--------|---------|----------|
| RandomForest | 99.34% | 99.17% | 99.30% | 99.24% | 99.91% | 99.43% |
| **XGBoost**  | **99.33%** | **99.26%** | **99.19%** | **99.23%** | **99.94%** | **99.41%** |
| LightGBM  | 99.30% | 99.19% | 99.21% | 99.20% | 99.92% | 99.43% |
| Stacking  | 99.30% | 99.15% | 99.23% | 99.19% | 99.92% | 99.41% |
| CatBoost  | 99.20% | 99.30% | 98.86% | 99.08% | 99.91% | 99.28% |

**XGBoost** was selected for deployment (highest ROC-AUC: 99.94%).

## The 7 Features
The model uses 7 PE (Portable Executable) analysis features:
- **Feature 0**: Entropy Score — measures randomness (packed/encrypted files = high)
- **Feature 1**: Import Density — suspicious if unusually high or low
- **Feature 2**: Code Section Ratio — proportion of code to data
- **Feature 3**: Resource Anomaly — unusual resource sections
- **Feature 4**: Packer Indicator — signs of code packing/obfuscation
- **Feature 5**: Suspicious API Score — use of encryption/file/registry APIs
- **Feature 6**: Behavioral Signature Score — matches known ransomware patterns

## ⚠️ Disclaimer
This is a **research/educational tool**. The test files contain only JSON data with numeric values — no actual malware. Do not use for production security decisions without proper validation.
