# 🛡️ AI-Powered Phishing URL Detector

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AI](https://img.shields.io/badge/AI-ML-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)
![Security](https://img.shields.io/badge/Cybersecurity-Defensive-00758F?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**An AI-enhanced phishing URL detection tool combining machine learning with rule-based heuristics**

</div>

---

## 📋 Overview

This project detects phishing URLs by analyzing 25+ URL features and combining two detection methods:

1. **Rule-Based Heuristics** — Checks for known phishing patterns (suspicious TLDs, IP addresses, shortening services, brand impersonation, etc.)
2. **AI/ML Detection** — Random Forest classifier trained on phishing/legitimate URL patterns

The tool produces a risk score (0.0–1.0) and classifies URLs as `LEGITIMATE`, `SUSPICIOUS`, or `PHISHING` with detailed reasoning.

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| 🔍 **25+ URL Features** | Extracts structural, lexical, and semantic features from URLs |
| 🤖 **AI Detection** | Random Forest ML model for pattern-based phishing detection |
| 📐 **Rule-Based Engine** | 15+ heuristic rules for known phishing indicators |
| 📊 **Risk Scoring** | Weighted ensemble score combining AI + rule-based results |
| 📝 **Detailed Reports** | Human-readable analysis with risk reasons |
| 📦 **Batch Analysis** | Analyze multiple URLs at once with summary reports |
| 🔌 **Dual Mode** | Works with or without ML libraries (falls back to rules) |
| 🛡️ **Defensive Tool** | Built for security education and defense, not offense |

---

## 🧠 Detection Methods

### Feature Extraction (25+ Features)

```
URL Structure:    length, hostname, path, query lengths
Character Analysis: dots, hyphens, underscores, slashes, @, ?, &, =
Digit Analysis:  digit count, digit-to-length ratio
Network Check:   IP address detection, port detection
TLD Analysis:    suspicious TLD detection (.tk, .ml, .cf, .xyz, etc.)
Security:        HTTPS/HTTP check, shortening service detection
Semantic:        suspicious keywords, brand name impersonation
Encoding:        URL-encoded characters, hex characters
```

### AI Model

- **Algorithm**: Random Forest Classifier (50 trees, max depth 10)
- **Training**: Synthetic phishing/legitimate URL patterns
- **Ensemble**: 60% ML score + 40% Rule-based score

---

## 📦 Installation

```bash
git clone https://github.com/BlackPanda999/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt
```

> Without ML libraries, the tool still works using rule-based detection only.

---

## 🚀 Usage

### Single URL Analysis

```bash
python src/detector.py "https://suspicious-site.xyz/login?verify=123"
```

### Multiple URLs

```bash
python src/detector.py "https://google.com" "http://paypal-login.tk/verify" "https://github.com"
```

### Demo Mode (no arguments)

```bash
python src/detector.py
```

### Python API

```python
from src.detector import AIPhishingDetector

detector = AIPhishingDetector()
result = detector.analyze("https://suspicious-site.xyz/login")

print(result['verdict'])      # PHISHING / SUSPICIOUS / LEGITIMATE
print(result['risk_score'])   # 0.0 - 1.0
print(result['reasons'])       # List of risk indicators
```

### Batch Analysis

```python
from src.detector import BatchAnalyzer

analyzer = BatchAnalyzer(use_ai=True)
report = analyzer.generate_report([
    "https://google.com",
    "http://paypal-login.tk/verify",
    "https://github.com/BlackPanda999"
])
print(report)
```

---

## 📊 Output Example

```
============================================================
  AI-Powered Phishing URL Detection Report
  Generated: 2026-07-31T00:20:00
============================================================

  Total URLs analyzed: 6
  Phishing detected:   2
  Suspicious:          1
  Legitimate:          3
  Average risk score:  0.342

------------------------------------------------------------
  [OK] [LEGITIMATE] Risk: 0.05 - https://www.google.com/search?q=cybersecurity
      > No significant risk indicators found

  [!] [PHISHING] Risk: 0.85 - http://paypal-secure-login.xyz/account/verify?id=12345
      > Uses a suspicious TLD commonly associated with phishing
      > Contains 3 suspicious keywords
      > Contains brand name in suspicious position

============================================================
```

---

## 🏗️ Project Structure

```
phishing-url-detector/
├── src/
│   └── detector.py        # Main detection engine
├── tests/
│   └── test_detector.py   # Unit tests
├── docs/
│   └── FEATURES.md        # Feature documentation
├── requirements.txt       # Python dependencies
├── LICENSE                # MIT License
└── README.md              # This file
```

---

## 🛡️ Safety & Ethics

This tool is designed for **defensive cybersecurity purposes only**:

- ✅ Educational use — learn about phishing indicators
- ✅ Security research — analyze URL patterns
- ✅ Defense teams — screen URLs in security pipelines
- ❌ Not for creating phishing campaigns
- ❌ Not for attacking or targeting individuals

Always obtain proper authorization before testing any URL in a production environment.

---

## 🤝 Contributing

Contributions welcome! Areas to improve:

- Larger training dataset for the ML model
- Additional URL features (WHOIS, DNS records, SSL cert analysis)
- Web interface / API endpoint
- Integration with threat intelligence feeds

---

## 👨‍💻 Author

**Osama Khan** — [BlackPanda999](https://github.com/BlackPanda999)

- 📧 cyberkhan554433@gmail.com
- 🔗 [LinkedIn](https://linkedin.com/in/osamakhan44)
- 🛡️ CompTIA Security+ | PenTest+ Certified

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

> ⭐ If this project helped you, consider starring the repo!
