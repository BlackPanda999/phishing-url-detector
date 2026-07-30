"""
AI-Powered Phishing URL Detector
================================
Main detection engine that combines rule-based heuristics
with machine learning to identify phishing URLs.

Author: BlackPanda999 (Osama Khan)
License: MIT
"""

import re
import math
import json
import socket
import urllib.parse
from collections import Counter
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Optional ML imports — falls back to rule-based if not available
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


# ─── Suspicious patterns ───────────────────────────────────────────────────

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.country']
SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'shorte.st',
    'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'rebrand.ly',
    'cutt.ly', 't.ly', 'rb.gy', 'shorturl.at'
]
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'password', 'wallet', 'bank', 'paypal', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'suspended', 'unlock', 'security', 'billing',
    'activate', 'validate', 'reset', 'alert', 'urgent', 'limited'
]
BRAND_NAMES = [
    'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook',
    'instagram', 'netflix', 'bank', 'chase', 'wellsfargo', 'citibank'
]

# ─── Feature Extraction ────────────────────────────────────────────────────


class URLFeatureExtractor:
    """Extracts features from URLs for phishing detection."""

    @staticmethod
    def extract_features(url: str) -> Dict[str, float]:
        """Extract 25+ features from a URL for phishing detection."""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''

        features = {}

        # ── URL structural features
        features['url_length'] = float(len(url))
        features['hostname_length'] = float(len(hostname))
        features['path_length'] = float(len(path))
        features['query_length'] = float(len(query))
        features['num_dots'] = float(url.count('.'))
        features['num_hyphens'] = float(url.count('-'))
        features['num_underscores'] = float(url.count('_'))
        features['num_slashes'] = float(url.count('/'))
        features['num_at_symbols'] = float(url.count('@'))
        features['num_question_marks'] = float(url.count('?'))
        features['num_ampersands'] = float(url.count('&'))
        features['num_equals'] = float(url.count('='))
        features['num_digits'] = float(sum(c.isdigit() for c in url))
        features['digit_ratio'] = features['num_digits'] / max(features['url_length'], 1)

        # ── IP address check
        features['has_ip_address'] = 1.0 if URLFeatureExtractor._is_ip(hostname) else 0.0

        # ── TLD analysis
        features['suspicious_tld'] = 1.0 if any(
            hostname.endswith(tld) for tld in SUSPICIOUS_TLDS
        ) else 0.0

        # ── HTTPS check
        features['uses_https'] = 1.0 if url.startswith('https://') else 0.0
        features['uses_http'] = 1.0 if url.startswith('http://') else 0.0

        # ── Shortening service check
        features['is_shortened'] = 1.0 if any(
            svc in hostname for svc in SHORTENING_SERVICES
        ) else 0.0

        # ── Suspicious keywords
        url_lower = url.lower()
        features['num_suspicious_keywords'] = float(sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
        ))

        # ── Brand name in URL (but not in legitimate domain)
        features['has_brand_name'] = 1.0 if any(
            brand in url_lower and brand not in hostname.split('.')[0]
            for brand in BRAND_NAMES
        ) else 0.0

        # ── Subdomain analysis
        subdomains = hostname.split('.')[:-2] if len(hostname.split('.')) > 2 else []
        features['num_subdomains'] = float(len(subdomains))

        # ── Port in URL
        features['has_port'] = 1.0 if re.search(r':\d+', hostname) else 0.0

        # ── Encoded characters
        features['has_encoded_chars'] = 1.0 if '%' in url else 0.0
        features['num_encoded_chars'] = float(url.count('%'))

        # ── Special patterns
        features['has_double_slash_redirect'] = 1.0 if '//' in path else 0.0
        features['has_hex_chars'] = 1.0 if re.search(r'0x[0-9a-fA-F]+', url) else 0.0

        # ── Length-based risk
        features['hostname_too_long'] = 1.0 if len(hostname) > 50 else 0.0
        features['url_too_long'] = 1.0 if len(url) > 100 else 0.0

        return features

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        """Check if hostname is an IP address."""
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            return False

    @staticmethod
    def get_feature_vector(url: str) -> List[float]:
        """Get features as an ordered list for ML models."""
        features = URLFeatureExtractor.extract_features(url)
        return list(features.values())

    @staticmethod
    def get_feature_names() -> List[str]:
        """Get feature names in order."""
        return list(URLFeatureExtractor.extract_features('').keys())


# ─── Rule-Based Detector ────────────────────────────────────────────────────


class RuleBasedDetector:
    """Rule-based phishing URL detector with risk scoring."""

    def __init__(self):
        self.threshold = 0.5

    def analyze(self, url: str) -> Dict:
        """Analyze a URL and return risk assessment."""
        features = URLFeatureExtractor.extract_features(url)
        risk_score = 0.0
        reasons = []

        # ── High-risk indicators
        if features['has_ip_address']:
            risk_score += 0.20
            reasons.append("URL contains IP address instead of domain name")

        if features['suspicious_tld']:
            risk_score += 0.15
            reasons.append("Uses a suspicious TLD commonly associated with phishing")

        if features['is_shortened']:
            risk_score += 0.10
            reasons.append("URL uses a shortening service (hides destination)")

        if features['num_at_symbols'] > 0:
            risk_score += 0.15
            reasons.append("Contains '@' symbol which can redirect users")

        if features['has_port']:
            risk_score += 0.10
            reasons.append("Contains non-standard port number")

        if features['num_suspicious_keywords'] >= 2:
            risk_score += 0.15
            reasons.append(f"Contains {int(features['num_suspicious_keywords'])} suspicious keywords")

        if features['has_brand_name']:
            risk_score += 0.15
            reasons.append("Contains brand name in suspicious position")

        # ── Medium-risk indicators
        if features['url_too_long']:
            risk_score += 0.08
            reasons.append("URL is unusually long")

        if features['hostname_too_long']:
            risk_score += 0.05
            reasons.append("Hostname is unusually long")

        if features['num_dots'] > 5:
            risk_score += 0.08
            reasons.append(f"Contains {int(features['num_dots'])} dots (excessive subdomains)")

        if features['num_hyphens'] > 5:
            risk_score += 0.05
            reasons.append("Contains many hyphens (common in phishing)")

        if features['digit_ratio'] > 0.3:
            risk_score += 0.05
            reasons.append("High ratio of digits in URL")

        if features['has_encoded_chars'] and features['num_encoded_chars'] > 3:
            risk_score += 0.05
            reasons.append("Contains many encoded characters")

        if not features['uses_https']:
            risk_score += 0.05
            reasons.append("Does not use HTTPS")

        # ── Cap the score
        risk_score = min(risk_score, 1.0)

        # ── Determine verdict
        if risk_score >= 0.7:
            verdict = "PHISHING"
            risk_level = "HIGH"
        elif risk_score >= 0.4:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        else:
            verdict = "LEGITIMATE"
            risk_level = "LOW"

        return {
            'url': url,
            'verdict': verdict,
            'risk_level': risk_level,
            'risk_score': round(risk_score, 3),
            'reasons': reasons if reasons else ["No significant risk indicators found"],
            'features': {k: round(v, 3) for k, v in features.items()},
            'timestamp': datetime.now().isoformat(),
            'detector': 'rule-based'
        }


# ─── AI-Powered Detector ────────────────────────────────────────────────────


class AIPhishingDetector:
    """AI-enhanced phishing detector combining ML with rule-based heuristics."""

    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.model = None
        self.vectorizer = None
        self.is_trained = False

        if ML_AVAILABLE:
            self._train_model()

    def _train_model(self):
        """Train a simple model on known phishing/legitimate URL patterns."""
        # Training data — synthetic patterns for educational purposes
        phishing_patterns = [
            "http://paypal-secure-login.tk/account/verify?id=123",
            "http://192.168.1.1/amazon/signin/update",
            "https://google-security-alert.xyz/login?token=abc",
            "http://bit.ly/2x9FkLp/secure-login",
            "http://apple-id-verify.cf/account/locked",
            "https://microsoft-online-verify.ml/login?id=456",
            "http://bank-account-update.tk/verify?user=123",
            "https://facebook-reset-password.gq/confirm?token=xyz",
            "http://paypal-com-signin.click/account/suspended",
            "https://amazon-secure-update.top/login.php",
        ]
        legitimate_patterns = [
            "https://www.google.com/search?q=python",
            "https://github.com/BlackPanda999/projects",
            "https://www.python.org/downloads/",
            "https://docs.python.org/3/library/",
            "https://www.linkedin.com/in/osamakhan44",
            "https://stackoverflow.com/questions/tagged/python",
            "https://www.aws.amazon.com/security/",
            "https://azure.microsoft.com/en-us/services/",
            "https://www.nist.gov/cybersecurity",
            "https://www.cloudflare.com/security/",
        ]

        urls = phishing_patterns + legitimate_patterns
        labels = [1] * len(phishing_patterns) + [0] * len(legitimate_patterns)

        # Extract features for training
        X = [URLFeatureExtractor.get_feature_vector(url) for url in urls]

        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X, labels)
        self.is_trained = True

    def analyze(self, url: str) -> Dict:
        """Analyze URL using both AI and rule-based detection."""
        # Get rule-based analysis
        rule_result = self.rule_detector.analyze(url)

        if not self.is_trained or not ML_AVAILABLE:
            rule_result['detector'] = 'rule-based (ML unavailable)'
            return rule_result

        # Get ML prediction
        features = URLFeatureExtractor.get_feature_vector(url)
        prediction = self.model.predict([features])[0]
        probability = self.model.predict_proba([features])[0]

        ml_score = probability[1]  # Probability of being phishing
        rule_score = rule_result['risk_score']

        # Combine scores (weighted ensemble)
        combined_score = (ml_score * 0.6) + (rule_score * 0.4)
        combined_score = round(min(combined_score, 1.0), 3)

        # Determine verdict
        if combined_score >= 0.7:
            verdict = "PHISHING"
            risk_level = "HIGH"
        elif combined_score >= 0.4:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        else:
            verdict = "LEGITIMATE"
            risk_level = "LOW"

        ml_confidence = round(max(probability), 3)

        return {
            'url': url,
            'verdict': verdict,
            'risk_level': risk_level,
            'risk_score': combined_score,
            'ml_score': round(ml_score, 3),
            'rule_score': round(rule_score, 3),
            'ml_confidence': ml_confidence,
            'ml_prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
            'reasons': rule_result['reasons'],
            'features': rule_result['features'],
            'timestamp': datetime.now().isoformat(),
            'detector': 'ai-enhanced (RandomForest + Rules)',
            'ml_available': True
        }


# ─── Batch Analysis ────────────────────────────────────────────────────────


class BatchAnalyzer:
    """Analyze multiple URLs and generate reports."""

    def __init__(self, use_ai: bool = True):
        if use_ai and ML_AVAILABLE:
            self.detector = AIPhishingDetector()
        else:
            self.detector = RuleBasedDetector()

    def analyze_batch(self, urls: List[str]) -> Dict:
        """Analyze a list of URLs and return summary report."""
        results = []
        for url in urls:
            try:
                result = self.detector.analyze(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'verdict': 'ERROR',
                    'error': str(e)
                })

        # Summary
        verdicts = Counter(r['verdict'] for r in results)
        avg_risk = sum(r.get('risk_score', 0) for r in results) / max(len(results), 1)

        return {
            'total_urls': len(urls),
            'verdicts': dict(verdicts),
            'average_risk_score': round(avg_risk, 3),
            'results': results,
            'timestamp': datetime.now().isoformat()
        }

    def generate_report(self, urls: List[str], output_file: str = None) -> str:
        """Generate a human-readable report."""
        batch_result = self.analyze_batch(urls)

        report_lines = [
            "=" * 60,
            "  AI-Powered Phishing URL Detection Report",
            f"  Generated: {batch_result['timestamp']}",
            "=" * 60,
            "",
            f"  Total URLs analyzed: {batch_result['total_urls']}",
            f"  Phishing detected:   {batch_result['verdicts'].get('PHISHING', 0)}",
            f"  Suspicious:          {batch_result['verdicts'].get('SUSPICIOUS', 0)}",
            f"  Legitimate:          {batch_result['verdicts'].get('LEGITIMATE', 0)}",
            f"  Average risk score:  {batch_result['average_risk_score']}",
            "",
            "-" * 60,
        ]

        for r in batch_result['results']:
            if r['verdict'] == 'ERROR':
                report_lines.append(f"  X ERROR: {r['url']} - {r.get('error', 'Unknown')}")
                continue

            icon = "[!]" if r['verdict'] == "PHISHING" else "[?]" if r['verdict'] == "SUSPICIOUS" else "[OK]"
            report_lines.append(f"  {icon} [{r['verdict']}] Risk: {r['risk_score']} - {r['url'][:70]}")
            if r.get('reasons'):
                for reason in r['reasons'][:3]:
                    report_lines.append(f"      > {reason}")
            report_lines.append("")

        report_lines.append("=" * 60)
        report_lines.append("  Powered by BlackPanda999 - AI Phishing URL Detector")
        report_lines.append("=" * 60)

        report = "\n".join(report_lines)

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(batch_result, f, indent=2)
            print(f"Report saved to {output_file}")

        return report


# ─── Main Entry Point ───────────────────────────────────────────────────────


def main():
    """CLI entry point for the phishing URL detector."""
    import sys

    print("=" * 60)
    print("  AI-Powered Phishing URL Detector")
    print("  by BlackPanda999")
    print("=" * 60)

    if ML_AVAILABLE:
        print("  [OK] ML libraries available - AI detection enabled")
    else:
        print("  [!] ML libraries not available - using rule-based detection")
        print("     Install with: pip install numpy scikit-learn")
    print()

    analyzer = BatchAnalyzer(use_ai=ML_AVAILABLE)

    if len(sys.argv) > 1:
        urls = sys.argv[1:]
    else:
        # Demo with example URLs
        urls = [
            "https://www.google.com/search?q=cybersecurity",
            "http://paypal-secure-login.xyz/account/verify?id=12345",
            "https://github.com/BlackPanda999/projects",
            "http://192.168.1.1/amazon/signin/update",
            "https://www.python.org/downloads/",
            "https://apple-id-verify.cf/account/locked?token=abc",
        ]
        print("  Running demo with example URLs...\n")

    report = analyzer.generate_report(urls)
    print(report)


if __name__ == "__main__":
    main()
