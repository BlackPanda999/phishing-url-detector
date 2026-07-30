"""
Unit tests for the Phishing URL Detector.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from detector import URLFeatureExtractor, RuleBasedDetector, BatchAnalyzer


class TestURLFeatureExtractor:
    """Test URL feature extraction."""

    def test_extract_features_returns_dict(self):
        features = URLFeatureExtractor.extract_features("https://www.google.com/search?q=test")
        assert isinstance(features, dict)
        assert len(features) >= 25

    def test_https_detection(self):
        features = URLFeatureExtractor.extract_features("https://google.com")
        assert features['uses_https'] == 1.0

    def test_http_detection(self):
        features = URLFeatureExtractor.extract_features("http://google.com")
        assert features['uses_http'] == 1.0

    def test_ip_address_detection(self):
        features = URLFeatureExtractor.extract_features("http://192.168.1.1/page")
        assert features['has_ip_address'] == 1.0

    def test_suspicious_tld_detection(self):
        features = URLFeatureExtractor.extract_features("http://test.tk/page")
        assert features['suspicious_tld'] == 1.0

    def test_shortening_service_detection(self):
        features = URLFeatureExtractor.extract_features("http://bit.ly/abc123")
        assert features['is_shortened'] == 1.0

    def test_feature_vector_length(self):
        vector = URLFeatureExtractor.get_feature_vector("https://example.com")
        assert len(vector) >= 25


class TestRuleBasedDetector:
    """Test rule-based phishing detection."""

    def test_legitimate_url(self):
        detector = RuleBasedDetector()
        result = detector.analyze("https://www.google.com/search?q=python")
        assert result['verdict'] == 'LEGITIMATE'
        assert result['risk_score'] < 0.4

    def test_phishing_url_ip(self):
        detector = RuleBasedDetector()
        result = detector.analyze("http://192.168.1.1/paypal/login")
        assert result['verdict'] in ['SUSPICIOUS', 'PHISHING']
        assert result['risk_score'] > 0.4

    def test_phishing_url_suspicious_tld(self):
        detector = RuleBasedDetector()
        result = detector.analyze("http://paypal-secure-login.xyz/verify?id=123")
        assert result['risk_score'] > 0.3

    def test_returns_reasons(self):
        detector = RuleBasedDetector()
        result = detector.analyze("http://paypal-login.tk/verify")
        assert len(result['reasons']) > 0

    def test_returns_features(self):
        detector = RuleBasedDetector()
        result = detector.analyze("https://github.com")
        assert 'features' in result
        assert isinstance(result['features'], dict)


class TestBatchAnalyzer:
    """Test batch URL analysis."""

    def test_batch_analysis(self):
        analyzer = BatchAnalyzer(use_ai=False)
        urls = [
            "https://www.google.com",
            "http://paypal-login.tk/verify",
            "https://github.com/BlackPanda999"
        ]
        result = analyzer.analyze_batch(urls)
        assert result['total_urls'] == 3
        assert 'verdicts' in result
        assert 'average_risk_score' in result

    def test_generate_report(self):
        analyzer = BatchAnalyzer(use_ai=False)
        urls = ["https://google.com", "http://suspicious.tk/login"]
        report = analyzer.generate_report(urls)
        assert "Phishing URL Detection Report" in report
        assert "Total URLs analyzed" in report
