import pytest
from src.features.url_features import URLFeatureExtractor

class TestURLFeatureExtractor:
    def setup_method(self):
        self.extractor = URLFeatureExtractor()

    def test_basic_url_features(self):
        url = "https://www.example.com"
        features = self.extractor.extract_features(url)
        
        assert features['url_length'] == len(url)
        assert features['uses_https'] == 1
        assert features['dot_count'] == 2
        assert features['uses_ip_address'] == 0

    def test_domain_features(self):
        url = "http://subdomain.example.com"
        features = self.extractor.extract_features(url)
        
        assert features['domain_length'] == len("example")
        assert features['suspicious_tld'] == 0  # Assuming .com is not suspicious
        assert features['contains_popular_domain'] == 0  # "example" is not in the popular domains

    def test_path_query_features(self):
        url = "http://www.example.com/login?user=test"
        features = self.extractor.extract_features(url)
        
        assert features['path_length'] == len("/login")
        assert features['query_length'] == len("user=test")
        assert features['query_param_count'] == 1
        assert features['suspicious_words_count'] == 1  # "login" is a suspicious word

    def test_ip_address_url(self):
        url = "http://192.168.1.1"
        features = self.extractor.extract_features(url)
        
        assert features['uses_ip_address'] == 1

    def test_url_with_special_chars(self):
        url = "http://www.example.com/?param=<script>alert('xss')</script>"
        features = self.extractor.extract_features(url)
        
        assert features['url_special_chars'] > 0  # There are special characters in the URL