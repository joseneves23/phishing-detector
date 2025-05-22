import pytest
from src.features.content_features import ContentFeatureExtractor

def test_extract_features_valid_url():
    extractor = ContentFeatureExtractor()
    url = "http://example.com"
    features = extractor.extract_features(url)
    
    assert isinstance(features, dict)
    assert 'has_form' in features
    assert 'form_with_password' in features
    assert 'form_external_action' in features
    assert 'external_resource_ratio' in features
    assert 'external_link_ratio' in features
    assert 'has_redirect' in features
    assert 'visible_links_count' in features
    assert 'invisible_links_count' in features
    assert 'url_in_title' in features
    assert 'suspicious_text_score' in features

def test_extract_features_invalid_url():
    extractor = ContentFeatureExtractor()
    url = "http://invalid-url"
    features = extractor.extract_features(url)
    
    assert isinstance(features, dict)
    assert features['has_form'] == 0
    assert features['form_with_password'] == 0
    assert features['form_external_action'] == 0
    assert features['external_resource_ratio'] == 0
    assert features['external_link_ratio'] == 0
    assert features['has_redirect'] == 0
    assert features['visible_links_count'] == 0
    assert features['invisible_links_count'] == 0
    assert features['url_in_title'] == 0
    assert features['suspicious_text_score'] == 0

def test_extract_features_no_form():
    extractor = ContentFeatureExtractor()
    url = "http://example.com/no-form"
    features = extractor.extract_features(url)
    
    assert features['has_form'] == 0
    assert features['form_with_password'] == 0

def test_extract_features_with_redirect():
    extractor = ContentFeatureExtractor()
    url = "http://example.com/redirect"
    features = extractor.extract_features(url)
    
    assert features['has_redirect'] == 1  # Assuming this URL has a redirect

def test_extract_features_with_suspicious_text():
    extractor = ContentFeatureExtractor()
    url = "http://example.com/suspicious"
    features = extractor.extract_features(url)
    
    assert features['suspicious_text_score'] > 0  # Assuming this URL has suspicious text