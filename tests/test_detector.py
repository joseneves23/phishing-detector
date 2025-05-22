from src.detector import PhishingDetector
import pandas as pd
import pytest

@pytest.fixture
def detector():
    model_path = 'path/to/your/model.joblib'  # Update with the actual model path if needed
    return PhishingDetector(model_path)

def test_predict_phishing(detector):
    url = "http://example-phishing.com"
    result = detector.predict(url)
    assert isinstance(result, dict)
    assert 'is_phishing' in result
    assert 'confidence' in result
    assert 'risk_level' in result
    assert 'top_indicators' in result

def test_train_model(detector):
    # Load a sample dataset for training
    data = {
        'url': ['http://example.com', 'http://example-phishing.com'],
        'is_phishing': [0, 1]
    }
    df = pd.DataFrame(data)
    
    # Train the model
    detector.train(df)
    
    # Check if the model is trained
    assert detector.model is not None

def test_predict_legitimate_url(detector):
    url = "http://example.com"
    result = detector.predict(url)
    assert result['is_phishing'] is False
    assert result['confidence'] < 0.5  # Assuming legitimate URLs have low confidence for phishing

def test_predict_phishing_url(detector):
    url = "http://example-phishing.com"
    result = detector.predict(url)
    assert result['is_phishing'] is True
    assert result['confidence'] >= 0.5  # Assuming phishing URLs have high confidence for phishing