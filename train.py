# filepath: c:\Users\areia\Desktop\phishing-detector\train.py
import pandas as pd
from src.detector import PhishingDetector

# Carregar dataset
df = pd.read_csv('data/urls_train.csv')

# Instanciar detector
detector = PhishingDetector()

# Treinar modelo
detector.train(df)

# Salvar modelo treinado
detector.save_model('data/phishing_model.joblib')
print("Modelo treinado e salvo com sucesso!")