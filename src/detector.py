import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from src.features.url_features import URLFeatureExtractor
from src.features.content_features import ContentFeatureExtractor
from src.features.ssl_features import SSLFeatureExtractor


class PhishingDetector:
    """
    Classe principal para detecção de sites de phishing
    """

    def __init__(self, model_path=None):
        # Inicializar os extratores de características
        self.url_extractor = URLFeatureExtractor()
        self.content_extractor = ContentFeatureExtractor()
        self.ssl_extractor = SSLFeatureExtractor()

        # Inicializar modelo
        self.model = None
        if model_path:
            try:
                self.model = joblib.load(model_path)
            except:
                # Se não conseguir carregar, criar um novo modelo
                self.model = self._create_model()
        else:
            self.model = self._create_model()

    def _create_model(self):
        """Cria um novo modelo de machine learning"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )

    def extract_features(self, url):
        """Extrai todas as características de uma URL"""
        # Extrair características da URL
        url_features = self.url_extractor.extract_features(url)

        # Extrair características do conteúdo
        content_features = self.content_extractor.extract_features(url)

        # Extrair características do SSL
        ssl_features = self.ssl_extractor.extract_features(url)

        # Combinar todas as características
        features = {**url_features, **content_features, **ssl_features}

        return features

    def train(self, urls_dataframe):
        """
        Treina o modelo com um DataFrame contendo URLs e rótulos

        Args:
            urls_dataframe: DataFrame com colunas 'url' e 'is_phishing' (0 ou 1)
        """
        X = []
        y = urls_dataframe['is_phishing'].values

        # Extrair características para cada URL
        for url in urls_dataframe['url']:
            features = self.extract_features(url)
            X.append(features)

        # Converter para DataFrame para tratamento uniforme
        X_df = pd.DataFrame(X)

        # Preencher valores ausentes
        X_df = X_df.fillna(-1)

        # Treinar modelo
        self.model.fit(X_df, y)

        return self

    def predict(self, url):
        """
        Prediz se uma URL é phishing

        Args:
            url: URL para analisar

        Returns:
            Dicionário com resultado da predição e pontuação
        """
        # Extrair características
        features = self.extract_features(url)

        # Converter para DataFrame
        X = pd.DataFrame([features])

        # Preencher valores ausentes
        X = X.fillna(-1)

        # Fazer predição
        try:
            is_phishing = self.model.predict(X)[0]
            # Probabilidade da classe positiva
            score = self.model.predict_proba(X)[0][1]
        except Exception as e:
            # Se houver problemas com a predição, usar regras heurísticas
            is_phishing, score = self._heuristic_prediction(features)

        # Classificar nível de risco
        risk_level = self._get_risk_level(score)

        # Encontrar os indicadores mais importantes
        negative_indicators = self._get_negative_indicators(features, url)
        positive_indicators = self._get_positive_indicators(features, url)

        return {
            'is_phishing': bool(is_phishing),
            'confidence': float(score),
            'risk_level': risk_level,
            'negative_indicators': negative_indicators,
            'positive_indicators': positive_indicators
        }

    def _heuristic_prediction(self, features):
        """Usa regras heurísticas para fazer predição quando o modelo falha"""
        # Critérios suspeitos
        suspicious_criteria = [
            features.get('uses_https', 1) == 0,
            features.get('uses_ip_address', 0) == 1,
            features.get('suspicious_tld', 0) == 1,
            features.get('contains_popular_domain', 0) == 1,
            features.get('domain_age_days', 365) < 30,
            features.get('form_external_action', 0) == 1,
            features.get('has_redirect', 0) == 1,
            features.get('domain_match', 1) == 0 and features.get(
                'has_ssl', 0) == 1,
            features.get('suspicious_text_score', 0) >= 2
        ]

        # Contar critérios suspeitos que foram atendidos
        suspicious_count = sum(1 for x in suspicious_criteria if x)

        # Calcular pontuação como a proporção de critérios suspeitos
        score = suspicious_count / len(suspicious_criteria)

        # Decidir se é phishing baseado em um limiar
        is_phishing = score > 0.4

        return int(is_phishing), score

    def _get_risk_level(self, score):
        """Classifica o nível de risco baseado na pontuação"""
        if score < 0.2:
            return "Baixo"
        elif score < 0.5:
            return "Médio"
        elif score < 0.8:
            return "Alto"
        else:
            return "Muito Alto"

    def _get_negative_indicators(self, features, url):
        """Retorna os principais indicadores que contribuíram para a classificação"""
        indicators = []

        # Verificar características específicas e adicionar indicadores relevantes
        if features.get('uses_https', 1) == 0:
            indicators.append("URL não usa HTTPS")

        if features.get('uses_ip_address', 0) == 1:
            indicators.append("URL contém endereço IP em vez de domínio")

        if features.get('suspicious_tld', 0) == 1:
            indicators.append("Domínio usa TLD suspeito")

        if features.get('contains_popular_domain', 0) == 1:
            indicators.append("URL contém imitação de domínio popular")

        if features.get('domain_age_days', 365) < 30 and features.get('domain_age_days', -1) > 0:
            indicators.append(
                f"Domínio registado recentemente ({features.get('domain_age_days')} dias)")

        if features.get('form_external_action', 0) == 1:
            indicators.append("Formulário envia dados para site externo")

        if features.get('suspicious_text_score', 0) >= 2:
            indicators.append("Página contém texto suspeito")

        if features.get('has_redirect', 0) == 1:
            indicators.append("Página contém redirecionamento automático")

        if features.get('has_ssl', 1) == 0:
            indicators.append("Site não utiliza certificado SSL")
        elif features.get('trusted_issuer', 1) == 0:
            indicators.append(
                "Certificado SSL não emitido por autoridade confiável")
        elif features.get('is_expired', 0) == 1:
            indicators.append("Certificado SSL expirado")
        elif features.get('domain_match', 1) == 0:
            indicators.append("Certificado SSL não corresponde ao domínio")

        # Limitar a 5 indicadores principais
        return indicators[:5]

    def _get_positive_indicators(self, features, url):
        """Retorna indicadores positivos de segurança"""
        indicators = []
        if features.get('uses_https', 1) == 1:
            indicators.append("URL usa HTTPS")
        if features.get('uses_ip_address', 0) == 0:
            indicators.append("URL utiliza domínio válido")
        if features.get('suspicious_tld', 0) == 0:
            indicators.append("Domínio usa TLD confiável")
        if features.get('contains_popular_domain', 0) == 0:
            indicators.append("URL não imita domínios populares")
        if features.get('domain_age_days', 365) >= 30:
            indicators.append("Domínio registado há mais de 30 dias")
        if features.get('form_external_action', 0) == 0:
            indicators.append("Formulário não envia dados para site externo")
        if features.get('suspicious_text_score', 0) < 2:
            indicators.append("Página não contém texto suspeito")
        if features.get('has_redirect', 0) == 0:
            indicators.append("Página não contém redirecionamento automático")
        if features.get('has_ssl', 1) == 1:
            indicators.append("Site utiliza certificado SSL")
        if features.get('trusted_issuer', 1) == 1:
            indicators.append(
                "Certificado SSL emitido por autoridade confiável")
        if features.get('is_expired', 0) == 0:
            indicators.append("Certificado SSL válido")
        if features.get('domain_match', 1) == 1:
            indicators.append("Certificado SSL corresponde ao domínio")
        # Limitar a 5 indicadores principais
        return indicators[:5]

    def save_model(self, path):
        """Salva o modelo treinado em disco"""
        if self.model:
            joblib.dump(self.model, path)
            return True
        return False
