import re
import tldextract
import whois
from datetime import datetime
import urllib.parse
from src.utils import safe_request

class URLFeatureExtractor:
    """Extrai características de URLs para detecção de phishing"""
    
    def __init__(self):
        # Lista de domínios populares para comparação
        self.popular_domains = [
            'google', 'facebook', 'amazon', 'apple', 'netflix', 
            'microsoft', 'paypal', 'yahoo', 'instagram', 'twitter'
        ]
    
    def extract_features(self, url):
        """Extrai todas as características de uma URL"""
        features = {}
        
        # Características básicas da URL
        features.update(self._basic_url_features(url))
        
        # Características do domínio
        features.update(self._domain_features(url))
        
        # Características do caminho e query
        features.update(self._path_query_features(url))
        
        return features
    
    def _basic_url_features(self, url):
        """Extrai características básicas da URL"""
        features = {}
        
        # Comprimento da URL
        features['url_length'] = len(url)
        
        # Contagem de caracteres especiais
        features['url_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.-]', url))
        
        # Presença de 'http' vs 'https'
        features['uses_https'] = int(url.startswith('https://'))
        
        # Número de pontos na URL
        features['dot_count'] = url.count('.')
        
        # Presença de IP em vez de domínio
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['uses_ip_address'] = int(bool(re.match(ip_pattern, url)))
        
        return features
    
    def _domain_features(self, url):
        """Extrai características do domínio"""
        features = {}
        
        # Extrair informações do domínio
        extracted = tldextract.extract(url)
        domain = extracted.domain
        tld = extracted.suffix
        
        # Domínio contém algum domínio popular?
        features['contains_popular_domain'] = 0
        for pop_domain in self.popular_domains:
            if pop_domain in domain and pop_domain != domain:
                features['contains_popular_domain'] = 1
                break
        
        # Comprimento do domínio
        features['domain_length'] = len(domain)
        
        # Número de hífens no domínio
        features['domain_hyphen_count'] = domain.count('-')
        
        # TLD suspeito (lista de TLDs comuns em phishing)
        suspicious_tlds = ['tk', 'xyz', 'ml', 'ga', 'cf', 'gq']
        features['suspicious_tld'] = int(tld in suspicious_tlds)
        
        # Idade do domínio (quando possível)
        features['domain_age_days'] = -1  # valor padrão se não conseguir obter
        try:
            w = whois.whois(extracted.registered_domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                domain_age = (datetime.now() - creation_date).days
                features['domain_age_days'] = domain_age
        except Exception:            
            pass
        
        return features
    
    def _path_query_features(self, url):
        """Extrai características do caminho e query da URL"""
        features = {}
        
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # Comprimento do caminho
        features['path_length'] = len(path)
        
        # Comprimento da query
        features['query_length'] = len(query)
        
        # Número de parâmetros na query
        features['query_param_count'] = len(urllib.parse.parse_qs(query))
        
        # Presença de palavras suspeitas no caminho ou query
        suspicious_words = ['login', 'signin', 'account', 'password', 'secure', 
                            'update', 'banking', 'confirm', 'verify', 'paypal']
        path_query = path.lower() + query.lower()
        
        features['suspicious_words_count'] = 0
        for word in suspicious_words:
            if word in path_query:
                features['suspicious_words_count'] += 1
        
        return features