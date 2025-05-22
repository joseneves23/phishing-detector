import ssl
import socket
import datetime
from urllib.parse import urlparse
from src.utils import safe_request

class SSLFeatureExtractor:
    """Extrai características do certificado SSL/TLS para detecção de phishing"""
    
    def extract_features(self, url):
        """Extrai todas as características relacionadas ao SSL/TLS"""
        features = {}
        
        # Verificar se a URL usa HTTPS
        if not url.startswith('https://'):
            return self._empty_features()
        
        try:
            # Extrair domínio
            domain = urlparse(url).netloc
            
            # Criar contexto SSL
            context = ssl.create_default_context()
            
            # Conectar ao servidor e obter certificado
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Extrair características do certificado
            features['has_ssl'] = 1
            
            # Verificar emissor do certificado
            issuer = dict(x[0] for x in cert['issuer'])
            issuer_org = issuer.get('organizationName', '')
            
            # Lista de autoridades certificadoras confiáveis
            trusted_cas = [
                'DigiCert', 'Let\'s Encrypt', 'Comodo', 'GeoTrust', 'GlobalSign',
                'Thawte', 'Symantec', 'RapidSSL', 'Amazon', 'Google', 'Microsoft'
            ]
            
            features['trusted_issuer'] = 0
            for ca in trusted_cas:
                if ca.lower() in issuer_org.lower():
                    features['trusted_issuer'] = 1
                    break
            
            # Verificar data de validade
            if 'notAfter' in cert:
                not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                expiry_date = datetime.datetime.fromtimestamp(not_after)
                days_to_expiry = (expiry_date - datetime.datetime.now()).days
                features['days_to_expiry'] = days_to_expiry
                features['is_expired'] = int(days_to_expiry <= 0)
            else:
                features['days_to_expiry'] = -1
                features['is_expired'] = 1
            
            # Verificar se o certificado corresponde ao domínio
            domain_match = False
            if 'subjectAltName' in cert:
                for type_name, alt_name in cert['subjectAltName']:
                    if type_name == 'DNS' and (alt_name == domain or alt_name.startswith('*.')):
                        domain_match = True
                        break
            
            features['domain_match'] = int(domain_match)
            
            # Verificar tipo de certificado (EV, OV, DV)
            # Geralmente, Certificados EV têm informações organizacionais mais ricas
            subject = dict(x[0] for x in cert['subject'])
            has_org_info = 'organizationName' in subject
            features['has_org_info'] = int(has_org_info)
            
            return features
            
        except Exception as e:
            # Em caso de erro, retornar características vazias
            return self._empty_features()
    
    def _empty_features(self):
        """Retorna um dicionário de características vazias quando não há SSL"""
        return {
            'has_ssl': 0,
            'trusted_issuer': 0,
            'days_to_expiry': -1,
            'is_expired': 1,
            'domain_match': 0,
            'has_org_info': 0
        }