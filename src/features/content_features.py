import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from src.utils import safe_request

class ContentFeatureExtractor:
    """Extrai características do conteúdo da página para detecção de phishing"""
    
    def extract_features(self, url):
        """Extrai todas as características do conteúdo de uma página"""
        features = {}
        
        # Tentar fazer request para obter o conteúdo da página
        response = safe_request(url)
        if not response:
            # Se não conseguir acessar, retornar características vazias
            return self._empty_features()
        
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Características dos formulários
        features.update(self._form_features(soup, url))
        
        # Características de links e recursos externos
        features.update(self._external_resource_features(soup, url))
        
        # Características de redirecionamento
        features.update(self._redirect_features(soup, response))
        
        # Características do conteúdo textual
        features.update(self._text_content_features(soup))
        
        return features
    
    def _empty_features(self):
        """Retorna um dicionário de características vazias quando não há conteúdo"""
        return {
            'has_form': 0,
            'form_with_password': 0,
            'form_external_action': 0,
            'external_resource_ratio': 0,
            'external_link_ratio': 0,
            'has_redirect': 0,
            'visible_links_count': 0,
            'invisible_links_count': 0,
            'url_in_title': 0,
            'suspicious_text_score': 0
        }
    
    def _form_features(self, soup, url):
        """Analisa características dos formulários na página"""
        features = {}
        
        # Buscar todos os formulários
        forms = soup.find_all('form')
        features['has_form'] = int(len(forms) > 0)
        
        # Verificar se há campos de senha nos formulários
        password_inputs = soup.find_all('input', {'type': 'password'})
        features['form_with_password'] = int(len(password_inputs) > 0)
        
        # Verificar se algum formulário envia dados para domínios externos
        base_domain = urlparse(url).netloc
        external_action = 0
        
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith('http'):
                form_domain = urlparse(action).netloc
                if form_domain and form_domain != base_domain:
                    external_action = 1
                    break
        
        features['form_external_action'] = external_action
        
        return features
    
    def _external_resource_features(self, soup, url):
        """Analisa recursos externos (imagens, scripts, etc.)"""
        features = {}
        
        base_domain = urlparse(url).netloc
        
        # Contar recursos internos e externos
        resources = []
        resources.extend(soup.find_all('img'))
        resources.extend(soup.find_all('script'))
        resources.extend(soup.find_all('link', {'rel': 'stylesheet'}))
        
        if not resources:
            features['external_resource_ratio'] = 0
            features['external_link_ratio'] = 0
            return features
        
        external_count = 0
        for res in resources:
            src = res.get('src') or res.get('href') or ''
            if src.startswith('http'):
                res_domain = urlparse(src).netloc
                if res_domain and res_domain != base_domain:
                    external_count += 1
        
        # Calcular proporção de recursos externos
        features['external_resource_ratio'] = external_count / len(resources) if resources else 0
        
        # Análise de links
        links = soup.find_all('a')
        if not links:
            features['external_link_ratio'] = 0
        else:
            external_links = 0
            for link in links:
                href = link.get('href', '')
                if href.startswith('http'):
                    link_domain = urlparse(href).netloc
                    if link_domain and link_domain != base_domain:
                        external_links += 1
            
            features['external_link_ratio'] = external_links / len(links) if links else 0
        
        return features
    
    def _redirect_features(self, soup, response):
        """Analisa características de redirecionamento"""
        features = {}
        
        # Verificar redirecionamentos via meta refresh
        meta_refresh = soup.find('meta', {'http-equiv': re.compile('^refresh$', re.I)})
        
        # Verificar redirecionamentos via JavaScript
        scripts = soup.find_all('script')
        js_redirect = False
        for script in scripts:
            script_text = script.string if script.string else ''
            if 'window.location' in script_text or 'document.location' in script_text:
                js_redirect = True
                break
        
        # Verificar redirecionamentos HTTP
        http_redirect = len(response.history) > 0
        
        features['has_redirect'] = int(bool(meta_refresh) or js_redirect or http_redirect)
        
        return features
    
    def _text_content_features(self, soup):
        """Analisa o conteúdo textual da página"""
        features = {}
        
        # Contar links visíveis e invisíveis
        links = soup.find_all('a')
        invisible_count = 0
        for link in links:
            # Verificar estilo inline para visibilidade
            style = link.get('style', '')
            if 'display:none' in style or 'visibility:hidden' in style:
                invisible_count += 1
        
        features['visible_links_count'] = len(links) - invisible_count
        features['invisible_links_count'] = invisible_count
        
        # Verificar se o domínio aparece no título
        title = soup.find('title')
        if title and title.text:
            base_url = urlparse(soup.get('url', '')).netloc
            features['url_in_title'] = int(base_url in title.text.lower())
        else:
            features['url_in_title'] = 0
        
        # Pontuação para palavras suspeitas no texto
        body_text = soup.get_text().lower()
        suspicious_phrases = [
            'verify your account', 'update your information',
            'limited time', 'urgent action required', 'suspicious activity',
            'problem with your account', 'confirm your details',
            'your account will be locked', 'security alert'
        ]
        
        score = 0
        for phrase in suspicious_phrases:
            if phrase in body_text:
                score += 1
        
        features['suspicious_text_score'] = score
        
        return features