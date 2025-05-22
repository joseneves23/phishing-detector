import requests
from urllib3.exceptions import InsecureRequestWarning
import time

# Suprimir avisos sobre certificados inválidos
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def safe_request(url, timeout=5, max_retries=2):
    """
    Realiza um request HTTP com segurança, tratando exceções e timeouts
    
    Args:
        url: URL para fazer o request
        timeout: Tempo máximo de espera em segundos
        max_retries: Número máximo de tentativas
    
    Returns:
        Objeto Response ou None em caso de falha
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,  # Ignorar erros de SSL
                allow_redirects=True
            )
            return response
        except (requests.exceptions.RequestException, 
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError):
            if attempt < max_retries - 1:
                time.sleep(1)  # Aguardar um pouco antes de tentar novamente
            continue
    
    return None

def is_valid_url(url):
    """Verifica se uma URL é válida"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False