# Detector de Phishing

Sistema para identificar tentativas de phishing através da análise de URLs e do conteúdo de páginas web.

## Visão Geral

Este projeto implementa um sistema de detecção de phishing baseado em múltiplos indicadores, incluindo:
- **Estrutura e características da URL** (uso de HTTPS, TLD suspeito, presença de IP, etc.)
- **Conteúdo da página** (textos suspeitos, formulários, redirecionamentos)
- **Certificado SSL/TLS** (presença, validade, autoridade emissora)
- **Comportamentos suspeitos** (redirecionamentos automáticos, ações de formulário externas)

O sistema combina esses fatores para classificar um site como potencialmente malicioso ou legítimo, fornecendo também o nível de risco, confiança e os principais indicadores que levaram à classificação.

## Estrutura do Projeto

```
phishing-detector/
├── app/                  # Interface web
├── data/                 # Dados de treino e teste
├── src/                  # Código-fonte do detector
├── tests/                # Testes automatizados
├── requirements.txt
└── README.md
```

## Instalação

1. Clone o repositório:
   ```sh
   git clone https://github.com/?? <!-- Em desenvolvimento-->
   cd phishing-detector
   ```
2. Instale as dependências:
   ```sh
   pip install -r requirements.txt
   ```

## Uso

### Interface Web

Para iniciar a aplicação web:
```sh
python app/app.py
```
Acesse a interface em [http://localhost:5000](http://localhost:5000).

### Linha de Comando

Você também pode testar URLs diretamente pelo terminal:
```sh
python src/detector.py --url "http://exemplo.com"
```

## Testes

Para rodar os testes unitários:
```sh
pytest tests/
```

## Treino do modelo

Para treinar o modelo, basta garantir que o caminho para o arquivo `.csv` está correto dentro do `train.py` e executar o seguinte comando no terminal:

```sh
py train.py
```

## Exemplos de URLs para Teste

**Inseguros / Phishing:**
- http://neverssl.com
- http://expired.badssl.com
- http://secure-paypal.com-login-update-account.info
- http://appleid.apple.com.verify-login.security-alert.com
- http://facebook.com.account-security-alerts.ru

**Legítimos:**
- https://www.google.com
- https://www.paypal.com
- https://www.apple.com
- https://www.facebook.com
- https://www.microsoft.com
