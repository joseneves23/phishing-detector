from flask import Flask, render_template, request, jsonify
import os
import sys
import pandas as pd

# Adicionar diretório raiz ao path para importar módulos do projeto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import PhishingDetector

app = Flask(__name__)
app.config['SECRET_KEY'] = 'phishing-detector-secret-key'

# Inicializar detector
model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                          'data', 'phishing_model.joblib')

if os.path.exists(model_path):
    detector = PhishingDetector(model_path)
else:
    detector = PhishingDetector()
    
    # Treinar com dataset padrão se disponível
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'data', 'sample_urls.csv')
    if os.path.exists(dataset_path):
        urls_df = pd.read_csv(dataset_path)
        detector.train(urls_df)
        detector.save_model(model_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '')
    if not url:
        return jsonify({
            'error': 'URL não fornecida'
        }), 400
    
    # Garantir que a URL tenha um esquema
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    # Analisar URL
    result = detector.predict(url)
    
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    # Esta função poderia ser usada para coletar feedback dos usuários
    # sobre os resultados do detector, para melhorar o modelo no futuro
    url = request.form.get('url', '')
    is_phishing = request.form.get('is_phishing', '') == 'true'
    
    # Aqui você poderia salvar esse feedback em um arquivo ou banco de dados
    # para usar posteriormente no retreinamento do modelo
    
    return jsonify({'success': True})

@app.route('/bulk_analyze', methods=['POST'])
def bulk_analyze():
    # Endpoint para análise em lote de URLs
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo vazio'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Apenas arquivos CSV são aceitos'}), 400
    
    try:
        # Ler CSV
        urls_df = pd.read_csv(file)
        
        if 'url' not in urls_df.columns:
            return jsonify({'error': 'O arquivo deve conter uma coluna "url"'}), 400
        
        # Analisar URLs
        results = []
        for url in urls_df['url']:
            # Garantir que a URL tenha um esquema
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'http://' + url
            
            result = detector.predict(url)
            results.append({
                'url': url,
                'is_phishing': result['is_phishing'],
                'confidence': result['confidence'],
                'risk_level': result['risk_level']
            })
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)