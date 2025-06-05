import glob

# Lista de sites legítimos (adicione mais se quiser)
legit_urls = [
    "http://www.apple.com",
    "http://www.microsoft.com",
    "http://www.google.com",
    "http://www.amazon.com",
    "http://www.facebook.com",
    "http://www.twitter.com",
    "http://www.linkedin.com",
    "http://www.instagram.com",
    "http://www.netflix.com",
    "http://www.paypal.com",
    "http://www.reddit.com",
    "http://www.wikipedia.org",
    "http://www.github.com",
    "http://www.stackoverflow.com",
    "http://www.youtube.com",
    "http://www.ebay.com",
    "http://www.bbc.com",
    "http://www.cnn.com",
    "http://www.nytimes.com",
    "http://www.forbes.com"
]

# Caminho para os ficheiros de phishing (ajuste conforme necessário)
phishing_files = glob.glob('data/phishing*.txt')

with open('data/urls_train.csv', 'w', encoding='utf-8') as out:
    out.write('url,is_phishing\n')
    # Adiciona sites legítimos
    for url in legit_urls:
        out.write(f"{url},0\n")
    # Adiciona URLs de phishing
    for fname in phishing_files:
        with open(fname, encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('//') and not url.startswith('!'):
                    out.write(f"{url},1\n")