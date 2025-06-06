import glob

# Lista de sites legítimos (adicione mais se quiser)
legit_urls = [
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://www.google.com",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.netflix.com",
    "https://www.paypal.com",
    "https://www.reddit.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.youtube.com",
    "https://www.ebay.com",
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.forbes.com"
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
