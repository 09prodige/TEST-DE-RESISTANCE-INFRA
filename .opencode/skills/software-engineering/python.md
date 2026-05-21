# Software Engineering — Standards Python

## Conventions
- Python 3.11+ exclusivement
- stdlib en priorité, dépendances externes minimales
- `if __name__ == "__main__":` obligatoire dans chaque module
- Commentaires en anglais
- Communication équipe en français

## Structure projet
```
src/
  cli.py              # Click entry point
  core/
    scanner.py        # orchestrateur
    report.py         # générateur rapports
  modules/
    recon/            # reconnaissance
    web/              # analyse web
    vuln/             # scan vulnérabilités
  utils/
    http.py           # client HTTP
    logger.py         # logging structuré
tests/
  test_recon.py
  test_web.py
  test_vuln.py
```

## Dépendances autorisées
- `requests` — HTTP
- `click` — CLI
- `dnspython` — DNS
- `python-whois` — WHOIS
- `cryptography` — SSL/TLS
- `beautifulsoup4` — HTML parsing
- `rich` — terminal output
- `pytest` — tests

## Tests
- pytest dans `tests/`
- Mocks pour appels réseau (unit tests)
- Pas de dépendance API payante dans les tests
