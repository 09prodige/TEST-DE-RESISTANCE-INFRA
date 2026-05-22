---
name: software-engineering
description: Software engineering — Python 3.11+, architecture scanner, Click CLI, conventions code, dépendances autorisées
---

# Skill: software-engineering

## Conventions code
- Python 3.11+ exclusivement
- Stdlib en priorité, dépendances externes minimales
- `if __name__ == "__main__":` obligatoire dans chaque module
- Type hints sur toutes les fonctions publiques
- Commentaires en anglais, communication équipe en français
- Style : PEP 8 (validé par `ruff`)

## Architecture projet
```
src/
  cli.py              # Click entry point
  core/
    scanner.py        # orchestrateur — dispatch modules
    report.py         # générateur rapports (JSON, HTML, PDF)
  modules/
    recon/            # subdomain, dns, whois, portscan
    web/              # headers, ssl, crawler, fingerprint
    vuln/             # sqli, xss, csrf, owasp
  utils/
    http.py           # client HTTP sécurisé (session, retry, rate-limit)
    logger.py         # logging structuré
tests/
  conftest.py
  test_core.py
  test_recon.py
  test_web.py
  test_vuln.py
```

## Dépendances autorisées
| Package | Usage |
|---------|-------|
| `requests` | HTTP client |
| `click` | CLI |
| `dnspython` | DNS resolution |
| `python-whois` | WHOIS lookup |
| `cryptography` | SSL/TLS audit |
| `beautifulsoup4` | HTML parsing |
| `rich` | Terminal output (progress, colors) |
| `jinja2` | HTML report templates |
| `pytest` | Tests |

## Interface module (contrat)
Chaque module expose une fonction `run_<module>(target: str) -> dict` :
```python
def run_recon(target: str) -> dict:
    """Returns structured recon results."""
    return {
        "dns": {...},
        "whois": {...},
        "subdomains": [...],
        "ports": [...]
    }
```

## Sécurité code
- Jamais de credentials hardcodés
- Valider/sanitiser toutes les entrées utilisateur (URL, domaine)
- Rate limiting sur les requêtes réseau
- Timeout sur tous les appels HTTP/DNS/socket
