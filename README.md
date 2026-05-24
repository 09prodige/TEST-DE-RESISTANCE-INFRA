# 🔒 RIG Security Scanner

**Resistance Infrastructure Gabon** — Scanner de sécurité web autonome.
Audit de vulnérabilités complet : reconnaissance, analyse web, tests d'intrusion OWASP Top 10, reporting CVSS.

[![CI](https://github.com/09prodige/TEST-DE-RESISTANCE-INFRA/actions/workflows/ci.yml/badge.svg)](https://github.com/09prodige/TEST-DE-RESISTANCE-INFRA/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-396%20passing-brightgreen)

---

## ✨ Fonctionnalités

| Module | Capacités |
|--------|-----------|
| **🔍 Recon** | DNS (A/MX/NS/TXT/CNAME), WHOIS, sous-domaines (bruteforce + crt.sh), scan TCP (100+ ports) |
| **🌐 Web** | Analyse en-têtes sécurité (HSTS, CSP, XFO…), audit SSL/TLS, crawler depth-2, fingerprint CMS (14 techs) |
| **⚔️ Vuln** | SQLi error-based & boolean-based (5 bases), XSS reflected (13 payloads), CSRF, fichiers sensibles (50+ chemins), Open Redirect |
| **📊 Reporting** | CVSS v3.1, rapport HTML (Jinja2), JSON, PDF — coloré, résumé exécutif, grade A→F |
| **🖥️ Interface Web** | Dashboard local Flask, saisie cible, suivi temps réel, téléchargement 1 clic |

---

## 🚀 Installation

```bash
# Cloner
git clone https://github.com/09prodige/TEST-DE-RESISTANCE-INFRA.git
cd TEST-DE-RESISTANCE-INFRA

# Environnement virtuel
python -m venv venv
source venv/bin/activate   # Linux/Mac
# ou  venv\Scripts\activate  # Windows

# Dépendances
pip install -r requirements.txt
```

---

## 🖥️ Utilisation

### Interface Web (recommandée)

```bash
python run_webui.py
```

Ouvrir **http://127.0.0.1:5000** dans le navigateur.

Fonctionnalités :
- Champ de saisie : URL cible
- Sélection des modules (recon, web, vuln) par checkboxes
- Suivi en direct avec barre de progression
- Résultats visuels : grade, bar chart sévérité, badges couleur
- Téléchargement des rapports en 1 clic (JSON / HTML / PDF)
- Historique complet des scans (base SQLite locale)

### Ligne de commande (CLI)

```bash
# Scan complet (recon + web + vuln)
python -m src.cli scan https://example.com

# Modules spécifiques
python -m src.cli scan https://example.com -m recon -m web

# Format de sortie
python -m src.cli scan https://example.com -f html -o reports/audit

# Avec fichier de configuration
python -m src.cli scan https://example.com -c config/rig.yml

# Mode silencieux (chemin du rapport seulement)
python -m src.cli scan https://example.com -q

# Mode verbeux (affichage temps réel des findings)
python -m src.cli scan https://example.com -v

# Aide
python -m src.cli scan --help
```

#### Options CLI

| Option | Description |
|--------|-------------|
| `target` | URL ou domaine à scanner (obligatoire) |
| `-m, --modules` | Modules : `recon`, `web`, `vuln` (défaut: `all`) |
| `-o, --output` | Chemin du rapport (défaut: `reports/report`) |
| `-f, --format` | Format : `json`, `html`, `pdf` (défaut: `json`) |
| `-c, --config` | Chemin fichier YAML de configuration |
| `-v, --verbose` | Affichage détaillé en temps réel |
| `-q, --quiet` | Mode silencieux |

### 🐳 Docker

```bash
# Construire l'image
make build

# Lancer un scan
make scan target=https://example.com

# Scan complet
make scan-full target=https://example.com

# Scan rapide (recon uniquement)
make scan-quick target=https://example.com

# Shell interactif dans le conteneur
make shell

# Ou directement avec Docker Compose :
docker compose run --rm rig-scanner scan example.com -f html
```

### ⚙️ Configuration YAML

Créez un fichier `config/rig.yml` ou `rig.yml` :

```yaml
scan:
  timeout: 30
  max_threads: 20
  rate_limit: 10
  user_agent: "RIG-Scanner/0.2"

modules:
  recon:
    port_range: [1, 10000]
    dns_timeout: 5
  web:
    crawl_depth: 2
    ssl_timeout: 10
  vuln:
    sqli_payloads: default
    xss_payloads: default

reporting:
  format: html
  output_dir: reports/
  cvss_version: "3.1"
```

Le fichier est cherché automatiquement dans :
1. `./rig.yml` (racine du projet)
2. `./config/rig.yml`
3. `~/.config/rig/config.yml`

Exemple complet : [`config/rig.example.yml`](config/rig.example.yml)

---

## 📁 Structure du projet

```
RIG/
├── run_webui.py              # ← Interface web (point d'entrée)
├── src/
│   ├── cli.py                # CLI (Click + Rich)
│   ├── config.py             # Configuration YAML
│   ├── core/
│   │   ├── scanner.py        # Orchestrateur (ThreadPoolExecutor)
│   │   └── report.py         # Rapport JSON/HTML/PDF
│   ├── modules/
│   │   ├── recon/            # DNS, WHOIS, subdomains, portscan
│   │   ├── web/              # Headers, SSL, crawler, fingerprint
│   │   └── vuln/             # SQLi, XSS, CSRF, fichiers, redirect
│   ├── reporting/
│   │   ├── cvss.py           # Calculateur CVSS v3.1
│   │   └── templates/        # Template Jinja2
│   ├── utils/
│   │   ├── http.py           # Client HTTP + RateLimiter
│   │   └── logger.py         # Logger structuré
│   └── webui/                # Interface Flask
│       ├── app.py
│       ├── db.py             # SQLite
│       ├── templates/        # Jinja2 (dark theme)
│       └── static/           # CSS + JS
├── config/
│   └── rig.example.yml
├── reports/                  # Rapports générés
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```

---

## 🧪 Tests

```bash
# Tous les tests
python -m pytest tests/ -v

# Tests par module
python -m pytest tests/test_recon.py -v
python -m pytest tests/test_web.py -v
python -m pytest tests/test_vuln.py -v
python -m pytest tests/test_reporting.py -v
python -m pytest tests/test_cli.py -v
python -m pytest tests/test_async.py -v
python -m pytest tests/test_core.py -v

# Avec couverture
python -m pytest tests/ --cov=src -v
```

**396 tests** — couverture complète des modules, mock réseau, edge cases.

---

## 🤖 Architecture agentique (opencode)

Le projet utilise 7 agents coordonnés en Scrum/Kanban :

| Agent | Rôle |
|-------|------|
| `scrum-master` | Coordination, sprints, GitHub Projects (agent par défaut) |
| `project-manager` | Vision, roadmap, validation livrables |
| `software-engineer` | Développement modules Python |
| `devops-engineer` | CI/CD GitHub Actions, Docker, config |
| `qa-engineer` | Tests pytest, validation |
| `cybersecurity-engineer` | Audit OWASP, pentest (read-only) |
| `token-optimizer` | Optimisation tokens, RTK |

```bash
opencode                          # scrum-master (défaut)
opencode --agent software-engineer  # développement
opencode --agent cybersecurity-engineer  # audit sécurité
```

---

## 📜 Éthique

Ce scanner est un outil d'audit de sécurité. Utilisez-le uniquement sur des infrastructures pour lesquelles vous avez une **autorisation écrite explicite**. L'utilisation non autorisée peut être illégale.

---

## 📦 Dépendances

| Package | Utilisation |
|---------|-------------|
| `requests` | Client HTTP |
| `click` | CLI |
| `flask` | Interface web |
| `jinja2` | Templates HTML |
| `rich` | Terminal coloré (progress bars) |
| `dnspython` | Résolution DNS |
| `python-whois` | WHOIS lookup |
| `cryptography` | Audit SSL/TLS |
| `beautifulsoup4` | Parsing HTML (crawler) |
| `pyyaml` | Configuration YAML |
| `pytest` | Tests |
