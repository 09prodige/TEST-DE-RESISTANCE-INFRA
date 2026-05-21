# Resistance Infrastructure Gabon

Scanner de sécurité web autonome — audit de vulnérabilités sur sites d'entreprise.

[![CI](https://github.com/09prodige/TEST-DE-RESISTANCE-INFRA/actions/workflows/ci.yml/badge.svg)](https://github.com/09prodige/TEST-DE-RESISTANCE-INFRA/actions/workflows/ci.yml)

## Architecture agentique

7 agents opencode coordonnés par Scrum/Kanban sur GitHub Projects :

| Agent | Rôle |
|-------|------|
| `scrum-master` | Coordination, sprints, GitHub Projects (défaut) |
| `project-manager` | Vision, roadmap, validation |
| `software-engineer` | Code Python (modules scanner) |
| `devops-engineer` | CI/CD, GitHub Actions |
| `qa-engineer` | Tests pytest, validation |
| `cybersecurity-engineer` | Audit OWASP, pentest (read-only) |
| `token-optimizer` | Optimisation tokens, RTK, compaction |

## Modules scanner

- **Recon** — subdomain enumeration, DNS, WHOIS, port scan
- **Web Analysis** — headers HTTP, SSL/TLS, crawler, fingerprinting
- **Vulnerability** — SQLi, XSS, CSRF, OWASP Top 10
- **Reporting** — HTML, JSON, PDF avec scoring CVSS

## Usage

```bash
# Scan complet
python -m src.cli scan https://target.com

# Modules spécifiques
python -m src.cli scan https://target.com -m recon -m web

# Format de sortie
python -m src.cli scan https://target.com -f json -o reports/audit
```

## Lancer opencode

```bash
opencode          # lance avec scrum-master (défaut)
opencode --agent cybersecurity-engineer   # audit sécurité
opencode --agent software-engineer        # développement
```

## Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Éthique
Scanner uniquement les cibles pour lesquelles vous avez une autorisation explicite.
