# DevOps — CI/CD GitHub Actions

## Pipeline multi-étapes
```
lint → test → security → build
```

## Contraintes
- Timeout jobs : 15 minutes max
- Artefacts tests : rétention 7 jours
- Secrets : GitHub Secrets natif, jamais hardcodés
- Tests obligatoires avant merge
- Branches : `devops/<feature>`

## Workflow type
```yaml
on:
  push:
    branches: [main, "devops/**", "feature/**"]
  pull_request:
    branches: [main]
```

## Outils CI
- `flake8` — lint Python
- `pytest` — tests
- `bandit` — audit sécurité code
- `safety` — audit dépendances CVE

## GitHub Projects
- Board Kanban : Backlog → Sprint → In Progress → Review → Done
- Issues liées aux PRs via `gh`
- Labels : recon, web-analysis, vulnerability, reporting, setup, bug
