---
name: devops
description: DevOps — CI/CD GitHub Actions, ruff, pytest, bandit, automation, GitHub Projects
---

# Skill: devops

## Pipeline CI/CD
```
lint (ruff + mypy) → test (pytest) → security (bandit + safety) → merge
```

## Contraintes
- Timeout jobs : 15 minutes max
- Artefacts tests : rétention 7 jours
- Secrets : GitHub Secrets natif, jamais hardcodés
- Tests obligatoires avant merge PR
- Branches de travail : `devops/<feature>` ou `feature/<name>`

## Outils CI
- `ruff` — lint Python (remplace flake8, isort, pyupgrade)
- `mypy` — typage statique
- `pytest` — tests unitaires et intégration
- `bandit` — audit sécurité code source
- `safety` — audit dépendances (CVE)

## Workflow type
```yaml
on:
  push:
    branches: [main, "devops/**", "feature/**"]
  pull_request:
    branches: [main]
```

## GitHub Projects — Board Kanban
Colonnes : `Backlog → Sprint → In Progress → Review → Done`

### Automation
- Issue ouverte → Backlog
- PR ouverte → In Progress
- PR ready for review → Review
- PR mergée / issue fermée → Done

## Labels projet
- `sprint-1` `sprint-2` `sprint-3` `sprint-4` `sprint-5`
- `epic` `enhancement` `bug` `security` `test` `docs` `infra`

## Checklist DevOps
- [ ] CI workflow fonctionnel et testé
- [ ] Dépendances dans `requirements.txt`
- [ ] Secrets dans GitHub Secrets
- [ ] `opencode.json` JSON valide
- [ ] Badges CI à jour dans README
- [ ] `ruff` passe sans erreur sur `src/` et `tests/`
