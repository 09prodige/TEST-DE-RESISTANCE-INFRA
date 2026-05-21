# Équipe Agentique — Resistance Infrastructure Gabon

## Structure

| Agent | Mode | Rôle |
|-------|------|------|
| `project-manager` | primary | Vision, roadmap, validation livrables |
| `scrum-master` | **default** | Sprints, GitHub Projects, coordination |
| `software-engineer` | subagent | Code Python, modules scanner |
| `devops-engineer` | subagent | CI/CD, GitHub Actions, opencode.json |
| `qa-engineer` | subagent | Tests pytest, validation modules |
| `cybersecurity-engineer` | subagent | Audit OWASP, pentest, read-only |
| `token-optimizer` | subagent | Optimisation tokens, RTK, compaction |

## Workflow

```
Vision (project-manager)
  → Sprint Planning (scrum-master)
    → [token-optimizer] audit avant délégation
    → Développement (software-engineer)
    → Infrastructure (devops-engineer)
    → Tests (qa-engineer)
    → Audit sécurité (cybersecurity-engineer)
  → Sprint Review (scrum-master + project-manager)
  → Merge PR → Done
```

## Conventions
- Langue communication : **français**
- Langue code/commentaires : **anglais**
- Format : Markdown (GitHub Flavored)
- Modèle : `meta/llama-3.1-70b-instruct` (NVIDIA)

## Board Kanban
`Backlog → Sprint → In Progress → Review → Done`

## Définition of Done
- [ ] Critères d'acceptation validés
- [ ] Tests QA passés
- [ ] Audit cybersecurity-engineer validé (CRITICAL bloque merge)
- [ ] PR mergée sur `main`
- [ ] Issue fermée sur GitHub Projects
