---
name: project-management
description: Project management — roadmap, sprints, GitHub Projects, Scrum/Kanban, Definition of Done
---

# Skill: project-management

## Roadmap Resistance Infrastructure Gabon

| Sprint | Thème | Epic |
|--------|-------|------|
| Sprint 1 | Cartographie de la cible | Module Recon |
| Sprint 2 | Analyse de la surface exposée | Module Web Analysis |
| Sprint 3 | Détection de vulnérabilités | Module Vuln |
| Sprint 4 | Rapports exploitables | Reporting HTML/PDF |
| Sprint 5 | Production-ready | Infrastructure & DX |

## Board Kanban GitHub Projects
Colonnes : `Backlog → Sprint → In Progress → Review → Done`

## Cérémonies Scrum
- **Sprint Planning** : sélection issues + estimation + assignation agents
- **Daily** : Done? En cours? Bloqué?
- **Sprint Review** : demo livrables, validation
- **Rétro** : ce qui a marché, améliorations

## Définition of Done
- [ ] Critères d'acceptation validés
- [ ] Tests QA passés (qa-engineer)
- [ ] Audit cybersecurity validé (finding CRITICAL = bloque merge)
- [ ] PR mergée sur `main`
- [ ] Issue fermée et déplacée → Done sur le board

## User Stories format
```
En tant que [rôle], je veux [fonctionnalité] afin de [bénéfice].

Critères d'acceptation :
- [ ] ...
```

## Références
- Scrum Guide (Schwaber & Sutherland)
- OWASP Testing Guide v4.2
- PMBOK (PMI)
