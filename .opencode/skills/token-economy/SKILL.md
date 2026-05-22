---
name: token-economy
description: Token economy — RTK, caveman mode, compaction, sélection modèle, agents parallèles
---

# Skill: token-economy

## Layer 1 — Caveman mode (output tokens)
- Fragments acceptés, pas d'articles inutiles
- Pas de "Bien sûr !", "Absolument !", openers vides
- Pas de résumé final redisant ce qui vient d'être fait
- Réponses 2–3x plus courtes à contenu égal

## Layer 2 — RTK Shell (input tokens)
- Préfixer toutes les commandes bash avec `rtk`
- `rtk git diff` → ~80% réduction output vs `git diff`
- `rtk gain` — auditer les économies de la session
- `rtk discover` — identifier les opportunités manquées

## Layer 3 — Agents parallèles
- Chaque sous-agent recharge ~43K tokens de config
- Parallèle uniquement si tâches vraiment indépendantes
- Sinon : séquentiel obligatoire

## Layer 4 — Compaction
- `/compact` manuel à ~50–60% usage contexte
- Autocompact = résumé non contrôlé → éviter si possible
- Vérifier avant délégation longue

## Sélection modèle par tâche
| Tâche | Modèle recommandé |
|-------|------------------|
| Collecte données, filtrage simple | small/fast |
| Raisonnement complexe, architecture | modèle principal |
| Code complexe, sécurité | modèle principal |
| Tests unitaires simples | small/fast |

## Commandes RTK utiles
```bash
rtk gain              # économies session courante
rtk gain --history    # historique toutes sessions
rtk discover          # analyse opportunités manquées
rtk proxy <cmd>       # exécuter commande sans filtrage (debug)
```
