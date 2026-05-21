# Token Economy — Règles d'optimisation

## Layer 1 — Caveman mode (output)
- Fragments acceptés, pas d'articles inutiles
- Pas de "Bien sûr !", "Absolument !", openers vides
- Pas de résumé final redisant ce qui vient d'être fait
- Réponses 2-3x plus courtes à contenu égal

## Layer 2 — RTK Shell (input)
- Préfixer toutes les commandes bash avec `rtk`
- `rtk git diff` au lieu de `git diff` → ~80% réduction output
- `rtk gain` pour auditer les économies
- `rtk discover` pour identifier les opportunités manquées

## Layer 3 — Agents parallèles
- Chaque sous-agent recharge ~43K tokens de config
- Parallèle uniquement si tâches vraiment indépendantes
- Sinon : séquentiel obligatoire

## Layer 4 — Compaction
- `/compact` manuel à ~50-60% usage contexte
- Autocompact = résumé non contrôlé → éviter si possible
- Vérifier avant délégation longue

## Sélection modèle
| Tâche | Modèle |
|-------|--------|
| Collecte données simple | small/fast |
| Raisonnement, architecture | modèle principal |
| Code complexe, sécurité | modèle principal |
| Tests unitaires simples | small/fast |
