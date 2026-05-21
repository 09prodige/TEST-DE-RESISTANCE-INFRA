# Glossaire — Resistance Infrastructure Gabon

## Concepts Agents & LLM

**Agent** : Programme autonome qui perçoit son environnement, raisonne et agit pour accomplir un objectif. Dans opencode, configuré via frontmatter markdown.

**Default Agent** : Agent chargé automatiquement au lancement d'opencode dans le dossier. Défini par `default_agent` dans `opencode.json`. Ici : `scrum-master`.

**Sub-agent** : Agent secondaire défini dans `.opencode/agents/`, appelé par délégation de tâche (`task`).

**ReAct Loop** : Cycle Reasoning → Action → Observation permettant à l'agent d'interagir dynamiquement avec ses outils.

**Tool Calling** : Capacité du LLM à générer des appels de fonctions structurés (JSON) exécutés par le runtime.

**Compaction** : Résumé automatique de l'historique de conversation pour éviter la saturation du contexte.

**Permissions** : Règles définissant les capacités d'un agent (`allow`, `deny`, `ask`).

## Architecture & Workflow

**MCP** (Model Context Protocol) : Protocole standardisé connectant les LLMs à des outils externes, fichiers, APIs.

**Hooks** : Points du cycle de vie opencode (`preToolUse`, `postToolUse`) déclenchant des actions automatisées.

**Handoff** : Transfert de session entre agents ou environnements.

**StateGraph** : Dans LangGraph, graphe dirigé où des nœuds Python modifient un état typé.

## Sécurité Pentest

**OWASP Top 10** : Liste des 10 risques de sécurité web les plus critiques (mise à jour 2021).

**OWASP LLM Top 10** : Liste des 10 risques spécifiques aux applications LLM (prompt injection, excessive agency…).

**CVSS** : Common Vulnerability Scoring System — système de scoring de sévérité (0.0 à 10.0).

**Recon** : Phase de reconnaissance — collecte d'informations sur la cible (passive et active).

**Fingerprinting** : Identification des technologies utilisées par une cible web (framework, serveur, CMS…).

**SQLi** : SQL Injection — injection de code SQL malveillant dans les inputs d'une application.

**XSS** : Cross-Site Scripting — injection de scripts dans une page web consultée par d'autres utilisateurs.

**CSRF** : Cross-Site Request Forgery — forcer un utilisateur authentifié à exécuter des actions non désirées.

**SSRF** : Server-Side Request Forgery — forcer le serveur à faire des requêtes vers des ressources internes.

## Token Economy

**RTK** : Rust Token Killer — proxy CLI filtrant les outputs shell pour réduire les tokens (~80% d'économie).

**Caveman Mode** : Mode de sortie compressé — fragments acceptés, pas d'openers vides, 2-3x plus court.

**Context Window** : Nombre maximum de tokens qu'un modèle traite en une inférence.

**KV Cache** : Mémoire GPU stockant les paires clé-valeur d'attention — goulot d'étranglement pour les longues séquences.
