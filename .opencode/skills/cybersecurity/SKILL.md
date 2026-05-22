---
name: cybersecurity
description: Cybersécurité — pentest web, OWASP Top 10, audit sécurité agents LLM, méthodologie scan
---

# Skill: cybersecurity

## Méthodologie pentest web (5 phases)
1. **Reconnaissance passive** — OSINT, DNS, WHOIS, Google dorks
2. **Reconnaissance active** — ports, services, fingerprinting, crawler
3. **Analyse surfaces d'attaque** — headers, SSL, endpoints, formulaires
4. **Tests de vulnérabilités** — OWASP Top 10, injection, auth
5. **Reporting** — findings classifiés CVSS, remédiation

## OWASP Top 10 Web (2021)
| ID | Nom | Check scanner |
|----|-----|---------------|
| A01 | Broken Access Control | Contrôles d'accès sur endpoints |
| A02 | Cryptographic Failures | SSL/TLS, données sensibles en clair |
| A03 | Injection | SQLi, XSS, command injection |
| A04 | Insecure Design | Architecture non sécurisée |
| A05 | Security Misconfiguration | Headers manquants, configs par défaut |
| A06 | Vulnerable Components | Dépendances avec CVE connues |
| A07 | Auth Failures | Session management, brute force |
| A08 | Software Integrity Failures | Supply chain |
| A09 | Logging Failures | Monitoring insuffisant |
| A10 | SSRF | Server-Side Request Forgery |

## OWASP LLM Top 10 (agents opencode)
| ID | Nom |
|----|-----|
| LLM01 | Prompt Injection |
| LLM02 | Insecure Output Handling |
| LLM03 | Training Data Poisoning |
| LLM05 | Supply Chain Vulnerabilities |
| LLM06 | Sensitive Information Disclosure |
| LLM08 | Excessive Agency |

## Headers HTTP à auditer
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

## Outils intégrés au projet
- `dnspython` — résolution DNS avancée
- `requests` — requêtes HTTP contrôlées
- `beautifulsoup4` — parsing HTML
- `python-whois` — WHOIS lookup
- `cryptography` — audit SSL/TLS

## Checklist sécurité agent (cybersecurity-engineer)
- [ ] Aucun credential hardcodé
- [ ] Injections prompt mitigées
- [ ] Permissions agents minimales (least privilege)
- [ ] Validation inputs sur tool calls
- [ ] Rate limiting implémenté
- [ ] Logging des activités agents
- [ ] Isolation contextes sessions
- [ ] Sanitisation outputs avant exécution

## Format findings
```
[SÉVÉRITÉ] fichier:ligne — description — recommandation
```
Sévérités : `LOW | MEDIUM | HIGH | CRITICAL`
**Finding CRITICAL → bloque le merge PR.**

## Éthique & légalité
- Scanner uniquement cibles autorisées
- Documenter toutes les autorisations avant scan
- Ne jamais persister d'accès non autorisé
- Rapporter toutes les vulnérabilités au client
