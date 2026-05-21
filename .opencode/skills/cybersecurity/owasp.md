# OWASP Top 10 — Référence

## Web Application Top 10 (2021)
| ID | Nom | Check |
|----|-----|-------|
| A01 | Broken Access Control | Contrôles d'accès sur endpoints |
| A02 | Cryptographic Failures | SSL/TLS, données sensibles en clair |
| A03 | Injection | SQLi, XSS, command injection |
| A04 | Insecure Design | Architecture non sécurisée |
| A05 | Security Misconfiguration | Headers manquants, configs par défaut |
| A06 | Vulnerable Components | Dépendances avec CVE connues |
| A07 | Auth Failures | Session management, brute force |
| A08 | Software Integrity Failures | Supply chain |
| A09 | Logging Failures | Monitoring et alerting insuffisants |
| A10 | SSRF | Server-Side Request Forgery |

## LLM Top 10 (agents opencode)
| ID | Nom |
|----|-----|
| LLM01 | Prompt Injection |
| LLM02 | Insecure Output Handling |
| LLM03 | Training Data Poisoning |
| LLM04 | Model Denial of Service |
| LLM05 | Supply Chain Vulnerabilities |
| LLM06 | Sensitive Information Disclosure |
| LLM07 | Insecure Plugin Design |
| LLM08 | Excessive Agency |
| LLM09 | Overreliance |
| LLM10 | Model Theft |

## Headers de sécurité à vérifier
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
