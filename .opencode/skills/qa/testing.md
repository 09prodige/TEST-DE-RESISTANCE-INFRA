# QA — Standards de test

## Framework
- pytest (sans dépendances lourdes)
- Mocks pour appels réseau dans unit tests
- Tests d'intégration séparés (marqueur `@pytest.mark.integration`)

## Structure tests
```
tests/
  test_recon.py     # recon module tests
  test_web.py       # web analysis tests
  test_vuln.py      # vulnerability scanner tests
  test_report.py    # report generator tests
  conftest.py       # fixtures partagées
```

## Format reporting findings
```
[SÉVÉRITÉ] fichier:ligne — description — recommandation
```
Sévérités : LOW | MEDIUM | HIGH | CRITICAL

## Checklist QA
- [ ] `if __name__ == "__main__":` présent
- [ ] Imports disponibles (pas d'API payante)
- [ ] Tests reproductibles
- [ ] Pas de faux positifs scanners
- [ ] Benchmarks documentés
