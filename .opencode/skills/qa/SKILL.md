---
name: qa
description: QA & Tests — pytest, mocks réseau, fixtures, benchmarks, validation modules scanner
---

# Skill: qa

## Framework
- `pytest` (sans dépendances lourdes)
- Mocks pour appels réseau dans unit tests (`unittest.mock`, `responses`)
- Tests d'intégration séparés : `@pytest.mark.integration`

## Structure tests
```
tests/
  conftest.py       # fixtures partagées
  test_core.py      # scanner + report
  test_recon.py     # module recon
  test_web.py       # module web analysis
  test_vuln.py      # module vulnerability
  test_report.py    # report HTML/PDF/JSON
```

## Checklist QA par module
- [ ] `if __name__ == "__main__":` présent dans chaque fichier
- [ ] Imports disponibles sans API payante
- [ ] Tests reproductibles (pas de dépendance réseau en unit test)
- [ ] Pas de faux positifs dans les scanners
- [ ] Couverture minimale : fonctions publiques testées
- [ ] Benchmarks documentés et reproductibles

## Format rapport findings
```
[SÉVÉRITÉ] fichier:ligne — description — recommandation
```
Sévérités : `LOW | MEDIUM | HIGH | CRITICAL`

## Fixtures type
```python
@pytest.fixture
def mock_response():
    """Mock HTTP response for testing without network."""
    ...

@pytest.fixture
def sample_target():
    return "https://example.com"
```

## Commandes
```bash
python -m pytest tests/ -v --tb=short
python -m pytest tests/ -v -m "not integration"
python -m pytest tests/ -v -m integration
```
