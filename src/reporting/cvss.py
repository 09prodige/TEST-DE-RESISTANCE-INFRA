"""CVSS v3.1 Base Score Calculator (US-16).

Implements the CVSS v3.1 base score calculation according to
the FIRST specification. Supports vector string generation,
score computation, severity classification, and automated
finding classification from scanner results.
"""

from __future__ import annotations

import math
from typing import Any, Literal

# --- CVSS v3.1 Metric Definitions ---

AV = Literal["N", "A", "L", "P"]  # Attack Vector
AC = Literal["L", "H"]            # Attack Complexity
PR = Literal["N", "L", "H"]       # Privileges Required
UI = Literal["N", "R"]            # User Interaction
S = Literal["U", "C"]             # Scope
CIA = Literal["H", "L", "N"]      # Confidentiality / Integrity / Availability

SeverityLabel = Literal["None", "Low", "Medium", "High", "Critical"]

# Metric value → numeric score mappings (CVSS v3.1)
AV_SCORES: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_SCORES: dict[str, float] = {"L": 0.77, "H": 0.44}
PR_SCORES: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_SCORES_SCOPE_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.5}
UI_SCORES: dict[str, float] = {"N": 0.85, "R": 0.62}
CIA_SCORES: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}

# Severity thresholds (CVSS v3.1)
SEVERITY_THRESHOLDS: list[tuple[float, SeverityLabel]] = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
]


def _roundup(value: float) -> float:
    """Round up to 1 decimal place per CVSS v3.1 spec."""
    int_value = int(value * 100_000)
    if int_value % 10_000 == 0:
        return int_value / 100_000.0
    return (math.floor(int_value / 10_000) + 1) / 10.0


def _compute_iss(c: float, i: float, a: float) -> float:
    """Compute the Impact Sub-Score (ISS)."""
    return 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)


def calculate_score(
    attack_vector: AV = "N",
    attack_complexity: AC = "L",
    privileges_required: PR = "N",
    user_interaction: UI = "N",
    scope: S = "U",
    confidentiality: CIA = "H",
    integrity: CIA = "H",
    availability: CIA = "H",
) -> dict[str, Any]:
    """Calculate CVSS v3.1 base score from individual metrics.

    Args:
        attack_vector: Network (N), Adjacent (A), Local (L), Physical (P)
        attack_complexity: Low (L), High (H)
        privileges_required: None (N), Low (L), High (H)
        user_interaction: None (N), Required (R)
        scope: Unchanged (U), Changed (C)
        confidentiality: High (H), Low (L), None (N)
        integrity: High (H), Low (L), None (N)
        availability: High (H), Low (L), None (N)

    Returns:
        Dict with:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict containing ``vector``, ``base_score``,
          ``severity``, ``metrics``
    """
    try:
        # Validate inputs
        _validate_metric("AV", attack_vector, list(AV_SCORES.keys()))
        _validate_metric("AC", attack_complexity, list(AC_SCORES.keys()))
        _validate_metric("PR", privileges_required, list(PR_SCORES.keys()))
        _validate_metric("UI", user_interaction, list(UI_SCORES.keys()))
        _validate_metric("S", scope, ["U", "C"])
        _validate_metric("C", confidentiality, list(CIA_SCORES.keys()))
        _validate_metric("I", integrity, list(CIA_SCORES.keys()))
        _validate_metric("A", availability, list(CIA_SCORES.keys()))

        # Lookup numeric scores
        av = AV_SCORES[attack_vector]
        ac = AC_SCORES[attack_complexity]
        pr = PR_SCORES_SCOPE_CHANGED[privileges_required] if scope == "C" else PR_SCORES[privileges_required]
        ui = UI_SCORES[user_interaction]
        c = CIA_SCORES[confidentiality]
        i = CIA_SCORES[integrity]
        a = CIA_SCORES[availability]

        # Impact Sub-Score (ISS)
        iss = _compute_iss(c, i, a)

        # Impact score depends on Scope
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15.0

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base score computation
        if impact <= 0.0:
            base_score = 0.0
        else:
            base_score = _roundup(min(impact + exploitability, 10.0))
            if scope == "C":
                base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

        # Build vector string
        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
            f"/PR:{privileges_required}/UI:{user_interaction}"
            f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        severity = _score_to_severity(base_score)

        return {
            "status": "success",
            "data": {
                "vector": vector,
                "base_score": round(base_score, 1),
                "severity": severity,
                "metrics": {
                    "attack_vector": attack_vector,
                    "attack_complexity": attack_complexity,
                    "privileges_required": privileges_required,
                    "user_interaction": user_interaction,
                    "scope": scope,
                    "confidentiality": confidentiality,
                    "integrity": integrity,
                    "availability": availability,
                },
            },
        }
    except (ValueError, KeyError, TypeError) as exc:
        return {
            "status": "error",
            "data": {},
            "error": str(exc),
        }


def _validate_metric(name: str, value: str, allowed: list[str]) -> None:
    """Validate a CVSS metric value."""
    if value not in allowed:
        raise ValueError(
            f"Invalid {name} value: {value!r}. "
            f"Must be one of {allowed}"
        )


def _score_to_severity(score: float) -> SeverityLabel:
    """Convert a CVSS v3.1 numeric score to severity label.

    Args:
        score: Numeric score from 0.0 to 10.0.

    Returns:
        ``"None"``, ``"Low"``, ``"Medium"``, ``"High"``, or ``"Critical"``.
    """
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "None"


def severity_to_cvss_metrics(severity: str) -> dict[str, str]:
    """Map a severity label to representative CVSS v3.1 metrics.

    Used for quick scoring when full metrics are not available.

    Args:
        severity: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
                  or ``"info"``.

    Returns:
        Dict of CVSS metric value strings for that severity level.
    """
    severity_map: dict[str, dict[str, str]] = {
        "critical": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "high": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "medium": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "low": {
            "attack_vector": "N",
            "attack_complexity": "H",
            "privileges_required": "L",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        "info": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "N",
            "availability": "N",
        },
    }
    return severity_map.get(severity, severity_map["info"])


# --- Vulnerability Type → CVSS Mapping ---
# Maps known vulnerability types to their typical CVSS v3.1 metrics.
VULN_TYPE_METRICS: dict[str, dict[str, str]] = {
    "sqli": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "H",
        "availability": "H",
    },
    "xss": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "R",
        "scope": "U",
        "confidentiality": "L",
        "integrity": "L",
        "availability": "N",
    },
    "csrf": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "R",
        "scope": "U",
        "confidentiality": "N",
        "integrity": "L",
        "availability": "N",
    },
    "sensitive_files": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "N",
        "availability": "N",
    },
    "open_redirect": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "R",
        "scope": "U",
        "confidentiality": "N",
        "integrity": "L",
        "availability": "N",
    },
    "ssl_tls": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "L",
        "availability": "N",
    },
    "headers": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "L",
        "integrity": "N",
        "availability": "N",
    },
}


def classify_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Classify a scanner finding with a CVSS v3.1 score.

    Examines the finding dict for ``type``, ``severity``, and
    ``cvss_score`` fields. If a ``cvss_score`` already exists,
    it returns it directly. Otherwise, it attempts to map the
    vulnerability type to standard CVSS metrics and compute
    the base score.

    Args:
        finding: A vulnerability finding dict from any scanner module.
                 Expected to contain at least ``type`` or ``name``.

    Returns:
        Dict with ``status`` and ``data`` containing:
        - ``vector``: CVSS vector string
        - ``base_score``: Numeric score 0.0–10.0
        - ``severity``: Severity label
        - ``metrics``: Individual metric values
        - ``source``: How the score was determined
    """
    # If finding already has a CVSS score, use it
    existing_score = finding.get("cvss_score")
    if existing_score is not None and isinstance(existing_score, (int, float)):
        sev = finding.get("severity", _score_to_severity(existing_score))
        return {
            "status": "success",
            "data": {
                "vector": "",
                "base_score": round(float(existing_score), 1),
                "severity": sev.capitalize() if sev else "None",
                "metrics": {},
                "source": "finding",
            },
        }

    # Try to map by vulnerability type
    vuln_type = (finding.get("type") or finding.get("name") or "").lower()
    scoring_method: str = "mapped"

    # Try exact match on vulnerability type key
    for key, metrics in VULN_TYPE_METRICS.items():
        if key in vuln_type:
            result = calculate_score(**metrics)  # type: ignore[arg-type]
            result["data"]["source"] = "mapped"
            return result

    # Fallback: map by severity
    severity = (finding.get("severity") or "medium").lower()
    metrics = severity_to_cvss_metrics(severity)
    result = calculate_score(**metrics)  # type: ignore[arg-type]
    result["data"]["source"] = "severity_fallback"
    return result


def get_score_from_severity(severity: str) -> float:
    """Get a representative CVSS score for a given severity level.

    Args:
        severity: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
                  ``"info"``, or ``"None"``.

    Returns:
        A numeric score representative of the severity tier.
    """
    score_map = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
        "none": 0.0,
    }
    return score_map.get(severity.lower(), 0.0)


if __name__ == "__main__":
    # Demo: calculate scores for common vulnerability types
    test_cases = [
        ("SQL Injection", {"attack_vector": "N", "attack_complexity": "L",
                           "privileges_required": "N", "user_interaction": "N",
                           "scope": "U", "confidentiality": "H",
                           "integrity": "H", "availability": "H"}),
        ("Reflected XSS", {"attack_vector": "N", "attack_complexity": "L",
                           "privileges_required": "N", "user_interaction": "R",
                           "scope": "U", "confidentiality": "L",
                           "integrity": "L", "availability": "N"}),
        ("CSRF", {"attack_vector": "N", "attack_complexity": "L",
                  "privileges_required": "N", "user_interaction": "R",
                  "scope": "U", "confidentiality": "N",
                  "integrity": "L", "availability": "N"}),
    ]

    print("CVSS v3.1 Base Score Calculator — Demo")
    print("=" * 50)
    for name, metrics in test_cases:
        result = calculate_score(**metrics)  # type: ignore[arg-type]
        if result["status"] == "success":
            data = result["data"]
            print(f"\n{name}:")
            print(f"  Vector:     {data['vector']}")
            print(f"  Base Score: {data['base_score']}")
            print(f"  Severity:   {data['severity']}")
        else:
            print(f"\n{name}: ERROR — {result.get('error')}")
