"""Reporting module — CVSS scoring, report generation, HTML templates.

Provides utilities for:
- CVSS v3.1 score calculation (``cvss``)
- Report generation in JSON, HTML, and PDF formats (via ``core.report``)
"""

from src.reporting.cvss import (
    calculate_score,
    classify_finding,
    get_score_from_severity,
    severity_to_cvss_metrics,
)

__all__ = [
    "calculate_score",
    "classify_finding",
    "get_score_from_severity",
    "severity_to_cvss_metrics",
]
