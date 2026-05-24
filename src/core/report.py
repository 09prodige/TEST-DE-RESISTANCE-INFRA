"""Report generator — JSON, HTML (Jinja2), and PDF reports (US-14..16).

Provides the ``Report`` class that consumes scanner results and
produces structured reports in multiple formats. Supports:
- JSON output with metadata, statistics, and executive summary
- HTML output via Jinja2 template with responsive design
- PDF output via HTML-to-PDF conversion (fallback to HTML-only)

Typical usage::

    from src.core.report import Report

    report = Report(scan_results)
    report.save("reports/scan", fmt="json")
    report.save("reports/scan", fmt="html")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Template path relative to this file
HERE = Path(__file__).resolve().parent
TEMPLATE_DIR = HERE / ".." / "reporting" / "templates"
TEMPLATE_PATH = TEMPLATE_DIR / "report.html"

ReportFormat = Literal["json", "html", "pdf"]


def _load_template() -> str | None:
    """Load the Jinja2 HTML template, returning None if unavailable."""
    try:
        path = TEMPLATE_PATH.resolve()
        if path.exists():
            return path.read_text(encoding="utf-8")
        logger.warning(f"HTML template not found at {path}")
        return None
    except OSError as exc:
        logger.warning(f"Failed to load HTML template: {exc}")
        return None


def _compute_executive_summary(results: dict) -> dict[str, Any]:
    """Compute executive summary statistics from scan results.

    Analyzes the scan results dict (possibly with nested sub-modules)
    to produce:
    - Vulnerability counts by severity
    - Module completion/failure status
    - Overall total findings

    Args:
        results: Raw scanner results dict.

    Returns:
        Dict with ``vuln_summary``, ``stats``, and ``grade``.
    """
    vuln_summary: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    stats: dict[str, int] = {
        "modules_completed": 0,
        "modules_failed": 0,
        "total_findings": 0,
    }

    modules = results.get("modules", {})

    for _module_name, module_data in modules.items():
        _scan_data_node(module_data, vuln_summary, stats)

    # Compute overall grade based on findings
    grade = _compute_grade(vuln_summary)

    return {
        "grade": grade,
        "vuln_summary": vuln_summary,
        "stats": stats,
    }


def _scan_data_node(
    node: Any,
    vuln_summary: dict[str, int],
    stats: dict[str, int],
) -> None:
    """Recursively scan a module data node for findings and status.

    Handles both:
    - Direct module results: ``{"status": "success", "data": {"findings": [...]}}``
    - Nested sub-module dicts: ``{"sqli": {"status": "...", "data": {...}}, ...}``
    """
    if not isinstance(node, dict):
        return

    # Check if this node has a "status" key → it's a module/sub-module result
    if "status" in node:
        module_status = node.get("status", "")
        if module_status == "error":
            stats["modules_failed"] += 1
        else:
            stats["modules_completed"] += 1

        # Extract findings from "data" sub-key
        inner = node.get("data", {})
        if isinstance(inner, dict):
            _extract_findings_from_inner(inner, vuln_summary, stats)

        # Also check for SSL vulnerabilities at the data level
        vulns = node.get("vulnerabilities", [])
        if isinstance(vulns, list) and vulns:
            stats["total_findings"] += len(vulns)
            for v in vulns:
                sev = (v.get("severity") or "info").lower()
                _increment_severity(sev, vuln_summary)

        return

    # No "status" key — this is a container dict of sub-modules
    # e.g., {"sqli": {...}, "xss": {...}} or empty dict
    if not node:
        return

    # Check if this looks like a container of sub-modules
    # by recursing into each value
    has_sub_modules = False
    for value in node.values():
        if isinstance(value, dict) and ("status" in value or "data" in value):
            has_sub_modules = True
            _scan_data_node(value, vuln_summary, stats)

    # If no sub-modules detected, try treating it as direct data
    if not has_sub_modules:
        _extract_findings_from_inner(node, vuln_summary, stats)


def _extract_findings_from_inner(
    inner: dict,
    vuln_summary: dict[str, int],
    stats: dict[str, int],
) -> None:
    """Extract vulnerability findings from a data dict."""
    # Check for findings list (vuln modules)
    findings = inner.get("findings", [])
    if isinstance(findings, list) and findings:
        stats["total_findings"] += len(findings)
        for finding in findings:
            sev = (finding.get("severity") or "info").lower()
            _increment_severity(sev, vuln_summary)

    # Check for vulnerabilities list (SSL module)
    vulns = inner.get("vulnerabilities", [])
    if isinstance(vulns, list) and vulns:
        stats["total_findings"] += len(vulns)
        for v in vulns:
            sev = (v.get("severity") or "info").lower()
            _increment_severity(sev, vuln_summary)

    # Recursively check nested sub-keys for more findings
    for key, val in inner.items():
        if key in ("findings", "vulnerabilities"):
            continue
        if isinstance(val, dict):
            _extract_findings_from_inner(val, vuln_summary, stats)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _extract_findings_from_inner(item, vuln_summary, stats)


def _increment_severity(severity: str, vuln_summary: dict[str, int]) -> None:
    """Increment the count for a given severity level."""
    normalized = severity.lower()
    if normalized in vuln_summary:
        vuln_summary[normalized] += 1
    else:
        vuln_summary["info"] += 1


def _compute_grade(vuln_summary: dict[str, int]) -> str:
    """Compute an overall security grade (A-F) from the vulnerability summary.

    Args:
        vuln_summary: Dict of counts per severity level.

    Returns:
        ``"A"`` through ``"F"``.
    """
    if vuln_summary.get("critical", 0) > 0:
        return "F"
    if vuln_summary.get("high", 0) > 2:
        return "D"
    if vuln_summary.get("high", 0) > 0:
        return "C"
    if vuln_summary.get("medium", 0) > 3:
        return "C"
    if vuln_summary.get("medium", 0) > 0:
        return "B"
    if vuln_summary.get("low", 0) > 5:
        return "B"
    return "A"


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


class Report:
    """Generates security scan reports in JSON, HTML, and PDF formats.

    Args:
        results: The scan results dict from ``Scanner.run()``.
        scan_duration: Optional scan execution time in seconds.

    Attributes:
        results: The raw scan results.
        generated_at: ISO-formatted generation timestamp.
        summary: Pre-computed executive summary data.
    """

    def __init__(self, results: dict, scan_duration: float | None = None):
        self.results = results
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self.scan_duration = scan_duration
        self.summary = _compute_executive_summary(results)

    # ── JSON ──────────────────────────────────────────────

    def to_json(self, pretty: bool = True) -> str:
        """Serialize the report to a JSON string.

        Includes metadata, executive summary, and raw module results.

        Args:
            pretty: Whether to pretty-print with indentation.

        Returns:
            JSON string of the full report.
        """
        report_data = self._build_report_dict()
        indent = 2 if pretty else None
        return json.dumps(report_data, indent=indent, default=str)

    def _build_report_dict(self) -> dict[str, Any]:
        """Build the complete report data structure."""
        return {
            "metadata": {
                "report_type": "security_scan",
                "generated_at": self.generated_at,
                "scanner_version": "0.1.0",
                "scan_duration": self.scan_duration,
                "scan_duration_formatted": (
                    _format_duration(self.scan_duration) if self.scan_duration else None
                ),
            },
            "executive_summary": self.summary,
            "target": self.results.get("target", ""),
            "modules": self.results.get("modules", {}),
        }

    # ── HTML ──────────────────────────────────────────────

    def to_html(self) -> str:
        """Generate an HTML report using the Jinja2 template.

        Falls back to a minimal inline HTML if the template is
        unavailable or Jinja2 is not installed.

        Returns:
            HTML string of the full report.
        """
        template_str = _load_template()
        if not template_str:
            return self._fallback_html()

        try:
            from jinja2 import Template

            template = Template(template_str)
            context = self._build_template_context()
            return template.render(**context)
        except ImportError:
            logger.warning("Jinja2 not available — using fallback HTML")
            return self._fallback_html()
        except Exception as exc:
            logger.warning(f"Template rendering failed ({exc}) — using fallback HTML")
            return self._fallback_html()

    def _build_template_context(self) -> dict[str, Any]:
        """Build the context dict for the Jinja2 HTML template."""
        modules = self.results.get("modules", {})
        scan_duration = (
            _format_duration(self.scan_duration) if self.scan_duration else None
        )

        return {
            "target": self.results.get("target", ""),
            "generated_at": self.generated_at,
            "scan_duration": scan_duration,
            "grade": self.summary["grade"],
            "vuln_summary": self.summary["vuln_summary"],
            "stats": self.summary["stats"],
            "recon": modules.get("recon"),
            "web": modules.get("web"),
            "vuln": modules.get("vuln"),
        }

    def _fallback_html(self) -> str:
        """Generate a minimal fallback HTML when the template is unavailable."""
        target = self.results.get("target", "unknown")
        summary = self.summary
        vs = summary["vuln_summary"]

        html_parts = [
            "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>",
            f"<title>Security Scan Report — {target}</title>",
            "<style>body{font-family:sans-serif;max-width:960px;margin:0 auto;padding:20px;}</style>",
            "</head><body>",
            f"<h1>Security Scan Report: {target}</h1>",
            f"<p>Generated: {self.generated_at}</p>",
            f"<h2>Executive Summary</h2>",
            f"<p>Grade: <strong>{summary['grade']}</strong></p>",
            f"<ul>",
            f"<li>Critical: {vs.get('critical', 0)}</li>",
            f"<li>High: {vs.get('high', 0)}</li>",
            f"<li>Medium: {vs.get('medium', 0)}</li>",
            f"<li>Low: {vs.get('low', 0)}</li>",
            f"<li>Info: {vs.get('info', 0)}</li>",
            f"</ul>",
            f"<p>Total findings: {summary['stats']['total_findings']}</p>",
            "</body></html>",
        ]
        return "\n".join(html_parts)

    # ── PDF ───────────────────────────────────────────────

    def to_pdf(self) -> bytes:
        """Generate a PDF report.

        Attempts conversion via weasyprint. Falls back to
        wkhtmltopdf/pdfkit if available.

        Returns:
            PDF bytes, or raises ``NotImplementedError`` if no
            PDF backend is available.

        Raises:
            NotImplementedError: If no PDF conversion library
                is installed.
        """
        html_content = self.to_html()

        # Try weasyprint first
        try:
            import weasyprint
            pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
            if pdf_bytes and len(pdf_bytes) > 100:
                return pdf_bytes
        except ImportError:
            pass
        except Exception as exc:
            logger.warning(f"weasyprint PDF generation failed: {exc}")

        # Try pdfkit as fallback
        try:
            import pdfkit
            pdf_bytes = pdfkit.from_string(html_content, False)
            if pdf_bytes and len(pdf_bytes) > 100:
                return pdf_bytes
        except ImportError:
            pass
        except Exception as exc:
            logger.warning(f"pdfkit PDF generation failed: {exc}")

        raise NotImplementedError(
            "PDF generation requires weasyprint or pdfkit. "
            "Install with: pip install weasyprint  # or pdfkit"
        )

    # ── Save ──────────────────────────────────────────────

    def save(self, filename: str, fmt: ReportFormat = "json") -> str:
        """Save the report to a file in the specified format.

        Args:
            filename: Output file path **without extension**.
            fmt: Output format — ``"json"``, ``"html"``, or ``"pdf"``.

        Returns:
            The full path to the saved file.

        Raises:
            ValueError: If the format is unsupported.
            NotImplementedError: If PDF is requested without
                a PDF backend.
            OSError: If the file cannot be written.
        """
        format_handlers: dict[str, tuple[str, Any]] = {
            "json": ("json", self.to_json),
            "html": ("html", self.to_html),
            "pdf": ("pdf", self.to_pdf),
        }

        if fmt not in format_handlers:
            raise ValueError(
                f"Unsupported format: {fmt!r}. Use 'json', 'html', or 'pdf'."
            )

        extension, handler = format_handlers[fmt]

        # Ensure output directory exists
        out_path = Path(f"{filename}.{extension}")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        content = handler()
        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"

        with open(out_path, mode, encoding=encoding) as f:
            f.write(content)  # type: ignore[arg-type]

        logger.info(f"Report saved: {out_path}")
        return str(out_path.resolve())


def generate_report(
    results: dict,
    output_path: str = "reports/report",
    fmt: ReportFormat = "json",
    scan_duration: float | None = None,
) -> str:
    """Convenience function to generate and save a report in one call.

    Args:
        results: Scan results from ``Scanner.run()``.
        output_path: Output file path without extension.
        fmt: Output format (``"json"``, ``"html"``, ``"pdf"``).
        scan_duration: Optional scan duration in seconds.

    Returns:
        Path to the saved report file.
    """
    report = Report(results, scan_duration=scan_duration)
    return report.save(output_path, fmt=fmt)


if __name__ == "__main__":
    # Demo: create a sample report
    sample_results = {
        "target": "example.com",
        "modules": {
            "recon": {
                "dns": {"A": ["93.184.216.34"], "MX": [], "NS": [], "TXT": [], "CNAME": []},
                "whois": {"registrar": "Example Registrar", "country": "US"},
                "subdomains": [
                    {"subdomain": "www.example.com", "ip": "93.184.216.34", "source": "bruteforce"}
                ],
                "portscan": [
                    {"port": 80, "state": "open", "service": "http", "banner": "Apache"},
                    {"port": 443, "state": "open", "service": "https", "banner": ""},
                ],
            },
            "web": {
                "headers": {
                    "status": "success",
                    "data": {
                        "headers": [
                            {"header": "Strict-Transport-Security", "present": True,
                             "value": "max-age=31536000", "status": "pass", "score": 20,
                             "max_score": 20, "recommendation": "", "description": "HSTS"},
                        ],
                        "score": 80, "max_score": 100, "percentage": 80.0, "grade": "B",
                    },
                },
                "ssl_tls": {
                    "status": "error",
                    "data": {},
                    "error": "Connection refused",
                },
            },
            "vuln": {
                "xss": {
                    "status": "success",
                    "data": {
                        "findings": [
                            {"param": "q", "method": "GET", "payload": "<script>alert(1)</script>",
                             "type": "reflected", "severity": "high", "cvss_score": 6.5,
                             "url": "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
                             "status_code": 200, "confidence": 0.8,
                             "evidence": "Payload reflected in HTML context",
                             "context": "html"},
                        ]
                    },
                },
            },
        },
    }

    print("Generating sample report...")
    r = Report(sample_results, scan_duration=12.5)
    print(r.to_json()[:200] + "...")
    print(f"\nGrade: {r.summary['grade']}")
    print(f"Findings: {r.summary['stats']['total_findings']}")
    print(f"Vuln summary: {r.summary['vuln_summary']}")
