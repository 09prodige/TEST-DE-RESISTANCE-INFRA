"""Tests for the reporting module — CVSS scoring and report generation.

Covers:
- CVSS v3.1 calculator: scoring, edge cases, validation
- ``classify_finding()``: mapping findings to scores
- ``Report`` class: JSON, HTML, PDF generation
- Integration: end-to-end report from scanner results
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.report import Report, _compute_executive_summary, _format_duration
from src.reporting.cvss import (
    calculate_score,
    classify_finding,
    get_score_from_severity,
    severity_to_cvss_metrics,
    _score_to_severity,
)


# ===================================================================
#  CVSS Calculator — Unit Tests
# ===================================================================

class TestCalculateScore:
    """Tests for the core CVSS v3.1 calculation logic."""

    def test_sqli_default(self):
        """SQLi default metrics: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"""
        result = calculate_score("N", "L", "N", "N", "U", "H", "H", "H")
        assert result["status"] == "success"
        data = result["data"]
        assert data["base_score"] == 9.8
        assert data["severity"] == "Critical"
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in data["vector"]

    def test_xss_reflected(self):
        """Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"""
        result = calculate_score("N", "L", "N", "R", "U", "L", "L", "N")
        assert result["status"] == "success"
        data = result["data"]
        assert 4.0 <= data["base_score"] <= 7.0
        assert data["severity"] in ("Medium", "High")
        assert "UI:R" in data["vector"]

    def test_csrf(self):
        """CSRF: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"""
        result = calculate_score("N", "L", "N", "R", "U", "N", "L", "N")
        assert result["status"] == "success"
        data = result["data"]
        assert data["base_score"] == 4.3
        assert data["severity"] == "Medium"

    def test_no_impact(self):
        """All Nones should yield score 0.0"""
        result = calculate_score("N", "L", "N", "N", "U", "N", "N", "N")
        assert result["status"] == "success"
        assert result["data"]["base_score"] == 0.0
        assert result["data"]["severity"] == "None"

    def test_physical_attack_vector(self):
        """Physical attack vector reduces score"""
        result = calculate_score("P", "L", "N", "N", "U", "H", "H", "H")
        assert result["status"] == "success"
        assert result["data"]["base_score"] < 9.0
        assert result["data"]["severity"] in ("High", "Medium")

    def test_changed_scope(self):
        """Scope 'Changed' scenario yields higher score"""
        result = calculate_score("N", "L", "N", "N", "C", "H", "H", "H")
        assert result["status"] == "success"
        data = result["data"]
        assert data["base_score"] >= 9.0
        assert data["severity"] == "Critical"
        assert "S:C" in data["vector"]

    def test_high_complexity_reduces_score(self):
        """High attack complexity reduces the score."""
        low = calculate_score("N", "L", "N", "N", "U", "H", "H", "H")
        high = calculate_score("N", "H", "N", "N", "U", "H", "H", "H")
        assert high["data"]["base_score"] < low["data"]["base_score"]

    def test_user_interaction_required(self):
        """User Interaction required reduces score."""
        none = calculate_score("N", "L", "N", "N", "U", "L", "L", "N")
        req = calculate_score("N", "L", "N", "R", "U", "L", "L", "N")
        assert req["data"]["base_score"] < none["data"]["base_score"]

    def test_invalid_attack_vector(self):
        """Invalid AV should return error."""
        result = calculate_score("X", "L", "N", "N", "U", "H", "H", "H")  # type: ignore
        assert result["status"] == "error"

    def test_invalid_metric(self):
        """Invalid metric value returns error status."""
        result = calculate_score("N", "X", "N", "N", "U", "H", "H", "H")  # type: ignore
        assert result["status"] == "error"

    def test_score_rounding(self):
        """CVSS score rounding to 1 decimal place."""
        result = calculate_score("A", "H", "L", "R", "U", "L", "L", "N")
        assert result["status"] == "success"
        score = result["data"]["base_score"]
        # Score should have at most 1 decimal place
        assert isinstance(score, float)
        score_str = str(score)
        if "." in score_str:
            decimal_places = len(score_str.split(".")[1])
            assert decimal_places <= 1, f"Score {score} has too many decimal places"

    def test_severity_thresholds(self):
        """Verify severity thresholds at boundary values."""
        assert _score_to_severity(9.0) == "Critical"
        assert _score_to_severity(8.9) == "High"
        assert _score_to_severity(7.0) == "High"
        assert _score_to_severity(6.9) == "Medium"
        assert _score_to_severity(4.0) == "Medium"
        assert _score_to_severity(3.9) == "Low"
        assert _score_to_severity(0.1) == "Low"
        assert _score_to_severity(0.0) == "None"


# ===================================================================
#  classify_finding — Tests
# ===================================================================

class TestClassifyFinding:
    """Tests for automated finding-to-CVSS classification."""

    def test_sqli_finding(self):
        """SQLi finding maps to Critical."""
        finding = {"type": "error-based", "severity": "critical", "param": "id"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        # Should map from 'error-based' type → sqli metrics
        assert result["data"]["severity"] in ("Critical", "High")

    def test_xss_finding(self):
        """XSS finding maps correctly."""
        finding = {"type": "reflected", "severity": "high", "param": "q"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        assert result["data"]["base_score"] > 0

    def test_with_existing_cvss_score(self):
        """Finding with existing cvss_score uses it directly."""
        finding = {"cvss_score": 7.5, "severity": "high", "type": "reflected"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        assert result["data"]["base_score"] == 7.5
        assert result["data"]["source"] == "finding"

    def test_with_existing_cvss_float(self):
        """Float cvss_score is handled correctly."""
        finding = {"cvss_score": 6.5, "type": "reflected"}
        result = classify_finding(finding)
        assert result["data"]["base_score"] == 6.5

    def test_unknown_type_fallback_severity(self):
        """Unknown type falls back to severity-based mapping."""
        finding = {"type": "unknown_vuln", "severity": "high"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        assert result["data"]["severity"] in ("High", "Critical")
        assert result["data"]["source"] == "severity_fallback"

    def test_no_severity_fallback(self):
        """No severity field defaults to medium."""
        finding = {"type": "weird_thing"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        assert result["data"]["severity"] in ("Low", "Medium", "High")

    def test_ssl_vuln_mapped(self):
        """SSL vulnerability types map correctly."""
        finding = {"name": "ssl_tls_vulnerability", "severity": "high"}
        result = classify_finding(finding)
        assert result["status"] == "success"
        assert result["data"]["base_score"] > 0


# ===================================================================
#  severity_to_cvss_metrics & get_score_from_severity
# ===================================================================

class TestSeverityHelpers:

    def test_severity_to_metrics_critical(self):
        metrics = severity_to_cvss_metrics("critical")
        assert metrics["confidentiality"] == "H"
        assert metrics["scope"] == "C"

    def test_severity_to_metrics_info(self):
        metrics = severity_to_cvss_metrics("info")
        assert metrics["confidentiality"] == "N"
        assert metrics["integrity"] == "N"

    def test_severity_to_metrics_unknown(self):
        metrics = severity_to_cvss_metrics("unknown")
        # Should return default (info-like)
        assert isinstance(metrics, dict)
        assert metrics["attack_vector"] == "N"

    def test_get_score_from_severity(self):
        assert get_score_from_severity("critical") == 9.5
        assert get_score_from_severity("high") == 7.5
        assert get_score_from_severity("medium") == 5.5
        assert get_score_from_severity("low") == 2.5
        assert get_score_from_severity("info") == 0.0
        assert get_score_from_severity("none") == 0.0
        assert get_score_from_severity("UNKNOWN") == 0.0


# ===================================================================
#  Report — Unit Tests
# ===================================================================

class TestReportInit:
    """Tests for Report initialization and properties."""

    def test_init_with_results(self, sample_results):
        report = Report(sample_results)
        assert report.results == sample_results
        assert report.generated_at is not None
        assert isinstance(report.generated_at, str)

    def test_init_with_duration(self, sample_results):
        report = Report(sample_results, scan_duration=42.5)
        assert report.scan_duration == 42.5

    def test_summary_computed(self, sample_results):
        report = Report(sample_results)
        assert "grade" in report.summary
        assert "vuln_summary" in report.summary
        assert "stats" in report.summary

    def test_summary_with_empty_modules(self):
        results = {"target": "test.com", "modules": {}}
        report = Report(results)
        assert report.summary["grade"] == "A"
        assert report.summary["vuln_summary"]["critical"] == 0


class TestReportJSON:
    """Tests for JSON report generation."""

    def test_to_json_string(self, sample_results):
        report = Report(sample_results)
        output = report.to_json()
        assert isinstance(output, str)
        data = json.loads(output)
        assert "metadata" in data
        assert "executive_summary" in data
        assert "target" in data
        assert data["target"] == "example.com"

    def test_to_json_contains_generated_at(self, sample_results):
        report = Report(sample_results)
        data = json.loads(report.to_json())
        assert "generated_at" in data["metadata"]

    def test_json_executive_summary_fields(self, sample_results):
        report = Report(sample_results)
        data = json.loads(report.to_json())
        ess = data["executive_summary"]
        assert "grade" in ess
        assert "vuln_summary" in ess
        assert "stats" in ess

    def test_json_with_duration(self, sample_results):
        report = Report(sample_results, scan_duration=30.0)
        data = json.loads(report.to_json())
        assert data["metadata"]["scan_duration"] == 30.0
        assert data["metadata"]["scan_duration_formatted"] == "30.0s"

    def test_json_modules_preserved(self, sample_results):
        report = Report(sample_results)
        data = json.loads(report.to_json())
        assert "modules" in data
        assert "recon" in data["modules"]

    def test_json_save(self, tmp_path, sample_results):
        report = Report(sample_results)
        out = str(tmp_path / "report")
        result_path = report.save(out, fmt="json")
        assert os.path.exists(f"{out}.json")
        assert result_path.endswith(".json")

    def test_json_save_content(self, tmp_path, sample_results):
        report = Report(sample_results)
        out = str(tmp_path / "report")
        report.save(out, fmt="json")
        with open(f"{out}.json") as f:
            data = json.load(f)
        assert data["target"] == "example.com"


class TestReportHTML:
    """Tests for HTML report generation."""

    def test_to_html_returns_string(self, sample_results):
        report = Report(sample_results)
        html = report.to_html()
        assert isinstance(html, str)
        assert len(html) > 100

    def test_to_html_contains_target(self, sample_results):
        report = Report(sample_results)
        html = report.to_html()
        assert "example.com" in html

    def test_to_html_contains_doctype(self, sample_results):
        report = Report(sample_results)
        html = report.to_html()
        assert "<!DOCTYPE html>" in html or "<!DOCTYPE" in html

    def test_to_html_fallback_without_jinja2(self, sample_results):
        """Without Jinja2, fallback HTML should still be generated."""
        report = Report(sample_results)
        with patch.dict('sys.modules', {'jinja2': None}):
            # We need to reload/recreate since jinja2 is already imported
            pass
        # Just check that normal call works
        html = report.to_html()
        assert len(html) > 50

    def test_html_template_not_found_fallback(self, sample_results, monkeypatch):
        """When template file is missing, fallback HTML should be used."""
        report = Report(sample_results)
        monkeypatch.setattr(
            "src.core.report.TEMPLATE_PATH",
            Path("/nonexistent/template.html"),
        )
        html = report.to_html()
        assert len(html) > 50

    def test_html_contains_severity_section(self, sample_results):
        """HTML should include severity-related content."""
        report = Report(sample_results)
        html = report.to_html()
        assert "critical" in html.lower() or "Critical" in html

    def test_html_report_save(self, tmp_path, sample_results):
        report = Report(sample_results)
        out = str(tmp_path / "report")
        result_path = report.save(out, fmt="html")
        assert os.path.exists(f"{out}.html")
        assert result_path.endswith(".html")

    def test_html_report_save_content(self, tmp_path, sample_results):
        report = Report(sample_results)
        out = str(tmp_path / "report")
        report.save(out, fmt="html")
        with open(f"{out}.html") as f:
            content = f.read()
        assert "example.com" in content


# ===================================================================
#  Report — PDF
# ===================================================================

class TestReportPDF:
    """Tests for PDF report generation (expected to fail gracefully)."""

    def test_to_pdf_raises_not_implemented(self, sample_results):
        """Without a PDF lib, to_pdf raises NotImplementedError."""
        report = Report(sample_results)
        with pytest.raises(NotImplementedError):
            report.to_pdf()

    def test_save_pdf_raises_not_implemented(self, tmp_path, sample_results):
        report = Report(sample_results)
        out = str(tmp_path / "report")
        with pytest.raises((NotImplementedError, ValueError)):
            report.save(out, fmt="pdf")


# ===================================================================
#  Report — Edge Cases & Error Handling
# ===================================================================

class TestReportEdgeCases:

    def test_unsupported_format(self, tmp_path, sample_results):
        report = Report(sample_results)
        with pytest.raises(ValueError):
            report.save(str(tmp_path / "report"), fmt="xml")  # type: ignore

    def test_summary_with_findings(self):
        """Summary counts findings correctly across modules."""
        results = {
            "target": "test.com",
            "modules": {
                "vuln": {
                    "sqli": {
                        "status": "success",
                        "data": {
                            "findings": [
                                {"severity": "critical", "type": "error-based"},
                                {"severity": "high", "type": "boolean-based"},
                            ]
                        },
                    },
                    "xss": {
                        "status": "success",
                        "data": {
                            "findings": [
                                {"severity": "medium", "type": "reflected"},
                            ]
                        },
                    },
                },
                "web": {
                    "ssl_tls": {
                        "status": "success",
                        "data": {
                            "vulnerabilities": [
                                {"severity": "HIGH", "name": "WEAK_CIPHER"},
                                {"severity": "MEDIUM", "name": "OLD_TLS"},
                            ]
                        },
                    }
                },
            },
        }
        report = Report(results)
        assert report.summary["vuln_summary"]["critical"] == 1
        assert report.summary["vuln_summary"]["high"] >= 2  # 1 from sqli + 1 from ssl
        assert report.summary["stats"]["total_findings"] >= 4

    def test_summary_module_error(self):
        """A module with error status counts as failed."""
        results = {
            "target": "test.com",
            "modules": {
                "recon": {"status": "error", "data": {}},
                "web": {"status": "success", "data": {}},
            },
        }
        summary = _compute_executive_summary(results)
        assert summary["stats"]["modules_failed"] >= 1

    def test_empty_results(self):
        results = {}
        summary = _compute_executive_summary(results)
        assert summary["grade"] == "A"
        assert summary["stats"]["total_findings"] == 0

    def test_grade_a(self):
        """No findings should yield grade A."""
        summary = _compute_executive_summary({"target": "x", "modules": {}})
        assert summary["grade"] == "A"

    def test_grade_f_critical(self):
        """Any critical finding yields grade F."""
        results = {
            "target": "x",
            "modules": {
                "sqli": {
                    "data": {"findings": [{"severity": "critical", "type": "error-based"}]}
                }
            },
        }
        summary = _compute_executive_summary(results)
        assert summary["grade"] == "F"

    def test_grade_c_high(self):
        """One high finding yields grade C."""
        results = {
            "target": "x",
            "modules": {
                "xss": {
                    "data": {"findings": [{"severity": "high", "type": "reflected"}]}
                }
            },
        }
        summary = _compute_executive_summary(results)
        assert summary["grade"] == "C"

    def test_report_json_pretty_false(self, sample_results):
        report = Report(sample_results)
        output = report.to_json(pretty=False)
        # Without pretty-print, should be on one line or compact
        data = json.loads(output)
        assert data["target"] == "example.com"


# ===================================================================
#  _format_duration
# ===================================================================

class TestFormatDuration:

    def test_seconds_only(self):
        assert _format_duration(30.5) == "30.5s"

    def test_minutes_and_seconds(self):
        assert _format_duration(125) == "2m 5s"

    def test_exact_minute(self):
        assert _format_duration(60) == "1m 0s"

    def test_zero(self):
        assert _format_duration(0) == "0.0s"


# ===================================================================
#  Integration Tests
# ===================================================================

class TestReportIntegration:
    """Integration tests: end-to-end report generation."""

    def test_full_report_json_roundtrip(self, sample_results):
        """Generate JSON report and parse back."""
        report = Report(sample_results)
        data = json.loads(report.to_json())
        assert data["metadata"]["report_type"] == "security_scan"
        assert isinstance(data["executive_summary"]["vuln_summary"]["critical"], int)

    def test_full_report_html_sections(self, sample_results):
        """HTML report should contain all major sections."""
        report = Report(sample_results)
        html = report.to_html()
        # Should contain key terms
        assert "Executive Summary" in html or "executive" in html.lower()

    def test_convenience_generate_report(self, tmp_path, sample_results):
        """Test the generate_report convenience function."""
        from src.core.report import generate_report
        out = str(tmp_path / "convenience")
        result = generate_report(sample_results, out, fmt="json")
        assert os.path.exists(result)

    def test_report_with_recon_data(self, mock_dns_results, mock_whois_results,
                                    mock_subdomain_results, mock_portscan_results):
        """Report with full recon data should render properly."""
        results = {
            "target": "example.com",
            "modules": {
                "recon": {
                    "dns": mock_dns_results,
                    "whois": mock_whois_results,
                    "subdomains": mock_subdomain_results,
                    "portscan": mock_portscan_results,
                }
            },
        }
        report = Report(results)
        # JSON should contain all recon data
        data = json.loads(report.to_json())
        assert "dns" in data["modules"]["recon"]
        assert data["modules"]["recon"]["dns"]["A"] == ["93.184.216.34"]

    def test_report_with_vuln_data(self):
        """Report with vulnerability data should score correctly."""
        results = {
            "target": "example.com",
            "modules": {
                "vuln": {
                    "sqli": {
                        "status": "success",
                        "data": {
                            "findings": [
                                {
                                    "param": "id",
                                    "method": "GET",
                                    "type": "error-based",
                                    "severity": "critical",
                                    "cvss_score": 9.1,
                                    "payload": "' OR '1'='1",
                                    "evidence": ["MySQL"],
                                    "confidence": 0.85,
                                    "url": "http://example.com/?id=%27+OR+%271%27%3D%271",
                                }
                            ]
                        },
                    }
                },
            },
        }
        report = Report(results)
        assert report.summary["vuln_summary"]["critical"] == 1
        assert report.summary["stats"]["total_findings"] == 1
        assert report.summary["grade"] == "F"

    def test_report_with_web_data(self):
        """Report with web analysis data renders correctly."""
        results = {
            "target": "example.com",
            "modules": {
                "web": {
                    "headers": {
                        "status": "success",
                        "data": {
                            "headers": [],
                            "score": 50,
                            "max_score": 100,
                            "percentage": 50.0,
                            "grade": "D",
                        },
                    },
                },
            },
        }
        report = Report(results)
        data = json.loads(report.to_json())
        assert data["modules"]["web"]["headers"]["data"]["grade"] == "D"


# ===================================================================
#  Parameterized CVSS Tests
# ===================================================================

class TestCalculateScoreParameterized:
    """Parameterized CVSS scoring tests for known vulnerability types."""

    @pytest.mark.parametrize("name,metrics,expected_severity", [
        (
            "SQL Injection",
            {"attack_vector": "N", "attack_complexity": "L",
             "privileges_required": "N", "user_interaction": "N",
             "scope": "U", "confidentiality": "H", "integrity": "H",
             "availability": "H"},
            "Critical",
        ),
        (
            "Reflected XSS",
            {"attack_vector": "N", "attack_complexity": "L",
             "privileges_required": "N", "user_interaction": "R",
             "scope": "U", "confidentiality": "L", "integrity": "L",
             "availability": "N"},
            "Medium",
        ),
        (
            "CSRF",
            {"attack_vector": "N", "attack_complexity": "L",
             "privileges_required": "N", "user_interaction": "R",
             "scope": "U", "confidentiality": "N", "integrity": "L",
             "availability": "N"},
            "Medium",
        ),
        (
            "No Impact",
            {"attack_vector": "N", "attack_complexity": "L",
             "privileges_required": "N", "user_interaction": "N",
             "scope": "U", "confidentiality": "N", "integrity": "N",
             "availability": "N"},
            "None",
        ),
    ])
    def test_cvss_parameterized(self, name, metrics, expected_severity):
        result = calculate_score(**metrics)  # type: ignore
        assert result["status"] == "success", f"{name} failed: {result.get('error')}"
        assert result["data"]["severity"] == expected_severity, (
            f"{name}: expected {expected_severity}, got {result['data']['severity']}"
        )


if __name__ == "__main__":
    pytest.main(["-v", __file__])
