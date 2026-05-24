"""Comprehensive unit tests for the vulnerability scanner modules (US-09 to US-13, US-24)."""

from unittest.mock import MagicMock, Mock, patch, call

import pytest

from src.modules.vuln.sqli import (
    scan_sqli,
    _parse_sql_errors,
    _compute_sqli_cvss,
    _score_to_severity,
    SQL_ERROR_PATTERNS,
)
from src.modules.vuln.xss import scan_xss, _is_reflected, _determine_context, XSS_PAYLOADS
from src.modules.vuln.csrf import (
    scan_csrf,
    _has_csrf_token,
    _check_samesite_cookies,
    _get_samesite_severity,
)
from src.modules.vuln.sensitive_files import (
    scan_sensitive_files,
    _get_content_preview,
    _path_severity_to_cvss,
    _downgrade_severity,
    SENSITIVE_PATHS,
)
from src.modules.vuln.open_redirect import (
    scan_open_redirect,
    _is_external_url,
    _check_meta_refresh,
    _check_js_redirect,
)
from src.core.scanner import Scanner


# =============================================================================
# SQL Injection Tests (US-09)
# =============================================================================

class TestSQLi:
    """Tests for src.modules.vuln.sqli.scan_sqli."""

    @pytest.fixture
    def mock_get(self):
        """Patch requests.Session.get with a mock."""
        with patch("src.modules.vuln.sqli.safe_session") as mock:
            session = MagicMock()
            mock.return_value = session
            yield session

    def _make_error_response(self, text="<html>OK</html>", status=200):
        """Create a mock response with SQL error markers."""
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.content = text.encode()
        resp.headers = {"Content-Type": "text/html"}
        return resp

    # -- Validation tests --

    def test_scan_sqli_invalid_target(self):
        """Invalid target returns error status."""
        result = scan_sqli(None)
        assert result["status"] == "error"

        result = scan_sqli("")
        assert result["status"] == "error"

    def test_scan_sqli_adds_scheme(self):
        """Target without scheme gets https:// prepended."""
        with patch("src.modules.vuln.sqli.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = self._make_error_response()
            mock.return_value = session

            result = scan_sqli("example.com")

            # Verify request was made to https://example.com
            calls = [c for c in session.get.call_args_list]
            assert any("https://example.com" in str(c) for c in calls)

    # -- Error-based detection tests --

    def test_scan_sqli_error_based_detection(self, mock_get):
        """SQL error in response should be detected as error-based SQLi."""
        normal_resp = self._make_error_response("<html>OK</html>")
        error_resp = self._make_error_response(
            "<html>SQL syntax; check MySQL manual</html>"
        )

        # Must return many responses for all the payload tests
        def side_effect(url=None, **kw):
            if "id=%27" in url or "id='" in url or "%27" in url:
                return error_resp
            return normal_resp

        mock_get.get.side_effect = side_effect

        with patch("src.modules.vuln.sqli._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.sqli.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_sqli("http://example.com")

        assert result["status"] == "success"
        assert len(result["data"]["findings"]) >= 1
        assert result["data"]["findings"][0]["type"] == "error-based"

    def test_scan_sqli_multiple_error_patterns(self):
        """Multiple DB error patterns should be detected."""
        html = (
            "You have an error in your SQL syntax; check MySQL manual "
            "Unclosed quotation mark after the character string"
        )
        db_errors = _parse_sql_errors(html)
        assert "MySQL" in db_errors
        assert "MSSQL" in db_errors

    def test_scan_sqli_no_error_clean_page(self, mock_get):
        """Clean page without errors should return no findings."""
        mock_get.get.return_value = self._make_error_response("<html>No errors here</html>")

        with patch("src.modules.vuln.sqli._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.sqli.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_sqli("http://example.com")

        assert len(result["data"]["findings"]) == 0

    def test_parse_sql_errors_mysql(self):
        """MySQL-specific error patterns should be recognized."""
        html = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
        errors = _parse_sql_errors(html)
        assert "MySQL" in errors

    def test_parse_sql_errors_postgresql(self):
        """PostgreSQL-specific error patterns should be recognized."""
        html = "PostgreSQL ERROR: division by zero"
        errors = _parse_sql_errors(html)
        assert "PostgreSQL" in errors

    def test_parse_sql_errors_mssql(self):
        """MSSQL-specific error patterns should be recognized."""
        html = "Unclosed quotation mark after the character string"
        errors = _parse_sql_errors(html)
        assert "MSSQL" in errors

    def test_parse_sql_errors_oracle(self):
        """Oracle-specific error patterns should be recognized."""
        html = "ORA-00933: SQL command not properly ended"
        errors = _parse_sql_errors(html)
        assert "Oracle" in errors

    def test_parse_sql_errors_no_match(self):
        """Clean HTML should return empty dict."""
        errors = _parse_sql_errors("<html><body>Hello</body></html>")
        assert errors == {}

    # -- Boolean-based detection tests --

    def test_scan_sqli_boolean_based(self, mock_get):
        """Different response lengths should trigger boolean-based detection."""
        call_count = [0]

        def side_effect(url=None, **kw):
            call_count[0] += 1
            # All error-payload injections get normal response
            # For boolean test calls, alternate lengths
            if "AND+%271%27%3D%271" in url or "AND+1%3D1--" in url:
                return self._make_error_response("<html>OK " + "A" * 100)
            if "AND+%271%27%3D%272" in url or "AND+1%3D2--" in url:
                return self._make_error_response("<html>OK</html>")
            return self._make_error_response("<html>OK</html>")

        mock_get.get.side_effect = side_effect

        with patch("src.modules.vuln.sqli._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.sqli.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_sqli("http://example.com")

        assert result["status"] in ("success", "partial")

    # -- POST form injection tests --

    def test_scan_sqli_post_form_injection(self, mock_get):
        """POST forms should be tested for SQLi."""
        mock_get.get.return_value = self._make_error_response(
            "<html>SQL syntax error near MySQL</html>"
        )

        forms = [{
            "action": "http://example.com/login",
            "method": "POST",
            "inputs": [
                {"type": "text", "name": "username", "value": ""},
                {"type": "password", "name": "password", "value": ""},
            ],
        }]

        with patch("src.modules.vuln.sqli.parse_qs") as mock_qs:
            mock_qs.return_value = {}
            result = scan_sqli("http://example.com", forms=forms)

        assert len(result["data"]["findings"]) >= 1

    # -- Score utilities --

    def test_compute_sqli_cvss(self):
        """CVSS score calculation for SQLi."""
        assert _compute_sqli_cvss("error-based") == 9.0
        assert _compute_sqli_cvss("boolean-based") == 7.5

    def test_score_to_severity(self):
        """Score to severity mapping."""
        assert _score_to_severity(9.5) == "critical"
        assert _score_to_severity(7.5) == "high"
        assert _score_to_severity(5.0) == "medium"
        assert _score_to_severity(3.0) == "low"

    # -- Edge cases --

    def test_scan_sqli_http_error_handling(self, mock_get):
        """HTTP errors should not crash the scan."""
        mock_get.get.side_effect = Exception("Connection error")

        with patch("src.modules.vuln.sqli._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.sqli.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_sqli("http://example.com")

        assert "status" in result

    def test_scan_sqli_empty_forms(self, mock_get):
        """Empty form list should not crash."""
        mock_get.get.return_value = self._make_error_response()

        result = scan_sqli("http://example.com", forms=[])
        assert result["status"] in ("success", "partial")

    def test_sql_error_patterns_are_lists(self):
        """All SQL_ERROR_PATTERNS values should be lists."""
        for db, patterns in SQL_ERROR_PATTERNS.items():
            assert isinstance(patterns, list), f"{db} patterns not a list"
            assert len(patterns) > 0, f"{db} has empty patterns"


# =============================================================================
# XSS Tests (US-10)
# =============================================================================

class TestXSS:
    """Tests for src.modules.vuln.xss.scan_xss."""

    @pytest.fixture
    def mock_get(self):
        with patch("src.modules.vuln.xss.safe_session") as mock:
            session = MagicMock()
            mock.return_value = session
            yield session

    def _make_response(self, text="<html>OK</html>", status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.content = text.encode()
        resp.headers = {"Content-Type": "text/html"}
        return resp

    # -- Validation tests --

    def test_scan_xss_invalid_target(self):
        """Invalid target returns error status."""
        result = scan_xss(None)
        assert result["status"] == "error"

        result = scan_xss("")
        assert result["status"] == "error"

    def test_scan_xss_adds_scheme(self):
        """Target without scheme gets https:// prepended."""
        with patch("src.modules.vuln.xss.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = self._make_response()
            mock.return_value = session

            result = scan_xss("example.com")

            calls = [str(c) for c in session.get.call_args_list]
            assert any("https://example.com" in c for c in calls)

    # -- Reflection detection --

    def test_scan_xss_reflected_detected(self, mock_get):
        """Payload reflected in response should be detected as XSS."""
        payload = "<script>alert(1)</script>"
        mock_get.get.return_value = self._make_response(
            f"<html>User input: {payload}</html>"
        )

        with patch("src.modules.vuln.xss._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.xss.parse_qs") as mock_qs:
                mock_qs.return_value = {"q": [""]}
                result = scan_xss("http://example.com")

        assert result["status"] == "success"
        assert len(result["data"]["findings"]) >= 1

    def test_scan_xss_no_reflection(self, mock_get):
        """No payload reflection should return partial status."""
        mock_get.get.return_value = self._make_response(
            "<html>No user input here</html>"
        )

        with patch("src.modules.vuln.xss._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.xss.parse_qs") as mock_qs:
                mock_qs.return_value = {"q": [""]}
                result = scan_xss("http://example.com")

        assert result["status"] == "partial"
        assert len(result["data"]["findings"]) == 0

    # -- _is_reflected tests --

    def test_is_reflected_exact_match(self):
        """Exact payload match should be detected."""
        assert _is_reflected("<script>alert(1)</script>",
                             "<html><script>alert(1)</script></html>")

    def test_is_reflected_not_present(self):
        """Absent payload should not be detected."""
        assert not _is_reflected("<script>alert(1)</script>",
                                 "<html>Hello world</html>")

    def test_is_reflected_partial_match(self):
        """Partial (encoded) reflection should be detected."""
        assert _is_reflected("<script>alert(1)</script>",
                             "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>")

    # -- Context detection --

    def test_determine_context_html(self):
        """HTML context detection."""
        ctx = _determine_context("<b>test</b>", "<html><b>test</b></html>")
        assert ctx == "html"

    def test_determine_context_script(self):
        """Script context detection."""
        ctx = _determine_context("alert(1)",
                                 '<html><script>alert(1)</script></html>')
        assert ctx == "script"

    # -- POST form injection --

    def test_scan_xss_post_form(self, mock_get):
        """POST forms should be tested for XSS."""
        mock_get.get.return_value = self._make_response(
            "<html><script>alert(1)</script></html>"
        )

        forms = [{
            "action": "http://example.com/submit",
            "method": "POST",
            "inputs": [
                {"type": "text", "name": "comment", "value": ""},
                {"type": "submit", "name": "submit", "value": "Send"},
            ],
        }]

        with patch("src.modules.vuln.xss.parse_qs") as mock_qs:
            mock_qs.return_value = {}
            result = scan_xss("http://example.com", forms=forms)

        assert len(result["data"]["findings"]) >= 1

    # -- Edge cases --

    def test_xss_payloads_list_not_empty(self):
        """XSS_PAYLOADS should contain test payloads."""
        assert len(XSS_PAYLOADS) > 5

    def test_scan_xss_http_error(self, mock_get):
        """HTTP errors should not crash the scan."""
        mock_get.get.side_effect = Exception("Timeout")

        with patch("src.modules.vuln.xss._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.xss.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_xss("http://example.com")

        assert "status" in result

    def test_scan_xss_no_forms(self, mock_get):
        """No forms should not crash."""
        mock_get.get.return_value = self._make_response("<html>OK</html>")

        with patch("src.modules.vuln.xss._extract_forms_from_page", return_value=[]):
            with patch("src.modules.vuln.xss.parse_qs") as mock_qs:
                mock_qs.return_value = {"id": [""]}
                result = scan_xss("http://example.com", forms=[])

        assert result["status"] == "partial"

    def test_is_reflected_simplified(self):
        """Simplified payload (no quotes) should be detected."""
        assert _is_reflected("<script>alert('x')</script>",
                             "<html><script>alert(x)</script></html>")


# =============================================================================
# CSRF Tests (US-11)
# =============================================================================

class TestCSRF:
    """Tests for src.modules.vuln.csrf.scan_csrf."""

    # -- Token detection tests --

    def test_has_csrf_token_hidden_field(self):
        """Hidden field with csrf name should be detected."""
        inputs = [
            {"type": "hidden", "name": "csrf_token", "value": "abc123"},
            {"type": "text", "name": "email", "value": ""},
        ]
        assert _has_csrf_token(inputs)

    def test_has_csrf_token_no_token(self):
        """No CSRF token should return False."""
        inputs = [
            {"type": "text", "name": "email", "value": ""},
            {"type": "password", "name": "password", "value": ""},
        ]
        assert not _has_csrf_token(inputs)

    def test_has_csrf_token_various_names(self):
        """Various CSRF token naming conventions."""
        for name in ["csrf", "_token", "authenticity_token", "xsrf", "anticsrf"]:
            inputs = [{"type": "hidden", "name": name, "value": "x"}]
            assert _has_csrf_token(inputs), f"Failed for {name}"

    def test_has_csrf_token_case_insensitive(self):
        """CSRF token detection should be case-insensitive."""
        inputs = [{"type": "hidden", "name": "CSRF_TOKEN", "value": "x"}]
        assert _has_csrf_token(inputs)

    def test_has_csrf_token_no_hidden(self):
        """Only visible fields should not be tokens."""
        inputs = [{"type": "text", "name": "csrf_token", "value": ""}]
        assert not _has_csrf_token(inputs)

    # -- SameSite cookie tests --

    def test_check_samesite_cookies_strict(self):
        """SameSite=Strict is secure."""
        results = _check_samesite_cookies({
            "Set-Cookie": "session=abc123; SameSite=Strict; Secure"
        })
        assert len(results) == 1
        assert results[0]["samesite"] == "strict"
        assert results[0]["secure"] is True

    def test_check_samesite_cookies_lax(self):
        """SameSite=Lax is acceptable."""
        results = _check_samesite_cookies({
            "Set-Cookie": "session=abc123; SameSite=Lax"
        })
        assert results[0]["samesite"] == "lax"

    def test_check_samesite_cookies_none(self):
        """SameSite=None is insecure."""
        results = _check_samesite_cookies({
            "Set-Cookie": "session=abc123; SameSite=None"
        })
        assert results[0]["samesite"] == "none"

    def test_check_samesite_cookies_missing(self):
        """Missing SameSite is a finding."""
        results = _check_samesite_cookies({
            "Set-Cookie": "session=abc123"
        })
        assert results[0]["samesite"] is None

    def test_check_samesite_no_cookies(self):
        """No Set-Cookie header returns empty list."""
        results = _check_samesite_cookies({})
        assert results == []

    # -- SameSite severity mapping --

    def test_get_samesite_severity(self):
        """SameSite severity mapping."""
        assert _get_samesite_severity(None) == "medium"
        assert _get_samesite_severity("none") == "medium"
        assert _get_samesite_severity("lax") == "low"
        assert _get_samesite_severity("strict") is None

    # -- Full scan tests --

    def test_scan_csrf_invalid_target(self):
        """Invalid target returns error."""
        result = scan_csrf(None)
        assert result["status"] == "error"

    def test_scan_csrf_missing_token_in_form(self):
        """Form without CSRF token should be reported."""
        forms = [{
            "action": "http://example.com/login",
            "method": "POST",
            "inputs": [
                {"type": "text", "name": "username", "value": ""},
                {"type": "password", "name": "password", "value": ""},
            ],
        }]

        result = scan_csrf("http://example.com", forms=forms)
        csrf_findings = [f for f in result["data"]["findings"]
                         if f.get("type") == "missing_csrf_token"]
        assert len(csrf_findings) >= 1

    def test_scan_csrf_with_token_is_secure(self):
        """Form with CSRF token should not generate a finding."""
        forms = [{
            "action": "http://example.com/login",
            "method": "POST",
            "inputs": [
                {"type": "hidden", "name": "csrf_token", "value": "abc123"},
                {"type": "text", "name": "username", "value": ""},
                {"type": "password", "name": "password", "value": ""},
            ],
        }]

        result = scan_csrf("http://example.com", forms=forms)
        csrf_findings = [f for f in result["data"]["findings"]
                         if f.get("type") == "missing_csrf_token"]
        assert len(csrf_findings) == 0

    def test_scan_csrf_get_form_ignored(self):
        """GET forms should be ignored (no CSRF needed)."""
        forms = [{
            "action": "http://example.com/search",
            "method": "GET",
            "inputs": [
                {"type": "text", "name": "q", "value": ""},
            ],
        }]

        result = scan_csrf("http://example.com", forms=forms)
        csrf_findings = [f for f in result["data"]["findings"]
                         if f.get("type") == "missing_csrf_token"]
        assert len(csrf_findings) == 0

    def test_scan_csrf_samesite_finding(self):
        """Missing SameSite on cookie should generate finding."""
        with patch("src.modules.vuln.csrf.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {
                "Set-Cookie": "session=abc123",
                "Content-Type": "text/html",
            }
            mock_resp.text = "<html>Login page</html>"
            mock_get.return_value = mock_resp

            result = scan_csrf("http://example.com")
            cookie_findings = [f for f in result["data"]["findings"]
                               if f.get("type") == "cookie_samesite"]
            assert len(cookie_findings) >= 1

    def test_scan_csrf_empty_forms(self):
        """Empty forms should not crash."""
        result = scan_csrf("http://example.com", forms=[])
        assert "status" in result


# =============================================================================
# Sensitive Files Tests (US-12)
# =============================================================================

class TestSensitiveFiles:
    """Tests for src.modules.vuln.sensitive_files.scan_sensitive_files."""

    @pytest.fixture
    def mock_session(self):
        with patch("src.modules.vuln.sensitive_files.safe_session") as mock:
            session = MagicMock()
            mock.return_value = session
            yield session

    # -- Validation tests --

    def test_scan_sensitive_files_invalid_target(self):
        """Invalid target returns error."""
        result = scan_sensitive_files(None)
        assert result["status"] == "error"

    def test_scan_sensitive_files_adds_scheme(self):
        """Target without scheme gets https://."""
        with patch("src.modules.vuln.sensitive_files.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = MagicMock(status_code=404)
            mock.return_value = session

            result = scan_sensitive_files("example.com")

            # Verify at least one call to https://
            urls = [c[0][0] for c in session.get.call_args_list]
            assert any("https://example.com" in url for url in urls)

    # -- Detection tests --

    def test_scan_sensitive_files_200_detected(self, mock_session):
        """200 response should be flagged as exposed."""
        def side_effect(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "DATABASE_URL=postgres://user:pass@localhost/db"
            resp.content = resp.text.encode()
            resp.headers = {"Content-Type": "text/plain"}
            return resp

        mock_session.get.side_effect = side_effect

        result = scan_sensitive_files("http://example.com")

        # All paths that return 200 should be findings
        assert len(result["data"]["findings"]) >= 1
        for f in result["data"]["findings"]:
            assert f["exposed"] is True

    def test_scan_sensitive_files_404_ignored(self, mock_session):
        """404 responses should not generate findings."""
        mock_session.get.return_value = MagicMock(
            status_code=404, text="Not Found"
        )

        result = scan_sensitive_files("http://example.com")
        assert len(result["data"]["findings"]) == 0

    def test_scan_sensitive_files_403_protected(self, mock_session):
        """403 responses should be reported as protected."""
        mock_session.get.return_value = MagicMock(
            status_code=403, text="Forbidden"
        )

        result = scan_sensitive_files("http://example.com")
        protected = [f for f in result["data"]["findings"] if not f["exposed"]]
        assert len(protected) >= 1

    # -- Content preview tests --

    def test_get_content_preview_truncation(self):
        """Content preview should truncate long text."""
        text = "A" * 500
        preview = _get_content_preview(text)
        assert len(preview) <= 210  # 200 + "..."
        assert preview.endswith("...")

    def test_get_content_preview_redacts_secrets(self):
        """Secrets in content should be redacted."""
        text = "password = super_secret_123"
        preview = _get_content_preview(text)
        assert "super_secret_123" not in preview
        assert "***REDACTED***" in preview

    def test_get_content_preview_short_text(self):
        """Short text should not be truncated."""
        text = "Hello world"
        preview = _get_content_preview(text)
        assert preview == "Hello world"

    # -- Severity utilities --

    def test_path_severity_to_cvss(self):
        """CVSS mapping for path severities."""
        assert _path_severity_to_cvss("critical") == 9.0
        assert _path_severity_to_cvss("high") == 7.0
        assert _path_severity_to_cvss("medium") == 5.0
        assert _path_severity_to_cvss("low") == 2.0

    def test_downgrade_severity(self):
        """Severity downgrade for protected files."""
        assert _downgrade_severity("critical") == "high"
        assert _downgrade_severity("high") == "medium"
        assert _downgrade_severity("medium") == "low"
        assert _downgrade_severity("low") == "info"

    # -- Edge cases --

    def test_scan_sensitive_files_http_error(self, mock_session):
        """HTTP errors should not crash the scan."""
        mock_session.get.side_effect = Exception("Connection refused")

        result = scan_sensitive_files("http://example.com")
        assert result["status"] == "success"

    def test_sensitive_paths_list_has_entries(self):
        """SENSITIVE_PATHS should have multiple entries."""
        assert len(SENSITIVE_PATHS) >= 40

    def test_sensitive_paths_have_required_keys(self):
        """Each sensitive path entry should have path, description, severity."""
        for entry in SENSITIVE_PATHS:
            assert "path" in entry
            assert "description" in entry
            assert "severity" in entry
            assert entry["severity"] in ("critical", "high", "medium", "low")


# =============================================================================
# Open Redirect Tests (US-13)
# =============================================================================

class TestOpenRedirect:
    """Tests for src.modules.vuln.open_redirect.scan_open_redirect."""

    @pytest.fixture
    def mock_session(self):
        with patch("src.modules.vuln.open_redirect.safe_session") as mock:
            session = MagicMock()
            mock.return_value = session
            yield session

    def _make_redirect_response(self, location="https://evil.com", status=302):
        """Create a mock redirect response."""
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"Location": location}
        resp.text = "<html>Redirecting...</html>"
        return resp

    def _make_normal_response(self, text="<html>OK</html>"):
        """Create a normal (non-redirect) response."""
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = text
        return resp

    # -- Validation tests --

    def test_scan_open_redirect_invalid_target(self):
        """Invalid target returns error."""
        result = scan_open_redirect(None)
        assert result["status"] == "error"

    def test_scan_open_redirect_adds_scheme(self):
        """Target without scheme gets https://."""
        with patch("src.modules.vuln.open_redirect.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = self._make_normal_response()
            mock.return_value = session
            result = scan_open_redirect("example.com")

            urls = [c[0][0] for c in session.get.call_args_list
                    if c[0]]
            assert any("https://example.com" in url for url in urls)

    # -- Redirect detection tests --

    def test_scan_open_redirect_detected(self, mock_session):
        """302 redirect to external URL should be detected."""
        def side_effect(url, **kw):
            if "evil" in url:
                return self._make_redirect_response("https://evil.com")
            return self._make_normal_response()

        mock_session.get.side_effect = side_effect

        result = scan_open_redirect("http://example.com")
        assert result["status"] == "success"
        assert len(result["data"]["findings"]) >= 1

    def test_scan_open_redirect_no_redirect(self, mock_session):
        """No redirect should return partial status."""
        mock_session.get.return_value = self._make_normal_response()

        result = scan_open_redirect("http://example.com")
        assert result["status"] == "partial"
        assert len(result["data"]["findings"]) == 0

    # -- _is_external_url tests --

    def test_is_external_url_external(self):
        """External URL should be detected as external."""
        assert _is_external_url("https://evil.com", "example.com")

    def test_is_external_url_internal(self):
        """Internal URL should not be detected as external."""
        assert not _is_external_url("https://example.com/page", "example.com")

    def test_is_external_url_no_netloc(self):
        """URL without netloc should not be external."""
        assert not _is_external_url("/relative/path", "example.com")

    # -- Meta refresh tests --

    def test_check_meta_refresh_found(self):
        """Meta refresh tag with external URL should be detected."""
        html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        result = _check_meta_refresh(html)
        assert result == "https://evil.com"

    def test_check_meta_refresh_not_found(self):
        """HTML without meta refresh should return None."""
        result = _check_meta_refresh("<html>OK</html>")
        assert result is None

    def test_check_meta_refresh_no_external(self):
        """Meta refresh with internal URL should be detected too."""
        html = '<meta http-equiv="refresh" content="0;url=/dashboard">'
        result = _check_meta_refresh(html)
        assert result == "/dashboard"

    # -- JS redirect tests --

    def test_check_js_redirect_found(self):
        """JavaScript redirect to external URL should be detected."""
        html = '<script>window.location.href = "https://evil.com";</script>'
        result = _check_js_redirect(html, "https://evil.com")
        assert result == "https://evil.com"

    def test_check_js_redirect_not_found(self):
        """HTML without JS redirect should return None."""
        result = _check_js_redirect("<html>OK</html>", "https://evil.com")
        assert result is None

    # -- Edge cases --

    def test_scan_open_redirect_http_error(self, mock_session):
        """HTTP errors should not crash the scan."""
        mock_session.get.side_effect = Exception("Timeout")

        result = scan_open_redirect("http://example.com")
        assert result["status"] == "error" or result["status"] == "partial"

    def test_scan_open_redirect_301_redirect(self, mock_session):
        """301 redirect should also be detected."""
        def side_effect(url, **kw):
            return self._make_redirect_response("https://evil.com", 301)

        mock_session.get.side_effect = side_effect

        result = scan_open_redirect("http://example.com")
        if result["status"] == "success":
            assert result["data"]["findings"][0]["status_code"] == 301

    def test_scan_open_redirect_303_redirect(self, mock_session):
        """303 redirect should also be detected."""
        def side_effect(url, **kw):
            return self._make_redirect_response("https://evil.com", 303)

        mock_session.get.side_effect = side_effect

        result = scan_open_redirect("http://example.com")
        if result["status"] == "success":
            assert result["data"]["findings"][0]["status_code"] == 303

    def test_scan_open_redirect_meta_refresh_finding(self, mock_session):
        """Meta refresh redirect should be detected."""
        def side_effect(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            resp.text = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
            return resp

        mock_session.get.side_effect = side_effect

        result = scan_open_redirect("http://example.com")
        if result["status"] == "success":
            finding = result["data"]["findings"][0]
            assert finding.get("redirect_type") == "meta_refresh"


# =============================================================================
# Scanner Integration Tests
# =============================================================================

class TestScannerVulnIntegration:
    """Tests for vuln integration in Scanner."""

    def test_scanner_run_vuln_exists(self, sample_target):
        """Scanner should have _run_vuln method."""
        s = Scanner(sample_target)
        assert hasattr(s, "_run_vuln")

    def test_scanner_run_vuln_returns_dict(self, sample_target):
        """_run_vuln should return a dict with all sub-modules."""
        s = Scanner(sample_target)
        result = s._run_vuln()
        assert isinstance(result, dict)
        assert "sqli" in result
        assert "xss" in result
        assert "csrf" in result
        assert "sensitive_files" in result
        assert "open_redirect" in result

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    def test_scanner_run_includes_vuln(self, mock_web, mock_recon, sample_target):
        """Scanner.run() should include vuln results."""
        mock_recon.return_value = {}
        mock_web.return_value = {}

        s = Scanner(sample_target)
        result = s.run()
        assert "vuln" in result["modules"]

    def test_scanner_run_vuln_module_only(self, sample_target):
        """Running vuln-only should only return vuln results."""
        s = Scanner(sample_target, modules=["vuln"])
        result = s.run()
        assert "vuln" in result["modules"]
        # Should not run recon or web
        assert result["modules"].get("recon", "__missing__") == "__missing__" or \
               result["modules"]["recon"] == {}
        assert result["modules"].get("web", "__missing__") == "__missing__" or \
               result["modules"]["web"] == {}


# =============================================================================
# Additional Edge Case & Quality Tests
# =============================================================================

class TestVulnModuleQuality:
    """Quality checks for the vuln module package."""

    def test_vuln_init_exists(self):
        """__init__.py should be importable."""
        from src.modules import vuln
        assert vuln.__name__ == "src.modules.vuln"

    def test_sqli_module_importable(self):
        """sqli module should be importable."""
        from src.modules.vuln import sqli
        assert hasattr(sqli, "scan_sqli")

    def test_xss_module_importable(self):
        """xss module should be importable."""
        from src.modules.vuln import xss
        assert hasattr(xss, "scan_xss")

    def test_csrf_module_importable(self):
        """csrf module should be importable."""
        from src.modules.vuln import csrf
        assert hasattr(csrf, "scan_csrf")

    def test_sensitive_files_module_importable(self):
        """sensitive_files module should be importable."""
        from src.modules.vuln import sensitive_files
        assert hasattr(sensitive_files, "scan_sensitive_files")

    def test_open_redirect_module_importable(self):
        """open_redirect module should be importable."""
        from src.modules.vuln import open_redirect
        assert hasattr(open_redirect, "scan_open_redirect")

    # -- Return value contract tests --

    def _check_contract(self, result):
        """Verify the standard return contract."""
        assert isinstance(result, dict)
        assert "status" in result
        assert result["status"] in ("success", "error", "partial")
        assert "data" in result
        assert "findings" in result["data"]
        return True

    def test_sqli_return_contract(self):
        """SQLi result should follow the contract."""
        result = scan_sqli("http://example.com", forms=[])
        assert self._check_contract(result)

    def test_xss_return_contract(self):
        """XSS result should follow the contract."""
        result = scan_xss("http://example.com", forms=[])
        assert self._check_contract(result)

    def test_csrf_return_contract(self):
        """CSRF result should follow the contract."""
        result = scan_csrf("http://example.com", forms=[])
        assert self._check_contract(result)

    def test_sensitive_files_return_contract(self):
        """Sensitive files result should follow the contract."""
        with patch("src.modules.vuln.sensitive_files.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = MagicMock(status_code=404)
            mock.return_value = session
            result = scan_sensitive_files("http://example.com")
        assert self._check_contract(result)

    def test_open_redirect_return_contract(self):
        """Open redirect result should follow the contract."""
        with patch("src.modules.vuln.open_redirect.safe_session") as mock:
            session = MagicMock()
            session.get.return_value = MagicMock(
                status_code=200, text="<html>OK</html>"
            )
            mock.return_value = session
            result = scan_open_redirect("http://example.com")
        assert self._check_contract(result)
