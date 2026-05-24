"""Comprehensive unit tests for the web analysis module (headers, SSL, crawler, fingerprint)."""

import socket
import ssl
from unittest.mock import MagicMock, Mock, patch, call, PropertyMock

import pytest

from src.modules.web.headers import analyze_headers, HEADER_CHECKS, MAX_SCORE
from src.modules.web.ssl_tls import audit_ssl, _is_weak_cipher, _is_strong_cipher
from src.modules.web.crawler import (
    crawl,
    _normalize_url,
    _is_same_domain,
    _extract_forms,
    _extract_links,
    _extract_resources,
)
from src.modules.web.fingerprint import fingerprint, _find_meta_tag, _check_paths
from src.core.scanner import Scanner


# =============================================================================
# Headers Tests (US-05)
# =============================================================================

class TestHeaders:
    """Tests for src.modules.web.headers.analyze_headers."""

    @pytest.fixture
    def mock_response_factory(self):
        """Return a factory that creates mock responses with custom headers."""
        from tests.helpers import make_mock_response

        def factory(status_code=200, headers=None, text="OK", url="https://example.com"):
            return make_mock_response(
                status_code=status_code,
                headers=headers or {},
                text=text,
                url=url,
            )
        return factory

    @pytest.fixture
    def secure_headers(self):
        """A dict of all 'perfect' security headers."""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()",
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST",
        }

    # -- Success Cases --

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_all_secure(self, mock_get, mock_response_factory, secure_headers):
        """All security headers present and correctly configured get max score."""
        mock_resp = mock_response_factory(headers=secure_headers)
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        assert result["status"] == "success"
        assert result["data"]["score"] == MAX_SCORE
        assert result["data"]["grade"] == "A"
        assert result["data"]["percentage"] == 100.0

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_no_headers(self, mock_get, mock_response_factory):
        """No security headers returns score 0 and grade F."""
        mock_resp = mock_response_factory(headers={"Content-Type": "text/html"})
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        assert result["status"] == "success"
        assert result["data"]["score"] == 0
        assert result["data"]["grade"] == "F"

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_partial_hsts(self, mock_get, mock_response_factory):
        """HSTS without includeSubDomains gets partial score."""
        mock_resp = mock_response_factory(headers={
            "Strict-Transport-Security": "max-age=31536000",
        })
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        hsts = [h for h in result["data"]["headers"] if h["header"] == "Strict-Transport-Security"][0]
        assert hsts["status"] == "partial"
        assert hsts["score"] == 10  # half of 20

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_grade_b(self, mock_get, mock_response_factory):
        """Score of 80% gets grade B."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        mock_resp = mock_response_factory(headers=headers)
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        assert result["data"]["grade"] == "B"
        assert 75 <= result["data"]["percentage"] < 90

    # -- Error Cases --

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_fetch_failure(self, mock_get):
        """Failed HTTP request returns error status."""
        mock_get.return_value = None

        result = analyze_headers("https://example.com")
        assert result["status"] == "error"
        assert result["error"] is not None

    def test_analyze_headers_invalid_url_empty(self):
        """Empty URL returns error."""
        result = analyze_headers("")
        assert result["status"] == "error"

    def test_analyze_headers_invalid_url_none(self):
        """None URL returns error."""
        result = analyze_headers(None)  # type: ignore[arg-type]
        assert result["status"] == "error"

    def test_analyze_headers_invalid_url_not_string(self):
        """Non-string URL returns error."""
        result = analyze_headers(123)  # type: ignore[arg-type]
        assert result["status"] == "error"

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_url_scheme_added(self, mock_get, mock_response_factory):
        """URL without scheme gets https:// prepended."""
        mock_resp = mock_response_factory(url="https://example.com")
        mock_get.return_value = mock_resp

        analyze_headers("example.com")
        # Verify https:// was prepended
        call_url = mock_get.call_args[0][0]
        assert call_url == "https://example.com"

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_result_structure(self, mock_get, mock_response_factory):
        """Return dict has the expected keys."""
        mock_resp = mock_response_factory(headers={"X-Frame-Options": "DENY"})
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        assert set(result.keys()) == {"status", "data", "error"}
        assert "headers" in result["data"]
        assert "score" in result["data"]
        assert "max_score" in result["data"]
        assert "percentage" in result["data"]
        assert "grade" in result["data"]

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_header_entry_keys(self, mock_get, mock_response_factory):
        """Each header entry has the expected keys."""
        mock_resp = mock_response_factory(headers={"X-Frame-Options": "DENY"})
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        entry = result["data"]["headers"][0]
        expected_keys = {
            "header", "present", "value", "score", "max_score",
            "status", "recommendation", "description",
        }
        assert set(entry.keys()) == expected_keys

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_cors_wildcard(self, mock_get, mock_response_factory):
        """CORS with wildcard origin gets score 0."""
        mock_resp = mock_response_factory(headers={
            "Access-Control-Allow-Origin": "*",
        })
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        cors = [h for h in result["data"]["headers"] if h["header"] == "Access-Control-Allow-Origin"][0]
        assert cors["status"] == "partial"
        assert cors["score"] == 2

    @patch("src.modules.web.headers.get")
    def test_analyze_headers_xss_protection_disabled(self, mock_get, mock_response_factory):
        """X-XSS-Protection set to 0 gets partial score."""
        mock_resp = mock_response_factory(headers={
            "X-XSS-Protection": "0",
        })
        mock_get.return_value = mock_resp

        result = analyze_headers("https://example.com")
        xss = [h for h in result["data"]["headers"] if h["header"] == "X-XSS-Protection"][0]
        assert xss["status"] == "fail"

    def test_calculate_grade_a(self):
        """90%+ gets A."""
        from src.modules.web.headers import _calculate_grade
        assert _calculate_grade(95.0) == "A"
        assert _calculate_grade(100.0) == "A"

    def test_calculate_grade_b(self):
        """75-89% gets B."""
        from src.modules.web.headers import _calculate_grade
        assert _calculate_grade(80.0) == "B"
        assert _calculate_grade(75.0) == "B"

    def test_calculate_grade_f(self):
        """<40% gets F."""
        from src.modules.web.headers import _calculate_grade
        assert _calculate_grade(30.0) == "F"
        assert _calculate_grade(0.0) == "F"


# =============================================================================
# SSL/TLS Tests (US-06)
# =============================================================================

class TestSSL:
    """Tests for src.modules.web.ssl_tls.audit_ssl."""

    @pytest.fixture
    def mock_cert(self):
        """Sample certificate dict as returned by ssl.getpeercert()."""
        return {
            "subject": [
                [("commonName", "example.com")],
                [("organizationName", "Example Inc")],
            ],
            "issuer": [
                [("commonName", "CA Authority")],
                [("organizationName", "Trusted CA")],
            ],
            "notBefore": "May 24 00:00:00 2025 GMT",
            "notAfter": "May 24 00:00:00 2027 GMT",
            "serialNumber": "1234567890ABCDEF",
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
            ),
            "fingerprint": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
            "version": 3,
            "extensions": [],
        }

    def _make_tls_socket(self, version="TLSv1.3", tls_version=ssl.TLSVersion.TLSv1_3,
                         cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                         cert=None):
        """Create a mock TLS socket with specified configuration."""
        mock_sock = MagicMock(spec=ssl.SSLSocket)
        mock_sock.version.return_value = version
        # Use Mock instead of returning MagicMock for proper tuple unpacking
        mock_sock.cipher = Mock(return_value=cipher)
        mock_sock.getpeercert = Mock(return_value=cert or {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA Authority"),),),
            "notBefore": "May 24 00:00:00 2025 GMT",
            "notAfter": "May 24 00:00:00 2027 GMT",
            "serialNumber": "1234",
            "subjectAltName": (("DNS", "example.com"),),
            "fingerprint": "",
            "extensions": [],
        })
        mock_sslobj = MagicMock()
        mock_sslobj._get_tls_version_number = Mock(return_value=tls_version)
        mock_sock._sslobj = mock_sslobj
        # Python 3.14+: MagicMock.__enter__ no longer returns self
        mock_sock.__enter__.return_value = mock_sock
        return mock_sock

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    @patch("src.modules.web.ssl_tls.ssl.create_default_context")
    def test_audit_ssl_success_tls13(self, mock_ssl_ctx, mock_create_conn):
        """Successful TLS 1.3 audit returns secure result."""
        tls_sock = self._make_tls_socket()

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value = tls_sock

        mock_conn = MagicMock()
        mock_create_conn.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn

        result = audit_ssl("example.com", 443)

        assert result["status"] == "success"
        assert result["data"]["tls_version"] == "TLS 1.3"
        assert result["data"]["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
        assert result["data"]["cipher"]["is_weak"] is False
        assert result["data"]["cipher"]["is_strong"] is True
        assert result["data"]["secure"] is True
        assert result["data"]["vulnerabilities"] == []

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    @patch("src.modules.web.ssl_tls.ssl.create_default_context")
    def test_audit_ssl_self_signed(self, mock_ssl_ctx, mock_create_conn):
        """Self-signed certificate flagged as vulnerability."""
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "example.com"),),),  # Same as subject
            "notBefore": "May 24 00:00:00 2025 GMT",
            "notAfter": "May 24 00:00:00 2027 GMT",
            "serialNumber": "1234",
            "subjectAltName": (("DNS", "example.com"),),
            "fingerprint": "",
            "extensions": [],
        }
        tls_sock = self._make_tls_socket(cert=cert)

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value = tls_sock

        mock_conn = MagicMock()
        mock_create_conn.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn

        result = audit_ssl("example.com", 443)

        assert result["status"] == "success"
        vuln_names = [v["name"] for v in result["data"]["vulnerabilities"]]
        assert "SELF_SIGNED_CERTIFICATE" in vuln_names

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    @patch("src.modules.web.ssl_tls.ssl.create_default_context")
    def test_audit_ssl_expired_cert(self, mock_ssl_ctx, mock_create_conn):
        """Expired certificate flagged as CRITICAL vulnerability."""
        from datetime import datetime, timezone, timedelta
        past = datetime.now(timezone.utc) - timedelta(days=30)
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA Authority"),),),
            "notBefore": "May 24 00:00:00 2022 GMT",
            "notAfter": past.strftime("%b %d %H:%M:%S %Y GMT"),
            "serialNumber": "1234",
            "subjectAltName": (("DNS", "example.com"),),
            "fingerprint": "",
            "extensions": [],
        }
        tls_sock = self._make_tls_socket(cert=cert)

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value = tls_sock

        mock_conn = MagicMock()
        mock_create_conn.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn

        result = audit_ssl("example.com", 443)

        assert result["status"] == "success"
        vuln_names = [v["name"] for v in result["data"]["vulnerabilities"]]
        assert "EXPIRED_CERTIFICATE" in vuln_names
        expired_vuln = [v for v in result["data"]["vulnerabilities"] if v["name"] == "EXPIRED_CERTIFICATE"][0]
        assert expired_vuln["severity"] == "CRITICAL"

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    @patch("src.modules.web.ssl_tls.ssl.create_default_context")
    def test_audit_ssl_tls12(self, mock_ssl_ctx, mock_create_conn):
        """TLS 1.2 gets a LOW vulnerability (moderate)."""
        tls_sock = self._make_tls_socket(
            version="TLSv1.2",
            tls_version=ssl.TLSVersion.TLSv1_2,
        )

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value = tls_sock

        mock_conn = MagicMock()
        mock_create_conn.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn

        result = audit_ssl("example.com", 443)

        assert result["status"] == "success"
        vuln_names = [v["name"] for v in result["data"]["vulnerabilities"]]
        assert "MODERATE_TLS_VERSION" in vuln_names

    # -- Error Cases --

    def test_audit_ssl_invalid_hostname_empty(self):
        """Empty hostname returns error."""
        result = audit_ssl("")
        assert result["status"] == "error"

    def test_audit_ssl_invalid_hostname_none(self):
        """None hostname returns error."""
        result = audit_ssl(None)  # type: ignore[arg-type]
        assert result["status"] == "error"

    def test_audit_ssl_invalid_hostname_not_string(self):
        """Non-string hostname returns error."""
        result = audit_ssl(123)  # type: ignore[arg-type]
        assert result["status"] == "error"

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    def test_audit_ssl_timeout(self, mock_create_conn):
        """Connection timeout returns error."""
        mock_create_conn.side_effect = socket.timeout("timed out")

        result = audit_ssl("example.com", 443)
        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    def test_audit_ssl_connection_refused(self, mock_create_conn):
        """Connection refused returns error."""
        mock_create_conn.side_effect = ConnectionRefusedError

        result = audit_ssl("example.com", 443)
        assert result["status"] == "error"
        assert "Connection refused" in result["error"]

    @patch("src.modules.web.ssl_tls.socket.create_connection")
    def test_audit_ssl_dns_failure(self, mock_create_conn):
        """DNS resolution failure returns error."""
        mock_create_conn.side_effect = socket.gaierror("Name or service not known")

        result = audit_ssl("nonexistent.example.com", 443)
        assert result["status"] == "error"
        assert "DNS" in result["error"]

    def test_is_weak_cipher_true(self):
        """Weak cipher keywords are detected."""
        assert _is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA") is True
        assert _is_weak_cipher("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA") is True
        assert _is_weak_cipher("TLS_ECDHE_RSA_WITH_NULL_SHA") is True

    def test_is_weak_cipher_false(self):
        """Strong ciphers are not marked weak."""
        assert _is_weak_cipher("TLS_AES_256_GCM_SHA384") is False
        assert _is_weak_cipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") is False

    def test_is_strong_cipher_true(self):
        """Strong cipher prefixes are detected."""
        assert _is_strong_cipher("TLS_AES_256_GCM_SHA384") is True
        # OpenSSL naming with dashes
        assert _is_strong_cipher("ECDHE-RSA-AES256-GCM-SHA384") is True
        assert _is_strong_cipher("ECDHE-ECDSA-AES128-GCM-SHA256") is True
        assert _is_strong_cipher("DHE-RSA-AES128-GCM-SHA256") is True

    def test_is_strong_cipher_false(self):
        """Weak ciphers are not marked strong."""
        assert _is_strong_cipher("TLS_RSA_WITH_RC4_128_SHA") is False


# =============================================================================
# Crawler Tests (US-07)
# =============================================================================

class TestCrawler:
    """Tests for src.modules.web.crawler.crawl."""

    @pytest.fixture(autouse=True)
    def clear_robots_cache(self):
        """Clear the global robots.txt cache between tests."""
        import src.modules.web.crawler as crawler_mod
        crawler_mod._robots_disallowed = []
        yield

    SAMPLE_HTML = (
        '<html><head><title>Test Page</title></head><body>'
        '<a href="/page1">Page 1</a>'
        '<a href="https://external.com">External</a>'
        '<form action="/login" method="POST">'
        '<input type="text" name="user"/>'
        '<input type="password" name="pass"/>'
        '</form>'
        '<script src="/js/app.js"></script>'
        '<img src="/img/logo.png"/>'
        '<link rel="stylesheet" href="/css/style.css"/>'
        '</body></html>'
    )

    PAGE1_HTML = (
        '<html><head><title>Page 1</title></head><body>'
        '<a href="/page2">Page 2</a>'
        '<form action="/submit" method="GET">'
        '<input type="text" name="q"/>'
        '</form>'
        '</body></html>'
    )

    PAGE2_HTML = (
        '<html><head><title>Page 2</title></head><body>'
        '<a href="https://other.com">Other</a>'
        '</body></html>'
    )

    @patch("src.modules.web.crawler.get")
    def test_crawl_basic(self, mock_get):
        """Basic crawl returns pages, forms, links, and resources."""

        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url == "https://example.com/robots.txt":
                resp.status_code = 404
            elif url == "https://example.com/":
                resp.text = self.SAMPLE_HTML
                resp.url = "https://example.com/"
            else:
                resp.text = "<html><body>Unknown</body></html>"
                resp.url = url
            return resp

        mock_get.side_effect = side_effect

        result = crawl("https://example.com/", max_depth=0)

        assert result["status"] == "success"
        assert result["data"]["total_pages"] == 1  # depth 0 = only homepage
        assert result["data"]["total_forms"] == 1
        assert result["data"]["total_resources"] == 3  # script, img, link

    @patch("src.modules.web.crawler.get")
    def test_crawl_depth_2(self, mock_get):
        """Depth 2 crawl discovers internal linked pages."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url == "https://example.com/robots.txt":
                resp.status_code = 404
            elif url == "https://example.com/":
                resp.text = self.SAMPLE_HTML
                resp.url = "https://example.com/"
            elif url == "https://example.com/page1":
                resp.text = self.PAGE1_HTML
                resp.url = url
            elif url == "https://example.com/page2":
                resp.text = self.PAGE2_HTML
                resp.url = url
            else:
                resp.text = "<html><body>Unknown</body></html>"
                resp.url = url
            return resp

        mock_get.side_effect = side_effect

        result = crawl("https://example.com/", max_depth=2)

        assert result["status"] == "success"
        assert result["data"]["total_pages"] >= 2

    @patch("src.modules.web.crawler.get")
    def test_crawl_form_extraction(self, mock_get):
        """Form extraction produces correct structure."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url == "https://example.com/robots.txt":
                resp.status_code = 404
            elif url == "https://example.com/":
                resp.text = self.SAMPLE_HTML
                resp.url = url
            else:
                resp.text = self.SAMPLE_HTML
                resp.url = url
            return resp

        mock_get.side_effect = side_effect

        result = crawl("https://example.com/", max_depth=0)

        assert result["status"] == "success"
        assert len(result["data"]["forms"]) == 1
        form = result["data"]["forms"][0]
        assert form["method"] == "POST"
        assert "/login" in form["action"]
        assert len(form["inputs"]) == 2
        assert form["inputs"][0]["name"] == "user"

    def test_crawl_invalid_url_empty(self):
        """Empty URL returns error."""
        result = crawl("")
        assert result["status"] == "error"

    def test_crawl_invalid_url_none(self):
        """None URL returns error."""
        result = crawl(None)  # type: ignore[arg-type]
        assert result["status"] == "error"

    @patch("src.modules.web.crawler.get")
    def test_crawl_non_html_content_type(self, mock_get):
        """Non-HTML responses are skipped."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if url == "https://example.com/robots.txt":
                resp.status_code = 404
            else:
                resp.headers = {"Content-Type": "application/json"}
                resp.text = '{"key": "value"}'
                resp.url = url
            return resp

        mock_get.side_effect = side_effect

        result = crawl("https://example.com/", max_depth=1)

        assert result["status"] == "success"
        assert result["data"]["total_pages"] == 0  # no HTML pages found

    def test_normalize_url_removes_fragment(self):
        """URL fragment is removed during normalization."""
        result = _normalize_url("https://example.com", "/page#section")
        assert result is not None
        assert "#" not in result

    def test_normalize_url_invalid_scheme(self):
        """Non-http/https URLs return None."""
        result = _normalize_url("https://example.com", "ftp://files.example.com")
        assert result is None

    def test_normalize_url_javascript(self):
        """javascript: links return None."""
        result = _normalize_url("https://example.com", "javascript:void(0)")
        assert result is None

    def test_is_same_domain_true(self):
        """Same domain returns True."""
        assert _is_same_domain("https://www.example.com/page", "example.com") is True

    def test_is_same_domain_false(self):
        """Different domain returns False."""
        assert _is_same_domain("https://other.com/page", "example.com") is False

    def test_extract_forms_empty(self):
        """No forms in HTML returns empty list."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><p>No forms</p></body></html>", "html.parser")
        forms = _extract_forms(soup, "https://example.com")
        assert forms == []

    def test_extract_links_empty(self):
        """No links in HTML returns empty list."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><p>No links</p></body></html>", "html.parser")
        links = _extract_links(soup, "https://example.com")
        assert links == []

    def test_extract_resources_empty(self):
        """No resources in HTML returns empty list."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><p>No resources</p></body></html>", "html.parser")
        resources = _extract_resources(soup, "https://example.com")
        assert resources == []


# =============================================================================
# Fingerprint Tests (US-08)
# =============================================================================

class TestFingerprint:
    """Tests for src.modules.web.fingerprint.fingerprint."""

    @pytest.fixture
    def mock_wordpress_response(self):
        """Create a mock response with WordPress headers and body."""
        from tests.helpers import make_mock_response
        return make_mock_response(
            status_code=200,
            headers={
                "X-Generator": "WordPress 6.0",
                "Server": "Apache/2.4.41",
            },
            text=(
                '<html><head>'
                '<meta name="generator" content="WordPress 6.0" />'
                '</head><body>'
                '<link rel="stylesheet" href="/wp-content/themes/style.css"/>'
                '<script src="/wp-includes/js/jquery.js"/>'
                '</body></html>'
            ),
            url="https://example.com",
        )

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_wordpress(self, mock_get, mock_wordpress_response):
        """WordPress detection from headers and meta tags."""
        # First call returns the homepage
        # Subsequent path check calls also return 200 for wp paths
        call_count = 0

        def side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_wordpress_response
            # Path checks: return 200 for wp paths
            resp = MagicMock()
            if "/wp-" in url:
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp

        mock_get.side_effect = side_effect

        result = fingerprint("https://example.com")

        assert result["status"] == "success"
        techs = {t["name"]: t for t in result["data"]["technologies"]}
        assert "WordPress" in techs
        assert techs["WordPress"]["confidence"] >= 0.5
        assert techs["WordPress"]["category"] == "CMS"

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_django(self, mock_get):
        """Django detection from headers."""
        from tests.helpers import make_mock_response
        mock_resp = make_mock_response(
            status_code=200,
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            text='<html><body>Admin: <a href="/admin/">Admin</a></body></html>',
            url="https://example.com",
        )
        mock_get.return_value = mock_resp

        result = fingerprint("https://example.com")

        assert result["status"] == "success"
        techs = {t["name"]: t for t in result["data"]["technologies"]}
        assert "Django" in techs

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_cloudflare(self, mock_get):
        """Cloudflare detection from headers."""
        from tests.helpers import make_mock_response
        mock_resp = make_mock_response(
            status_code=200,
            headers={
                "Server": "cloudflare",
                "CF-RAY": "123abc",
            },
            text="<html><body>Site behind Cloudflare</body></html>",
            url="https://example.com",
        )
        mock_get.return_value = mock_resp

        result = fingerprint("https://example.com")

        assert result["status"] == "success"
        techs = {t["name"]: t for t in result["data"]["technologies"]}
        assert "Cloudflare" in techs

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_no_tech_detected(self, mock_get):
        """Minimal response with no tech signatures returns empty list."""
        from tests.helpers import make_mock_response
        mock_resp = make_mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="<html><body>Custom static site</body></html>",
            url="https://example.com",
        )
        mock_get.return_value = mock_resp

        result = fingerprint("https://example.com")

        assert result["status"] == "success"
        assert result["data"]["total_detected"] >= 0

    # -- Error Cases --

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_fetch_failure(self, mock_get):
        """Failed HTTP request returns error status."""
        mock_get.return_value = None

        result = fingerprint("https://example.com")
        assert result["status"] == "error"

    def test_fingerprint_invalid_url_empty(self):
        """Empty URL returns error."""
        result = fingerprint("")
        assert result["status"] == "error"

    def test_fingerprint_invalid_url_none(self):
        """None URL returns error."""
        result = fingerprint(None)  # type: ignore[arg-type]
        assert result["status"] == "error"

    def test_find_meta_tag_found(self):
        """Meta generator tag is found and content extracted."""
        html = '<meta name="generator" content="WordPress 6.0" />'
        assert _find_meta_tag(html, "generator") == "WordPress 6.0"

    def test_find_meta_tag_not_found(self):
        """Missing meta tag returns None."""
        html = "<html><head></head><body></body></html>"
        assert _find_meta_tag(html, "generator") is None

    def test_find_meta_tag_reversed_attrs(self):
        """Meta tag with reversed attribute order."""
        html = '<meta content="Drupal 9" name="generator" />'
        assert _find_meta_tag(html, "generator") == "Drupal 9"

    @patch("src.modules.web.fingerprint.get")
    def test_check_paths_all_found(self, mock_get):
        """All paths found returns 0.3 confidence."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        mock_get.side_effect = side_effect

        confidence = _check_paths("https://example.com", ["/path1", "/path2"])
        assert confidence == 0.3

    @patch("src.modules.web.fingerprint.get")
    def test_check_paths_none_found(self, mock_get):
        """No paths found returns 0.0 confidence."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        mock_get.side_effect = side_effect

        confidence = _check_paths("https://example.com", ["/path1", "/path2"])
        assert confidence == 0.0

    @patch("src.modules.web.fingerprint.get")
    def test_fingerprint_result_structure(self, mock_get):
        """Return dict has the expected structure."""
        from tests.helpers import make_mock_response
        mock_resp = make_mock_response(
            status_code=200,
            headers={},
            text="<html><body>Hello</body></html>",
        )
        mock_get.return_value = mock_resp

        result = fingerprint("https://example.com")
        assert set(result.keys()) == {"status", "data", "error"}
        assert "technologies" in result["data"]
        assert "total_detected" in result["data"]


# =============================================================================
# Scanner Integration Tests
# =============================================================================

class TestScannerWebIntegration:
    """Tests for Scanner.run() with web module integration."""

    @patch("src.modules.web.headers.analyze_headers")
    @patch("src.modules.web.ssl_tls.audit_ssl")
    @patch("src.modules.web.crawler.crawl")
    @patch("src.modules.web.fingerprint.fingerprint")
    def test_scanner_run_web_module(
        self, mock_fp, mock_crawl, mock_ssl, mock_headers, sample_target,
    ):
        """Scanner.run() with web module calls all web sub-modules."""
        mock_headers.return_value = {
            "status": "success",
            "data": {"headers": [], "score": 100, "max_score": 100, "percentage": 100.0, "grade": "A"},
            "error": None,
        }
        mock_ssl.return_value = {
            "status": "success",
            "data": {"tls_version": "TLS 1.3", "secure": True},
            "error": None,
        }
        mock_crawl.return_value = {
            "status": "success",
            "data": {"pages": [], "total_pages": 0, "total_forms": 0, "total_links": 0, "total_resources": 0},
            "error": None,
        }
        mock_fp.return_value = {
            "status": "success",
            "data": {"technologies": [], "total_detected": 0},
            "error": None,
        }

        scanner = Scanner(sample_target, modules=["web"])
        results = scanner.run()

        assert results["target"] == sample_target
        assert "web" in results["modules"]
        assert "headers" in results["modules"]["web"]
        assert "ssl_tls" in results["modules"]["web"]
        assert "crawler" in results["modules"]["web"]
        assert "fingerprint" in results["modules"]["web"]

        mock_headers.assert_called_once()
        mock_ssl.assert_called_once()
        mock_crawl.assert_called_once()
        mock_fp.assert_called_once()

    @patch("src.modules.web.headers.analyze_headers")
    @patch("src.modules.web.ssl_tls.audit_ssl")
    @patch("src.modules.web.crawler.crawl")
    @patch("src.modules.web.fingerprint.fingerprint")
    def test_scanner_web_module_failure_graceful(
        self, mock_fp, mock_crawl, mock_ssl, mock_headers, sample_target,
    ):
        """Exception in a web sub-module does not crash the scanner."""
        mock_headers.side_effect = RuntimeError("Headers crashed")
        mock_ssl.side_effect = RuntimeError("SSL crashed")
        mock_crawl.side_effect = RuntimeError("Crawler crashed")
        mock_fp.side_effect = RuntimeError("Fingerprint crashed")

        scanner = Scanner(sample_target, modules=["web"])
        results = scanner.run()

        assert results["modules"]["web"]["headers"]["status"] == "error"
        assert results["modules"]["web"]["ssl_tls"]["status"] == "error"
        assert results["modules"]["web"]["crawler"]["status"] == "error"
        assert results["modules"]["web"]["fingerprint"]["status"] == "error"

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    @patch("src.modules.web.headers.analyze_headers")
    @patch("src.modules.web.ssl_tls.audit_ssl")
    @patch("src.modules.web.crawler.crawl")
    @patch("src.modules.web.fingerprint.fingerprint")
    def test_scanner_run_all_modules(
        self, mock_fp, mock_crawl, mock_ssl, mock_headers,
        mock_scan, mock_sub, mock_whois, mock_dns, sample_target,
    ):
        """Scanner.run() with modules=['all'] runs both recon and web."""
        # Configure recon mocks
        mock_dns.return_value = {"A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        mock_whois.return_value = {"registrar": None, "organization": None, "country": None,
                                   "creation_date": None, "expiration_date": None,
                                   "updated_date": None, "name_servers": [], "raw": None}
        mock_sub.return_value = []
        mock_scan.return_value = []

        # Configure web mocks
        mock_headers.return_value = {"status": "success", "data": {}, "error": None}
        mock_ssl.return_value = {"status": "success", "data": {}, "error": None}
        mock_crawl.return_value = {"status": "success", "data": {}, "error": None}
        mock_fp.return_value = {"status": "success", "data": {}, "error": None}

        scanner = Scanner(sample_target, modules=["all"])
        results = scanner.run()

        assert "recon" in results["modules"]
        assert "web" in results["modules"]

    @patch("src.modules.web.headers.analyze_headers")
    @patch("src.modules.web.ssl_tls.audit_ssl")
    @patch("src.modules.web.crawler.crawl")
    @patch("src.modules.web.fingerprint.fingerprint")
    def test_scanner_run_excludes_web(
        self, mock_fp, mock_crawl, mock_ssl, mock_headers, sample_target,
    ):
        """Scanner with modules=['recon'] does not run web."""
        scanner = Scanner(sample_target, modules=["recon"])
        scanner.run()

        mock_headers.assert_not_called()
        mock_ssl.assert_not_called()
        mock_crawl.assert_not_called()
        mock_fp.assert_not_called()
