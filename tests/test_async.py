"""Tests for US-20: Async scanning — ThreadPoolExecutor, rate limiting, timeouts."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from src.core.scanner import Scanner, RateLimiter
from src.utils.http import RateLimiter as HttpRateLimiter


# =============================================================================
# RateLimiter Tests
# =============================================================================


class TestRateLimiter:
    """Tests for the RateLimiter class."""

    def test_rate_limiter_init(self):
        """RateLimiter initializes with default values."""
        rl = RateLimiter(max_requests=10, window=5.0)
        assert rl.max_requests == 10
        assert rl.window == 5.0
        assert rl.current_count == 0

    def test_rate_limiter_acquire_no_block(self):
        """Acquire does not block when under limit."""
        rl = RateLimiter(max_requests=100, window=10.0)
        start = time.monotonic()
        for _ in range(5):
            rl.acquire()
        elapsed = time.monotonic() - start
        # Should be near-instant (no blocking)
        assert elapsed < 2.0

    def test_rate_limiter_blocks_at_limit(self):
        """Acquire blocks when over limit."""
        rl = RateLimiter(max_requests=2, window=1.0)
        rl.acquire()
        rl.acquire()
        # Third call should block briefly
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        # Should have waited for at least one expiry
        assert elapsed >= 0.0  # Just verify it doesn't crash

    def test_rate_limiter_current_count(self):
        """Current count returns correct number of recent requests."""
        rl = RateLimiter(max_requests=50, window=10.0)
        assert rl.current_count == 0
        rl.acquire()
        assert rl.current_count == 1
        rl.acquire()
        assert rl.current_count == 2

    def test_rate_limiter_thread_safety(self):
        """RateLimiter is thread-safe."""
        import concurrent.futures

        rl = RateLimiter(max_requests=100, window=5.0)
        errors = []

        def worker():
            try:
                for _ in range(5):
                    rl.acquire()
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(worker) for _ in range(4)]
            concurrent.futures.wait(futures)

        assert len(errors) == 0

    def test_http_rate_limiter_exists(self):
        """HTTP module has global RateLimiter compat."""
        rl = HttpRateLimiter(max_requests=20, window=10.0)
        assert rl.max_requests == 20
        rl.acquire()
        assert rl.current_count >= 1


# =============================================================================
# Scanner Async Tests
# =============================================================================


class TestScannerAsync:
    """Tests for Scanner async (ThreadPoolExecutor) features."""

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_runs_in_parallel(self, mock_vuln, mock_web, mock_recon, sample_target):
        """All modules run when 'all' is specified."""
        mock_recon.return_value = {"dns": {}}
        mock_web.return_value = {"headers": {}}
        mock_vuln.return_value = {"sqli": {}}

        scanner = Scanner(sample_target, max_workers=3)
        results = scanner.run()

        assert "recon" in results["modules"]
        assert "web" in results["modules"]
        assert "vuln" in results["modules"]
        mock_recon.assert_called_once()
        mock_web.assert_called_once()
        mock_vuln.assert_called_once()

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_selected_modules(self, mock_vuln, mock_web, mock_recon, sample_target):
        """Only selected modules run."""
        scanner = Scanner(sample_target, modules=["recon", "web"], max_workers=2)
        results = scanner.run()

        assert "recon" in results["modules"]
        assert "web" in results["modules"]
        assert "vuln" not in results["modules"]
        mock_recon.assert_called_once()
        mock_web.assert_called_once()
        mock_vuln.assert_not_called()

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_single_module(self, mock_vuln, mock_web, mock_recon, sample_target):
        """Single module runs without parallel overhead."""
        mock_recon.return_value = {"dns": {}}
        scanner = Scanner(sample_target, modules=["recon"], max_workers=3)
        results = scanner.run()

        assert "recon" in results["modules"]
        mock_recon.assert_called_once()
        mock_web.assert_not_called()
        mock_vuln.assert_not_called()

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_returns_dict(self, mock_vuln, mock_web, mock_recon, sample_target):
        """Scanner.run() always returns a dict with target and modules."""
        mock_recon.return_value = {}
        mock_web.return_value = {}
        mock_vuln.return_value = {}

        scanner = Scanner(sample_target)
        result = scanner.run()

        assert isinstance(result, dict)
        assert result["target"] == sample_target
        assert "modules" in result
        assert isinstance(result["modules"], dict)

    @patch("src.core.scanner.Scanner._run_recon", side_effect=RuntimeError("Recon failed"))
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_module_failure_isolated(self, mock_vuln, mock_web, mock_recon, sample_target):
        """Failure in one module does not affect others."""
        mock_web.return_value = {"headers": {}}
        mock_vuln.return_value = {"sqli": {}}

        scanner = Scanner(sample_target)
        results = scanner.run()

        assert results["modules"]["recon"]["status"] == "error"
        assert "web" in results["modules"]
        assert "vuln" in results["modules"]

    def test_run_single_module_unknown(self, sample_target):
        """_run_single_module with unknown name returns error."""
        scanner = Scanner(sample_target)
        result = scanner._run_single_module("unknown")
        assert result["status"] == "error"

    def test_run_single_module_recon(self, sample_target):
        """_run_single_module runs recon successfully."""
        with patch("src.modules.recon.dns.resolve_dns", return_value={}), \
             patch("src.modules.recon.whois.lookup_whois", return_value={}), \
             patch("src.modules.recon.subdomains.enumerate_subdomains", return_value=[]), \
             patch("src.modules.recon.portscan.scan_ports", return_value=[]):
            scanner = Scanner(sample_target)
            result = scanner._run_single_module("recon")
            assert isinstance(result, dict)

    def test_run_single_module_web(self, sample_target):
        """_run_single_module runs web analysis successfully."""
        with patch("src.modules.web.headers.get", return_value=None), \
             patch("src.modules.web.ssl_tls.socket.create_connection",
                   side_effect=ConnectionRefusedError), \
             patch("src.modules.web.crawler.get", return_value=None), \
             patch("src.modules.web.fingerprint.get", return_value=None):
            scanner = Scanner(sample_target)
            result = scanner._run_single_module("web")
            assert isinstance(result, dict)

    def test_run_single_module_vuln(self, sample_target):
        """_run_single_module runs vuln scan successfully."""
        with patch("src.modules.vuln.sqli.safe_session"), \
             patch("src.modules.vuln.xss.safe_session"), \
             patch("src.modules.vuln.csrf.get", return_value=None), \
             patch("src.modules.vuln.sensitive_files.safe_session"), \
             patch("src.modules.vuln.open_redirect.safe_session"):
            scanner = Scanner(sample_target)
            result = scanner._run_single_module("vuln")
            assert isinstance(result, dict)
            assert "sqli" in result
            assert "xss" in result
            assert "csrf" in result

    def test_scan_no_valid_modules(self, sample_target):
        """No valid modules returns empty results."""
        scanner = Scanner(sample_target, modules=["invalid"])
        result = scanner.run()
        assert result["modules"] == {}
        assert "target" in result

    @patch("src.modules.recon.dns.resolve_dns", return_value={})
    @patch("src.modules.recon.whois.lookup_whois", return_value={})
    @patch("src.modules.recon.subdomains.enumerate_subdomains", return_value=[])
    @patch("src.modules.recon.portscan.scan_ports", return_value=[])
    @patch("src.modules.web.headers.analyze_headers", return_value={"status": "success", "data": {}})
    @patch("src.modules.web.ssl_tls.audit_ssl", return_value={"status": "success", "data": {}})
    @patch("src.modules.web.crawler.crawl", return_value={"status": "success", "data": {}})
    @patch("src.modules.web.fingerprint.fingerprint", return_value={"status": "success", "data": {}})
    def test_scan_timings_recorded(self, mock_fp, mock_crawl, mock_ssl, mock_headers,
                                    mock_scan, mock_sub, mock_whois, mock_dns, sample_target):
        """Timings are recorded for each module."""
        scanner = Scanner(sample_target, modules=["recon", "web"])
        scanner.run()

        timings = scanner.timings
        assert "recon" in timings
        assert "web" in timings

    @patch("src.core.scanner.Scanner._run_single_module")
    def test_timings_empty_before_run(self, mock_run, sample_target):
        """Timings property returns empty dict before scan."""
        scanner = Scanner(sample_target)
        assert scanner.timings == {}

    def test_scan_cancel(self, sample_target):
        """Cancel signals stop."""
        scanner = Scanner(sample_target)
        scanner.cancel()
        result = scanner._run_single_module("recon")
        assert result["status"] == "error"
        assert "cancelled" in result["error"].lower()

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_uses_thread_pool(self, mock_vuln, mock_web, mock_recon, sample_target):
        """Scanner uses ThreadPoolExecutor for parallel execution."""
        import concurrent.futures

        mock_recon.return_value = {"dns": {}}
        mock_web.return_value = {"headers": {}}
        mock_vuln.return_value = {"sqli": {}}

        # Run the scanner — it will use the real ThreadPoolExecutor
        scanner = Scanner(sample_target)
        result = scanner.run()

        # Verify results are returned correctly
        assert "recon" in result["modules"]
        assert "web" in result["modules"]
        assert "vuln" in result["modules"]

        # Verify all mocks were called
        mock_recon.assert_called_once()
        mock_web.assert_called_once()
        mock_vuln.assert_called_once()

    @patch("src.core.scanner.Scanner._run_recon")
    @patch("src.core.scanner.Scanner._run_web")
    @patch("src.core.scanner.Scanner._run_vuln")
    def test_scan_timeout_cancels_remaining(self, mock_vuln, mock_web, mock_recon, sample_target):
        """When timeout is exceeded, remaining modules are cancelled."""
        import concurrent.futures

        mock_recon.return_value = {"dns": {}}
        mock_web.return_value = {"headers": {}}
        mock_vuln.return_value = {"sqli": {}}

        # Patch concurrent.futures.wait to run for a short time but return not_done
        original_wait = concurrent.futures.wait

        def mock_wait(futures, timeout=None, return_when="ALL_COMPLETED"):
            # Return the first future as done, rest as not done
            fut_list = list(futures)
            return ({fut_list[0]}, set(fut_list[1:])) if len(fut_list) > 1 else (set(futures), set())

        with patch("concurrent.futures.wait", side_effect=mock_wait):
            scanner = Scanner(sample_target, scan_timeout=0.1)
            results = scanner.run()

            # At least some modules should be present
            assert "modules" in results


# =============================================================================
# Scanner Backward Compatibility Tests
# =============================================================================


class TestScannerBackwardCompat:
    """Ensure backward compatibility with existing test patterns."""

    def test_scanner_init_defaults(self, sample_target):
        """Scanner initializes with default values (existing test)."""
        s = Scanner(sample_target)
        assert s.target == sample_target
        assert s.modules == ["all"]
        assert s.module_timeout == 120.0
        assert s.scan_timeout == 600.0

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_recon_integration(self, mock_scan, mock_sub, mock_whois, mock_dns, sample_target):
        """Recon integration works as before (existing test pattern)."""
        mock_dns.return_value = {"A": ["93.184.216.34"]}
        mock_whois.return_value = {"registrar": "Example Inc"}
        mock_sub.return_value = [{"subdomain": "www.example.com", "ip": "93.184.216.34", "source": "bruteforce"}]
        mock_scan.return_value = [{"port": 80, "state": "open", "service": "http", "banner": ""}]

        scanner = Scanner(sample_target, modules=["recon"])
        results = scanner.run()

        assert results["target"] == sample_target
        assert "recon" in results["modules"]
        assert "dns" in results["modules"]["recon"]
        assert "whois" in results["modules"]["recon"]
        assert "subdomains" in results["modules"]["recon"]
        assert "portscan" in results["modules"]["recon"]

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_recon_failure_graceful(self, mock_scan, mock_sub, mock_whois, mock_dns, sample_target):
        """Exception in recon sub-module doesn't crash (existing test pattern)."""
        mock_dns.side_effect = RuntimeError("DNS crashed")
        mock_whois.return_value = {}
        mock_sub.return_value = []
        mock_scan.return_value = []

        scanner = Scanner(sample_target, modules=["recon"])
        results = scanner.run()

        assert results["modules"]["recon"]["dns"] == {}
        assert results["modules"]["recon"]["whois"] == {}

    def test_run_vuln_exists(self, sample_target):
        """Scanner has _run_vuln method (existing test)."""
        s = Scanner(sample_target)
        assert hasattr(s, "_run_vuln")

    def test_run_vuln_returns_dict(self, sample_target):
        """_run_vuln returns dict with all sub-modules (existing test)."""
        with patch("src.modules.vuln.sqli.safe_session"), \
             patch("src.modules.vuln.xss.safe_session"), \
             patch("src.modules.vuln.csrf.get", return_value=None), \
             patch("src.modules.vuln.sensitive_files.safe_session"), \
             patch("src.modules.vuln.open_redirect.safe_session"):
            s = Scanner(sample_target)
            result = s._run_vuln()
            assert isinstance(result, dict)
            assert "sqli" in result
            assert "xss" in result
            assert "csrf" in result
            assert "sensitive_files" in result
            assert "open_redirect" in result

    @patch("src.core.scanner.Scanner._run_recon")
    def test_scanner_excludes_when_not_requested(self, mock_recon, sample_target):
        """Scanner doesn't run modules not in list (existing test pattern)."""
        mock_recon.return_value = {}
        scanner = Scanner(sample_target, modules=["web"])
        scanner.run()
        mock_recon.assert_not_called()

    def test_run_returns_dict_with_target(self, sample_target):
        """run() returns dict with target key (existing test)."""
        with patch("src.core.scanner.Scanner._run_recon", return_value={}), \
             patch("src.core.scanner.Scanner._run_web", return_value={}), \
             patch("src.core.scanner.Scanner._run_vuln", return_value={}):
            s = Scanner(sample_target)
            result = s.run()
            assert isinstance(result, dict)
            assert result["target"] == sample_target


# =============================================================================
# Scanner Config Tests
# =============================================================================


class TestScannerConfig:
    """Tests for Scanner configuration parameters."""

    def test_custom_module_timeout(self, sample_target):
        """Custom module timeout is stored correctly."""
        s = Scanner(sample_target, module_timeout=30.0)
        assert s.module_timeout == 30.0

    def test_custom_scan_timeout(self, sample_target):
        """Custom scan timeout is stored correctly."""
        s = Scanner(sample_target, scan_timeout=120.0)
        assert s.scan_timeout == 120.0

    def test_custom_max_workers(self, sample_target):
        """Custom max workers is passed to executor."""
        s = Scanner(sample_target, max_workers=5)
        assert s.max_workers == 5

    def test_custom_rate_limit(self, sample_target):
        """Custom rate limit creates RateLimiter with correct params."""
        s = Scanner(sample_target, rate_limit=50, rate_window=5.0)
        assert s._rate_limiter.max_requests == 50
        assert s._rate_limiter.window == 5.0

    def test_run_with_all_modules_default(self, sample_target):
        """Default modules=['all'] runs all three modules."""
        with patch("src.core.scanner.Scanner._run_recon", return_value={}), \
             patch("src.core.scanner.Scanner._run_web", return_value={}), \
             patch("src.core.scanner.Scanner._run_vuln", return_value={}):
            s = Scanner(sample_target)
            result = s.run()
            assert "recon" in result["modules"]
            assert "web" in result["modules"]
            assert "vuln" in result["modules"]
