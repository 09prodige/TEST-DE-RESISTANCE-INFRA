"""Core scanner — orchestrates all scan modules against a target.

Supports parallel execution of modules via ``ThreadPoolExecutor``,
configurable timeouts, rate limiting, and optional YAML configuration
(via :mod:`src.config`). When no config is provided the scanner falls
back to built-in defaults, preserving full backward compatibility.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Any

from src.config import get_module_config, load_config
from src.utils.http import RateLimiter
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Default configuration
DEFAULT_MODULE_TIMEOUT = 120.0  # seconds per module
DEFAULT_SCAN_TIMEOUT = 600.0  # total scan timeout
DEFAULT_RATE_LIMIT = 20  # requests per window
DEFAULT_RATE_WINDOW = 10.0  # window in seconds


class Scanner:
    """Orchestrates the security scan by dispatching to individual modules.

    Args:
        target: The target domain or URL to scan.
        modules: List of modules to run (``"recon"``, ``"web"``, ``"vuln"``,
            or ``"all"``). Defaults to ``["all"]``.
        module_timeout: Maximum time in seconds per module.
        scan_timeout: Maximum total scan time in seconds.
        max_workers: Maximum number of parallel module executions (default 3).
        rate_limit: Maximum HTTP requests per rate window.
        rate_window: Rate limiting window in seconds.
        config: Optional configuration dict loaded via
            :func:`src.config.load_config`. When ``None``, built-in
            defaults are used.

    Attributes:
        target: The target being scanned.
        modules: List of module names to execute.
        results: Accumulated scan results dict.
        module_timeout: Per-module timeout.
        scan_timeout: Total scan timeout.
        config: The active configuration dict.
    """

    def __init__(
        self,
        target: str,
        modules: list[str] | None = None,
        module_timeout: float = DEFAULT_MODULE_TIMEOUT,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        max_workers: int = 3,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        rate_window: float = DEFAULT_RATE_WINDOW,
        config: dict[str, Any] | None = None,
    ):
        self.target = target
        self.modules = modules or ["all"]
        self.config: dict[str, Any] = load_config() if config is None else config
        self.results: dict[str, Any] = {"target": target, "modules": {}}
        self.module_timeout = module_timeout
        self.scan_timeout = scan_timeout
        self.max_workers = max_workers
        self._rate_limiter = RateLimiter(max_requests=rate_limit, window=rate_window)
        self._timings: dict[str, float] = {}
        self._cancel_event = threading.Event()

    # ── Public API ────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """Dispatch and run configured scan modules against target.

        Modules are executed in parallel using a thread pool. The method
        blocks until all modules complete (or timeout).

        Returns:
            Dict with ``target`` and ``modules`` keys containing results.
        """
        run_all = "all" in self.modules
        modules_to_run: list[str] = []

        if run_all:
            modules_to_run = ["recon", "web", "vuln"]
        else:
            for mod in ("recon", "web", "vuln"):
                if mod in self.modules:
                    modules_to_run.append(mod)

        if not modules_to_run:
            logger.warning("No valid modules specified; returning empty results.")
            return self.results

        logger.info(
            "Starting scan on %s — modules: %s (timeout: %ds, workers: %d)",
            self.target, ", ".join(modules_to_run),
            self.scan_timeout, self.max_workers,
        )

        start_time = time.monotonic()

        # Run modules in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(modules_to_run)),
        ) as executor:
            future_map: dict[concurrent.futures.Future, str] = {}

            for module_name in modules_to_run:
                future = executor.submit(self._run_single_module, module_name)
                future_map[future] = module_name

            # Collect results as they complete
            done, not_done = concurrent.futures.wait(
                future_map.keys(),
                timeout=self.scan_timeout,
                return_when=concurrent.futures.FIRST_EXCEPTION,
            )

            # Cancel any remaining futures after timeout
            for future in not_done:
                mod_name = future_map[future]
                logger.warning("Module '%s' timed out after %ds", mod_name, self.scan_timeout)
                future.cancel()
                self.results["modules"][mod_name] = {
                    "status": "error",
                    "data": {},
                    "error": f"Module timed out ({self.scan_timeout}s)",
                }

            # Gather results from completed futures
            for future in done:
                mod_name = future_map[future]
                try:
                    result = future.result()
                    if mod_name not in self.results["modules"]:
                        self.results["modules"][mod_name] = result
                except concurrent.futures.CancelledError:
                    logger.warning("Module '%s' was cancelled", mod_name)
                    self.results["modules"][mod_name] = {
                        "status": "error", "data": {},
                        "error": "Module was cancelled",
                    }
                except Exception as exc:
                    logger.error("Module '%s' failed with exception: %s", mod_name, exc)
                    self.results["modules"][mod_name] = {
                        "status": "error", "data": {},
                        "error": str(exc),
                    }

        elapsed = time.monotonic() - start_time
        self.results["scan_duration"] = elapsed
        logger.info("Scan completed in %.1fs", elapsed)

        return self.results

    def cancel(self) -> None:
        """Signal cancellation of the current scan."""
        self._cancel_event.set()
        logger.info("Scan cancellation requested")

    @property
    def timings(self) -> dict[str, float]:
        """Return per-module execution timings."""
        return dict(self._timings)

    # ── Internal: Module dispatch ─────────────────────────────

    def _run_single_module(self, module_name: str) -> dict[str, Any]:
        """Run a single top-level module with timeout.

        Args:
            module_name: ``"recon"``, ``"web"``, or ``"vuln"``.

        Returns:
            Module results dict.
        """
        if self._cancel_event.is_set():
            return {"status": "error", "data": {}, "error": "Scan cancelled"}

        logger.info("Starting module: %s", module_name)
        start = time.monotonic()

        try:
            if module_name == "recon":
                result = self._run_recon()
            elif module_name == "web":
                result = self._run_web()
            elif module_name == "vuln":
                result = self._run_vuln()
            else:
                raise ValueError(f"Unknown module: {module_name}")

            elapsed = time.monotonic() - start
            self._timings[module_name] = elapsed
            logger.info("Module '%s' completed in %.1fs", module_name, elapsed)
            return result

        except Exception as exc:
            elapsed = time.monotonic() - start
            self._timings[module_name] = elapsed
            logger.error("Module '%s' failed after %.1fs: %s", module_name, elapsed, exc)
            return {"status": "error", "data": {}, "error": str(exc)}

    # ── Recon ─────────────────────────────────────────────────

    def _run_recon(self) -> dict[str, Any]:
        """Execute all recon sub-modules and return combined results."""
        recon_results: dict[str, Any] = {}

        # DNS lookup
        try:
            from src.modules.recon.dns import resolve_dns
            recon_results["dns"] = resolve_dns(self.target)
            logger.info(
                "DNS resolution complete — %d records",
                sum(len(v) for v in recon_results.get("dns", {}).values()),
            )
        except Exception as exc:
            logger.error("DNS module failed: %s", exc)
            recon_results["dns"] = {}

        # WHOIS lookup
        try:
            from src.modules.recon.whois import lookup_whois
            recon_results["whois"] = lookup_whois(self.target)
            logger.info("WHOIS lookup complete")
        except Exception as exc:
            logger.error("WHOIS module failed: %s", exc)
            recon_results["whois"] = {}

        # Subdomain enumeration
        try:
            from src.modules.recon.subdomains import enumerate_subdomains
            recon_results["subdomains"] = enumerate_subdomains(self.target)
            logger.info("Subdomain enumeration complete — %d found", len(recon_results["subdomains"]))
        except Exception as exc:
            logger.error("Subdomain enumeration failed: %s", exc)
            recon_results["subdomains"] = []

        # Port scan
        try:
            from src.modules.recon.portscan import scan_ports
            recon_results["portscan"] = scan_ports(self.target)
            logger.info("Port scan complete — %d open ports", len(recon_results["portscan"]))
        except Exception as exc:
            logger.error("Port scan failed: %s", exc)
            recon_results["portscan"] = []

        return recon_results

    # ── Web Analysis ───────────────────────────────────────────

    def _run_web(self) -> dict[str, Any]:
        """Execute all web analysis sub-modules and return combined results."""
        web_results: dict[str, Any] = {}

        # Construct target URL
        target_url = self.target
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        # Extract hostname for SSL audit
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname or self.target

        # Headers analysis
        try:
            from src.modules.web.headers import analyze_headers
            web_results["headers"] = analyze_headers(target_url)
            header_status = web_results["headers"].get("status", "error")
            logger.info("Headers analysis complete — status: %s", header_status)
        except Exception as exc:
            logger.error("Headers analysis failed: %s", exc)
            web_results["headers"] = {"status": "error", "data": {}, "error": str(exc)}

        # SSL/TLS audit
        try:
            from src.modules.web.ssl_tls import audit_ssl
            web_results["ssl_tls"] = audit_ssl(hostname)
            ssl_status = web_results["ssl_tls"].get("status", "error")
            logger.info("SSL/TLS audit complete — status: %s", ssl_status)
        except Exception as exc:
            logger.error("SSL/TLS audit failed: %s", exc)
            web_results["ssl_tls"] = {"status": "error", "data": {}, "error": str(exc)}

        # Crawler (use crawl_depth from config, default 2)
        try:
            from src.modules.web.crawler import crawl
            web_cfg = get_module_config("web", self.config)
            crawl_depth = web_cfg.get("crawl_depth", 2)
            web_results["crawler"] = crawl(target_url, max_depth=crawl_depth)
            crawler_pages = (
                web_results["crawler"]
                .get("data", {})
                .get("total_pages", 0)
            )
            logger.info("Crawler complete — %d pages (depth: %d)", crawler_pages, crawl_depth)
        except Exception as exc:
            logger.error("Crawler failed: %s", exc)
            web_results["crawler"] = {"status": "error", "data": {}, "error": str(exc)}

        # Fingerprinting
        try:
            from src.modules.web.fingerprint import fingerprint
            web_results["fingerprint"] = fingerprint(target_url)
            fp_count = (
                web_results["fingerprint"]
                .get("data", {})
                .get("total_detected", 0)
            )
            logger.info("Fingerprinting complete — %d technologies detected", fp_count)
        except Exception as exc:
            logger.error("Fingerprinting failed: %s", exc)
            web_results["fingerprint"] = {"status": "error", "data": {}, "error": str(exc)}

        return web_results

    # ── Vulnerability Scan ─────────────────────────────────────

    def _run_vuln(self) -> dict[str, Any]:
        """Execute all vulnerability sub-modules and return combined results."""
        vuln_results: dict[str, Any] = {}

        # Construct target URL
        target_url = self.target
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        # SQL Injection
        try:
            from src.modules.vuln.sqli import scan_sqli
            vuln_results["sqli"] = scan_sqli(target_url)
            sqli_findings = len(vuln_results["sqli"].get("data", {}).get("findings", []))
            logger.info("SQLi scan complete — %d findings", sqli_findings)
        except Exception as exc:
            logger.error("SQLi module failed: %s", exc)
            vuln_results["sqli"] = {"status": "error", "data": {"findings": []}}

        # XSS
        try:
            from src.modules.vuln.xss import scan_xss
            vuln_results["xss"] = scan_xss(target_url)
            xss_findings = len(vuln_results["xss"].get("data", {}).get("findings", []))
            logger.info("XSS scan complete — %d findings", xss_findings)
        except Exception as exc:
            logger.error("XSS module failed: %s", exc)
            vuln_results["xss"] = {"status": "error", "data": {"findings": []}}

        # CSRF
        try:
            from src.modules.vuln.csrf import scan_csrf
            vuln_results["csrf"] = scan_csrf(target_url)
            csrf_findings = len(vuln_results["csrf"].get("data", {}).get("findings", []))
            logger.info("CSRF scan complete — %d findings", csrf_findings)
        except Exception as exc:
            logger.error("CSRF module failed: %s", exc)
            vuln_results["csrf"] = {"status": "error", "data": {"findings": []}}

        # Sensitive files
        try:
            from src.modules.vuln.sensitive_files import scan_sensitive_files
            vuln_results["sensitive_files"] = scan_sensitive_files(target_url)
            sf_findings = len(vuln_results["sensitive_files"].get("data", {}).get("findings", []))
            logger.info("Sensitive files scan complete — %d findings", sf_findings)
        except Exception as exc:
            logger.error("Sensitive files module failed: %s", exc)
            vuln_results["sensitive_files"] = {"status": "error", "data": {"findings": []}}

        # Open Redirect
        try:
            from src.modules.vuln.open_redirect import scan_open_redirect
            vuln_results["open_redirect"] = scan_open_redirect(target_url)
            or_findings = len(vuln_results["open_redirect"].get("data", {}).get("findings", []))
            logger.info("Open redirect scan complete — %d findings", or_findings)
        except Exception as exc:
            logger.error("Open redirect module failed: %s", exc)
            vuln_results["open_redirect"] = {"status": "error", "data": {"findings": []}}

        return vuln_results


if __name__ == "__main__":
    s = Scanner("example.com")
    print(s.run())
