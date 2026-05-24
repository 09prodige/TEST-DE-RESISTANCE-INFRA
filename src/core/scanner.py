"""Core scanner — orchestrates all scan modules against a target."""

from src.utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    """Orchestrates the security scan by dispatching to individual modules."""

    def __init__(self, target: str, modules: list | None = None):
        self.target = target
        self.modules = modules or ["all"]
        self.results: dict = {"target": target, "modules": {}}

    def run(self) -> dict:
        """Dispatch and run configured scan modules against target."""
        run_all = "all" in self.modules

        if run_all or "recon" in self.modules:
            logger.info("Running recon module...")
            self.results["modules"]["recon"] = self._run_recon()

        if run_all or "web" in self.modules:
            logger.info("Running web analysis module...")
            self.results["modules"]["web"] = self._run_web()

        if run_all or "vuln" in self.modules:
            logger.info("Running vulnerability scanner...")
            self.results["modules"]["vuln"] = self._run_vuln()

        return self.results

    def _run_recon(self) -> dict:
        """Execute all recon sub-modules and return combined results."""
        recon_results: dict = {}

        # DNS lookup
        try:
            from src.modules.recon.dns import resolve_dns
            recon_results["dns"] = resolve_dns(self.target)
            logger.info(f"DNS resolution complete — "
                        f"{sum(len(v) for v in recon_results.get('dns', {}).values())} records")
        except Exception as exc:
            logger.error(f"DNS module failed: {exc}")
            recon_results["dns"] = {}

        # WHOIS lookup
        try:
            from src.modules.recon.whois import lookup_whois
            recon_results["whois"] = lookup_whois(self.target)
            logger.info("WHOIS lookup complete")
        except Exception as exc:
            logger.error(f"WHOIS module failed: {exc}")
            recon_results["whois"] = {}

        # Subdomain enumeration
        try:
            from src.modules.recon.subdomains import enumerate_subdomains
            recon_results["subdomains"] = enumerate_subdomains(self.target)
            logger.info(f"Subdomain enumeration complete — "
                        f"{len(recon_results['subdomains'])} found")
        except Exception as exc:
            logger.error(f"Subdomain enumeration failed: {exc}")
            recon_results["subdomains"] = []

        # Port scan
        try:
            from src.modules.recon.portscan import scan_ports
            recon_results["portscan"] = scan_ports(self.target)
            logger.info(f"Port scan complete — "
                        f"{len(recon_results['portscan'])} open ports")
        except Exception as exc:
            logger.error(f"Port scan failed: {exc}")
            recon_results["portscan"] = []

        return recon_results

    def _run_web(self) -> dict:
        """Execute all web analysis sub-modules and return combined results."""
        web_results: dict = {}

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
            logger.info(f"Headers analysis complete — "
                        f"status: {header_status}")
        except Exception as exc:
            logger.error(f"Headers analysis failed: {exc}")
            web_results["headers"] = {"status": "error", "data": {}, "error": str(exc)}

        # SSL/TLS audit
        try:
            from src.modules.web.ssl_tls import audit_ssl
            web_results["ssl_tls"] = audit_ssl(hostname)
            ssl_status = web_results["ssl_tls"].get("status", "error")
            logger.info(f"SSL/TLS audit complete — "
                        f"status: {ssl_status}")
        except Exception as exc:
            logger.error(f"SSL/TLS audit failed: {exc}")
            web_results["ssl_tls"] = {"status": "error", "data": {}, "error": str(exc)}

        # Crawler
        try:
            from src.modules.web.crawler import crawl
            web_results["crawler"] = crawl(target_url, max_depth=2)
            crawler_pages = (
                web_results["crawler"]
                .get("data", {})
                .get("total_pages", 0)
            )
            logger.info(f"Crawler complete — {crawler_pages} pages")
        except Exception as exc:
            logger.error(f"Crawler failed: {exc}")
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
            logger.info(f"Fingerprinting complete — "
                        f"{fp_count} technologies detected")
        except Exception as exc:
            logger.error(f"Fingerprinting failed: {exc}")
            web_results["fingerprint"] = {"status": "error", "data": {}, "error": str(exc)}

        return web_results

    def _run_vuln(self) -> dict:
        """Execute all vulnerability sub-modules and return combined results."""
        vuln_results: dict = {}

        # Construct target URL
        target_url = self.target
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        # SQL Injection
        try:
            from src.modules.vuln.sqli import scan_sqli
            vuln_results["sqli"] = scan_sqli(target_url)
            sqli_findings = len(vuln_results["sqli"].get("data", {}).get("findings", []))
            logger.info(f"SQLi scan complete — {sqli_findings} findings")
        except Exception as exc:
            logger.error(f"SQLi module failed: {exc}")
            vuln_results["sqli"] = {"status": "error", "data": {"findings": []}}

        # XSS
        try:
            from src.modules.vuln.xss import scan_xss
            vuln_results["xss"] = scan_xss(target_url)
            xss_findings = len(vuln_results["xss"].get("data", {}).get("findings", []))
            logger.info(f"XSS scan complete — {xss_findings} findings")
        except Exception as exc:
            logger.error(f"XSS module failed: {exc}")
            vuln_results["xss"] = {"status": "error", "data": {"findings": []}}

        # CSRF
        try:
            from src.modules.vuln.csrf import scan_csrf
            vuln_results["csrf"] = scan_csrf(target_url)
            csrf_findings = len(vuln_results["csrf"].get("data", {}).get("findings", []))
            logger.info(f"CSRF scan complete — {csrf_findings} findings")
        except Exception as exc:
            logger.error(f"CSRF module failed: {exc}")
            vuln_results["csrf"] = {"status": "error", "data": {"findings": []}}

        # Sensitive files
        try:
            from src.modules.vuln.sensitive_files import scan_sensitive_files
            vuln_results["sensitive_files"] = scan_sensitive_files(target_url)
            sf_findings = len(vuln_results["sensitive_files"].get("data", {}).get("findings", []))
            logger.info(f"Sensitive files scan complete — {sf_findings} findings")
        except Exception as exc:
            logger.error(f"Sensitive files module failed: {exc}")
            vuln_results["sensitive_files"] = {"status": "error", "data": {"findings": []}}

        # Open Redirect
        try:
            from src.modules.vuln.open_redirect import scan_open_redirect
            vuln_results["open_redirect"] = scan_open_redirect(target_url)
            or_findings = len(vuln_results["open_redirect"].get("data", {}).get("findings", []))
            logger.info(f"Open redirect scan complete — {or_findings} findings")
        except Exception as exc:
            logger.error(f"Open redirect module failed: {exc}")
            vuln_results["open_redirect"] = {"status": "error", "data": {"findings": []}}

        return vuln_results


if __name__ == "__main__":
    s = Scanner("example.com")
    print(s.run())
