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
            # TODO: from src.modules.web import run_web
            # self.results["modules"]["web"] = run_web(self.target)
            self.results["modules"]["web"] = {}

        if run_all or "vuln" in self.modules:
            logger.info("Running vulnerability scanner...")
            # TODO: from src.modules.vuln import run_vuln
            # self.results["modules"]["vuln"] = run_vuln(self.target)
            self.results["modules"]["vuln"] = {}

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


if __name__ == "__main__":
    s = Scanner("example.com")
    print(s.run())
