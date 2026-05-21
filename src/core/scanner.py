from src.utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    def __init__(self, target: str, modules: list = None):
        self.target = target
        self.modules = modules or ["all"]
        self.results = {"target": target, "modules": {}}

    def run(self) -> dict:
        """Dispatch and run configured scan modules against target."""
        run_all = "all" in self.modules

        if run_all or "recon" in self.modules:
            logger.info("Running recon module...")
            # TODO: from src.modules.recon import run_recon
            # self.results["modules"]["recon"] = run_recon(self.target)

        if run_all or "web" in self.modules:
            logger.info("Running web analysis module...")
            # TODO: from src.modules.web import run_web
            # self.results["modules"]["web"] = run_web(self.target)

        if run_all or "vuln" in self.modules:
            logger.info("Running vulnerability scanner...")
            # TODO: from src.modules.vuln import run_vuln
            # self.results["modules"]["vuln"] = run_vuln(self.target)

        return self.results


if __name__ == "__main__":
    s = Scanner("example.com")
    print(s.run())
