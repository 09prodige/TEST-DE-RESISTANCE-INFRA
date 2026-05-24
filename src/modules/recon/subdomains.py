"""Subdomain enumeration module — brute-force + passive (crt.sh)."""

import time
import socket
from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not available — DNS validation disabled")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    logger.warning("requests not available — crt.sh passive discovery disabled")


# Top 100 most common subdomains (brute-force wordlist)
SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "admin", "ftp", "dev", "api", "blog", "webmail", "shop",
    "test", "support", "m", "app", "static", "media", "cdn", "img", "css",
    "js", "assets", "download", "upload", "forum", "help", "wiki", "news",
    "store", "video", "live", "chat", "login", "register", "signup", "auth",
    "status", "portal", "email", "smtp", "pop", "imap", "vpn", "remote",
    "docs", "documentation", "git", "svn", "jenkins", "jira", "confluence",
    "travis", "ci", "stage", "staging", "preprod", "prod", "production",
    "backup", "db", "database", "mysql", "redis", "memcache", "cache",
    "cloud", "aws", "s3", "bucket", "firebase", "server", "node", "nodejs",
    "python", "java", "tomcat", "jboss", "weblogic", "websphere",
    "monitor", "monitoring", "metrics", "graphite", "grafana", "kibana",
    "elastic", "elk", "log", "logs", "analytics", "tracking", "stats",
    "phone", "mobile", "ios", "android", "play", "itunes", "account",
    "profile", "user", "users", "billing", "payment", "checkout", "cart",
    "wholesale", "partner", "partners", "affiliate", "demo", "sandbox",
    "admin-console", "console", "dashboard", "gateway", "proxy",
]


def enumerate_subdomains(domain: str, delay: float = 0.1) -> list[dict]:
    """Enumerate subdomains of the given domain.

    Uses both brute-force (top 100 wordlist) and passive discovery
    via crt.sh. Validates discovered subdomains with DNS resolution.

    Args:
        domain: The parent domain to enumerate (e.g. \"example.com\").
        delay: Seconds to wait between DNS queries (rate limiting).

    Returns:
        A list of dicts:
          [{"subdomain": str, "ip": str, "source": str}, ...]
    """
    if not domain or not isinstance(domain, str):
        logger.warning(f"Invalid domain: {domain!r}")
        return []

    discovered: dict[str, dict] = {}  # subdomain -> info

    # Phase 1: brute-force
    logger.info(f"Starting brute-force enumeration for {domain}")
    for sub in SUBDOMAIN_WORDLIST:
        fqdn = f"{sub}.{domain}"
        ip = _resolve_subdomain(fqdn)
        if ip:
            discovered[fqdn] = {"subdomain": fqdn, "ip": ip, "source": "bruteforce"}
        time.sleep(delay)

    # Phase 2: passive via crt.sh
    logger.info(f"Querying crt.sh for {domain}")
    crt_results = _query_crtsh(domain)
    for fqdn in crt_results:
        if fqdn not in discovered:
            ip = _resolve_subdomain(fqdn)
            if ip:
                discovered[fqdn] = {
                    "subdomain": fqdn,
                    "ip": ip,
                    "source": "crtsh",
                }
        time.sleep(delay)

    logger.info(f"Found {len(discovered)} subdomains for {domain}")
    return list(discovered.values())


def _resolve_subdomain(fqdn: str) -> str | None:
    """Resolve a fully-qualified subdomain to an IP address.

    Tries A record first via dnspython, falls back to socket.gethostbyname.
    Returns None on failure.
    """
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(fqdn, "A")
            for answer in answers:
                return str(answer)
        except (dns.exception.DNSException, Exception):
            pass

    # Fallback: direct socket resolution
    try:
        return socket.gethostbyname(fqdn)
    except (socket.gaierror, OSError):
        return None


def _query_crtsh(domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency log for subdomains.

    Returns a set of FQDN subdomains discovered via SSL certificate logs.
    """
    if not HAS_REQUESTS:
        logger.debug("requests library required for crt.sh queries")
        return set()

    subdomains: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10, headers={
            "User-Agent": "RIG-Scanner/0.1 (security-audit; authorized)",
        })
        if resp.status_code != 200:
            logger.debug(f"crt.sh returned status {resp.status_code}")
            return set()

        data = resp.json()
        for entry in data:
            name = entry.get("name_value", "")
            # crt.sh may return multiple names separated by newlines
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.endswith(f".{domain}") and line != f"*.{domain}":
                    subdomains.add(line)
    except requests.RequestException as exc:
        logger.debug(f"crt.sh query failed: {exc}")
    except (ValueError, TypeError) as exc:
        logger.debug(f"crt.sh response parse error: {exc}")

    return subdomains


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"Enumerating subdomains for: {target}")
    results = enumerate_subdomains(target, delay=0.05)
    for r in results:
        print(f"  {r['subdomain']:30s} -> {r['ip']:15s}  [{r['source']}]")
    print(f"\nTotal: {len(results)} subdomains found")
