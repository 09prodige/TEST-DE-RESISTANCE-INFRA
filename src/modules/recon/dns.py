"""DNS resolution module — resolves A, MX, NS, TXT, CNAME records."""

from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not available — DNS resolution disabled")


def resolve_dns(domain: str, timeout: float = 5.0) -> dict:
    """Resolve DNS records (A, MX, NS, TXT, CNAME) for the given domain.

    Args:
        domain: Domain name or hostname to resolve.
        timeout: Query timeout in seconds (default 5.0).

    Returns:
        A dict mapping record types (A, MX, NS, TXT, CNAME) to lists
        of string values. On error or for invalid domains, returns an
        empty dict.
    """
    if not HAS_DNSPYTHON:
        logger.error("dnspython is required for DNS resolution")
        return {}

    result: dict[str, list[str]] = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
    }

    if not domain or not isinstance(domain, str):
        logger.warning(f"Invalid domain: {domain!r}")
        return {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    record_types = ["A", "MX", "NS", "TXT", "CNAME"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for answer in answers:
                if rtype == "MX":
                    result["MX"].append(str(answer.exchange).rstrip("."))
                else:
                    result[rtype].append(str(answer).rstrip("."))
        except dns.resolver.NoAnswer:
            # Record type exists but has no answer — not an error
            pass
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
            return {}
        except dns.resolver.NoNameservers:
            logger.warning(f"No nameservers could be reached for {domain}")
            return {}
        except dns.exception.Timeout:
            logger.warning(f"DNS query timed out for {domain} ({rtype})")
            return {}
        except Exception as exc:
            logger.debug(f"DNS {rtype} lookup failed for {domain}: {exc}")

    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"Resolving DNS for: {target}")
    res = resolve_dns(target)
    for rtype, records in res.items():
        print(f"  {rtype}: {records}")
