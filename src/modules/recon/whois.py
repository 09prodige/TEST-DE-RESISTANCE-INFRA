"""WHOIS lookup module — retrieves domain registration information."""

from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    logger.warning("python-whois not available — WHOIS lookup disabled")


def lookup_whois(domain: str) -> dict:
    """Perform a WHOIS lookup for the given domain.

    Args:
        domain: Domain name to query.

    Returns:
        A structured dict with keys:
          - registrar (str or None)
          - organization (str or None)
          - country (str or None)
          - creation_date (str or None)
          - expiration_date (str or None)
          - updated_date (str or None)
          - name_servers (list[str])
          - raw (str | None): truncated raw response for debugging.
    """
    if not HAS_WHOIS:
        logger.error("python-whois is required for WHOIS lookup")
        return _empty_result()

    if not domain or not isinstance(domain, str):
        logger.warning(f"Invalid domain: {domain!r}")
        return _empty_result()

    try:
        w = whois.whois(domain)

        result = {
            "registrar": _first_str(w.registrar) if hasattr(w, "registrar") else None,
            "organization": _first_str(w.org) if hasattr(w, "org") else None,
            "country": _first_str(w.country) if hasattr(w, "country") else None,
            "creation_date": _format_date(w.creation_date) if hasattr(w, "creation_date") else None,
            "expiration_date": _format_date(w.expiration_date) if hasattr(w, "expiration_date") else None,
            "updated_date": _format_date(w.updated_date) if hasattr(w, "updated_date") else None,
            "name_servers": _to_list(w.name_servers) if hasattr(w, "name_servers") else [],
            "raw": str(w)[:500] if w.text else None,
        }

        logger.info(f"WHOIS data retrieved for {domain}")
        return result

    except whois.exceptions.PywhoisError as exc:
        logger.warning(f"WHOIS parse error for {domain}: {exc}")
        return _empty_result()
    except Exception as exc:
        logger.warning(f"WHOIS lookup failed for {domain}: {exc}")
        return _empty_result()


def _empty_result() -> dict:
    """Return an empty result structure."""
    return {
        "registrar": None,
        "organization": None,
        "country": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "raw": None,
    }


def _first_str(value) -> str | None:
    """Extract the first string from a value that may be a list or None."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _to_list(value) -> list:
    """Normalize a value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _format_date(value) -> str | None:
    """Format a date value to ISO string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"WHOIS lookup for: {target}")
    res = lookup_whois(target)
    for key, val in res.items():
        print(f"  {key}: {val}")
