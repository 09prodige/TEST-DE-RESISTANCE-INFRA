"""Enhanced HTTP client with safe sessions, retries, and redirect tracking."""

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "RIG-Scanner/0.1 (security-audit; authorized)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Rate limiting
_REQUEST_TIMESTAMPS: list[float] = []
_MIN_REQUEST_INTERVAL = 0.5  # seconds between requests


def _rate_limit() -> None:
    """Enforce minimum delay between requests."""
    now = time.time()
    # Clean old timestamps
    while _REQUEST_TIMESTAMPS and _REQUEST_TIMESTAMPS[0] < now - 60:
        _REQUEST_TIMESTAMPS.pop(0)
    if _REQUEST_TIMESTAMPS:
        elapsed = now - _REQUEST_TIMESTAMPS[-1]
        if elapsed < _MIN_REQUEST_INTERVAL:
            time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _REQUEST_TIMESTAMPS.append(time.time())


def safe_session(
    retries: int = 3,
    backoff_factor: float = 0.5,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Session:
    """Create a ``requests.Session`` with retry, timeout, and default headers.

    Args:
        retries: Number of retries on connection/read errors.
        backoff_factor: Backoff factor for retry delays.
        timeout: Default timeout in seconds.

    Returns:
        A configured ``requests.Session``.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    return session


def get(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    """Safe HTTP GET with rate limiting, timeout, and error handling.

    Args:
        url: The URL to fetch.
        timeout: Request timeout in seconds.
        session: Optional ``requests.Session`` (created fresh if not given).
        **kwargs: Additional arguments passed to ``session.get()``.

    Returns:
        ``requests.Response`` on success, ``None`` on failure.
    """
    _rate_limit()
    close_session = session is None
    s = session or safe_session(timeout=timeout)

    try:
        resp = s.get(url, timeout=timeout, **kwargs)
        return resp
    except requests.RequestException as e:
        logger.warning(f"GET {url} failed: {e}")
        return None
    finally:
        if close_session and session is None:
            s.close()


def get_redirect_chain(
    url: str,
    max_redirects: int = 10,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Follow HTTP redirects and return the full chain.

    Args:
        url: Starting URL.
        max_redirects: Maximum number of redirects to follow.
        timeout: Request timeout in seconds.

    Returns:
        A list of dicts, each with ``url``, ``status_code``, and ``headers``.
        On error, returns a list with at least the initial attempt.
    """
    chain: list[dict[str, Any]] = []
    session = safe_session(timeout=timeout)

    try:
        current = url
        for _ in range(max_redirects + 1):
            _rate_limit()
            try:
                resp = session.get(
                    current,
                    timeout=timeout,
                    allow_redirects=False,
                )
                chain.append({
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                })

                # Check if this is a redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if location:
                        current = location
                        continue
                break
            except requests.RequestException as e:
                logger.warning(f"Redirect chain: GET {current} failed: {e}")
                chain.append({
                    "url": current,
                    "status_code": 0,
                    "headers": {},
                    "error": str(e),
                })
                break
    finally:
        session.close()

    return chain


if __name__ == "__main__":
    r = get("https://example.com")
    if r:
        print(r.status_code)
    chain = get_redirect_chain("http://httpbin.org/redirect/3")
    print(f"Redirect chain length: {len(chain)}")
