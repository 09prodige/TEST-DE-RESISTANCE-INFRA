"""Enhanced HTTP client with safe sessions, retries, and redirect tracking."""

import threading
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
_REQUEST_TIMESTAMPS_LOCK = threading.Lock()
_MIN_REQUEST_INTERVAL = 0.5  # seconds between requests


class RateLimiter:
    """Configurable rate limiter for HTTP requests.

    Ensures that no more than ``max_requests`` are made per
    ``window`` seconds. Thread-safe.

    Args:
        max_requests: Maximum number of requests allowed in the window.
        window: Time window in seconds.
    """

    def __init__(self, max_requests: int = 10, window: float = 10.0):
        self.max_requests = max_requests
        self.window = window
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a request slot is available."""
        with self._lock:
            now = time.time()
            # Remove timestamps outside the window
            cutoff = now - self.window
            self._timestamps = [t for t in self._timestamps if t > cutoff]

            if len(self._timestamps) >= self.max_requests:
                # Sleep until the oldest timestamp expires
                sleep_time = self._timestamps[0] + self.window - now
                if sleep_time > 0:
                    time.sleep(sleep_time)
                # Retry after sleeping
                self._timestamps = [t for t in self._timestamps if t > time.time() - self.window]

            self._timestamps.append(time.time())

    @property
    def current_count(self) -> int:
        """Return the number of requests in the current window."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            return len(self._timestamps)


# Global rate limiter instance (backward-compatible)
_GLOBAL_RATELIMITER = RateLimiter(max_requests=20, window=10.0)


def _rate_limit() -> None:
    """Enforce minimum delay between requests (legacy)."""
    _GLOBAL_RATELIMITER.acquire()


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
