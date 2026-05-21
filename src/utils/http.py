import requests
from src.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "RIG-Scanner/0.1 (security-audit; authorized)"
}


def get(url: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> requests.Response | None:
    """Safe HTTP GET with timeout and error handling."""
    try:
        resp = requests.get(url, timeout=timeout,
                            headers=DEFAULT_HEADERS, **kwargs)
        return resp
    except requests.RequestException as e:
        logger.warning(f"GET {url} failed: {e}")
        return None


if __name__ == "__main__":
    r = get("https://example.com")
    if r:
        print(r.status_code)
