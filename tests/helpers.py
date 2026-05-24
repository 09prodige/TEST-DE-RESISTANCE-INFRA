"""Test helpers for mocking HTTP responses and servers."""

from collections.abc import Callable
from unittest.mock import Mock, patch
from typing import Any


def make_mock_response(
    status_code: int = 200,
    headers: dict | None = None,
    text: str = "",
    json_data: Any = None,
    url: str = "http://example.com",
) -> Mock:
    """Create a mock ``requests.Response`` object.

    Args:
        status_code: HTTP status code.
        headers: Response headers dict.
        text: Response body text.
        json_data: Data to return from ``.json()`` (if any).
        url: The request URL.

    Returns:
        A configured ``Mock`` simulating ``requests.Response``.
    """
    mock_resp = Mock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.text = text
    mock_resp.url = url
    mock_resp.content = text.encode("utf-8")
    mock_resp.ok = 200 <= status_code < 400

    if json_data is not None:
        mock_resp.json.return_value = json_data
    else:
        mock_resp.json.side_effect = ValueError("Not JSON")

    return mock_resp


def make_mock_http_server() -> dict[str, Mock]:
    """Create a set of mock HTTP response fixtures for common scenarios.

    Returns a dict of named mock response factories:
      - ``ok``: 200 OK with security headers
      - ``redirect``: 301 redirect
      - ``forbidden``: 403 Forbidden
      - ``not_found``: 404 Not Found
      - ``server_error``: 500 Internal Server Error
      - ``form``: 200 OK with an HTML form
    """
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    }

    form_html = (
        "<html><body>"
        "<form action='/login' method='POST'>"
        "<input type='text' name='username'/>"
        "<input type='password' name='password'/>"
        "<input type='submit' value='Login'/>"
        "</form>"
        "</body></html>"
    )

    return {
        "ok": lambda url="http://example.com": make_mock_response(
            status_code=200,
            headers={**security_headers, "Content-Type": "text/html"},
            text="<html><body>OK</body></html>",
            url=url,
        ),
        "redirect": lambda url="http://example.com": make_mock_response(
            status_code=301,
            headers={"Location": "http://example.com/redirected"},
            text="Moved Permanently",
            url=url,
        ),
        "forbidden": lambda url="http://example.com": make_mock_response(
            status_code=403,
            text="<html><body>Forbidden</body></html>",
            url=url,
        ),
        "not_found": lambda url="http://example.com": make_mock_response(
            status_code=404,
            text="<html><body>Not Found</body></html>",
            url=url,
        ),
        "server_error": lambda url="http://example.com": make_mock_response(
            status_code=500,
            text="<html><body>Internal Server Error</body></html>",
            url=url,
        ),
        "form": lambda url="http://example.com": make_mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            text=form_html,
            url=url,
        ),
    }


def patch_requests_get(mock_response: Mock) -> Callable:
    """Return a context manager that patches ``requests.get``.

    Usage::

        with patch_requests_get(mock_response):
            resp = requests.get("http://example.com")
            assert resp.status_code == 200
    """
    return patch("requests.get", return_value=mock_response)
