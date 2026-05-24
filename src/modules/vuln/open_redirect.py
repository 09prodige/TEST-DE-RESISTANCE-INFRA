"""Open Redirect detection module (US-13).

Detects open redirect vulnerabilities by injecting external URLs
into common redirect parameters and checking for 3xx redirects to
external destinations.
"""

from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urljoin

from src.utils.http import safe_session
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common redirect parameter names
REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "return",
    "return_url",
    "return_to",
    "return_path",
    "to",
    "destination",
    "dest",
    "target",
    "out",
    "view",
    "page",
    "forward",
    "forward_url",
    "path",
    "site",
    "html",
    "file",
    "document",
    "folder",
    "root",
    "image_url",
    "go",
    "goto",
    "link",
    "link_url",
    "ref",
    "referer",
    "referrer",
    "checkout_url",
    "continue",
    "continue_url",
    "callback",
    "callback_url",
    "redirect_to",
    "redirectUrl",
    "redirectURL",
    "rurl",
    "ru",
    "u",
    "share_url",
    "source",
    "domain",
    "host",
    "uri",
    "url_redirect",
    "success_url",
    "failure_url",
    "cancel_url",
]

# External test URLs for injection
EXTERNAL_TARGETS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "https:evil.com",
    "https://evil.com/redirect",
    "http://attacker.net",
    "//attacker.net",
]

# Status codes considered as redirects
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


def _is_external_url(url: str, base_domain: str) -> bool:
    """Check if a URL points to an external domain.

    Args:
        url: The URL to check.
        base_domain: The base domain of the target.

    Returns:
        True if the URL is external.
    """
    parsed = urlparse(url)
    if not parsed.netloc:
        return False
    return parsed.netloc.lower() != base_domain.lower()


def _extract_base_domain(target_url: str) -> str:
    """Extract the base domain from a URL.

    Args:
        target_url: Full URL.

    Returns:
        The hostname (netloc) portion.
    """
    return urlparse(target_url).netloc or target_url


def scan_open_redirect(target_url: str) -> dict[str, Any]:
    """Scan for open redirect vulnerabilities.

    Args:
        target_url: The target URL to scan.

    Returns:
        Dict with status and findings:
        - ``status``: ``"success"`` or ``"partial"``
        - ``data``: dict with ``findings`` list
    """
    logger.info(f"Starting open redirect scan on {target_url}")

    findings: list[dict[str, Any]] = []

    # Validate target
    if not target_url or not isinstance(target_url, str):
        return {
            "status": "error",
            "data": {"findings": []},
        }

    # Ensure URL has scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    base_domain = _extract_base_domain(target_url)
    session = safe_session(timeout=10, retries=1)

    try:
        parsed_url = urlparse(target_url)
        base_params = parse_qs(parsed_url.query, keep_blank_values=True)

        # Test each redirect parameter with each payload
        for param in REDIRECT_PARAMS:
            for external_url in EXTERNAL_TARGETS:
                try:
                    # Build the injected URL
                    params = parse_qs(parsed_url.query, keep_blank_values=True)
                    params[param] = [external_url]
                    new_query = urlencode(params, doseq=True)
                    injected_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment,
                    ))

                    # Make request without following redirects
                    resp = session.get(
                        injected_url,
                        timeout=10,
                        allow_redirects=False,
                    )

                    if resp is None:
                        continue

                    redirect_url = None
                    is_open = False

                    # Check for redirect status codes
                    if resp.status_code in REDIRECT_STATUS_CODES:
                        location = resp.headers.get("Location", "")
                        if location and _is_external_url(location, base_domain):
                            redirect_url = location
                            is_open = True

                    # Also check for meta refresh redirects
                    if not is_open:
                        meta_redirect = _check_meta_refresh(resp.text)
                        if meta_redirect and _is_external_url(
                            meta_redirect, base_domain
                        ):
                            redirect_url = meta_redirect
                            is_open = True

                    # Check for JavaScript redirects
                    if not is_open:
                        js_redirect = _check_js_redirect(resp.text, external_url)
                        if js_redirect:
                            redirect_url = js_redirect
                            is_open = True

                    if is_open:
                        finding: dict[str, Any] = {
                            "param": param,
                            "payload": external_url,
                            "redirect_url": redirect_url,
                            "status_code": resp.status_code,
                            "severity": "medium",
                            "cvss_score": 5.0,
                            "url": injected_url,
                            "redirect_type": _categorize_redirect_type(
                                resp.status_code, resp.text
                            ),
                        }
                        findings.append(finding)
                        logger.info(
                            f"Open redirect found: {param}={external_url[:30]} "
                            f"-> {redirect_url}"
                        )
                        break  # One finding per param is enough

                except Exception as exc:
                    logger.warning(
                        f"Redirect test failed for {param}: {exc}"
                    )
                    continue

    except Exception as exc:
        logger.error(f"Open redirect scan failed: {exc}")
        return {
            "status": "error",
            "data": {"findings": findings},
        }
    finally:
        session.close()

    status = "success" if len(findings) > 0 else "partial"
    return {
        "status": status,
        "data": {"findings": findings},
    }


def _check_meta_refresh(html: str) -> str | None:
    """Check for meta refresh redirect in HTML.

    Args:
        html: Response body text.

    Returns:
        Redirect URL if found, None otherwise.
    """
    import re
    # Match: <meta http-equiv="refresh" content="0;url=http://...">
    patterns = [
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']\d+;url=(.+?)["\'>]',
        r'<meta[^>]+content\s*=\s*["\']\d+;url=(.+?)["\'>][^>]*http-equiv\s*=\s*["\']?refresh["\']?',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None


def _check_js_redirect(html: str, target_url: str) -> str | None:
    """Check for JavaScript-based redirects.

    Args:
        html: Response body text.
        target_url: The external URL being tested.

    Returns:
        Redirect URL if found, None otherwise.
    """
    import re
    # Check for common JS redirect patterns
    patterns = [
        rf'window\.location\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'window\.location\.href\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'window\.location\.replace\(["\']({re.escape(target_url)})["\']\)',
        rf'document\.location\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'document\.location\.href\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'location\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'location\.href\s*=\s*["\']({re.escape(target_url)})["\']',
        rf'window\.open\(["\']({re.escape(target_url)})["\']',
        rf'window\.navigate\(["\']({re.escape(target_url)})["\']',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _categorize_redirect_type(
    status_code: int, html: str
) -> str:
    """Categorize the type of redirect detected.

    Args:
        status_code: HTTP status code.
        html: Response body text.

    Returns:
        ``"http_redirect"``, ``"meta_refresh"``, or ``"javascript"``.
    """
    if status_code in REDIRECT_STATUS_CODES:
        return "http_redirect"
    if _check_meta_refresh(html):
        return "meta_refresh"
    return "javascript"


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = scan_open_redirect(target)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['data']['findings'])}")
    for f in result['data']['findings']:
        print(f"  [{f['severity']}] {f['param']} -> {f.get('redirect_url', 'N/A')}")
