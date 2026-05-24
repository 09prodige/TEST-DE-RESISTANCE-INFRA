"""CSRF vulnerability detection module (US-11).

Analyzes forms for CSRF protection tokens and checks cookie SameSite
attributes and Origin/Referer header validation.
"""

import re
from typing import Any
from urllib.parse import urljoin

from src.utils.http import get
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common CSRF token field names
CSRF_TOKEN_NAMES: set[str] = {
    "csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "token",
    "authenticity_token",
    "_token",
    "csrf-token",
    "xsrf-token",
    "xsrf",
    "_csrf",
    "csrf_name",
    "csrf_value",
    "csrfkey",
    "csrfparam",
    "csrftoken",
    "requesttoken",
    "__requestverificationtoken",
    "form_token",
    "securitytoken",
    "anticsrf",
}

# Regex patterns for CSRF tokens in input names
CSRF_TOKEN_PATTERNS = [
    re.compile(r"csrf", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"authenticity", re.IGNORECASE),
    re.compile(r"xsrf", re.IGNORECASE),
    re.compile(r"anticsrf", re.IGNORECASE),
]

# SameSite values and their security levels
SAMESITE_SECURITY: dict[str, str] = {
    "strict": "secure",
    "lax": "partial",
    "none": "insecure",
    "": "missing",
}

# Content types that should have CSRF protection
CSRF_REQUIRED_CONTENT_TYPES = [
    "text/html",
    "application/xhtml",
    "application/xml",
    "text/xml",
    "application/json",
]


def _has_csrf_token(inputs: list[dict[str, str]]) -> bool:
    """Check if any input field is a CSRF token.

    Args:
        inputs: List of form input dicts with ``name``, ``type``, ``value``.

    Returns:
        True if a CSRF token field is found.
    """
    for inp in inputs:
        name = inp.get("name", "")
        inp_type = inp.get("type", "")

        # Hidden fields are typical for CSRF tokens
        if inp_type != "hidden":
            continue

        if name.lower() in {n.lower() for n in CSRF_TOKEN_NAMES}:
            return True

        for pattern in CSRF_TOKEN_PATTERNS:
            if pattern.search(name):
                return True

    return False


def _check_samesite_cookies(
    response_headers: dict[str, str],
) -> list[dict[str, str | None]]:
    """Parse Set-Cookie headers and check SameSite attribute.

    Args:
        response_headers: Dict of HTTP response headers.

    Returns:
        List of dicts with ``cookie_name``, ``samesite``, and ``secure``.
    """
    cookie_results: list[dict[str, str | None]] = []
    set_cookie = response_headers.get("Set-Cookie", "")

    if not set_cookie:
        return cookie_results

    # Handle multiple Set-Cookie headers (joined by the caller)
    cookies = [set_cookie] if isinstance(set_cookie, str) else set_cookie

    for cookie_str in cookies if isinstance(cookies, list) else [cookies]:
        # Extract cookie name
        parts = cookie_str.split(";")
        cookie_name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()

        # Check SameSite
        samesite = None
        secure = False
        for part in parts[1:]:
            part = part.strip()
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1].strip().lower()
            if part.lower() == "secure":
                secure = True

        cookie_results.append({
            "cookie_name": cookie_name,
            "samesite": samesite,
            "secure": secure,
        })

    return cookie_results


def _check_origin_referer(
    response_headers: dict[str, str],
    target_url: str,
) -> dict[str, Any]:
    """Check if the response includes Origin/Referer validation hints.

    Args:
        response_headers: Dict of HTTP response headers.
        target_url: The target URL being checked.

    Returns:
        Dict with ``origin_header``, ``referer_header``,
        ``has_origin_header``, ``has_referer_check``.
    """
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"

    result: dict[str, Any] = {
        "origin_header": response_headers.get("Origin", ""),
        "referer_header": response_headers.get("Referer", ""),
        "access_control_origin": response_headers.get("Access-Control-Allow-Origin", ""),
        "target_origin": target_origin,
    }

    return result


def scan_csrf(target_url: str, forms: list | None = None) -> dict[str, Any]:
    """Scan for CSRF vulnerabilities in web forms.

    Args:
        target_url: The target URL to scan.
        forms: Optional list of forms from the crawler. If None,
               forms will be scraped from the page.

    Returns:
        Dict with status and findings:
        - ``status``: ``"success"``, ``"partial"``, or ``"error"``
        - ``data``: dict with ``findings`` list
    """
    logger.info(f"Starting CSRF scan on {target_url}")

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

    try:
        # Fetch the page to check cookies and headers
        response = get(target_url)

        # Check SameSite cookies
        if response is not None:
            cookie_info = _check_samesite_cookies(response.headers)

            for cookie in cookie_info:
                samesite = cookie.get("samesite")
                severity = _get_samesite_severity(samesite)

                if severity:
                    finding: dict[str, Any] = {
                        "type": "cookie_samesite",
                        "cookie_name": cookie["cookie_name"],
                        "samesite": samesite,
                        "secure": cookie.get("secure", False),
                        "severity": severity,
                        "cvss_score": _samesite_to_cvss(samesite),
                        "url": target_url,
                    }
                    findings.append(finding)
                    logger.info(
                        f"CSRF cookie issue: {cookie['cookie_name']} "
                        f"SameSite={samesite}"
                    )

        # Check Origin/Referer headers
        if response is not None:
            origin_check = _check_origin_referer(response.headers, target_url)
            if origin_check.get("access_control_origin") == "*":
                findings.append({
                    "type": "cors_misconfiguration",
                    "detail": "Access-Control-Allow-Origin: *",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "url": target_url,
                })

        # Analyze forms if provided or fetch page
        target_forms = forms

        if target_forms is None and response is not None:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")

            target_forms = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs: list[dict[str, str]] = []

                for inp in form.find_all(["input", "textarea", "select"]):
                    inp_type = inp.get("type", "text") if inp.name == "input" else inp.name
                    inp_name = inp.get("name", "")
                    inp_value = inp.get("value", "")
                    inputs.append({
                        "type": inp_type,
                        "name": inp_name,
                        "value": inp_value,
                    })

                action_url = urljoin(target_url, action) if action else target_url

                target_forms.append({
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                })

        # Analyze each form for CSRF protection
        for form in (target_forms or []):
            form_action = form.get("action", target_url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            # Only check state-changing methods
            if method not in ("POST", "PUT", "DELETE", "PATCH"):
                continue

            has_token = _has_csrf_token(inputs)

            if not has_token:
                # Check if there are any inputs at all (meaningful form)
                has_inputs = any(
                    inp.get("name") and inp.get("type") != "submit"
                    for inp in inputs
                )

                if has_inputs:
                    finding = {
                        "type": "missing_csrf_token",
                        "form_action": form_action,
                        "method": method,
                        "has_csrf_token": False,
                        "input_count": len(inputs),
                        "severity": "medium",
                        "cvss_score": 5.0,
                        "url": form_action,
                    }
                    findings.append(finding)
                    logger.info(
                        f"CSRF token missing: {form_action} ({method})"
                    )

    except Exception as exc:
        logger.error(f"CSRF scan failed: {exc}")
        return {
            "status": "error",
            "data": {"findings": findings},
        }

    status = "success" if len(findings) > 0 else "partial"
    return {
        "status": status,
        "data": {"findings": findings},
    }


def _get_samesite_severity(samesite: str | None) -> str | None:
    """Get severity level based on SameSite attribute.

    Args:
        samesite: The SameSite value (strict, lax, none, or None).

    Returns:
        Severity string or None if secure.
    """
    if samesite is None:
        return "medium"
    if samesite.lower() == "none":
        return "medium"
    if samesite.lower() == "lax":
        return "low"
    if samesite.lower() == "strict":
        return None  # secure
    return "medium"


def _samesite_to_cvss(samesite: str | None) -> float:
    """Convert SameSite setting to CVSS-like score.

    Args:
        samesite: The SameSite value.

    Returns:
        Numeric score.
    """
    if samesite is None:
        return 5.0
    if samesite.lower() == "none":
        return 5.0
    if samesite.lower() == "lax":
        return 3.0
    if samesite.lower() == "strict":
        return 0.0
    return 5.0


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = scan_csrf(target)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['data']['findings'])}")
    for f in result['data']['findings']:
        print(f"  [{f['severity']}] {f.get('type', 'unknown')}")
