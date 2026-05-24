"""SQL Injection detection module (US-09).

Detects SQL injection vulnerabilities using error-based and
boolean-based techniques on GET parameters and form inputs.
"""

import re
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from bs4 import BeautifulSoup

from src.utils.http import get, safe_session
from src.utils.logger import get_logger

logger = get_logger(__name__)

# SQL error patterns for various databases
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"Unknown column '[^']+' in 'field list'",
        r"MySqlException",
        r"com\.mysql\.jdbc",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"WARNING:\s+psql",
        r"PGError",
        r"psql:.*ERROR",
        r"PostgreSQL.*warning",
        r"pg_query\(\):",
        r"driver\.connect\(.*postgresql",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"org.sqlite.",
        r"warning.*sqlite",
        r"sqlite.*error",
        r"SQLITE_ERROR",
    ],
    "MSSQL": [
        r"Microsoft.*SQL.*Server.*error",
        r"Driver.*SQL Server",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver",
        r"Exception.*SQL.*Server",
        r"\[SQL Server\]",
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"Line \d+:",
    ],
    "Oracle": [
        r"Oracle.*Driver",
        r"oracle\.jdbc",
        r"ORA-[0-9]{5}",
        r"OracleException",
        r"PLS-[0-9]{5}",
    ],
}

# SQL boolean-based payloads
BOOLEAN_TRUE_PAYLOADS = [
    "' AND '1'='1",
    "' AND 1=1--",
    "1' AND '1'='1",
    "' OR '1'='1",
]
BOOLEAN_FALSE_PAYLOADS = [
    "' AND '1'='2",
    "' AND 1=2--",
    "1' AND '1'='2",
    "' OR '1'='2",
]

# Error-based payloads (triggers SQL errors)
ERROR_PAYLOADS = [
    "'",
    "\"",
    "--",
    ";",
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "\" OR \"1\"=\"1",
    "' AND SLEEP(5)--",
    "'; SELECT 1; --",
    "1' OR '1'='1",
    "`",
]


def _parse_sql_errors(html: str) -> dict[str, list[str]]:
    """Search HTML for SQL error messages by database type.

    Args:
        html: Response body text to scan.

    Returns:
        dict mapping database names to lists of matched patterns.
    """
    found: dict[str, list[str]] = {}
    for db_name, patterns in SQL_ERROR_PATTERNS.items():
        matches: list[str] = []
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                matches.append(match.group(0))
        if matches:
            found[db_name] = matches
    return found


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

        from urllib.parse import urljoin
        action_url = urljoin(page_url, action) if action else page_url

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs,
        })

    return forms


def _inject_get_param(
    url: str,
    param: str,
    payload: str,
    session: Any,
    timeout: int = 10,
) -> tuple[str, Any] | None:
    """Inject a payload into a GET parameter and return the response.

    Args:
        url: Base URL.
        param: Parameter name to inject into.
        payload: Payload string to inject.
        session: Requests session.
        timeout: Request timeout.

    Returns:
        Tuple of (injected_url, response) or None on failure.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]

    new_query = urlencode(params, doseq=True)
    injected_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment,
    ))

    try:
        resp = session.get(injected_url, timeout=timeout)
        return injected_url, resp
    except Exception as exc:
        logger.warning(f"GET injection failed for {param}={payload}: {exc}")
        return None


def scan_sqli(target_url: str, forms: list | None = None) -> dict[str, Any]:
    """Scan for SQL injection vulnerabilities.

    Args:
        target_url: The target URL to scan.
        forms: Optional list of forms from the crawler. If None,
               forms will be scraped from the page.

    Returns:
        Dict with status and findings:
        - ``status``: ``"success"``, ``"partial"``, or ``"error"``
        - ``data``: dict with ``findings`` list
    """
    logger.info(f"Starting SQLi scan on {target_url}")

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

        # -- Error-based detection on GET parameters --
        parsed_url = urlparse(target_url)
        base_params = parse_qs(parsed_url.query, keep_blank_values=True)

        # If no params exist, try common params for testing
        if not base_params:
            base_params = {"id": [""], "page": [""], "q": [""], "search": [""]}

        for param in base_params:
            for payload in ERROR_PAYLOADS:
                result = _inject_get_param(target_url, param, payload, session)
                if result is None:
                    continue

                injected_url, resp = result
                db_errors = _parse_sql_errors(resp.text)

                if db_errors:
                    cvss_score = _compute_sqli_cvss("error-based", db_errors)
                    severity = _score_to_severity(cvss_score)

                    finding: dict[str, Any] = {
                        "param": param,
                        "method": "GET",
                        "type": "error-based",
                        "payload": payload,
                        "evidence": list(db_errors.keys()),
                        "confidence": 0.85,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "url": injected_url,
                        "status_code": resp.status_code,
                    }
                    findings.append(finding)
                    logger.info(
                        f"SQLi (error) found: {param} via {payload} "
                        f"-> {list(db_errors.keys())}"
                    )

        # -- Boolean-based detection on GET parameters --
        for param in base_params:
            baseline_resp = session.get(target_url, timeout=10)
            if baseline_resp is None:
                continue

            baseline_length = len(baseline_resp.text)

            for true_payload in BOOLEAN_TRUE_PAYLOADS:
                result_true = _inject_get_param(
                    target_url, param, true_payload, session
                )
                if result_true is None:
                    continue

                _, resp_true = result_true
                true_length = len(resp_true.text)

                # Find corresponding false payload
                false_idx = BOOLEAN_TRUE_PAYLOADS.index(true_payload)
                if false_idx >= len(BOOLEAN_FALSE_PAYLOADS):
                    continue

                false_payload = BOOLEAN_FALSE_PAYLOADS[false_idx]
                result_false = _inject_get_param(
                    target_url, param, false_payload, session
                )
                if result_false is None:
                    continue

                _, resp_false = result_false
                false_length = len(resp_false.text)

                # If response lengths differ significantly, it may be boolean-based
                if abs(true_length - false_length) > 50:
                    finding = {
                        "param": param,
                        "method": "GET",
                        "type": "boolean-based",
                        "payload": f"{true_payload} vs {false_payload}",
                        "evidence": (
                            f"Response diff: true={true_length}, "
                            f"false={false_length}, baseline={baseline_length}"
                        ),
                        "confidence": 0.65,
                        "severity": "high",
                        "cvss_score": 7.5,
                        "url": target_url,
                        "status_code": resp_true.status_code,
                    }
                    findings.append(finding)
                    logger.info(
                        f"SQLi (boolean) found: {param} "
                        f"diff={true_length - false_length}"
                    )

        # -- Form-based testing (POST parameters) --
        for form in target_forms:
            form_action = form.get("action", target_url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if method != "POST":
                continue

            # Find inputs that accept text
            text_inputs = [
                inp for inp in inputs
                if inp["type"] in ("text", "search", "textarea", "") and inp["name"]
            ]

            for inp in text_inputs:
                param = inp["name"]

                for payload in ERROR_PAYLOADS:
                    form_data: dict[str, str] = {}
                    for field in inputs:
                        field_name = field["name"]
                        if field_name == param:
                            form_data[field_name] = payload
                        elif field.get("value"):
                            form_data[field_name] = field["value"]
                        else:
                            form_data[field_name] = ""

                    try:
                        resp = session.post(
                            form_action, data=form_data, timeout=10
                        )
                    except Exception as exc:
                        logger.warning(
                            f"POST injection failed for {param}: {exc}"
                        )
                        continue

                    db_errors = _parse_sql_errors(resp.text)

                    if db_errors:
                        finding = {
                            "param": param,
                            "method": "POST",
                            "type": "error-based",
                            "payload": payload,
                            "evidence": list(db_errors.keys()),
                            "confidence": 0.85,
                            "severity": _score_to_severity(
                                _compute_sqli_cvss("error-based", db_errors)
                            ),
                            "cvss_score": _compute_sqli_cvss(
                                "error-based", db_errors
                            ),
                            "url": form_action,
                            "status_code": resp.status_code,
                        }
                        findings.append(finding)
                        logger.info(
                            f"SQLi (POST) found: {param} via {payload}"
                        )

    except Exception as exc:
        logger.error(f"SQLi scan failed: {exc}")
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


def _compute_sqli_cvss(vuln_type: str, db_errors: dict | None = None) -> float:
    """Compute a CVSS-like score for an SQLi finding.

    Args:
        vuln_type: "error-based" or "boolean-based".
        db_errors: Dict of matched database error patterns.

    Returns:
        A float score from 0.0 to 10.0.
    """
    base_score = 9.0 if vuln_type == "error-based" else 7.5
    # Reduce slightly if we only have low-confidence patterns
    if db_errors and len(db_errors) >= 2:
        base_score = min(10.0, base_score + 0.5)
    return base_score


def _score_to_severity(score: float) -> str:
    """Convert a CVSS-like score to severity label.

    Args:
        score: Numeric score (0.0 to 10.0).

    Returns:
        ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = scan_sqli(target)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['data']['findings'])}")
    for f in result['data']['findings']:
        print(f"  [{f['severity']}] {f['param']} ({f['type']})")
