"""HTTP security headers analysis module (US-05).

Analyzes HTTP response security headers and produces a scored
assessment with recommendations.
"""

from typing import Any

from src.utils.http import get
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Security headers to check with their scoring rules
HEADER_CHECKS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "weight": 20,
        "description": "HTTP Strict Transport Security (HSTS)",
        "check": lambda v: "max-age=" in v and "includeSubDomains" in v,
        "partial": lambda v: "max-age=" in v,
        "recommendation": (
            "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
        ),
    },
    "Content-Security-Policy": {
        "weight": 20,
        "description": "Content Security Policy (CSP)",
        "check": lambda v: bool(v.strip()),
        "partial": lambda v: False,
        "recommendation": (
            "Set a Content-Security-Policy header to mitigate XSS and data injection attacks"
        ),
    },
    "X-Frame-Options": {
        "weight": 10,
        "description": "Clickjacking Protection",
        "check": lambda v: v in ("DENY", "SAMEORIGIN"),
        "partial": lambda v: bool(v),
        "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking",
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "MIME-type Sniffing Protection",
        "check": lambda v: v == "nosniff",
        "partial": lambda v: bool(v),
        "recommendation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing",
    },
    "X-XSS-Protection": {
        "weight": 5,
        "description": "Cross-Site Scripting Filter",
        "check": lambda v: "1; mode=block" in v,
        "partial": lambda v: v.startswith("1"),
        "recommendation": (
            "Set 'X-XSS-Protection: 1; mode=block' (deprecated but still recommended)"
        ),
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Referrer Policy",
        "check": lambda v: v in (
            "no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "no-referrer-when-downgrade",
        ),
        "partial": lambda v: bool(v),
        "recommendation": (
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' "
            "or 'no-referrer'"
        ),
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Permissions Policy (Feature Policy)",
        "check": lambda v: bool(v.strip()),
        "partial": lambda v: False,
        "recommendation": (
            "Set a Permissions-Policy header to restrict browser feature access"
        ),
    },
    "Access-Control-Allow-Origin": {
        "weight": 5,
        "description": "CORS - Allowed Origins",
        "check": lambda v: v not in ("*", "null"),
        "partial": lambda v: bool(v),
        "recommendation": (
            "Avoid using wildcard '*' for Access-Control-Allow-Origin in production"
        ),
    },
    "Access-Control-Allow-Credentials": {
        "weight": 5,
        "description": "CORS - Credentials",
        "check": lambda v: v == "true",
        "partial": lambda v: False,
        "recommendation": (
            "Only set 'Access-Control-Allow-Credentials: true' if the app "
            "explicitly needs credential sharing"
        ),
    },
    "Access-Control-Allow-Methods": {
        "weight": 5,
        "description": "CORS - Allowed Methods",
        "check": lambda v: bool(v.strip()),
        "partial": lambda v: False,
        "recommendation": "Restrict Access-Control-Allow-Methods to only required HTTP methods",
    },
}

MAX_SCORE = sum(check["weight"] for check in HEADER_CHECKS.values())


def analyze_headers(target_url: str) -> dict[str, Any]:
    """Analyze HTTP security headers for a target URL.

    Args:
        target_url: The full URL (e.g., ``https://example.com``).

    Returns:
        A dict with keys:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict with ``headers`` (list of header analyses),
          ``score`` (int), ``max_score`` (int), ``percentage`` (float),
          ``grade`` (str)
        - ``error``: ``None`` or error message
    """
    logger.info(f"Analyzing security headers for {target_url}")

    if not target_url or not isinstance(target_url, str):
        return {
            "status": "error",
            "data": {},
            "error": "Invalid target URL",
        }

    # Ensure URL has scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    response = get(target_url, timeout=10)
    if response is None:
        return {
            "status": "error",
            "data": {},
            "error": f"Failed to fetch {target_url}",
        }

    headers = response.headers
    results: list[dict[str, Any]] = []
    total_score = 0

    for header, config in HEADER_CHECKS.items():
        value = headers.get(header, "")
        present = header in headers

        if present and config["check"](value):
            score = config["weight"]
            status_tag = "pass"
        elif present and config["partial"](value):
            score = config["weight"] // 2
            status_tag = "partial"
        else:
            score = 0
            status_tag = "fail"

        total_score += score

        results.append({
            "header": header,
            "present": present,
            "value": value,
            "score": score,
            "max_score": config["weight"],
            "status": status_tag,
            "recommendation": config["recommendation"],
            "description": config["description"],
        })

    percentage = (total_score / MAX_SCORE * 100) if MAX_SCORE > 0 else 0.0
    grade = _calculate_grade(percentage)

    return {
        "status": "success",
        "data": {
            "headers": results,
            "score": total_score,
            "max_score": MAX_SCORE,
            "percentage": round(percentage, 1),
            "grade": grade,
        },
        "error": None,
    }


def _calculate_grade(percentage: float) -> str:
    """Convert a percentage score to a letter grade (A-F)."""
    if percentage >= 90:
        return "A"
    if percentage >= 75:
        return "B"
    if percentage >= 60:
        return "C"
    if percentage >= 40:
        return "D"
    return "F"


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = analyze_headers(target)
    print(f"Status: {result['status']}")
    if result["data"]:
        print(f"Grade: {result['data']['grade']} "
              f"({result['data']['score']}/{result['data']['max_score']})")
        for h in result["data"]["headers"]:
            print(f"  [{h['status']:>7}] {h['header']}: {h['value'] or '(missing)'}")
