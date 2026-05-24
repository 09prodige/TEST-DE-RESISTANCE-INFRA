"""CMS and framework fingerprinting module (US-08).

Detects web technologies (CMS, frameworks, languages) from HTTP
headers, HTML meta tags, and known paths.
"""

from typing import Any
from urllib.parse import urljoin

from src.utils.http import get
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Technology fingerprint signatures
TECH_SIGNATURES: list[dict[str, Any]] = [
    # === CMS ===
    {
        "name": "WordPress",
        "category": "CMS",
        "headers": {
            "X-Powered-By": [],
            "X-Generator": ["wordpress"],
        },
        "meta": {
            "generator": ["wordpress"],
        },
        "paths": [
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/",
            "/wp-json/",
            "/xmlrpc.php",
            "/wp-login.php",
        ],
        "body_patterns": [
            r"\/wp-content\/",
            r"\/wp-includes\/",
            r"wordpress",
        ],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "headers": {
            "X-Generator": ["drupal"],
            "X-Drupal": [],
        },
        "meta": {
            "generator": ["drupal"],
        },
        "paths": [
            "/sites/default/",
            "/core/",
            "/modules/",
            "/themes/",
            "/node/",
            "/user/login",
        ],
        "body_patterns": [
            r"drupal",
            r"Drupal.settings",
        ],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "headers": {
            "X-Generator": ["joomla"],
            "X-Content-Encoded-By": [],
        },
        "meta": {
            "generator": ["joomla"],
        },
        "paths": [
            "/administrator/",
            "/components/",
            "/modules/",
            "/templates/",
            "/plugins/",
            "/media/",
        ],
        "body_patterns": [
            r"joomla",
            r"Joomla",
        ],
    },
    # === Frameworks (PHP) ===
    {
        "name": "Laravel",
        "category": "Framework",
        "headers": {
            "X-Powered-By": [],
            "Set-Cookie": ["laravel_session"],
        },
        "meta": {},
        "paths": [
            "/artisan",
            "/vendor/",
            "/storage/",
        ],
        "body_patterns": [
            r"Laravel",
            r"csrf-token",
            r"laravel_session",
        ],
    },
    # === Frameworks (Python) ===
    {
        "name": "Django",
        "category": "Framework",
        "headers": {
            "X-Frame-Options": [],
            "X-Content-Type-Options": [],
        },
        "meta": {},
        "paths": [
            "/admin/",
            "/static/admin/",
            "/accounts/login/",
        ],
        "body_patterns": [
            r"csrfmiddlewaretoken",
            r"__admin",
            r"django",
        ],
    },
    {
        "name": "Flask",
        "category": "Framework",
        "headers": {
            "Server": [],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    # === Frameworks (Ruby) ===
    {
        "name": "Ruby on Rails",
        "category": "Framework",
        "headers": {
            "X-Powered-By": [],
            "X-Runtime": [],
            "X-Request-Id": [],
        },
        "meta": {
            "csrf-param": ["authenticity_token"],
        },
        "paths": [
            "/rails/info/properties",
            "/assets/",
            "/favicon.ico",
        ],
        "body_patterns": [
            r"rails",
            r"authenticity_token",
            r"csrf-token",
        ],
    },
    # === Frameworks (JavaScript) ===
    {
        "name": "Express.js",
        "category": "Framework",
        "headers": {
            "X-Powered-By": ["express"],
            "Set-Cookie": ["connect.sid"],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    {
        "name": "Next.js",
        "category": "Framework",
        "headers": {
            "X-Powered-By": ["next"],
        },
        "meta": {},
        "paths": [
            "/_next/static/",
            "/api/",
        ],
        "body_patterns": [
            r"__NEXT_DATA__",
            r"next\.",
            r"\/_next\/",
        ],
    },
    {
        "name": "Nuxt.js",
        "category": "Framework",
        "headers": {},
        "meta": {},
        "paths": [
            "/_nuxt/",
        ],
        "body_patterns": [
            r"__NUXT__",
            r"\/_nuxt\/",
        ],
    },
    # === Web Servers / Languages ===
    {
        "name": "PHP",
        "category": "Language",
        "headers": {
            "X-Powered-By": ["php"],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    {
        "name": "Apache",
        "category": "Server",
        "headers": {
            "Server": ["apache"],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    {
        "name": "Nginx",
        "category": "Server",
        "headers": {
            "Server": ["nginx"],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    {
        "name": "IIS",
        "category": "Server",
        "headers": {
            "Server": ["iis"],
            "X-Powered-By": ["asp.net"],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
    {
        "name": "Cloudflare",
        "category": "CDN",
        "headers": {
            "Server": ["cloudflare"],
            "CF-RAY": [],
        },
        "meta": {},
        "paths": [],
        "body_patterns": [],
    },
]

# Technologies detectable purely from headers (no path check needed)
HEADER_ONLY_TECHS = {"Apache", "Nginx", "IIS", "PHP", "Cloudflare", "Express.js", "Flask"}


def fingerprint(target_url: str) -> dict[str, Any]:
    """Fingerprint web technologies used by a target URL.

    Makes HEAD request, fetches homepage, and optionally probes
    known paths to identify CMS, frameworks, and servers.

    Args:
        target_url: The target URL to fingerprint.

    Returns:
        A dict with keys:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict with ``technologies`` (list of detected techs)
        - ``error``: ``None`` or error message
    """
    logger.info(f"Fingerprinting {target_url}")

    if not target_url or not isinstance(target_url, str):
        return {
            "status": "error",
            "data": {},
            "error": "Invalid target URL",
        }

    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    # Fetch headers and body
    response = get(target_url, timeout=10)
    if response is None:
        return {
            "status": "error",
            "data": {},
            "error": f"Failed to fetch {target_url}",
        }

    headers = response.headers
    body = response.text
    detected: list[dict[str, Any]] = []

    for tech in TECH_SIGNATURES:
        evidence: list[str] = []
        confidence = 0.0

        # 1. Check headers
        for header, expected_values in tech["headers"].items():
            value = headers.get(header, "")
            if not value:
                continue
            if expected_values:
                if any(exp.lower() in value.lower() for exp in expected_values):
                    evidence.append(f"Header {header}: {value}")
                    confidence += 0.3
            else:
                # Header exists (any value)
                evidence.append(f"Header {header} present: {value}")
                confidence += 0.2

        # 2. Check meta tags
        for meta_name, expected_values in tech["meta"].items():
            meta_tag = _find_meta_tag(body, meta_name)
            if meta_tag:
                if any(exp.lower() in meta_tag.lower() for exp in expected_values):
                    evidence.append(f"Meta {meta_name}: {meta_tag}")
                    confidence += 0.25

        # 3. Check body patterns
        for pattern in tech["body_patterns"]:
            import re
            if re.search(pattern, body, re.IGNORECASE):
                evidence.append(f"Body pattern match: {pattern}")
                confidence += 0.15

        # 4. Check known paths (only if already some signal or if it's a path-heavy tech)
        if tech["paths"] and (confidence > 0 or tech["name"] in ("WordPress", "Drupal", "Joomla")):
            path_confidence = _check_paths(target_url, tech["paths"])
            if path_confidence > 0:
                evidence.append(f"Found {int(path_confidence * 100)}% of known paths")
                confidence += path_confidence

        if confidence > 0:
            # Cap confidence at 1.0
            confidence = min(confidence, 1.0)
            detected.append({
                "name": tech["name"],
                "category": tech["category"],
                "confidence": round(confidence, 2),
                "evidence": evidence,
            })

    # Sort by confidence descending
    detected.sort(key=lambda t: t["confidence"], reverse=True)

    return {
        "status": "success",
        "data": {
            "technologies": detected,
            "total_detected": len(detected),
        },
        "error": None,
    }


def _find_meta_tag(html: str, meta_name: str) -> str | None:
    """Find a meta tag's content by name attribute using simple string search."""
    import re
    # Match: <meta name="generator" content="..." /> or <meta ... name='generator' ...>
    pattern = (
        r'<meta[^>]*?\s+name\s*=\s*["\']'
        + re.escape(meta_name)
        + r'["\'][^>]*?\s+content\s*=\s*["\']([^"\']+)["\']'
    )
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    # Try reversed attribute order
    pattern2 = (
        r'<meta[^>]*?\s+content\s*=\s*["\']([^"\']+)["\'][^>]*?\s+name\s*=\s*["\']'
        + re.escape(meta_name)
        + r'["\']'
    )
    match = re.search(pattern2, html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def _check_paths(base_url: str, paths: list[str]) -> float:
    """Check which known paths exist on the target, returning confidence."""
    found = 0
    total = len(paths)
    if total == 0:
        return 0.0

    for path in paths:
        url = urljoin(base_url, path)
        resp = get(url, timeout=5)
        if resp is not None and resp.status_code not in (404, 410):
            found += 1

    ratio = found / total
    return ratio * 0.3  # Path checks contribute up to 0.3 confidence


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = fingerprint(target)
    print(f"Status: {result['status']}")
    if result["data"]:
        print(f"Technologies detected: {result['data']['total_detected']}")
        for tech in result["data"]["technologies"]:
            print(f"  [{tech['category']}] {tech['name']} "
                  f"(confidence: {tech['confidence']:.0%})")
            for ev in tech["evidence"]:
                print(f"    - {ev}")
