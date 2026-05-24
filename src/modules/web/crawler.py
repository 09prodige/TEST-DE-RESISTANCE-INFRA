"""Web crawler module (US-07).

Crawls a target website up to a configurable depth, collecting pages,
forms, links, and resources.
"""

import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from src.utils.http import get, safe_session
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Resources to collect by tag/attribute
RESOURCE_TAGS: dict[str, str] = {
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "source": "src",
    "video": "src",
    "audio": "src",
    "embed": "src",
    "object": "data",
}

# File extensions considered as pages (not resources)
PAGE_EXTENSIONS = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp",
                   ".do", ".cgi", ".pl", ".py", ".cfm", ".shtml"}

# Robots.txt disallowed paths cache
_robots_disallowed: list[str] = []


def _fetch_robots_txt(base_url: str) -> list[str]:
    """Fetch and parse robots.txt for the given base URL.

    Args:
        base_url: The base URL of the target site.

    Returns:
        A list of disallowed path patterns.
    """
    global _robots_disallowed
    if _robots_disallowed:
        return _robots_disallowed

    robots_url = urljoin(base_url, "/robots.txt")
    response = get(robots_url, timeout=5)

    if response is None or response.status_code != 200:
        _robots_disallowed = []
        return _robots_disallowed

    disallowed: list[str] = []
    for line in response.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line[9:].strip()
            if path:
                disallowed.append(path)

    _robots_disallowed = disallowed
    return disallowed


def _is_allowed_by_robots(url: str) -> bool:
    """Check if a URL is allowed by robots.txt."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    for disallowed in _robots_disallowed:
        if disallowed == "/":
            return False
        if disallowed.endswith("*"):
            if path.startswith(disallowed[:-1]):
                return False
        elif path.startswith(disallowed):
            return False
    return True


def _normalize_url(base: str, href: str) -> str | None:
    """Resolve and normalize a URL, returning None if invalid."""
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None

    joined = urljoin(base, href)
    parsed = urlparse(joined)

    # Only http/https
    if parsed.scheme not in ("http", "https"):
        return None

    # Normalize: remove fragment, lowercase scheme/host
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/") or "/" if parsed.path else "/",
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))

    return normalized


def _is_same_domain(url: str, base_domain: str) -> bool:
    """Check if URL belongs to the same domain."""
    return base_domain in urlparse(url).netloc


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[dict[str, Any]]:
    """Extract form elements from parsed HTML."""
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

        # Resolve form action URL
        if action:
            action_url = urljoin(page_url, action)
        else:
            action_url = page_url

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs,
        })

    return forms


def _extract_links(soup: BeautifulSoup, page_url: str) -> list[str]:
    """Extract all anchor href links from parsed HTML."""
    links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        url = _normalize_url(page_url, anchor["href"])
        if url:
            links.append(url)
    return list(set(links))


def _extract_resources(soup: BeautifulSoup, page_url: str) -> list[dict[str, str]]:
    """Extract resource URLs from parsed HTML."""
    resources: list[dict[str, str]] = []
    seen: set[str] = set()

    for tag_name, attr in RESOURCE_TAGS.items():
        for tag in soup.find_all(tag_name):
            value = tag.get(attr)
            if value:
                url = _normalize_url(page_url, value)
                if url and url not in seen:
                    seen.add(url)
                    resources.append({
                        "tag": tag_name,
                        "attribute": attr,
                        "url": url,
                    })

    return resources


def crawl(target_url: str, max_depth: int = 2) -> dict[str, Any]:
    """Crawl a target website up to the specified depth.

    Args:
        target_url: The starting URL to crawl.
        max_depth: Maximum crawl depth (default 2).

    Returns:
        A dict with keys:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict with ``pages``, ``forms``, ``links``,
          ``resources``, ``total_pages``, ``total_forms``,
          ``total_links``, ``total_resources``
        - ``error``: ``None`` or error message
    """
    logger.info(f"Crawling {target_url} (max depth: {max_depth})")

    if not target_url or not isinstance(target_url, str):
        return {
            "status": "error",
            "data": {},
            "error": "Invalid target URL",
        }

    # Ensure URL has scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    # Fetch robots.txt
    _fetch_robots_txt(target_url)

    # Get base domain
    parsed_base = urlparse(target_url)
    base_domain = parsed_base.netloc

    # Crawl state
    visited: set[str] = set()
    to_visit: list[tuple[str, int]] = [(target_url, 0)]  # (url, depth)
    all_forms: list[dict[str, Any]] = []
    all_links: list[str] = []
    all_resources: list[dict[str, str]] = []
    pages: list[dict[str, Any]] = []

    session = safe_session(timeout=10)

    try:
        while to_visit:
            url, depth = to_visit.pop(0)

            if url in visited:
                continue
            if depth > max_depth:
                continue
            if not _is_allowed_by_robots(url):
                logger.debug(f"Skipping (disallowed by robots.txt): {url}")
                continue

            visited.add(url)
            logger.debug(f"Crawling [{depth}/{max_depth}]: {url}")

            # Fetch page
            response = get(url, timeout=10, session=session)
            if response is None:
                logger.debug(f"Failed to fetch: {url}")
                continue

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                logger.debug(f"Skipping non-HTML: {url} ({content_type})")
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract data
            forms = _extract_forms(soup, url)
            links = _extract_links(soup, url)
            resources = _extract_resources(soup, url)

            all_forms.extend(forms)
            all_links.extend(links)
            all_resources.extend(resources)

            pages.append({
                "url": url,
                "depth": depth,
                "title": soup.title.string if soup.title else "",
                "status_code": response.status_code,
                "content_type": content_type,
                "form_count": len(forms),
                "link_count": len(links),
                "resource_count": len(resources),
            })

            # Enqueue internal links for further crawling
            if depth < max_depth:
                for link in links:
                    if link not in visited and _is_same_domain(link, base_domain):
                        to_visit.append((link, depth + 1))

    finally:
        session.close()

    # Deduplicate links
    all_links = list(set(all_links))

    return {
        "status": "success",
        "data": {
            "target_url": target_url,
            "max_depth": max_depth,
            "pages": pages,
            "forms": all_forms,
            "links": all_links,
            "resources": all_resources,
            "total_pages": len(pages),
            "total_forms": len(all_forms),
            "total_links": len(all_links),
            "total_resources": len(all_resources),
        },
        "error": None,
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = crawl(target, max_depth=1)
    print(f"Status: {result['status']}")
    if result["data"]:
        print(f"Pages: {result['data']['total_pages']}")
        print(f"Forms: {result['data']['total_forms']}")
        print(f"Links: {result['data']['total_links']}")
        print(f"Resources: {result['data']['total_resources']}")
