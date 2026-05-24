"""Sensitive files exposure detection module (US-12).

Tests for exposed sensitive files and directories such as .env,
.git/config, backup files, admin panels, etc.
"""

from typing import Any
from urllib.parse import urljoin

from src.utils.http import safe_session
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common sensitive paths to check
SENSITIVE_PATHS: list[dict[str, Any]] = [
    # Configuration files
    {"path": ".env", "description": "Environment variables file", "severity": "critical"},
    {"path": ".env.example", "description": "Environment variables example", "severity": "medium"},
    {"path": ".env.bak", "description": "Environment variables backup", "severity": "critical"},
    {"path": ".env.local", "description": "Local environment variables", "severity": "critical"},
    {"path": ".env.production", "description": "Production environment variables", "severity": "critical"},

    # Git
    {"path": ".git/config", "description": "Git configuration", "severity": "high"},
    {"path": ".git/HEAD", "description": "Git HEAD reference", "severity": "high"},
    {"path": ".gitignore", "description": "Git ignore rules", "severity": "medium"},

    # Database
    {"path": "backup.sql", "description": "Database backup", "severity": "critical"},
    {"path": "dump.sql", "description": "Database dump", "severity": "critical"},
    {"path": "db.sqlite3", "description": "SQLite database", "severity": "critical"},
    {"path": "database.sql", "description": "Database SQL file", "severity": "critical"},
    {"path": "db_backup.sql", "description": "Database backup", "severity": "critical"},
    {"path": "backup.zip", "description": "Backup archive", "severity": "critical"},
    {"path": "backup.tar.gz", "description": "Backup archive", "severity": "critical"},

    # CMS specific
    {"path": "wp-config.php", "description": "WordPress configuration", "severity": "critical"},
    {"path": "wp-admin/", "description": "WordPress admin panel", "severity": "medium"},
    {"path": "wp-content/debug.log", "description": "WordPress debug log", "severity": "high"},
    {"path": "config.php", "description": "Application configuration", "severity": "high"},
    {"path": "configuration.php", "description": "Joomla configuration", "severity": "critical"},
    {"path": "config/", "description": "Configuration directory", "severity": "medium"},

    # Info disclosure
    {"path": "phpinfo.php", "description": "PHP info page", "severity": "high"},
    {"path": "info.php", "description": "PHP info page", "severity": "high"},
    {"path": "test.php", "description": "Test PHP script", "severity": "low"},
    {"path": "info/", "description": "Info directory", "severity": "medium"},

    # Log files
    {"path": "error.log", "description": "Error log file", "severity": "high"},
    {"path": "debug.log", "description": "Debug log file", "severity": "high"},
    {"path": "access.log", "description": "Access log file", "severity": "high"},
    {"path": "install.log", "description": "Installation log", "severity": "medium"},
    {"path": "composer.log", "description": "Composer log", "severity": "medium"},

    # Version control / CI
    {"path": ".svn/entries", "description": "Subversion entries file", "severity": "high"},
    {"path": ".svn/wc.db", "description": "Subversion working copy database", "severity": "high"},
    {"path": ".DS_Store", "description": "macOS directory metadata", "severity": "low"},
    {"path": "Thumbs.db", "description": "Windows thumbnail cache", "severity": "low"},

    # Security
    {"path": ".htaccess", "description": "Apache access control", "severity": "medium"},
    {"path": "crossdomain.xml", "description": "Adobe cross-domain policy", "severity": "medium"},
    {"path": "clientaccesspolicy.xml", "description": "Silverlight cross-domain policy", "severity": "medium"},
    {"path": "sitemap.xml", "description": "XML sitemap", "severity": "low"},

    # Admin / management
    {"path": "admin/", "description": "Admin panel", "severity": "medium"},
    {"path": "administrator/", "description": "Administrator panel", "severity": "medium"},
    {"path": "manager/", "description": "Management panel", "severity": "medium"},
    {"path": "panel/", "description": "Control panel", "severity": "medium"},

    # API docs and specs
    {"path": "swagger.json", "description": "Swagger API documentation", "severity": "medium"},
    {"path": "api-docs/", "description": "API documentation", "severity": "medium"},
    {"path": "openapi.json", "description": "OpenAPI specification", "severity": "medium"},
    {"path": "graphql", "description": "GraphQL endpoint (debug)", "severity": "low"},

    # Other common
    {"path": "composer.json", "description": "Composer dependencies", "severity": "medium"},
    {"path": "composer.lock", "description": "Composer lock file", "severity": "low"},
    {"path": "package.json", "description": "NPM package info", "severity": "low"},
    {"path": "package-lock.json", "description": "NPM lock file", "severity": "low"},
    {"path": "Procfile", "description": "Procfile (Heroku)", "severity": "low"},
    {"path": "Dockerfile", "description": "Docker configuration", "severity": "low"},
    {"path": "docker-compose.yml", "description": "Docker Compose config", "severity": "medium"},
    {"path": "requirements.txt", "description": "Python dependencies", "severity": "low"},
    {"path": "Gemfile", "description": "Ruby dependencies", "severity": "low"},
    {"path": "Gemfile.lock", "description": "Ruby lock file", "severity": "low"},
    {"path": "web.config", "description": "IIS configuration", "severity": "medium"},
]

# File extensions that typically indicate sensitive content
SENSITIVE_EXTENSIONS = {
    ".sql", ".bak", ".backup", ".old", ".orig", ".save",
    ".swp", ".swo", "~", ".log", ".zip", ".tar", ".gz",
    ".rar", ".7z", ".tgz",
}

# Known content signatures for banner grabbing
CONTENT_SIGNATURES: dict[str, list[str]] = {
    "Git repository": [b"ref:", b"HEAD", b"\\[core\\]"],
    "Environment file": [b"=", b"API_KEY", b"SECRET", b"PASSWORD", b"DATABASE_URL"],
    "PHP info": [b"PHP Version", b"phpinfo()", b"PHP License"],
    "Database dump": [b"DROP TABLE", b"CREATE TABLE", b"INSERT INTO", b"MySQL dump"],
    "WordPress config": [b"define\\(", b"DB_NAME", b"DB_USER", b"DB_PASSWORD"],
    "Apache config": [b"RewriteEngine", b"RewriteRule", b"Order allow,deny"],
}


def _get_content_preview(text: str, max_length: int = 200) -> str:
    """Get a preview of the content, sanitized.

    Args:
        text: Response body text.
        max_length: Maximum preview length.

    Returns:
        Truncated and sanitized preview string.
    """
    # Strip excessive whitespace
    preview = " ".join(text.split())

    # Truncate
    if len(preview) > max_length:
        preview = preview[:max_length] + "..."

    # Replace sensitive-looking values
    import re
    preview = re.sub(r'(?:password|pass|secret|key|token)\s*[=:]\s*\S+',
                     '***REDACTED***', preview, flags=re.IGNORECASE)

    return preview


def _detect_content_type(text: str) -> str | None:
    """Try to identify the type of file based on content.

    Args:
        text: Response body text.

    Returns:
            Content type label or None if unknown.
    """
    text_bytes = text.encode("utf-8")

    for content_type, signatures in CONTENT_SIGNATURES.items():
        import re
        for sig in signatures:
            if re.search(sig, text_bytes):
                return content_type

    return None


def scan_sensitive_files(target_url: str) -> dict[str, Any]:
    """Scan for exposed sensitive files and directories.

    Args:
        target_url: The target URL to scan.

    Returns:
        Dict with status and findings:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict with ``findings`` list
    """
    logger.info(f"Starting sensitive files scan on {target_url}")

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
        for entry in SENSITIVE_PATHS:
            path = entry["path"]
            description = entry["description"]
            severity = entry["severity"]

            test_url = urljoin(target_url + "/" if not target_url.endswith("/") else target_url, path)

            try:
                resp = session.get(test_url, timeout=10)

                status_code = resp.status_code

                # Determine exposure level
                if status_code == 200:
                    preview = _get_content_preview(resp.text)
                    content_type_hint = _detect_content_type(resp.text)

                    finding = {
                        "path": path,
                        "full_url": test_url,
                        "status_code": status_code,
                        "content_preview": preview,
                        "content_type_hint": content_type_hint,
                        "content_length": len(resp.content),
                        "severity": severity,
                        "cvss_score": _path_severity_to_cvss(severity),
                        "exposed": True,
                    }
                    findings.append(finding)
                    logger.info(
                        f"Sensitive file exposed: {test_url} "
                        f"({status_code}) [{severity}]"
                    )
                elif status_code in (401, 403):
                    # Protected but found
                    finding = {
                        "path": path,
                        "full_url": test_url,
                        "status_code": status_code,
                        "content_preview": None,
                        "content_type_hint": None,
                        "content_length": len(resp.content),
                        "severity": _downgrade_severity(severity),
                        "cvss_score": _path_severity_to_cvss(
                            _downgrade_severity(severity)
                        ),
                        "exposed": False,
                    }
                    findings.append(finding)
                    logger.info(
                        f"Sensitive file protected: {test_url} ({status_code})"
                    )
                # 404 = not found, skip
            except Exception as exc:
                logger.warning(
                    f"Sensitive file check failed for {test_url}: {exc}"
                )
                continue

    except Exception as exc:
        logger.error(f"Sensitive files scan failed: {exc}")
        return {
            "status": "error",
            "data": {"findings": findings},
        }
    finally:
        session.close()

    return {
        "status": "success",
        "data": {"findings": findings},
    }


def _path_severity_to_cvss(severity: str) -> float:
    """Convert a severity label to a CVSS-like score.

    Args:
        severity: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.

    Returns:
        Numeric score.
    """
    scores = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 2.0,
    }
    return scores.get(severity, 3.0)


def _downgrade_severity(severity: str) -> str:
    """Downgrade severity for protected files (403/401).

    Args:
        severity: Original severity.

    Returns:
        Downgraded severity.
    """
    downgrades = {
        "critical": "high",
        "high": "medium",
        "medium": "low",
        "low": "info",
    }
    return downgrades.get(severity, "info")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = scan_sensitive_files(target)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['data']['findings'])}")
    for f in result['data']['findings']:
        print(f"  [{f['severity']}] {f['path']} ({f['status_code']})")
