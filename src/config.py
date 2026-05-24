"""YAML-based configuration loader for RIG Security Scanner.

Provides a centralized configuration system with sensible defaults.
Configuration is loaded from a YAML file with automatic search paths:

    ``./rig.yml`` → ``./config/rig.yml`` → ``~/.config/rig/config.yml``

Typical usage::

    from src.config import load_config

    config = load_config("config/rig.yml")
    module_cfg = get_module_config("web")
    timeout = config["scan"]["timeout"]
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Default configuration — every key present so partial YAML files merge safely
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: dict[str, Any] = {
    "scan": {
        "default_modules": ["recon", "web", "vuln"],
        "timeout": 30,
        "max_threads": 20,
        "rate_limit": 10,
        "user_agent": "RIG-Scanner/0.2",
    },
    "modules": {
        "recon": {
            "port_range": [1, 10000],
            "subdomain_wordlist": "default",
            "dns_timeout": 5,
        },
        "web": {
            "crawl_depth": 2,
            "ssl_timeout": 10,
        },
        "vuln": {
            "sqli_payloads": "default",
            "xss_payloads": "default",
        },
    },
    "reporting": {
        "format": "html",
        "output_dir": "reports/",
        "cvss_version": "3.1",
    },
    "docker": {
        "network": "host",
    },
}

# ---------------------------------------------------------------------------
# Search paths (in order of priority)
# ---------------------------------------------------------------------------
CONFIG_SEARCH_PATHS: list[str] = [
    "./rig.yml",
    "./config/rig.yml",
    "~/.config/rig/config.yml",
]


def _merge_config(user_cfg: dict, defaults: dict) -> dict:
    """Deep-merge *user_cfg* over *defaults*, preserving all default keys.

    Args:
        user_cfg: User-provided configuration dict (possibly partial).
        defaults: Full default configuration dict.

    Returns:
        A new dict with user values overriding defaults at every level.
    """
    merged = defaults.copy()
    for key, value in user_cfg.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_config(value, merged[key])
        else:
            merged[key] = value
    return merged


def _find_config(path: str | None = None) -> Path | None:
    """Locate the first existing config file from search paths or *path*.

    Args:
        path: Explicit path provided by the caller (optional).

    Returns:
        ``Path`` to the first readable config file, or ``None``.
    """
    if path is not None:
        p = Path(path).expanduser().resolve()
        if p.is_file():
            logger.info(f"Using config: {p}")
            return p
        logger.warning(f"Config file not found: {p}")
        return None

    for search in CONFIG_SEARCH_PATHS:
        p = Path(search).expanduser().resolve()
        if p.is_file():
            logger.info(f"Using config: {p}")
            return p

    logger.debug("No config file found — using defaults")
    return None


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load configuration from a YAML file, merging with defaults.

    If no *path* is given the search order is:
    ``./rig.yml`` → ``./config/rig.yml`` → ``~/.config/rig/config.yml``

    If no file is found the built-in defaults are returned.

    Args:
        path: Optional explicit path to a YAML config file.

    Returns:
        A complete configuration dict with all keys present.
    """
    config_path = _find_config(path)
    if config_path is None:
        return _deepcopy_config(DEFAULT_CONFIG)

    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is required. Install with: pip install pyyaml")
        return _deepcopy_config(DEFAULT_CONFIG)

    try:
        raw = config_path.read_text(encoding="utf-8")
        user_cfg: dict[str, Any] = yaml.safe_load(raw) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.error(f"Failed to parse {config_path}: {exc}")
        return _deepcopy_config(DEFAULT_CONFIG)

    merged = _merge_config(user_cfg, DEFAULT_CONFIG)
    logger.debug(f"Config loaded from {config_path}")
    return merged


def get_module_config(module: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the configuration sub-tree for a given module.

    Args:
        module: Module name (``"recon"``, ``"web"``, ``"vuln"``).
        config: Full configuration dict (loaded via :func:`load_config`).
                If ``None``, loads default config.

    Returns:
        Module-specific configuration dict.
    """
    if config is None:
        config = load_config()
    return config.get("modules", {}).get(module, DEFAULT_CONFIG["modules"].get(module, {}))


def _deepcopy_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-ish copy of the configuration dict.

    Standard ``dict.copy()`` is shallow; we use this helper to avoid
    mutating the global defaults when callers modify the returned dict.
    """
    import copy
    return copy.deepcopy(cfg)


def get_reporting_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the reporting sub-configuration.

    Args:
        config: Full configuration dict. If ``None``, loads default config.

    Returns:
        Reporting configuration dict.
    """
    if config is None:
        config = load_config()
    return config.get("reporting", DEFAULT_CONFIG["reporting"])


# ---------------------------------------------------------------------------
# CLI integration helper
# ---------------------------------------------------------------------------
def config_to_cli_options(config: dict[str, Any]) -> dict[str, Any]:
    """Convert config dict to Click-compatible option overrides.

    This is useful when the CLI wants to pre-fill defaults from the
    config file. Currently returns an empty dict — expand as needed.

    Args:
        config: Full configuration dict.

    Returns:
        Dict mapping option names to values.
    """
    options: dict[str, Any] = {}
    scan_cfg = config.get("scan", {})
    if "default_modules" in scan_cfg:
        options["modules"] = scan_cfg["default_modules"]
    return options


if __name__ == "__main__":
    # Quick self-test
    cfg = load_config()
    print("=== Default config ===")
    import json
    print(json.dumps(cfg, indent=2, default=str))
    print(f"\nWeb module config: {get_module_config('web', cfg)}")
    print(f"Reporting config: {get_reporting_config(cfg)}")
