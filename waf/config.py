"""
config.py — loads and validates config.yaml, with env-var overrides.
"""

import os
import logging
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML is required: pip install pyyaml")

logger = logging.getLogger(__name__)

_DEFAULTS = {
    "backend": {"host": "127.0.0.1", "port": 8000, "scheme": "http", "timeout": 10},
    "waf": {"host": "0.0.0.0", "port": 5000, "debug": False},
    "detection": {
        "wordlist": "data.txt",
        "threshold": 0.75,
        "embedding_model": "all-MiniLM-L6-v2",
    },
    "route_rules": {},
    "allowlist": {"ips": [], "paths": []},
    "block": {
        "format": "html",
        "status_code": 403,
        "html_template": "block.html",
        "json_body": '{"error": "Request blocked by WAF"}',
    },
    "rate_limit": {"enabled": True, "requests_per_minute": 60, "burst": 10},
    "dashboard": {
        "enabled": True,
        "route": "/waf-dashboard",
        "api_key": "change-me-before-deploying",
    },
    "logging": {"level": "INFO", "file": "waf.log", "db": "waf_events.db"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load(path: str = "config.yaml") -> dict:
    cfg = _DEFAULTS.copy()

    p = Path(path)
    if p.exists():
        with open(p) as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = _deep_merge(cfg, user_cfg)
        logger.info(f"Config loaded from {p}")
    else:
        logger.warning(f"Config file {p} not found — using defaults")

    # Environment variable overrides
    _env_overrides(cfg)
    return cfg


def _env_overrides(cfg: dict):
    """Allow critical settings to be overridden via environment variables."""
    overrides = {
        "WAF_BACKEND_HOST":      ("backend", "host"),
        "WAF_BACKEND_PORT":      ("backend", "port"),
        "WAF_PORT":              ("waf", "port"),
        "WAF_THRESHOLD":         ("detection", "threshold"),
        "WAF_WORDLIST":          ("detection", "wordlist"),
        "WAF_DASHBOARD_KEY":     ("dashboard", "api_key"),
        "WAF_LOG_LEVEL":         ("logging", "level"),
        "WAF_DB":                ("logging", "db"),
    }
    for env_key, (section, key) in overrides.items():
        val = os.environ.get(env_key)
        if val is not None:
            # Cast to original type
            original = cfg[section][key]
            try:
                if isinstance(original, bool):
                    cfg[section][key] = val.lower() in ("1", "true", "yes")
                elif isinstance(original, int):
                    cfg[section][key] = int(val)
                elif isinstance(original, float):
                    cfg[section][key] = float(val)
                else:
                    cfg[section][key] = val
            except (ValueError, TypeError):
                logger.warning(f"Could not cast env var {env_key}={val!r} — ignored")


def build_detection_config(cfg: dict) -> dict:
    """Flatten the config into the shape WAFDetector expects."""
    det = cfg["detection"]
    return {
        "threshold":       det["threshold"],
        "wordlist":        det["wordlist"],
        "embedding_model": det["embedding_model"],
        "route_rules":     cfg.get("route_rules", {}),
        "allowlist":       cfg.get("allowlist", {"ips": [], "paths": []}),
    }
