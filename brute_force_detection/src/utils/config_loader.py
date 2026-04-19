"""
config_loader.py — Centralised YAML configuration loader with environment
variable override support.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@lru_cache(maxsize=1)
def get_config(config_path: str = "config/config.yaml") -> dict:
    """
    Load and return the merged configuration dictionary.
    Environment variables prefixed with BG_ override YAML values.
    e.g. BG_DATABASE__SQLITE__PATH=/tmp/test.db
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path.absolute()}")

    with open(path, "r") as fh:
        cfg: dict = yaml.safe_load(fh)

    _apply_env_overrides(cfg, prefix="BG")
    return cfg


def _apply_env_overrides(cfg: dict, prefix: str) -> None:
    """Walk environment variables and apply dot-path overrides."""
    for key, val in os.environ.items():
        if not key.startswith(f"{prefix}_"):
            continue
        parts = key[len(prefix) + 1:].lower().split("__")
        _set_nested(cfg, parts, _coerce(val))


def _set_nested(d: dict, keys: list, value: Any) -> None:
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _coerce(value: str) -> Any:
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
