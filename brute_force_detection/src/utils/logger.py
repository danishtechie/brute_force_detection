"""
logger.py — Structured logging configuration for BruteGuard.

Uses loguru with JSON sink for production and colourised console
output for development. All modules import `logger` from here.
"""

import sys
from pathlib import Path

from loguru import logger


def configure_logging(level: str = "INFO", log_dir: str = "data/logs") -> None:
    """
    Configure loguru sinks:
      - Colourised stdout for interactive use
      - Rotating JSON file for machine-readable audit trail
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger.remove()  # Remove default handler

    # ── Console sink ──────────────────────────────────────────────────────
    logger.add(
        sys.stdout,
        level=level,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        backtrace=True,
        diagnose=True,
    )

    # ── Rotating JSON file sink ───────────────────────────────────────────
    logger.add(
        f"{log_dir}/bruteguard_{{time:YYYY-MM-DD}}.log",
        level="DEBUG",
        rotation="00:00",       # New file at midnight
        retention="30 days",
        compression="gz",
        serialize=True,         # JSON output
        backtrace=True,
        diagnose=False,         # Disable in prod (may expose sensitive data)
        enqueue=True,           # Thread-safe async logging
    )

    # ── Security events file (always INFO+) ───────────────────────────────
    logger.add(
        f"{log_dir}/security_events.log",
        level="INFO",
        rotation="100 MB",
        retention="90 days",
        compression="gz",
        filter=lambda record: "SECURITY" in record["extra"],
        format="{time:YYYY-MM-DDTHH:mm:ss.SSSZ} | {level} | {message} | {extra}",
        enqueue=True,
    )

    logger.info("Logging subsystem initialised", level=level, log_dir=log_dir)


def get_security_logger():
    """Return a logger bound with SECURITY context tag."""
    return logger.bind(SECURITY=True)


# Export the global logger for convenience
__all__ = ["logger", "configure_logging", "get_security_logger"]
