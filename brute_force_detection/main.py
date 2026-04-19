"""
main.py — BruteGuard SOC Platform entry point.

Bootstraps the database, seeds historical data, starts the detection
pipeline, and launches the Flask/SocketIO web server.

Usage:
    python main.py [--config CONFIG_PATH] [--seed] [--no-pipeline]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

import sys
if sys.platform != "win32":
    import eventlet
    eventlet.monkey_patch() # Must be first for SocketIO async mode

from loguru import logger
from werkzeug.security import generate_password_hash

from src.api.app import create_app, set_socketio
from src.database.db_manager import get_db
from src.detectors.pipeline import DetectionPipeline
from src.utils.config_loader import get_config
from src.utils.logger import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="BruteGuard SOC Platform — Brute Force Detection System"
    )
    parser.add_argument("--config",      default="config/config.yaml",  help="Config file path")
    parser.add_argument("--seed",        action="store_true",           help="Seed DB with historical simulation data")
    parser.add_argument("--no-pipeline", action="store_true",           help="Run web server only (no detection)")
    parser.add_argument("--host",        default=None,                  help="Override API host")
    parser.add_argument("--port",        type=int, default=None,        help="Override API port")
    return parser.parse_args()


def bootstrap_database(seed: bool = False) -> None:
    """Initialise database tables and optionally seed with historical data."""
    db = get_db()
    db.create_tables()
    logger.info("Database tables verified")

    # Provision default detection rules
    _seed_detection_rules(db)

    # Seed default user passwords (first run)
    _provision_users()

    if seed:
        logger.info("Seeding historical simulation data…")
        from src.collectors.simulation import EventSimulator
        from src.database.models import LoginEvent
        sim    = EventSimulator()
        events = sim.generate_historical_data(days_back=7, events_per_hour=150)
        db.bulk_insert_events(events)
        logger.success(f"Seeded {len(events):,} historical events")


def _seed_detection_rules(db) -> None:
    from src.database.models import AlertSeverity, AttackPattern, DetectionRule
    default_rules = [
        DetectionRule(name="IP_BRUTE_FORCE_THRESHOLD",    pattern=AttackPattern.BRUTE_FORCE,
                      threshold=5,  time_window_sec=300, severity=AlertSeverity.HIGH,
                      description="5+ failures from same IP in 5 minutes"),
        DetectionRule(name="USER_BRUTE_FORCE_THRESHOLD",  pattern=AttackPattern.BRUTE_FORCE,
                      threshold=10, time_window_sec=300, severity=AlertSeverity.MEDIUM,
                      description="10+ failures against same account in 5 minutes"),
        DetectionRule(name="PASSWORD_SPRAY_DETECTION",    pattern=AttackPattern.PASSWORD_SPRAY,
                      threshold=5,  time_window_sec=300, severity=AlertSeverity.HIGH,
                      description="Single IP targeting 5+ unique usernames"),
        DetectionRule(name="CREDENTIAL_STUFFING_BURST",   pattern=AttackPattern.CREDENTIAL_STUFFING,
                      threshold=20, time_window_sec=60,  severity=AlertSeverity.CRITICAL,
                      description="20+ failures across multiple IPs in 60 seconds"),
        DetectionRule(name="ACCOUNT_LOCKOUT_4740",        pattern=AttackPattern.ACCOUNT_LOCKOUT,
                      threshold=1,  time_window_sec=0,   severity=AlertSeverity.HIGH,
                      description="Windows account lockout event detected"),
        DetectionRule(name="ISOLATION_FOREST_ANOMALY",    pattern=AttackPattern.ML_DETECTED,
                      threshold=None, time_window_sec=300, severity=AlertSeverity.MEDIUM,
                      description="Isolation Forest anomaly score below threshold"),
    ]
    with db.session() as session:
        from src.database.models import DetectionRule as DR
        existing = {r.name for r in session.query(DR).all()}
        for rule in default_rules:
            if rule.name not in existing:
                session.add(rule)
    logger.info("Detection rules provisioned")


def _provision_users() -> None:
    """Update placeholder password hashes in config on first run."""
    cfg_path = Path("config/config.yaml")
    if not cfg_path.exists():
        return
    with open(cfg_path, "r") as f:
        content = f.read()

    if "placeholder" in content:
        import yaml
        with open(cfg_path, "r") as f:
            cfg = yaml.safe_load(f)

        changed = False
        for user in cfg.get("users", []):
            if "placeholder" in user.get("password_hash", ""):
                default_pw = f"{user['username']}_changeme_2024!"
                user["password_hash"] = generate_password_hash(default_pw)
                logger.warning(
                    f"Default password set for '{user['username']}': "
                    f"'{default_pw}' — CHANGE THIS IN PRODUCTION!"
                )
                changed = True

        if changed:
            with open(cfg_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

        # Invalidate config cache
        from src.utils.config_loader import get_config
        get_config.cache_clear()


def print_banner() -> None:
    banner = r"""
╔══════════════════════════════════════════════════════════════╗
║   ____             _         ____                     _     ║
║  | __ ) _ __ _   _| |_ ___  / ___|_   _  __ _ _ __ __| |   ║
║  |  _ \| '__| | | | __/ _ \| |  _| | | |/ _` | '__/ _` |   ║
║  | |_) | |  | |_| | ||  __/| |_| | |_| | (_| | | | (_| |   ║
║  |____/|_|   \__,_|\__\___| \____|\__,_|\__,_|_|  \__,_|   ║
║                                                              ║
║           SOC Platform v2.1 — Brute Force Detection          ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main() -> None:
    args = parse_args()
    configure_logging(level="INFO")
    print_banner()

    cfg      = get_config(args.config)
    api_cfg  = cfg["api"]
    host     = args.host or api_cfg["host"]
    port     = args.port or api_cfg["port"]

    # 1. Bootstrap database
    bootstrap_database(seed=args.seed)

    # 2. Create Flask app + SocketIO
    app, socketio = create_app()
    set_socketio(socketio)

    # 3. Start detection pipeline (background threads)
    pipeline = None
    if not args.no_pipeline:
        pipeline = DetectionPipeline(socketio=socketio)
        pipeline.start()

    # 4. Launch web server
    logger.success(f"BruteGuard dashboard: http://{host}:{port}")
    logger.info(f"Default credentials → admin / admin_changeme_2024! (CHANGE IMMEDIATELY!)")

    try:
        socketio.run(
            app,
            host=host,
            port=port,
            debug=cfg["app"]["debug"],
            use_reloader=False,
            log_output=False,
        )
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        if pipeline:
            pipeline.stop()
        logger.info("BruteGuard shutdown complete")


if __name__ == "__main__":
    main()
