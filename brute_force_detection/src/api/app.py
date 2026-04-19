"""
app.py — BruteGuard SOC Platform — Flask + SocketIO application factory.

Provides:
  - REST API endpoints for dashboard data
  - WebSocket events for real-time alert streaming
  - Role-based authentication via Flask-Login
  - Rate limiting and CORS
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from loguru import logger
from werkzeug.security import check_password_hash, generate_password_hash

from src.database.db_manager import get_db
from src.database.models import AlertSeverity
from src.utils.config_loader import get_config


# ─── Application Factory ─────────────────────────────────────────────────────

def create_app() -> tuple[Flask, SocketIO]:
    """Create and configure the Flask application and SocketIO instance."""
    cfg = get_config()

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "../../dashboard/templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "../../dashboard/static"),
    )
    app.config["SECRET_KEY"] = cfg["app"]["secret_key"]
    app.config["DEBUG"]      = cfg["app"]["debug"]

    # ── Extensions ──────────────────────────────────────────────────────
    CORS(app, origins=cfg["api"]["cors_origins"], supports_credentials=True)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[cfg["api"]["rate_limit"]],
        storage_uri="memory://",
    )

    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # ── Authentication ───────────────────────────────────────────────────
    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login_page"

    # Build user store from config
    _users: dict[str, dict] = {}
    for user_cfg in cfg.get("users", []):
        uname = user_cfg["username"]
        # If still placeholder hash, generate from a default (change in prod!)
        ph = user_cfg.get("password_hash", "")
        if "placeholder" in ph:
            ph = generate_password_hash(f"admin_{uname}_changeme!")
        _users[uname] = {"username": uname, "password_hash": ph, "role": user_cfg.get("role", "analyst")}

    class User(UserMixin):
        def __init__(self, username: str, role: str) -> None:
            self.id   = username
            self.role = role

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        u = _users.get(user_id)
        return User(u["username"], u["role"]) if u else None

    # ── Decorators ───────────────────────────────────────────────────────
    def admin_required(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != "admin":
                return jsonify({"error": "Admin access required"}), 403
            return f(*args, **kwargs)
        return decorated

    # ── Register blueprints ──────────────────────────────────────────────
    from src.api.routes.auth      import build_auth_blueprint
    from src.api.routes.dashboard import build_dashboard_blueprint
    from src.api.routes.api       import build_api_blueprint

    app.register_blueprint(build_auth_blueprint(_users, User, login_manager), url_prefix="/")
    app.register_blueprint(build_dashboard_blueprint(),                         url_prefix="/")
    app.register_blueprint(build_api_blueprint(admin_required),                 url_prefix="/api/v1")

    # ── WebSocket events ─────────────────────────────────────────────────
    @socketio.on("connect")
    def handle_connect():
        logger.debug(f"WebSocket client connected: {request.sid}")
        emit("connected", {"status": "ok", "server_time": datetime.utcnow().isoformat()})

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.debug(f"WebSocket client disconnected: {request.sid}")

    @socketio.on("subscribe_alerts")
    def handle_subscribe():
        """Client subscribes to real-time alert stream."""
        emit("subscribed", {"message": "Subscribed to alert feed"})

    # ── Health check ─────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

    logger.info("Flask application created")
    return app, socketio


# ─── Global SocketIO broadcaster ─────────────────────────────────────────────
# Imported by the detection pipeline to push alerts to connected clients.

_socketio_instance: SocketIO | None = None


def get_socketio() -> SocketIO | None:
    return _socketio_instance


def set_socketio(sio: SocketIO) -> None:
    global _socketio_instance
    _socketio_instance = sio


def broadcast_alert(alert_dict: dict) -> None:
    """Push an alert dict to all connected WebSocket clients."""
    sio = get_socketio()
    if sio:
        try:
            sio.emit("new_alert", alert_dict, namespace="/")
        except Exception as exc:
            logger.debug(f"WebSocket broadcast failed: {exc}")
