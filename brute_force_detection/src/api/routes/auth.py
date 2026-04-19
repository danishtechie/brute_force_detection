"""
auth.py — Authentication blueprint: login, logout, user management.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from src.database.db_manager import get_db


def build_auth_blueprint(users: dict, User, login_manager: LoginManager) -> Blueprint:
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login", methods=["GET"])
    def login_page():
        return render_template("login.html")

    @auth_bp.route("/login", methods=["POST"])
    def login():
        # Accept both JSON body and HTML form submissions
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form
        username = (data.get("username") or "").strip().lower()
        password = (data.get("password") or "")

        user_record = users.get(username)
        if not user_record or not check_password_hash(user_record["password_hash"], password):
            get_db().log_audit(
                actor="anonymous", action="login_failed",
                target_type="user", target_id=username,
                ip_address=request.remote_addr, success=False,
            )
            if request.is_json:
                return jsonify({"error": "Invalid credentials"}), 401
            return render_template("login.html", error="Invalid username or password"), 401

        user = User(user_record["username"], user_record["role"])
        login_user(user, remember=True)

        get_db().log_audit(
            actor=username, action="login_success",
            target_type="user", target_id=username,
            ip_address=request.remote_addr, success=True,
        )

        if request.is_json:
            return jsonify({"status": "ok", "role": user_record["role"]})
        return redirect(url_for("dashboard.dashboard_page"))

    @auth_bp.route("/logout")
    @login_required
    def logout():
        get_db().log_audit(
            actor=str(getattr(__import__("flask_login", fromlist=["current_user"]).current_user, "id", "unknown")),
            action="logout", target_type="user",
        )
        logout_user()
        return redirect(url_for("auth.login_page"))

    return auth_bp