"""
dashboard.py — Dashboard HTML page routes.
"""

from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required


def build_dashboard_blueprint() -> Blueprint:
    dash_bp = Blueprint("dashboard", __name__)

    @dash_bp.route("/")
    @dash_bp.route("/dashboard")
    @login_required
    def dashboard_page():
        return render_template("dashboard.html")

    @dash_bp.route("/reports")
    @login_required
    def reports_page():
        return render_template("reports.html")

    return dash_bp
