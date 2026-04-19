"""
api.py — REST API blueprint providing all data endpoints for the dashboard
and external SIEM/SOAR integrations.

All endpoints return JSON. Authentication is enforced via Flask-Login session.
Rate limiting is applied globally via the app factory.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from typing import Callable

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user, login_required
from loguru import logger

from src.database.db_manager import get_db
from src.database.models import AlertSeverity, AttackPattern
from src.enrichment.ip_reputation import ThreatIntelEnricher


def build_api_blueprint(admin_required: Callable) -> Blueprint:
    api_bp  = Blueprint("api", __name__)
    db      = get_db()
    enricher = ThreatIntelEnricher()

    # ─── Summary / KPIs ──────────────────────────────────────────────────

    @api_bp.route("/summary")
    @login_required
    def summary():
        """High-level KPI summary for the dashboard overview panel."""
        window = int(request.args.get("hours", 24))
        return jsonify(db.get_dashboard_summary(window_hours=window))

    # ─── Events ──────────────────────────────────────────────────────────

    @api_bp.route("/events/timeseries")
    @login_required
    def events_timeseries():
        """Bucketed failed/success login counts for timeline chart."""
        hours  = int(request.args.get("hours", 24))
        bucket = int(request.args.get("bucket_minutes", 15))
        since  = datetime.utcnow() - timedelta(hours=hours)
        data   = db.get_events_timeseries(since, bucket_minutes=bucket)
        return jsonify(data)

    @api_bp.route("/events/top-ips")
    @login_required
    def top_ips():
        """Top attacking IP addresses by failure count."""
        hours = int(request.args.get("hours", 24))
        limit = int(request.args.get("limit", 10))
        since = datetime.utcnow() - timedelta(hours=hours)
        rows  = db.get_top_attacking_ips(since, limit=limit)
        result = []
        for ip, count in rows:
            ti = enricher.get_threat_summary(ip)
            result.append({
                "ip":           ip,
                "count":        count,
                "country":      ti.get("country", "Unknown"),
                "abuse_score":  ti.get("abuse_score"),
                "is_known_bad": ti.get("is_known_bad", False),
                "lat":          ti.get("lat"),
                "lon":          ti.get("lon"),
            })
        return jsonify(result)

    @api_bp.route("/events/geo")
    @login_required
    def geo_distribution():
        """Geographic distribution of attacks for map visualisation."""
        hours = int(request.args.get("hours", 24))
        since = datetime.utcnow() - timedelta(hours=hours)
        data  = db.get_geo_distribution(since)
        return jsonify(data)

    # ─── Alerts ──────────────────────────────────────────────────────────

    @api_bp.route("/alerts")
    @login_required
    def list_alerts():
        """Paginated alert list with optional severity/status filters."""
        limit  = min(int(request.args.get("limit", 50)), 500)
        sev    = request.args.get("severity")
        acked  = request.args.get("acknowledged")

        severity_filter = AlertSeverity(sev) if sev else None
        acked_filter = {"true": True, "false": False}.get(acked)

        alerts = db.get_recent_alerts(
            limit=limit,
            severity=severity_filter,
            acknowledged=acked_filter,
        )
        return jsonify([_serialise_alert(a) for a in alerts])

    @api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    @login_required
    def acknowledge_alert(alert_id: int):
        analyst = str(current_user.id)
        success = db.acknowledge_alert(alert_id, analyst)
        if not success:
            return jsonify({"error": "Alert not found"}), 404
        db.log_audit(
            actor=analyst, action="alert_acknowledged",
            target_type="alert", target_id=str(alert_id),
        )
        return jsonify({"status": "acknowledged", "by": analyst})

    @api_bp.route("/alerts/export/csv")
    @login_required
    def export_alerts_csv():
        """Export alert list as CSV for external analysis."""
        hours  = int(request.args.get("hours", 72))
        alerts = db.get_recent_alerts(limit=5000)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "created_at", "severity", "pattern",
            "source_ip", "username", "attempt_count",
            "time_window_sec", "description", "acknowledged",
        ])
        for a in alerts:
            writer.writerow([
                a.id, a.created_at, a.severity.value, a.pattern.value,
                a.source_ip, a.username, a.attempt_count,
                a.time_window_sec, a.description, a.is_acknowledged,
            ])

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"bruteguard_alerts_{datetime.utcnow():%Y%m%d_%H%M}.csv",
        )

    # ─── Threat Intelligence ─────────────────────────────────────────────

    @api_bp.route("/threat-intel/<ip>")
    @login_required
    def threat_intel_lookup(ip: str):
        """On-demand TI enrichment for a specific IP."""
        summary = enricher.get_threat_summary(ip)
        if not summary.get("enriched"):
            # Trigger live lookup
            record = enricher.enrich(ip)
            summary = enricher.get_threat_summary(ip)
        return jsonify(summary)

    # ─── Blocked IPs ─────────────────────────────────────────────────────

    @api_bp.route("/blocked-ips")
    @login_required
    def list_blocked():
        with db.session() as session:
            from src.database.models import BlockedIP
            from datetime import datetime as dt
            rows = (
                session.query(BlockedIP)
                .filter(BlockedIP.is_active == True)
                .order_by(BlockedIP.blocked_at.desc())
                .all()
            )
        return jsonify([
            {
                "id":         r.id,
                "ip":         r.ip_address,
                "blocked_at": r.blocked_at.isoformat(),
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "reason":     r.reason,
                "blocked_by": r.blocked_by,
            }
            for r in rows
        ])

    @api_bp.route("/blocked-ips/<int:block_id>/unblock", methods=["POST"])
    @login_required
    @admin_required
    def unblock_ip(block_id: int):
        with db.session() as session:
            from src.database.models import BlockedIP
            record = session.query(BlockedIP).filter(BlockedIP.id == block_id).first()
            if not record:
                return jsonify({"error": "Not found"}), 404
            record.is_active = False

        db.log_audit(
            actor=str(current_user.id), action="ip_unblocked",
            target_type="ip", target_id=record.ip_address,
        )
        return jsonify({"status": "unblocked"})

    # ─── ML Model ────────────────────────────────────────────────────────

    @api_bp.route("/ml/status")
    @login_required
    def ml_status():
        from src.detectors.ml_detector import MLDetector
        detector = MLDetector()
        return jsonify({
            "enabled":    detector.enabled,
            "is_trained": detector.is_ready,
            "model_path": detector.model_path,
        })

    @api_bp.route("/ml/retrain", methods=["POST"])
    @login_required
    @admin_required
    def ml_retrain():
        """Trigger ML model retraining on recent events."""
        from src.detectors.ml_detector import MLDetector
        from src.database.models import LoginEvent
        hours = int(request.json.get("hours", 168)) if request.json else 168
        since = datetime.utcnow() - timedelta(hours=hours)
        with db.session() as session:
            events = (
                session.query(LoginEvent)
                .filter(LoginEvent.timestamp >= since)
                .all()
            )
        detector = MLDetector()
        result   = detector.train(events)
        return jsonify(result)

    # ─── Reports ─────────────────────────────────────────────────────────

    @api_bp.route("/reports/generate", methods=["POST"])
    @login_required
    def generate_report():
        from src.reporting.report_generator import ReportGenerator
        hours  = (request.json or {}).get("hours", 24)
        fmt    = (request.json or {}).get("format", "pdf")
        gen    = ReportGenerator()
        path   = gen.generate(hours=hours, fmt=fmt)
        return jsonify({"status": "generated", "path": path})

    # ─── Serialiser ──────────────────────────────────────────────────────

    def _serialise_alert(a) -> dict:
        return {
            "id":             a.id,
            "created_at":     a.created_at.isoformat() if a.created_at else None,
            "severity":       a.severity.value,
            "pattern":        a.pattern.value,
            "source_ip":      a.source_ip,
            "username":       a.username,
            "attempt_count":  a.attempt_count,
            "time_window":    a.time_window_sec,
            "description":    a.description,
            "rule_name":      a.rule_name,
            "threat_score":   a.threat_score,
            "acknowledged":   a.is_acknowledged,
            "acknowledged_by": a.acknowledged_by,
        }

    return api_bp
