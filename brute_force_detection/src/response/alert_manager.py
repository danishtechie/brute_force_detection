"""
alert_manager.py — Centralised alert lifecycle management and response orchestration.

Responsibilities:
  - Persist alerts to database
  - Enrich with threat intelligence
  - Determine severity escalation
  - Dispatch notifications (email / Slack)
  - Trigger automated response (IP blocking)
  - Write audit trail entries
"""

from __future__ import annotations

import json
import smtplib
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

import requests
from loguru import logger

from src.database.db_manager import get_db
from src.database.models import Alert, AlertSeverity, AuditLog
from src.enrichment.ip_reputation import ThreatIntelEnricher
from src.utils.config_loader import get_config


# ─── Severity colour palette (for Slack/email) ───────────────────────────────

SEVERITY_EMOJI = {
    AlertSeverity.LOW:      "🔵",
    AlertSeverity.MEDIUM:   "🟡",
    AlertSeverity.HIGH:     "🟠",
    AlertSeverity.CRITICAL: "🔴",
}

SEVERITY_COLOUR = {    # Slack attachment colours
    AlertSeverity.LOW:      "#36a64f",
    AlertSeverity.MEDIUM:   "#f0c027",
    AlertSeverity.HIGH:     "#e07b00",
    AlertSeverity.CRITICAL: "#cc0000",
}


# ─── Email Notifier ──────────────────────────────────────────────────────────

class EmailNotifier:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.enabled = cfg.get("enabled", False)

    def send(self, alert: Alert, ti_summary: dict) -> bool:
        if not self.enabled:
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = (
                f"[BruteGuard] {SEVERITY_EMOJI.get(alert.severity, '')} "
                f"{alert.severity.value.upper()} — {alert.pattern.value.replace('_', ' ').title()}"
            )
            msg["From"]    = self.cfg["sender"]
            msg["To"]      = ", ".join(self.cfg["recipients"])

            html_body = self._build_html(alert, ti_summary)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.cfg["smtp_host"], self.cfg["smtp_port"]) as smtp:
                if self.cfg.get("use_tls"):
                    smtp.starttls()
                smtp.login(self.cfg["username"], self.cfg["password"])
                smtp.sendmail(self.cfg["sender"], self.cfg["recipients"], msg.as_string())

            logger.info(f"Email alert sent for alert id={alert.id}")
            return True
        except Exception as exc:
            logger.error(f"Email send failed: {exc}")
            return False

    def _build_html(self, alert: Alert, ti: dict) -> str:
        severity_color = SEVERITY_COLOUR.get(alert.severity, "#555")
        return f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #e6edf3; padding: 20px;">
        <div style="border-left: 4px solid {severity_color}; padding: 12px 20px; background: #161b22; border-radius: 6px;">
            <h2 style="margin:0; color: {severity_color};">
                {SEVERITY_EMOJI.get(alert.severity, '')} BruteGuard Alert — {alert.severity.value.upper()}
            </h2>
            <p><b>Pattern:</b> {alert.pattern.value.replace('_', ' ').title()}</p>
            <p><b>Source IP:</b> {alert.source_ip or 'N/A'} &nbsp;
               <b>Country:</b> {ti.get('country', 'Unknown')} &nbsp;
               <b>Abuse Score:</b> {ti.get('abuse_score', 'N/A')}/100</p>
            <p><b>Target User:</b> {alert.username or 'Multiple'}</p>
            <p><b>Attempts:</b> {alert.attempt_count} in {alert.time_window_sec}s</p>
            <p><b>Description:</b><br>{alert.description}</p>
            <p style="color:#8b949e; font-size:11px;">
                Generated at {alert.created_at} UTC by BruteGuard SOC Platform v2.1
            </p>
        </div>
        </body></html>
        """


# ─── Slack Notifier ──────────────────────────────────────────────────────────

class SlackNotifier:
    def __init__(self, cfg: dict) -> None:
        self.cfg     = cfg
        self.enabled = cfg.get("enabled", False)
        self.webhook = cfg.get("webhook_url", "")

    def send(self, alert: Alert, ti_summary: dict) -> bool:
        if not self.enabled or not self.webhook:
            return False

        emoji = SEVERITY_EMOJI.get(alert.severity, "⚠️")
        color = SEVERITY_COLOUR.get(alert.severity, "#555")

        payload = {
            "channel": self.cfg.get("channel", "#soc-alerts"),
            "username": "BruteGuard SOC",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color":  color,
                "pretext": f"{emoji} *Security Alert — {alert.severity.value.upper()}*",
                "fields": [
                    {"title": "Pattern",   "value": alert.pattern.value.replace("_", " ").title(), "short": True},
                    {"title": "Source IP", "value": alert.source_ip or "N/A",                      "short": True},
                    {"title": "Country",   "value": ti_summary.get("country", "Unknown"),          "short": True},
                    {"title": "Abuse Score","value": f"{ti_summary.get('abuse_score', 'N/A')}/100","short": True},
                    {"title": "Target",    "value": alert.username or "Multiple users",            "short": True},
                    {"title": "Attempts",  "value": f"{alert.attempt_count} / {alert.time_window_sec}s", "short": True},
                    {"title": "Detail",    "value": alert.description, "short": False},
                ],
                "footer": "BruteGuard SOC Platform",
                "ts":     int(datetime.utcnow().timestamp()),
            }],
        }

        try:
            resp = requests.post(self.webhook, json=payload, timeout=5)
            resp.raise_for_status()
            logger.info(f"Slack alert sent for id={alert.id}")
            return True
        except requests.RequestException as exc:
            logger.error(f"Slack send failed: {exc}")
            return False


# ─── Firewall Manager (simulation-safe) ──────────────────────────────────────

class FirewallManager:
    """
    Manages Windows Firewall block rules.
    On non-Windows systems (or if auto_block is disabled) operates in
    simulation mode, logging intended actions without making system calls.
    """

    def __init__(self) -> None:
        import platform
        self.is_windows = platform.system() == "Windows"
        cfg = get_config()["response"]
        self.enabled        = cfg["auto_block"]["enabled"]
        self.whitelist      = cfg["auto_block"]["whitelist_ips"]
        self.duration_min   = cfg["auto_block"]["block_duration_minutes"]

    def block_ip(self, ip: str, reason: str) -> bool:
        if not self.enabled:
            logger.info(f"[SIMULATE BLOCK] Would block {ip}: {reason}")
            return True

        if self._is_whitelisted(ip):
            logger.info(f"Block skipped — {ip} is whitelisted")
            return False

        rule_name = f"BruteGuard_Block_{ip.replace('.', '_')}"
        if self.is_windows:
            return self._windows_block(ip, rule_name, reason)
        else:
            logger.info(f"[SIMULATE] netsh advfirewall add rule name='{rule_name}' "
                        f"protocol=any dir=in action=block remoteip={ip}")
            return True

    def unblock_ip(self, ip: str) -> bool:
        rule_name = f"BruteGuard_Block_{ip.replace('.', '_')}"
        if self.is_windows:
            return self._windows_unblock(rule_name)
        logger.info(f"[SIMULATE] Would remove firewall rule: {rule_name}")
        return True

    def _windows_block(self, ip: str, rule_name: str, reason: str) -> bool:
        import subprocess
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "protocol=any", "dir=in",
            "action=block", f"remoteip={ip}",
            f"description=BruteGuard: {reason[:100]}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Firewall rule added: block {ip}")
            return True
        logger.error(f"Firewall block failed: {result.stderr}")
        return False

    def _windows_unblock(self, rule_name: str) -> bool:
        import subprocess
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0

    def _is_whitelisted(self, ip: str) -> bool:
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            for entry in self.whitelist:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip == entry:
                    return True
        except ValueError:
            pass
        return False


# ─── Alert Manager ───────────────────────────────────────────────────────────

class AlertManager:
    """
    Central hub for alert processing, enrichment, notification, and response.
    Designed to be called from the detection pipeline on a background thread.
    """

    def __init__(self) -> None:
        cfg = get_config()
        alert_cfg = cfg["alerting"]
        sev_thresh = alert_cfg["severity_thresholds"]

        self._db         = get_db()
        self._enricher   = ThreatIntelEnricher()
        self._email      = EmailNotifier(alert_cfg["email"])
        self._slack      = SlackNotifier(alert_cfg["slack"])
        self._firewall   = FirewallManager()

        self._sev_thresholds = {
            AlertSeverity.LOW:      sev_thresh["low"],
            AlertSeverity.MEDIUM:   sev_thresh["medium"],
            AlertSeverity.HIGH:     sev_thresh["high"],
            AlertSeverity.CRITICAL: sev_thresh["critical"],
        }

        # Notification dedup: alert id → sent timestamp
        self._notified: dict = {}
        self._lock = threading.Lock()

        logger.info("AlertManager initialised")

    def handle_alert(self, alert: Alert) -> Alert:
        """
        Full alert lifecycle: persist → enrich → notify → respond → audit.
        Thread-safe; can be called concurrently from worker threads.
        """
        with self._lock:
            # 1. Persist to database
            saved = self._db.create_alert(alert)

            # 2. Threat intelligence enrichment
            ti_summary: dict = {}
            if saved.source_ip:
                ti = self._enricher.enrich(saved.source_ip)
                if ti:
                    ti_summary = self._enricher.get_threat_summary(saved.source_ip)
                    # Update alert threat score from TI
                    saved.threat_score = float(ti.abuse_score or 0) / 100.0

            # 3. Send notifications
            if saved.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
                sent = self._notify(saved, ti_summary)
                saved.notification_sent = sent

            # 4. Automated response (IP blocking)
            if (
                saved.severity == AlertSeverity.CRITICAL
                and saved.source_ip
                and not self._db.is_ip_blocked(saved.source_ip)
            ):
                blocked = self._firewall.block_ip(
                    saved.source_ip,
                    f"Auto-block: {saved.pattern.value} detected"
                )
                if blocked:
                    self._db.block_ip(
                        ip         = saved.source_ip,
                        reason     = saved.description,
                        duration_minutes = get_config()["response"]["auto_block"]["block_duration_minutes"],
                        blocked_by = "bruteguard-autoresponse",
                    )

            # 5. Audit trail
            self._db.log_audit(
                actor       = "bruteguard-engine",
                action      = "alert_created",
                target_type = "alert",
                target_id   = str(saved.id),
                detail      = json.dumps({
                    "severity": saved.severity.value,
                    "pattern":  saved.pattern.value,
                    "ip":       saved.source_ip,
                    "user":     saved.username,
                }),
            )

            logger.info(
                f"Alert processed | id={saved.id} severity={saved.severity.value} "
                f"pattern={saved.pattern.value} ip={saved.source_ip}"
            )
            return saved

    def handle_batch(self, alerts: List[Alert]) -> List[Alert]:
        return [self.handle_alert(a) for a in alerts]

    def _notify(self, alert: Alert, ti_summary: dict) -> bool:
        """Send notifications; returns True if at least one succeeded."""
        if alert.id in self._notified:
            return False
        self._notified[alert.id] = datetime.utcnow()

        email_ok = self._email.send(alert, ti_summary)
        slack_ok = self._slack.send(alert, ti_summary)

        return email_ok or slack_ok
