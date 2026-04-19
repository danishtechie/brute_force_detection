"""
report_generator.py — Automated incident report generation.

Produces:
  - PDF executive summary with charts embedded (via ReportLab + Plotly)
  - CSV raw data export for SIEM ingestion
  - JSON structured incident log for API consumers
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from loguru import logger

from src.database.db_manager import get_db
from src.utils.config_loader import get_config


class ReportGenerator:
    """Generates incident reports in PDF, CSV, and JSON formats."""

    def __init__(self) -> None:
        cfg = get_config()["reporting"]
        self.output_dir = Path(cfg["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, hours: int = 24, fmt: str = "pdf") -> str:
        """Generate a report for the last N hours. Returns file path."""
        since = datetime.utcnow() - timedelta(hours=hours)
        db    = get_db()

        summary = db.get_dashboard_summary(window_hours=hours)
        alerts  = db.get_recent_alerts(limit=1000)
        top_ips = db.get_top_attacking_ips(since, limit=20)
        ts_data = db.get_events_timeseries(since, bucket_minutes=30)

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"bruteguard_report_{ts}.{fmt}"
        filepath = self.output_dir / filename

        if fmt == "pdf":
            self._generate_pdf(filepath, summary, alerts, top_ips, ts_data, hours)
        elif fmt == "csv":
            self._generate_csv(filepath, alerts)
        elif fmt == "json":
            self._generate_json(filepath, summary, alerts, top_ips)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        logger.success(f"Report generated: {filepath}")
        return str(filepath)

    def _generate_pdf(self, path, summary, alerts, top_ips, ts_data, hours) -> None:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, HRFlowable,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.error("reportlab not installed; falling back to JSON")
            self._generate_json(path.with_suffix(".json"), summary, alerts, top_ips)
            return

        doc   = SimpleDocTemplate(str(path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # ── Custom styles ─────────────────────────────────────────────
        title_style = ParagraphStyle(
            "BruteGuardTitle",
            parent=styles["Title"],
            fontSize=22,
            spaceAfter=6,
            textColor=colors.HexColor("#0d1117"),
        )
        header_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=13,
            textColor=colors.HexColor("#21262d"),
            spaceAfter=4,
        )
        body_style = styles["BodyText"]

        # ── Cover ─────────────────────────────────────────────────────
        story.append(Paragraph("🛡️ BruteGuard SOC Platform", title_style))
        story.append(Paragraph("Incident Report", styles["Heading1"]))
        story.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Coverage: Last {hours} hours",
            body_style,
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363d")))
        story.append(Spacer(1, 0.2 * inch))

        # ── Executive Summary ─────────────────────────────────────────
        story.append(Paragraph("Executive Summary", header_style))
        kpi_data = [
            ["Metric",              "Value"],
            ["Total Login Events",  f"{summary['total_events']:,}"],
            ["Failed Logins",       f"{summary['total_failures']:,}"],
            ["Unique Attack IPs",   f"{summary['unique_attack_ips']:,}"],
            ["Open Alerts",         f"{summary['open_alerts']:,}"],
            ["Critical Alerts",     f"{summary['critical_alerts']:,}"],
            ["Blocked IPs",         f"{summary['blocked_ips']:,}"],
        ]
        kpi_table = Table(kpi_data, colWidths=[3 * inch, 2 * inch])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#21262d")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f6f8fa"), colors.white]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 0.3 * inch))

        # ── Top Attacking IPs ─────────────────────────────────────────
        story.append(Paragraph("Top Attacking IP Addresses", header_style))
        ip_data = [["Rank", "IP Address", "Failed Attempts"]]
        for i, (ip, count) in enumerate(top_ips[:10], 1):
            ip_data.append([str(i), ip, f"{count:,}"])

        ip_table = Table(ip_data, colWidths=[0.8 * inch, 3 * inch, 2 * inch])
        ip_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#da3633")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#fff0f0"), colors.white]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 0.3 * inch))

        # ── Recent Critical Alerts ────────────────────────────────────
        story.append(Paragraph("Recent High/Critical Alerts", header_style))
        critical = [a for a in alerts if a.severity.value in ("high", "critical")][:10]
        if critical:
            alert_data = [["Time (UTC)", "Severity", "Pattern", "Source IP", "Target User"]]
            for a in critical:
                alert_data.append([
                    a.created_at.strftime("%m-%d %H:%M") if a.created_at else "",
                    a.severity.value.upper(),
                    a.pattern.value.replace("_", " ").title(),
                    a.source_ip or "N/A",
                    (a.username or "Multiple")[:20],
                ])
            al_table = Table(
                alert_data,
                colWidths=[1.2 * inch, 0.9 * inch, 1.5 * inch, 1.4 * inch, 1.5 * inch],
            )
            al_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#9a3412")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#fef3c7"), colors.white]),
                ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#d0d7de")),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ]))
            story.append(al_table)
        else:
            story.append(Paragraph("No high/critical alerts in this period.", body_style))

        # ── Footer ────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
        story.append(Paragraph(
            "BruteGuard SOC Platform v2.1 — CONFIDENTIAL — For internal security use only.",
            ParagraphStyle("Footer", parent=styles["Normal"],
                           fontSize=8, textColor=colors.HexColor("#57606a")),
        ))

        doc.build(story)

    def _generate_csv(self, path, alerts) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "created_at", "severity", "pattern",
                "source_ip", "username", "attempt_count",
                "time_window_sec", "threat_score", "rule_name",
                "description", "acknowledged",
            ])
            for a in alerts:
                writer.writerow([
                    a.id, a.created_at, a.severity.value, a.pattern.value,
                    a.source_ip, a.username, a.attempt_count, a.time_window_sec,
                    a.threat_score, a.rule_name, a.description, a.is_acknowledged,
                ])

    def _generate_json(self, path, summary, alerts, top_ips) -> None:
        payload = {
            "generated_at":  datetime.utcnow().isoformat(),
            "summary":       summary,
            "top_attack_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "alerts": [
                {
                    "id":          a.id,
                    "created_at":  a.created_at.isoformat() if a.created_at else None,
                    "severity":    a.severity.value,
                    "pattern":     a.pattern.value,
                    "source_ip":   a.source_ip,
                    "username":    a.username,
                    "description": a.description,
                }
                for a in alerts
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
