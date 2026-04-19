"""
models.py — SQLAlchemy ORM models for BruteGuard SOC Platform.

Defines all database entities: LoginEvent, Alert, Incident,
ThreatIntelRecord, BlockedIP, and AuditLog.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey,
    Integer, String, Text, Index, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


# ─── Base ────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ─── Enumerations ────────────────────────────────────────────────────────────

class LoginResult(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKOUT = "lockout"


class AlertSeverity(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class AttackPattern(str, enum.Enum):
    BRUTE_FORCE         = "brute_force"
    PASSWORD_SPRAY      = "password_spray"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ANOMALY             = "anomaly"
    ML_DETECTED         = "ml_detected"
    ACCOUNT_LOCKOUT     = "account_lockout"


class IncidentStatus(str, enum.Enum):
    OPEN        = "open"
    INVESTIGATING = "investigating"
    RESOLVED    = "resolved"
    FALSE_POSITIVE = "false_positive"


# ─── Models ──────────────────────────────────────────────────────────────────

class LoginEvent(Base):
    """
    Parsed Windows Security Event Log entry.

    Stores both successful (4624) and failed (4625) login events
    with rich contextual metadata for correlation analysis.
    """
    __tablename__ = "login_events"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    event_id        = Column(Integer, nullable=False, index=True)          # Windows Event ID
    timestamp       = Column(DateTime, nullable=False, index=True)
    source_ip       = Column(String(45), nullable=True, index=True)        # IPv4/IPv6
    source_hostname = Column(String(255), nullable=True)
    username        = Column(String(255), nullable=False, index=True)
    domain          = Column(String(255), nullable=True)
    logon_type      = Column(Integer, nullable=True)                       # 2=interactive, 3=network, etc.
    result          = Column(Enum(LoginResult), nullable=False, index=True)
    workstation     = Column(String(255), nullable=True)
    process_name    = Column(String(512), nullable=True)
    auth_package    = Column(String(128), nullable=True)                   # NTLM, Kerberos, etc.
    failure_reason  = Column(String(255), nullable=True)
    raw_xml         = Column(Text, nullable=True)                          # Original event XML
    ingested_at     = Column(DateTime, default=datetime.utcnow)
    host_source     = Column(String(255), default="local")                 # which collector gathered this

    # Relationships
    alerts          = relationship("Alert", back_populates="trigger_event", lazy="dynamic")

    __table_args__ = (
        Index("ix_login_events_ip_time",    "source_ip",  "timestamp"),
        Index("ix_login_events_user_time",  "username",   "timestamp"),
        Index("ix_login_events_result_time","result",     "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<LoginEvent id={self.id} event_id={self.event_id} "
            f"user='{self.username}' ip='{self.source_ip}' result={self.result} "
            f"ts={self.timestamp}>"
        )

    @property
    def is_failure(self) -> bool:
        return self.result == LoginResult.FAILURE

    @property
    def is_success(self) -> bool:
        return self.result == LoginResult.SUCCESS


class Alert(Base):
    """
    Generated detection alert tied to a triggering event or aggregate pattern.
    """
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    created_at      = Column(DateTime, default=datetime.utcnow, index=True)
    severity        = Column(Enum(AlertSeverity), nullable=False, index=True)
    pattern         = Column(Enum(AttackPattern), nullable=False, index=True)
    source_ip       = Column(String(45), nullable=True, index=True)
    username        = Column(String(255), nullable=True, index=True)
    attempt_count   = Column(Integer, nullable=True)
    time_window_sec = Column(Integer, nullable=True)
    description     = Column(Text, nullable=False)
    rule_name       = Column(String(255), nullable=True)                   # Which rule triggered
    threat_score    = Column(Float, nullable=True)                         # From TI enrichment
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    notification_sent = Column(Boolean, default=False)

    trigger_event_id = Column(Integer, ForeignKey("login_events.id"), nullable=True)
    trigger_event    = relationship("LoginEvent", back_populates="alerts")
    incident_id      = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    incident         = relationship("Incident", back_populates="alerts")

    threat_intel     = relationship("ThreatIntelRecord",
                                    primaryjoin="Alert.source_ip == foreign(ThreatIntelRecord.ip_address)",
                                    uselist=False, viewonly=True)

    __table_args__ = (
        Index("ix_alerts_severity_created", "severity", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} severity={self.severity} "
            f"pattern={self.pattern} ip='{self.source_ip}'>"
        )


class Incident(Base):
    """
    Aggregated security incident grouping one or more related alerts.
    Represents a complete attack campaign for case management.
    """
    __tablename__ = "incidents"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    created_at      = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    title           = Column(String(512), nullable=False)
    description     = Column(Text, nullable=True)
    severity        = Column(Enum(AlertSeverity), nullable=False)
    status          = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, index=True)
    primary_ip      = Column(String(45), nullable=True)
    affected_users  = Column(Text, nullable=True)                          # JSON list
    alert_count     = Column(Integer, default=0)
    assigned_to     = Column(String(128), nullable=True)
    resolved_at     = Column(DateTime, nullable=True)
    resolution_note = Column(Text, nullable=True)

    alerts          = relationship("Alert", back_populates="incident", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Incident id={self.id} status={self.status} severity={self.severity}>"


class ThreatIntelRecord(Base):
    """
    Cached threat intelligence data for IP addresses.
    Reduces redundant API calls and enables offline correlation.
    """
    __tablename__ = "threat_intel"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    ip_address      = Column(String(45), nullable=False, unique=True, index=True)
    queried_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=True)
    abuse_score     = Column(Integer, nullable=True)                       # 0-100 AbuseIPDB score
    is_known_bad    = Column(Boolean, default=False)
    isp             = Column(String(255), nullable=True)
    org             = Column(String(255), nullable=True)
    country_code    = Column(String(4), nullable=True)
    country_name    = Column(String(128), nullable=True)
    city            = Column(String(128), nullable=True)
    region          = Column(String(128), nullable=True)
    latitude        = Column(Float, nullable=True)
    longitude       = Column(Float, nullable=True)
    asn             = Column(String(64), nullable=True)
    tor_exit_node   = Column(Boolean, default=False)
    vpn_detected    = Column(Boolean, default=False)
    raw_response    = Column(Text, nullable=True)                          # Full JSON from API

    def __repr__(self) -> str:
        return (
            f"<ThreatIntel ip='{self.ip_address}' "
            f"score={self.abuse_score} country='{self.country_code}'>"
        )

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return True
        return datetime.utcnow() > self.expires_at


class BlockedIP(Base):
    """
    Registry of IPs blocked via automated or manual response actions.
    """
    __tablename__ = "blocked_ips"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    ip_address      = Column(String(45), nullable=False, index=True)
    blocked_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=True)
    reason          = Column(String(512), nullable=False)
    blocked_by      = Column(String(128), default="system")               # system | admin username
    is_active       = Column(Boolean, default=True, index=True)
    firewall_rule_id = Column(String(255), nullable=True)                 # OS-level rule reference
    incident_id     = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("ip_address", "is_active", name="uq_blocked_ip_active"),
    )

    def __repr__(self) -> str:
        return f"<BlockedIP ip='{self.ip_address}' active={self.is_active}>"


class AuditLog(Base):
    """
    Immutable audit trail for all system and analyst actions.
    Forensic-grade record for compliance and investigation.
    """
    __tablename__ = "audit_logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    actor       = Column(String(128), nullable=False)                      # system | username
    action      = Column(String(255), nullable=False)
    target_type = Column(String(64), nullable=True)                        # ip, user, alert, incident
    target_id   = Column(String(255), nullable=True)
    detail      = Column(Text, nullable=True)
    ip_address  = Column(String(45), nullable=True)
    success     = Column(Boolean, default=True)

    __table_args__ = (
        Index("ix_audit_actor_time", "actor", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog actor='{self.actor}' action='{self.action}' ts={self.timestamp}>"


class DetectionRule(Base):
    """
    Configurable detection rules stored in database for runtime modification.
    """
    __tablename__ = "detection_rules"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    name            = Column(String(255), nullable=False, unique=True)
    description     = Column(Text, nullable=True)
    pattern         = Column(Enum(AttackPattern), nullable=False)
    is_enabled      = Column(Boolean, default=True)
    threshold       = Column(Integer, nullable=True)
    time_window_sec = Column(Integer, nullable=True)
    severity        = Column(Enum(AlertSeverity), nullable=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by      = Column(String(128), nullable=True)

    def __repr__(self) -> str:
        return f"<DetectionRule name='{self.name}' enabled={self.is_enabled}>"
