"""
db_manager.py — Database session management and query layer for BruteGuard.

Provides a thread-safe session factory, connection health checks,
and high-level query helpers used across the detection pipeline.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Generator, List, Optional, Tuple

from loguru import logger
from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool

from src.database.models import (
    Alert, AlertSeverity, AttackPattern, AuditLog, Base,
    BlockedIP, DetectionRule, Incident, IncidentStatus,
    LoginEvent, LoginResult, ThreatIntelRecord,
)
from src.utils.config_loader import get_config


class DatabaseManager:
    """
    Singleton database manager providing session factory and
    optimised query helpers for the BruteGuard detection pipeline.
    """

    _instance: Optional[DatabaseManager] = None

    def __new__(cls) -> DatabaseManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialised = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialised:
            return
        cfg = get_config()
        db_cfg = cfg["database"]

        if db_cfg["type"] == "sqlite":
            db_url = f"sqlite:///{db_cfg['sqlite']['path']}"
            engine_kwargs = {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            }
        else:
            pg = db_cfg["postgresql"]
            db_url = (
                f"postgresql+psycopg2://{pg['user']}:{pg['password']}"
                f"@{pg['host']}:{pg['port']}/{pg['name']}"
            )
            engine_kwargs = {
                "poolclass": QueuePool,
                "pool_size": pg.get("pool_size", 10),
                "max_overflow": pg.get("max_overflow", 20),
                "pool_pre_ping": True,
            }

        self.engine = create_engine(db_url, echo=False, **engine_kwargs)
        self.SessionFactory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        self._initialised = True
        logger.info(f"DatabaseManager initialised [{db_cfg['type']}]")

    def create_tables(self) -> None:
        """Create all tables (idempotent)."""
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created/verified")

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Context manager yielding a transactional session."""
        db: Session = self.SessionFactory()
        try:
            yield db
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error(f"DB transaction rolled back: {exc}")
            raise
        finally:
            db.close()

    # ─── Event Ingestion ─────────────────────────────────────────────────────

    def bulk_insert_events(self, events: List[LoginEvent]) -> int:
        """Bulk-insert parsed login events; returns number inserted."""
        with self.session() as db:
            db.bulk_save_objects(events)
        logger.debug(f"Bulk inserted {len(events)} login events")
        return len(events)

    def insert_event(self, event: LoginEvent) -> LoginEvent:
        """Insert a single login event and return with generated id."""
        with self.session() as db:
            db.add(event)
            db.flush()
            db.refresh(event)
        return event

    # ─── Alert Management ────────────────────────────────────────────────────

    def create_alert(self, alert: Alert) -> Alert:
        with self.session() as db:
            db.add(alert)
            db.flush()
            db.refresh(alert)
        return alert

    def get_recent_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        acknowledged: Optional[bool] = None,
    ) -> List[Alert]:
        with self.session() as db:
            q = db.query(Alert).order_by(Alert.created_at.desc())
            if severity:
                q = q.filter(Alert.severity == severity)
            if acknowledged is not None:
                q = q.filter(Alert.is_acknowledged == acknowledged)
            return q.limit(limit).all()

    def acknowledge_alert(self, alert_id: int, analyst: str) -> bool:
        with self.session() as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return False
            alert.is_acknowledged = True
            alert.acknowledged_by = analyst
            alert.acknowledged_at = datetime.utcnow()
        return True

    # ─── Detection Queries ───────────────────────────────────────────────────

    def count_failures_by_ip(
        self, ip: str, since: datetime
    ) -> int:
        """Count failed login events from a given IP since timestamp."""
        with self.session() as db:
            return (
                db.query(func.count(LoginEvent.id))
                .filter(
                    LoginEvent.source_ip == ip,
                    LoginEvent.result == LoginResult.FAILURE,
                    LoginEvent.timestamp >= since,
                )
                .scalar()
            ) or 0

    def count_failures_by_user(
        self, username: str, since: datetime
    ) -> int:
        with self.session() as db:
            return (
                db.query(func.count(LoginEvent.id))
                .filter(
                    LoginEvent.username == username,
                    LoginEvent.result == LoginResult.FAILURE,
                    LoginEvent.timestamp >= since,
                )
                .scalar()
            ) or 0

    def get_unique_users_per_ip(
        self, ip: str, since: datetime
    ) -> List[str]:
        """Return distinct usernames targeted from an IP (spray detection)."""
        with self.session() as db:
            rows = (
                db.query(LoginEvent.username)
                .filter(
                    LoginEvent.source_ip == ip,
                    LoginEvent.result == LoginResult.FAILURE,
                    LoginEvent.timestamp >= since,
                )
                .distinct()
                .all()
            )
        return [r[0] for r in rows]

    def get_top_attacking_ips(
        self, since: datetime, limit: int = 10
    ) -> List[Tuple[str, int]]:
        """Return (ip, failure_count) ordered by failure count desc."""
        with self.session() as db:
            rows = (
                db.query(LoginEvent.source_ip, func.count(LoginEvent.id).label("cnt"))
                .filter(
                    LoginEvent.result == LoginResult.FAILURE,
                    LoginEvent.timestamp >= since,
                    LoginEvent.source_ip.isnot(None),
                )
                .group_by(LoginEvent.source_ip)
                .order_by(func.count(LoginEvent.id).desc())
                .limit(limit)
                .all()
            )
        return [(r[0], r[1]) for r in rows]

    def get_events_timeseries(
        self, since: datetime, bucket_minutes: int = 5
    ) -> List[dict]:
        """
        Return bucketed failure/success counts for time-series charts.
        Uses SQLite strftime or PostgreSQL date_trunc depending on engine.
        """
        with self.session() as db:
            is_sqlite = "sqlite" in str(self.engine.url)
            if is_sqlite:
                bucket_expr = func.strftime(
                    f"%Y-%m-%dT%H:%M",
                    func.datetime(LoginEvent.timestamp, f"-{bucket_minutes} minutes"),
                )
            else:
                # PostgreSQL
                bucket_expr = func.to_char(
                    func.date_trunc("minute",
                        func.date_trunc("minute", LoginEvent.timestamp)
                        - text(f"INTERVAL '{bucket_minutes - 1} minutes'")
                    ),
                    "YYYY-MM-DD\"T\"HH24:MI",
                )

            rows = (
                db.query(
                    bucket_expr.label("bucket"),
                    LoginEvent.result,
                    func.count(LoginEvent.id).label("cnt"),
                )
                .filter(LoginEvent.timestamp >= since)
                .group_by("bucket", LoginEvent.result)
                .order_by("bucket")
                .all()
            )

        result: dict = {}
        for bucket, res, cnt in rows:
            if bucket not in result:
                result[bucket] = {"timestamp": bucket, "failures": 0, "successes": 0}
            if res == LoginResult.FAILURE:
                result[bucket]["failures"] = cnt
            else:
                result[bucket]["successes"] = cnt

        return sorted(result.values(), key=lambda x: x["timestamp"])

    def get_geo_distribution(self, since: datetime) -> List[dict]:
        """Join events with threat intel to get geo data for map visualisation."""
        with self.session() as db:
            rows = (
                db.query(
                    ThreatIntelRecord.country_code,
                    ThreatIntelRecord.country_name,
                    ThreatIntelRecord.latitude,
                    ThreatIntelRecord.longitude,
                    func.count(LoginEvent.id).label("attack_count"),
                )
                .join(LoginEvent, LoginEvent.source_ip == ThreatIntelRecord.ip_address)
                .filter(
                    LoginEvent.result == LoginResult.FAILURE,
                    LoginEvent.timestamp >= since,
                    ThreatIntelRecord.latitude.isnot(None),
                )
                .group_by(
                    ThreatIntelRecord.country_code,
                    ThreatIntelRecord.country_name,
                    ThreatIntelRecord.latitude,
                    ThreatIntelRecord.longitude,
                )
                .all()
            )
        return [
            {
                "country_code":  r[0],
                "country_name":  r[1],
                "lat":           r[2],
                "lon":           r[3],
                "attack_count":  r[4],
            }
            for r in rows
        ]

    # ─── Threat Intelligence ─────────────────────────────────────────────────

    def upsert_threat_intel(self, record: ThreatIntelRecord) -> None:
        with self.session() as db:
            existing = (
                db.query(ThreatIntelRecord)
                .filter(ThreatIntelRecord.ip_address == record.ip_address)
                .first()
            )
            if existing:
                existing.queried_at  = record.queried_at
                existing.expires_at  = record.expires_at
                existing.abuse_score = record.abuse_score
                existing.is_known_bad = record.is_known_bad
                existing.isp          = record.isp
                existing.org          = record.org
                existing.country_code = record.country_code
                existing.country_name = record.country_name
                existing.city         = record.city
                existing.latitude     = record.latitude
                existing.longitude    = record.longitude
                existing.tor_exit_node = record.tor_exit_node
            else:
                db.add(record)

    def get_threat_intel(self, ip: str) -> Optional[ThreatIntelRecord]:
        with self.session() as db:
            return (
                db.query(ThreatIntelRecord)
                .filter(ThreatIntelRecord.ip_address == ip)
                .first()
            )

    # ─── Blocked IPs ─────────────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str, duration_minutes: int = 60,
                 blocked_by: str = "system", incident_id: Optional[int] = None) -> BlockedIP:
        expires = datetime.utcnow() + timedelta(minutes=duration_minutes)
        record = BlockedIP(
            ip_address=ip, reason=reason, expires_at=expires,
            blocked_by=blocked_by, incident_id=incident_id,
        )
        with self.session() as db:
            db.add(record)
            db.flush()
            db.refresh(record)
        return record

    def is_ip_blocked(self, ip: str) -> bool:
        with self.session() as db:
            return bool(
                db.query(BlockedIP)
                .filter(
                    BlockedIP.ip_address == ip,
                    BlockedIP.is_active == True,
                    BlockedIP.expires_at > datetime.utcnow(),
                )
                .first()
            )

    # ─── Audit Logging ───────────────────────────────────────────────────────

    def log_audit(
        self, actor: str, action: str, target_type: Optional[str] = None,
        target_id: Optional[str] = None, detail: Optional[str] = None,
        ip_address: Optional[str] = None, success: bool = True,
    ) -> None:
        entry = AuditLog(
            actor=actor, action=action, target_type=target_type,
            target_id=str(target_id) if target_id else None,
            detail=detail, ip_address=ip_address, success=success,
        )
        with self.session() as db:
            db.add(entry)

    # ─── Dashboard Stats ─────────────────────────────────────────────────────

    def get_dashboard_summary(self, window_hours: int = 24) -> dict:
        """Return high-level KPIs for the dashboard overview panel."""
        since = datetime.utcnow() - timedelta(hours=window_hours)
        with self.session() as db:
            total_events  = db.query(func.count(LoginEvent.id)).filter(LoginEvent.timestamp >= since).scalar() or 0
            total_failures = (
                db.query(func.count(LoginEvent.id))
                .filter(LoginEvent.result == LoginResult.FAILURE, LoginEvent.timestamp >= since)
                .scalar()
            ) or 0
            total_successes = total_events - total_failures
            unique_ips = (
                db.query(func.count(func.distinct(LoginEvent.source_ip)))
                .filter(LoginEvent.result == LoginResult.FAILURE, LoginEvent.timestamp >= since)
                .scalar()
            ) or 0
            open_alerts = (
                db.query(func.count(Alert.id))
                .filter(Alert.is_acknowledged == False, Alert.created_at >= since)
                .scalar()
            ) or 0
            critical_alerts = (
                db.query(func.count(Alert.id))
                .filter(Alert.severity == AlertSeverity.CRITICAL, Alert.created_at >= since)
                .scalar()
            ) or 0
            blocked_ips = (
                db.query(func.count(BlockedIP.id))
                .filter(BlockedIP.is_active == True)
                .scalar()
            ) or 0

        return {
            "total_events":     total_events,
            "total_failures":   total_failures,
            "total_successes":  total_successes,
            "unique_attack_ips": unique_ips,
            "open_alerts":      open_alerts,
            "critical_alerts":  critical_alerts,
            "blocked_ips":      blocked_ips,
            "window_hours":     window_hours,
        }


# ─── Module-level singleton accessor ─────────────────────────────────────────

_db: Optional[DatabaseManager] = None


def get_db() -> DatabaseManager:
    global _db
    if _db is None:
        _db = DatabaseManager()
    return _db
