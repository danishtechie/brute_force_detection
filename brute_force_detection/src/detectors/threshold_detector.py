"""
threshold_detector.py — Rule-based brute force and spray detection engine.

Implements three detection strategies:
  1. IP Threshold    : N failures from same IP in T seconds → brute force
  2. User Threshold  : N failures against same account → credential attack
  3. Spray Detection : Single IP targeting M+ distinct users → password spray
  4. Stuffing Detect : Rapid burst from multiple IPs → credential stuffing
  5. Lockout Detect  : Account lockout events (4740) → confirmed compromise attempt

All detections return Alert ORM objects ready for persistence.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger

from src.database.models import Alert, AlertSeverity, AttackPattern, LoginEvent, LoginResult
from src.utils.config_loader import get_config


# ─── In-memory sliding windows ───────────────────────────────────────────────

class SlidingWindow:
    """
    Lightweight fixed-duration sliding window counter.
    Stores (timestamp, value) tuples and evicts expired entries on read.
    """

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._buckets: List[Tuple[datetime, str]] = []

    def add(self, timestamp: datetime, value: str) -> None:
        self._buckets.append((timestamp, value))

    def count(self, now: Optional[datetime] = None) -> int:
        self._evict(now)
        return len(self._buckets)

    def distinct_values(self, now: Optional[datetime] = None) -> Set[str]:
        self._evict(now)
        return {v for _, v in self._buckets}

    def _evict(self, now: Optional[datetime] = None) -> None:
        cutoff = (now or datetime.utcnow()) - timedelta(seconds=self.window_seconds)
        self._buckets = [(ts, v) for ts, v in self._buckets if ts >= cutoff]

    def __len__(self) -> int:
        return self.count()


# ─── Detector ────────────────────────────────────────────────────────────────

class ThresholdDetector:
    """
    Stateful threshold-based detector using in-memory sliding windows.
    Designed to run on a single background thread; not multi-process safe.

    For high-volume deployments, replace in-memory windows with Redis.
    """

    def __init__(self) -> None:
        cfg = get_config()["detection"]
        thresh = cfg["threshold"]
        spray  = cfg["spray"]
        stuff  = cfg["stuffing"]

        # Thresholds
        self._ip_fail_threshold    = thresh["failed_attempts_per_ip"]
        self._user_fail_threshold  = thresh["failed_attempts_per_user"]
        self._ip_window            = thresh["time_window_seconds"]
        self._spray_user_threshold = spray["unique_users_per_ip"]
        self._spray_window         = spray["time_window_seconds"]
        self._stuffing_threshold   = stuff["min_attempts"]
        self._stuffing_window      = stuff["time_window_seconds"]

        # State: keyed by IP or username
        self._ip_failures:   Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self._ip_window)
        )
        self._user_failures: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self._ip_window)
        )
        self._spray_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self._spray_window)
        )
        # Stuffing: global rapid-burst window across all IPs
        self._stuffing_window_obj = SlidingWindow(self._stuffing_window)

        # De-duplicate alerts: set of (pattern, key) → last alert time
        self._alert_cooldowns: Dict[Tuple[str, str], datetime] = {}
        self._cooldown_seconds = 120  # Re-alert same key after 2 minutes

        logger.info(
            f"ThresholdDetector ready | "
            f"ip_thresh={self._ip_fail_threshold}/{self._ip_window}s | "
            f"user_thresh={self._user_fail_threshold} | "
            f"spray={self._spray_user_threshold} users"
        )

    # ─── Public API ──────────────────────────────────────────────────────────

    def process_event(self, event: LoginEvent) -> List[Alert]:
        """
        Process a single login event and return any triggered alerts.
        Call this for every event flowing through the pipeline.
        """
        alerts: List[Alert] = []
        now = event.timestamp or datetime.utcnow()

        if event.result == LoginResult.FAILURE:
            alerts.extend(self._check_ip_brute_force(event, now))
            alerts.extend(self._check_user_brute_force(event, now))
            alerts.extend(self._check_password_spray(event, now))
            alerts.extend(self._check_credential_stuffing(event, now))

        if event.result == LoginResult.LOCKOUT:
            alerts.extend(self._check_account_lockout(event, now))

        return alerts

    def process_batch(self, events: List[LoginEvent]) -> List[Alert]:
        """Process a list of events and return all triggered alerts."""
        all_alerts: List[Alert] = []
        for event in sorted(events, key=lambda e: e.timestamp or datetime.utcnow()):
            all_alerts.extend(self.process_event(event))
        return all_alerts

    # ─── Detection strategies ────────────────────────────────────────────────

    def _check_ip_brute_force(self, event: LoginEvent, now: datetime) -> List[Alert]:
        if not event.source_ip:
            return []

        window = self._ip_failures[event.source_ip]
        window.add(now, event.username or "")
        count = window.count(now)

        if count < self._ip_fail_threshold:
            return []

        key = ("brute_force", event.source_ip)
        if self._in_cooldown(key, now):
            return []
        self._set_cooldown(key, now)

        severity = self._calculate_severity(count, self._ip_fail_threshold)
        logger.warning(
            f"[BRUTE FORCE] IP={event.source_ip} | "
            f"failures={count}/{self._ip_window}s | severity={severity}"
        )
        return [Alert(
            severity        = severity,
            pattern         = AttackPattern.BRUTE_FORCE,
            source_ip       = event.source_ip,
            username        = event.username,
            attempt_count   = count,
            time_window_sec = self._ip_window,
            description     = (
                f"Brute force detected from {event.source_ip}: "
                f"{count} failed login attempts in {self._ip_window}s "
                f"targeting '{event.username}' (and potentially others)"
            ),
            rule_name       = "IP_BRUTE_FORCE_THRESHOLD",
            trigger_event   = event,
        )]

    def _check_user_brute_force(self, event: LoginEvent, now: datetime) -> List[Alert]:
        if not event.username or event.username in ("UNKNOWN", "-", ""):
            return []

        window = self._user_failures[event.username]
        window.add(now, event.source_ip or "")
        count = window.count(now)

        if count < self._user_fail_threshold:
            return []

        key = ("user_brute_force", event.username)
        if self._in_cooldown(key, now):
            return []
        self._set_cooldown(key, now)

        distinct_ips = window.distinct_values(now)
        severity = AlertSeverity.HIGH if len(distinct_ips) > 3 else AlertSeverity.MEDIUM

        logger.warning(
            f"[USER BRUTE FORCE] user={event.username} | "
            f"failures={count} from {len(distinct_ips)} IPs"
        )
        return [Alert(
            severity        = severity,
            pattern         = AttackPattern.BRUTE_FORCE,
            source_ip       = event.source_ip,
            username        = event.username,
            attempt_count   = count,
            time_window_sec = self._ip_window,
            description     = (
                f"Account under attack: '{event.username}' received {count} "
                f"failed logins from {len(distinct_ips)} distinct IP(s) in {self._ip_window}s"
            ),
            rule_name       = "USER_BRUTE_FORCE_THRESHOLD",
            trigger_event   = event,
        )]

    def _check_password_spray(self, event: LoginEvent, now: datetime) -> List[Alert]:
        if not event.source_ip:
            return []

        window = self._spray_windows[event.source_ip]
        window.add(now, event.username or "")
        distinct_users = window.distinct_values(now)

        if len(distinct_users) < self._spray_user_threshold:
            return []

        key = ("password_spray", event.source_ip)
        if self._in_cooldown(key, now):
            return []
        self._set_cooldown(key, now)

        logger.warning(
            f"[PASSWORD SPRAY] IP={event.source_ip} | "
            f"targeted {len(distinct_users)} users in {self._spray_window}s"
        )
        return [Alert(
            severity        = AlertSeverity.HIGH,
            pattern         = AttackPattern.PASSWORD_SPRAY,
            source_ip       = event.source_ip,
            username        = None,
            attempt_count   = window.count(now),
            time_window_sec = self._spray_window,
            description     = (
                f"Password spray from {event.source_ip}: "
                f"{len(distinct_users)} unique usernames targeted in {self._spray_window}s. "
                f"Accounts: {', '.join(list(distinct_users)[:8])}{'…' if len(distinct_users) > 8 else ''}"
            ),
            rule_name       = "PASSWORD_SPRAY_DETECTION",
            trigger_event   = event,
        )]

    def _check_credential_stuffing(self, event: LoginEvent, now: datetime) -> List[Alert]:
        """Detect rapid-fire failures across many IPs and users."""
        self._stuffing_window_obj.add(now, f"{event.source_ip}:{event.username}")
        count = self._stuffing_window_obj.count(now)

        if count < self._stuffing_threshold:
            return []

        key = ("credential_stuffing", "global")
        if self._in_cooldown(key, now):
            return []
        self._set_cooldown(key, now)

        logger.warning(
            f"[CREDENTIAL STUFFING] global burst: {count} failures in {self._stuffing_window}s"
        )
        return [Alert(
            severity        = AlertSeverity.CRITICAL,
            pattern         = AttackPattern.CREDENTIAL_STUFFING,
            source_ip       = event.source_ip,
            username        = event.username,
            attempt_count   = count,
            time_window_sec = self._stuffing_window,
            description     = (
                f"Credential stuffing campaign detected: {count} failures across "
                f"multiple IPs and usernames in {self._stuffing_window}s — "
                f"latest from {event.source_ip}"
            ),
            rule_name       = "CREDENTIAL_STUFFING_BURST",
            trigger_event   = event,
        )]

    def _check_account_lockout(self, event: LoginEvent, now: datetime) -> List[Alert]:
        logger.warning(f"[LOCKOUT] Account locked: user={event.username} ip={event.source_ip}")
        return [Alert(
            severity        = AlertSeverity.HIGH,
            pattern         = AttackPattern.ACCOUNT_LOCKOUT,
            source_ip       = event.source_ip,
            username        = event.username,
            attempt_count   = 1,
            time_window_sec = 0,
            description     = (
                f"Account lockout triggered for '{event.username}' "
                f"from {event.source_ip or 'unknown source'} "
                f"(Event ID 4740)"
            ),
            rule_name       = "ACCOUNT_LOCKOUT_4740",
            trigger_event   = event,
        )]

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _calculate_severity(self, count: int, threshold: int) -> AlertSeverity:
        ratio = count / threshold
        if ratio >= 6:
            return AlertSeverity.CRITICAL
        if ratio >= 3:
            return AlertSeverity.HIGH
        if ratio >= 1.5:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _in_cooldown(self, key: Tuple[str, str], now: datetime) -> bool:
        last = self._alert_cooldowns.get(key)
        if last is None:
            return False
        return (now - last).total_seconds() < self._cooldown_seconds

    def _set_cooldown(self, key: Tuple[str, str], now: datetime) -> None:
        self._alert_cooldowns[key] = now

    def reset_state(self) -> None:
        """Clear all in-memory windows (useful for testing)."""
        self._ip_failures.clear()
        self._user_failures.clear()
        self._spray_windows.clear()
        self._stuffing_window_obj = SlidingWindow(self._stuffing_window)
        self._alert_cooldowns.clear()
        logger.debug("ThresholdDetector state reset")
