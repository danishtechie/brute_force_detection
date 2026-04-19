"""
ml_detector.py — Machine Learning anomaly detector using Isolation Forest.

Features engineered from login event time-series:
  - Rolling failure rate per IP
  - Entropy of targeted usernames (spray indicator)
  - Inter-arrival time statistics (timing anomaly)
  - Hour-of-day distribution deviation

The model is trained/retrained on historical event data and serialised
to disk via joblib. In inference mode it flags events with anomaly scores
below the contamination threshold as potential attacks.
"""

from __future__ import annotations

import math
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from loguru import logger
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.database.models import Alert, AlertSeverity, AttackPattern, LoginEvent, LoginResult
from src.utils.config_loader import get_config


# ─── Feature Engineering ─────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Maintains rolling state to extract temporal features from event streams.
    Uses a fixed-size deque per IP to compute rolling statistics efficiently.
    """

    WINDOW = 300          # 5-minute rolling window in seconds
    MAX_EVENTS = 200      # Max events to keep in memory per IP

    def __init__(self) -> None:
        # ip → deque of (timestamp, username)
        self._ip_events: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.MAX_EVENTS)
        )
        # Baseline hour-of-day failure rates (updated during training)
        self._hour_baseline: Dict[int, float] = {h: 1.0 for h in range(24)}

    def update(self, event: LoginEvent) -> None:
        if event.source_ip and event.result == LoginResult.FAILURE:
            self._ip_events[event.source_ip].append(
                (event.timestamp or datetime.utcnow(), event.username or "")
            )

    def extract(self, event: LoginEvent) -> Optional[np.ndarray]:
        """
        Extract a feature vector for a given (failed) login event.
        Returns None if insufficient history exists for the IP.
        """
        ip = event.source_ip
        ts = event.timestamp or datetime.utcnow()

        if not ip:
            return None

        window = self._get_window_events(ip, ts)
        if len(window) < 3:
            return None  # Too little history

        timestamps = [t for t, _ in window]
        usernames  = [u for _, u in window]

        # Feature 1: Failure count in window
        fail_count = len(window)

        # Feature 2: Failure rate (per minute)
        duration = max((ts - timestamps[0]).total_seconds(), 1.0)
        fail_rate = fail_count / (duration / 60.0)

        # Feature 3: Username entropy (spray indicator; high = spray)
        username_entropy = self._entropy(usernames)

        # Feature 4: Mean inter-arrival time (low = rapid-fire)
        if len(timestamps) > 1:
            deltas = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            mean_iat = np.mean(deltas)
            std_iat  = np.std(deltas)
        else:
            mean_iat = self.WINDOW
            std_iat  = 0.0

        # Feature 5: Unique username count
        unique_users = len(set(usernames))

        # Feature 6: Hour-of-day deviation from baseline
        hour = ts.hour
        baseline = self._hour_baseline.get(hour, 1.0)
        hour_deviation = fail_rate / max(baseline, 0.1)

        # Feature 7: Burstiness (coefficient of variation of IAT)
        burstiness = std_iat / max(mean_iat, 0.001)

        return np.array([
            fail_count,
            fail_rate,
            username_entropy,
            mean_iat,
            std_iat,
            unique_users,
            hour_deviation,
            burstiness,
        ], dtype=np.float32)

    def _get_window_events(self, ip: str, now: datetime) -> List[Tuple[datetime, str]]:
        cutoff = now - timedelta(seconds=self.WINDOW)
        return [(ts, u) for ts, u in self._ip_events[ip] if ts >= cutoff]

    @staticmethod
    def _entropy(values: List[str]) -> float:
        if not values:
            return 0.0
        total = len(values)
        counts = defaultdict(int)
        for v in values:
            counts[v] += 1
        return -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
            if c > 0
        )

    def set_hour_baseline(self, baseline: Dict[int, float]) -> None:
        self._hour_baseline = baseline


# ─── ML Model ────────────────────────────────────────────────────────────────

class MLDetector:
    """
    Isolation Forest-based anomaly detector for brute-force patterns.

    Training: Fit on historical event data (mix of normal + attack).
    Inference: Score each new failed-login feature vector; scores below
               threshold are flagged as anomalies.
    """

    FEATURE_NAMES = [
        "fail_count", "fail_rate_per_min", "username_entropy",
        "mean_iat_sec", "std_iat_sec", "unique_users",
        "hour_deviation", "burstiness",
    ]

    def __init__(self) -> None:
        cfg = get_config()
        ml_cfg = cfg["detection"]["ml"]
        self.model_path     = ml_cfg["model_path"]
        self.contamination  = ml_cfg["contamination"]
        self.enabled        = ml_cfg["enabled"]
        self._extractor     = FeatureExtractor()
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._is_trained    = False

        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)

        if self.enabled:
            self._try_load_model()

    def _try_load_model(self) -> None:
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self._model   = bundle["model"]
                self._scaler  = bundle["scaler"]
                self._extractor.set_hour_baseline(bundle.get("hour_baseline", {}))
                self._is_trained = True
                logger.info(f"ML model loaded from {self.model_path}")
            except Exception as exc:
                logger.warning(f"Failed to load ML model: {exc} — will train from scratch")

    def train(self, events: List[LoginEvent]) -> Dict[str, Any]:
        """
        Train the Isolation Forest on a list of historical events.
        Extracts features for all failed-login events and fits the model.

        Returns training metrics.
        """
        logger.info(f"Training ML detector on {len(events)} events…")

        # Feed all events to extractor to build history
        sorted_events = sorted(events, key=lambda e: e.timestamp or datetime.utcnow())
        feature_rows: List[np.ndarray] = []

        for event in sorted_events:
            self._extractor.update(event)
            if event.result == LoginResult.FAILURE:
                fv = self._extractor.extract(event)
                if fv is not None:
                    feature_rows.append(fv)

        if len(feature_rows) < 50:
            logger.warning("Insufficient data for ML training (need ≥50 feature rows)")
            return {"status": "skipped", "reason": "insufficient_data"}

        X = np.vstack(feature_rows)

        # Compute hour baseline from training data
        hour_rates: Dict[int, List[float]] = defaultdict(list)
        for ev in sorted_events:
            if ev.result == LoginResult.FAILURE and ev.timestamp:
                hour_rates[ev.timestamp.hour].append(1.0)
        hour_baseline = {
            h: np.mean(rates) for h, rates in hour_rates.items()
        }
        self._extractor.set_hour_baseline(hour_baseline)

        # Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Fit Isolation Forest
        self._model = IsolationForest(
            n_estimators    = 200,
            contamination   = self.contamination,
            max_samples     = "auto",
            random_state    = 42,
            n_jobs          = -1,
        )
        self._model.fit(X_scaled)
        self._is_trained = True

        # Save model bundle
        joblib.dump(
            {
                "model":         self._model,
                "scaler":        self._scaler,
                "hour_baseline": hour_baseline,
                "feature_names": self.FEATURE_NAMES,
                "trained_at":    datetime.utcnow().isoformat(),
                "n_samples":     len(X),
            },
            self.model_path,
        )

        # Evaluate on training set (for logging; not a proper hold-out)
        preds = self._model.predict(X_scaled)
        anomaly_count = int(np.sum(preds == -1))
        anomaly_rate  = anomaly_count / len(preds)

        logger.success(
            f"ML model trained | samples={len(X)} | "
            f"anomalies_detected={anomaly_count} ({anomaly_rate:.1%}) | "
            f"saved → {self.model_path}"
        )
        return {
            "status":         "trained",
            "samples":        len(X),
            "anomaly_count":  anomaly_count,
            "anomaly_rate":   anomaly_rate,
            "model_path":     self.model_path,
        }

    def process_event(self, event: LoginEvent) -> List[Alert]:
        """Score an event and return an Alert if it is anomalous."""
        if not self.enabled or not self._is_trained:
            return []
        if event.result != LoginResult.FAILURE:
            return []

        self._extractor.update(event)
        fv = self._extractor.extract(event)
        if fv is None:
            return []

        try:
            X_scaled = self._scaler.transform(fv.reshape(1, -1))
            pred     = self._model.predict(X_scaled)[0]       # 1 = normal, -1 = anomaly
            score    = self._model.score_samples(X_scaled)[0]  # Lower = more anomalous
        except Exception as exc:
            logger.debug(f"ML scoring error: {exc}")
            return []

        if pred == 1:
            return []

        # Anomaly detected
        anomaly_strength = abs(score)
        severity = (
            AlertSeverity.CRITICAL if anomaly_strength > 0.15
            else AlertSeverity.HIGH if anomaly_strength > 0.10
            else AlertSeverity.MEDIUM
        )

        feature_summary = ", ".join(
            f"{n}={v:.2f}"
            for n, v in zip(self.FEATURE_NAMES, fv)
        )

        logger.warning(
            f"[ML ANOMALY] IP={event.source_ip} score={score:.4f} "
            f"features=[{feature_summary}]"
        )
        return [Alert(
            severity        = severity,
            pattern         = AttackPattern.ML_DETECTED,
            source_ip       = event.source_ip,
            username        = event.username,
            attempt_count   = int(fv[0]),
            time_window_sec = FeatureExtractor.WINDOW,
            description     = (
                f"ML anomaly detected (Isolation Forest score={score:.4f}) "
                f"from {event.source_ip}. "
                f"Features: fail_rate={fv[1]:.1f}/min, "
                f"unique_users={int(fv[5])}, entropy={fv[2]:.2f}"
            ),
            rule_name       = "ISOLATION_FOREST_ANOMALY",
            trigger_event   = event,
        )]

    def process_batch(self, events: List[LoginEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for ev in sorted(events, key=lambda e: e.timestamp or datetime.utcnow()):
            alerts.extend(self.process_event(ev))
        return alerts

    @property
    def is_ready(self) -> bool:
        return self._is_trained and self.enabled
