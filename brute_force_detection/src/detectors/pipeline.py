"""
pipeline.py — Detection pipeline orchestrator.

Ties together the full ingestion → detection → enrichment → alerting chain.
Runs as a background daemon thread alongside the Flask/SocketIO web server.

Architecture:
  CollectorThread → event queue → DetectorWorker → alert queue → AlertWorker
"""

from __future__ import annotations

import queue
import threading
import time
from datetime import datetime
from typing import List, Optional

from loguru import logger

from src.collectors.windows_log_collector import build_collector
from src.database.db_manager import get_db
from src.database.models import Alert, LoginEvent
from src.detectors.ml_detector import MLDetector
from src.detectors.threshold_detector import ThresholdDetector
from src.response.alert_manager import AlertManager
from src.utils.config_loader import get_config


class DetectionPipeline:
    """
    Multi-threaded detection pipeline.

    Thread layout:
      1. CollectorThread  — fetches events from Windows/EVTX/Simulator
      2. DetectorThread   — runs threshold + ML detection on batches
      3. AlertWorkerThread— persists, enriches, and notifies on alerts

    Queues provide back-pressure and decouple stages for throughput.
    """

    def __init__(self, socketio=None) -> None:
        self._socketio       = socketio
        self._cfg            = get_config()
        self._db             = get_db()
        self._collector      = build_collector()
        self._threshold_det  = ThresholdDetector()
        self._ml_det         = MLDetector()
        self._alert_mgr      = AlertManager()

        self._event_queue: queue.Queue[List[LoginEvent]] = queue.Queue(maxsize=500)
        self._alert_queue: queue.Queue[List[Alert]]      = queue.Queue(maxsize=200)

        self._running        = False
        self._threads: List[threading.Thread] = []

        self._stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "started_at":       None,
        }

        logger.info("DetectionPipeline initialised")

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start all pipeline threads."""
        if self._running:
            logger.warning("Pipeline already running")
            return

        self._running = True
        self._stats["started_at"] = datetime.utcnow()

        # Optionally train ML model on historical data first
        self._maybe_train_ml()

        threads_config = [
            ("CollectorThread",   self._collector_loop,    True),
            ("DetectorThread",    self._detector_loop,     True),
            ("AlertWorkerThread", self._alert_worker_loop, True),
            ("CleanupThread",     self._cleanup_loop,      True),
        ]

        for name, target, daemon in threads_config:
            t = threading.Thread(target=target, name=name, daemon=daemon)
            t.start()
            self._threads.append(t)
            logger.info(f"Started thread: {name}")

        logger.success("Detection pipeline running")

    def stop(self) -> None:
        """Gracefully stop the pipeline."""
        logger.info("Shutting down pipeline…")
        self._running = False
        # Unblock queues
        try:
            self._event_queue.put_nowait([])
            self._alert_queue.put_nowait([])
        except queue.Full:
            pass
        for t in self._threads:
            t.join(timeout=5)
        logger.info("Pipeline stopped")

    def get_stats(self) -> dict:
        uptime = None
        if self._stats["started_at"]:
            delta = datetime.utcnow() - self._stats["started_at"]
            uptime = str(delta).split(".")[0]
        return {**self._stats, "uptime": uptime, "running": self._running}

    # ─── Thread: Collector ────────────────────────────────────────────────

    def _collector_loop(self) -> None:
        """
        Pulls event batches from the configured collector and enqueues them.
        Handles both streaming (simulation) and polling (live/file) sources.
        """
        cfg = self._cfg["collection"]
        poll_interval = cfg["poll_interval_seconds"]
        batch_size    = cfg["batch_size"]
        mode          = cfg["mode"]

        logger.info(f"CollectorThread started | mode={mode}")

        if mode == "simulation":
            # Simulation yields a generator; consume it
            for batch in self._collector.stream():
                if not self._running:
                    break
                if batch:
                    self._enqueue_events(batch)
        else:
            # Live/file: open collector and poll
            if hasattr(self._collector, "open"):
                self._collector.open()
            try:
                while self._running:
                    if hasattr(self._collector, "poll"):
                        batch = list(self._collector.poll(batch_size=batch_size))
                    elif hasattr(self._collector, "collect"):
                        batch = list(self._collector.collect())
                        self._running = False  # file collector exhausts itself
                    else:
                        break

                    if batch:
                        self._enqueue_events(batch)
                    time.sleep(poll_interval)
            finally:
                if hasattr(self._collector, "close"):
                    self._collector.close()

        logger.info("CollectorThread exited")

    def _enqueue_events(self, events: List[LoginEvent]) -> None:
        """Persist events to DB and push to detection queue."""
        if not events:
            return
        try:
            # Bulk persist
            self._db.bulk_insert_events(events)
            self._stats["events_processed"] += len(events)

            # Push to detection queue (drop if full to avoid memory bloat)
            try:
                self._event_queue.put_nowait(events)
            except queue.Full:
                logger.warning("Event queue full — dropping batch (detection may lag)")
        except Exception as exc:
            logger.error(f"Event ingestion error: {exc}")

    # ─── Thread: Detector ─────────────────────────────────────────────────

    def _detector_loop(self) -> None:
        """
        Consumes event batches, runs threshold and ML detection,
        and enqueues generated alerts for the alert worker.
        """
        logger.info("DetectorThread started")

        while self._running:
            try:
                events = self._event_queue.get(timeout=2)
                if not events:
                    continue

                alerts: List[Alert] = []

                # Threshold detection (always on)
                alerts.extend(self._threshold_det.process_batch(events))

                # ML detection (if model is trained)
                if self._ml_det.is_ready:
                    alerts.extend(self._ml_det.process_batch(events))

                if alerts:
                    self._stats["alerts_generated"] += len(alerts)
                    try:
                        self._alert_queue.put_nowait(alerts)
                    except queue.Full:
                        logger.warning("Alert queue full — dropping alerts")

                self._event_queue.task_done()

            except queue.Empty:
                continue
            except Exception as exc:
                logger.error(f"Detection error: {exc}")

        logger.info("DetectorThread exited")

    # ─── Thread: Alert Worker ─────────────────────────────────────────────

    def _alert_worker_loop(self) -> None:
        """
        Consumes alerts from queue, runs full lifecycle (persist/enrich/notify),
        and broadcasts to WebSocket clients.
        """
        logger.info("AlertWorkerThread started")

        while self._running:
            try:
                alerts = self._alert_queue.get(timeout=2)
                if not alerts:
                    continue

                for alert in alerts:
                    try:
                        saved = self._alert_mgr.handle_alert(alert)
                        self._broadcast_alert(saved)
                    except Exception as exc:
                        logger.error(f"Alert processing error: {exc}")

                self._alert_queue.task_done()

            except queue.Empty:
                continue
            except Exception as exc:
                logger.error(f"AlertWorker error: {exc}")

        logger.info("AlertWorkerThread exited")

    def _broadcast_alert(self, alert: Alert) -> None:
        """Push alert to connected WebSocket clients via SocketIO."""
        if self._socketio is None:
            return
        try:
            payload = {
                "id":          alert.id,
                "created_at":  alert.created_at.isoformat() if alert.created_at else None,
                "severity":    alert.severity.value,
                "pattern":     alert.pattern.value,
                "source_ip":   alert.source_ip,
                "username":    alert.username,
                "attempt_count": alert.attempt_count,
                "description": alert.description,
                "threat_score": alert.threat_score,
            }
            self._socketio.emit("new_alert", payload, namespace="/")
        except Exception as exc:
            logger.debug(f"WebSocket broadcast error: {exc}")

    # ─── Thread: Cleanup ─────────────────────────────────────────────────

    def _cleanup_loop(self) -> None:
        """
        Periodically expire blocked IPs and prune old audit logs.
        Runs every 10 minutes.
        """
        logger.info("CleanupThread started")
        while self._running:
            try:
                self._expire_blocks()
            except Exception as exc:
                logger.error(f"Cleanup error: {exc}")
            time.sleep(600)  # 10 min
        logger.info("CleanupThread exited")

    def _expire_blocks(self) -> None:
        from src.database.models import BlockedIP
        from src.response.alert_manager import FirewallManager
        fw = FirewallManager()
        with self._db.session() as session:
            expired = (
                session.query(BlockedIP)
                .filter(
                    BlockedIP.is_active == True,
                    BlockedIP.expires_at < datetime.utcnow(),
                )
                .all()
            )
            for block in expired:
                fw.unblock_ip(block.ip_address)
                block.is_active = False
                logger.info(f"Expired block removed: {block.ip_address}")

    # ─── ML Bootstrap ─────────────────────────────────────────────────────

    def _maybe_train_ml(self) -> None:
        """
        If the ML model doesn't exist yet, generate synthetic data and train.
        Subsequent startups load the saved model from disk.
        """
        if not self._cfg["detection"]["ml"]["enabled"]:
            return
        if self._ml_det.is_ready:
            logger.info("ML model already trained — skipping initial training")
            return

        logger.info("No saved ML model found — generating training data…")
        try:
            from src.collectors.simulation import EventSimulator
            sim    = EventSimulator()
            events = sim.generate_historical_data(days_back=7, events_per_hour=200)
            self._ml_det.train(events)
        except Exception as exc:
            logger.warning(f"ML pre-training failed: {exc} — ML detection disabled")
