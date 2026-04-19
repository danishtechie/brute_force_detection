"""
windows_log_collector.py — Windows Security Event Log collector.

Supports three collection modes:
  - live    : Windows API via pywin32 (Windows only)
  - file    : Parse an .evtx file using python-evtx
  - simulation: Generate synthetic attack/normal events (cross-platform)

The collector yields LoginEvent ORM objects for downstream processing.
"""

from __future__ import annotations

import platform
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Generator, List, Optional

from loguru import logger

from src.database.models import LoginEvent, LoginResult
from src.utils.config_loader import get_config

# Windows-only imports guarded at runtime
_WIN32_AVAILABLE = platform.system() == "Windows"
if _WIN32_AVAILABLE:
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
    except ImportError:
        _WIN32_AVAILABLE = False
        logger.warning("pywin32 not available – live collection disabled")


# ─── Event ID mappings ───────────────────────────────────────────────────────

EVENT_ID_MAP = {
    4624: ("successful_login",  LoginResult.SUCCESS),
    4625: ("failed_login",      LoginResult.FAILURE),
    4740: ("account_lockout",   LoginResult.LOCKOUT),
    4648: ("explicit_creds",    LoginResult.SUCCESS),
    4771: ("kerberos_failure",  LoginResult.FAILURE),
    4776: ("ntlm_validation",   LoginResult.FAILURE),
}

# Logon type descriptions
LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}


# ─── Namespace helper ────────────────────────────────────────────────────────

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _xml_find(root: ET.Element, path: str) -> Optional[str]:
    el = root.find(path, NS)
    return el.text if el is not None else None


# ─── XML Parser ──────────────────────────────────────────────────────────────

def parse_event_xml(raw_xml: str) -> Optional[LoginEvent]:
    """
    Parse a Windows Security Event XML string into a LoginEvent ORM object.

    Handles variations between Event IDs 4624, 4625, 4740, etc.
    Returns None if the event is not a recognised login event.
    """
    try:
        root = ET.fromstring(raw_xml)
        system = root.find("e:System", NS)
        if system is None:
            return None

        event_id_el = system.find("e:EventID", NS)
        if event_id_el is None:
            return None
        event_id = int(event_id_el.text)

        if event_id not in EVENT_ID_MAP:
            return None

        _, result = EVENT_ID_MAP[event_id]

        time_created = system.find("e:TimeCreated", NS)
        ts_str = time_created.get("SystemTime") if time_created is not None else None
        timestamp = (
            datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            if ts_str
            else datetime.utcnow()
        )

        # EventData fields differ by Event ID
        event_data = root.find("e:EventData", NS)
        data = {}
        if event_data is not None:
            for item in event_data.findall("e:Data", NS):
                name = item.get("Name", "")
                data[name] = item.text or ""

        username = (
            data.get("TargetUserName")
            or data.get("SubjectUserName")
            or "UNKNOWN"
        )
        source_ip = data.get("IpAddress") or data.get("WorkstationName")
        if source_ip in ("-", "::1", "127.0.0.1", None):
            source_ip = None  # Normalise local loopback / empty

        domain = data.get("TargetDomainName") or data.get("SubjectDomainName")

        try:
            logon_type = int(data.get("LogonType", 0))
        except (ValueError, TypeError):
            logon_type = 0

        return LoginEvent(
            event_id        = event_id,
            timestamp       = timestamp,
            source_ip       = source_ip,
            source_hostname = data.get("WorkstationName"),
            username        = username,
            domain          = domain,
            logon_type      = logon_type,
            result          = result,
            auth_package    = data.get("AuthenticationPackageName") or data.get("PackageName"),
            failure_reason  = data.get("FailureReason") or data.get("Status"),
            process_name    = data.get("ProcessName"),
            raw_xml         = raw_xml,
        )
    except Exception as exc:
        logger.warning(f"Failed to parse event XML: {exc}")
        return None


# ─── Collector Classes ───────────────────────────────────────────────────────

class LiveWindowsCollector:
    """
    Polls the Windows Security event log using pywin32.
    Must run on Windows with appropriate privileges (SYSTEM/Admin).
    """

    def __init__(self, host: str = "localhost", log_name: str = "Security") -> None:
        if not _WIN32_AVAILABLE:
            raise RuntimeError("pywin32 is required for live collection on Windows")
        self.host = host
        self.log_name = log_name
        self._handle = None
        cfg = get_config()
        self._target_ids = set(
            cfg["collection"]["event_ids"]["failed_login"]
            + cfg["collection"]["event_ids"]["successful_login"]
            + cfg["collection"]["event_ids"]["account_lockout"]
        )

    def open(self) -> None:
        self._handle = win32evtlog.OpenEventLog(self.host, self.log_name)
        logger.info(f"Opened event log: \\\\{self.host}\\{self.log_name}")

    def close(self) -> None:
        if self._handle:
            win32evtlog.CloseEventLog(self._handle)
            self._handle = None

    def poll(self, batch_size: int = 500) -> Generator[LoginEvent, None, None]:
        """Read a batch of events from the current read pointer."""
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            raw_events = win32evtlog.ReadEventLog(self._handle, flags, 0, batch_size)
        except Exception as exc:
            logger.error(f"ReadEventLog failed: {exc}")
            return

        for ev in raw_events:
            if ev.EventID not in self._target_ids:
                continue
            try:
                xml_str = win32evtlogutil.SafeFormatMessage(ev, self.log_name)
                event = parse_event_xml(xml_str)
                if event:
                    event.host_source = self.host
                    yield event
            except Exception as exc:
                logger.debug(f"Skipping malformed event: {exc}")


class EvtxFileCollector:
    """
    Parse a saved .evtx file using the python-evtx library.
    Useful for offline forensic analysis and testing.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def collect(self) -> Generator[LoginEvent, None, None]:
        try:
            import Evtx.Evtx as evtx  # type: ignore
        except ImportError:
            raise ImportError("python-evtx is required: pip install python-evtx")

        logger.info(f"Parsing EVTX file: {self.file_path}")
        with evtx.Evtx(self.file_path) as log:
            for record in log.records():
                try:
                    event = parse_event_xml(record.xml())
                    if event:
                        yield event
                except Exception as exc:
                    logger.debug(f"Record parse error: {exc}")


# ─── Factory ─────────────────────────────────────────────────────────────────

def build_collector(mode: Optional[str] = None):
    """
    Return the appropriate collector based on config mode.
    Falls back to simulation if live collection is unavailable.
    """
    cfg = get_config()
    mode = mode or cfg["collection"]["mode"]

    if mode == "live":
        if not _WIN32_AVAILABLE:
            logger.warning("Live mode requested but pywin32 unavailable – falling back to simulation")
            from src.collectors.simulation import EventSimulator
            return EventSimulator()
        return LiveWindowsCollector()

    if mode == "file":
        return EvtxFileCollector(cfg["collection"]["log_file_path"])

    # Default: simulation
    from src.collectors.simulation import EventSimulator
    return EventSimulator()
