"""
ip_reputation.py — Threat Intelligence enrichment for attacking IP addresses.

Integrates with:
  - AbuseIPDB  : Crowdsourced abuse score and category tags
  - ip-api.com : Free geo-location (city, country, lat/lon, ISP, ASN)
  - Local cache: SQLite-backed TTL cache to minimise API calls

All network calls are wrapped with retry logic and rate-limiting guards.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

import requests
from loguru import logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.database.db_manager import get_db
from src.database.models import ThreatIntelRecord
from src.utils.config_loader import get_config


# ─── HTTP Session with retry ─────────────────────────────────────────────────

def _build_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "BruteGuard-SOC/2.1"})
    return session


_HTTP = _build_session()


# ─── AbuseIPDB client ────────────────────────────────────────────────────────

class AbuseIPDBClient:
    """
    Query AbuseIPDB for IP reputation data.
    Returns confidence score (0-100) and category breakdown.
    """

    def __init__(self) -> None:
        cfg = get_config()["threat_intelligence"]["abuseipdb"]
        self.api_key   = cfg["api_key"]
        self.base_url  = cfg["base_url"]
        self.threshold = cfg["confidence_threshold"]
        self._last_call = 0.0
        self._min_interval = 1.0  # 1 request/second rate limit guard

    def check_ip(self, ip: str) -> Dict:
        """Query the /check endpoint. Returns parsed response dict."""
        if self.api_key in ("YOUR_ABUSEIPDB_API_KEY", "", None):
            logger.debug(f"AbuseIPDB not configured – skipping lookup for {ip}")
            return {}

        # Rate limiting
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        try:
            resp = _HTTP.get(
                f"{self.base_url}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30, "verbose": True},
                timeout=5,
            )
            self._last_call = time.time()

            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit hit")
                return {}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            logger.debug(f"AbuseIPDB: {ip} → score={data.get('abuseConfidenceScore')}")
            return data

        except requests.RequestException as exc:
            logger.warning(f"AbuseIPDB request failed for {ip}: {exc}")
            return {}


# ─── Geo-location client ─────────────────────────────────────────────────────

class GeoIPClient:
    """
    Geo-locate IP addresses using ip-api.com (free tier, 45 req/min).
    Falls back gracefully when rate-limited.
    """

    BASE_URL = "http://ip-api.com/json"
    FIELDS   = "status,country,countryCode,region,city,lat,lon,isp,org,as,query"

    def __init__(self) -> None:
        self._last_call = 0.0
        self._min_interval = 1.4   # 45 req/min ≈ 1.33s between calls

    def locate(self, ip: str) -> Dict:
        """Return geo-location dict for the given IP."""
        # Skip private/RFC1918 addresses
        if self._is_private(ip):
            return {"status": "private", "country": "Internal", "countryCode": "INT"}

        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        try:
            resp = _HTTP.get(
                f"{self.BASE_URL}/{ip}",
                params={"fields": self.FIELDS},
                timeout=4,
            )
            self._last_call = time.time()

            if resp.status_code == 429:
                logger.warning("ip-api.com rate limit hit")
                return {}
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "success":
                return {}
            return data

        except requests.RequestException as exc:
            logger.debug(f"GeoIP lookup failed for {ip}: {exc}")
            return {}

    @staticmethod
    def _is_private(ip: str) -> bool:
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False


# ─── Enrichment Engine ───────────────────────────────────────────────────────

class ThreatIntelEnricher:
    """
    Orchestrates IP enrichment using AbuseIPDB + GeoIP with SQLite caching.
    The cache TTL prevents redundant API calls for the same IP within
    the configured window (default: 24 hours).
    """

    def __init__(self) -> None:
        cfg = get_config()["threat_intelligence"]
        self.enabled    = cfg["enabled"]
        self._abuseipdb = AbuseIPDBClient()
        self._geo       = GeoIPClient()
        self._db        = get_db()
        self._ttl_hours = cfg["abuseipdb"]["cache_ttl_hours"]
        logger.info(f"ThreatIntelEnricher initialised | enabled={self.enabled}")

    def enrich(self, ip: str) -> Optional[ThreatIntelRecord]:
        """
        Return an enriched ThreatIntelRecord for the given IP.
        Checks cache first; queries APIs if cache miss or expired.
        """
        if not self.enabled or not ip:
            return None

        # Cache check
        cached = self._db.get_threat_intel(ip)
        if cached and not cached.is_expired:
            return cached

        record = self._fetch_and_build_record(ip)
        if record:
            self._db.upsert_threat_intel(record)
        return record

    def enrich_batch(self, ips: list[str]) -> Dict[str, Optional[ThreatIntelRecord]]:
        """Enrich a list of IPs, honouring rate limits between calls."""
        return {ip: self.enrich(ip) for ip in set(ips)}

    def _fetch_and_build_record(self, ip: str) -> Optional[ThreatIntelRecord]:
        now = datetime.utcnow()
        expires = now + timedelta(hours=self._ttl_hours)

        # ── Geo location ──────────────────────────────────────────────────
        geo_data = self._geo.locate(ip)

        # ── Abuse score ───────────────────────────────────────────────────
        abuse_data = self._abuseipdb.check_ip(ip)

        if not geo_data and not abuse_data:
            # Both failed; build a minimal record to avoid repeated lookups
            return ThreatIntelRecord(
                ip_address = ip,
                queried_at = now,
                expires_at = now + timedelta(hours=1),
            )

        abuse_score  = abuse_data.get("abuseConfidenceScore", 0)
        isp          = geo_data.get("isp") or abuse_data.get("isp")
        org          = geo_data.get("org") or abuse_data.get("domain")
        asn          = geo_data.get("as") or str(abuse_data.get("asn", ""))

        record = ThreatIntelRecord(
            ip_address   = ip,
            queried_at   = now,
            expires_at   = expires,
            abuse_score  = abuse_score,
            is_known_bad = (abuse_score or 0) >= 50,
            isp          = isp,
            org          = org,
            country_code = geo_data.get("countryCode") or abuse_data.get("countryCode"),
            country_name = geo_data.get("country") or abuse_data.get("countryName"),
            city         = geo_data.get("city"),
            region       = geo_data.get("region"),
            latitude     = geo_data.get("lat"),
            longitude    = geo_data.get("lon"),
            asn          = asn,
            tor_exit_node = abuse_data.get("isTor", False),
            raw_response  = json.dumps({"geo": geo_data, "abuse": abuse_data}),
        )

        logger.info(
            f"TI enriched: {ip} | country={record.country_code} "
            f"abuse_score={record.abuse_score} tor={record.tor_exit_node}"
        )
        return record

    def get_threat_summary(self, ip: str) -> dict:
        """Return a human-readable threat summary for dashboard display."""
        record = self._db.get_threat_intel(ip)
        if not record:
            return {"ip": ip, "enriched": False}
        return {
            "ip":           record.ip_address,
            "enriched":     True,
            "country":      f"{record.country_name} ({record.country_code})",
            "city":         record.city,
            "isp":          record.isp,
            "abuse_score":  record.abuse_score,
            "is_known_bad": record.is_known_bad,
            "tor":          record.tor_exit_node,
            "lat":          record.latitude,
            "lon":          record.longitude,
        }
