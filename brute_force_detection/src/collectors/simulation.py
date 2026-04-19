"""
simulation.py — Realistic Windows Security Event simulator.

Generates synthetic login events mimicking real attack patterns:
  - Brute-force (high frequency, single IP → single user)
  - Password spray (medium frequency, single IP → many users)
  - Credential stuffing (rapid burst, multiple IPs → many users)
  - Normal activity (distributed, legitimate logins)

All events are indistinguishable from real parsed events at the ORM level.
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timedelta
from typing import Generator, List, Optional

from faker import Faker
from loguru import logger

from src.database.models import LoginEvent, LoginResult
from src.utils.config_loader import get_config

fake = Faker()
Faker.seed(42)

# ─── Realistic data pools ────────────────────────────────────────────────────

ATTACK_IPS = [
    "185.220.101.34",  "194.165.16.72",   "45.33.32.156",
    "198.98.54.23",    "91.108.4.177",    "179.43.128.15",
    "103.75.190.34",   "162.247.74.201",  "5.188.62.140",
    "46.161.27.155",   "89.234.157.254",  "185.100.87.43",
]

LEGITIMATE_IPS = [
    "10.0.0.{i}".format(i=i) for i in range(1, 50)
] + ["192.168.1.{i}".format(i=i) for i in range(1, 30)]

DOMAINS = ["CORP", "WORKGROUP", "INTERNAL", "HQ", "LAB"]
AUTH_PACKAGES = ["NTLM", "Kerberos", "Negotiate", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"]
FAILURE_REASONS = [
    "%%2313",   # Unknown user or bad password
    "%%2304",   # Account currently disabled
    "%%2305",   # Account expired
    "%%2309",   # Account locked out
    "%%2310",   # Invalid workstation
]
LOGON_TYPES = [2, 3, 7, 10]        # Interactive, Network, Unlock, RemoteInteractive
WORKSTATIONS = [
    f"WORKSTATION-{fake.random_int(100, 999)}" for _ in range(20)
]


def _make_username(base: Optional[str] = None) -> str:
    if base:
        return base
    first = fake.first_name().lower()
    last  = fake.last_name().lower()
    return random.choice([
        f"{first}.{last}",
        f"{first[0]}{last}",
        f"{first}_{last[:4]}",
        f"svc_{fake.lexify('????')}",
    ])


def _make_event(
    event_id: int,
    username: str,
    source_ip: str,
    result: LoginResult,
    timestamp: Optional[datetime] = None,
) -> LoginEvent:
    ts = timestamp or datetime.utcnow()
    return LoginEvent(
        event_id        = event_id,
        timestamp       = ts,
        source_ip       = source_ip,
        source_hostname = fake.hostname(),
        username        = username,
        domain          = random.choice(DOMAINS),
        logon_type      = random.choice(LOGON_TYPES),
        result          = result,
        workstation     = random.choice(WORKSTATIONS),
        auth_package    = random.choice(AUTH_PACKAGES),
        failure_reason  = random.choice(FAILURE_REASONS) if result == LoginResult.FAILURE else None,
        host_source     = "simulator",
    )


# ─── Attack pattern generators ───────────────────────────────────────────────

class AttackPatternGenerator:
    """Encapsulates a single attack campaign state."""

    def __init__(self, pattern: str, cfg: dict) -> None:
        self.pattern = pattern
        self.cfg = cfg
        self.attack_ip = random.choice(ATTACK_IPS)
        self.target_user = _make_username()
        self.user_pool = [_make_username() for _ in range(50)]
        self._burst_remaining = 0

    def next_events(self) -> List[LoginEvent]:
        """Return a list of events for one simulation tick."""
        if self.pattern == "brute_force":
            return self._brute_force()
        if self.pattern == "password_spray":
            return self._password_spray()
        if self.pattern == "credential_stuffing":
            return self._credential_stuffing()
        return []

    def _brute_force(self) -> List[LoginEvent]:
        """Single IP hammering a single username."""
        count = random.randint(2, 8)
        events = []
        for _ in range(count):
            events.append(_make_event(4625, self.target_user, self.attack_ip, LoginResult.FAILURE))
        # Occasional success (attacker found password)
        if random.random() < 0.02:
            events.append(_make_event(4624, self.target_user, self.attack_ip, LoginResult.SUCCESS))
            self.target_user = _make_username()  # Move to next target
        return events

    def _password_spray(self) -> List[LoginEvent]:
        """Single IP trying one password across many usernames."""
        targets = random.sample(self.user_pool, k=random.randint(3, 12))
        return [
            _make_event(4625, user, self.attack_ip, LoginResult.FAILURE)
            for user in targets
        ]

    def _credential_stuffing(self) -> List[LoginEvent]:
        """Rapid burst from multiple IPs across many username/password combos."""
        if self._burst_remaining <= 0:
            self._burst_remaining = random.randint(20, 50)
            self.attack_ip = random.choice(ATTACK_IPS)

        batch_size = min(random.randint(3, 8), self._burst_remaining)
        self._burst_remaining -= batch_size
        return [
            _make_event(
                4625,
                random.choice(self.user_pool),
                random.choice(ATTACK_IPS),
                LoginResult.FAILURE,
            )
            for _ in range(batch_size)
        ]


class EventSimulator:
    """
    Main simulator engine. Produces a continuous stream of realistic
    login events mixing legitimate activity with attack patterns.
    """

    def __init__(self) -> None:
        cfg = get_config()
        sim_cfg = cfg["simulation"]
        self.attack_rate       = sim_cfg["attack_rate"]
        self.events_per_second = sim_cfg["events_per_second"]
        self.legitimate_users  = [_make_username() for _ in range(sim_cfg["num_legitimate_users"])]
        self.legitimate_ips    = random.sample(LEGITIMATE_IPS, k=min(30, len(LEGITIMATE_IPS)))
        self.patterns          = sim_cfg["attack_patterns"]

        self._attack_generators = [
            AttackPatternGenerator(p, sim_cfg)
            for p in self.patterns
        ]
        self._running = False
        logger.info(
            f"EventSimulator initialised | patterns={self.patterns} "
            f"attack_rate={self.attack_rate}"
        )

    def generate_batch(self, size: int = 20) -> List[LoginEvent]:
        """Generate a batch of mixed events (attack + legitimate)."""
        events: List[LoginEvent] = []
        for _ in range(size):
            if random.random() < self.attack_rate:
                gen = random.choice(self._attack_generators)
                events.extend(gen.next_events())
            else:
                events.append(self._legitimate_event())
        return events

    def _legitimate_event(self) -> LoginEvent:
        user   = random.choice(self.legitimate_users)
        ip     = random.choice(self.legitimate_ips)
        # 5% failure rate for normal users (mistyped password, etc.)
        if random.random() < 0.05:
            return _make_event(4625, user, ip, LoginResult.FAILURE)
        return _make_event(4624, user, ip, LoginResult.SUCCESS)

    def stream(self) -> Generator[List[LoginEvent], None, None]:
        """
        Continuously yield event batches. Simulates real-time ingestion.
        Used by the background collection worker.
        """
        self._running = True
        logger.info("Event stream started")
        try:
            while self._running:
                batch = self.generate_batch(size=random.randint(3, 12))
                yield batch
                time.sleep(1.0 / self.events_per_second)
        except GeneratorExit:
            pass
        finally:
            self._running = False
            logger.info("Event stream stopped")

    def stop(self) -> None:
        self._running = False

    def generate_historical_data(
        self,
        days_back: int = 7,
        events_per_hour: int = 150,
    ) -> List[LoginEvent]:
        """
        Backfill historical events for seeding the database on first run.
        Creates a week of realistic activity with several distinct attack campaigns.
        """
        logger.info(f"Generating {days_back} days of historical data…")
        all_events: List[LoginEvent] = []
        now = datetime.utcnow()
        start = now - timedelta(days=days_back)

        current = start
        while current < now:
            # Simulate hourly batch
            count = int(events_per_hour * random.uniform(0.7, 1.4))
            hour_events = []

            for _ in range(count):
                offset_sec = random.uniform(0, 3600)
                ts = current + timedelta(seconds=offset_sec)

                if random.random() < self.attack_rate:
                    gen = random.choice(self._attack_generators)
                    for ev in gen.next_events():
                        ev.timestamp = ts
                        hour_events.append(ev)
                else:
                    ev = self._legitimate_event()
                    ev.timestamp = ts
                    hour_events.append(ev)

            # Inject an attack spike during business hours
            hour = current.hour
            if 8 <= hour <= 18 and random.random() < 0.15:
                spike_ip = random.choice(ATTACK_IPS)
                spike_user = _make_username()
                for i in range(random.randint(15, 40)):
                    ts = current + timedelta(seconds=random.uniform(0, 600))
                    hour_events.append(
                        _make_event(4625, spike_user, spike_ip, LoginResult.FAILURE, ts)
                    )

            all_events.extend(hour_events)
            current += timedelta(hours=1)

        logger.success(f"Generated {len(all_events):,} historical events over {days_back} days")
        return all_events
