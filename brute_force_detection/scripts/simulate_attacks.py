#!/usr/bin/env python3
"""
simulate_attacks.py — Standalone attack simulation script.

Generates realistic Windows Security Event Log entries and stores
them directly in the database. Useful for:
  - Populating a demo database without running the full platform
  - Testing detection rules in isolation
  - Generating benchmark datasets for ML training

Usage:
    python scripts/simulate_attacks.py --days 7 --intensity high
    python scripts/simulate_attacks.py --days 1 --intensity low --dry-run
    python scripts/simulate_attacks.py --pattern spray --count 500
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.table   import Table

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="BruteGuard Attack Simulator")
    p.add_argument("--days",      type=int,   default=7,          help="Historical days to generate")
    p.add_argument("--intensity", choices=["low","medium","high"], default="medium")
    p.add_argument("--pattern",   choices=["all","brute_force","spray","stuffing"], default="all")
    p.add_argument("--count",     type=int,   default=None,        help="Exact event count to generate")
    p.add_argument("--dry-run",   action="store_true",             help="Don't write to database")
    p.add_argument("--live",      action="store_true",             help="Stream events in real-time")
    return p.parse_args()


INTENSITY_MAP = {
    "low":    {"events_per_hour": 50,  "attack_rate": 0.2},
    "medium": {"events_per_hour": 150, "attack_rate": 0.4},
    "high":   {"events_per_hour": 400, "attack_rate": 0.65},
}


def run_historical(args) -> None:
    from src.collectors.simulation import EventSimulator
    from src.database.db_manager import get_db
    from src.utils.config_loader import get_config

    cfg = get_config()
    cfg["simulation"]["attack_rate"] = INTENSITY_MAP[args.intensity]["attack_rate"]
    if args.pattern != "all":
        cfg["simulation"]["attack_patterns"] = [args.pattern if args.pattern != "spray" else "password_spray"]

    events_per_hour = (
        args.count // (args.days * 24) if args.count
        else INTENSITY_MAP[args.intensity]["events_per_hour"]
    )

    console.print(f"\n[bold cyan]BruteGuard Attack Simulator[/bold cyan]")
    console.print(f"Mode: Historical | Days: {args.days} | Intensity: {args.intensity}")
    console.print(f"Pattern: {args.pattern} | Events/hour: {events_per_hour}\n")

    sim = EventSimulator()

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Generating events…", total=None)
        events = sim.generate_historical_data(
            days_back=args.days,
            events_per_hour=events_per_hour,
        )
        progress.update(task, description=f"Generated {len(events):,} events")

    if not args.dry_run:
        db = get_db()
        db.create_tables()
        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Writing to database…", total=None)
            # Write in chunks of 1000
            for i in range(0, len(events), 1000):
                db.bulk_insert_events(events[i:i+1000])
            progress.update(task, description=f"Wrote {len(events):,} events to database")
    else:
        console.print("[yellow]DRY RUN — no data written to database[/yellow]")

    # Stats summary
    from src.database.models import LoginResult
    failures  = sum(1 for e in events if e.result == LoginResult.FAILURE)
    successes = sum(1 for e in events if e.result == LoginResult.SUCCESS)

    t = Table(title="Simulation Summary", style="cyan")
    t.add_column("Metric")
    t.add_column("Value", justify="right")
    t.add_row("Total events",     f"{len(events):,}")
    t.add_row("Failed logins",    f"{failures:,}")
    t.add_row("Successful logins",f"{successes:,}")
    t.add_row("Failure rate",     f"{failures/len(events):.1%}")
    t.add_row("Days covered",     str(args.days))
    console.print(t)


def run_live(args) -> None:
    """Stream events in real-time to database."""
    from src.collectors.simulation import EventSimulator
    from src.database.db_manager import get_db

    db  = get_db()
    db.create_tables()
    sim = EventSimulator()

    console.print("[bold green]Live simulation started — Ctrl+C to stop[/bold green]\n")
    total = 0
    try:
        for batch in sim.stream():
            if not args.dry_run:
                db.bulk_insert_events(batch)
            total += len(batch)
            failures = sum(1 for e in batch if e.result.value == "failure")
            console.print(
                f"[dim]{datetime.utcnow().strftime('%H:%M:%S')}[/dim] "
                f"Batch: {len(batch):2d} events | "
                f"[red]✗ {failures}[/red] failures | "
                f"Total: {total:,}"
            )
    except KeyboardInterrupt:
        console.print(f"\n[yellow]Stopped. Total events generated: {total:,}[/yellow]")


def main() -> None:
    args = parse_args()
    if args.live:
        run_live(args)
    else:
        run_historical(args)


if __name__ == "__main__":
    main()
