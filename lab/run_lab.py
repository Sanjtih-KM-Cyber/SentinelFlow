#!/usr/bin/env python3
"""
SentinelFlow — Lab Benchmark Runner
Scans the local OWASP Juice Shop and DVWA containers for validation.

Usage:
    python lab/run_lab.py
    python lab/run_lab.py --target juice-shop
    python lab/run_lab.py --target dvwa
"""

import asyncio
import logging
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import init_db
from core.orchestrator import run_pipeline

LAB_TARGETS = {
    "juice-shop": "juice-shop",   # Docker service hostname
    "dvwa":       "dvwa",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("lab")


async def main():
    parser = argparse.ArgumentParser(description="SentinelFlow Lab Benchmark Runner")
    parser.add_argument(
        "--target",
        choices=list(LAB_TARGETS.keys()) + ["all"],
        default="all",
        help="Which lab target to scan (default: all)",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Suppress Telegram notifications during lab runs",
    )
    args = parser.parse_args()

    init_db()

    targets = (
        list(LAB_TARGETS.values())
        if args.target == "all"
        else [LAB_TARGETS[args.target]]
    )

    log.info("═══ SentinelFlow Lab Benchmark ═══")
    log.info("Targets: %s", ", ".join(targets))

    for target in targets:
        log.info("── Scanning lab target: %s ──", target)
        try:
            scan_id = await run_pipeline(target, notify=not args.no_notify)
            log.info("Lab scan complete for %s — scan_id=%d", target, scan_id)
        except Exception as exc:
            log.error("Lab scan failed for %s: %s", target, exc)


if __name__ == "__main__":
    asyncio.run(main())
