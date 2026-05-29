#!/usr/bin/env python3
"""
SentinelFlow - Automated External Attack Surface Management (EASM)
Entry point for the SentinelFlow security monitoring pipeline.

LEGAL NOTICE: This tool is intended ONLY for use on systems you own
or have explicit written authorization to test. Unauthorized use against
systems is illegal and unethical.
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from core.orchestrator import SentinelOrchestrator
from core.config import Config
from core.logger import get_logger
from utils.banner import print_banner

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SentinelFlow - External Attack Surface Management Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline scan
  python main.py --domain example.com --output ./results

  # Phase-specific scan
  python main.py --domain example.com --phases discovery,audit

  # With Telegram notifications
  python main.py --domain example.com --telegram-token TOKEN --telegram-chat CHAT_ID

  # Start Telegram bot for interactive mode
  python main.py --bot-mode --telegram-token TOKEN --telegram-chat CHAT_ID

DISCLAIMER: Only scan systems you own or have explicit written permission to test.
        """
    )

    # Target specification
    target = parser.add_argument_group("Target")
    target.add_argument("--domain", "-d", help="Root domain to scan (seed domain)")
    target.add_argument(
        "--scope-file",
        help="File with list of in-scope domains (one per line)"
    )
    target.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you have authorization to scan this target (required)"
    )

    # Phase control
    phases = parser.add_argument_group("Phases")
    phases.add_argument(
        "--phases",
        default="all",
        help="Comma-separated list of phases to run: discovery,audit,dast,report (default: all)"
    )
    phases.add_argument("--skip-phases", help="Phases to skip")
    phases.add_argument(
        "--passive-only",
        action="store_true",
        help="Run only passive reconnaissance (no active probing)"
    )

    # Output
    output = parser.add_argument_group("Output")
    output.add_argument("--output", "-o", default="./results", help="Output directory")
    output.add_argument(
        "--format",
        choices=["json", "pdf", "both"],
        default="both",
        help="Report format"
    )
    output.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Notifications
    notif = parser.add_argument_group("Notifications")
    notif.add_argument("--telegram-token", help="Telegram bot token")
    notif.add_argument("--telegram-chat", help="Telegram chat ID for alerts")

    # Bot mode
    bot = parser.add_argument_group("Bot Mode")
    bot.add_argument(
        "--bot-mode",
        action="store_true",
        help="Start in Telegram bot mode (interactive)"
    )

    # Config
    cfg = parser.add_argument_group("Configuration")
    cfg.add_argument("--config", default="config/sentinelflow.yaml", help="Config file path")
    cfg.add_argument("--db", default="sentinelflow.db", help="SQLite database path")
    cfg.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    cfg.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    cfg.add_argument("--rate-limit", type=int, default=100, help="Requests per second limit")

    return parser.parse_args()


async def main():
    print_banner()
    args = parse_args()

    # Load configuration
    config = Config(
        config_file=args.config,
        db_path=args.db,
        output_dir=args.output,
        verbose=args.verbose,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        passive_only=args.passive_only,
        telegram_token=args.telegram_token,
        telegram_chat=args.telegram_chat,
    )

    # Bot mode - start interactive Telegram bot
    if args.bot_mode:
        if not args.telegram_token or not args.telegram_chat:
            logger.error("Bot mode requires --telegram-token and --telegram-chat")
            sys.exit(1)
        from phases.notifier import TelegramNotifier
        notifier = TelegramNotifier(config)
        logger.info("Starting SentinelFlow Telegram Bot...")
        await notifier.start_bot()
        return

    # Standard scan mode
    if not args.domain and not args.scope_file:
        logger.error("Provide --domain or --scope-file for scanning")
        sys.exit(1)

    # Authorization gate
    if not args.authorized:
        print("\n" + "="*70)
        print("  AUTHORIZATION REQUIRED")
        print("="*70)
        print(f"\n  Target: {args.domain or args.scope_file}")
        print("\n  Do you have explicit written authorization to scan this target?")
        print("  Unauthorized scanning is illegal under the Computer Fraud and")
        print("  Abuse Act (CFAA) and equivalent laws worldwide.\n")
        confirm = input("  Type 'YES I AM AUTHORIZED' to proceed: ").strip()
        if confirm != "YES I AM AUTHORIZED":
            print("\n  Scan aborted. Authorization not confirmed.")
            sys.exit(0)

    # Determine phases
    if args.phases == "all":
        phases = ["discovery", "audit", "dast", "report"]
    else:
        phases = [p.strip() for p in args.phases.split(",")]

    if args.skip_phases:
        skip = [p.strip() for p in args.skip_phases.split(",")]
        phases = [p for p in phases if p not in skip]

    # Collect domains
    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.scope_file:
        with open(args.scope_file) as f:
            domains.extend(line.strip() for line in f if line.strip())

    logger.info(f"SentinelFlow starting scan for {len(domains)} domain(s)")
    logger.info(f"Active phases: {', '.join(phases)}")

    # Run orchestrator
    orchestrator = SentinelOrchestrator(config)
    await orchestrator.initialize()

    for domain in domains:
        logger.info(f"{'='*60}")
        logger.info(f"Scanning domain: {domain}")
        logger.info(f"{'='*60}")
        await orchestrator.run_pipeline(domain=domain, phases=phases)

    await orchestrator.shutdown()
    logger.info("SentinelFlow scan complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Shutting down gracefully...")
        sys.exit(0)
