"""
SentinelFlow — Central Orchestrator
Coordinates the full pipeline: Discovery → Audit → DAST → Alert → Report
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    SCAN_TIMEOUT_SEC,
    ALERT_ON_SEVERITIES,
)
from core.database import (
    init_db,
    create_scan,
    finish_scan,
    get_assets,
    get_findings,
    mark_alerted,
    summary_stats,
)
from phases.discovery.subdomain_enum   import run_subdomain_enum
from phases.discovery.service_probe    import run_service_probe
from phases.audit.endpoint_fuzz        import run_endpoint_fuzz
from phases.audit.js_sast              import run_js_sast
from phases.audit.cloud_exposure       import run_cloud_exposure
from phases.dast.input_validation      import run_input_validation
from phases.dast.nuclei_scan           import run_nuclei_scan
from phases.alerting.telegram_bot      import send_finding_alert, send_scan_summary
from phases.reporting.report_generator import generate_report

log = logging.getLogger("orchestrator")


async def run_pipeline(seed: str, notify: bool = True) -> int:
    """
    Execute the full SentinelFlow pipeline for a given seed domain.
    Returns the scan_id.
    """
    log.info("═══════════════════════════════════════════")
    log.info("  SentinelFlow — starting scan for: %s", seed)
    log.info("═══════════════════════════════════════════")

    scan_id = create_scan(seed)
    log.info("Scan #%d created", scan_id)

    try:
        # ── Phase I: Asset Discovery ──────────────────────────────────────────
        log.info("[Phase I] Starting digital asset inventory...")
        await run_subdomain_enum(scan_id, seed)
        await run_service_probe(scan_id)

        assets = get_assets(scan_id)
        alive  = get_assets(scan_id, http_alive_only=True)
        log.info(
            "[Phase I] Complete — %d subdomains found, %d HTTP-alive",
            len(assets), len(alive),
        )

        if not alive:
            log.warning("No live HTTP services found. Skipping audit/DAST phases.")
            finish_scan(scan_id, "done")
            return scan_id

        # ── Phase II: Config & Secret Leakage Audit ───────────────────────────
        log.info("[Phase II] Starting configuration & secret leakage audit...")
        audit_tasks = [
            run_endpoint_fuzz(scan_id, alive),
            run_js_sast(scan_id, alive),
            run_cloud_exposure(scan_id, seed),
        ]
        await asyncio.gather(*audit_tasks)
        log.info("[Phase II] Audit complete")

        # ── Phase III: DAST ───────────────────────────────────────────────────
        log.info("[Phase III] Starting dynamic security validation...")
        dast_tasks = [
            run_input_validation(scan_id, alive),
            run_nuclei_scan(scan_id, alive),
        ]
        await asyncio.gather(*dast_tasks)
        log.info("[Phase III] DAST complete")

        # ── Phase IV: Alert ───────────────────────────────────────────────────
        if notify:
            log.info("[Phase IV] Dispatching alerts...")
            await _dispatch_alerts(scan_id)

        # ── Reporting ─────────────────────────────────────────────────────────
        log.info("[Reporting] Generating compliance report...")
        report_path = await generate_report(scan_id, seed)
        log.info("[Reporting] Report saved to %s", report_path)

        finish_scan(scan_id, "done")

        stats = summary_stats(scan_id)
        log.info(
            "═══ Scan #%d COMPLETE — Assets: %d | C:%d H:%d M:%d L:%d ═══",
            scan_id,
            stats["asset_count"],
            stats["critical"],
            stats["high"],
            stats["medium"],
            stats["low"],
        )

        if notify:
            await send_scan_summary(scan_id, seed, stats)

    except asyncio.CancelledError:
        log.warning("Scan #%d was cancelled", scan_id)
        finish_scan(scan_id, "error")
        raise
    except Exception as exc:
        log.exception("Scan #%d failed: %s", scan_id, exc)
        finish_scan(scan_id, "error")
        raise

    return scan_id


async def _dispatch_alerts(scan_id: int) -> None:
    """Send Telegram alerts for unalerted findings that meet severity threshold."""
    alerted_ids = []
    for severity in ALERT_ON_SEVERITIES:
        findings = get_findings(scan_id, severity=severity, unalerted_only=True)
        for finding in findings:
            try:
                await send_finding_alert(finding)
                alerted_ids.append(finding["id"])
            except Exception as exc:
                log.warning("Alert failed for finding %d: %s", finding["id"], exc)

    mark_alerted(alerted_ids)
    log.info("[Phase IV] Alerted on %d findings", len(alerted_ids))


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SentinelFlow — EASM & Continuous Security Monitor"
    )
    parser.add_argument("seed", help="Root domain to scan (e.g. example.com)")
    parser.add_argument(
        "--no-notify", action="store_true", help="Disable Telegram notifications"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    init_db()

    try:
        asyncio.run(
            asyncio.wait_for(
                run_pipeline(args.seed, notify=not args.no_notify),
                timeout=SCAN_TIMEOUT_SEC,
            )
        )
    except asyncio.TimeoutError:
        log.error("Scan timed out after %d seconds", SCAN_TIMEOUT_SEC)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
