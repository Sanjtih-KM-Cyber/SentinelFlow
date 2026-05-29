"""
SentinelFlow Central Orchestrator
Coordinates the full EASM pipeline: discovery → audit → DAST → reporting → alerting.
"""

import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from core.config import Config
from core.database import Database
from core.logger import get_logger

logger = get_logger(__name__)


class SentinelOrchestrator:
    """
    The heart of SentinelFlow.
    Manages phase execution, state persistence, and result aggregation.
    """

    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config.db_path)
        self.notifier = None
        self._scan_id: Optional[int] = None
        self._domain_id: Optional[int] = None

    async def initialize(self):
        """Set up database and notification channels."""
        await self.db.connect()
        logger.info("Database initialized")

        if self.config.has_telegram:
            from phases.notifier import TelegramNotifier
            self.notifier = TelegramNotifier(self.config)
            await self.notifier.send_message("🛡️ *SentinelFlow* initialized and ready.")
            logger.info("Telegram notifier connected")

    async def shutdown(self):
        """Graceful teardown."""
        await self.db.close()
        logger.info("Orchestrator shutdown complete")

    # ─── Pipeline ─────────────────────────────────────────────────────────

    async def run_pipeline(self, domain: str, phases: List[str]) -> Dict[str, Any]:
        """
        Execute the full security pipeline for a given domain.

        Args:
            domain: Root domain to scan.
            phases: List of phase names to run.

        Returns:
            Aggregated results dictionary.
        """
        start_time = datetime.now()
        logger.info(f"Pipeline started for {domain} | Phases: {phases}")

        # Register domain and scan session
        self._domain_id = await self.db.upsert_domain(domain)
        self._scan_id = await self.db.create_scan(domain, phases)
        await self.db.update_domain_scan_time(self._domain_id)

        if self.notifier:
            await self.notifier.send_message(
                f"🔍 *New Scan Started*\n"
                f"Domain: `{domain}`\n"
                f"Phases: {', '.join(phases)}\n"
                f"Scan ID: `{self._scan_id}`"
            )

        results: Dict[str, Any] = {
            "domain": domain,
            "scan_id": self._scan_id,
            "phases_run": phases,
            "started_at": start_time.isoformat(),
            "subdomains": [],
            "services": [],
            "findings": [],
        }

        phase_map = {
            "discovery": self._run_discovery,
            "audit": self._run_audit,
            "dast": self._run_dast,
            "report": self._run_reporting,
        }

        scan_status = "complete"

        for phase_name in phases:
            handler = phase_map.get(phase_name)
            if not handler:
                logger.warning(f"Unknown phase: {phase_name}, skipping")
                continue

            logger.info(f"▶ Starting phase: {phase_name.upper()}")
            try:
                phase_result = await handler(domain, results)
                results[f"{phase_name}_result"] = phase_result
                logger.info(f"✔ Phase complete: {phase_name.upper()}")
            except Exception as exc:
                logger.error(f"Phase {phase_name} failed: {exc}", exc_info=True)
                results[f"{phase_name}_error"] = str(exc)
                scan_status = "partial"

        # Finalize scan
        summary = await self.db.get_findings_summary(self._scan_id)
        elapsed = (datetime.now() - start_time).total_seconds()

        await self.db.complete_scan(self._scan_id, status=scan_status, stats=summary)

        results["finished_at"] = datetime.now().isoformat()
        results["elapsed_seconds"] = elapsed
        results["findings_summary"] = summary

        self._log_summary(domain, summary, elapsed)

        if self.notifier:
            await self.notifier.send_scan_complete(domain, summary, elapsed)

        return results

    # ─── Phase Handlers ───────────────────────────────────────────────────

    async def _run_discovery(self, domain: str, results: Dict) -> Dict:
        """Phase I: Asset discovery — subdomains, services, ports."""
        from phases.discovery import AssetDiscovery

        discovery = AssetDiscovery(self.config, self.db)
        phase_result = await discovery.run(
            domain=domain,
            domain_id=self._domain_id,
            scan_id=self._scan_id,
        )

        results["subdomains"] = phase_result.get("subdomains", [])
        results["services"] = phase_result.get("services", [])

        sub_count = len(results["subdomains"])
        svc_count = len(results["services"])
        logger.info(f"Discovery: {sub_count} subdomains, {svc_count} live services")

        if self.notifier:
            await self.notifier.send_message(
                f"📡 *Discovery Complete*\n"
                f"Subdomains: `{sub_count}`\n"
                f"Live services: `{svc_count}`"
            )

        return phase_result

    async def _run_audit(self, domain: str, results: Dict) -> Dict:
        """Phase II: Configuration & secret leakage auditing."""
        from phases.auditor import ConfigAuditor

        auditor = ConfigAuditor(self.config, self.db)
        services = results.get("services") or await self.db.get_services(self._domain_id)

        phase_result = await auditor.run(
            domain=domain,
            domain_id=self._domain_id,
            scan_id=self._scan_id,
            services=services,
        )

        # Alert on critical/high findings immediately
        await self._alert_new_findings()
        return phase_result

    async def _run_dast(self, domain: str, results: Dict) -> Dict:
        """Phase III: Dynamic Application Security Testing — scans ALL services."""
        from phases.dast import DASTScanner

        dast = DASTScanner(self.config, self.db)
        # Get ALL services from DB, not just current scan
        services = results.get("services") or await self.db.get_services(self._domain_id)

        # Also add any subdomains that have live services from DB
        all_db_services = await self.db.get_services(self._domain_id)
        if all_db_services:
            existing_urls = {s.get("url") for s in services}
            for svc in all_db_services:
                if svc.get("url") not in existing_urls:
                    services.append(svc)
                    existing_urls.add(svc.get("url"))

        logger.info(f"[DAST] Scanning {len(services)} total services")

        phase_result = await dast.run(
            domain=domain,
            domain_id=self._domain_id,
            scan_id=self._scan_id,
            services=services,
        )

        await self._alert_new_findings()
        return phase_result

    async def _run_reporting(self, domain: str, results: Dict) -> Dict:
        """Phase V: Generate compliance report."""
        from reports.generator import ReportGenerator

        generator = ReportGenerator(self.config, self.db)
        report_result = await generator.generate(
            domain=domain,
            scan_id=self._scan_id,
            results=results,
        )
        return report_result

    # ─── Alert Dispatch ───────────────────────────────────────────────────

    async def _alert_new_findings(self):
        """Send Telegram alerts for unalerted critical/high findings."""
        if not self.notifier:
            return

        unalerted = await self.db.get_findings(scan_id=self._scan_id, alerted=False)
        alert_severities = set(self.config.alert_on_severity)

        for finding in unalerted:
            if finding["severity"] in alert_severities:
                await self.notifier.send_finding_alert(finding)
                await self.db.mark_finding_alerted(finding["id"])

    # ─── Utilities ────────────────────────────────────────────────────────

    def _log_summary(self, domain: str, summary: Dict, elapsed: float):
        """Print final scan summary table."""
        logger.info("=" * 60)
        logger.info(f"  SCAN COMPLETE: {domain}")
        logger.info(f"  Duration: {elapsed:.1f}s")
        logger.info("-" * 60)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(sev, 0)
            if count:
                logger.info(f"  {sev.upper():10s}: {count}")
        logger.info("=" * 60)
