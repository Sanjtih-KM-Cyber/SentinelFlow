"""
SentinelFlow Phase IV: Real-Time Incident Notification System
Telegram bot integration for alerts, scan triggering, and status reporting.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime

from core.config import Config
from core.logger import get_logger

logger = get_logger(__name__)

# Severity emoji map
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

CATEGORY_EMOJI = {
    "sql_injection": "💉",
    "cross_site_scripting": "📜",
    "exposed_file": "📁",
    "secret_exposure": "🔑",
    "cloud_misconfiguration": "☁️",
    "missing_security_header": "🛡️",
    "cors_misconfiguration": "🌐",
    "open_redirect": "↪️",
    "nuclei": "🧬",
    "information_disclosure": "📢",
}


class TelegramNotifier:
    """
    Telegram bot for real-time security alerts and interactive scan control.
    Supports:
    - Sending findings alerts based on severity
    - Scan status updates
    - Interactive bot commands to trigger and control scans
    """

    def __init__(self, config: Config):
        self.config = config
        self.token = config.telegram_token
        self.chat_id = config.telegram_chat
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self._last_update_id = 0
        self._running = False

    # ─── Message Sending ───────────────────────────────────────────────────

    async def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Send a plain message to the configured chat."""
        import aiohttp
        from utils.http_client import create_session

        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        async with create_session(self.config) as session:
            try:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        return True
                    else:
                        body = await resp.text()
                        logger.warning(f"Telegram send failed [{resp.status}]: {body[:200]}")
                        return False
            except Exception as e:
                logger.error(f"Telegram error: {e}")
                return False

    async def send_finding_alert(self, finding: Dict) -> bool:
        """Send a formatted security finding alert."""
        severity = finding.get("severity", "info")
        category = finding.get("category", "")
        sev_emoji = SEVERITY_EMOJI.get(severity, "⚪")
        cat_emoji = CATEGORY_EMOJI.get(category, "🔍")

        # Truncate long fields
        title = finding.get("title", "Unknown")[:100]
        url = finding.get("url", "N/A")[:200]
        description = (finding.get("description") or "")[:300]
        evidence = (finding.get("evidence") or "")[:200]

        message = (
            f"{sev_emoji} *SECURITY FINDING* {sev_emoji}\n"
            f"{'─' * 30}\n"
            f"{cat_emoji} *{title}*\n\n"
            f"*Severity:* `{severity.upper()}`\n"
            f"*Category:* `{category}`\n"
            f"*URL:* `{url}`\n\n"
        )

        if description:
            message += f"*Details:* {description}\n\n"

        if evidence:
            message += f"*Evidence:*\n```\n{evidence}\n```\n"

        if finding.get("cve_id"):
            message += f"*CVE:* `{finding['cve_id']}`\n"

        if finding.get("cvss_score"):
            message += f"*CVSS:* `{finding['cvss_score']}`\n"

        message += f"\n⏰ `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}`"

        return await self.send_message(message)

    async def send_scan_complete(
        self, domain: str, summary: Dict, elapsed: float
    ) -> bool:
        """Send a scan completion summary."""
        total = sum(summary.values())
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)

        status_emoji = "🚨" if critical > 0 else ("⚠️" if high > 0 else "✅")

        message = (
            f"{status_emoji} *Scan Complete*\n"
            f"{'─' * 30}\n"
            f"🌐 *Domain:* `{domain}`\n"
            f"⏱️ *Duration:* `{elapsed:.1f}s`\n\n"
            f"📊 *Findings Summary:*\n"
            f"  🔴 Critical: `{summary.get('critical', 0)}`\n"
            f"  🟠 High: `{summary.get('high', 0)}`\n"
            f"  🟡 Medium: `{summary.get('medium', 0)}`\n"
            f"  🔵 Low: `{summary.get('low', 0)}`\n"
            f"  ⚪ Info: `{summary.get('info', 0)}`\n"
            f"  ─────────────\n"
            f"  📋 Total: `{total}`\n"
        )

        return await self.send_message(message)

    async def send_phase_update(self, phase: str, status: str, details: str = "") -> bool:
        """Send a phase progress update."""
        phase_emoji = {
            "discovery": "📡",
            "audit": "🔍",
            "dast": "⚡",
            "report": "📄",
        }.get(phase, "▶️")

        status_emoji = "✅" if status == "complete" else ("▶️" if status == "running" else "❌")

        message = (
            f"{phase_emoji} *Phase {phase.upper()}* {status_emoji}\n"
            f"Status: `{status}`"
        )
        if details:
            message += f"\n{details}"

        return await self.send_message(message)

    # ─── Bot Mode (Interactive) ────────────────────────────────────────────

    async def start_bot(self):
        """Start interactive Telegram bot for receiving commands."""
        self._running = True
        logger.info("Telegram bot started. Listening for commands...")

        await self.send_message(
            "🤖 *SentinelFlow Bot Active*\n\n"
            "Available commands:\n"
            "• `/scan <domain>` - Start a new scan\n"
            "• `/status` - Show recent scans\n"
            "• `/findings <scan_id>` - List findings for a scan\n"
            "• `/stop` - Stop the bot\n"
            "• `/help` - Show this help"
        )

        while self._running:
            try:
                updates = await self._get_updates()
                for update in updates:
                    await self._handle_update(update)
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Bot error: {e}")
                await asyncio.sleep(5)

    async def _get_updates(self) -> List[Dict]:
        """Poll Telegram for new updates."""
        import aiohttp
        from utils.http_client import create_session

        url = f"{self.base_url}/getUpdates"
        params = {
            "offset": self._last_update_id + 1,
            "timeout": 30,
            "limit": 10,
        }

        async with create_session(self.config) as session:
            try:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=35),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        updates = data.get("result", [])
                        if updates:
                            self._last_update_id = updates[-1]["update_id"]
                        return updates
            except Exception as e:
                logger.debug(f"Get updates error: {e}")
        return []

    async def _handle_update(self, update: Dict):
        """Process a single Telegram update."""
        message = update.get("message", {})
        text = message.get("text", "").strip()
        chat_id = str(message.get("chat", {}).get("id", ""))

        # Security: only respond to configured chat
        if chat_id != str(self.chat_id):
            logger.warning(f"Ignoring message from unauthorized chat: {chat_id}")
            return

        if not text.startswith("/"):
            return

        parts = text.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handlers = {
            "/scan": self._cmd_scan,
            "/status": self._cmd_status,
            "/findings": self._cmd_findings,
            "/stop": self._cmd_stop,
            "/help": self._cmd_help,
        }

        handler = handlers.get(command)
        if handler:
            await handler(args)
        else:
            await self.send_message(f"Unknown command: `{command}`\nType /help for available commands.")

    async def _cmd_scan(self, args: str):
        """Handle /scan command."""
        domain = args.strip()
        if not domain:
            await self.send_message("Usage: `/scan <domain>`\nExample: `/scan example.com`")
            return

        # Basic validation
        import re
        if not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', domain):
            await self.send_message(f"❌ Invalid domain: `{domain}`")
            return

        await self.send_message(
            f"🚀 *Scan Queued*\n"
            f"Domain: `{domain}`\n\n"
            f"⚠️ *Authorization required.* Only submit domains you own or "
            f"have explicit written authorization to scan.\n\n"
            f"Starting scan in 5 seconds..."
        )

        await asyncio.sleep(5)

        # Launch scan in background
        asyncio.create_task(self._run_bot_scan(domain))

    async def _run_bot_scan(self, domain: str):
        """Execute a scan triggered from Telegram bot."""
        try:
            from core.orchestrator import SentinelOrchestrator
            orchestrator = SentinelOrchestrator(self.config)
            await orchestrator.initialize()
            await orchestrator.run_pipeline(domain=domain, phases=["discovery", "audit", "dast", "report"])
            await orchestrator.shutdown()
        except Exception as e:
            await self.send_message(f"❌ Scan failed for `{domain}`:\n```{str(e)[:200]}```")

    async def _cmd_status(self, args: str):
        """Handle /status command."""
        try:
            from core.database import Database
            db = Database(self.config.db_path)
            await db.connect()
            scans = await db.get_recent_scans(limit=5)
            await db.close()

            if not scans:
                await self.send_message("No scans found in database.")
                return

            lines = ["📊 *Recent Scans*\n"]
            for scan in scans:
                stats = json.loads(scan.get("stats") or "{}")
                total = sum(stats.values())
                status_emoji = "✅" if scan["status"] == "complete" else "⚠️"
                lines.append(
                    f"{status_emoji} ID `{scan['id']}` | `{scan['domain']}`\n"
                    f"   Status: `{scan['status']}` | Findings: `{total}`\n"
                    f"   Started: `{scan['started_at']}`"
                )

            await self.send_message("\n\n".join(lines))
        except Exception as e:
            await self.send_message(f"❌ Error fetching status: {e}")

    async def _cmd_findings(self, args: str):
        """Handle /findings <scan_id> command."""
        if not args.strip().isdigit():
            await self.send_message("Usage: `/findings <scan_id>`")
            return

        scan_id = int(args.strip())
        try:
            from core.database import Database
            db = Database(self.config.db_path)
            await db.connect()
            findings = await db.get_findings(scan_id=scan_id, min_severity="medium")
            await db.close()

            if not findings:
                await self.send_message(f"No medium+ findings for scan `{scan_id}`.")
                return

            lines = [f"🔍 *Findings for Scan #{scan_id}*\n"]
            for f in findings[:10]:  # Limit output
                emoji = SEVERITY_EMOJI.get(f["severity"], "⚪")
                lines.append(
                    f"{emoji} `{f['severity'].upper()}` — {f['title'][:60]}"
                )

            if len(findings) > 10:
                lines.append(f"\n_...and {len(findings) - 10} more_")

            await self.send_message("\n".join(lines))
        except Exception as e:
            await self.send_message(f"❌ Error fetching findings: {e}")

    async def _cmd_stop(self, args: str):
        """Handle /stop command."""
        await self.send_message("🛑 SentinelFlow bot stopping...")
        self._running = False

    async def _cmd_help(self, args: str):
        """Handle /help command."""
        await self.send_message(
            "🤖 *SentinelFlow Bot Help*\n\n"
            "*Commands:*\n"
            "• `/scan <domain>` — Start a full scan pipeline\n"
            "• `/status` — Show last 5 scans\n"
            "• `/findings <id>` — List findings for a scan ID\n"
            "• `/stop` — Shutdown the bot\n"
            "• `/help` — Show this message\n\n"
            "*Severity Levels:*\n"
            "🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Info\n\n"
            "⚠️ Only scan systems you own or are authorized to test."
        )
