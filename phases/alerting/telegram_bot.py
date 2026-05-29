"""
Phase IV — Telegram Alerting & Bot Interface
Sends prioritised security alerts and allows triggering scans via /scan <domain>.
"""

import asyncio
import json
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

from config.settings import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    ALERT_ON_SEVERITIES,
    SEVERITY_SCORE,
)

log = logging.getLogger("alerting.telegram")

# Severity → Telegram emoji prefix
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"


# ── Sending alerts ─────────────────────────────────────────────────────────────

async def send_finding_alert(finding) -> None:
    """Send a single finding as a Telegram message."""
    severity = finding["severity"]
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    text = (
        f"{emoji} *SentinelFlow Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Severity:* `{severity.upper()}`\n"
        f"*Phase:* `{finding['phase']}`\n"
        f"*Category:* `{finding['category']}`\n"
        f"*Title:* {_escape(finding['title'])}\n"
        f"*Evidence:* `{_escape(finding['evidence'][:200])}`\n"
    )
    if finding.get("detail"):
        text += f"*Detail:* {_escape(finding['detail'][:300])}\n"

    await _send_message(text, parse_mode="Markdown")


async def send_scan_summary(scan_id: int, seed: str, stats: dict) -> None:
    """Send a scan-complete summary card."""
    text = (
        f"✅ *Scan Complete — #{scan_id}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *Target:* `{seed}`\n"
        f"📦 *Assets discovered:* {stats['asset_count']}\n"
        f"🔎 *Total findings:* {stats['total']}\n\n"
        f"🔴 Critical: {stats['critical']}\n"
        f"🟠 High:     {stats['high']}\n"
        f"🟡 Medium:   {stats['medium']}\n"
        f"🔵 Low:      {stats['low']}\n"
    )
    await _send_message(text, parse_mode="Markdown")


async def send_plain(text: str) -> None:
    await _send_message(text)


async def _send_message(
    text: str,
    chat_id: str = TELEGRAM_CHAT_ID,
    parse_mode: str = "Markdown",
) -> bool:
    """POST a message to the Telegram Bot API."""
    if TELEGRAM_BOT_TOKEN == "PLACEHOLDER_BOT_TOKEN":
        log.debug("[Telegram mock] %s", text[:80])
        return True

    payload = json.dumps({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }).encode()

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, _post, f"{BASE_URL}/sendMessage", payload)
        return result
    except Exception as exc:
        log.warning("Telegram send failed: %s", exc)
        return False


def _post(url: str, payload: bytes) -> bool:
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        log.warning("Telegram HTTP %d: %s", e.code, e.read().decode(errors="ignore")[:200])
        return False


def _escape(text: str) -> str:
    """Escape Markdown special characters."""
    for ch in ("_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        text = text.replace(ch, f"\\{ch}")
    return text


# ── Bot listener (long polling) ────────────────────────────────────────────────

class SentinelBot:
    """
    Telegram bot that listens for /scan <domain> commands and triggers the pipeline.
    Run with: python -m phases.alerting.telegram_bot
    """

    def __init__(self):
        self._offset = 0
        self._running = False

    async def start(self):
        log.info("SentinelBot starting (long polling)...")
        self._running = True
        await send_plain("🤖 *SentinelFlow Bot online*\nSend /scan <domain> to start a scan\nSend /status to check recent scans")
        while self._running:
            try:
                updates = await self._get_updates()
                for update in updates:
                    await self._handle_update(update)
                    self._offset = update["update_id"] + 1
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Polling error: %s", exc)
                await asyncio.sleep(5)

    async def stop(self):
        self._running = False

    async def _get_updates(self) -> list:
        loop = asyncio.get_event_loop()
        url = (
            f"{BASE_URL}/getUpdates"
            f"?offset={self._offset}&timeout=30&allowed_updates=[\"message\"]"
        )
        try:
            raw = await loop.run_in_executor(None, _get, url)
            if not raw:
                return []
            data = json.loads(raw)
            return data.get("result", []) if data.get("ok") else []
        except Exception:
            return []

    async def _handle_update(self, update: dict) -> None:
        message = update.get("message", {})
        text    = message.get("text", "").strip()
        chat_id = str(message.get("chat", {}).get("id", TELEGRAM_CHAT_ID))

        if not text:
            return

        if text.startswith("/scan"):
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                await _send_message("Usage: /scan <domain>", chat_id=chat_id)
                return
            domain = parts[1].strip().lower()
            await _send_message(
                f"🚀 Starting scan for `{domain}`...\nYou'll be notified of critical findings in real time.",
                chat_id=chat_id,
            )
            # Import here to avoid circular imports
            from core.orchestrator import run_pipeline
            asyncio.create_task(run_pipeline(domain, notify=True))

        elif text.startswith("/status"):
            from core.database import list_scans
            scans = list_scans()[:5]
            if not scans:
                await _send_message("No scans yet. Use /scan <domain> to start.", chat_id=chat_id)
                return
            lines = ["📋 *Recent scans:*"]
            for s in scans:
                lines.append(f"  #{s['id']} `{s['seed']}` — {s['status']} ({s['started_at'][:10]})")
            await _send_message("\n".join(lines), chat_id=chat_id)

        elif text.startswith("/help"):
            help_text = (
                "🛡 *SentinelFlow Bot Commands*\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "/scan <domain> — Start a full EASM scan\n"
                "/status — Show last 5 scans\n"
                "/help — Show this message\n"
            )
            await _send_message(help_text, chat_id=chat_id)

        else:
            await _send_message(
                "Unknown command. Send /help for available commands.",
                chat_id=chat_id,
            )


def _get(url: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=35) as resp:
            return resp.read().decode(errors="ignore")
    except Exception:
        return None


# ── Standalone runner ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent.parent))
    from core.database import init_db
    init_db()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    bot = SentinelBot()
    asyncio.run(bot.start())
