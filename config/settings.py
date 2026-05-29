"""
SentinelFlow — Central Configuration
All secrets are loaded from environment variables / .env file.
Never commit real credentials to version control.
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR    = BASE_DIR / "logs"

for _d in (DATA_DIR, REPORT_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "sentinelflow.db"

# ── External tool binaries ────────────────────────────────────────────────────
SUBFINDER_BIN = os.getenv("SUBFINDER_BIN", "subfinder")
HTTPX_BIN     = os.getenv("HTTPX_BIN",     "httpx")
NAABU_BIN     = os.getenv("NAABU_BIN",     "naabu")
NUCLEI_BIN    = os.getenv("NUCLEI_BIN",    "nuclei")
SQLMAP_BIN    = os.getenv("SQLMAP_BIN",    "sqlmap")
FFUF_BIN      = os.getenv("FFUF_BIN",      "ffuf")

# ── API keys (set in .env) ────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "PLACEHOLDER_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "PLACEHOLDER_CHAT_ID")

SHODAN_API_KEY        = os.getenv("SHODAN_API_KEY",        "PLACEHOLDER_SHODAN_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "PLACEHOLDER_ST_KEY")

# ── Scan behaviour ────────────────────────────────────────────────────────────
SCAN_TIMEOUT_SEC      = int(os.getenv("SCAN_TIMEOUT_SEC", "3600"))
MAX_CONCURRENT_TASKS  = int(os.getenv("MAX_CONCURRENT_TASKS", "5"))
RESCAN_INTERVAL_HOURS = int(os.getenv("RESCAN_INTERVAL_HOURS", "24"))

# ── Severity thresholds ───────────────────────────────────────────────────────
ALERT_ON_SEVERITIES = os.getenv(
    "ALERT_ON_SEVERITIES", "critical,high"
).lower().split(",")

SEVERITY_SCORE = {
    "critical": 10,
    "high":      7,
    "medium":    4,
    "low":       1,
    "info":      0,
}

# ── Nuclei templates ──────────────────────────────────────────────────────────
NUCLEI_TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "~/.local/nuclei-templates")
NUCLEI_SEVERITY_FILTER = os.getenv("NUCLEI_SEVERITY_FILTER", "critical,high,medium")

# ── FFuf wordlist ─────────────────────────────────────────────────────────────
FFUF_WORDLIST = os.getenv(
    "FFUF_WORDLIST",
    "/usr/share/wordlists/dirb/common.txt"
)

# ── S3 public-bucket check ────────────────────────────────────────────────────
S3_CHECK_ENABLED = os.getenv("S3_CHECK_ENABLED", "true").lower() == "true"
