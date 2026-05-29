"""
SentinelFlow Logger
Structured, colored logging for the pipeline.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
WHITE = "\033[97m"

SEVERITY_COLORS = {
    "critical": RED + BOLD,
    "high": RED,
    "medium": YELLOW,
    "low": CYAN,
    "info": GREEN,
    "unknown": DIM,
}


class SentinelFormatter(logging.Formatter):
    """Custom formatter with colors and severity-aware styling."""

    LEVEL_STYLES = {
        logging.DEBUG: DIM + "[DBG]" + RESET,
        logging.INFO: CYAN + "[INF]" + RESET,
        logging.WARNING: YELLOW + "[WRN]" + RESET,
        logging.ERROR: RED + "[ERR]" + RESET,
        logging.CRITICAL: RED + BOLD + "[CRT]" + RESET,
    }

    def format(self, record: logging.LogRecord) -> str:
        level_str = self.LEVEL_STYLES.get(record.levelno, "[???]")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        module = f"{DIM}{record.name.split('.')[-1]}{RESET}"
        message = record.getMessage()

        # Color-code finding severity keywords in messages
        for severity, color in SEVERITY_COLORS.items():
            if severity.upper() in message:
                message = message.replace(severity.upper(), f"{color}{severity.upper()}{RESET}")

        return f"{DIM}{timestamp}{RESET} {level_str} {module}: {message}"


class FileFormatter(logging.Formatter):
    """Plain formatter for file output."""
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        return f"{timestamp} [{record.levelname}] {record.name}: {record.getMessage()}"


# Module-level registry
_loggers: dict = {}
_initialized: bool = False


def initialize_logging(verbose: bool = False, log_file: str = None):
    """Initialize the logging system. Call once at startup."""
    global _initialized
    if _initialized:
        return

    root = logging.getLogger("sentinelflow")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(SentinelFormatter())
    root.addHandler(console)

    # File handler
    if log_file is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / f"sentinelflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(FileFormatter())
    root.addHandler(file_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Get a named logger under the sentinelflow namespace."""
    if not _initialized:
        initialize_logging()

    if name not in _loggers:
        # Strip full module path to just component name
        short_name = name.replace("sentinelflow.", "")
        logger = logging.getLogger(f"sentinelflow.{short_name}")
        _loggers[name] = logger

    return _loggers[name]


def log_finding(logger: logging.Logger, severity: str, title: str, details: dict):
    """Structured log for security findings."""
    color = SEVERITY_COLORS.get(severity.lower(), "")
    sev_label = f"{color}[{severity.upper()}]{RESET}"
    logger.warning(f"FINDING {sev_label} {title} | {details}")
