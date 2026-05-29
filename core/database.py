"""
SentinelFlow — Database Layer
Manages all persistent state: assets, scans, findings.
"""

import sqlite3
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from config.settings import DB_PATH

log = logging.getLogger(__name__)


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seed        TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending',  -- pending|running|done|error
    started_at  TEXT,
    finished_at TEXT,
    meta        TEXT    DEFAULT '{}'                 -- JSON extras
);

CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    fqdn         TEXT    NOT NULL,
    ip           TEXT,
    ports        TEXT    DEFAULT '[]',               -- JSON list of ints
    http_alive   INTEGER DEFAULT 0,                  -- 0|1
    first_seen   TEXT    NOT NULL,
    last_scanned TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_asset ON assets(scan_id, fqdn);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    asset_id    INTEGER REFERENCES assets(id),
    phase       TEXT    NOT NULL,  -- discovery|audit|dast
    category    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,  -- critical|high|medium|low|info
    detail      TEXT    DEFAULT '',
    evidence    TEXT    DEFAULT '',
    fingerprint TEXT    NOT NULL,  -- dedup hash
    alerted     INTEGER DEFAULT 0,
    created_at  TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding ON findings(scan_id, fingerprint);
"""


# ── Connection helper ─────────────────────────────────────────────────────────

@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    log.info("Database initialised at %s", DB_PATH)


# ── Scan helpers ──────────────────────────────────────────────────────────────

def create_scan(seed: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (seed, status, started_at) VALUES (?, 'running', ?)",
            (seed, _now()),
        )
        return cur.lastrowid


def finish_scan(scan_id: int, status: str = "done") -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status=?, finished_at=? WHERE id=?",
            (status, _now(), scan_id),
        )


def get_scan(scan_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()


def list_scans() -> list:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()


# ── Asset helpers ─────────────────────────────────────────────────────────────

def upsert_asset(scan_id: int, fqdn: str, **kwargs) -> int:
    """Insert or update an asset; return its id."""
    now = _now()
    ports = json.dumps(kwargs.get("ports", []))
    http_alive = int(kwargs.get("http_alive", False))
    ip = kwargs.get("ip", "")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO assets (scan_id, fqdn, ip, ports, http_alive, first_seen, last_scanned)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, fqdn) DO UPDATE SET
                ip=excluded.ip,
                ports=excluded.ports,
                http_alive=excluded.http_alive,
                last_scanned=excluded.last_scanned
            """,
            (scan_id, fqdn, ip, ports, http_alive, now, now),
        )
        row = conn.execute(
            "SELECT id FROM assets WHERE scan_id=? AND fqdn=?", (scan_id, fqdn)
        ).fetchone()
        return row["id"]


def get_assets(scan_id: int, http_alive_only: bool = False) -> list:
    query = "SELECT * FROM assets WHERE scan_id=?"
    params: list = [scan_id]
    if http_alive_only:
        query += " AND http_alive=1"
    with get_conn() as conn:
        return conn.execute(query, params).fetchall()


# ── Finding helpers ───────────────────────────────────────────────────────────

def insert_finding(
    scan_id: int,
    asset_id: Optional[int],
    phase: str,
    category: str,
    title: str,
    severity: str,
    detail: str = "",
    evidence: str = "",
) -> Optional[int]:
    """Insert a finding; silently ignore duplicates (same fingerprint). Returns id or None."""
    import hashlib
    fp = hashlib.sha256(
        f"{scan_id}:{phase}:{category}:{title}:{evidence[:120]}".encode()
    ).hexdigest()[:32]

    with get_conn() as conn:
        try:
            cur = conn.execute(
                """
                INSERT INTO findings
                    (scan_id, asset_id, phase, category, title, severity,
                     detail, evidence, fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, asset_id, phase, category, title, severity,
                 detail, evidence, fp, _now()),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None  # duplicate


def get_findings(
    scan_id: int,
    phase: Optional[str] = None,
    severity: Optional[str] = None,
    unalerted_only: bool = False,
) -> list:
    query = "SELECT * FROM findings WHERE scan_id=?"
    params: list = [scan_id]
    if phase:
        query += " AND phase=?"
        params.append(phase)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if unalerted_only:
        query += " AND alerted=0"
    query += " ORDER BY created_at DESC"
    with get_conn() as conn:
        return conn.execute(query, params).fetchall()


def mark_alerted(finding_ids: list[int]) -> None:
    if not finding_ids:
        return
    placeholders = ",".join("?" * len(finding_ids))
    with get_conn() as conn:
        conn.execute(
            f"UPDATE findings SET alerted=1 WHERE id IN ({placeholders})",
            finding_ids,
        )


# ── Utilities ─────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def summary_stats(scan_id: int) -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT severity, COUNT(*) as cnt
            FROM findings WHERE scan_id=?
            GROUP BY severity
            """,
            (scan_id,),
        ).fetchall()
        asset_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]

    counts = {r["severity"]: r["cnt"] for r in rows}
    return {
        "asset_count": asset_count,
        "critical": counts.get("critical", 0),
        "high":     counts.get("high",     0),
        "medium":   counts.get("medium",   0),
        "low":      counts.get("low",      0),
        "info":     counts.get("info",     0),
        "total":    sum(counts.values()),
    }
