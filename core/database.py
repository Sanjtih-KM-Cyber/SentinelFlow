"""
SentinelFlow Database Layer
SQLite-based persistent state management for assets, findings, and scan history.
"""

import sqlite3
import json
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from contextlib import asynccontextmanager
from pathlib import Path
import aiosqlite

from core.logger import get_logger

logger = get_logger(__name__)


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
-- Root domains under management
CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT UNIQUE NOT NULL,
    added_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scan   TIMESTAMP,
    scan_count  INTEGER DEFAULT 0,
    is_active   BOOLEAN DEFAULT 1
);

-- Discovered subdomains
CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id   INTEGER NOT NULL REFERENCES domains(id),
    subdomain   TEXT NOT NULL,
    source      TEXT,
    resolved_ip TEXT,
    first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active   BOOLEAN DEFAULT 1,
    UNIQUE(domain_id, subdomain)
);

-- Live HTTP/HTTPS services
CREATE TABLE IF NOT EXISTS services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id    INTEGER REFERENCES subdomains(id),
    url             TEXT NOT NULL UNIQUE,
    status_code     INTEGER,
    title           TEXT,
    server          TEXT,
    tech_stack      TEXT,    -- JSON array
    ports           TEXT,    -- JSON array of open ports
    tls_valid       BOOLEAN,
    tls_expiry      TEXT,
    cdn             TEXT,
    waf             TEXT,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active       BOOLEAN DEFAULT 1
);

-- Security findings / vulnerabilities
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER REFERENCES scans(id),
    service_id      INTEGER REFERENCES services(id),
    subdomain       TEXT,
    url             TEXT,
    phase           TEXT NOT NULL,   -- discovery, audit, dast
    severity        TEXT NOT NULL,   -- critical, high, medium, low, info
    category        TEXT,            -- sqli, xss, secrets, misconfiguration, etc.
    title           TEXT NOT NULL,
    description     TEXT,
    evidence        TEXT,            -- raw response snippet or proof
    remediation     TEXT,
    cvss_score      REAL,
    cve_id          TEXT,
    tool            TEXT,
    template        TEXT,
    alerted         BOOLEAN DEFAULT 0,
    false_positive  BOOLEAN DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan sessions
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    phases      TEXT,            -- JSON array
    status      TEXT DEFAULT 'running',  -- running, complete, failed, partial
    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    stats       TEXT             -- JSON: findings counts by severity
);

-- JavaScript secrets discovered
CREATE TABLE IF NOT EXISTS js_secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id  INTEGER REFERENCES services(id),
    js_url      TEXT NOT NULL,
    secret_type TEXT,   -- api_key, password, token, aws_key, etc.
    pattern     TEXT,   -- regex that matched
    matched     TEXT,   -- the matched value (may be truncated)
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(js_url, secret_type, matched)
);

-- Endpoints discovered (from JS, ffuf, crawling)
CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id  INTEGER REFERENCES services(id),
    url         TEXT NOT NULL,
    method      TEXT DEFAULT 'GET',
    params      TEXT,            -- JSON
    source      TEXT,            -- js_parser, ffuf, crawl, wayback
    status_code INTEGER,
    interesting BOOLEAN DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(service_id, url, method)
);

-- Cloud storage exposure results
CREATE TABLE IF NOT EXISTS cloud_exposure (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id   INTEGER REFERENCES domains(id),
    bucket_name TEXT,
    provider    TEXT,    -- aws, gcp, azure
    is_public   BOOLEAN,
    readable    BOOLEAN,
    writable    BOOLEAN,
    checked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(bucket_name, provider)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id);
CREATE INDEX IF NOT EXISTS idx_services_subdomain ON services(subdomain_id);
"""


class Database:
    """Async SQLite database interface for SentinelFlow."""

    def __init__(self, db_path: str = "sentinelflow.db"):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        """Open database connection and initialize schema."""
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        logger.info(f"Database connected: {self.db_path}")

    async def close(self):
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ─── Domain Management ────────────────────────────────────────────────

    async def upsert_domain(self, domain: str) -> int:
        """Insert or get a root domain. Returns domain ID."""
        async with self._conn.execute(
            "INSERT OR IGNORE INTO domains (domain) VALUES (?)", (domain,)
        ):
            pass
        await self._conn.commit()
        async with self._conn.execute(
            "SELECT id FROM domains WHERE domain = ?", (domain,)
        ) as cur:
            row = await cur.fetchone()
            return row["id"]

    async def update_domain_scan_time(self, domain_id: int):
        await self._conn.execute(
            "UPDATE domains SET last_scan = CURRENT_TIMESTAMP, scan_count = scan_count + 1 WHERE id = ?",
            (domain_id,)
        )
        await self._conn.commit()

    # ─── Subdomains ───────────────────────────────────────────────────────

    async def upsert_subdomain(
        self, domain_id: int, subdomain: str, source: str, resolved_ip: str = None
    ) -> Tuple[int, bool]:
        """
        Upsert subdomain. Returns (id, is_new).
        """
        async with self._conn.execute(
            "SELECT id FROM subdomains WHERE domain_id = ? AND subdomain = ?",
            (domain_id, subdomain)
        ) as cur:
            existing = await cur.fetchone()

        if existing:
            await self._conn.execute(
                "UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP, resolved_ip = COALESCE(?, resolved_ip) WHERE id = ?",
                (resolved_ip, existing["id"])
            )
            await self._conn.commit()
            return existing["id"], False
        else:
            async with self._conn.execute(
                "INSERT INTO subdomains (domain_id, subdomain, source, resolved_ip) VALUES (?, ?, ?, ?)",
                (domain_id, subdomain, source, resolved_ip)
            ) as cur:
                row_id = cur.lastrowid
            await self._conn.commit()
            return row_id, True

    async def get_subdomains(self, domain_id: int) -> List[Dict]:
        async with self._conn.execute(
            "SELECT * FROM subdomains WHERE domain_id = ? AND is_active = 1 ORDER BY subdomain",
            (domain_id,)
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ─── Services ─────────────────────────────────────────────────────────

    async def upsert_service(self, subdomain_id: int, data: Dict[str, Any]) -> Tuple[int, bool]:
        url = data.get("url")
        async with self._conn.execute(
            "SELECT id FROM services WHERE url = ?", (url,)
        ) as cur:
            existing = await cur.fetchone()

        tech_stack = json.dumps(data.get("tech_stack", []))
        ports = json.dumps(data.get("ports", []))

        if existing:
            await self._conn.execute(
                """UPDATE services SET
                    status_code = ?, title = ?, server = ?, tech_stack = ?,
                    ports = ?, tls_valid = ?, tls_expiry = ?, cdn = ?, waf = ?,
                    last_seen = CURRENT_TIMESTAMP, is_active = 1
                   WHERE id = ?""",
                (
                    data.get("status_code"), data.get("title"), data.get("server"),
                    tech_stack, ports, data.get("tls_valid"), data.get("tls_expiry"),
                    data.get("cdn"), data.get("waf"), existing["id"]
                )
            )
            await self._conn.commit()
            return existing["id"], False
        else:
            async with self._conn.execute(
                """INSERT INTO services
                   (subdomain_id, url, status_code, title, server, tech_stack, ports, tls_valid, tls_expiry, cdn, waf)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    subdomain_id, url, data.get("status_code"), data.get("title"),
                    data.get("server"), tech_stack, ports, data.get("tls_valid"),
                    data.get("tls_expiry"), data.get("cdn"), data.get("waf")
                )
            ) as cur:
                row_id = cur.lastrowid
            await self._conn.commit()
            return row_id, True

    async def get_services(self, domain_id: int = None) -> List[Dict]:
        if domain_id:
            async with self._conn.execute(
                """SELECT s.* FROM services s
                   JOIN subdomains sub ON s.subdomain_id = sub.id
                   WHERE sub.domain_id = ? AND s.is_active = 1""",
                (domain_id,)
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]
        else:
            async with self._conn.execute(
                "SELECT * FROM services WHERE is_active = 1"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    # ─── Findings ─────────────────────────────────────────────────────────

    async def insert_finding(self, finding: Dict[str, Any]) -> int:
        async with self._conn.execute(
            """INSERT INTO findings
               (scan_id, service_id, subdomain, url, phase, severity, category,
                title, description, evidence, remediation, cvss_score, cve_id, tool, template)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.get("scan_id"), finding.get("service_id"),
                finding.get("subdomain"), finding.get("url"),
                finding.get("phase"), finding.get("severity", "info"),
                finding.get("category"), finding.get("title"),
                finding.get("description"), finding.get("evidence"),
                finding.get("remediation"), finding.get("cvss_score"),
                finding.get("cve_id"), finding.get("tool"), finding.get("template")
            )
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_findings(
        self,
        scan_id: int = None,
        severity: str = None,
        min_severity: str = None,
        alerted: bool = None
    ) -> List[Dict]:
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        conditions = ["false_positive = 0"]
        params = []

        if scan_id:
            conditions.append("scan_id = ?")
            params.append(scan_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if alerted is not None:
            conditions.append("alerted = ?")
            params.append(1 if alerted else 0)

        where = " AND ".join(conditions)
        async with self._conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC",
            params
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        if min_severity:
            min_score = severity_order.get(min_severity.lower(), 0)
            rows = [r for r in rows if severity_order.get(r["severity"], 0) >= min_score]

        return rows

    async def mark_finding_alerted(self, finding_id: int):
        await self._conn.execute(
            "UPDATE findings SET alerted = 1 WHERE id = ?", (finding_id,)
        )
        await self._conn.commit()

    async def get_findings_summary(self, scan_id: int) -> Dict[str, int]:
        async with self._conn.execute(
            """SELECT severity, COUNT(*) as count FROM findings
               WHERE scan_id = ? AND false_positive = 0
               GROUP BY severity""",
            (scan_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {row["severity"]: row["count"] for row in rows}

    # ─── Scans ────────────────────────────────────────────────────────────

    async def create_scan(self, domain: str, phases: List[str]) -> int:
        async with self._conn.execute(
            "INSERT INTO scans (domain, phases) VALUES (?, ?)",
            (domain, json.dumps(phases))
        ) as cur:
            scan_id = cur.lastrowid
        await self._conn.commit()
        return scan_id

    async def complete_scan(self, scan_id: int, status: str = "complete", stats: Dict = None):
        await self._conn.execute(
            "UPDATE scans SET status = ?, finished_at = CURRENT_TIMESTAMP, stats = ? WHERE id = ?",
            (status, json.dumps(stats or {}), scan_id)
        )
        await self._conn.commit()

    async def get_scan(self, scan_id: int) -> Optional[Dict]:
        async with self._conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_recent_scans(self, limit: int = 10) -> List[Dict]:
        async with self._conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ─── JS Secrets ───────────────────────────────────────────────────────

    async def insert_js_secret(self, data: Dict) -> int:
        async with self._conn.execute(
            """INSERT OR IGNORE INTO js_secrets (service_id, js_url, secret_type, pattern, matched)
               VALUES (?, ?, ?, ?, ?)""",
            (data.get("service_id"), data.get("js_url"), data.get("secret_type"),
             data.get("pattern"), data.get("matched"))
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    # ─── Endpoints ────────────────────────────────────────────────────────

    async def upsert_endpoint(self, data: Dict) -> int:
        async with self._conn.execute(
            """INSERT OR IGNORE INTO endpoints (service_id, url, method, params, source, status_code)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (data.get("service_id"), data.get("url"), data.get("method", "GET"),
             json.dumps(data.get("params", {})), data.get("source"), data.get("status_code"))
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_endpoints(self, service_id: int = None) -> List[Dict]:
        if service_id:
            async with self._conn.execute(
                "SELECT * FROM endpoints WHERE service_id = ?", (service_id,)
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]
        async with self._conn.execute("SELECT * FROM endpoints") as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ─── Cloud Exposure ───────────────────────────────────────────────────

    async def upsert_cloud_exposure(self, data: Dict):
        await self._conn.execute(
            """INSERT OR REPLACE INTO cloud_exposure
               (domain_id, bucket_name, provider, is_public, readable, writable)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (data.get("domain_id"), data.get("bucket_name"), data.get("provider"),
             data.get("is_public"), data.get("readable"), data.get("writable"))
        )
        await self._conn.commit()
