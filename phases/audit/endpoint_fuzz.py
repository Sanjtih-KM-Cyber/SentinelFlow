"""
Phase II — Endpoint Fuzzing
Uses FFuf to discover sensitive files: .env, .git, config files, backups.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path

from config.settings import FFUF_BIN, FFUF_WORDLIST
from core.database import upsert_asset, insert_finding

log = logging.getLogger("audit.endpoint_fuzz")

# High-value targets that FFuf should prioritise (supplement the wordlist)
SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".svn/entries",
    "config.php", "config.yml", "config.yaml", "config.json",
    "wp-config.php", "wp-config.php.bak",
    "database.yml", "database.json",
    "settings.py", "settings.local.py",
    "app.config", "web.config",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "dump.sql",
    "admin/", "phpmyadmin/", "adminer.php",
    "server-status", "server-info",
    "actuator", "actuator/env", "actuator/health",
    "actuator/mappings", "actuator/beans",
    "api/swagger.json", "api/openapi.json", "swagger.json",
    "swagger-ui.html", "api-docs",
    "debug", "console", "trace",
    "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "package.json", "composer.json",
    "Dockerfile", "docker-compose.yml",
    ".DS_Store",
]

# Severity mapping based on what was found
SEVERITY_MAP = {
    ".env":        "critical",
    ".git":        "critical",
    ".svn":        "high",
    "config":      "high",
    "backup":      "high",
    "sql":         "high",
    "wp-config":   "critical",
    "database":    "high",
    "actuator":    "high",
    "swagger":     "medium",
    "openapi":     "medium",
    "debug":       "medium",
    "console":     "medium",
    "admin":       "medium",
    "phpmyadmin":  "high",
}


async def run_endpoint_fuzz(scan_id: int, assets: list) -> None:
    """Fuzz all HTTP-alive assets for sensitive paths."""
    tasks = [_fuzz_host(scan_id, asset) for asset in assets]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _fuzz_host(scan_id: int, asset) -> None:
    fqdn = asset["fqdn"]
    asset_id = asset["id"]

    # Try both HTTPS and HTTP
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{fqdn}"
        findings = await _run_ffuf(base_url)
        if findings:
            for finding in findings:
                sev = _classify_severity(finding["path"])
                insert_finding(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    phase="audit",
                    category="sensitive_exposure",
                    title=f"Sensitive path exposed: {finding['path']}",
                    severity=sev,
                    detail=f"HTTP {finding['status']} — {finding['size']} bytes",
                    evidence=f"{base_url}/{finding['path']}",
                )
                log.warning(
                    "  [%s] %s → %s/%s (HTTP %d)",
                    sev.upper(), fqdn, base_url, finding["path"], finding["status"],
                )
            break  # Don't double-report if HTTPS found things


async def _run_ffuf(base_url: str) -> list[dict]:
    """Run FFuf against base_url; return list of {path, status, size}."""
    # Write our curated sensitive paths + wordlist into a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(SENSITIVE_PATHS))
        tmp_wordlist = f.name

    cmd = [
        FFUF_BIN,
        "-u", f"{base_url}/FUZZ",
        "-w", f"{tmp_wordlist}:FUZZ",
        "-mc", "200,201,204,301,302,403",  # Interesting status codes
        "-of", "json",
        "-o", "/dev/stdout",
        "-t", "10",            # Threads
        "-timeout", "8",
        "-ac",                 # Auto-calibrate to filter false positives
        "-silent",
    ]

    # Append the system wordlist if it exists
    wordlist = Path(FFUF_WORDLIST)
    if wordlist.exists():
        cmd.extend(["-w", f"{FFUF_WORDLIST}:FUZZ"])

    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = stdout.decode(errors="ignore").strip()
        if raw:
            try:
                data = json.loads(raw)
                for r in data.get("results", []):
                    results.append({
                        "path":   r.get("input", {}).get("FUZZ", ""),
                        "status": r.get("status", 0),
                        "size":   r.get("length", 0),
                    })
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        log.warning(
            "ffuf not found at '%s'. Endpoint fuzzing skipped. "
            "Install: go install github.com/ffuf/ffuf/v2@latest",
            FFUF_BIN,
        )
    except asyncio.TimeoutError:
        log.debug("ffuf timed out for %s", base_url)
    finally:
        Path(tmp_wordlist).unlink(missing_ok=True)

    return results


def _classify_severity(path: str) -> str:
    path_lower = path.lower()
    for keyword, severity in SEVERITY_MAP.items():
        if keyword in path_lower:
            return severity
    return "low"
