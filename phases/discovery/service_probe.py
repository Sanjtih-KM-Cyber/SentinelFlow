"""
Phase I — Service Fingerprinting
Uses httpx to verify live HTTP(S) services and naabu for port discovery.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from config.settings import HTTPX_BIN, NAABU_BIN, MAX_CONCURRENT_TASKS
from core.database import get_assets, upsert_asset

log = logging.getLogger("discovery.service_probe")

# Ports naabu scans by default (top common ports)
NAABU_TOP_PORTS = "80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,22,21,25,3306,5432,6379,27017"


async def run_service_probe(scan_id: int) -> None:
    """
    For all discovered assets:
    1. Run naabu to find open ports
    2. Run httpx to identify live HTTP services
    """
    assets = get_assets(scan_id)
    if not assets:
        log.warning("No assets to probe")
        return

    fqdns = [a["fqdn"] for a in assets]
    log.info("Probing %d hosts for open ports and HTTP services", len(fqdns))

    # Write targets to a temp file (tools accept -l <file>)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(fqdns))
        target_file = f.name

    # Run port scan and HTTP probe concurrently
    port_results, http_results = await asyncio.gather(
        _run_naabu(target_file),
        _run_httpx(target_file),
        return_exceptions=True,
    )

    # Persist results
    if isinstance(port_results, dict):
        for fqdn, ports in port_results.items():
            upsert_asset(scan_id, fqdn, ports=ports)
            log.debug("  %s open ports: %s", fqdn, ports)

    if isinstance(http_results, set):
        for fqdn in http_results:
            upsert_asset(scan_id, fqdn, http_alive=True)
            log.debug("  %s → HTTP alive", fqdn)

    alive_count = sum(1 for a in get_assets(scan_id) if a["http_alive"])
    log.info("Service probe complete — %d HTTP-alive hosts", alive_count)

    # Cleanup temp file
    Path(target_file).unlink(missing_ok=True)


async def _run_naabu(target_file: str) -> dict:
    """
    Run naabu port scanner. Returns dict of {fqdn: [port, ...]}
    """
    cmd = [
        NAABU_BIN,
        "-l", target_file,
        "-p", NAABU_TOP_PORTS,
        "-silent",
        "-json",
        "-timeout", "3",
        "-rate", "500",
    ]
    results: dict = {}
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        for line in stdout.decode(errors="ignore").splitlines():
            try:
                data = json.loads(line.strip())
                host = data.get("host", "").lower()
                port = data.get("port")
                if host and port:
                    results.setdefault(host, []).append(int(port))
            except (json.JSONDecodeError, ValueError):
                pass
        return results
    except FileNotFoundError:
        log.warning(
            "naabu not found at '%s'. Port scanning skipped. "
            "Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            NAABU_BIN,
        )
        return {}
    except asyncio.TimeoutError:
        log.warning("naabu timed out")
        return results


async def _run_httpx(target_file: str) -> set:
    """
    Run httpx to identify live HTTP/HTTPS services.
    Returns set of alive FQDNs (without scheme).
    """
    cmd = [
        HTTPX_BIN,
        "-l", target_file,
        "-silent",
        "-json",
        "-follow-redirects",
        "-timeout", "10",
        "-threads", str(MAX_CONCURRENT_TASKS * 4),
        "-status-code",
        "-title",
        "-tech-detect",
    ]
    alive: set = set()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        for line in stdout.decode(errors="ignore").splitlines():
            try:
                data = json.loads(line.strip())
                # httpx returns the URL; strip scheme to get fqdn
                url  = data.get("url", "")
                host = data.get("host", "") or _strip_scheme(url)
                if host:
                    alive.add(host.lower())
            except json.JSONDecodeError:
                pass
        return alive
    except FileNotFoundError:
        log.warning(
            "httpx not found at '%s'. HTTP probing skipped. "
            "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            HTTPX_BIN,
        )
        return set()
    except asyncio.TimeoutError:
        log.warning("httpx timed out")
        return alive


def _strip_scheme(url: str) -> str:
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            return url[len(prefix):].split("/")[0].split(":")[0]
    return url
