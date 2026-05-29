"""
Phase I — Subdomain Enumeration
Uses subfinder for passive API-based discovery, then validates with DNS resolution.
"""

import asyncio
import json
import logging
import socket
from typing import Optional

from config.settings import SUBFINDER_BIN, MAX_CONCURRENT_TASKS
from core.database import upsert_asset

log = logging.getLogger("discovery.subdomain")


async def run_subdomain_enum(scan_id: int, seed: str) -> list[str]:
    """
    Enumerate subdomains for the given seed domain.
    Returns list of discovered FQDNs.
    """
    log.info("Running subfinder on %s", seed)
    subdomains = await _run_subfinder(seed)

    # Always include the seed itself
    subdomains = list({seed, *subdomains})
    log.info("Discovered %d subdomains (including seed)", len(subdomains))

    # Resolve IPs concurrently
    sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    tasks = [_resolve_and_store(sem, scan_id, fqdn) for fqdn in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)

    return subdomains


async def _run_subfinder(seed: str) -> list[str]:
    """Execute subfinder and parse its JSON-lines output."""
    cmd = [
        SUBFINDER_BIN,
        "-d", seed,
        "-silent",
        "-json",
        "-all",           # Use all passive sources
        "-timeout", "30",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        subdomains = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                fqdn = data.get("host", "").strip().lower()
                if fqdn:
                    subdomains.append(fqdn)
            except json.JSONDecodeError:
                # Plain text fallback
                subdomains.append(line.lower())

        return subdomains

    except FileNotFoundError:
        log.warning(
            "subfinder not found at '%s'. "
            "Falling back to seed-only discovery. "
            "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            SUBFINDER_BIN,
        )
        return []
    except asyncio.TimeoutError:
        log.warning("subfinder timed out for %s", seed)
        return []


async def _resolve_and_store(
    sem: asyncio.Semaphore, scan_id: int, fqdn: str
) -> Optional[str]:
    """DNS-resolve a FQDN and persist the asset."""
    async with sem:
        ip = await _dns_resolve(fqdn)
        upsert_asset(scan_id, fqdn, ip=ip or "")
        if ip:
            log.debug("  %s → %s", fqdn, ip)
        else:
            log.debug("  %s → (no DNS record)", fqdn)
        return ip


async def _dns_resolve(fqdn: str) -> Optional[str]:
    """Non-blocking DNS resolution; returns first A record or None."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
        )
        return result[0][4][0] if result else None
    except (socket.gaierror, OSError):
        return None
