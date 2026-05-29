"""
Phase III — Input Validation Testing (DAST)
Harvests URL parameters from live assets and runs non-destructive SQLi / XSS probes.
"""

import asyncio
import json
import logging
import re
import urllib.request
import urllib.parse
import ssl
from typing import Optional

from config.settings import SQLMAP_BIN, MAX_CONCURRENT_TASKS
from core.database import insert_finding

log = logging.getLogger("dast.input_validation")

# XSS probe payloads — deliberately non-destructive, observation-only
XSS_PROBES = [
    "<script>alert('SFXSS')</script>",
    "'\"><img src=x onerror=alert('SFXSS')>",
    "javascript:alert('SFXSS')",
    "<svg onload=alert('SFXSS')>",
]

# SQLi error signatures that indicate a vulnerability
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "unterminated string literal",
    "sqlstate",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "sqlite3::exception",
    "sqlite error",
]

XSS_REFLECTION_MARKERS = [
    "SFXSS",
    "alert('SFXSS')",
]


async def run_input_validation(scan_id: int, assets: list) -> None:
    """Harvest parameters from each asset and probe for SQLi / XSS."""
    sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    tasks = [_test_host(sem, scan_id, asset) for asset in assets]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _test_host(sem: asyncio.Semaphore, scan_id: int, asset) -> None:
    async with sem:
        fqdn     = asset["fqdn"]
        asset_id = asset["id"]

        for scheme in ("https", "http"):
            base_url = f"{scheme}://{fqdn}"
            param_urls = await _harvest_params(base_url)
            if param_urls:
                log.debug("  %s — testing %d parameterised URLs", fqdn, len(param_urls))
                for url in param_urls[:15]:  # Cap per host
                    await _probe_sqli(scan_id, asset_id, url)
                    await _probe_xss(scan_id, asset_id, url)
                # Also run SQLmap if available
                await _run_sqlmap(scan_id, asset_id, param_urls[:5])
                break


async def _harvest_params(base_url: str) -> list[str]:
    """
    Fetch the page and extract all links containing query parameters.
    In production, integrate with Wayback Machine API for historical URLs.
    """
    loop = asyncio.get_event_loop()
    try:
        html = await loop.run_in_executor(None, _fetch, base_url, 512_000)
        if not html:
            return []
        # Find href links with query strings
        links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', html, re.IGNORECASE)
        urls = []
        for link in links:
            if link.startswith("http"):
                urls.append(link)
            elif link.startswith("/"):
                urls.append(base_url.rstrip("/") + link)
        return list(set(urls))[:30]
    except Exception as exc:
        log.debug("Param harvest failed for %s: %s", base_url, exc)
        return []


async def _probe_sqli(scan_id: int, asset_id: int, url: str) -> None:
    """Inject a single-quote into each parameter and check for SQL errors."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    loop = asyncio.get_event_loop()
    for param_name in list(params.keys())[:5]:
        injected_params = dict(params)
        injected_params[param_name] = ["'"]
        new_query = urllib.parse.urlencode(injected_params, doseq=True)
        probe_url = parsed._replace(query=new_query).geturl()

        try:
            body = await loop.run_in_executor(None, _fetch, probe_url, 65_536)
            if not body:
                continue
            body_lower = body.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body_lower:
                    insert_finding(
                        scan_id=scan_id,
                        asset_id=asset_id,
                        phase="dast",
                        category="sqli",
                        title=f"Potential SQL Injection: parameter '{param_name}'",
                        severity="critical",
                        detail=f"SQL error signature '{sig}' detected in response.",
                        evidence=probe_url,
                    )
                    log.warning("  [CRITICAL] SQLi indicator — %s param=%s", probe_url, param_name)
                    break
        except Exception as exc:
            log.debug("SQLi probe error for %s: %s", probe_url, exc)


async def _probe_xss(scan_id: int, asset_id: int, url: str) -> None:
    """Inject XSS payloads and check for reflection in response."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    loop = asyncio.get_event_loop()
    for param_name in list(params.keys())[:5]:
        for payload in XSS_PROBES[:2]:  # Keep it lightweight
            injected_params = dict(params)
            injected_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(injected_params, doseq=True)
            probe_url = parsed._replace(query=new_query).geturl()

            try:
                body = await loop.run_in_executor(None, _fetch, probe_url, 65_536)
                if not body:
                    continue
                for marker in XSS_REFLECTION_MARKERS:
                    if marker in body:
                        insert_finding(
                            scan_id=scan_id,
                            asset_id=asset_id,
                            phase="dast",
                            category="xss",
                            title=f"Reflected XSS: parameter '{param_name}'",
                            severity="high",
                            detail=f"XSS payload reflected unescaped in response body.",
                            evidence=probe_url,
                        )
                        log.warning("  [HIGH] XSS reflection — %s param=%s", probe_url, param_name)
                        break
            except Exception as exc:
                log.debug("XSS probe error for %s: %s", probe_url, exc)


async def _run_sqlmap(scan_id: int, asset_id: int, urls: list[str]) -> None:
    """Run SQLmap in non-destructive mode against parameterised URLs."""
    for url in urls:
        cmd = [
            SQLMAP_BIN,
            "-u", url,
            "--batch",              # Non-interactive
            "--level=1",
            "--risk=1",             # Non-destructive
            "--timeout=10",
            "--retries=1",
            "--output-dir=/tmp/sqlmap_out",
            "--forms",
            "--crawl=1",
            "--json-output",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
            output = stdout.decode(errors="ignore")
            # Look for sqlmap's confirmation strings
            if "is vulnerable" in output.lower() or "sql injection" in output.lower():
                insert_finding(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    phase="dast",
                    category="sqli_confirmed",
                    title="Confirmed SQL Injection (sqlmap)",
                    severity="critical",
                    detail="SQLmap confirmed exploitable SQL injection.",
                    evidence=url,
                )
                log.warning("  [CRITICAL] SQLmap confirmed SQLi at %s", url)
        except FileNotFoundError:
            log.warning(
                "sqlmap not found at '%s'. Skipping deep SQLi validation. "
                "Install: pip install sqlmap",
                SQLMAP_BIN,
            )
            return
        except asyncio.TimeoutError:
            log.debug("sqlmap timed out for %s", url)


def _fetch(url: str, max_bytes: int) -> Optional[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (SentinelFlow/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.read(max_bytes).decode(errors="ignore")
    except Exception:
        return None
