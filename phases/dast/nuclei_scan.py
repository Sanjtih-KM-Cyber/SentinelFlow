"""
Phase III — Nuclei Template-Based Scanning
Cross-references services against known CVEs and misconfiguration templates.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path

from config.settings import (
    NUCLEI_BIN,
    NUCLEI_TEMPLATES_PATH,
    NUCLEI_SEVERITY_FILTER,
    MAX_CONCURRENT_TASKS,
)
from core.database import insert_finding

log = logging.getLogger("dast.nuclei")

# Nuclei severity → our internal severity (they match, but let's be explicit)
SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

# Template tags to prioritise
PRIORITY_TAGS = [
    "cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi",
    "auth-bypass", "default-login", "exposed-panel",
    "misconfiguration", "exposure", "takeover",
    "header-injection", "open-redirect",
]


async def run_nuclei_scan(scan_id: int, assets: list) -> None:
    """Run Nuclei against all HTTP-alive assets."""
    if not assets:
        log.warning("No assets to scan with Nuclei")
        return

    # Write targets to temp file
    targets = []
    for asset in assets:
        fqdn = asset["fqdn"]
        for scheme in ("https", "http"):
            targets.append(f"{scheme}://{fqdn}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        target_file = f.name

    log.info("Running Nuclei against %d targets (%d URLs)", len(assets), len(targets))

    findings = await _run_nuclei(target_file)

    # Map findings back to asset_id
    fqdn_to_id = {a["fqdn"]: a["id"] for a in assets}

    for finding in findings:
        host = finding.get("host", "").replace("https://", "").replace("http://", "").split("/")[0]
        asset_id = fqdn_to_id.get(host)
        sev = SEVERITY_MAP.get(finding.get("info", {}).get("severity", "info").lower(), "info")

        finding_id = insert_finding(
            scan_id=scan_id,
            asset_id=asset_id,
            phase="dast",
            category=f"nuclei:{finding.get('template-id', 'unknown')}",
            title=finding.get("info", {}).get("name", "Nuclei Finding"),
            severity=sev,
            detail=_format_detail(finding),
            evidence=finding.get("matched-at", finding.get("host", "")),
        )
        if finding_id:
            log.warning(
                "  [%s] %s — %s",
                sev.upper(),
                finding.get("template-id", "?"),
                finding.get("matched-at", host),
            )

    log.info("Nuclei scan complete — %d findings recorded", len(findings))
    Path(target_file).unlink(missing_ok=True)


async def _run_nuclei(target_file: str) -> list[dict]:
    """Execute Nuclei and parse JSONL output."""
    templates_path = Path(NUCLEI_TEMPLATES_PATH).expanduser()

    cmd = [
        NUCLEI_BIN,
        "-l", target_file,
        "-severity", NUCLEI_SEVERITY_FILTER,
        "-jsonl",                           # JSON Lines output
        "-silent",
        "-no-interactsh",                   # Disable OOB for safety
        "-timeout", "10",
        "-rate-limit", "100",               # Requests per second
        "-bulk-size", str(MAX_CONCURRENT_TASKS * 2),
        "-concurrency", str(MAX_CONCURRENT_TASKS),
        "-retries", "1",
        "-stats",
    ]

    # Add templates path if it exists
    if templates_path.exists():
        cmd.extend(["-t", str(templates_path)])
    else:
        log.info(
            "Nuclei templates not found at %s — using auto-download. "
            "Run 'nuclei -update-templates' to pre-fetch them.",
            templates_path,
        )

    # Add priority tags
    for tag in PRIORITY_TAGS:
        cmd.extend(["-tags", tag])

    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1800)  # 30 min max

        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Only keep findings with a real severity (skip pure info)
                sev = data.get("info", {}).get("severity", "").lower()
                if sev in ("critical", "high", "medium", "low"):
                    results.append(data)
            except json.JSONDecodeError:
                pass

        return results

    except FileNotFoundError:
        log.warning(
            "nuclei not found at '%s'. Template scanning skipped. "
            "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            NUCLEI_BIN,
        )
        return []
    except asyncio.TimeoutError:
        log.warning("Nuclei scan timed out")
        return results


def _format_detail(finding: dict) -> str:
    info = finding.get("info", {})
    parts = []

    description = info.get("description", "")
    if description:
        parts.append(f"Description: {description[:300]}")

    cve_ids = info.get("classification", {}).get("cve-id", [])
    if cve_ids:
        parts.append(f"CVEs: {', '.join(cve_ids)}")

    cvss = info.get("classification", {}).get("cvss-score")
    if cvss:
        parts.append(f"CVSS Score: {cvss}")

    remediation = info.get("remediation", "")
    if remediation:
        parts.append(f"Remediation: {remediation[:200]}")

    curl_cmd = finding.get("curl-command", "")
    if curl_cmd:
        parts.append(f"Reproduce: {curl_cmd[:200]}")

    return "\n".join(parts) if parts else "No additional detail."
