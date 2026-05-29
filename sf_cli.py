#!/usr/bin/env python3
"""
SentinelFlow — CLI Results Viewer
Query and display scan results without running a new scan.

Usage:
    python sf_cli.py scans                    # List all scans
    python sf_cli.py findings <scan_id>       # Show findings for a scan
    python sf_cli.py assets <scan_id>         # Show assets for a scan
    python sf_cli.py summary <scan_id>        # Show summary stats
    python sf_cli.py report <scan_id>         # Re-generate report for a scan
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.database import init_db, list_scans, get_findings, get_assets, get_scan, summary_stats
from phases.reporting.report_generator import generate_report


def _severity_colour(sev: str) -> str:
    colours = {
        "critical": "\033[91m",  # bright red
        "high":     "\033[93m",  # yellow
        "medium":   "\033[33m",  # orange
        "low":      "\033[94m",  # blue
        "info":     "\033[37m",  # grey
    }
    reset = "\033[0m"
    return f"{colours.get(sev, '')}[{sev.upper()}]{reset}"


def cmd_scans():
    scans = list_scans()
    if not scans:
        print("No scans in database. Run: python -m core.orchestrator <domain>")
        return
    print(f"\n{'ID':>4}  {'Seed':<30}  {'Status':<8}  {'Started':<20}  Findings")
    print("─" * 80)
    for s in scans:
        stats = summary_stats(s["id"])
        total = stats["total"]
        crits = stats["critical"]
        print(
            f"{s['id']:>4}  {s['seed']:<30}  {s['status']:<8}  "
            f"{(s['started_at'] or '')[:19]:<20}  "
            f"{total} total ({crits} critical)"
        )
    print()


def cmd_findings(scan_id: int):
    findings = get_findings(scan_id)
    if not findings:
        print(f"No findings for scan #{scan_id}")
        return
    print(f"\nFindings for scan #{scan_id} ({len(findings)} total):\n")
    for f in findings:
        print(f"  {_severity_colour(f['severity'])} [{f['phase']}] {f['title']}")
        if f["evidence"]:
            print(f"    → {f['evidence'][:100]}")
    print()


def cmd_assets(scan_id: int):
    assets = get_assets(scan_id)
    if not assets:
        print(f"No assets for scan #{scan_id}")
        return
    print(f"\nAssets for scan #{scan_id} ({len(assets)} total):\n")
    print(f"  {'FQDN':<40}  {'IP':<16}  {'HTTP':<5}  Ports")
    print("  " + "─" * 80)
    for a in assets:
        ports = json.loads(a["ports"] or "[]")
        alive = "✓" if a["http_alive"] else "✗"
        print(f"  {a['fqdn']:<40}  {(a['ip'] or '—'):<16}  {alive:<5}  {', '.join(map(str, ports)) or '—'}")
    print()


def cmd_summary(scan_id: int):
    scan  = get_scan(scan_id)
    stats = summary_stats(scan_id)
    if not scan:
        print(f"Scan #{scan_id} not found")
        return
    print(f"\n{'═'*40}")
    print(f"  Scan #{scan_id} — {scan['seed']}")
    print(f"{'═'*40}")
    print(f"  Status:   {scan['status']}")
    print(f"  Started:  {scan['started_at']}")
    print(f"  Finished: {scan['finished_at']}")
    print(f"  Assets:   {stats['asset_count']}")
    print(f"  ─────────────────")
    print(f"  Critical: {stats['critical']}")
    print(f"  High:     {stats['high']}")
    print(f"  Medium:   {stats['medium']}")
    print(f"  Low:      {stats['low']}")
    print(f"  Total:    {stats['total']}")
    print()


def cmd_report(scan_id: int):
    scan = get_scan(scan_id)
    if not scan:
        print(f"Scan #{scan_id} not found")
        return
    print(f"Generating report for scan #{scan_id}...")
    path = asyncio.run(generate_report(scan_id, scan["seed"]))
    print(f"Report saved to: {path}")


def main():
    init_db()

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "scans":
        cmd_scans()
    elif cmd == "findings" and len(sys.argv) >= 3:
        cmd_findings(int(sys.argv[2]))
    elif cmd == "assets" and len(sys.argv) >= 3:
        cmd_assets(int(sys.argv[2]))
    elif cmd == "summary" and len(sys.argv) >= 3:
        cmd_summary(int(sys.argv[2]))
    elif cmd == "report" and len(sys.argv) >= 3:
        cmd_report(int(sys.argv[2]))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
