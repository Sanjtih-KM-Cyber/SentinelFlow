"""
Phase V — Report Generator
Produces JSON and PDF compliance reports from scan findings.
PDF is generated via reportlab (pure-Python, no external tools needed).
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import REPORT_DIR, SEVERITY_SCORE
from core.database import get_scan, get_assets, get_findings, summary_stats

log = logging.getLogger("reporting.generator")


async def generate_report(scan_id: int, seed: str) -> Path:
    """Generate both JSON and PDF reports. Returns path to the PDF."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _generate_sync, scan_id, seed)


def _generate_sync(scan_id: int, seed: str) -> Path:
    scan     = get_scan(scan_id)
    assets   = get_assets(scan_id)
    findings = get_findings(scan_id)
    stats    = summary_stats(scan_id)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_seed = seed.replace(".", "_").replace("/", "_")
    base_name = f"sentinelflow_{safe_seed}_{timestamp}"

    # ── JSON report ───────────────────────────────────────────────────────────
    report_data = _build_json_report(scan, assets, findings, stats, seed)
    json_path   = REPORT_DIR / f"{base_name}.json"
    json_path.write_text(json.dumps(report_data, indent=2, default=str))
    log.info("JSON report written: %s", json_path)

    # ── PDF report ────────────────────────────────────────────────────────────
    pdf_path = REPORT_DIR / f"{base_name}.pdf"
    try:
        _generate_pdf(report_data, pdf_path)
        log.info("PDF report written: %s", pdf_path)
    except ImportError:
        log.warning("reportlab not installed — skipping PDF. Install: pip install reportlab")
    except Exception as exc:
        log.warning("PDF generation failed: %s", exc)

    return pdf_path if pdf_path.exists() else json_path


def _build_json_report(scan, assets, findings, stats: dict, seed: str) -> dict:
    """Assemble the full structured report dict."""
    # Sort findings by severity score descending
    sorted_findings = sorted(
        [dict(f) for f in findings],
        key=lambda f: SEVERITY_SCORE.get(f.get("severity", "info"), 0),
        reverse=True,
    )

    return {
        "report_meta": {
            "tool":         "SentinelFlow v1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id":      scan["id"],
            "seed":         seed,
            "scan_status":  scan["status"],
            "started_at":   scan["started_at"],
            "finished_at":  scan["finished_at"],
        },
        "executive_summary": {
            "target":           seed,
            "assets_discovered": stats["asset_count"],
            "total_findings":   stats["total"],
            "critical":         stats["critical"],
            "high":             stats["high"],
            "medium":           stats["medium"],
            "low":              stats["low"],
            "risk_rating":      _overall_risk(stats),
        },
        "assets": [
            {
                "fqdn":       a["fqdn"],
                "ip":         a["ip"],
                "ports":      json.loads(a["ports"] or "[]"),
                "http_alive": bool(a["http_alive"]),
                "first_seen": a["first_seen"],
            }
            for a in assets
        ],
        "findings": sorted_findings,
        "findings_by_phase": {
            "discovery": [f for f in sorted_findings if f.get("phase") == "discovery"],
            "audit":     [f for f in sorted_findings if f.get("phase") == "audit"],
            "dast":      [f for f in sorted_findings if f.get("phase") == "dast"],
        },
        "compliance_notes": _compliance_notes(sorted_findings),
    }


def _generate_pdf(report: dict, output_path: Path) -> None:
    """Render the report to PDF using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )

    SEV_COLORS = {
        "critical": colors.HexColor("#C0392B"),
        "high":     colors.HexColor("#E67E22"),
        "medium":   colors.HexColor("#F1C40F"),
        "low":      colors.HexColor("#3498DB"),
        "info":     colors.HexColor("#95A5A6"),
    }

    doc    = SimpleDocTemplate(str(output_path), pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    H1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=20, spaceAfter=6)
    H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, spaceAfter=4)
    BODY = styles["BodyText"]
    MONO = ParagraphStyle("Mono", parent=BODY, fontName="Courier", fontSize=8)

    meta = report["report_meta"]
    summ = report["executive_summary"]

    # Cover
    story += [
        Paragraph("🛡 SentinelFlow Security Report", H1),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2C3E50")),
        Spacer(1, 0.3*cm),
        Paragraph(f"<b>Target:</b> {meta['seed']}", BODY),
        Paragraph(f"<b>Scan ID:</b> #{meta['scan_id']}", BODY),
        Paragraph(f"<b>Generated:</b> {meta['generated_at'][:19]} UTC", BODY),
        Spacer(1, 0.5*cm),
    ]

    # Executive summary table
    story.append(Paragraph("Executive Summary", H2))
    summary_table_data = [
        ["Metric", "Value"],
        ["Overall Risk Rating", summ["risk_rating"]],
        ["Assets Discovered",   str(summ["assets_discovered"])],
        ["Total Findings",      str(summ["total_findings"])],
        ["Critical",            str(summ["critical"])],
        ["High",                str(summ["high"])],
        ["Medium",              str(summ["medium"])],
        ["Low",                 str(summ["low"])],
    ]
    tbl = Table(summary_table_data, colWidths=[8*cm, 8*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ECF0F1"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story += [tbl, Spacer(1, 0.5*cm)]

    # Findings table
    story.append(Paragraph("Findings", H2))
    findings = report["findings"]
    if findings:
        rows = [["#", "Severity", "Phase", "Title", "Evidence"]]
        for i, f in enumerate(findings[:100], 1):
            rows.append([
                str(i),
                f.get("severity", "?").upper(),
                f.get("phase", "?"),
                Paragraph(f.get("title", "")[:80], BODY),
                Paragraph(f.get("evidence", "")[:60], MONO),
            ])
        ftbl = Table(rows, colWidths=[0.7*cm, 1.8*cm, 2*cm, 8*cm, 5*cm])
        style = TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("GRID",        (0, 0), (-1, -1), 0.25, colors.HexColor("#BDC3C7")),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("PADDING",     (0, 0), (-1, -1), 4),
        ])
        # Colour-code severity rows
        for i, f in enumerate(findings[:100], 1):
            sev   = f.get("severity", "info")
            colour = SEV_COLORS.get(sev, colors.white)
            style.add("BACKGROUND", (1, i), (1, i), colour)
            style.add("TEXTCOLOR",  (1, i), (1, i), colors.white)
        ftbl.setStyle(style)
        story.append(ftbl)
    else:
        story.append(Paragraph("No findings recorded.", BODY))

    story += [Spacer(1, 0.5*cm), PageBreak()]

    # Assets
    story.append(Paragraph("Asset Inventory", H2))
    arows = [["FQDN", "IP", "Ports", "HTTP Alive"]]
    for a in report["assets"]:
        arows.append([
            a["fqdn"],
            a["ip"] or "—",
            ", ".join(str(p) for p in a["ports"]) or "—",
            "✓" if a["http_alive"] else "✗",
        ])
    atbl = Table(arows, colWidths=[7*cm, 3*cm, 4*cm, 3*cm])
    atbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ECF0F1"), colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.25, colors.HexColor("#BDC3C7")),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("PADDING",        (0, 0), (-1, -1), 4),
    ]))
    story.append(atbl)

    # Compliance notes
    notes = report.get("compliance_notes", [])
    if notes:
        story += [Spacer(1, 0.5*cm), Paragraph("Compliance Notes (OWASP Top 10)", H2)]
        for note in notes:
            story.append(Paragraph(f"• {note}", BODY))

    doc.build(story)


def _overall_risk(stats: dict) -> str:
    if stats["critical"] > 0:  return "CRITICAL"
    if stats["high"] > 0:      return "HIGH"
    if stats["medium"] > 0:    return "MEDIUM"
    if stats["low"] > 0:       return "LOW"
    return "MINIMAL"


def _compliance_notes(findings: list) -> list[str]:
    notes = []
    categories = {f.get("category", "") for f in findings}
    cats_str   = " ".join(categories)

    if "sqli" in cats_str:
        notes.append("OWASP A03 — Injection: SQL injection vulnerabilities detected. Parameterise all queries.")
    if "xss" in cats_str:
        notes.append("OWASP A03 — Injection: XSS vulnerabilities detected. Implement output encoding and CSP.")
    if "secret_exposure" in cats_str:
        notes.append("OWASP A02 — Cryptographic Failures: Hardcoded credentials in client-side code detected.")
    if "sensitive_exposure" in cats_str:
        notes.append("OWASP A05 — Security Misconfiguration: Sensitive files publicly accessible.")
    if "cloud_exposure" in cats_str:
        notes.append("OWASP A05 — Security Misconfiguration: Cloud storage buckets publicly accessible.")
    if "auth-bypass" in cats_str or "default-login" in cats_str:
        notes.append("OWASP A07 — Identification and Authentication Failures: Default or bypassable auth detected.")
    if not notes:
        notes.append("No critical OWASP Top 10 mappings triggered. Continue monitoring.")
    return notes
