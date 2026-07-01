"""
PDF report builder using ReportLab.

The LLM writes executive summary and remediation narratives.
All tabular structure (control tables, finding lists, gap counts)
is generated here in Python — never by the LLM.
"""
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

from app.core.agents.reporting_agent import write_executive_summary, write_remediation
from app.core.nist.mapper import compute_and_store_gaps, get_controls
from app.models.models import Finding

REPORTS_DIR = Path("reports")
Framework = Literal["nist_csf", "iso27001"]

_FRAMEWORK_LABELS = {
    "nist_csf": "NIST Cybersecurity Framework (CSF)",
    "iso27001": "ISO/IEC 27001:2022",
}


def _make_styles():
    base = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=base["Title"], fontSize=20, spaceAfter=12)
    h1 = ParagraphStyle("H1", parent=base["Heading1"], fontSize=14, spaceAfter=8)
    h2 = ParagraphStyle("H2", parent=base["Heading2"], fontSize=11, spaceAfter=6)
    body = ParagraphStyle("Body", parent=base["Normal"], fontSize=9, spaceAfter=4)
    return title, h1, h2, body


def _severity_color(severity: str) -> colors.Color:
    return {
        "critical": colors.HexColor("#d32f2f"),
        "high": colors.HexColor("#f57c00"),
        "medium": colors.HexColor("#fbc02d"),
        "low": colors.HexColor("#388e3c"),
    }.get(severity, colors.grey)


def _clean_llm_text(text: str) -> str:
    """Convert LLM markdown-ish output into clean paragraph text for PDFs."""
    if not text:
        return ""

    cleaned = text.strip()
    # Remove common markdown heading/bold/code tokens.
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("__", "")
    cleaned = cleaned.replace("`", "")
    # Replace bullet prefixes with simple sentence separators.
    cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned, flags=re.MULTILINE)
    # Normalize wrapped newlines into readable paragraphs.
    cleaned = re.sub(r"\r\n?", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"(?<!\n)\n(?!\n)", " ", cleaned)
    # Collapse excess spaces but keep paragraph breaks.
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


def _to_pdf_paragraph(text: str) -> str:
    """Convert paragraph breaks to ReportLab-friendly markup."""
    return text.replace("\n\n", "<br/><br/>")


async def build_report(
    findings: list[Finding],
    gaps: dict[str, list[str]],
    framework: Framework,
    session,
) -> str:
    REPORTS_DIR.mkdir(exist_ok=True)
    report_id = uuid.uuid4()
    path = REPORTS_DIR / f"{framework}_{report_id}.pdf"

    title_style, h1_style, h2_style, body_style = _make_styles()

    critical_count = sum(1 for f in findings if f.severity_label == "critical")
    high_count = sum(1 for f in findings if f.severity_label == "high")
    kev_count = sum(1 for f in findings if f.cisa_kev)

    stats = (
        f"Total findings: {len(findings)} | Critical: {critical_count} | "
        f"High: {high_count} | CISA KEV: {kev_count} | "
        f"Gapped controls: {len(gaps)}"
    )
    gap_summary = "\n".join(
        f"{ctrl}: {len(fids)} finding(s)" for ctrl, fids in sorted(gaps.items())
    )

    exec_summary = await write_executive_summary(
        framework=_FRAMEWORK_LABELS.get(framework, framework),
        gap_summary=gap_summary,
        stats=stats,
    )
    exec_summary = _clean_llm_text(exec_summary)

    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
    )
    story = []

    story.append(Paragraph(f"RAGScan Compliance Gap Report", title_style))
    story.append(Paragraph(
        f"{_FRAMEWORK_LABELS.get(framework, framework)} | "
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        body_style,
    ))
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Executive Summary", h1_style))
    story.append(Paragraph(_to_pdf_paragraph(exec_summary), body_style))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Finding Statistics", h1_style))
    stats_data = [
        ["Metric", "Count"],
        ["Total Findings", str(len(findings))],
        ["Critical", str(critical_count)],
        ["High", str(high_count)],
        ["CISA KEV (Actively Exploited)", str(kev_count)],
        ["Gapped Controls", str(len(gaps))],
    ]
    stats_table = Table(stats_data, colWidths=[100 * mm, 50 * mm])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Compliance Gaps", h1_style))
    for ctrl_id, finding_ids in sorted(gaps.items()):
        ctrl_findings = [f for f in findings if str(f.id) in finding_ids]
        if not ctrl_findings:
            continue

        ctrl_finding = ctrl_findings[0]
        controls = get_controls(ctrl_finding.cwe_id, ctrl_finding.severity_label, framework)
        ctrl_desc = next((c["description"] for c in controls if c["control_id"] == ctrl_id), ctrl_id)

        story.append(Paragraph(f"Control: {ctrl_id}", h2_style))
        story.append(Paragraph(ctrl_desc, body_style))

        finding_rows = [["Finding ID", "CVE", "Severity", "Risk Score", "Host"]]
        for f in sorted(ctrl_findings, key=lambda x: -(x.risk_score or 0)):
            finding_rows.append([
                str(f.id)[:8] + "...",
                f.cve_id or "N/A",
                f.severity_label.upper(),
                str(f.risk_score or "N/A"),
                f.hostname or f.host_ip or "N/A",
            ])

        finding_table = Table(finding_rows, colWidths=[40 * mm, 35 * mm, 25 * mm, 20 * mm, 40 * mm])
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#546e7a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        story.append(finding_table)

        findings_text = "\n".join(
            f"[{f.id}] {f.title} | {f.cve_id or 'N/A'} | Risk: {f.risk_score}"
            for f in ctrl_findings[:5]
        )
        narrative = await write_remediation(
            framework=_FRAMEWORK_LABELS.get(framework, framework),
            control_id=ctrl_id,
            control_desc=ctrl_desc,
            findings_text=findings_text,
        )
        narrative = _clean_llm_text(narrative)
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("Remediation Guidance", h2_style))
        story.append(Paragraph(_to_pdf_paragraph(narrative), body_style))
        story.append(Spacer(1, 4 * mm))

    doc.build(story)
    return str(path)
