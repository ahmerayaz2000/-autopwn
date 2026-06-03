"""PDF report generator using ReportLab Platypus."""
import os
from datetime import datetime
from typing import List

from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.aggregator import Finding
from core.scorer import SEVERITY_ORDER, get_risk_summary

# ── Palette ───────────────────────────────────────────────────────────────────
_DARK   = HexColor("#1A1A2E")
_ACCENT = HexColor("#0F3460")
_MID    = HexColor("#16213E")

_SEV_FG = {
    "CRITICAL": HexColor("#C0392B"),
    "HIGH":     HexColor("#E74C3C"),
    "MEDIUM":   HexColor("#E67E22"),
    "LOW":      HexColor("#F39C12"),
    "INFO":     HexColor("#3498DB"),
}
_SEV_BG = {
    "CRITICAL": HexColor("#FADBD8"),
    "HIGH":     HexColor("#FDEDEC"),
    "MEDIUM":   HexColor("#FEF9E7"),
    "LOW":      HexColor("#FFFDE7"),
    "INFO":     HexColor("#EBF5FB"),
}
_GREY_ROW = HexColor("#F8F9FA")
_BORDER   = HexColor("#DEE2E6")
_BODY_FG  = HexColor("#2C3E50")
_MUTED    = HexColor("#7F8C8D")


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
    )


def _styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("H1", parent=base["Normal"], fontSize=15,
                             textColor=_ACCENT, spaceBefore=10, spaceAfter=5,
                             fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("H2", parent=base["Normal"], fontSize=11,
                             textColor=_MID, spaceBefore=7, spaceAfter=3,
                             fontName="Helvetica-Bold"),
        "body": ParagraphStyle("Body", parent=base["Normal"], fontSize=9,
                               leading=14, textColor=_BODY_FG),
        "small": ParagraphStyle("Small", parent=base["Normal"], fontSize=7,
                                leading=11, textColor=_MUTED),
        "center_white": ParagraphStyle("CW", parent=base["Normal"], fontSize=18,
                                       textColor=white, alignment=TA_CENTER,
                                       fontName="Helvetica-Bold"),
        "cover_sub": ParagraphStyle("CS", parent=base["Normal"], fontSize=12,
                                    textColor=HexColor("#BDC3C7"), alignment=TA_CENTER),
        "right_white": ParagraphStyle("RW", parent=base["Normal"], fontSize=8,
                                      textColor=HexColor("#BDC3C7"), alignment=TA_RIGHT),
        "bold_white": ParagraphStyle("BW", parent=base["Normal"], fontSize=10,
                                     textColor=white, fontName="Helvetica-Bold"),
        "code": ParagraphStyle("Code", parent=base["Normal"], fontSize=7,
                               leading=10, fontName="Courier",
                               textColor=HexColor("#C0392B"),
                               backColor=HexColor("#F5F5F5")),
        "disclaimer": ParagraphStyle("Disc", parent=base["Normal"], fontSize=7,
                                     textColor=_MUTED, alignment=TA_CENTER, leading=11),
    }


def generate(findings: List[Finding], target_url: str, output_path: str) -> None:
    print("[*] [Reporter] Generating PDF report...")
    summary = get_risk_summary(findings)
    s = _styles()
    W = 17 * cm  # usable page width

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    story = []

    story += _cover(target_url, summary, s, W)
    story.append(PageBreak())
    story += _exec_summary(findings, target_url, summary, s, W)
    story.append(PageBreak())
    story += _stats(findings, summary, s, W)
    story.append(PageBreak())
    story += _detailed_findings(findings, s, W)
    story.append(PageBreak())
    story += _remediation_table(findings, s, W)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    print(f"[+] [Reporter] Saved: {output_path}")


# ── Cover page ────────────────────────────────────────────────────────────────

def _cover(target_url, summary, s, W):
    elems = []

    def _banner_table(content, bg, height_pad=18):
        t = Table([[content]], colWidths=[W])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), bg),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0), (-1,-1), height_pad),
            ("BOTTOMPADDING", (0,0), (-1,-1), height_pad),
        ]))
        return t

    elems.append(_banner_table(Paragraph("AutoPwn", s["center_white"]), _DARK, 22))
    elems.append(Spacer(1, 0.3*cm))
    elems.append(_banner_table(Paragraph("Automated Web Penetration Test Report", s["cover_sub"]), _ACCENT, 10))
    elems.append(Spacer(1, 1*cm))

    rows = [
        ["Target URL",    target_url],
        ["Report Date",   datetime.now().strftime("%B %d, %Y  %H:%M:%S")],
        ["Risk Rating",   summary["overall_rating"]],
        ["Total Findings",str(summary["total_findings"])],
        ["Vulnerabilities",str(summary["vuln_count"])],
        ["Tool Version",  "AutoPwn v1.0"],
    ]
    detail_table = Table(rows, colWidths=[5*cm, W-5*cm])
    detail_table.setStyle(TableStyle([
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",    (0,0), (0,-1), _ACCENT),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[_GREY_ROW, white]),
        ("GRID",         (0,0), (-1,-1), 0.5, _BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]))
    elems.append(detail_table)
    elems.append(Spacer(1, 1*cm))

    rating = summary["overall_rating"]
    rating_table = Table(
        [[Paragraph(f"Overall Risk Rating:  {rating}", s["center_white"])]],
        colWidths=[W],
    )
    rating_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), _SEV_FG.get(rating, _ACCENT)),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
    ]))
    elems.append(rating_table)
    return elems


# ── Executive summary ─────────────────────────────────────────────────────────

def _exec_summary(findings, target_url, summary, s, W):
    elems = []
    elems.append(Paragraph("1. Executive Summary", s["h1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    elems.append(Spacer(1, 0.3*cm))

    intro = (
        f"AutoPwn performed an automated security assessment of <b>{_esc(target_url)}</b> on "
        f"{datetime.now().strftime('%B %d, %Y')}. "
        f"The scan identified <b>{summary['total_findings']} total findings</b>, of which "
        f"<b>{summary['vuln_count']} are security vulnerabilities</b>. "
        f"The overall risk rating is <b>{summary['overall_rating']}</b>."
    )
    elems.append(Paragraph(intro, s["body"]))
    elems.append(Spacer(1, 0.5*cm))

    descs = {
        "CRITICAL": "Immediate exploitation likely; severe business impact",
        "HIGH":     "Easily exploited; significant impact",
        "MEDIUM":   "Moderate difficulty to exploit; moderate impact",
        "LOW":      "Difficult to exploit or minimal impact",
        "INFO":     "Informational — no direct risk",
    }
    rows = [["Severity", "Count", "Description"]]
    for sev in SEVERITY_ORDER:
        rows.append([sev, str(summary["counts"].get(sev, 0)), descs[sev]])

    t = Table(rows, colWidths=[4*cm, 2*cm, W-6*cm])
    style = [
        ("BACKGROUND", (0,0), (-1,0), _MID),
        ("TEXTCOLOR",  (0,0), (-1,0), white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("ALIGN",      (1,0), (1,-1), "CENTER"),
        ("GRID",       (0,0), (-1,-1), 0.5, _BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING",(0,0), (-1,-1), 8),
    ]
    for i, sev in enumerate(SEVERITY_ORDER, 1):
        style += [
            ("BACKGROUND", (0,i), (0,i), _SEV_FG[sev]),
            ("TEXTCOLOR",  (0,i), (0,i), white),
            ("FONTNAME",   (0,i), (0,i), "Helvetica-Bold"),
            ("BACKGROUND", (1,i), (-1,i), _SEV_BG[sev]),
        ]
    t.setStyle(TableStyle(style))
    elems.append(t)
    return elems


# ── Statistics ────────────────────────────────────────────────────────────────

def _stats(findings, summary, s, W):
    elems = []
    elems.append(Paragraph("2. Scan Statistics", s["h1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    elems.append(Spacer(1, 0.3*cm))

    # Module breakdown
    modules: dict = {}
    for f in findings:
        modules.setdefault(f.module, {sv: 0 for sv in SEVERITY_ORDER})
        modules[f.module][f.severity] = modules[f.module].get(f.severity, 0) + 1

    elems.append(Paragraph("Findings by Module", s["h2"]))
    mod_rows = [["Module", "Crit", "High", "Med", "Low", "Info", "Total"]]
    for mod, cnts in modules.items():
        total = sum(cnts.values())
        mod_rows.append([
            mod.upper(),
            str(cnts.get("CRITICAL", 0)), str(cnts.get("HIGH", 0)),
            str(cnts.get("MEDIUM", 0)),   str(cnts.get("LOW", 0)),
            str(cnts.get("INFO", 0)),      str(total),
        ])
    cws = [4*cm, 2*cm, 2*cm, 2*cm, 2*cm, 2*cm, 3*cm]
    mod_t = Table(mod_rows, colWidths=cws)
    mod_t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), _MID),
        ("TEXTCOLOR",  (0,0), (-1,0), white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("ALIGN",      (1,0), (-1,-1), "CENTER"),
        ("GRID",       (0,0), (-1,-1), 0.5, _BORDER),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [_GREY_ROW, white]),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING",(0,0), (-1,-1), 6),
    ]))
    elems.append(mod_t)
    elems.append(Spacer(1, 0.5*cm))

    # All-findings index
    elems.append(Paragraph("All Findings Index", s["h2"]))
    idx_rows = [["#", "Severity", "Module", "Title", "CVSS"]]
    for i, f in enumerate(findings, 1):
        idx_rows.append([
            str(i),
            f.severity,
            f.module.upper(),
            _esc(f.title[:65] + ("…" if len(f.title) > 65 else "")),
            str(f.cvss) if f.cvss > 0 else "N/A",
        ])
    idx_t = Table(idx_rows, colWidths=[0.8*cm, 2.5*cm, 2.5*cm, 9.2*cm, 2*cm])
    idx_style = [
        ("BACKGROUND", (0,0), (-1,0), _MID),
        ("TEXTCOLOR",  (0,0), (-1,0), white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 7),
        ("ALIGN",      (0,0), (0,-1), "CENTER"),
        ("ALIGN",      (4,0), (4,-1), "CENTER"),
        ("GRID",       (0,0), (-1,-1), 0.5, _BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING",(0,0), (-1,-1), 4),
    ]
    for i, f in enumerate(findings, 1):
        idx_style += [
            ("TEXTCOLOR",  (1,i), (1,i), _SEV_FG.get(f.severity, _ACCENT)),
            ("FONTNAME",   (1,i), (1,i), "Helvetica-Bold"),
            ("BACKGROUND", (0,i), (-1,i), _SEV_BG.get(f.severity, white)
             if f.severity != "INFO" else white),
        ]
    idx_t.setStyle(TableStyle(idx_style))
    elems.append(idx_t)
    return elems


# ── Detailed findings ─────────────────────────────────────────────────────────

def _detailed_findings(findings, s, W):
    elems = []
    elems.append(Paragraph("3. Detailed Findings", s["h1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    elems.append(Spacer(1, 0.3*cm))

    vulns = [f for f in findings if f.severity != "INFO"]
    infos = [f for f in findings if f.severity == "INFO"]

    for f in vulns:
        elems += _finding_card(f, s, W)

    if infos:
        elems.append(Spacer(1, 0.5*cm))
        elems.append(Paragraph("Informational Findings", s["h2"]))
        for f in infos:
            elems += _finding_card(f, s, W)

    return elems


def _finding_card(f: Finding, s, W):
    elems = [Spacer(1, 0.25*cm)]
    fg = _SEV_FG.get(f.severity, _ACCENT)
    bg = _SEV_BG.get(f.severity, white)

    hdr = Table([
        [
            Paragraph(f"[{f.severity}] {_esc(f.title)}", s["bold_white"]),
            Paragraph(
                f"CVSS: {f.cvss if f.cvss > 0 else 'N/A'}  |  {f.module.upper()}",
                s["right_white"],
            ),
        ]
    ], colWidths=[11*cm, W-11*cm])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), fg),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    elems.append(hdr)

    body_rows = [
        [Paragraph("<b>Description</b>", s["body"]),
         Paragraph(_esc(f.description), s["body"])],
        [Paragraph("<b>Evidence</b>", s["body"]),
         Paragraph(
             f"<font name='Courier' size='7'>{_esc(f.evidence[:600])}</font>",
             s["body"],
         )],
        [Paragraph("<b>Remediation</b>", s["body"]),
         Paragraph(_esc(f.remediation) if f.remediation else "N/A", s["body"])],
    ]
    body_t = Table(body_rows, colWidths=[3*cm, W-3*cm])
    body_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("GRID",          (0,0), (-1,-1), 0.5, _BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
    ]))
    elems.append(body_t)
    return elems


# ── Remediation table ─────────────────────────────────────────────────────────

def _remediation_table(findings, s, W):
    elems = []
    elems.append(Paragraph("4. Remediation Summary", s["h1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    elems.append(Spacer(1, 0.3*cm))

    vulns = [f for f in findings if f.remediation and f.severity != "INFO"]
    if not vulns:
        elems.append(Paragraph("No actionable vulnerabilities found.", s["body"]))
    else:
        rows = [["#", "Severity", "Finding", "Remediation"]]
        for i, f in enumerate(vulns, 1):
            rows.append([
                str(i),
                f.severity,
                _esc(f.title[:45] + ("…" if len(f.title) > 45 else "")),
                _esc(f.remediation[:110] + ("…" if len(f.remediation) > 110 else "")),
            ])
        rem_t = Table(rows, colWidths=[0.8*cm, 2.5*cm, 5.5*cm, W-8.8*cm])
        rem_style = [
            ("BACKGROUND", (0,0), (-1,0), _MID),
            ("TEXTCOLOR",  (0,0), (-1,0), white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 7),
            ("ALIGN",      (0,0), (1,-1), "CENTER"),
            ("GRID",       (0,0), (-1,-1), 0.5, _BORDER),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [_GREY_ROW, white]),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0), (-1,-1), 5),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ]
        for i, f in enumerate(vulns, 1):
            rem_style += [
                ("TEXTCOLOR", (1,i), (1,i), _SEV_FG.get(f.severity, _ACCENT)),
                ("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"),
            ]
        rem_t.setStyle(TableStyle(rem_style))
        elems.append(rem_t)

    elems.append(Spacer(1, 1*cm))
    elems.append(Paragraph(
        "DISCLAIMER: This report was generated by AutoPwn for authorised security testing only. "
        "Unauthorised use against systems you do not own or lack explicit written permission to test "
        "is illegal and unethical.",
        s["disclaimer"],
    ))
    return elems


# ── Page footer ───────────────────────────────────────────────────────────────

def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_MUTED)
    canvas.drawRightString(19.5*cm, 1.2*cm, f"AutoPwn Security Report  —  Page {doc.page}")
    canvas.restoreState()
