"""
report.py — Exportable PDF threat report for WAFisGoingOn.

Generates a professional multi-page PDF containing:
  - Executive summary (totals, block rate, time window)
  - Attack pattern breakdown table + bar chart
  - Top attacking IPs
  - Hourly attack timeline
  - Recent blocked events log (last 100)

Requires: reportlab
"""

import io
import math
from datetime import datetime, timezone
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        BaseDocTemplate, Frame, HRFlowable, PageTemplate,
        Paragraph, Spacer, Table, TableStyle, KeepTogether,
    )
    from reportlab.platypus.flowables import Drawing
    from reportlab.graphics.shapes import (
        Drawing as RLDrawing, Rect, String, Line, Group,
    )
    from reportlab.graphics import renderPDF
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False


# ── Palette ───────────────────────────────────────────────────────────────────

class P:
    BG        = colors.HexColor("#0f1117")
    SURFACE   = colors.HexColor("#1a1d2e")
    BORDER    = colors.HexColor("#2d3048")
    TEXT      = colors.HexColor("#e2e8f0")
    MUTED     = colors.HexColor("#94a3b8")
    ACCENT    = colors.HexColor("#6366f1")
    RED       = colors.HexColor("#f87171")
    GREEN     = colors.HexColor("#34d399")
    YELLOW    = colors.HexColor("#fbbf24")
    WHITE     = colors.white
    BLACK     = colors.black
    DARK_ROW  = colors.HexColor("#1e2235")
    LIGHT_ROW = colors.HexColor("#252840")


PAGE_W, PAGE_H = A4
MARGIN = 1.8 * cm


# ── Helpers ───────────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontSize=22, textColor=P.WHITE,
                                fontName="Helvetica-Bold", spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontSize=10, textColor=P.MUTED,
                                   fontName="Helvetica", spaceAfter=16),
        "h2": ParagraphStyle("h2", fontSize=13, textColor=P.ACCENT,
                             fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("body", fontSize=9, textColor=P.TEXT,
                               fontName="Helvetica", leading=14),
        "mono": ParagraphStyle("mono", fontSize=8, textColor=P.TEXT,
                               fontName="Courier", leading=12),
        "muted": ParagraphStyle("muted", fontSize=8, textColor=P.MUTED,
                                fontName="Helvetica"),
        "center": ParagraphStyle("center", fontSize=9, textColor=P.TEXT,
                                 fontName="Helvetica", alignment=TA_CENTER),
        "badge_red":    ParagraphStyle("br", fontSize=8, textColor=P.RED,    fontName="Helvetica-Bold", alignment=TA_CENTER),
        "badge_green":  ParagraphStyle("bg", fontSize=8, textColor=P.GREEN,  fontName="Helvetica-Bold", alignment=TA_CENTER),
        "badge_yellow": ParagraphStyle("by", fontSize=8, textColor=P.YELLOW, fontName="Helvetica-Bold", alignment=TA_CENTER),
        "badge_muted":  ParagraphStyle("bm", fontSize=8, textColor=P.MUTED,  fontName="Helvetica-Bold", alignment=TA_CENTER),
    }


def _hr():
    return HRFlowable(width="100%", thickness=0.5,
                      color=P.BORDER, spaceAfter=8, spaceBefore=4)


def _tbl_style(header_bg=None) -> TableStyle:
    hbg = header_bg or P.ACCENT
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  hbg),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  P.WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  8),
        ("BOTTOMPADDING",(0, 0), (-1, 0),  6),
        ("TOPPADDING",   (0, 0), (-1, 0),  6),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("TEXTCOLOR",    (0, 1), (-1, -1), P.TEXT),
        ("ROWBACKGROUNDS",(0, 1),(-1, -1), [P.DARK_ROW, P.LIGHT_ROW]),
        ("BOTTOMPADDING",(0, 1), (-1, -1), 5),
        ("TOPPADDING",   (0, 1), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, P.BORDER),
        ("ROWHEIGHT",    (0, 0), (-1, -1), 18),
    ])


# ── Mini bar chart (pure ReportLab Drawing) ───────────────────────────────────

def _bar_chart(patterns: list[dict], width: float = 440, height: float = 160) -> Any:
    """Return a ReportLab Drawing containing a horizontal bar chart."""
    d = RLDrawing(width, height)

    visible = [p for p in patterns if p["count"] > 0]
    if not visible:
        d.add(String(width / 2, height / 2, "No blocked attacks recorded",
                     fontSize=10, fillColor=P.MUTED, textAnchor="middle"))
        return d

    max_count = max(p["count"] for p in visible)
    bar_h = min(20, (height - 20) / len(visible) - 4)
    bar_area = width - 160  # leave room for label + count

    for i, pattern in enumerate(visible):
        y = height - 20 - i * (bar_h + 6)
        bar_w = (pattern["count"] / max_count) * bar_area if max_count else 0
        fill = colors.HexColor(pattern["color"])

        # Label
        d.add(String(0, y + bar_h / 2 - 4, pattern["label"],
                     fontSize=8, fillColor=P.TEXT))
        # Bar
        d.add(Rect(120, y, bar_w, bar_h, fillColor=fill, strokeColor=None))
        # Count
        d.add(String(120 + bar_w + 6, y + bar_h / 2 - 4,
                     str(pattern["count"]),
                     fontSize=8, fillColor=P.MUTED))

    return d


# ── Summary stat boxes ────────────────────────────────────────────────────────

def _stat_table(stats: dict, styles: dict) -> Table:
    """Four-cell summary row."""
    block_rate = stats.get("block_rate", 0)
    rate_style = styles["badge_red"] if block_rate > 20 else styles["badge_yellow"]

    cells = [
        [Paragraph("TOTAL REQUESTS", styles["muted"]),
         Paragraph("BLOCKED",        styles["muted"]),
         Paragraph("ALLOWED",        styles["muted"]),
         Paragraph("BLOCK RATE",     styles["muted"])],
        [Paragraph(f"{stats.get('total', 0):,}",   styles["center"]),
         Paragraph(f"{stats.get('blocked', 0):,}", styles["badge_red"]),
         Paragraph(f"{stats.get('allowed', 0):,}", styles["badge_green"]),
         Paragraph(f"{block_rate}%",               rate_style)],
    ]
    t = Table(cells, colWidths=[(PAGE_W - 2 * MARGIN) / 4] * 4)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), P.SURFACE),
        ("BOX",           (0, 0), (-1, -1), 0.5, P.BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, P.BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE",      (0, 1), (-1, 1),  16),
        ("FONTNAME",      (0, 1), (-1, 1),  "Helvetica-Bold"),
        ("TEXTCOLOR",     (0, 1), (-1, 1),  P.WHITE),
    ]))
    return t


# ── Page template with dark background ───────────────────────────────────────

def _make_doc(buffer: io.BytesIO) -> BaseDocTemplate:
    def _on_page(canvas, doc):
        canvas.saveState()
        # Dark background
        canvas.setFillColor(P.BG)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # Footer
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(P.MUTED)
        canvas.drawString(MARGIN, 14 * mm,
                          f"WAFisGoingOn Threat Report  ·  Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(PAGE_W - MARGIN, 14 * mm, f"Page {doc.page}")
        # Top accent line
        canvas.setStrokeColor(P.ACCENT)
        canvas.setLineWidth(2)
        canvas.line(MARGIN, PAGE_H - 12 * mm, PAGE_W - MARGIN, PAGE_H - 12 * mm)
        canvas.restoreState()

    frame = Frame(MARGIN, 20 * mm, PAGE_W - 2 * MARGIN,
                  PAGE_H - 34 * mm, id="main")
    tpl   = PageTemplate(id="main", frames=[frame], onPage=_on_page)
    doc   = BaseDocTemplate(buffer, pagesize=A4, pageTemplates=[tpl],
                            title="WAFisGoingOn Threat Report",
                            author="WAFisGoingOn")
    return doc


# ── Public API ────────────────────────────────────────────────────────────────

def generate(stats: dict) -> bytes:
    """
    Generate a PDF threat report from a stats dict (as returned by WAFDetector.get_stats()).
    Returns raw PDF bytes.
    """
    if not _REPORTLAB:
        raise RuntimeError(
            "reportlab is not installed. Run: pip install reportlab"
        )

    buf = io.BytesIO()
    doc = _make_doc(buf)
    S   = _styles()
    story = []

    # ── Cover / header ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("🛡️ WAFisGoingOn", S["title"]))
    story.append(Paragraph(
        f"Threat Intelligence Report  ·  Generated {datetime.now(timezone.utc).strftime('%A, %d %B %Y at %H:%M UTC')}",
        S["subtitle"]
    ))
    story.append(_hr())
    story.append(Spacer(1, 0.3 * cm))

    # ── Executive summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["h2"]))
    story.append(_stat_table(stats, S))
    story.append(Spacer(1, 0.5 * cm))

    # ── Attack pattern breakdown ──────────────────────────────────────────────
    story.append(Paragraph("Attack Pattern Breakdown", S["h2"]))

    patterns = stats.get("attack_patterns", [])
    if patterns:
        # Bar chart
        chart = _bar_chart(patterns, width=PAGE_W - 2 * MARGIN - 2, height=180)
        story.append(chart)
        story.append(Spacer(1, 0.4 * cm))

        # Table
        pat_data = [["Attack Type", "Count", "% of Blocked", "Severity"]]
        blocked_total = stats.get("blocked", 1) or 1
        for p in patterns:
            pct = round(p["count"] / blocked_total * 100, 1) if blocked_total else 0
            severity = (
                "HIGH"   if p["name"] in ("sql_injection", "command_injection", "xxe", "ssrf") else
                "MEDIUM" if p["name"] in ("xss", "path_traversal", "template_injection") else
                "LOW"
            )
            sev_style = (
                S["badge_red"]    if severity == "HIGH"   else
                S["badge_yellow"] if severity == "MEDIUM" else
                S["badge_muted"]
            )
            pat_data.append([
                Paragraph(f"{p['icon']}  {p['label']}", S["body"]),
                Paragraph(str(p["count"]), S["center"]),
                Paragraph(f"{pct}%", S["center"]),
                Paragraph(severity, sev_style),
            ])

        col_w = PAGE_W - 2 * MARGIN
        pat_tbl = Table(pat_data,
                        colWidths=[col_w * 0.45, col_w * 0.15, col_w * 0.2, col_w * 0.2])
        pat_tbl.setStyle(_tbl_style())
        story.append(pat_tbl)
    else:
        story.append(Paragraph("No attack pattern data available.", S["muted"]))

    story.append(Spacer(1, 0.5 * cm))

    # ── Top attacking IPs ─────────────────────────────────────────────────────
    story.append(Paragraph("Top Attacking IPs", S["h2"]))
    top_ips = stats.get("top_ips", [])
    if top_ips:
        ip_data = [["IP Address", "Blocked Requests"]]
        for row in top_ips:
            ip_data.append([
                Paragraph(str(row.get("ip", "—")), S["mono"]),
                Paragraph(str(row.get("c",  "—")), S["center"]),
            ])
        col_w = PAGE_W - 2 * MARGIN
        ip_tbl = Table(ip_data, colWidths=[col_w * 0.6, col_w * 0.4])
        ip_tbl.setStyle(_tbl_style())
        story.append(ip_tbl)
    else:
        story.append(Paragraph("No attacking IPs recorded.", S["muted"]))

    story.append(Spacer(1, 0.5 * cm))

    # ── Recent blocked events ─────────────────────────────────────────────────
    story.append(Paragraph("Recent Blocked Events (last 100)", S["h2"]))
    recent = [e for e in stats.get("recent", []) if e.get("blocked")][:100]

    if recent:
        ev_data = [["Timestamp", "IP", "Method", "Surface", "Class", "Score"]]
        for e in recent:
            ts  = str(e.get("ts",     "—"))[:19].replace("T", " ")
            cls_name = e.get("attack_class", "unknown")
            from waf.classifier import get_class_meta
            meta = get_class_meta(cls_name)
            ev_data.append([
                Paragraph(ts,                           S["mono"]),
                Paragraph(str(e.get("ip",      "—")),  S["mono"]),
                Paragraph(str(e.get("method",  "—")),  S["center"]),
                Paragraph(str(e.get("surface", "—")),  S["center"]),
                Paragraph(f"{meta.icon} {meta.label}", S["muted"]),
                Paragraph(f"{e.get('score', 0):.3f}",  S["center"]),
            ])

        col_w = PAGE_W - 2 * MARGIN
        ev_tbl = Table(
            ev_data,
            colWidths=[col_w*0.22, col_w*0.18, col_w*0.1,
                       col_w*0.13, col_w*0.24, col_w*0.13],
            repeatRows=1,
        )
        ev_tbl.setStyle(_tbl_style())
        story.append(ev_tbl)
    else:
        story.append(Paragraph("No blocked events recorded yet.", S["muted"]))

    doc.build(story)
    return buf.getvalue()
