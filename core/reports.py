"""CSV, HTML and PDF report generation."""
import csv
from datetime import datetime
from html import escape

from core import db, display

DEFAULT_COLORS = {"OK": "#c8e6c9", "WARN": "#fff3b0", "FAIL": "#ffcdd2", "ERROR": "#e0b0ff"}
COLOR_PRESETS = {
    "Default": DEFAULT_COLORS,
    # Blue / yellow / orange / purple differ in lightness as well as hue, so they stay distinct
    # for red-green colour blindness. The status word is always shown too.
    "Color-blind safe": {"OK": "#b3d9ff", "WARN": "#ffe08a", "FAIL": "#ffab76", "ERROR": "#cdb4f0"},
}
NA_COLOR = "#e0e0e0"                 # N/A (a check that does not apply): a quiet grey in every preset
COLORS = {**DEFAULT_COLORS, "N/A": NA_COLOR}   # the colours currently in use; modified in place by apply_colors()
ORDER = {"ERROR": 0, "FAIL": 1, "WARN": 2, "OK": 3, "N/A": 4}
COLS = ["Device", "Check", "Status", "Value", "Message"]

def apply_colors(preset="Default", custom=None):
    """Select a preset, then lay any individually chosen colours over it."""
    COLORS.clear()
    COLORS.update(COLOR_PRESETS.get(preset, DEFAULT_COLORS))
    COLORS.update({k: v for k, v in (custom or {}).items() if k in DEFAULT_COLORS})
    COLORS["N/A"] = NA_COLOR

def fg_for(bg_hex):
    """Dark text on light backgrounds, white on dark ones (WCAG relative luminance)."""
    h = bg_hex.lstrip("#")
    if len(h) != 6:
        return "#1a1a1a"
    lin = lambda c: (c / 255 / 12.92) if c / 255 <= 0.03928 else ((c / 255 + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(int(h[i:i + 2], 16)) for i in (0, 2, 4))
    return "#1a1a1a" if 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.18 else "#ffffff"

def _row(r):
    return [r.device, display.check_name(r.check), r.status, display.value(r.value), r.message]

def to_csv(results, path, scope="", when=None, title=None):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        w.writerows(_row(r) for r in results)

def _table(rows):
    head = "".join(f'<th align="left" bgcolor="#37474f"><font color="white">{c}</font></th>' for c in COLS)
    body = ""
    for r in rows:
        bg = COLORS.get(r.status, "#ffffff")
        cells = "".join(
            f'<td bgcolor="{bg}"><font color="{fg_for(bg)}">{escape(str(v))}</font></td>' for v in _row(r))
        body += f"<tr>{cells}</tr>"
    return f'<table width="100%" cellpadding="4" cellspacing="0" border="1">' \
           f"<tr>{head}</tr>{body}</table>"

def to_html(results, when=None, scope="", title=None):
    when = when or datetime.now().strftime("%Y-%m-%d %H:%M")
    if scope:
        when = f"{when} — {scope}"
    counts = {s: sum(r.status == s for r in results) for s in COLORS}
    summary = " &nbsp; ".join(
        f'<span style="background:{COLORS[s]};color:{fg_for(COLORS[s])};padding:2px 8px">{s}: {n}</span>'
        for s, n in counts.items())
    problems = sorted((r for r in results if r.status not in ("OK", "N/A")),
                      key=lambda r: (ORDER[r.status], r.device, r.check))
    title = title or db.get_setting("report_title").strip() or "Toner Health Report"
    org = db.get_setting("report_org").strip()
    org_line = f"<p><b>{escape(org)}</b></p>" if org else ""
    parts = [f"<h1>{escape(title)}</h1>{org_line}<p>Generated {escape(when)}</p><p>{summary}</p>"]
    parts.append("<h2>Needs attention</h2>" +
                 (_table(problems) if problems else "<p>No problems found.</p>"))
    if db.get_setting("report_include_all"):
        parts.append("<h2>All results by device</h2>")
        for dev in sorted({r.device for r in results}):
            parts.append(f"<h3>{escape(dev)}</h3>" + _table([r for r in results if r.device == dev]))
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}"
           "table{border-collapse:collapse;margin-bottom:12px}td,th{border:1px solid #bbb;padding:4px 8px}")
    return f"<html><head><meta charset='utf-8'><title>{escape(title)}</title>" \
           f"<style>{css}</style></head><body>{''.join(parts)}</body></html>"

def save_html(results, path, scope="", when=None, title=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_html(results, when=when, scope=scope, title=title))

def save_pdf(results, path, scope="", when=None, title=None):
    """Render the HTML report to PDF with Qt (no extra dependencies)."""
    from PySide6.QtCore import QMarginsF
    from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
    w = QPdfWriter(path)
    w.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    w.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout.Unit.Millimeter)
    doc = QTextDocument()
    doc.setHtml(to_html(results, when=when, scope=scope, title=title))
    doc.print_(w)
