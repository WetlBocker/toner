"""CSV, HTML and PDF report generation."""
import csv
import re
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
WIDTHS = (14, 24, 8, 12, 42)         # per cent of the page: the message carries the finding, so it gets the most
SCAN = "scan"                        # kind: the Scanning tab's vulnerability report (landscape, a line per device, every device listed)
SOFTWARE, KEV, HARDENING = "software version", "known exploited (CISA)", "Hardening: "       # as core/advisories and core/hardening name them
ADVISORY = re.compile(r"^(cisco-sa-|CVE-\d)")

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

def to_csv(results, path, scope="", when=None, title=None, kind=None):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        w.writerows(_row(r) for r in results)

def _table(rows):
    head = "".join(f'<th width="{w}%" align="left" bgcolor="#37474f"><font color="white">{c}</font></th>' for c, w in zip(COLS, WIDTHS))
    body = ""
    for r in rows:
        bg = COLORS.get(r.status, "#ffffff")
        cells = ""
        for i, v in enumerate(_row(r)):
            if i == 2:                                            # only the Status cell is coloured; the rest stays readable
                cells += f'<td bgcolor="{bg}"><font color="{fg_for(bg)}"><b>{escape(str(v))}</b></font></td>'
            else:
                cells += f"<td>{escape(str(v))}</td>"
        body += f"<tr>{cells}</tr>"
    return f'<table width="100%" cellpadding="3" cellspacing="0" border="1" bordercolor="#bbbbbb"><tr>{head}</tr>{body}</table>'

def _anchor(device):
    return "dev-" + re.sub(r"[^\w-]+", "-", device)

def _problems(rows):
    """'2 FAIL, 1 WARN', or 'all OK'."""
    n = {s: sum(r.status == s for r in rows) for s in ("ERROR", "FAIL", "WARN")}
    return ", ".join(f"{v} {s}" for s, v in n.items() if v) or "all OK"

def _scan_line(rows):
    """One line under a device's heading in the vulnerability report: version, advisories, CISA, hardening."""
    version = next((r.value for r in rows if r.check == SOFTWARE), "")
    adv = [r for r in rows if ADVISORY.match(r.check)]
    hard = [r for r in rows if r.check.startswith(HARDENING)]
    parts = [f"Version {display.value(version) if version else 'unknown'}"]
    if adv:
        parts.append(f"{len(adv)} advisor{'y' if len(adv) == 1 else 'ies'} ({_problems(adv)})")
    elif any(r.check == SOFTWARE and r.status == "OK" for r in rows):
        parts.append("no known advisories")
    if any(r.check == KEV and r.status == "FAIL" for r in rows):
        parts.append("on CISA's known exploited list")
    if hard:
        flagged = sum(r.status in ("FAIL", "WARN") for r in hard)
        parts.append(f"hardening: {flagged} of {len(hard)} rules flagged" if flagged else f"hardening: all {len(hard)} rules kept")
    return " · ".join(parts)

def to_html(results, when=None, scope="", title=None, kind=None):
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
    sections = kind == SCAN or db.get_setting("report_include_all")
    devices = sorted({r.device for r in results})
    if sections:                                                  # the first page lists every device, each a link to its section
        parts.append("<h2>Devices</h2><p>" + "<br>".join(
            f'<a href="#{_anchor(d)}">{escape(d)}</a> &nbsp; {_problems([r for r in results if r.device == d])}' for d in devices) + "</p>")
    parts.append('<h2 style="page-break-before: always">Needs attention</h2>' +
                 (_table(problems) if problems else "<p>No problems found.</p>"))
    if sections:
        parts.append("<h2>All results by device</h2>")
        for dev in devices:
            rows = [r for r in results if r.device == dev]
            line = f"<p>{escape(_scan_line(rows))}</p>" if kind == SCAN else ""
            parts.append(f'<h3><a name="{_anchor(dev)}" style="color:#222;text-decoration:none">{escape(dev)}</a></h3>{line}' + _table(rows))
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;font-size:9pt}"
           "table{border-collapse:collapse;margin-bottom:12px;table-layout:fixed}td,th{border:1px solid #bbb;padding:3px 6px;vertical-align:top;overflow-wrap:anywhere}"
           "a{color:#1a5fb4}")
    return f"<html><head><meta charset='utf-8'><title>{escape(title)}</title>" \
           f"<style>{css}</style></head><body>{''.join(parts)}</body></html>"

def save_html(results, path, scope="", when=None, title=None, kind=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_html(results, when=when, scope=scope, title=title, kind=kind))

def save_pdf(results, path, scope="", when=None, title=None, kind=None):
    """Render the HTML report to PDF with Qt (no extra dependencies): A4, landscape for the vulnerability report, 9-point type."""
    from PySide6.QtCore import QMarginsF
    from PySide6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument
    w = QPdfWriter(path)
    w.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    w.setPageOrientation(QPageLayout.Orientation.Landscape if kind == SCAN else QPageLayout.Orientation.Portrait)
    w.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout.Unit.Millimeter)
    doc = QTextDocument()
    doc.setDefaultFont(QFont("Segoe UI", 9))
    doc.setHtml(to_html(results, when=when, scope=scope, title=title, kind=kind))
    doc.print_(w)
