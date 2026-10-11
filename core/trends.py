"""The weekly or monthly report: how the network did over a period and against the one before it, who the worst offenders
were, what keeps failing, what is still wrong now, what changed, and how the Windows computers are trending."""
import csv
import os
from datetime import datetime, timedelta
from html import escape

from core import backup, db, display, fleet, reports

PERIODS = [("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]
SCHEDULES = [("Off", ""), ("Every week", "weekly"), ("Every month", "monthly")]
FMT = "%Y-%m-%d %H:%M:%S"


def _pct(part, whole):
    return None if not whole else part / whole * 100


def _overall(stats):
    runs = sum(s["runs"] for s in stats.values())
    return {"runs": runs, "healthy": _pct(sum(s["healthy"] for s in stats.values()), runs),
            "reachable": _pct(sum(s["reachable"] for s in stats.values()), runs)}


def compute(days=7, now=None):
    """Everything the trend report says, as plain data."""
    now = now or datetime.now()
    start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    cur = db.availability(start=start.strftime(FMT), end=now.strftime(FMT))
    prev = db.availability(start=prev_start.strftime(FMT), end=start.strftime(FMT))
    names = {d["name"] for d in db.list_devices()}
    cur = {k: v for k, v in cur.items() if k in names}
    prev = {k: v for k, v in prev.items() if k in names}
    now_o, before_o = _overall(cur), _overall(prev)
    delta = None if now_o["healthy"] is None or before_o["healthy"] is None else now_o["healthy"] - before_o["healthy"]
    worst = sorted(((d, _pct(s["healthy"], s["runs"]), _pct(s["reachable"], s["runs"]), s["runs"],
                     None if d not in prev else _pct(prev[d]["healthy"], prev[d]["runs"])) for d, s in cur.items() if s["runs"]),
                   key=lambda r: (r[1], r[0].lower()))
    worst = [w for w in worst if w[1] < 100][:10]
    with db.connect() as c:
        failing = [(r["check_name"], r["n"], r["devices"]) for r in c.execute(
            "SELECT check_name, COUNT(*) n, COUNT(DISTINCT device) devices FROM results JOIN runs ON runs.id = results.run_id "
            "WHERE runs.started_at >= ? AND runs.started_at < ? AND results.status IN ('FAIL','ERROR') AND check_name != 'config backup' "
            "GROUP BY check_name ORDER BY n DESC, check_name LIMIT 10", (start.strftime(FMT), now.strftime(FMT)))]
        still = [(r["device"], r["check_name"], r["status"], r["since"]) for r in c.execute(
            "SELECT device, check_name, status, since FROM alert_state WHERE status != 'OK' ORDER BY since")]
        cpu = [(r["device"], r["a"], r["m"]) for r in c.execute(
            "SELECT device, AVG(cpu) a, MAX(cpu) m FROM agent_metrics WHERE at >= ? AND cpu IS NOT NULL GROUP BY device "
            "ORDER BY a DESC LIMIT 5", (start.strftime(FMT),))]
        growth = []
        for r in c.execute("SELECT DISTINCT device FROM agent_metrics WHERE at >= ?", (start.strftime(FMT),)).fetchall():
            first = c.execute("SELECT disk FROM agent_metrics WHERE device=? AND at >= ? AND disk IS NOT NULL ORDER BY at LIMIT 1",
                              (r["device"], start.strftime(FMT))).fetchone()
            last = c.execute("SELECT disk FROM agent_metrics WHERE device=? AND disk IS NOT NULL ORDER BY at DESC LIMIT 1", (r["device"],)).fetchone()
            if first and last and last["disk"] - first["disk"] >= 1:
                growth.append((r["device"], first["disk"], last["disk"], last["disk"] - first["disk"]))
        growth.sort(key=lambda g: -g[3])
        runs = c.execute("SELECT COUNT(*) FROM runs WHERE started_at >= ? AND started_at < ?", (start.strftime(FMT), now.strftime(FMT))).fetchone()[0]
    s = fleet.summary()
    return {"days": days, "start": start.strftime(FMT), "end": now.strftime(FMT), "runs": runs, "devices": len(cur),
            "healthy": now_o["healthy"], "reachable": now_o["reachable"], "previous": before_o["healthy"], "delta": delta,
            "worst": worst, "failing": failing, "still": still, "changes": len(backup.recent_changes(24 * days)),
            "busiest": cpu, "disk_growth": growth[:5], "certs": s["sections"]["certs"] if s else [],
            "silent": s["sections"]["silent"] if s else [], "computers": s["computers"] if s else 0}


def _fmt(p):
    return "-" if p is None else f"{p:.1f}%"


def _color(p):
    return reports.COLORS["OK" if p is None or p >= 99.5 else "WARN" if p >= 95 else "FAIL"]


def _table(head, rows, colors=None):
    th = "".join(f'<th align="left" bgcolor="#37474f"><font color="white">{escape(h)}</font></th>' for h in head)
    body = ""
    for r in rows:
        body += "<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in r) + "</tr>"
    return f'<table width="100%" cellpadding="4" cellspacing="0" border="1"><tr>{th}</tr>{body}</table>'


def to_html(data):
    title = (db.get_setting("report_title").strip() or "Toner Health Report") + f" - {data['days']}-day trend"
    org = db.get_setting("report_org").strip()
    h, d = data["healthy"], data["delta"]
    trend = "" if d is None else (f" ({'up' if d > 0.05 else 'down' if d < -0.05 else 'unchanged'}"
                                  + (f" {abs(d):.1f} points" if abs(d) > 0.05 else "") + f" on the {data['days']} days before)")
    parts = [f"<h1>{escape(title)}</h1>" + (f"<p><b>{escape(org)}</b></p>" if org else "")
             + f"<p>{escape(data['start'])} to {escape(data['end'])}: {data['runs']} run(s) over {data['devices']} device(s).</p>",
             f'<p style="font-size:16pt"><span style="background:{_color(h)}">&nbsp;Healthy {_fmt(h)}&nbsp;</span> '
             f"&nbsp;Reachable {_fmt(data['reachable'])}{escape(trend)}</p>"]
    parts.append("<h2>Worst offenders</h2>" + (_table(["Device", "Healthy", "Reachable", "Runs", "Before"],
                 [(w[0], _fmt(w[1]), _fmt(w[2]), w[3], _fmt(w[4])) for w in data["worst"]]) if data["worst"] else "<p>Every device was healthy in every run.</p>"))
    if data["failing"]:
        parts.append("<h2>What keeps failing</h2>" + _table(["Check", "Failures", "Devices"], [(display.check_name(c), n, k) for c, n, k in data["failing"]]))
    parts.append("<h2>Still wrong now</h2>" + (_table(["Device", "Check", "Status", "Since"], [(a, display.check_name(b), c, s) for a, b, c, s in data["still"]])
                                              if data["still"] else "<p>Nothing is open.</p>"))
    parts.append(f"<h2>Changes</h2><p>{data['changes']} configuration change(s) in the period.</p>")
    if data["certs"]:
        parts.append("<h2>Certificates running out</h2>" + _table(["Device", "Detail"], data["certs"]))
    if data["computers"]:
        parts.append(f"<h2>Windows computers ({data['computers']})</h2>")
        if data["silent"]:
            parts.append("<p><b>Not reporting:</b> " + escape(", ".join(x for x, _ in data["silent"])) + "</p>")
        if data["busiest"]:
            parts.append("<h3>Busiest by CPU</h3>" + _table(["Computer", "Average", "Peak"], [(a, f"{b:.0f}%", f"{c:.0f}%") for a, b, c in data["busiest"]]))
        if data["disk_growth"]:
            parts.append("<h3>Disks filling up</h3>" + _table(["Computer", "At start", "Now", "Growth"],
                         [(a, f"{b:.0f}%", f"{c:.0f}%", f"+{g:.1f} points") for a, b, c, g in data["disk_growth"]]))
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;margin-bottom:12px}"
           "td,th{border:1px solid #bbb;padding:4px 8px}")
    return (f"<html><head><meta charset='utf-8'><title>{escape(title)}</title><style>{css}</style></head><body>{''.join(parts)}"
            f"<p style='color:#777'>Made by Toner on {datetime.now():%Y-%m-%d %H:%M}.</p></body></html>")


def save_html(data, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_html(data))


def save_pdf(data, path):
    from PySide6.QtCore import QMarginsF
    from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
    w = QPdfWriter(path)
    w.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    w.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout.Unit.Millimeter)
    doc = QTextDocument()
    doc.setHtml(to_html(data))
    doc.print_(w)


def to_csv(data, path):
    """One row per device that was not perfect, plus the headline numbers."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Period", f"{data['start']} to {data['end']}"])
        w.writerow(["Healthy %", f"{data['healthy']:.1f}" if data["healthy"] is not None else ""])
        w.writerow(["Reachable %", f"{data['reachable']:.1f}" if data["reachable"] is not None else ""])
        w.writerow([])
        w.writerow(["Device", "Healthy %", "Reachable %", "Runs", "Healthy % before"])
        for d, h, r, n, b in data["worst"]:
            w.writerow([d, f"{h:.1f}", f"{r:.1f}", n, "" if b is None else f"{b:.1f}"])


# ---------------------------------------------------------------- on a schedule
def due(now=None):
    """True when the scheduled trend report should be made now (Settings > Reports)."""
    kind = db.get_setting("trend_schedule")
    if kind not in ("weekly", "monthly"):
        return False
    last = db.get_setting("trend_last")
    if not last:
        return True
    try:
        then = datetime.strptime(last, FMT)
    except ValueError:
        return True
    return (now or datetime.now()) - then >= timedelta(days=7 if kind == "weekly" else 28)


def generate_scheduled(now=None):
    """Make the report into the reports folder (Settings > Reports) and remember when. PDF when the program has a Qt application,
    else HTML (a service has no window system). Returns the path, or '' when there is nowhere to put it."""
    folder = db.get_setting("report_folder")
    if not folder or not os.path.isdir(folder):
        return ""
    now = now or datetime.now()
    data = compute(7 if db.get_setting("trend_schedule") == "weekly" else 30, now)
    stem = os.path.join(folder, f"Toner-trend-{now:%Y-%m-%d}")
    try:
        from PySide6.QtGui import QGuiApplication
        pdf = QGuiApplication.instance() is not None
    except Exception:
        pdf = False
    path = stem + (".pdf" if pdf else ".html")
    (save_pdf if pdf else save_html)(data, path)
    db.set_setting("trend_last", now.strftime(FMT))
    return path
