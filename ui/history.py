import math
from datetime import datetime, timedelta

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import db, display
from core.reports import COLORS, fg_for
from ui import theme
from ui.widgets import GroupPicker, StatusDelegate, flow

PCT_CHECKS = ("cpu", "memory")


SERIES_COLORS = ["#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16", "#f97316"]


def is_percent(check):
    return check.split(" (")[0] in PCT_CHECKS + ("sessions",) or check.startswith("channel util")


def fmt_value(check, v):
    """A measured value the way a person would read it."""
    base = check.split(" (")[0]
    plain = lambda x, nd: f"{x:,.{nd}f}".rstrip("0").rstrip(".") if "." in f"{x:,.{nd}f}" else f"{x:,.{nd}f}"
    if is_percent(check):
        return plain(v, 1) + "%"
    if base == "temperature":
        return plain(v, 1) + " \u00b0C"
    if base == "uptime":
        return display.uptime(v)
    return plain(v, 2)


def is_uptime(check):
    return check.split(" (")[0] == "uptime"


def uptime_axis(peak_hours):
    """Grid lines for an uptime chart at round numbers of hours or days: [(hours, label)], the last one at or above the peak."""
    steps = (1, 2, 3, 6, 12, 24, 48, 72, 168, 336, 720, 1440, 2160, 4320, 8760)      # an hour up to a year
    want = max(float(peak_hours) * 1.05, 1.0)
    step = next((s for s in steps if want / s <= 5), math.ceil(want / 5 / 8760) * 8760)
    top = math.ceil(want / step) * step
    label = (lambda h: f"{h:g} h") if step < 24 else (lambda h: f"{h / 24:g} d")
    return float(top), [(k * step, label(k * step)) for k in range(int(round(top / step)) + 1)]


def restarts(points):
    """The times a device restarted: where its uptime fell from one run to the next. [(time, uptime before, uptime after)]."""
    out = []
    for (_, before), (stamp, after) in zip(points, points[1:]):
        if after < before - 0.02:                         # more than a minute less than last time
            out.append((stamp, before, after))
    return out


def uptime_caption(points):
    """'Up for 27:12:03:45, since 2026-09-14 08:12. Restarted 2 times in this period.' for one device's uptime."""
    if not points:
        return ""
    stamp, hours = points[-1]
    text = f"Up for {display.uptime(hours)}"
    try:
        text += ", since " + (datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S") - timedelta(hours=hours, seconds=-30)).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        pass
    n = len(restarts(points))
    return text + (f".  Restarted {n} time{'s' if n != 1 else ''} in this period." if n else ".  No restarts in this period.")


def scale_key(check, points):
    """Checks that can share one vertical axis: all the percentages, then plain numbers by order of magnitude."""
    if is_percent(check):
        return (0, 0)
    if is_uptime(check):
        return (2, 0)                                      # uptime is a time, not a count: its own chart, in days
    peak = max((abs(v) for _, v in points), default=0)
    return (1, int(math.floor(math.log10(peak))) if peak >= 1 else 0)


def scale_title(key):
    if key[0] == 0:
        return "Percent"
    if key[0] == 2:
        return "Uptime (days:hours:minutes:seconds)"
    lo = 10 ** key[1]
    return "Values up to 10" if key[1] == 0 else f"Values {lo:,} to {lo * 10:,}"


class TrendChart(QWidget):
    """One chart: one or more checks that share a vertical axis. Hover to read the measured values."""

    def __init__(self, title=""):
        super().__init__()
        self.title = title
        self.series, self.th = [], None            # series: [(check name, [(time, value)], colour)]
        self.hover = None                          # index of the run under the mouse
        self._geom = None                          # plot area and time axis from the last paint
        self.setMouseTracking(True)
        self.setMinimumSize(320, 230)

    def set_series(self, series, th=None, title=None):
        if title is not None:
            self.title = title
        self.series = [s for s in series if s[1]]
        self.th = th if len(self.series) == 1 else None      # thresholds only make sense for one check
        self.hover = None
        self.update()

    # ---------- hover ----------
    def mouseMoveEvent(self, e):
        g = self._geom
        if not g:
            return
        r, stamps = g["rect"], g["stamps"]
        pos = e.position()
        if r.adjusted(-14, -10, 14, 10).contains(pos):
            n = len(stamps)
            i = round((pos.x() - r.left()) / r.width() * (n - 1)) if n > 1 else 0
            i = max(0, min(n - 1, i))
        else:
            i = None
        if i != self.hover or i is not None:
            self.hover, self._mouse = i, pos
            self.update()

    def leaveEvent(self, _):
        self.hover = None
        self.update()

    # ---------- painting ----------
    def paintEvent(self, _):
        tk = theme.current() or {}
        col = lambda k, d: QColor(tk.get(k, d))
        surface, border, muted, text = (col("surface", "#ffffff"), col("border", "#dddddd"),
                                        col("muted", "#777777"), col("text", "#222222"))
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        card = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        p.setPen(QPen(border, 1))
        p.setBrush(surface)
        p.drawRoundedRect(card, 10, 10)
        self._geom = None
        if not self.series:
            p.setPen(muted)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Select one or more checks")
            return
        many = len(self.series) > 1
        fm = p.fontMetrics()
        top = 16
        if self.title:                                           # which scale this chart is
            p.setPen(muted)
            p.drawText(QRectF(22, 10, self.width() - 44, 18), Qt.AlignmentFlag.AlignVCenter, self.title)
            top = 38
        if many or self.title:                                   # legend: coloured dots, wrapping
            x, y = 22.0, float(top - 4)
            for name, _, color in self.series:
                label = display.check_name(name)
                w = fm.horizontalAdvance(label) + 30
                if x + w > self.width() - 20:
                    x, y = 22.0, y + 20
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(color)
                p.drawEllipse(QPointF(x + 5, y + 9), 4.5, 4.5)
                p.setPen(text)
                p.drawText(QRectF(x + 15, y, w, 18), Qt.AlignmentFlag.AlignVCenter, label)
                x += w + 8
            top = int(y + 32)
        r = QRectF(self.rect().adjusted(52, top, -22, -36))

        allpct = all(is_percent(c) for c, _, _ in self.series)
        peak = max(v for _, pts, _ in self.series for _, v in pts)
        only_uptime = all(is_uptime(c) for c, _, _ in self.series)
        if only_uptime:
            hi, grid = uptime_axis(peak)                         # round days, so the lines read as 7 d, 14 d, 21 d
        else:
            hi = 100.0 if allpct else (peak * 1.1 or 1.0)
            grid = [(hi * f, f"{hi * f:.0f}" if hi >= 10 else f"{hi * f:.1f}") for f in (0, 0.25, 0.5, 0.75, 1)]
        y = lambda v: r.bottom() - (min(max(v, 0), hi) / hi) * r.height()
        stamps = sorted({s for _, pts, _ in self.series for s, _ in pts})     # runs, evenly spaced in time order
        pos = {s: i for i, s in enumerate(stamps)}
        n = len(stamps)
        x = lambda s: r.left() + (pos[s] / (n - 1) if n > 1 else 0.5) * r.width()
        self._geom = {"rect": r, "stamps": stamps, "x": x}

        for value, label in grid:                                 # light horizontal grid with labels
            p.setPen(QPen(border, 1))
            p.drawLine(QPointF(r.left(), y(value)), QPointF(r.right(), y(value)))
            p.setPen(muted)
            p.drawText(QRectF(0, y(value) - 9, 46, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, label)
        if only_uptime:                                           # a drop in uptime is a restart: mark where, behind the lines
            red = QColor("#ef4444")
            for _c, points, color in self.series:
                for stamp, _before, _after in restarts(points):
                    red.setAlpha(150)
                    p.setPen(QPen(red, 1.4, Qt.PenStyle.DashLine))
                    p.drawLine(QPointF(x(stamp), r.top()), QPointF(x(stamp), r.bottom()))
                    if not many:
                        p.setPen(red)
                        p.drawText(QPointF(min(x(stamp) + 5, r.right() - fm.horizontalAdvance("restart") - 2), r.top() + 13), "restart")
        if self.th and allpct:
            for key, c in (("warn", "#e6b800"), ("fail", "#d32f2f")):
                p.setPen(QPen(QColor(c), 1.2, Qt.PenStyle.DashLine))
                p.drawLine(QPointF(r.left(), y(self.th[key])), QPointF(r.right(), y(self.th[key])))

        if self.hover is not None:                               # guide line under the mouse
            hx = x(stamps[self.hover])
            p.setPen(QPen(muted, 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(hx, r.top()), QPointF(hx, r.bottom()))

        for c, points, color in self.series:
            pts = [QPointF(x(s), y(v)) for s, v in points]
            if len(pts) > 1:
                if not many:                                      # a soft fill under a single line
                    area = QPainterPath(QPointF(pts[0].x(), r.bottom()))
                    for pt in pts:
                        area.lineTo(pt)
                    area.lineTo(QPointF(pts[-1].x(), r.bottom()))
                    area.closeSubpath()
                    g = QLinearGradient(0, r.top(), 0, r.bottom())
                    top_c, bot_c = QColor(color), QColor(color)
                    top_c.setAlpha(70)
                    bot_c.setAlpha(0)
                    g.setColorAt(0, top_c)
                    g.setColorAt(1, bot_c)
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(g)
                    p.drawPath(area)
                p.setPen(QPen(color, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                p.setBrush(Qt.BrushStyle.NoBrush)
                line = QPainterPath(pts[0])
                for pt in pts[1:]:
                    line.lineTo(pt)
                p.drawPath(line)
            for (s, v), pt in zip(points, pts):
                big = self.hover is not None and s == stamps[self.hover]
                p.setPen(QPen(surface, 1.5))
                p.setBrush(color)
                p.drawEllipse(pt, 5.0 if big else 3.2, 5.0 if big else 3.2)
        p.setPen(muted)
        p.drawText(QRectF(r.left(), r.bottom() + 8, r.width(), 20), Qt.AlignmentFlag.AlignLeft, stamps[0])
        p.drawText(QRectF(r.left(), r.bottom() + 8, r.width(), 20), Qt.AlignmentFlag.AlignRight, stamps[-1])
        if self.hover is not None:
            self._tooltip(p, stamps[self.hover], self.hover_rows(), fm)

    def hover_rows(self):
        """[(check name, measured value as text, colour)] for the run under the mouse."""
        if self.hover is None or not self._geom:
            return []
        stamp = self._geom["stamps"][self.hover]
        rows = [(display.check_name(c), fmt_value(c, dict(pts)[stamp]), color)
                for c, pts, color in self.series if stamp in dict(pts)]
        for c, pts, _color in self.series:                         # say so when the device restarted since the previous run
            if is_uptime(c) and any(s == stamp for s, _b, _a in restarts(pts)):
                rows.append(("Restarted", "since the run before", QColor("#ef4444")))
        return rows

    def _tooltip(self, p, stamp, rows, fm):
        """A small card next to the mouse: the time of the run and each measured value."""
        tk = theme.current() or {}
        bg, bd, tx, mu = (QColor(tk.get("surface2", "#f1f3f6")), QColor(tk.get("border", "#dddddd")),
                          QColor(tk.get("text", "#222222")), QColor(tk.get("muted", "#777777")))
        if not rows:
            return
        w = max([fm.horizontalAdvance(stamp)] + [fm.horizontalAdvance(a) + 24 + fm.horizontalAdvance(b) + 16
                                                 for a, b, _ in rows]) + 24
        h = 16 + 20 * (len(rows) + 1)
        pos = self._mouse
        x = pos.x() + 16
        if x + w > self.width() - 6:
            x = pos.x() - 16 - w
        y = min(max(6.0, pos.y() - h / 2), self.height() - h - 6)
        box = QRectF(x, y, w, h)
        p.setPen(QPen(bd, 1))
        p.setBrush(bg)
        p.drawRoundedRect(box, 8, 8)
        p.setPen(mu)
        p.drawText(QRectF(x + 12, y + 6, w - 24, 20), Qt.AlignmentFlag.AlignVCenter, stamp)
        for i, (name, val, color) in enumerate(rows):
            ry = y + 6 + 20 * (i + 1)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(color)
            p.drawEllipse(QPointF(x + 17, ry + 10), 4, 4)
            p.setPen(tx)
            p.drawText(QRectF(x + 28, ry, w - 40, 20), Qt.AlignmentFlag.AlignVCenter, name)
            f = QFont(p.font())
            f.setBold(True)
            p.setFont(f)
            p.drawText(QRectF(x + 12, ry, w - 24, 20), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, val)
            f.setBold(False)
            p.setFont(f)


class ChartStack(QScrollArea):
    """The chart area: one TrendChart per scale, so values of very different size are not squashed together.
    All percentages share one chart; other checks are grouped by order of magnitude."""

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        self.body = QWidget()
        self.lay = QVBoxLayout(self.body)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(12)
        self.setWidget(self.body)
        self.charts, self.series, self.th, self.requested = [], [], None, 0
        self.set_series([])

    def set_series(self, series, th=None):
        """series: [(check, [(time, value)])] in the order they were ticked."""
        self.requested = len(series)
        have = [(c, pts) for c, pts in series if pts]
        self.series = have
        coloured = {c: (QColor(theme.current().get("accent", "#2563eb")) if i == 0 else QColor(SERIES_COLORS[(i - 1) % len(SERIES_COLORS)]))
                    for i, (c, _) in enumerate(have)}                   # a check keeps its colour in every chart
        groups = {}
        for c, pts in have:
            groups.setdefault(scale_key(c, pts), []).append((c, pts, coloured[c]))
        while self.lay.count():
            w = self.lay.takeAt(0).widget()
            if w:
                w.hide()                      # gone at once, not at the next event-loop turn
                w.setParent(None)
                w.deleteLater()
        self.charts = []
        for key in sorted(groups) or [None]:
            ch = TrendChart()
            members = groups.get(key, [])
            title = scale_title(key) if key is not None and len(groups) > 1 else ""
            if key == (2, 0) and len(members) == 1:                # one device's uptime: say how long, since when, and how often it restarted
                title = uptime_caption(members[0][1])
            ch.set_series(members, th if len(have) == 1 else None, title=title)
            self.lay.addWidget(ch, 1)
            self.charts.append(ch)
        self.th = self.charts[0].th if self.charts else None

    def set_data(self, points, check, th):                    # single-check form
        self.set_series([(check, points)], th)



def _table(cols):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.horizontalHeader().setStretchLastSection(True)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    return t


class HistoryTab(QWidget):
    def __init__(self):
        super().__init__()
        self.runs = _table(["Run time", "OK", "WARN", "FAIL", "ERROR"])
        self.detail = _table(["Device", "Check", "Status", "Value", "Message"])
        self.detail.setItemDelegateForColumn(2, StatusDelegate(self.detail))
        self.runs.itemSelectionChanged.connect(self.show_run)
        self.group, self.dev = GroupPicker(), QComboBox()
        self.chk = GroupPicker(all_text="Select checks", noun="checks", clear_text="Clear selection")
        self.check_keys = {}                     # shown name -> stored check name
        self.group.set_labels(db.group_labels()[1:])
        self.group.changed.connect(self.group_changed)
        self.chart = ChartStack()
        self.dev.currentTextChanged.connect(self.fill_checks)
        self.chk.changed.connect(self.draw)

        left = QSplitter(Qt.Orientation.Vertical)
        left.addWidget(self.runs)
        left.addWidget(self.detail)
        right = QWidget()
        rl = QVBoxLayout(right)
        for w in (self.group, self.dev, self.chk):               # share the width, and wrap when the pane is narrow
            w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        rl.addLayout(flow("Group", self.group, "Device", self.dev, "Check", self.chk))
        rl.addWidget(self.chart, 1)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([450, 450])
        lay = QVBoxLayout(self)
        lay.addWidget(split)
        self.refresh()

    def _group_names(self):
        return db.group_device_names(self.group.selected())

    @staticmethod
    def _base(device):
        """UniFi rows are labelled 'controller / device'; the inventory name is the first part."""
        return (device or "").split(" / ")[0]

    def group_changed(self, *_):
        self.refresh(reload_groups=False)

    def refresh(self, reload_groups=True):
        if reload_groups:                      # inventory may have changed since last time
            self.group.set_labels(db.group_labels()[1:])
        runs = db.list_runs()
        self.run_ids = [r["id"] for r in runs]
        self.runs.setRowCount(len(runs))
        for i, r in enumerate(runs):
            for j, v in enumerate([r["started_at"], r["ok"], r["warn"], r["fail"], r["error"]]):
                self.runs.setItem(i, j, QTableWidgetItem(str(v)))
        self.runs.resizeColumnsToContents()
        names = self._group_names()
        self.map = {d: c for d, c in db.device_checks().items()
                    if names is None or self._base(d) in names}
        cur = self.dev.currentText()
        self.dev.blockSignals(True)
        self.dev.clear()
        self.dev.addItems(list(self.map))
        if cur in self.map:
            self.dev.setCurrentText(cur)
        self.dev.blockSignals(False)
        self.fill_checks(self.dev.currentText())

    def show_run(self):
        row = self.runs.currentRow()
        if not 0 <= row < len(self.run_ids):
            return
        names = self._group_names()
        res = [r for r in db.run_results(self.run_ids[row])
               if names is None or self._base(r["device"]) in names]
        self.detail.setRowCount(len(res))
        for i, r in enumerate(res):
            for j, v in enumerate([r["device"], display.check_name(r["check_name"]), r["status"],
                                   display.value(r["value"]), r["message"]]):
                self.detail.setItem(i, j, QTableWidgetItem(v or ""))

    def fill_checks(self, device):
        """List this device's checks. Ticks that still apply are kept; a first visit ticks the first check."""
        checks = self.map.get(device, [])
        self.check_keys = {display.check_name(c): c for c in checks}
        keep = self.chk.selected()
        self.chk.set_labels(list(self.check_keys))
        keep = [k for k in keep if k in self.check_keys]
        if not keep and self.check_keys:
            keep = [next(iter(self.check_keys))]
        self.chk.set_selected(keep)
        self.draw()

    def draw(self, *_):
        d = self.dev.currentText()
        picked = [self.check_keys[k] for k in self.chk.selected() if k in self.check_keys]
        series = [(c, db.series(d, c)) for c in picked] if d else []
        self.chart.set_series(series, db.get_thresholds().get(picked[0].split(" (")[0]) if picked else None)
