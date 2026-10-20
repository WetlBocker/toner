import math
from datetime import datetime, timedelta

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QSplitter,
                               QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)
from core import db, display, scope
from core.reports import COLORS, fg_for
from ui import theme
from ui.widgets import EmptyHint, FlowLayout, GroupPicker, StatusDelegate, flow
from ui.finder import FilterButton, SearchBox, device_sections, listed_devices, shown_devices, wants_archived
from ui import status as st

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


def nice_axis(peak):
    """Grid lines at round numbers (0, 20, 40 ... or 0, 250, 500 ...) with the last at or above the peak: (top, [(value, label)])."""
    peak = float(peak) if peak and peak > 0 else 1.0
    magnitude = 10 ** math.floor(math.log10(peak / 4))
    step = next(m * magnitude for m in (1, 2, 2.5, 5, 10) if peak * 1.04 / (m * magnitude) <= 5)
    top = math.ceil(peak * 1.04 / step - 1e-9) * step
    n = int(round(top / step))
    decimals = next(d for d in range(0, 6) if abs(round(step, d) - step) < 1e-9 or d == 5)
    fmt = lambda v: f"{v:,.{decimals}f}"
    return float(top), [(round(k * step, 9), fmt(k * step)) for k in range(n + 1)]


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


class RunAxis(pg.AxisItem):
    """The time axis: runs are evenly spaced (one step each), labelled with when they ran."""

    def __init__(self, chart):
        super().__init__("bottom")
        self.chart = chart

    def tickValues(self, minVal, maxVal, size):
        n = len(self.chart.stamps)
        if not n:
            return []
        lo, hi = max(0, math.ceil(minVal)), min(n - 1, math.floor(maxVal))
        if hi < lo:
            return []
        room = max(1, int(size // 110))                      # about one label per 110 pixels
        step = max(1, math.ceil((hi - lo + 1) / room))
        return [(step, list(range(lo, hi + 1, step)))]

    def tickStrings(self, values, scale, spacing):
        out = []
        for v in values:
            i = int(round(v))
            stamp = self.chart.stamps[i] if 0 <= i < len(self.chart.stamps) else ""
            out.append(stamp[5:16] if len(stamp) >= 16 and stamp[4] == "-" else stamp)      # 'MM-DD HH:MM'
        return out


class TrendChart(QFrame):
    """One chart: one or more checks that share a vertical axis, drawn with pyqtgraph. Hover to read the measured values; drag
    across it to zoom in on a stretch of time and double-click to zoom back out; click a name above it to hide that check."""

    def __init__(self, title=""):
        super().__init__()
        self.title = title
        self.series, self.th = [], None            # series: [(check name, [(time, value)], colour)]
        self.hover = None                          # index of the run under the mouse
        self.stamps, self.curves = [], {}
        self.setMinimumSize(320, 230)
        self.setObjectName("trendChart")
        self.caption = QLabel()
        self.caption.setProperty("muted", True)
        self.legend = QWidget()
        self.legend_lay = FlowLayout(12, 2)
        self.legend.setLayout(self.legend_lay)
        self.empty = QLabel("Select one or more checks")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setProperty("muted", True)
        self.axis = RunAxis(self)
        self.plot = pg.PlotWidget(axisItems={"bottom": self.axis})
        self.plot.setMenuEnabled(False)                         # pyqtgraph's own menu and "A" button are not part of Toner
        self.plot.hideButtons()
        self.plot.setMouseEnabled(x=True, y=False)              # zoom in time only; the scale stays put
        self.vb = self.plot.getViewBox()
        self.vb.setMouseMode(pg.ViewBox.RectMode)               # drag across a stretch of time to zoom in on it
        self.plot.scene().sigMouseMoved.connect(self._moved)
        self.plot.scene().sigMouseClicked.connect(self._clicked)
        self.guide = pg.InfiniteLine(angle=90, movable=False)
        self.readout = pg.TextItem(anchor=(0, 0))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 8)
        lay.setSpacing(4)
        for w in (self.caption, self.legend, self.empty, self.plot):
            lay.addWidget(w)
        lay.setStretch(3, 1)
        self.set_series([])

    def set_series(self, series, th=None, title=None):
        if title is not None:
            self.title = title
        self.series = [s for s in series if s[1]]
        self.th = th if len(self.series) == 1 else None      # thresholds only make sense for one check
        self.hover = None
        self.draw()

    # ---------- drawing ----------
    def draw(self):
        tk = theme.current() or {}
        col = lambda k, d: QColor(tk.get(k, d))
        surface, border, muted, text = col("surface", "#ffffff"), col("border", "#dddddd"), col("muted", "#777777"), col("text", "#222222")
        self.setStyleSheet(f"QFrame#trendChart {{ background: {surface.name()}; border: 1px solid {border.name()}; border-radius: 10px; }}")
        self.plot.setBackground(surface)
        for name in ("left", "bottom"):
            ax = self.plot.getAxis(name)
            ax.setPen(pg.mkPen(border))
            ax.setTextPen(pg.mkPen(muted))
        self.plot.clear()
        self.curves = {}
        self.plot.addItem(self.guide, ignoreBounds=True)
        self.plot.addItem(self.readout, ignoreBounds=True)
        self.guide.setPen(pg.mkPen(muted, width=1, style=Qt.PenStyle.DashLine))
        self.guide.hide()
        self.readout.hide()
        while self.legend_lay.count():
            w = self.legend_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.caption.setText(self.title)
        self.caption.setVisible(bool(self.title))
        has = bool(self.series)
        self.empty.setVisible(not has)
        self.plot.setVisible(has)
        many = len(self.series) > 1
        named = has and (many or bool(self.title))           # names above the chart: several checks, or a captioned one
        self.legend.setVisible(named)
        if not has:
            self.stamps = []
            return
        self.stamps = sorted({s for _, pts, _ in self.series for s, _ in pts})     # runs, evenly spaced in time order
        pos = {s: i for i, s in enumerate(self.stamps)}
        allpct = all(is_percent(c) for c, _, _ in self.series)
        peak = max(v for _, pts, _ in self.series for _, v in pts)
        only_uptime = all(is_uptime(c) for c, _, _ in self.series)
        if only_uptime:
            hi, grid = uptime_axis(peak)                         # round days, so the lines read as 7 d, 14 d, 21 d
        elif allpct:
            hi, grid = 100.0, [(v, f"{v:.0f}") for v in (0, 25, 50, 75, 100)]
        else:
            hi, grid = nice_axis(peak)
        left = self.plot.getAxis("left")
        left.setTicks([grid])
        self.plot.showGrid(x=False, y=True, alpha=0.35)
        self.vb.setLimits(xMin=-0.5, xMax=max(0.5, len(self.stamps) - 0.5), minXRange=1)
        self.plot.setYRange(0, hi, padding=0.02)
        self._full()
        if only_uptime:                                           # a drop in uptime is a restart: mark where, behind the lines
            red = st.qink("FAIL")
            red.setAlpha(150)
            for _c, points, _color in self.series:
                for stamp, _before, _after in restarts(points):
                    self.plot.addItem(pg.InfiniteLine(pos=pos[stamp], angle=90, pen=pg.mkPen(red, width=1.4, style=Qt.PenStyle.DashLine)))
                    if not many:
                        label = pg.TextItem("restart", color=st.qink("FAIL"), anchor=(0, 0))
                        label.setPos(pos[stamp], hi)
                        self.plot.addItem(label)
        if self.th and allpct:
            for key, c in (("warn", st.ink("WARN")), ("fail", st.ink("FAIL"))):
                self.plot.addItem(pg.InfiniteLine(pos=self.th[key], angle=0, pen=pg.mkPen(QColor(c), width=1.2, style=Qt.PenStyle.DashLine)))
        for c, points, color in self.series:
            xs, ys = [pos[s] for s, _ in points], [v for _, v in points]
            fill = None
            if not many:                                          # a soft fill under a single line
                soft = QColor(color)
                soft.setAlpha(45)
                fill = pg.mkBrush(soft)
            curve = self.plot.plot(xs, ys, pen=pg.mkPen(color, width=2.2), symbol="o", symbolSize=6, symbolBrush=color,
                                   symbolPen=pg.mkPen(surface, width=1.2), fillLevel=0 if fill else None, brush=fill)
            self.curves[c] = curve
            if named:
                self.legend_lay.addWidget(self._legend_button(c, color, text))

    def _legend_button(self, check, color, text):
        b = QToolButton()
        b.setText(display.check_name(check))
        b.setCheckable(True)
        b.setChecked(True)
        b.setAutoRaise(True)
        b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        dot = QPixmap(10, 10)
        dot.fill(Qt.GlobalColor.transparent)
        p = QPainter(dot)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(color))
        p.drawEllipse(0, 0, 10, 10)
        p.end()
        b.setIcon(QIcon(dot))
        b.toggled.connect(lambda on, c=check: self._show(c, on))
        return b

    def _show(self, check, on):
        """Hide or show one check (its name above the chart was clicked)."""
        if check in self.curves:
            self.curves[check].setVisible(on)

    def _full(self):
        self.plot.setXRange(-0.25, max(0.25, len(self.stamps) - 0.75), padding=0)

    # ---------- the mouse ----------
    def _clicked(self, ev):
        if ev.double():
            self._full()                                          # double-click: the whole stretch of time again

    def _moved(self, scene_pos):
        if not self.stamps or not self.plot.sceneBoundingRect().contains(scene_pos):
            self._leave()
            return
        x = self.vb.mapSceneToView(scene_pos).x()
        i = max(0, min(len(self.stamps) - 1, int(round(x))))
        self.hover = i
        rows = self.hover_rows()
        if not rows:
            self._leave()
            return
        tk = theme.current() or {}
        self.guide.setPos(i)
        self.guide.show()
        lines = [self.stamps[i]] + [f"{name}  {val}" for name, val, _c in rows]
        self.readout.setText("\n".join(lines), color=QColor(tk.get("text", "#222222")))
        self.readout.fill = pg.mkBrush(QColor(tk.get("surface2", "#f1f3f6")))
        self.readout.border = pg.mkPen(QColor(tk.get("border", "#dddddd")))
        (x0, x1), (y0, y1) = self.vb.viewRange()
        right = i > x0 + (x1 - x0) * 0.6                          # keep the readout inside: left of the line near the right edge
        self.readout.setAnchor((1, 0) if right else (0, 0))
        self.readout.setPos(i, y1)
        self.readout.show()

    def _leave(self):
        self.hover = None
        self.guide.hide()
        self.readout.hide()

    def leaveEvent(self, e):
        self._leave()
        super().leaveEvent(e)

    def hover_rows(self):
        """[(check name, measured value as text, colour)] for the run under the mouse."""
        if self.hover is None or not self.stamps:
            return []
        stamp = self.stamps[self.hover]
        rows = [(display.check_name(c), fmt_value(c, dict(pts)[stamp]), color)
                for c, pts, color in self.series if stamp in dict(pts) and (c not in self.curves or self.curves[c].isVisible())]
        for c, pts, _color in self.series:                         # say so when the device restarted since the previous run
            if is_uptime(c) and any(s == stamp for s, _b, _a in restarts(pts)):
                rows.append(("Restarted", "since the run before", st.qink("FAIL")))
        return rows


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
        self.hint = None
        if have:
            self.hint = QLabel("Drag across a graph to zoom in. Double-click to zoom back out. Click a name in the legend to hide it.")
            self.hint.setProperty("muted", True)
            self.hint.setWordWrap(True)
            self.lay.addWidget(self.hint)
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
        self.runs = _table(["Run time", "OK", "WARN", "FAIL", "ERROR", "Organization"])
        self.detail = _table(["Device", "Check", "Status", "Value", "Message"])
        self.detail.setItemDelegateForColumn(2, StatusDelegate(self.detail))
        self.runs.itemSelectionChanged.connect(self.show_run)
        self.runs_hint = EmptyHint(self.runs, "No runs yet", "Press Run checks (Results tab) to start the history")
        self.detail_hint = EmptyHint(self.detail, "Choose a run above", "to see every check from that run")
        hh = self.runs.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, hh.ResizeMode.Stretch)                  # the run time takes what the counts leave
        for col in range(1, 6):
            hh.setSectionResizeMode(col, hh.ResizeMode.ResizeToContents)
        self.dev = QComboBox()
        self.chk = GroupPicker(all_text="Select checks", noun="checks", clear_text="Clear selection")
        self.check_keys = {}                     # shown name -> stored check name
        self.find = SearchBox("Search devices", "Type part of a name, address, vendor, location, tag or detail. Several words must all match.",
                              page=self)
        self.funnel = FilterButton(lambda: device_sections(listed_devices(self.funnel)))
        self.find.textChanged.connect(lambda _t: self.group_changed())
        self.funnel.changed.connect(self.group_changed)
        self.chart = ChartStack()
        self.dev.currentIndexChanged.connect(lambda _i: self.fill_checks(self.dev.currentData()))
        self.chk.changed.connect(self.draw)

        left = QSplitter(Qt.Orientation.Vertical)
        left.addWidget(self.runs)
        left.addWidget(self.detail)
        right = QWidget()
        rl = QVBoxLayout(right)
        for w in (self.dev, self.chk):               # share the width, and wrap when the pane is narrow
            w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        rl.addLayout(flow("Device", self.dev, "Check", self.chk))
        rl.addWidget(self.chart, 1)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([450, 450])
        top = QHBoxLayout()
        top.addStretch(1)
        top.addWidget(self.find, 1)                 # on the right, as on Inventory
        top.addWidget(self.funnel)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split, 1)                 # the page takes all the height: without the stretch the header drifts down the window
        self.refresh()

    def _group_names(self):
        """The devices the search box and the funnel leave (within the client being looked at), or None for every device."""
        if not self.find.words() and not self.funnel.active():
            return scope.names()
        return {d["key"] for d in shown_devices(listed_devices(self.funnel), self.find, self.funnel)}

    @staticmethod
    def _base(device):
        """UniFi rows are labelled 'controller / device'; the inventory name is the first part."""
        return (device or "").split(" / ")[0]

    def group_changed(self, *_):
        """The search box or the funnel changed: the device list and the chosen run's rows follow."""
        self.refresh(reload_groups=False)
        self.show_run()

    def refresh(self, reload_groups=True):
        with db.including_archived(wants_archived(self.funnel)):
            runs = db.list_runs()
        orgs = self.funnel.selected("org")
        if orgs:                                                            # Global: only the runs of the organizations picked
            runs = [r for r in runs if r["org"] in orgs]
        self.run_ids = [(r["id"], r["org"]) for r in runs]
        self.runs.setRowCount(len(runs))
        self.runs.setColumnHidden(5, not db.several())
        for i, r in enumerate(runs):
            for j, v in enumerate([r["started_at"], r["ok"], r["warn"], r["fail"], r["error"], db.org_name(r["org"])]):
                self.runs.setItem(i, j, QTableWidgetItem(str(v)))
        self.runs_hint.setVisible(not runs)
        if runs and self.runs.currentRow() < 0:
            self.runs.selectRow(0)                                          # the latest run, so the lower table is never blank
        names = self._group_names()
        with db.including_archived(wants_archived(self.funnel)):
            checks = db.device_checks()
        self.map = {d: c for d, c in checks.items() if names is None or self._base(d) in names}
        cur = self.dev.currentData()
        self.dev.blockSignals(True)
        self.dev.clear()
        for key in self.map:
            self.dev.addItem(db.label_org(key), key)
        if cur in self.map:
            self.dev.setCurrentIndex(self.dev.findData(cur))
        self.dev.blockSignals(False)
        self.fill_checks(self.dev.currentData())

    def show_run(self):
        row = self.runs.currentRow()
        if not 0 <= row < len(self.run_ids):
            self.detail.setRowCount(0)                     # nothing chosen (or no runs): the lower table says so instead of showing an old run
            self.detail_hint.setVisible(True)
            return
        names = self._group_names()
        rid, org = self.run_ids[row]
        res = [r for r in db.run_results(rid, org)
               if names is None or self._base(r["device"]) in names]
        self.detail.setRowCount(len(res))
        self.detail_hint.setVisible(not res)
        for i, r in enumerate(res):
            for j, v in enumerate([db.label(r["device"]), display.check_name(r["check_name"]), r["status"],
                                   display.value(r["value"]), r["message"]]):
                self.detail.setItem(i, j, QTableWidgetItem(v or ""))

    def fill_checks(self, device):
        """List this device's checks. Ticks that still apply are kept; a first visit ticks the first check."""
        checks = self.map.get(device or "", [])
        self.check_keys = {display.check_name(c): c for c in checks}
        keep = self.chk.selected()
        self.chk.set_labels(list(self.check_keys))
        keep = [k for k in keep if k in self.check_keys]
        if not keep and self.check_keys:
            keep = [next(iter(self.check_keys))]
        self.chk.set_selected(keep)
        self.draw()

    def draw(self, *_):
        d = self.dev.currentData()
        picked = [self.check_keys[k] for k in self.chk.selected() if k in self.check_keys]
        series = [(c, db.series(d, c)) for c in picked] if d else []
        with db.within(db.split_key(d or "")[1]):                         # that organization's limits
            th = db.get_thresholds()
        self.chart.set_series(series, th.get(picked[0].split(" (")[0]) if picked else None)
