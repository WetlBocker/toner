"""History: every check result in a time range, charts of any checks over time, and the reports (CSV, HTML, PDF of the rows shown,
and the trend report), which used to be a section of their own."""
import math
import os
import re
from datetime import datetime, timedelta

import pyqtgraph as pg
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPoint, QSortFilterProxyModel, Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QSizePolicy,
                               QSplitter, QTabWidget, QTableView, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout,
                               QWidget)
from core import db, display, heatgrid, reports, scope, trends
from core.chartkinds import across_kind, shown_name, stored_names
from core.firmware import human_size
from core.reports import COLORS, fg_for
from drivers.base import Result
from ui import theme
from ui.detaillist import DetailList
from ui.toast import toast
from ui.widgets import FlowLayout, GroupPicker, StatusDelegate, flow, remember_sizes
from ui.finder import FilterButton, SearchBox, device_sections, listed_devices, shown_devices, wants_archived
from ui import chartspec
from ui.timerange import TimeRange
from ui.webchart import ChartView
from ui import status as st

PCT_CHECKS = ("cpu", "memory")
ACROSS_SWITCH = (("Latest", 0), ("7-day average", 7), ("30-day average", 30), ("90-day average", 90))
RING_SEGMENTS = (("Up", "OK"), ("Err-disabled", "WARN"), ("Down", "FAIL"))
WORST = {"FAIL": 0, "ERROR": 0, "WARN": 1, "OK": 2}                     # worst first
DISK_CHECKS = ("disk", "disks", "storage", "flash", "log disk", "pool space", "datasets")      # their marks are the "disk" thresholds
PCT_GAUGES = DISK_CHECKS + ("cpu", "memory", "utilization", "sessions", "channel_util", "wan usage")


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
        self.series, self.th, self.marks = [], None, []    # series: [(check name, [(time, value)], colour)]; marks: [(time, value)] in red
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

    def set_series(self, series, th=None, title=None, marks=()):
        if title is not None:
            self.title = title
        self.series = [s for s in series if s[1]]
        self.marks = list(marks)
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
        has = bool(self.series or self.marks)               # red marks alone (a device that never answered) still draw
        self.empty.setVisible(not has)
        self.plot.setVisible(has)
        many = len(self.series) > 1
        named = has and (many or bool(self.title))           # names above the chart: several checks, or a captioned one
        self.legend.setVisible(named)
        if not has:
            self.stamps = []
            return
        self.stamps = sorted({s for _, pts, _ in self.series for s, _ in pts} | {s for s, _ in self.marks})     # runs, evenly spaced in time order
        pos = {s: i for i, s in enumerate(self.stamps)}
        allpct = bool(self.series) and all(is_percent(c) for c, _, _ in self.series)
        peak = max((v for _, pts, _ in self.series for _, v in pts), default=0)
        only_uptime = bool(self.series) and all(is_uptime(c) for c, _, _ in self.series)
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
        if self.marks:                                            # checks with no answer (reachability): red points
            self.plot.plot([pos[s] for s, _ in self.marks], [v for _, v in self.marks], pen=None, symbol="o", symbolSize=9,
                           symbolBrush=st.qink("FAIL"), symbolPen=pg.mkPen(surface, width=1.2))

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

    def set_series(self, series, th=None, marks=()):
        """series: [(check, [(time, value)])] in the order they were ticked; marks: [(time, value)] drawn as red points."""
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
            ch.set_series(members, th if len(have) == 1 else None, title=title, marks=marks)
            self.lay.addWidget(ch, 1)
            self.charts.append(ch)
        self.th = self.charts[0].th if self.charts else None

    def set_data(self, points, check, th):                    # single-check form
        self.set_series([(check, points)], th)



def _table(cols):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    return _plain(t)


def _plain(t):
    t.horizontalHeader().setStretchLastSection(True)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    return t


class RowsModel(QAbstractTableModel):
    """The checks table: the stored rows of the time range, turned into text once, so thousands of rows stay quick. It sorts itself
    (one Python sort) and keeps that order when new rows come."""
    COLS = ["Time", "Device", "Check", "Status", "Value", "Message"]

    def __init__(self):
        super().__init__()
        self.rows, self.cells, self.key = [], [], (0, Qt.SortOrder.DescendingOrder)

    @staticmethod
    def cells_of(rows):
        return [(r["t"], db.label_org(r["device"]), display.check_name(r["check_name"]), r["status"], display.value(r["value"]) or "",
                 r["message"] or "") for r in rows]

    def _order(self, cells):
        col, order = self.key
        return sorted(range(len(cells)), key=lambda i: cells[i][col], reverse=order == Qt.SortOrder.DescendingOrder)

    def set_rows(self, rows, cells=None):
        cells = self.cells_of(rows) if cells is None else cells
        ix = self._order(cells)
        self.beginResetModel()
        self.rows, self.cells = [rows[i] for i in ix], [cells[i] for i in ix]
        self.endResetModel()

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        self.layoutAboutToBeChanged.emit()
        self.key = (column, order)
        ix = self._order(self.cells)
        moved = {old: new for new, old in enumerate(ix)}
        self.rows, self.cells = [self.rows[i] for i in ix], [self.cells[i] for i in ix]
        old = self.persistentIndexList()                      # the selection follows its row
        self.changePersistentIndexList(old, [self.index(moved[p.row()], p.column()) for p in old])
        self.layoutChanged.emit()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.cells)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        return self.cells[index.row()][index.column()] if role == Qt.ItemDataRole.DisplayRole else None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLS[section]
        return None


class RowsProxy(QSortFilterProxyModel):
    """Hands sorting to the model: Qt's own sort would ask Python for both cells of every comparison (seconds at 10,000 rows)."""

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        self.sourceModel().sort(column, order)


class LazyChart(QWidget):
    """A chart's place in Across devices' grid: its web view is made only when it first scrolls into view (see LazyArea), so a fleet of
    hundreds does not build hundreds of browser views on every redraw."""

    def __init__(self, width, height, name, builder, clicked=None):
        super().__init__()
        self.setFixedSize(width, height)
        self.name, self.builder, self.on_click, self.view = name, builder, clicked, None
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)

    def draw(self):
        self.view = ChartView(min_height=self.height())
        self.view.setAccessibleName(self.name)
        self.view.draw(self.builder)
        if self.on_click:
            self.view.clicked.connect(self.on_click)
        self.lay.addWidget(self.view)


class LazyArea(QScrollArea):
    """Across devices' page: draws its LazyCharts as they come into view, as the Over time panels are (ui.overtime.CheckPanels)."""

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        bar = self.verticalScrollBar()
        bar.valueChanged.connect(self.reveal)
        bar.rangeChanged.connect(self.reveal)

    def reveal(self, *_):
        body = self.widget()
        if body is None or not self.isVisible():
            return
        body.layout().activate()                                  # place the charts now, as the scroll area would at its next turn
        body.resize(self.viewport().width(), max(self.viewport().height(), body.heightForWidth(self.viewport().width()), body.minimumSizeHint().height()))
        vp = self.viewport()
        for s in body.findChildren(LazyChart):
            if s.view is None:
                y = s.mapTo(vp, QPoint(0, 0)).y()
                if y < vp.height() and y + s.height() > 0:
                    s.draw()

    def showEvent(self, e):
        super().showEvent(e)
        self.reveal()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.reveal()


class HistoryTab(QWidget):
    def __init__(self):
        super().__init__()
        self.range = TimeRange()                                            # one range for the table, the exports and Over time
        self._read = None                                                   # (archived too?, the range's rows, their cells) from the last read
        self.range.changed.connect(self._range_changed)
        self.model, self.proxy = RowsModel(), RowsProxy()
        self.proxy.setSourceModel(self.model)
        self.detail = _plain(QTableView())
        self.detail.setModel(self.proxy)
        self.detail.setSortingEnabled(True)
        self.detail.sortByColumn(0, Qt.SortOrder.DescendingOrder)            # newest first
        self.detail.setItemDelegateForColumn(3, StatusDelegate(self.detail))
        self.dev = QComboBox()
        self.chk = GroupPicker(all_text="Select checks", noun="checks", clear_text="Clear selection")
        self.check_keys = {}                     # shown name -> stored check name
        self.find = SearchBox("Search devices", "Type part of a name, address, vendor, location, tag or detail. Several words must all match.",
                              page=self)
        self.funnel = FilterButton(lambda: device_sections(listed_devices(self.funnel)))
        self.find.textChanged.connect(lambda _t: self.group_changed())
        self.funnel.changed.connect(self.group_changed)
        from ui.overtime import CheckPanels                     # (ui.overtime draws with this module's charts)
        self.panels = CheckPanels()
        self.dev.currentIndexChanged.connect(lambda _i: self.fill_checks(self.dev.currentData()))
        self.chk.changed.connect(self.draw)
        self.detail.selectionModel().selectionChanged.connect(self._pick_from_row)      # a check's row puts that device and check on the chart
        # the reports: of the rows shown, and the trend report over a period
        self.csv_btn, self.html_btn, self.pdf_btn = QPushButton("Export CSV"), QPushButton("HTML report"), QPushButton("PDF report")
        for b, fn in ((self.csv_btn, self.export_csv), (self.html_btn, self.export_html), (self.pdf_btn, self.export_pdf)):
            b.clicked.connect(fn)
        self.trend_period = QComboBox()
        for label, days in trends.PERIODS:
            self.trend_period.addItem(label, days)
        self.trend_btn = QPushButton("Trend report")
        self.trend_btn.setToolTip("How the whole period went compared with the one before: availability, worst offenders, what keeps failing, "
                                  "what is still wrong, changes, and the Windows computers.")
        self.trend_btn.clicked.connect(self.export_trend)
        self.report_label = QLabel("Report")
        self.report_label.setProperty("muted", True)
        bar = flow(self.report_label, self.csv_btn, self.html_btn, self.pdf_btn, self.trend_period, self.trend_btn)
        low = QWidget()
        lowl = QVBoxLayout(low)
        lowl.setContentsMargins(0, 0, 0, 0)
        lowl.addWidget(self.detail, 1)
        lowl.addLayout(bar)

        over_time = QWidget()
        rl = QVBoxLayout(over_time)
        rl.setContentsMargins(0, 8, 0, 0)
        for w in (self.dev, self.chk):               # share the width, and wrap when the pane is narrow
            w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        rl.addLayout(flow("Device", self.dev, "Check", self.chk))
        rl.addWidget(self.panels, 1)                                        # a panel per ticked check, each drawn as its kind
        # Across devices: each device's latest reading of the check picked here (or its average), drawn as the check's kind; not the range
        self.compare_check = QComboBox()
        self.compare_check.setToolTip("The check to chart")
        self.compare_check.currentIndexChanged.connect(lambda _i: self.draw_compare())
        self.compare_switch = QComboBox()
        for label, days in ACROSS_SWITCH:
            self.compare_switch.addItem(label, days)
        self.compare_switch.currentIndexChanged.connect(lambda _i: self.draw_compare())
        self.compare_area = LazyArea()
        self.compare_names, self.compare_gauges, self.compare_rings, self.compare_table, self.compare_detail = [], [], [], None, None
        across = QWidget()
        al = QVBoxLayout(across)
        al.setContentsMargins(0, 8, 0, 0)
        al.addLayout(flow("Check", self.compare_check, self.compare_switch))
        al.addWidget(self.compare_area, 1)
        # Failures: when problems happen (weekday by hour) and where (the devices with most), over the trend period
        self.fail_period = QComboBox()
        for label, days in trends.PERIODS:
            self.fail_period.addItem(label, days)
        self.fail_period.currentIndexChanged.connect(lambda _i: self.draw_failures())
        self.fail_when = ChartView(min_height=200)
        self.fail_when.setAccessibleName("Failures by weekday and hour")
        self.fail_where = ChartView(min_height=200)
        self.fail_where.setAccessibleName("Failures by device")
        self.fail_when.clicked.connect(self._fail_cell)                    # a cell or a bar: the rows it counts
        self.fail_where.clicked.connect(self._fail_bar)
        self._fail_rows, self._fail_worst = [], []
        fails = QWidget()
        fl = QVBoxLayout(fails)
        fl.setContentsMargins(0, 8, 0, 0)
        fl.addLayout(flow("Period", self.fail_period))
        fl.addWidget(self.fail_when, 1)
        fl.addWidget(self.fail_where, 1)
        self.chart_tabs = QTabWidget()
        self.chart_tabs.setDocumentMode(True)
        self.chart_tabs.addTab(over_time, "Over time")
        self.chart_tabs.addTab(across, "Across devices")
        self.chart_tabs.addTab(fails, "Failures")
        self.chart_tabs.currentChanged.connect(self._chart_tab_shown)
        right = self.chart_tabs
        split = QSplitter()
        split.addWidget(low)
        split.addWidget(right)
        split.setSizes([450, 450])
        remember_sizes(split, "history")
        top = QHBoxLayout()
        top.addWidget(self.range)
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
        """The search box or the funnel changed: the device list and the table's rows follow."""
        self.refresh(reload_groups=False)

    def refresh(self, reload_groups=True):
        names = self._group_names()
        with db.including_archived(wants_archived(self.funnel)):
            checks = db.device_all_checks()
            self.devs = {d["key"]: d for d in db.list_devices()}                 # for the charts' vendors and limits, read once here
        self.vendors = {k: d["vendor"] for k, d in self.devs.items()}
        self.map = {d: c for d, c in checks.items() if names is None or self._base(d) in names}
        self._fill_compare()
        cur = self.dev.currentData()
        self.dev.blockSignals(True)
        self.dev.clear()
        for key in self.map:
            self.dev.addItem(db.label_org(key), key)
        if cur in self.map:
            self.dev.setCurrentIndex(self.dev.findData(cur))
        self.dev.blockSignals(False)
        self.fill_checks(self.dev.currentData())
        self.show_rows(reread=reload_groups)                                # a search or funnel change only filters what was read

    def _range_changed(self):
        self.show_rows()
        self.draw()

    def show_rows(self, reread=True):
        """The checks table: every stored row in the time range, newest first, for the devices the search box and the funnel leave.
        The range is read again only when asked (a refresh, a new range) or when the funnel turns archived organizations on or off."""
        archived = wants_archived(self.funnel)
        if reread or self._read is None or self._read[0] != archived:
            with db.including_archived(archived):
                rows = db.results_between(*self.range.span())
            self._read = (archived, rows, RowsModel.cells_of(rows))
        names = self._group_names()
        _a, rows, cells = self._read
        keep = [i for i, r in enumerate(rows) if names is None or self._base(r["device"]) in names]
        self.model.set_rows([rows[i] for i in keep], [cells[i] for i in keep])

    # ---------- the charts beside the table
    def _chart_tab_shown(self, i):
        """A chart tab came into view: draw it from what is stored (the Failures tab reads a period, so only when looked at)."""
        if i == 1:
            self.draw_compare()
        elif i == 2:
            self.draw_failures()

    def restyle(self):
        for c in self.compare_area.findChildren(ChartView) + [self.fail_when, self.fail_where]:
            c.restyle()
        self.panels.restyle()

    def _fill_compare(self):
        """Across devices' checks: every check the devices shown have stored (not only in the time range), each once under its shown
        name, less those Across devices never draws; the pick is kept when it still applies."""
        self.compare_names = sorted({c for cs in self.map.values() for c in cs})
        shown = {shown_name(c) for c in self.compare_names if across_kind(c) != "hidden"}
        cur = self.compare_check.currentData()
        self.compare_check.blockSignals(True)
        self.compare_check.clear()
        for key in sorted(shown, key=lambda s: display.check_name(s).lower()):
            self.compare_check.addItem(display.check_name(key), key)
        if cur in shown:
            self.compare_check.setCurrentIndex(self.compare_check.findData(cur))
        self.compare_check.blockSignals(False)
        if self.chart_tabs.currentIndex() == 1:
            self.draw_compare()

    def draw_compare(self):
        """Each device's latest reading of the picked check, drawn as its kind (a device's vendor can change it: TrueNAS disks are
        SMART health), into a fresh page under the pickers. Read as the checks list was: with archived organizations when the funnel
        asks for them."""
        shown = self.compare_check.currentData()
        stored = stored_names(shown, self.compare_names) if shown else []
        names = self._group_names()
        mine = lambda d: names is None or self._base(d) in names
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        self.compare_gauges, self.compare_rings, self.compare_table, self.compare_detail = [], [], None, None
        with db.including_archived(wants_archived(self.funnel)):
            rows = [r for r in db.latest_per_device(stored) if mine(r["device"])] if stored else []
            kinds = {}
            for r in rows:
                kinds.setdefault(across_kind(r["check_name"], rows, self._vendor(r["device"])), []).append(r)
            if shown and across_kind(shown) == "firmware":
                kinds.setdefault("firmware", [])                     # devices that only have a version read (software_of)
            for kind in ("gauges", "rings", "certs", "environment", "firmware", "table", "health"):
                if kind in kinds:
                    getattr(self, "_across_" + kind)(lay, shown, stored, kinds[kind], mine)
        if not (self.compare_gauges or self.compare_rings or self.compare_table):
            view = ChartView(min_height=240)
            view.setAccessibleName("Values across devices")
            view.draw(lambda p: chartspec.empty("Nothing to show yet"))
            lay.addWidget(view)
        lay.addStretch(1)
        self.compare_switch.setVisible("gauges" in kinds)
        self.compare_area.setWidget(body)                            # the previous page goes with it
        self.compare_area.reveal()

    def _vendor(self, key):
        """A device key's vendor as the catalog names it ('truenas')."""
        return (self.vendors.get(self._base(key)) or "").lower()

    def _limits(self, key, check, cache):
        """The warn and fail marks for a device's check from its own thresholds (its organization's, with its overrides)."""
        if key not in cache:
            dev = self.devs.get(self._base(key))
            if dev:                                                   # Global lists another organization's device without its folder
                dev = {**dev, "folder_id": dev.get("_folder_id", dev.get("folder_id"))}
            with db.within(db.split_key(key)[1]):
                cache[key] = db.thresholds_for(dev) if dev else db.get_thresholds()
        base = check.split(" (")[0]
        return cache[key].get(base) or (cache[key].get("disk") if base in DISK_CHECKS else None) or {}

    def _across_gauges(self, lay, shown, stored, rows, mine):
        """A gauge per device, worst first; datasets and TrueNAS drive temperatures a gauge per item, labelled 'device / item' (the
        latest items name them; an average is of each item's own numbers)."""
        days = self.compare_switch.currentData()
        avg = db.average_per_device(stored, days) if days else {}
        cache, dials = {}, []                                         # (label, value, status, limits, check, value text)

        def band(v, lim):
            return "FAIL" if lim.get("fail") and v >= lim["fail"] else "WARN" if lim.get("warn") and v >= lim["warn"] else "OK"

        def per_item(device, check, items, averages):
            lim, name = self._limits(device, check, cache), db.label_org(device)
            for it in items or []:
                v = averages.get((device, it["name"])) if days else it["numeric"]
                if v is not None:
                    d = it["data"] or {}
                    size = f"\n{human_size(d['used'])} of {human_size(d['total'])}" if d.get("used") is not None and d.get("total") else ""
                    dials.append((f"{name} / {it['name']}{size}", v, band(v, lim), lim, check, ""))
            return bool(items)

        itemized = shown == "datasets"
        latest = db.latest_items_per_device(stored) if itemized else {}
        item_avg = db.average_items_per_device(stored, days) if itemized and days else {}
        for r in rows:
            if itemized and per_item(r["device"], r["check_name"], latest.get((r["device"], r["check_name"]), (None, None))[1], item_avg):
                continue
            lim = self._limits(r["device"], r["check_name"], cache)
            v = avg.get(r["device"]) if days else r["numeric"]
            if v is not None:
                dials.append((db.label_org(r["device"]), v, band(v, lim) if days else r["status"], lim, r["check_name"], r["value"] or ""))
        if shown == "temperature":                                    # TrueNAS drives: their "disks" items are temperatures
            drives = {k: v for k, v in db.latest_items_per_device(["disks"]).items() if self._vendor(k[0]) == "truenas" and mine(k[0])}
            drive_avg = db.average_items_per_device(["disks"], days) if days and drives else {}
            for (device, _c), (_t, items) in drives.items():
                per_item(device, "temperature", items, drive_avg)
        dials.sort(key=lambda d: (WORST.get(d[2], 3), -d[1]))
        box = QWidget()
        grid = FlowLayout(8, 8)
        box.setLayout(grid)
        for label, value, _status, lim, check, text in dials:         # sized as the device page's dials are
            base = check.split(" (")[0]
            pct = "%" in text or base in PCT_GAUGES
            top = 100 if pct else max(value * 1.25, float(lim.get("fail") or 0) * 1.1, 1)
            m = re.search(r"\d\s*([%a-zA-Z/]+)\s*$", text)               # a measurement's own unit: '12 ms'
            unit = "%" if pct else " °C" if base == "temperature" else f" {m.group(1)}" if m and len(m.group(1)) <= 4 else ""
            g = LazyChart(210, 170, f"{label} dial", lambda p, v=value, w=lim.get("warn"), f=lim.get("fail"), t=label, u=unit, m=top:
                          chartspec.gauge(p, v, warn=w or None, fail=f or None, title=t, unit=u, maximum=m))
            grid.addWidget(g)
            self.compare_gauges.append(g)
        lay.addWidget(box)

    def _across_rings(self, lay, _shown, stored, rows, _mine):
        """A ring per device: its interfaces up, err-disabled and down, the total in the middle; a segment lists those underneath."""
        from ui.overtime import DETAIL                               # (ui.overtime imports this module)
        latest = db.latest_items_per_device(stored)
        box = QWidget()
        grid = FlowLayout(8, 8)
        box.setLayout(grid)
        for r in sorted(rows, key=lambda r: (WORST.get(r["status"], 3), db.label_org(r["device"]).lower())):
            _t, items = latest.get((r["device"], r["check_name"]), (None, None))
            label = db.label_org(r["device"])
            if items is None:                                         # stored before each interface was kept: the row's 'up/counted'
                m = re.match(r"\s*(\d+)\s*/\s*(\d+)", r["value"] or "")
                if not m:
                    continue
                up, total = int(m.group(1)), int(m.group(2))
                counts = {"OK": up, "FAIL" if r["status"] == "FAIL" else "WARN": total - up}     # shortcut: a FAIL row's err-disabled count as down
                listed = {s: [{"t": r["t"], "device": label, "status": r["status"], "value": display.value(r["value"]), "message": r["message"] or ""}]
                          for s in counts}
            else:
                total = len(items)
                counts = {s: sum(1 for i in items if i["status"] == s) for _n, s in RING_SEGMENTS}
                listed = {s: [{"t": r["t"], "device": label, "status": i["status"], "value": i["name"], "message": i["text"] or ""}
                              for i in items if i["status"] == s] for _n, s in RING_SEGMENTS}
            ring = LazyChart(240, 220, label, lambda p, c=counts, n=total, t=label: chartspec.ring(
                p, [(name, c.get(s, 0), chartspec.status_color(p, s)) for name, s in RING_SEGMENTS], n, title=t),
                clicked=lambda hit, rows_=listed: self._ring_segment(rows_, hit, DETAIL))
            grid.addWidget(ring)
            self.compare_rings.append(ring)
        lay.addWidget(box)
        self.compare_detail = DetailList()
        self.compare_detail.setMinimumHeight(160)
        self.compare_detail.hide()
        lay.addWidget(self.compare_detail)

    def _ring_segment(self, listed, hit, columns):
        status = dict(RING_SEGMENTS).get(hit.get("name")) if hit.get("kind") == "series" else None
        if status is None:
            return
        self.compare_detail.show_rows(listed.get(status, []), columns)
        self.compare_detail.show()

    def _across_list(self, lay, rows, columns):
        self.compare_table = DetailList()
        self.compare_table.setMinimumHeight(200)
        self.compare_table.show_rows(rows, columns)
        lay.addWidget(self.compare_table, 1)

    def _across_certs(self, lay, _shown, stored, _rows, mine):
        """Every certificate of every device, from each certificate check's newest row, fewest days left first."""
        from ui.overtime import CERTS, cert_rows                    # (ui.overtime imports this module)
        out = []
        for (device, c), (_t, items) in db.latest_items_per_device(stored).items():
            if mine(device):
                last = db.check_rows(device, c, 1)[-1] if items is None else None      # stored before each certificate was kept: its own row
                out += [{"device": db.label_org(device), **x} for x in cert_rows(c, last, items)]
        out.sort(key=lambda x: (x["days"] is None, x["days"] or 0))
        self._across_list(lay, out, [("device", "Device")] + CERTS)

    def _across_environment(self, lay, _shown, stored, rows, _mine):
        latest = db.latest_items_per_device(stored)
        out = []
        for r in rows:
            _t, items = latest.get((r["device"], r["check_name"]), (None, None))
            if items is None:                                         # stored before each component was kept: the row itself
                out.append({"device": db.label_org(r["device"]), "component": display.check_name(r["check_name"]), "state": display.value(r["value"])})
            out += [{"device": db.label_org(r["device"]), "component": it["name"], "state": it["text"] or it["status"] or ""} for it in items or []]
        self._across_list(lay, out, [("device", "Device"), ("component", "Component"), ("state", "State")])

    def _across_firmware(self, lay, _shown, _stored, rows, mine):
        """Each device's firmware row, and every other device whose version Toner has read (a Cisco ASA has no firmware row)."""
        found = {r["device"]: display.value(r["value"]) for r in rows}
        for key, dev in self.devs.items():
            version = db.software_of(dev)["version"]
            if version and key not in found and mine(key):
                found[key] = version
        out = sorted(({"device": db.label_org(k), "version": v} for k, v in found.items()), key=lambda x: x["device"].lower())
        self._across_list(lay, out, [("device", "Device"), ("version", "Version")])

    def _across_table(self, lay, _shown, _stored, rows, _mine):
        out = sorted(({"device": db.label_org(r["device"]), "value": display.value(r["value"]), "t": r["t"]} for r in rows), key=lambda x: x["device"].lower())
        self._across_list(lay, out, [("device", "Device"), ("value", "Value"), ("t", "Checked")])

    def _across_health(self, lay, _shown, _stored, rows, _mine):
        out = [{"device": db.label_org(r["device"]), "status": r["status"], "value": display.value(r["value"]), "message": r["message"] or "",
                "t": r["t"]} for r in sorted(rows, key=lambda r: (WORST.get(r["status"], 3), db.label_org(r["device"]).lower()))]
        self._across_list(lay, out, [("device", "Device"), ("status", "Status"), ("value", "Value"), ("message", "Message"), ("t", "Checked")])

    def draw_failures(self):
        days = int(self.fail_period.currentData() or 7)
        with db.including_archived(wants_archived(self.funnel)):
            rows = db.problems(days)
        names = self._group_names()
        if names is not None:
            rows = [r for r in rows if self._base(r["device"]) in names]
        self._fail_rows, self._fail_worst = [], []
        if not rows:
            self.fail_when.draw(lambda p: chartspec.empty(f"No failures or errors in the last {days} days"))
            self.fail_where.draw(lambda p: chartspec.empty(""))
            return
        now = datetime.now()
        self._fail_grid = grid = heatgrid.layout(now - timedelta(days=days), now)
        cells = {}
        per_device = {}
        for r in rows:
            try:
                t = datetime.strptime(str(r["t"])[:16], "%Y-%m-%d %H:%M")
            except ValueError:
                continue
            xy = grid.cell(t)
            if xy is None:
                continue
            cells[xy] = cells.get(xy, 0) + 1
            self._fail_rows.append((t, r))
            per_device[r["device"]] = per_device.get(r["device"], 0) + 1
        squares = [(x, y, n) for (x, y), n in cells.items()]
        self.fail_when.draw(lambda p: chartspec.heatmap(p, grid.cols, grid.rows, squares, title=f"When: FAIL and ERROR rows, last {days} days"))
        worst = sorted(per_device.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:12]
        self._fail_worst = [d for d, _n in worst]
        self.fail_where.draw(lambda p: chartspec.bars(p, [db.label_org(d) for d, _n in worst], [n for _d, n in worst], title="Where: devices with most",
                                                      horizontal=True, colors=[chartspec.status_color(p, "FAIL")] * len(worst)))

    def _fail_cell(self, hit):
        """A heatmap square (an hour of a date, or a date) was clicked: the FAIL and ERROR rows it counts."""
        v = hit.get("value") if hit.get("kind") == "series" else None
        if not (isinstance(v, list) and len(v) >= 2):
            return
        grid = self._fail_grid
        try:
            a, b = grid.slot(int(v[0]), int(v[1]))
        except IndexError:
            return
        rows = [(t, r) for t, r in self._fail_rows if a <= t < b]
        self._show_failures(f"Failures: {grid.rows[int(v[1])]} {grid.cols[int(v[0])]}" + (":00" if grid.hourly else ""), rows)

    def _fail_bar(self, hit):
        """A device's bar was clicked: its FAIL and ERROR rows."""
        i = hit.get("dataIndex")
        if hit.get("kind") != "series" or not isinstance(i, int) or not 0 <= i < len(self._fail_worst):
            return
        device = self._fail_worst[i]
        self._show_failures(f"Failures: {db.label_org(device)}", [(t, r) for t, r in self._fail_rows if r["device"] == device])

    def _show_failures(self, title, rows):
        """The rows behind a cell or a bar, newest first, in a window of their own (none for an empty cell)."""
        if not rows:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(820, 460)
        lay = QVBoxLayout(dlg)
        dlg.table = _table(["Time", "Device", "Check", "Status", "Message"])
        dlg.table.setItemDelegateForColumn(3, StatusDelegate(dlg.table))
        for t, r in sorted(rows, key=lambda tr: tr[0], reverse=True):
            i = dlg.table.rowCount()
            dlg.table.insertRow(i)
            for j, v in enumerate([t.strftime("%Y-%m-%d %H:%M"), db.label_org(r["device"]), display.check_name(r["check"]), r["status"],
                                   r.get("message") or ""]):
                dlg.table.setItem(i, j, QTableWidgetItem(str(v)))
        dlg.table.resizeColumnsToContents()
        lay.addWidget(dlg.table)
        self._fail_list = dlg
        dlg.show()

    def _pick_from_row(self, *_):
        """A check's row was chosen in the table: that device and that check go on the chart (a check with no numbers
        to chart leaves the device's usual pick)."""
        ix = self.detail.currentIndex()
        if not ix.isValid():
            return
        r = self.model.rows[self.proxy.mapToSource(ix).row()]
        device, check = self._base(r["device"]), r["check_name"]
        i = self.dev.findData(device)
        if i < 0:
            return
        self.dev.setCurrentIndex(i)                               # fills the checks and ticks the first
        label = display.check_name(check)
        if label in self.check_keys and self.chk.selected() != [label]:
            self.chk.set_selected([label])
            self.draw()

    # ---------- reports
    def report_rows(self):
        """The rows the checks table shows, in its order, as the report writers take them (Global: another organization's device
        named with it)."""
        rows = (self.model.rows[self.proxy.mapToSource(self.proxy.index(i, 0)).row()] for i in range(self.proxy.rowCount()))
        return [Result(db.label_org(r["device"]), r["check_name"], r["status"], r["value"] or "", r["message"] or "") for r in rows]

    def report_date(self):
        return self.range.describe()

    def scope_text(self):
        parts = [self.funnel.describe()] if self.funnel.active() else []
        if self.find.words():
            parts.append(f"search: {self.find.text().strip()}")
        return ", ".join(p for p in parts if p)

    def _export(self, title, pattern, fn, open_after=False):
        rows = self.report_rows()
        if not rows:
            toast(self, "No results to export.")
            return
        ext = pattern.split("*")[-1].rstrip(")")
        folder = db.get_setting("report_folder")
        start = os.path.join(folder, f"Toner-{datetime.now():%Y-%m-%d_%H%M}{ext}") if folder and os.path.isdir(folder) else ""
        path, _ = QFileDialog.getSaveFileName(self, title, start, pattern)
        if path:
            fn(rows, path, scope=", ".join(p for p in (self.range.describe(), self.scope_text()) if p), when=None)     # dated when made
            if open_after:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_csv(self):
        self._export("Export CSV", "CSV (*.csv)", reports.to_csv)

    def export_html(self):
        self._export("HTML report", "HTML (*.html)", reports.save_html, True)

    def export_pdf(self):
        self._export("PDF report", "PDF (*.pdf)", reports.save_pdf, True)

    def export_trend(self):
        data = trends.compute(self.trend_period.currentData())
        if not data["runs"]:
            toast(self, "There are no runs in that period yet. Run the checks first.")
            return
        folder = db.get_setting("report_folder")
        start = os.path.join(folder, f"Toner-trend-{datetime.now():%Y-%m-%d}") if folder and os.path.isdir(folder) else ""
        path, _chosen = QFileDialog.getSaveFileName(self, "Trend report", start, "PDF (*.pdf);;HTML (*.html);;CSV (*.csv)")
        if not path:
            return
        low = path.lower()
        (trends.to_csv if low.endswith(".csv") else trends.save_html if low.endswith(".html") else trends.save_pdf)(data, path)
        if not low.endswith(".csv"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

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
        with db.within(db.split_key(d or "")[1]):                         # that organization's limits
            th = db.get_thresholds()
        vendor = self.vendors.get(self._base(d), "") if d else ""
        self.panels.show_checks(d or "", vendor, picked if d else [], *self.range.span(), th)

    def screen_context(self):
        """What the Assistant is told about this page: the time range and the rows shown, and the device and checks on the chart."""
        keys = ("time", "device", "check", "status", "value", "message")
        out = {"page": "History", "time_range": self.range.describe(),
               "rows": [{k: self.proxy.index(i, j).data() for j, k in enumerate(keys)} for i in range(min(self.proxy.rowCount(), 400))]}
        if self.dev.currentData():
            out["chart"] = {"device": db.label(self.dev.currentData()), "checks": self.chk.selected()}
        return out
