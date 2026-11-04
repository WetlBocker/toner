"""Overview: how the network is doing right now, from the stored results (so it is useful the moment Toner opens)."""
from datetime import datetime

from PySide6.QtCore import QEvent, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QKeySequence, QPainter, QPalette, QPen, QPixmap, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QBoxLayout, QCheckBox, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QMenu,
                               QPushButton, QScrollArea, QTableWidget, QTableWidgetItem, QToolButton, QToolTip, QVBoxLayout, QWidget)
import html

from core import acks, audit, backup, db, display, fleet, maintenance, notify, reports, scope, vendors
from ui import icons, theme
from ui.widgets import EmptyHint, FlowLayout, RefreshButton, StatusDelegate, add_tools_menu, filling
from ui import status as st
from ui import motion
from ui import glance
from ui.glance import GlanceMap
from ui import orgboard
from ui import chartspec
from ui.webchart import ChartView
from ui.panels import Panel, ProgressLine
from PySide6.QtWidgets import QSizePolicy


ATTENTION_ROW = 36          # a row of Needs attention: room for its buttons
ATTENTION_EMPTY = 120       # the list's height while it has nothing to show (the hint sits there)
ATTENTION_PER_ORG = 25      # devices listed under an organization's heading before "Show 41 more" (the rest open on a click)
ATTENTION_ALL = 50          # the same without headings (one organization, or none)
ATTENTION_WORDS = 170       # the least "What is wrong" may have beside the row buttons; with less, the row gives up room (see _fit_columns)


class Card(Panel):
    clicked = Signal()
    ICONS = {"OK": "check", "WARN": "warn-fill", "FAIL": "fail-fill", "devices": "inventory", "changes": "configs"}

    def __init__(self, title, color_key=None, caption=""):
        super().__init__()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.color_key = color_key
        self.caption = caption                          # under the number: what a click does, or (status cards) what it counts
        self._pop = None
        self._lifted = False
        self.value = QLabel("0")
        f = self.value.font()
        f.setPointSizeF(f.pointSizeF() * 2.8)
        f.setBold(True)
        self.value.setFont(f)
        self.title = QLabel(title)
        self.title.setProperty("muted", True)
        tf = self.title.font()                          # a semibold heading in capitals, as on Demarc's tiles
        tf.setWeight(QFont.Weight.DemiBold)
        tf.setCapitalization(QFont.Capitalization.AllUppercase)
        self.title.setFont(tf)
        self.mark = QLabel()                            # the status icon before the heading (OK, WARN, FAIL cards)
        self.mark.setFixedSize(16, 16)
        self.mark.setVisible(False)
        self.sub = QLabel("")
        self.sub.setProperty("muted", True)
        self.sub.setWordWrap(True)                      # a long caption wraps instead of making the card wider
        self.title.setWordWrap(True)
        self.lay = lay = QVBoxLayout(self.card)
        lay.setContentsMargins(18, 12, 18, 12)
        lay.setSpacing(2)
        top = QHBoxLayout()
        top.setSpacing(6)
        top.addWidget(self.mark)
        top.addWidget(self.title, 1)
        lay.addLayout(top)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)

    def _base_size(self):
        return QApplication.font().pointSizeF() * (2.2 if theme.is_terminal() else 2.8)

    def set(self, value, sub="", active=True):
        changed = self.value.text() != str(value) and self.value.text() != "0" or (self.value.text() == "0" and str(value) != "0")
        self.value.setText(str(value))
        f = self.value.font()                              # big numbers in the standard look, a step smaller in the console look
        f.setPointSizeF(self._base_size())
        self.value.setFont(f)
        if changed and self.isVisible():
            self._pop_value()
        self.sub.setText(self.caption)                      # the caption (what a click does, or "of 6 devices"); the count's own words go in the tooltip
        self.sub.setVisible(bool(self.caption))
        self._tip = self._tip if hasattr(self, "_tip") else self.toolTip()
        self.setToolTip(self._tip + (f"\n{sub}" if sub else ""))
        self.value.setStyleSheet("")                       # the number in the text colour: the heading and its icon carry the status colour
        icon = self.ICONS.get(self.color_key)
        self.mark.setVisible(bool(icon))
        if icon:
            colour = st.ink(self.color_key) if self.color_key in ("OK", "WARN", "FAIL") else (theme.current() or {}).get("muted", "#888888")
            self.mark.setPixmap(icons.icon(icon, colour).pixmap(16, 16))
            self.title.setStyleSheet(f"color: {colour};" if self.color_key in ("OK", "WARN", "FAIL") else "")

    def _pop_value(self):
        """The number swells and settles when it changes (nothing when motion is off)."""
        import math
        base = self._base_size()
        motion.stop(self._pop)
        def step(v):
            f = self.value.font()
            f.setPointSizeF(base * (1 + 0.14 * math.sin(math.pi * float(v))))
            self.value.setFont(f)
        self._pop = motion.animate(self, 380, step, curve=motion.QEasingCurve.Type.OutQuad)

    def enterEvent(self, e):
        super().enterEvent(e)
        if motion.lively() and not self._lifted:
            self._lifted = True
            self.lay.setContentsMargins(18, 10, 18, 14)

    def leaveEvent(self, e):
        super().leaveEvent(e)
        if self._lifted:
            self._lifted = False
            self.lay.setContentsMargins(18, 12, 18, 12)

    def mousePressEvent(self, e):
        self.clicked.emit()


def data_font(base):
    """The figures' font: monospace, so the numbers line up (the font the Terminal look gives tables)."""
    f = QFont(base)
    f.setFamilies(["Cascadia Mono", "Consolas", "Courier New"])
    return f


class BarList(QWidget):
    """Name, bar and percentage per row."""

    def __init__(self):
        super().__init__()
        self.rows = []                         # [(label, percent or None, detail)]
        self.grown = 1.0                       # 0..1: how much of each bar is drawn (they grow in when the rows change)
        self._grow = None
        self.setMinimumHeight(40)

    def set_rows(self, rows):
        changed = rows != self.rows
        self.rows = rows
        self.setMinimumHeight(max(40, 30 * len(rows) + 8))
        if changed and rows:
            motion.stop(self._grow)
            self.grown = 0.0
            self._grow = motion.animate(self, 900, self._on_grow)
        self.update()

    def _on_grow(self, v):
        self.grown = float(v)
        self.update()

    def replay(self):
        """Fill the bars again, the rows fading in one after another (when the Overview comes into view)."""
        if not self.rows or not motion.enabled():
            return
        motion.stop(self._grow)
        self.grown = 0.0
        self._grow = motion.animate(self, 900, self._on_grow)
        motion.reveal(self, self.bands)

    def bands(self):
        """(top, height) of each row, for the reveal."""
        return [(6 + i * 30, 26) for i in range(len(self.rows))]

    def paintEvent(self, _):
        tk = theme.current() or {}
        text, muted, track = QColor(tk.get("text", "#222")), QColor(tk.get("muted", "#777")), QColor(tk.get("surface2", "#eee"))
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.rows:
            p.setPen(muted)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No history yet")
            return
        name_w = min(180, self.width() * 0.34)
        for i, (label, pct, detail) in enumerate(self.rows):
            y = 6 + i * 30
            p.setPen(text)
            fm = p.fontMetrics()
            p.drawText(QRectF(0, y, name_w - 8, 22), Qt.AlignmentFlag.AlignVCenter, fm.elidedText(label, Qt.TextElideMode.ElideRight, int(name_w - 8)))
            terminal = theme.is_terminal()
            bar = QRectF(name_w, y + (9 if terminal else 6), self.width() - name_w - 62, 5 if terminal else 10)
            rad = min(st.radius(), 5)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(track)
            p.drawRoundedRect(bar, rad, rad)
            if pct is not None:
                key = "OK" if pct >= 99.5 else "WARN" if pct >= 95 else "FAIL"
                p.setBrush(QColor(st.ink(key)))
                p.drawRoundedRect(QRectF(bar.left(), bar.top(), max(8.0, bar.width() * pct / 100 * self.grown), bar.height()), rad, rad)
            p.setPen(QColor(st.ink(key)) if pct is not None and key != "OK" else muted)      # a figure below the line in its status colour
            p.save()
            p.setFont(data_font(p.font()))
            p.drawText(QRectF(self.width() - 64, y, 64, 22), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       f"{pct:.1f}%" if pct is not None else "-")
            p.restore()

    def event(self, e):
        if e.type() == QEvent.Type.ToolTip:                # each row says how often its device was reached
            row = int((e.pos().y() - 6) // 30)
            if 0 <= row < len(self.rows) and self.rows[row][2]:
                QToolTip.showText(e.globalPos(), self.rows[row][2], self)
            else:
                QToolTip.hideText()
            return True
        return super().event(e)


class _Heading(QWidget):
    """An organization's heading in Needs attention on Global: a fold mark, its colour, its name, its worst status and its counts.
    A click folds or unfolds its devices."""
    clicked = Signal()

    def __init__(self, name, colour, status, counts):
        super().__init__()
        self.setAutoFillBackground(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName(f"{name}, {counts}" if counts else name)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 8, 0)
        lay.setSpacing(8)
        self.chevron = QLabel()
        self.dot = QLabel()
        self.dot.setPixmap(orgboard.dot(colour).pixmap(10, 10))
        self.name = QLabel(name)
        f = self.name.font()
        f.setBold(True)
        self.name.setFont(f)
        self.mark = QLabel()
        self.mark.setFixedSize(16, 16)
        pm = QPixmap(16, 16)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        st.mark(p, QPointF(8, 8), status, 12, soft=True)
        p.end()
        self.mark.setPixmap(pm)
        self.counts = QLabel(counts)
        self.counts.setProperty("muted", True)
        for w in (self.chevron, self.dot, self.name, self.mark, self.counts):
            lay.addWidget(w)
        lay.addStretch(1)
        self.set_open(True)

    def set_open(self, on):
        t = theme.current() or {}
        self.chevron.setPixmap(icons.icon("chev-down" if on else "chev-right", t.get("icon", t.get("muted", "#888888"))).pixmap(14, 14))

    def mousePressEvent(self, e):
        self.clicked.emit()


class DashboardTab(QWidget):
    run_requested = Signal()
    backup_requested = Signal()
    open_device = Signal(str)
    goto = Signal(str)
    show_results = Signal(str)                   # a card was clicked: Results, filtered to what it counts ("healthy", "warn", "fail")
    device_action = Signal(str, str)             # ("open" | "run" | "ssh" | "rdp", device name) from Needs attention
    attention_count = Signal(int, int, str)      # devices needing attention, how many of them fail, and that in words (the badge on Results)
    action = Signal(str)                  # a step of the getting-started card: add, scan, notify
    open_org = Signal(int)
    tool_requested = Signal(str, dict)    # Needs attention's menu > Open in Tools: 'ping' | 'mtr' | 'tls' | 'snmp', the device                # Global: an organization's Open (or its row in Organizations) was used: switch Toner to it

    PERIODS = [("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30)]

    def __init__(self):
        super().__init__()
        self.title = QLabel("Overview")
        self.title.setProperty("title", True)
        self.when = QLabel("")
        self.when.setProperty("muted", True)
        self.run_btn = QPushButton("Run checks")
        self.run_btn.setProperty("primary", True)
        self.backup_btn = QPushButton("Back up configs")
        self.run_btn.clicked.connect(self.run_requested)
        self.backup_btn.clicked.connect(self.backup_requested)
        head = QHBoxLayout()
        head.addWidget(self.title)
        head.addWidget(self.when, 1)
        self.refresh_btn = RefreshButton(self.refresh)                  # the page again from what is stored
        head.addWidget(self.refresh_btn)
        head.addWidget(self.backup_btn)
        head.addWidget(self.run_btn)
        self.progress = ProgressLine()                                  # fills under the header while checks run
        self.checking = set()

        self.moved = QLabel("")                                         # what changed since the previous run
        self.moved.setWordWrap(True)
        self.moved.setTextFormat(Qt.TextFormat.RichText)
        self.overlap = QLabel("")                                       # why the cards can add up to more than the devices
        self.overlap.setProperty("muted", True)
        self.overlap.setWordWrap(True)
        self.cards = {"devices": Card("Devices", "devices", "Open the Inventory"), "ok": Card("Healthy", "OK", "Show OK results"),
                      "warn": Card("Warnings", "WARN", "Show warnings"), "fail": Card("Failing", "FAIL", "Show FAIL and ERROR"),
                      "changes": Card("Config changes", "changes", "Open Configs")}
        grid = FlowLayout(12, 12, even=True)                            # five tiles sharing the width; a narrow window wraps them 3 + 2
        for c in self.cards.values():
            c.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            grid.addWidget(c)
        self.cards["devices"].clicked.connect(lambda: self.goto.emit("Inventory"))
        for k, what in (("ok", "healthy"), ("warn", "warn"), ("fail", "fail")):
            self.cards[k].clicked.connect(lambda _=False, w=what: self.show_results.emit(w))
        self.cards["changes"].clicked.connect(lambda: self.goto.emit("Configs"))
        for k, tip in (("devices", "Open the Inventory"), ("ok", "Click to show OK results"), ("warn", "Click to show warnings"),
                       ("fail", "Click to show FAIL and ERROR"), ("changes", "Open Configs")):
            self.cards[k].setToolTip(tip)

        self.attention = QTableWidget(0, 5)                            # the status chip first, then the device, as the mockup had it
        self.attention.setAccessibleName("Needs attention")
        self.attention.setHorizontalHeaderLabels(["Status", "Device", "What is wrong", "Checked", "Actions"])
        self.attention.horizontalHeader().setVisible(False)             # the rows explain themselves
        self.attention.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.attention.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.attention.verticalHeader().setVisible(False)
        self.attention.setShowGrid(False)
        hh = self.attention.horizontalHeader()                      # the explanation takes what the others leave
        hh.setStretchLastSection(False)
        for col, mode in ((0, hh.ResizeMode.ResizeToContents), (1, hh.ResizeMode.ResizeToContents), (2, hh.ResizeMode.Stretch),
                          (3, hh.ResizeMode.ResizeToContents), (4, hh.ResizeMode.Fixed)):
            hh.setSectionResizeMode(col, mode)
        self.attention.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.attention.setItemDelegateForColumn(0, StatusDelegate(self.attention))
        self.attention.verticalHeader().setDefaultSectionSize(ATTENTION_ROW)       # room for the row's buttons
        self.attention.viewport().setAutoFillBackground(True)           # an opaque list: a see-through one keeps stale paint of its buttons
        self.attention.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)   # the list is as tall as its rows
        self.attention.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)  # (a narrow list hides its Actions instead)
        self.attention.viewport().installEventFilter(self)
        self.attention.doubleClicked.connect(self._open)
        self.attention.cellClicked.connect(lambda r, _c: self._show_more(r) if r in self.mores else None)
        for key in ("Return", "Enter"):
            QShortcut(QKeySequence(key), self.attention, activated=self._open, context=Qt.ShortcutContext.WidgetShortcut)
        self.attention.setMinimumWidth(330)                            # "What is wrong" is the point of this table: never squeeze it away
        self.hint = EmptyHint(self.attention, "Nothing needs attention", "Every device's latest checks are OK")
        self.names = []                                                  # the device on each row (None on an organization's heading)
        self.rows = []                                                   # (name, health, put-aside state or None) per row (None on a heading)
        self.heads = {}                                                  # row -> organization id, for the headings on Global
        self.folded = set()                                              # organizations whose devices are folded under their heading
        self.mores = {}                                                  # row -> the group its "Show 41 more" opens (None: the whole list)
        self.more_open = set()                                           # groups shown in full
        self.attention.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.attention.customContextMenuRequested.connect(self._attention_menu)
        self.attention.itemSelectionChanged.connect(self._attention_buttons)
        # Acknowledge and Snooze act on the selected problem, under the list (Open, Run checks and Connect sit on each row)
        self.act_ack = QPushButton("Acknowledge")
        self.act_ack.setToolTip("Put this device's problems aside until they change: they leave this list and are not announced.\n"
                                "A new problem, or one that gets worse, brings the device back.")
        self.act_snooze = QToolButton()
        self.act_snooze.setText("Snooze")
        self.act_snooze.setToolTip("Put the problems aside for a while (they come back sooner if they get worse)")
        self.act_snooze.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        snooze = QMenu(self.act_snooze)
        for label, hours in (("1 hour", 1), ("4 hours", 4), ("24 hours", 24), ("7 days", 168)):
            snooze.addAction(label, lambda h=hours: self._put_aside(h))
        self.act_snooze.setMenu(snooze)
        self.show_aside = QCheckBox("Show put aside")
        self.show_aside.setToolTip("List acknowledged and snoozed devices too (marked)")
        self.show_aside.toggled.connect(self.refresh)
        self.act_ack.setAutoDefault(False)
        self.act_ack.clicked.connect(self._ack_clicked)
        self.attention_bar = QHBoxLayout()
        self.attention_bar.setSpacing(6)
        for w in (self.act_ack, self.act_snooze):
            self.attention_bar.addWidget(w)
        self.attention_bar.addStretch()
        self.attention_bar.addWidget(self.show_aside)

        self.period = QComboBox()
        for label, days in self.PERIODS:
            self.period.addItem(label, days)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        self.bars = BarList()
        self.recent = QLabel("")
        self.recent.setTextFormat(Qt.TextFormat.RichText)
        self.recent.setWordWrap(True)
        self.recent.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        self.health_chart = ChartView(min_height=210)                   # devices by status as a ring; a slice opens those results
        self.health_chart.clicked.connect(self._health_clicked)
        self.runs_chart = ChartView(min_height=200)                     # the last runs as stacked OK / WARN / FAIL / ERROR bars
        self.map = GlanceMap()                                          # the devices as a small map, links from Tools > Topology
        self.map.setMinimumWidth(330)                                   # the right column keeps room for the map's dots and their names
        self.map.open_device.connect(self.open_device)
        self.map_summary = QLabel("")
        self.map_summary.setProperty("muted", True)
        self.map_summary.setToolTip(glance.DOWN_TIP)

        def panel(title, widget, extra=None):
            f = Panel()
            lay = QVBoxLayout(f.card)
            lay.setContentsMargins(16, 12, 16, 12)
            row = QHBoxLayout()
            lab = QLabel(title)
            lab.setStyleSheet("font-weight: 600;")
            row.addWidget(lab)
            f.count = QLabel("")                                        # "· 3 devices" after the title, where a panel counts
            f.count.setProperty("muted", True)
            row.addWidget(f.count)
            row.addStretch()
            if extra is not None:
                row.addWidget(extra)
            lay.addLayout(row)
            lay.addWidget(widget, 1)
            return f
        self.fleet_label = QLabel("")
        self.fleet_label.setTextFormat(Qt.TextFormat.RichText)
        self.fleet_label.setWordWrap(True)
        self.fleet_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.fleet_panel = panel("Windows computers and certificates", self.fleet_label)
        left = self.attention_panel = panel("Needs attention", self.attention)
        left.card.layout().addLayout(self.attention_bar)
        right = QVBoxLayout()
        right.setSpacing(12)
        self.map_panel = panel("Network at a glance", self.map, self.map_summary)
        right.addWidget(self.map_panel)
        self.org_board = orgboard.OrgBoard(self)                       # Global with organizations: one row each, under Needs attention
        self.org_board.open_org.connect(self.open_org)                 # (its columns need the wide column; the map is not shown there)
        self.org_panel = panel("Organizations", self.org_board)
        self.org_panel.hide()
        right.addWidget(panel("Health", self.health_chart))
        right.addWidget(panel("Availability", self.bars, self.period))
        right.addWidget(panel("Last runs", self.runs_chart))
        right.addWidget(self.fleet_panel)
        right.addWidget(panel("Recent activity", self.recent), 1)
        cols = self.cols = QHBoxLayout()
        cols.setSpacing(12)
        left_col = QVBoxLayout()                                       # each panel ends under its last row, not level with the right column
        left_col.setSpacing(12)
        left_col.addWidget(left)
        left_col.addWidget(self.org_panel)
        left_col.addStretch(1)
        cols.addLayout(left_col, 2)
        cols.addLayout(right, 1)                                       # (two thirds to the problems: their words are the point of the page)

        self.start = self._build_start()
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(14)
        bl.addWidget(self.start)
        bl.addWidget(self.moved)
        bl.addLayout(grid)
        bl.addWidget(self.overlap)
        bl.addLayout(cols, 1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)
        lay = QVBoxLayout(self)
        lay.addLayout(head)
        lay.addWidget(self.progress)
        lay.addWidget(scroll, 1)
        self.refresh()

    def restyle(self):
        """The look changed (the Panels knob, the theme): the panels, the list's background and the map follow."""
        for p in self.findChildren(Panel):
            p.restyle()
        self._paint_viewport()
        self.map.update()
        self.health_chart.restyle()
        self.runs_chart.restyle()

    def _health_clicked(self, hit):
        """A slice of the Health ring: the Results page listing that status."""
        what = {"OK": "healthy", "WARN": "warn", "FAIL": "fail", "ERROR": "fail"}.get(hit.get("name"))
        if what:
            self.show_results.emit(what)

    def _charts(self, health, runs):
        counts = {"OK": 0, "WARN": 0, "FAIL": 0, "ERROR": 0}
        for v in health.values():
            counts[v["status"] if v["status"] in counts else "ERROR"] += 1
        self.health_chart.draw(lambda p: chartspec.donut(p, counts, order=("OK", "WARN", "FAIL", "ERROR")) if any(counts.values()) else chartspec.empty("No results yet"))
        recent = list(reversed(runs[:12]))                              # oldest on the left
        labels = [str(r["started_at"])[5:16].replace("-", "/") for r in recent]
        series = [(st, [int(r.get(k) or 0) for r in recent]) for st, k in (("OK", "ok"), ("WARN", "warn"), ("FAIL", "fail"), ("ERROR", "error"))]
        self.runs_chart.draw(lambda p: chartspec.grouped_bars(p, labels, series, stacked=True) if recent else chartspec.empty("No checks run yet"))

    # ---------- a run going now
    def run_started(self, names):
        """Results started a run on these devices: the map rings each of them until its results are in."""
        self.checking = set(names)
        self.map.set_checking(self.checking)

    def device_done(self, name):
        self.checking.discard(name)
        self.map.set_checking(self.checking)

    def set_progress(self, done, total):
        running = 0 <= done < total
        self.run_btn.setText("Checking\u2026" if running else "Run checks")
        self.progress.set_progress(done, total)
        if not running:
            self.checking = set()
            self.map.set_checking(self.checking)

    def row_actions(self, row):
        """The buttons on one row of Needs attention: {"open", "run", "connect", "more"} (connect is None for a device with nothing to connect to)."""
        cell = self.attention.cellWidget(row, 4)
        return cell.buttons if cell else {}

    def _fade_in(self, table):
        """The list's rows fly up and fade in after a refill (the effect takes itself off when done), unless motion is off."""
        motion.reveal(table)

    def entered(self):
        """The Overview came into view: the problems fly in, the availability bars fade in and fill again."""
        if not motion.enabled():
            return
        motion.reveal(self.attention)
        self.bars.replay()

    def _build_start(self):
        """A short list for a new installation: add devices, run the checks, set up alerts. Each step ticks itself off."""
        f = Panel()
        row = FlowLayout(8, 6)
        row.setContentsMargins(16, 8, 10, 8)
        f.card.setLayout(row)
        self.start_dots = QLabel("")                                    # one dash per step, filled as they are done
        self.start_dots.setTextFormat(Qt.TextFormat.RichText)
        self.start_title = QLabel("Getting started")
        self.start_title.setStyleSheet("font-weight: 600;")
        self.start_next = QLabel("")                                    # the next step to take
        self.start_next.setProperty("muted", True)
        row.addWidget(self.start_dots)
        row.addWidget(self.start_title)
        self.start_next.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row.addWidget(self.start_next)
        acts = QWidget()                                                # the step's buttons and Hide go to the next line together
        al = QHBoxLayout(acts)
        al.setContentsMargins(0, 0, 0, 0)
        al.setSpacing(8)
        self.steps, self.step_buttons = {}, {}
        for key, text, buttons in (("devices", "Add the devices to watch", (("Add a device", "add"), ("Scan the network", "scan"))),
                                   ("run", "Run the checks once to see how they are doing", (("Run checks", "run"),)),
                                   ("alerts", "Choose how to be told when something breaks", (("Set up notifications", "notify"),))):
            mark, label = QLabel(""), QLabel(text)                      # the step's state (its mark) and its wording, kept for the line above
            mark.hide()
            label.hide()
            self.step_buttons[key] = []
            for caption, action in buttons:
                b = QPushButton(caption)
                b.clicked.connect(lambda _=False, a=action: self.run_requested.emit() if a == "run" else self.action.emit(a))
                al.addWidget(b)
                self.step_buttons[key].append(b)
            self.steps[key] = (mark, label)
        hide = QPushButton("Hide")
        hide.setProperty("ghost", True)
        hide.setToolTip("Do not show this again")
        hide.clicked.connect(self._hide_start)
        al.addWidget(hide)
        row.addWidget(acts)
        return f

    def _hide_start(self):
        db.set_setting("onboarding_done", True)
        self.start.setVisible(False)

    def _update_start(self, devices, ran):
        done = {"devices": bool(devices), "run": bool(ran), "alerts": any(c.get("enabled", True) for c in notify.channels())}
        t = theme.current() or {}
        dots = []
        for key, (mark, label) in self.steps.items():
            mark.setText("✓" if done[key] else "•")
            for b in self.step_buttons[key]:
                b.setVisible(not done[key])
            dots.append(f"<span style='color:{t.get('accent' if done[key] else 'border', '#888888')}'>&#9644;</span>")
        self.start_dots.setText(" ".join(dots))
        left = [k for k, d in done.items() if not d]
        self.start_title.setText(f"Getting started: {len(left)} step{'s' if len(left) != 1 else ''} left" if left else "Getting started")
        self.start_next.setText(self.steps[left[0]][1].text() + "." if left else "")
        self.start.setVisible(not db.get_setting("onboarding_done") and not all(done.values()))

    STACK_BELOW = 880                    # a window narrower than this puts the panels one under the other, so none is squeezed

    def resizeEvent(self, e):
        super().resizeEvent(e)
        want = QBoxLayout.Direction.TopToBottom if self.width() < self.STACK_BELOW else QBoxLayout.Direction.LeftToRight
        if self.cols.direction() != want:
            self.cols.setDirection(want)

    def _fleet(self):
        """The Windows panel: only there when there are Windows computers (or certificates running out)."""
        s = fleet.summary()
        self.fleet_panel.setVisible(bool(s))
        if not s:
            return
        esc = html.escape
        words = {"agent": "by agent", "winrm": "by WinRM", "local": "on this PC"}
        how = ", ".join(f"{n} {words.get(k, k)}" for k, n in sorted(s["by"].items()))
        lines = [f"<b>{s['computers']}</b> computer" + ("" if s["computers"] == 1 else "s") + (f" ({esc(how)})" if how else "")] if s["computers"] else []
        found = False
        for key, heading in fleet.SECTIONS:
            rows = s["sections"][key]
            if rows:
                found = True
                shown = "; ".join(f"{esc(d)} ({esc(t)})" if t else esc(d) for d, t in rows[:5]) + (f"; and {len(rows) - 5} more" if len(rows) > 5 else "")
                lines.append(f"<b>{heading}</b> ({len(rows)}): {shown}")
        if not found:
            lines.append("Nothing needs attention.")
        self.fleet_label.setText("<br>".join(lines))

    @staticmethod
    def _ago(stamp):
        return display.ago(stamp)

    def _moved(self):
        """'Since the previous run: 2 got worse (edge-fw, nvr), 1 improved (core-sw2).'"""
        try:
            ch = db.changes_since_previous()
        except Exception:
            ch = {"worse": [], "better": []}
        names = scope.names()
        if names is not None:
            ch = {k: [x for x in v if x[0].split(" / ")[0] in names] for k, v in ch.items()}
        bits = []
        for key, word in (("worse", "got worse"), ("better", "improved")):
            if ch[key]:
                shown = ", ".join(f"{db.label_org(d)}: {a} to {b}" for d, a, b in ch[key][:5]) + ("..." if len(ch[key]) > 5 else "")
                bits.append(f"<b>{len(ch[key])} {word}</b> ({html.escape(shown)})")
        self.moved.setText("Since the previous run: " + "; ".join(bits) + "." if bits else "")
        self.moved.setVisible(bool(bits))

    def _open(self, *_):
        r = self.attention.currentRow()
        if r in self.mores:
            self._show_more(r)
        elif r in self.heads:
            self._fold(self.heads[r])
        elif 0 <= r < len(self.names) and self.names[r]:
            self.open_device.emit(self.names[r])

    def _show_more(self, row):
        self.more_open.add(self.mores[row])
        self.refresh()

    def _cap(self, entries, grouped):
        """At most ATTENTION_PER_ORG devices under each heading (ATTENTION_ALL without headings), worst first as listed, then a
        ("more", group, how many) row for the rest, unless that group was opened in full."""
        limit = ATTENTION_PER_ORG if grouped else ATTENTION_ALL
        out, group, shown, rest = [], None, 0, 0
        for e in entries + [("head", "end", None)]:
            if e[0] == "head":
                if rest:
                    out.append(("more", group, rest))
                group, shown, rest = e[1], 0, 0
            elif shown < limit or group in self.more_open:
                shown += 1
            else:
                rest += 1
                continue
            out.append(e)
        return out[:-1]

    def _fold(self, oid):
        """Fold an organization's devices under its heading, or unfold them."""
        (self.folded.discard if oid in self.folded else self.folded.add)(oid)
        self._show_folds()
        self._fit_attention()

    def _show_folds(self):
        group = None
        for r in range(self.attention.rowCount()):
            if r in self.heads:
                group = self.heads[r]
                w = self.attention.cellWidget(r, 0)
                if w is not None:
                    w.set_open(group not in self.folded)
                self.attention.setRowHidden(r, False)
            else:
                self.attention.setRowHidden(r, group is not None and group in self.folded)

    def _layout_rows(self, problems, aside):
        """Global with organizations: [("head", org, (name, colour, down, failing, warned)), ("dev", name, health), ...], each
        organization's devices under its heading, the organization worst off first (a device down, then failing, then warned)."""
        from core import orgs
        info = {o["id"]: (o["name"] + (f" ({o['code']})" if o.get("code") else ""), o["colour"]) for o in orgs.list_orgs()}
        groups = {}
        for n, v in problems:
            groups.setdefault(db.split_key(n)[1] or 0, []).append((n, v))
        out = []
        def order(oid):
            down, failing, warned = orgboard.tally([v for n, v in groups[oid] if n not in aside])
            return (-(3 if down else 2 if failing else 1 if warned else 0), -down, -failing, -warned, info.get(oid, ("Global",))[0].lower())
        for oid in sorted(groups, key=order):
            name, colour = info.get(oid, ("Global", ""))
            out.append(("head", oid, (name, colour) + orgboard.tally([v for n, v in groups[oid] if n not in aside])))
            out.extend(("dev", n, v) for n, v in groups[oid])
        return out

    def _heading(self, oid, name, colour, down, failing, warned):
        """An organization's heading row: its fold mark, colour, name, worst status and counts (columns 0-3), and Open (column 4)."""
        status = orgboard.worst(down, failing, warned, True)[0]
        head = _Heading(name, colour, status, orgboard.counts_text(down, failing, warned))
        head.clicked.connect(lambda o=oid: self._fold(o))
        cell = QWidget()
        cell.setAutoFillBackground(True)
        lay = QHBoxLayout(cell)
        lay.setContentsMargins(2, 2, 2, 2)
        cell.buttons = {}
        if oid:                                                        # Global's own devices are where Toner already is
            b = QPushButton("Open")
            b.setProperty("outline", True)
            b.setAutoDefault(False)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedHeight(28)
            b.setStyleSheet("padding: 0 7px; min-height: 0;")
            b.setFixedWidth(b.fontMetrics().horizontalAdvance("Open") + 18)
            b.setToolTip(f"Switch Toner to {name}")
            b.clicked.connect(lambda _=False, o=oid: self.open_org.emit(o))
            lay.addWidget(b)
            cell.buttons["switch"] = b
        lay.addStretch(1)
        for w in (head, cell):
            self._paint_cell(w, False, heading=True)
        return head, cell

    # ---------- doing something about a problem
    def _current(self):
        r = self.attention.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) and self.attention.selectionModel().isRowSelected(r) else None

    def _device(self, name):
        """From the list the last refresh read (find_device reads every organization's file: once per row was seconds)."""
        return getattr(self, "_devs", {}).get(name) or db.find_device(name)

    @staticmethod
    def _connect_kind(dev):
        """'rdp', 'ssh' or '' for a device: what Connect opens."""
        return ("rdp" if dev["vendor"] == "windows" else "ssh" if vendors.ssh_reachable(dev["vendor"]) else "") if dev else ""

    def _row_buttons(self, name, health=None):
        """Open, Run checks and SSH or Remote Desktop for one row, as small buttons in its Actions cell. A device Toner could not reach
        has Open and Ping instead (Run checks and SSH are still in its ··· menu)."""
        cell = QWidget()
        cell.setObjectName("rowActions")
        cell.setAutoFillBackground(True)                              # opaque: the table under it is see-through, and a see-through cell
        self._paint_cell(cell, False)                                 # would keep every earlier paint of its buttons
        lay = QHBoxLayout(cell)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(3)
        cell.buttons = {}
        dev = self._device(name)
        kind = self._connect_kind(dev)
        down = glance.is_down(health) and bool(dev and dev.get("host"))
        connect = ("Ping", "ping") if down else ({"rdp": "Remote Desktop", "ssh": "SSH"}.get(kind, ""), kind)
        for key, caption, what in (("open", "Open", "open"), ("run", "" if down else "Run checks", "run"),
                                   ("connect", *connect), ("more", "\u00b7\u00b7\u00b7", "more")):
            if not caption:
                cell.buttons[key] = None
                continue
            b = QPushButton(caption)
            b.setProperty("ghost" if key == "more" else "outline", True)      # bordered buttons, as the mockup drew them; "..." is quiet
            b.setAutoDefault(False)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedHeight(28)
            b.setStyleSheet("padding: 0 7px; min-height: 0;" + (" font-weight: 700; padding: 0 2px;" if key == "more" else ""))
            b.setFixedWidth(24 if key == "more" else b.fontMetrics().horizontalAdvance(caption) + 18)   # as wide as its word (a button's own hint is wider)
            if key == "more":
                b.setToolTip("More: open, run checks, connect, ping, acknowledge or snooze")
                b.clicked.connect(lambda _=False, n=name, btn=b: self._row_menu(n, btn))
            elif what == "ping":
                from ui.pingpop import ping_popup
                b.clicked.connect(lambda _=False, d=dev: ping_popup(self, d["name"], d["host"]))
            else:
                b.clicked.connect(lambda _=False, w=what, n=name: self.device_action.emit(w, n))
            lay.addWidget(b)
            cell.buttons[key] = b
        lay.addStretch(1)                                              # the buttons sit together on the left, not spread apart
        return cell

    def _row_menu(self, name, button):
        """The row's "..." button: the same choices as a right-click on the row, under the button."""
        if name in self.names:
            self.attention.selectRow(self.names.index(name))
        m = self._menu_for_current()
        if m is not None:
            m.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def _fit_attention(self):
        """The list is as tall as its rows (or the hint when there are none): the panel ends under the last device."""
        rows = sum(1 for r in range(self.attention.rowCount()) if not self.attention.isRowHidden(r))
        h = rows * ATTENTION_ROW + 2 * self.attention.frameWidth() if rows else ATTENTION_EMPTY
        self.attention.setFixedHeight(h + 2)
        self._fit_columns()

    def _fit_columns(self):
        """A list too narrow for every row button and a readable "What is wrong" gives up room in this order: the Checked time, then
        Run checks and SSH or Remote Desktop, then Open. The "···" button stays, and its menu has all of them, so a row can
        always be acted on where it is."""
        t, cells = self.attention, getattr(self, "_cells", [])
        if not t.rowCount() or not cells:
            return
        def width(keys):                                               # the widest row decides (one may have SSH, another nothing),
            return max(sum(c.buttons[k].width() + 3 for k in keys if c.buttons.get(k) is not None) for c in cells) + 16   # plus margins
        levels = ((True, ("open", "run", "connect", "more")), (False, ("open", "run", "connect", "more")),
                  (False, ("open", "more")), (False, ("more",)))
        hh = t.horizontalHeader()
        fits = lambda c: max(t.sizeHintForColumn(c), hh.sectionSizeHint(c))   # as Qt sizes them: the hidden headings count too
        room = t.viewport().width() - ATTENTION_WORDS - fits(0) - fits(1)
        when = fits(3)
        for keep_when, keys in levels:
            if (when if keep_when else 0) + width(keys) <= room:
                break
        t.setColumnHidden(3, not keep_when)
        for c in cells:
            for k, b in c.buttons.items():
                if b is not None:
                    b.setVisible(k in keys)
        heads = [t.cellWidget(r, 4) for r in self.heads]
        t.setColumnWidth(4, max([width(keys)] + [w.buttons["switch"].width() + 16 for w in heads if w is not None and w.buttons]))

    def eventFilter(self, obj, event):
        if obj is self.attention.viewport() and event.type() == QEvent.Type.Resize:
            self._fit_columns()
        return super().eventFilter(obj, event)

    @staticmethod
    def _paint_cell(cell, selected, heading=False):
        t = theme.current() or {}
        pal = cell.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(t.get("surface2" if heading else "select" if selected else "surface", "#ffffff")))
        cell.setPalette(pal)

    def _paint_viewport(self):
        """The list's background in the card's colour (it is opaque, so nothing painted earlier shows through)."""
        t = theme.current() or {}
        pal = self.attention.viewport().palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(t.get("surface", "#ffffff")))
        self.attention.viewport().setPalette(pal)

    def _attention_buttons(self):
        cur = self._current()
        sel = self.attention.selectionModel()
        for i in range(self.attention.rowCount()):                     # the Actions cell follows its row's selection colour
            cell = self.attention.cellWidget(i, 4)
            if cell is not None and i not in self.heads:
                self._paint_cell(cell, sel.isRowSelected(i))
        for b in (self.act_ack, self.act_snooze):
            b.setEnabled(cur is not None)
        self.act_ack.setText("Undo" if cur and cur[2] else "Acknowledge")
        self.act_ack.setToolTip("Bring this device back to the list" if cur and cur[2] else self.act_ack.toolTip())

    def _device_act(self, what):
        cur = self._current()
        if not cur:
            return
        name = cur[0]
        if what == "connect":
            dev = self._device(name)
            what = "rdp" if dev and dev["vendor"] == "windows" else "ssh"
        self.device_action.emit(what, name)

    def _ack_clicked(self):
        cur = self._current()
        if not cur:
            return
        if cur[2]:                                                         # already put aside: bring it back
            acks.clear(cur[0])
            audit.log("problem un-acknowledged", db.label_org(cur[0]))
            self.refresh()
        else:
            self._put_aside(None)

    def _put_aside(self, hours):
        cur = self._current()
        if not cur:
            return
        name, health = cur[0], cur[1]
        acks.put_aside(name, health["problems"], hours)
        what = "acknowledged" if hours is None else f"snoozed for {hours} h"
        audit.log("problem " + ("acknowledged" if hours is None else "snoozed"),
                  f"{db.label_org(name)}: {', '.join(c for c, _s, _m in health['problems'][:5])}" + ("" if hours is None else f" for {hours} h"))
        from ui.toast import toast
        toast(self, f"{db.label_org(name)} {what}. It comes back if anything gets worse.")
        self.refresh()

    def _attention_menu(self, pos):
        row = self.attention.rowAt(pos.y())
        if row < 0:
            return
        self.attention.selectRow(row)
        m = self._menu_for_current()
        if m is not None:
            m.exec(self.attention.viewport().mapToGlobal(pos))

    def _menu_for_current(self):
        """The choices for the selected problem: open, run, connect, and acknowledge or snooze (None while nothing is selected)."""
        cur = self._current()
        if not cur:
            return None
        m = QMenu(self)
        m.addAction("Open device", lambda: self._device_act("open"))
        m.addAction("Run checks on this device", lambda: self._device_act("run"))
        dev = self._device(cur[0])
        kind = self._connect_kind(dev)
        if kind:
            m.addAction(f"Open {'Remote Desktop' if kind == 'rdp' else 'SSH'}", lambda: self._device_act("connect"))
        if dev and dev.get("host"):
            from ui.pingpop import ping_popup
            m.addAction("Ping", lambda: ping_popup(self, dev["name"], dev["host"]))
            add_tools_menu(m, dev, self.tool_requested.emit)
        m.addSeparator()
        if cur[2]:
            m.addAction("Undo (bring it back)", self._ack_clicked)
        else:
            m.addAction("Acknowledge", lambda: self._put_aside(None))
            sm = m.addMenu("Snooze")
            for label, hours in (("1 hour", 1), ("4 hours", 4), ("24 hours", 24), ("7 days", 168)):
                sm.addAction(label, lambda h=hours: self._put_aside(h))
        return m

    def refresh(self, *_):
        devs = scope.keep(db.list_devices())
        self._devs = {d["key"]: d for d in devs}
        enabled = [d for d in devs if d["enabled"]]
        health = db.device_health()
        known = {d["key"] for d in devs}
        health = {k: v for k, v in health.items() if k in known}
        count = lambda s: sum(1 for v in health.values() if v["status"] == s)
        bad = count("FAIL") + count("ERROR")
        changes = [c for c in backup.recent_changes(24) if c["device"] in known]
        self.cards["devices"].set(len(devs), f"{len(enabled)} enabled", active=False)
        of = f"of {len(devs)} device{'' if len(devs) == 1 else 's'}"                 # the three status cards count devices, and say so
        for k in ("ok", "warn", "fail"):
            self.cards[k].caption = of
        self.cards["ok"].set(count("OK"), "all checks OK")
        warned = sum(1 for v in health.values() if any(sv == "WARN" for _c, sv, _m in v["problems"]))    # a device that also fails still has its warning
        self.cards["warn"].set(warned, "with a warning")
        self.cards["fail"].set(bad, "failing or unreachable")
        self.cards["changes"].set(len(changes), "in 24 hours", active=False)
        both = sum(1 for v in health.values() if v["status"] in ("FAIL", "ERROR") and any(sv == "WARN" for _c, sv, _m in v["problems"]))
        self.overlap.setText(f"{both} device{' has' if both == 1 else 's have'} both a warning and a failure, so it is counted in Warnings and in Failing." if both else "")
        self.overlap.setVisible(bool(both))
        self._moved()
        self._fleet()
        last = db.last_run()
        self._update_start(devs, last)
        held = maintenance.devices_in_maintenance()
        client = scope.name()
        self.when.setText((f"   {client}  ·" if client else "") + (f"   Last run {display.ago(last['started_at'])}" if last else "   No checks run yet")
                          + (f"   |   {len(held)} device(s) in maintenance: alerts held" if held else ""))

        aside = acks.put_aside_devices(health)
        problems = sorted(((n, v) for n, v in health.items() if v["status"] != "OK" and (n not in aside or self.show_aside.isChecked())),
                          key=lambda kv: (kv[0] in aside, -{"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}[kv[1]["status"]], kv[0].lower()))
        keep = self._current()[0] if self._current() else None
        was = self.names
        grouped = db.several()                                         # Global with organizations: each one's devices under its heading
        entries = self._cap(self._layout_rows(problems, aside) if grouped else [("dev", n, v) for n, v in problems], grouped)
        self.names = [x if kind == "dev" else None for kind, x, _v in entries]
        self.rows = [(x, v, aside.get(x, (None,))[0]) if kind == "dev" else None for kind, x, v in entries]
        self.heads = {i: x for i, (kind, x, _v) in enumerate(entries) if kind == "head"}
        self.mores = {i: x for i, (kind, x, _v) in enumerate(entries) if kind == "more"}
        self.attention.setRowCount(0)                                  # the list lets go of every row's widgets first: a heading's row can
        for old in getattr(self, "_placed", []):                       # become a device's, and it must not keep a deleted heading; then
            old.hide()                                                 # the old widgets go (Qt keeps them alive otherwise)
            old.setParent(None)
            old.deleteLater()
        cells = {i: self._row_buttons(x, v) for i, (kind, x, v) in enumerate(entries) if kind == "dev"}
        self._cells = list(cells.values())
        self._placed = list(self._cells)                               # every widget the list is given, the headings' too
        if cells:                                                      # the buttons decide the column's width, set before they are placed
            self._actions_w = max(c.sizeHint().width() for c in cells.values()) + 12             # plus the row's own padding
            self.attention.setColumnWidth(4, self._actions_w)
            self.attention.setColumnHidden(4, False)
        with filling(self.attention):
            self.attention.clearSpans()
            self.attention.setRowCount(len(entries))
            muted = QColor((theme.current() or {}).get("muted", "#888888"))
            for i, (kind, name, v) in enumerate(entries):
                if kind == "head":                                     # an organization's heading: spans the first four columns
                    head, cell = self._heading(name, *v)
                    self._placed += [head, cell]
                    for j in range(4):
                        item = QTableWidgetItem("")
                        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                        self.attention.setItem(i, j, item)
                    self.attention.setSpan(i, 0, 1, 4)
                    self.attention.setCellWidget(i, 0, head)
                    self.attention.setCellWidget(i, 4, cell)
                    continue
                if kind == "more":                                     # "Show 41 more": a click or Enter lists the rest of the group
                    for j in range(5):
                        item = QTableWidgetItem(f"Show {v} more" if j == 0 else "")
                        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                        item.setForeground(QColor((theme.current() or {}).get("accent", "#2563eb")))
                        item.setToolTip(f"Show {v} more")
                        self.attention.setItem(i, j, item)
                    self.attention.setSpan(i, 0, 1, 5)
                    continue
                since = db.down_since(name) if glance.is_down(v) else None
                if since:                                              # Toner could not reach it: for how long, and why
                    why = next((m for c, s, m in v["problems"] if c == "connection" and s == "ERROR"), "")
                    what = f"Down for {display.span(since)}" + (f": {why}" if why else "")
                else:
                    what = "; ".join(display.said(display.check_name(c), m) for c, _, m in v["problems"][:2])
                    if len(v["problems"]) > 2:
                        what += f"  (+{len(v['problems']) - 2} more)"
                if name in held:
                    what = "(maintenance) " + what
                if name in aside:
                    state, entry = aside[name]
                    what = (f"(acknowledged {display.ago(entry['at'])}) " if state == "acknowledged"
                            else f"(snoozed until {entry['until'][11:16]}) ") + what
                label = db.split_key(name)[0] if grouped else db.label_org(name)      # under its organization's heading, the name alone
                for j, text in enumerate([v["status"], label, what, self._ago(v["at"])]):
                    item = QTableWidgetItem(text)
                    item.setToolTip(v["at"] if j == 3 else f"Toner could not connect to it since {since[:16]}." if j == 2 and since else text)
                    if j == 1:                                         # the device's name stands out; the time is quiet
                        f = item.font()
                        f.setBold(True)
                        item.setFont(f)
                    if (name in aside and j != 0) or j == 3:
                        item.setForeground(muted)
                    self.attention.setItem(i, j, item)
                self.attention.setCellWidget(i, 4, cells[i])
                if name == keep:
                    self.attention.selectRow(i)
        self._show_folds()
        self._fit_attention()
        self.attention_panel.count.setText(f"\u00b7 {len(problems)} device{'s' if len(problems) != 1 else ''}" if problems else "")
        open_ = [(n, v) for n, v in problems if n not in aside]
        failing = sum(1 for _n, v in open_ if v["status"] in ("FAIL", "ERROR"))
        warned = len(open_) - failing
        parts = [f"{failing} failing"] * bool(failing) + [f"{warned} with a warning"] * bool(warned)
        words = (f"{len(open_)} device{'s need' if len(open_) != 1 else ' needs'} attention: " + ", ".join(parts)) if open_ else ""
        if grouped and open_:                                          # Global: and how many organizations that is
            n_orgs = len({db.split_key(n)[1] or 0 for n, _v in open_})
            words += f", across {n_orgs} organization{'s' if n_orgs != 1 else ''}"
        self.attention_count.emit(len(open_), failing, words)
        self.attention.viewport().update()
        if self.names != was:
            self._fade_in(self.attention)
        hidden = sum(1 for n in aside if n in health and health[n]["status"] != "OK")
        self.show_aside.setText(f"Show put aside ({hidden})" if hidden else "Show put aside")
        self.show_aside.setVisible(bool(hidden) or self.show_aside.isChecked())
        self._attention_buttons()
        self._paint_viewport()
        self.map.refresh(db.device_health())
        self.map_summary.setText(f"\u00b7 {self.map.summary}" if self.map.summary else "")
        self.map_panel.setVisible(not grouped)
        self.org_panel.setVisible(grouped)
        if grouped:
            self.org_board.fill(devs, health, set(aside))
            self.org_panel.count.setText(self.org_board.summary)
        self.hint.setVisible(not problems)
        self.hint.set_text("Nothing needs attention" if health else "No results yet",
                           (f"Every other device's latest checks are OK ({hidden} put aside)" if hidden else "Every device's latest checks are OK")
                           if health else "Press Run checks to see how the network is doing")

        av = db.availability(int(self.period.currentData()))
        rows = [(db.label_org(n), v["reachable"] / v["runs"] * 100, f"Reached in {v['reachable']} of {v['runs']} runs")
                for n, v in av.items() if v["runs"] and n in known]
        rows.sort(key=lambda r: (r[1], r[0].lower()))
        self.bars.set_rows(rows[:10])

        parts = []
        if changes:
            parts.append("<b>Configuration changes (24 h)</b><br>" + "<br>".join(
                f"{html.escape(db.label_org(c['device']))} &nbsp; <span style='color:gray'>{c['taken_at']}  +{c['added']} / -{c['removed']}</span>"
                for c in changes[:6]))
        runs = db.list_runs(12)
        self._charts(health, runs)
        runs = runs[:5]
        if runs:
            parts.append(("<b>Runs</b><br>" if changes else "") + "<br>".join(
                f"<span style='color:gray'>{r['started_at']}</span> &nbsp; OK {r['ok']} &nbsp; WARN {r['warn']} &nbsp; "
                f"FAIL {r['fail']} &nbsp; ERROR {r['error']}" for r in runs))
        self.recent.setText("<br><br>".join(parts) or "Nothing has happened yet.")
