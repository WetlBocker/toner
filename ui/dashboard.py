"""Overview: how the network is doing right now, from the stored results (so it is useful the moment Toner opens)."""
from datetime import datetime

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPalette, QPen
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QBoxLayout, QCheckBox, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QMenu,
                               QPushButton, QScrollArea, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)
import html

from core import acks, audit, backup, db, display, fleet, maintenance, notify, reports, scope, vendors
from ui import icons, theme
from ui.widgets import EmptyHint, FlowLayout, StatusDelegate, filling
from ui import status as st
from ui import motion
from ui.glance import GlanceMap
from ui.panels import Panel, ProgressLine
from PySide6.QtWidgets import QGraphicsOpacityEffect, QSizePolicy, QToolButton, QWidget


class Card(Panel):
    clicked = Signal()
    ICONS = {"OK": "check", "WARN": "warn-fill", "FAIL": "fail-fill", "devices": "inventory", "changes": "configs"}

    def __init__(self, title, color_key=None):
        super().__init__()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.color_key = color_key
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
        self.sub.setText(sub)
        self.sub.setVisible(False)                          # Demarc's tiles have no caption line: it is kept in the tooltip
        self._tip = self._tip if hasattr(self, "_tip") else self.toolTip()
        self.setToolTip(self._tip + (f"\n{sub}" if sub else ""))
        self.value.setStyleSheet("")                       # the number in the text colour, as on Demarc: the icon carries the status colour
        icon = self.ICONS.get(self.color_key)
        self.mark.setVisible(bool(icon))
        if icon:
            colour = st.ink(self.color_key) if self.color_key in ("OK", "WARN", "FAIL") else (theme.current() or {}).get("muted", "#888888")
            self.mark.setPixmap(icons.icon(icon, colour).pixmap(16, 16))

    def _pop_value(self):
        """The number swells and settles when it changes (nothing when motion is off)."""
        import math
        base = self._base_size()
        if self._pop is not None:
            self._pop.stop()
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
            if self._grow is not None:
                self._grow.stop()
            self.grown = 0.0
            self._grow = motion.animate(self, 900, self._on_grow)
        self.update()

    def _on_grow(self, v):
        self.grown = float(v)
        self.update()

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
            p.setPen(muted)
            p.drawText(QRectF(self.width() - 56, y, 56, 22), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       f"{pct:.1f}%" if pct is not None else "-")
        self.setToolTip("Share of runs in the period where nothing was worse than WARN")


class DashboardTab(QWidget):
    run_requested = Signal()
    backup_requested = Signal()
    open_device = Signal(str)
    goto = Signal(str)
    show_results = Signal(str)
    device_action = Signal(str, str)             # ("open" | "run" | "ssh" | "rdp", device name) from Needs attention                   # a card was clicked: Results, filtered to what it counts ("healthy", "warn", "fail")
    action = Signal(str)                  # a step of the getting-started card: add, scan, notify

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
        self.cards = {"devices": Card("Devices", "devices"), "ok": Card("Healthy", "OK"), "warn": Card("Warnings", "WARN"),
                      "fail": Card("Failing", "FAIL"), "changes": Card("Config changes", "changes")}
        grid = FlowLayout(12, 12)                                       # five tiles sharing the width; a narrow window wraps them
        for c in self.cards.values():
            c.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            grid.addWidget(c)
        self.cards["devices"].clicked.connect(lambda: self.goto.emit("Inventory"))
        for k, what in (("ok", "healthy"), ("warn", "warn"), ("fail", "fail")):
            self.cards[k].clicked.connect(lambda _=False, w=what: self.show_results.emit(w))
        self.cards["changes"].clicked.connect(lambda: self.goto.emit("Configs"))
        for k, tip in (("devices", "Open the Inventory"), ("ok", "Show OK results"), ("warn", "Show warnings"),
                       ("fail", "Show FAIL and ERROR"), ("changes", "Open Configs")):
            self.cards[k].setToolTip(tip)

        self.attention = QTableWidget(0, 5)
        self.attention.setHorizontalHeaderLabels(["Device", "Status", "What is wrong", "Checked", "Actions"])
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
        self.attention.setItemDelegateForColumn(1, StatusDelegate(self.attention))
        self.attention.verticalHeader().setDefaultSectionSize(34)       # room for the row's buttons
        self.attention.setMinimumHeight(230)
        self.attention.doubleClicked.connect(self._open)
        self.attention.setMinimumWidth(330)                            # "What is wrong" is the point of this table: never squeeze it away
        self.hint = EmptyHint(self.attention, "Nothing needs attention", "Every device's latest checks are OK")
        self.names = []
        self.rows = []                                                   # (name, health, put-aside state or None) per row
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

        self.map = GlanceMap()                                          # the devices as a small map, links from Tools > Topology
        self.map.open_device.connect(self.open_device)
        self.map_summary = QLabel("")
        self.map_summary.setProperty("muted", True)

        def panel(title, widget, extra=None):
            f = Panel()
            lay = QVBoxLayout(f.card)
            lay.setContentsMargins(16, 12, 16, 12)
            row = QHBoxLayout()
            lab = QLabel(title)
            lab.setStyleSheet("font-weight: 600;")
            row.addWidget(lab)
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
        left = panel("Needs attention", self.attention)
        left.card.layout().addLayout(self.attention_bar)
        right = QVBoxLayout()
        right.setSpacing(12)
        right.addWidget(panel("Network at a glance", self.map, self.map_summary))
        right.addWidget(panel("Availability", self.bars, self.period))
        right.addWidget(self.fleet_panel)
        right.addWidget(panel("Recent activity", self.recent), 1)
        cols = self.cols = QHBoxLayout()
        cols.setSpacing(12)
        cols.addWidget(left, 3)
        cols.addLayout(right, 2)

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
        """The look changed (the Panels knob, the theme): the panels and the map follow."""
        for p in self.findChildren(Panel):
            p.restyle()
        self.map.update()

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
        """The buttons on one row of Needs attention: {"open", "run", "connect"} (connect is None for a device with nothing to connect to)."""
        cell = self.attention.cellWidget(row, 4)
        return cell.buttons if cell else {}

    def _fade_in(self, table):
        """The list fades in after a refill (one effect on the whole table, taken off when done), unless motion is off."""
        if not motion.enabled() or not table.isVisible():
            return
        eff = QGraphicsOpacityEffect(table)
        table.setGraphicsEffect(eff)
        def finish():
            if table.graphicsEffect() is eff:
                table.setGraphicsEffect(None)
        motion.animate(table, 260, eff.setOpacity, start=0.25, end=1.0, on_done=finish)

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
                row.addWidget(b)
                self.step_buttons[key].append(b)
            self.steps[key] = (mark, label)
        hide = QPushButton("Hide")
        hide.setProperty("ghost", True)
        hide.setToolTip("Do not show this again")
        hide.clicked.connect(self._hide_start)
        row.addWidget(hide)
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
        if 0 <= r < len(self.names):
            self.open_device.emit(self.names[r])

    # ---------- doing something about a problem
    def _current(self):
        r = self.attention.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) and self.attention.selectionModel().isRowSelected(r) else None

    def _device(self, name):
        return db.find_device(name)

    @staticmethod
    def _connect_kind(dev):
        """'rdp', 'ssh' or '' for a device: what Connect opens."""
        return ("rdp" if dev["vendor"] == "windows" else "ssh" if vendors.uses_ssh_login(dev["vendor"]) else "") if dev else ""

    def _row_buttons(self, name):
        """Open, Run checks and SSH or Remote Desktop for one row, as small buttons in its Actions cell."""
        cell = QWidget()
        cell.setObjectName("rowActions")
        cell.setAutoFillBackground(True)                              # opaque: the table under it is see-through, and a see-through cell
        self._paint_cell(cell, False)                                 # would keep every earlier paint of its buttons
        lay = QHBoxLayout(cell)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(4)
        cell.buttons = {}
        kind = self._connect_kind(self._device(name))
        for key, caption, what in (("open", "Open", "open"), ("run", "Run checks", "run"),
                                   ("connect", {"rdp": "Remote Desktop", "ssh": "SSH"}.get(kind, ""), kind)):
            if not caption:
                cell.buttons[key] = None
                continue
            b = QPushButton(caption)
            b.setProperty("ghost", True)
            b.setAutoDefault(False)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedHeight(26)
            b.setStyleSheet("padding: 0 8px; min-height: 0;")
            b.clicked.connect(lambda _=False, w=what, n=name: self.device_action.emit(w, n))
            lay.addWidget(b)
            cell.buttons[key] = b
        lay.addStretch(1)                                              # two buttons sit together on the left, not spread apart
        return cell

    @staticmethod
    def _paint_cell(cell, selected):
        t = theme.current() or {}
        pal = cell.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(t.get("select" if selected else "surface", "#ffffff")))
        cell.setPalette(pal)

    def _attention_buttons(self):
        cur = self._current()
        sel = self.attention.selectionModel()
        for i in range(self.attention.rowCount()):                     # the Actions cell follows its row's selection colour
            cell = self.attention.cellWidget(i, 4)
            if cell is not None:
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
        cur = self._current()
        if not cur:
            return
        m = QMenu(self)
        m.addAction("Open device", lambda: self._device_act("open"))
        m.addAction("Run checks on this device", lambda: self._device_act("run"))
        kind = self._connect_kind(self._device(cur[0]))
        if kind:
            m.addAction(f"Open {'Remote Desktop' if kind == 'rdp' else 'SSH'}", lambda: self._device_act("connect"))
        m.addSeparator()
        if cur[2]:
            m.addAction("Undo (bring it back)", self._ack_clicked)
        else:
            m.addAction("Acknowledge", lambda: self._put_aside(None))
            sm = m.addMenu("Snooze")
            for label, hours in (("1 hour", 1), ("4 hours", 4), ("24 hours", 24), ("7 days", 168)):
                sm.addAction(label, lambda h=hours: self._put_aside(h))
        m.exec(self.attention.viewport().mapToGlobal(pos))

    def refresh(self, *_):
        devs = scope.keep(db.list_devices())
        enabled = [d for d in devs if d["enabled"]]
        health = db.device_health()
        known = {d["key"] for d in devs}
        health = {k: v for k, v in health.items() if k in known}
        count = lambda s: sum(1 for v in health.values() if v["status"] == s)
        bad = count("FAIL") + count("ERROR")
        changes = [c for c in backup.recent_changes(24) if c["device"] in known]
        self.cards["devices"].set(len(devs), f"{len(enabled)} enabled", active=False)
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
        self.names = [n for n, _ in problems]
        self.rows = [(n, v, aside.get(n, (None,))[0]) for n, v in problems]
        cells = [self._row_buttons(name) for name, _v in problems]
        if cells:                                                      # the buttons decide the column's width, set before they are placed
            self.attention.setColumnWidth(4, max(c.sizeHint().width() for c in cells) + 24)      # plus the row's own padding
        with filling(self.attention):
            self.attention.setRowCount(len(problems))
            muted = QColor((theme.current() or {}).get("muted", "#888888"))
            for i, (name, v) in enumerate(problems):
                what = "; ".join(display.said(display.check_name(c), m) for c, _, m in v["problems"][:2])
                if len(v["problems"]) > 2:
                    what += f"  (+{len(v['problems']) - 2} more)"
                if name in held:
                    what = "(maintenance) " + what
                if name in aside:
                    state, entry = aside[name]
                    what = (f"(acknowledged {display.ago(entry['at'])}) " if state == "acknowledged"
                            else f"(snoozed until {entry['until'][11:16]}) ") + what
                for j, text in enumerate([db.label_org(name), v["status"], what, self._ago(v["at"])]):
                    item = QTableWidgetItem(text)
                    item.setToolTip(v["at"] if j == 3 else text)
                    if name in aside and j != 1:
                        item.setForeground(muted)
                    self.attention.setItem(i, j, item)
                self.attention.setCellWidget(i, 4, cells[i])
                if name == keep:
                    self.attention.selectRow(i)
        self.attention.viewport().update()
        if self.names != was:
            self._fade_in(self.attention)
        hidden = sum(1 for n in aside if n in health and health[n]["status"] != "OK")
        self.show_aside.setText(f"Show put aside ({hidden})" if hidden else "Show put aside")
        self.show_aside.setVisible(bool(hidden) or self.show_aside.isChecked())
        self._attention_buttons()
        self.map.refresh(db.device_health())
        self.map_summary.setText(f"\u00b7 {self.map.summary}" if self.map.summary else "")
        self.hint.setVisible(not problems)
        self.hint.set_text("Nothing needs attention" if health else "No results yet",
                           (f"Every other device's latest checks are OK ({hidden} put aside)" if hidden else "Every device's latest checks are OK")
                           if health else "Press Run checks to see how the network is doing")

        av = db.availability(int(self.period.currentData()))
        rows = [(db.label_org(n), v["healthy"] / v["runs"] * 100, "") for n, v in av.items() if v["runs"] and n in known]
        rows.sort(key=lambda r: (r[1], r[0].lower()))
        self.bars.set_rows(rows[:10])

        parts = []
        if changes:
            parts.append("<b>Configuration changes (24 h)</b><br>" + "<br>".join(
                f"{html.escape(db.label_org(c['device']))} &nbsp; <span style='color:gray'>{c['taken_at']}  +{c['added']} / -{c['removed']}</span>"
                for c in changes[:6]))
        runs = db.list_runs(5)
        if runs:
            parts.append(("<b>Runs</b><br>" if changes else "") + "<br>".join(
                f"<span style='color:gray'>{r['started_at']}</span> &nbsp; OK {r['ok']} &nbsp; WARN {r['warn']} &nbsp; "
                f"FAIL {r['fail']} &nbsp; ERROR {r['error']}" for r in runs))
        self.recent.setText("<br><br>".join(parts) or "Nothing has happened yet.")
