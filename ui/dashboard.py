"""Overview: how the network is doing right now, from the stored results (so it is useful the moment Toner opens)."""
from datetime import datetime

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
                               QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
import html

from core import backup, db, display, fleet, maintenance, notify, reports
from ui import theme
from ui.widgets import EmptyHint, StatusDelegate


class Card(QFrame):
    clicked = Signal()

    def __init__(self, title, color_key=None):
        super().__init__()
        self.setProperty("card", True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.color_key = color_key
        self.value = QLabel("0")
        f = self.value.font()
        f.setPointSizeF(f.pointSizeF() * 2.4)
        f.setBold(True)
        self.value.setFont(f)
        self.title = QLabel(title)
        self.title.setProperty("muted", True)
        self.sub = QLabel("")
        self.sub.setProperty("muted", True)
        self.sub.setWordWrap(True)                      # a long caption wraps instead of making the card wider
        self.title.setWordWrap(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(2)
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)

    def set(self, value, sub="", active=True):
        self.value.setText(str(value))
        self.sub.setText(sub)
        color = reports.COLORS.get(self.color_key) if self.color_key and active and int(value or 0) else None
        self.value.setStyleSheet(f"color: {color};" if color else "")
        if color:                                                   # pastel fills are light; use a readable stroke
            self.value.setStyleSheet(f"color: {self._strong(color)};")

    @staticmethod
    def _strong(hexcolor):
        c = QColor(hexcolor)
        h, s, v, _ = c.getHsv()
        return QColor.fromHsv(h, min(255, max(s, 150) + 40), 190 if (theme.current() or {}).get("dark") is False else 255).name()

    def mousePressEvent(self, e):
        self.clicked.emit()


class BarList(QWidget):
    """Name, bar and percentage per row."""

    def __init__(self):
        super().__init__()
        self.rows = []                         # [(label, percent or None, detail)]
        self.setMinimumHeight(40)

    def set_rows(self, rows):
        self.rows = rows
        self.setMinimumHeight(max(40, 30 * len(rows) + 8))
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
            bar = QRectF(name_w, y + 6, self.width() - name_w - 62, 10)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(track)
            p.drawRoundedRect(bar, 5, 5)
            if pct is not None:
                key = "OK" if pct >= 99.5 else "WARN" if pct >= 95 else "FAIL"
                p.setBrush(QColor(reports.COLORS.get(key, "#888")))
                p.drawRoundedRect(QRectF(bar.left(), bar.top(), max(8.0, bar.width() * pct / 100), bar.height()), 5, 5)
            p.setPen(muted)
            p.drawText(QRectF(self.width() - 56, y, 56, 22), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       f"{pct:.1f}%" if pct is not None else "-")
        self.setToolTip("Share of runs in the period where nothing was worse than WARN")


class DashboardTab(QWidget):
    run_requested = Signal()
    backup_requested = Signal()
    open_device = Signal(str)
    goto = Signal(str)
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

        self.cards = {"devices": Card("Devices"), "ok": Card("Healthy", "OK"), "warn": Card("Warnings", "WARN"),
                      "fail": Card("Failing", "FAIL"), "changes": Card("Config changes")}
        grid = QHBoxLayout()
        grid.setSpacing(12)
        for c in self.cards.values():
            grid.addWidget(c, 1)
        self.cards["devices"].clicked.connect(lambda: self.goto.emit("Inventory"))
        for k in ("ok", "warn", "fail"):
            self.cards[k].clicked.connect(lambda: self.goto.emit("Results"))
        self.cards["changes"].clicked.connect(lambda: self.goto.emit("Configs"))

        self.attention = QTableWidget(0, 4)
        self.attention.setHorizontalHeaderLabels(["Device", "Status", "What is wrong", "Checked"])
        self.attention.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.attention.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.attention.verticalHeader().setVisible(False)
        self.attention.setShowGrid(False)
        hh = self.attention.horizontalHeader()                      # the explanation takes what the others leave
        hh.setStretchLastSection(False)
        for col, mode in ((0, hh.ResizeMode.ResizeToContents), (1, hh.ResizeMode.ResizeToContents), (2, hh.ResizeMode.Stretch),
                          (3, hh.ResizeMode.ResizeToContents)):
            hh.setSectionResizeMode(col, mode)
        self.attention.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.attention.setItemDelegateForColumn(1, StatusDelegate(self.attention))
        self.attention.setMinimumHeight(230)
        self.attention.doubleClicked.connect(self._open)
        self.hint = EmptyHint(self.attention, "Nothing needs attention", "Every device's latest checks are OK")
        self.names = []

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

        def panel(title, widget, extra=None):
            f = QFrame()
            f.setProperty("card", True)
            lay = QVBoxLayout(f)
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
        right = QVBoxLayout()
        right.setSpacing(12)
        right.addWidget(panel("Availability", self.bars, self.period))
        right.addWidget(self.fleet_panel)
        right.addWidget(panel("Recent activity", self.recent), 1)
        cols = QHBoxLayout()
        cols.setSpacing(12)
        cols.addWidget(left, 3)
        cols.addLayout(right, 2)

        self.start = self._build_start()
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(14)
        bl.addWidget(self.start)
        bl.addLayout(grid)
        bl.addLayout(cols, 1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)
        lay = QVBoxLayout(self)
        lay.addLayout(head)
        lay.addWidget(scroll, 1)
        self.refresh()

    def _build_start(self):
        """A short list for a new installation: add devices, run the checks, set up alerts. Each step ticks itself off."""
        f = QFrame()
        f.setProperty("card", True)
        lay = QVBoxLayout(f)
        lay.setContentsMargins(16, 12, 16, 12)
        top = QHBoxLayout()
        head = QLabel("Getting started")
        head.setStyleSheet("font-weight: 600;")
        top.addWidget(head)
        top.addStretch()
        hide = QPushButton("Hide")
        hide.setProperty("ghost", True)
        hide.setToolTip("Do not show this again")
        hide.clicked.connect(self._hide_start)
        top.addWidget(hide)
        lay.addLayout(top)
        self.steps = {}
        for key, text, buttons in (("devices", "Add the devices to watch", (("Add a device", "add"), ("Scan the network", "scan"))),
                                   ("run", "Run the checks once to see how they are doing", (("Run checks", "run"),)),
                                   ("alerts", "Choose how to be told when something breaks", (("Set up notifications", "notify"),))):
            row = QHBoxLayout()
            mark = QLabel("")
            mark.setFixedWidth(22)
            label = QLabel(text)
            row.addWidget(mark)
            row.addWidget(label, 1)
            for caption, action in buttons:
                b = QPushButton(caption)
                b.clicked.connect(lambda _=False, a=action: self.run_requested.emit() if a == "run" else self.action.emit(a))
                row.addWidget(b)
            lay.addLayout(row)
            self.steps[key] = (mark, label)
        return f

    def _hide_start(self):
        db.set_setting("onboarding_done", True)
        self.start.setVisible(False)

    def _update_start(self, devices, ran):
        done = {"devices": bool(devices), "run": bool(ran), "alerts": any(c.get("enabled", True) for c in notify.channels())}
        for key, (mark, label) in self.steps.items():
            mark.setText("✓" if done[key] else "•")
            f = label.font()
            f.setStrikeOut(done[key])
            label.setFont(f)
            label.setProperty("muted", done[key])
            label.style().unpolish(label)
            label.style().polish(label)
        self.start.setVisible(not db.get_setting("onboarding_done") and not all(done.values()))

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

    def _open(self, *_):
        r = self.attention.currentRow()
        if 0 <= r < len(self.names):
            self.open_device.emit(self.names[r])

    def refresh(self, *_):
        devs = db.list_devices()
        enabled = [d for d in devs if d["enabled"]]
        health = db.device_health()
        known = {d["name"] for d in devs}
        health = {k: v for k, v in health.items() if k in known}
        count = lambda s: sum(1 for v in health.values() if v["status"] == s)
        bad = count("FAIL") + count("ERROR")
        changes = backup.recent_changes(24)
        self.cards["devices"].set(len(devs), f"{len(enabled)} enabled", active=False)
        self.cards["ok"].set(count("OK"), "devices with all checks OK")
        warned = sum(1 for v in health.values() if any(st == "WARN" for _c, st, _m in v["problems"]))    # a device that also fails still has its warning
        self.cards["warn"].set(warned, "devices with a warning")
        self.cards["fail"].set(bad, "failing or unreachable")
        self.cards["changes"].set(len(changes), "in the last 24 hours", active=False)
        self._fleet()
        last = db.last_run()
        self._update_start(devs, last)
        held = maintenance.devices_in_maintenance()
        self.when.setText((f"   Last run {last['started_at']}" if last else "   No checks run yet")
                          + (f"   |   {len(held)} device(s) in maintenance: alerts held" if held else ""))

        problems = sorted(((n, v) for n, v in health.items() if v["status"] != "OK"),
                          key=lambda kv: (-{"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}[kv[1]["status"]], kv[0].lower()))
        self.names = [n for n, _ in problems]
        self.attention.setRowCount(len(problems))
        for i, (name, v) in enumerate(problems):
            what = "; ".join(f"{display.check_name(c)}: {m}" if m else display.check_name(c) for c, _, m in v["problems"][:2])
            if len(v["problems"]) > 2:
                what += f"  (+{len(v['problems']) - 2} more)"
            if name in held:
                what = "(maintenance) " + what
            for j, text in enumerate([name, v["status"], what, v["at"]]):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.attention.setItem(i, j, item)
        self.hint.setVisible(not problems)
        self.hint.findChildren(QLabel)[0].setText("Nothing needs attention" if health else "No results yet")
        self.hint.findChildren(QLabel)[1].setText("Every device's latest checks are OK" if health
                                                  else "Press Run checks to see how the network is doing")

        av = db.availability(int(self.period.currentData()))
        rows = [(n, v["healthy"] / v["runs"] * 100, "") for n, v in av.items() if v["runs"] and n in known]
        rows.sort(key=lambda r: (r[1], r[0].lower()))
        self.bars.set_rows(rows[:10])

        parts = []
        if changes:
            parts.append("<b>Configuration changes (24 h)</b><br>" + "<br>".join(
                f"{c['device']} &nbsp; <span style='color:gray'>{c['taken_at']}  +{c['added']} / -{c['removed']}</span>"
                for c in changes[:6]))
        runs = db.list_runs(5)
        if runs:
            parts.append(("<b>Runs</b><br>" if changes else "") + "<br>".join(
                f"<span style='color:gray'>{r['started_at']}</span> &nbsp; OK {r['ok']} &nbsp; WARN {r['warn']} &nbsp; "
                f"FAIL {r['fail']} &nbsp; ERROR {r['error']}" for r in runs))
        self.recent.setText("<br><br>".join(parts) or "Nothing has happened yet.")
