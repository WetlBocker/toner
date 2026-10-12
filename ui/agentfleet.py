"""Inventory > Agents: the computers that report to Toner through an agent, with their last report and what needs attention.
(The receiver, certificate, package and sign-up key stay in Settings > Agents.)"""
from datetime import datetime

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QLabel, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)
from core import agents, audit, db

DEVICE = Qt.ItemDataRole.UserRole           # on a row's first cell: which computer the row is, whatever the sort order
SORT_KEY = Qt.ItemDataRole.UserRole + 1     # on the Age cell: minutes, so "9 min" sorts before "2.0 h"


class _Item(QTableWidgetItem):
    """A cell that sorts by a number when it has one, else by its text."""

    def __lt__(self, other):
        a, b = self.data(SORT_KEY), other.data(SORT_KEY)
        return a < b if a is not None and b is not None else self.text().lower() < other.text().lower()


class AgentFleet(QWidget):
    changed = Signal()                    # a computer was removed: the inventory changed
    open_device = Signal(str)             # double-click: show this device
    open_settings = Signal()              # "Agent settings...": go to Settings > Agents
    COLS = ["Device", "Computer", "System", "Last report", "Age", "From", "Agent", "Notes"]
    COMPUTER, AGE, NOTES = 1, 4, 7

    def __init__(self):
        super().__init__()
        self.rows = []
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(False)
        for col in range(len(self.COLS)):
            hh.setSectionResizeMode(col, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(self.NOTES, hh.ResizeMode.Stretch)       # notes take what is left, so nothing needs a sideways scroll
        hh.setSectionResizeMode(2, hh.ResizeMode.Interactive)             # the system name can be long: cap it and cut it short, so the notes stay readable
        hh.resizeSection(2, 230)
        hh.setSortIndicatorShown(True)
        hh.setSortIndicator(0, Qt.SortOrder.AscendingOrder)               # by name, A to Z, until the user chooses otherwise
        self.table.setSortingEnabled(True)                                 # click a heading to sort
        self.info = QLabel("")
        self.info.setProperty("muted", True)
        self.info.setWordWrap(True)
        self.revoke = QPushButton("Revoke")
        self.revoke.setToolTip("Stop accepting this computer's agent. The device stays in the inventory.")
        self.remove = QPushButton("Remove...")
        self.remove.setToolTip("Delete the device and everything stored for it. The agent on the computer is not uninstalled.")
        self.reload_btn = QPushButton("Refresh")
        self.settings_btn = QPushButton("Agent settings...")
        self.settings_btn.setToolTip("The receiver, the agent package, sign-up and the certificate")
        bar = QHBoxLayout()
        for b in (self.revoke, self.remove, self.reload_btn):
            bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(self.settings_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.info)
        lay.addWidget(self.table, 1)
        lay.addLayout(bar)
        self.revoke.clicked.connect(self._revoke)
        self.remove.clicked.connect(self._remove)
        self.reload_btn.clicked.connect(self.refresh)
        self.settings_btn.clicked.connect(self.open_settings)
        self.table.itemSelectionChanged.connect(self._buttons)
        self.table.cellDoubleClicked.connect(self._double_clicked)
        self.timer = QTimer(self)                          # ages move on by themselves
        self.timer.setInterval(30_000)
        self.timer.timeout.connect(lambda: self.isVisible() and self.refresh())
        self.timer.start()
        self.refresh()

    @staticmethod
    def _when(stamp):
        """'2026-10-11 03:10' in this computer's time (reports are stored in UTC)."""
        try:
            return datetime.fromisoformat(stamp).astimezone().strftime("%Y-%m-%d %H:%M") if stamp else ""
        except ValueError:
            return stamp

    @staticmethod
    def _age(minutes):
        if minutes is None:
            return "never"
        return f"{minutes:.0f} min" if minutes < 120 else f"{minutes / 60:.1f} h" if minutes < 2880 else f"{minutes / 1440:.0f} days"

    def refresh(self, *_):
        keep = set(self._selected())
        fail = float(db.get_thresholds()["agent_silent"]["fail"])
        hh = self.table.horizontalHeader()
        sort_col, sort_order = hh.sortIndicatorSection(), hh.sortIndicatorOrder()
        self.rows = agents.overview()
        self.table.setSortingEnabled(False)                                # fill in order, then sort once
        self.table.setRowCount(len(self.rows))
        silent = 0
        for i, r in enumerate(self.rows):
            age = r["age"]
            notes = []
            if not r["has_token"]:
                notes.append("revoked or no token")
            elif age is None:
                notes.append("no report yet")
            elif age > fail:
                notes.append("silent")
                silent += 1
            if r["pending_reboot"]:
                notes.append("reboot pending")
            if r["version"] and agents.agent_outdated(r["version"]):
                notes.append("agent will update")
            vals = (r["device"], r["computer"], r["os"].replace("Microsoft ", "") + (f"  ({r['domain']})" if r["domain"] else ""),
                    self._when(r["received_at"]), self._age(age), r["source"], f"v{r['version']}" if r["version"] else "", ", ".join(notes))
            for j, v in enumerate(vals):
                item = _Item(v)
                item.setToolTip(v)
                if j == 0:
                    item.setData(DEVICE, r["device"])
                if j == self.AGE:
                    item.setData(SORT_KEY, age if age is not None else 1e12)
                if j == self.NOTES and ("silent" in v or "revoked" in v):
                    item.setForeground(QColor("#d32f2f"))
                self.table.setItem(i, j, item)
        same = all((r["computer"] or "").lower() in ("", r["device"].lower()) for r in self.rows)
        self.table.setColumnHidden(self.COMPUTER, bool(self.rows) and same)    # the same name twice is only clutter
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(sort_col if sort_col >= 0 else 0, sort_order)
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).data(DEVICE) in keep:
                self.table.selectRow(i)
        n = len(self.rows)
        self.info.setText(f"{n} computer{'' if n == 1 else 's'} reporting through an agent" + (f", {silent} silent." if silent else ".")
                          if self.rows else "No computer reports through an agent yet. Turn on the receiver and download the package in "
                                            "Settings > Agents, or add a Windows device with How to monitor: Agent.")
        self._buttons()

    def count(self):
        return len(agents.overview())

    def silent_count(self):
        fail = float(db.get_thresholds()["agent_silent"]["fail"])
        return sum(1 for r in agents.overview() if r["has_token"] and r["age"] is not None and r["age"] > fail)

    def _buttons(self):
        have = bool(self.table.selectionModel().selectedRows()) if self.table.rowCount() else False
        self.revoke.setEnabled(have)
        self.remove.setEnabled(have)

    def _selected(self):
        return [self.table.item(i.row(), 0).data(DEVICE) for i in self.table.selectionModel().selectedRows()
                if self.table.item(i.row(), 0) is not None]

    def _double_clicked(self, row, _col):
        item = self.table.item(row, 0)
        if item is not None:
            self.open_device.emit(item.data(DEVICE))

    def _revoke(self):
        names = self._selected()
        if names and QMessageBox.question(self, "Revoke", "Stop accepting the agent on: " + ", ".join(names) + "?\n\nThe device stays in the "
                                          "inventory. To start again, give the computer a new package or script.") == QMessageBox.StandardButton.Yes:
            for n in names:
                agents.revoke(n)
                audit.log("agent revoked", n)
            self.refresh()

    def _remove(self):
        names = self._selected()
        if not names or QMessageBox.question(self, "Remove", "Delete " + ", ".join(names) + " from Toner, with its reports and token?\n\n"
                                             "The agent on the computer is not uninstalled.") != QMessageBox.StandardButton.Yes:
            return
        for n in names:
            for d in [x for x in db.list_devices() if x["name"] == n]:
                db.delete_device(d["id"])
            db.delete_device_secrets(n)
            agents.forget(n)
            audit.log("agent removed", n)
        self.refresh()
        self.changed.emit()
