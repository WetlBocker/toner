"""Choose which of a device's interfaces Toner checks, from the device's own list."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

NAME = Qt.ItemDataRole.UserRole
WAN_HINT = "Tick the interfaces that connect to the internet. Available bandwidth starts at the port speed; type your circuit speed in Mbps if it is lower."


def speed_text(bps):
    """A port speed as people say it: 1 Gbps, 100 Mbps."""
    mbps = bps / 1e6
    return f"{mbps / 1000:g} Gbps" if mbps >= 1000 else f"{mbps:g} Mbps"


class InterfacePicker(QDialog):
    COLS = ["", "Interface", "State now"]
    WAN_COLS = ["WAN", "Available bandwidth"]

    def __init__(self, interfaces, chosen, wan=None, choose_checked=True, title="Interfaces to check", hint="", parent=None):
        """interfaces: [(name, state)] or [(name, state, port speed in bps or None)]. wan: {name: Mbps or None} to offer the WAN columns
        (None: no such columns). choose_checked False hides the 'check only these' tick column."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 520)
        interfaces = [(i[0], i[1], i[2] if len(i) > 2 else None) for i in interfaces]
        self.has_wan = wan is not None
        wan = wan or {}
        known = {n.lower() for n, _s, _v in interfaces}
        gone = [(n, "Not on the device now", None) for n in dict.fromkeys([*chosen, *wan]) if n.lower() not in known]      # chosen before, but no longer there: kept, so it can be dropped on purpose
        self.rows = gone + interfaces
        picked = {n.lower() for n in chosen}
        wanted = {n.lower(): v for n, v in wan.items()}
        from ui.finder import SearchBox
        self.search = SearchBox("Search interfaces", "Type part of an interface name.", page=self)
        cols = self.COLS + (self.WAN_COLS if self.has_wan else [])
        self.table = QTableWidget(len(self.rows), len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        for i, (name, state, speed) in enumerate(self.rows):
            box = QTableWidgetItem("")
            box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            box.setCheckState(Qt.CheckState.Checked if name.lower() in picked else Qt.CheckState.Unchecked)
            box.setData(NAME, name)
            self.table.setItem(i, 0, box)
            for j, text in enumerate((name, state), start=1):
                it = QTableWidgetItem(text)
                it.setToolTip(text)
                self.table.setItem(i, j, it)
            if self.has_wan:
                tick = QTableWidgetItem("")
                tick.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                tick.setCheckState(Qt.CheckState.Checked if name.lower() in wanted else Qt.CheckState.Unchecked)
                self.table.setItem(i, 3, tick)
                edit = QLineEdit("" if wanted.get(name.lower()) is None else f"{wanted[name.lower()]:g}")
                edit.setPlaceholderText(f"{speed_text(speed)} (port speed)" if speed else "")
                self.table.setCellWidget(i, 4, edit)
        edits = [self.table.cellWidget(i, 4) for i in range(len(self.rows))] if self.has_wan else []
        if edits:                                                    # every box as wide as the longest port speed, rows tall enough for one
            wide = max(e.fontMetrics().horizontalAdvance(e.placeholderText()) for e in edits) + 32
            for e in edits:
                e.setMinimumWidth(wide)
            vh = self.table.verticalHeader()
            vh.setDefaultSectionSize(max(vh.defaultSectionSize(), edits[0].sizeHint().height() + 12))
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, hh.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, hh.ResizeMode.ResizeToContents)
        if self.has_wan:
            hh.setSectionResizeMode(3, hh.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(4, hh.ResizeMode.ResizeToContents)
        self.table.setColumnHidden(0, not choose_checked)
        self.count = QLabel("")
        self.count.setProperty("muted", True)
        self.up_btn, self.shown_btn, self.none_btn = QPushButton("Tick the ones that are up"), QPushButton("Tick all shown"), QPushButton("Clear all")
        for b in (self.up_btn, self.shown_btn, self.none_btn):
            b.setAutoDefault(False)
        self.up_btn.clicked.connect(lambda: self._tick(lambda i: self.rows[i][1] == "Up"))
        self.shown_btn.clicked.connect(lambda: self._tick(lambda i: not self.table.isRowHidden(i)))
        self.none_btn.clicked.connect(lambda: self._set_all(False))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        bar = QHBoxLayout()
        for b in (self.up_btn, self.shown_btn, self.none_btn):
            bar.addWidget(b)
            b.setVisible(choose_checked)
        bar.addStretch()
        lay = QVBoxLayout(self)
        intro = QLabel(hint or " ".join(([ "Tick the interfaces to check. The others are left alone: they are not counted as down, and their errors are not read."]
                                         if choose_checked else []) + ([WAN_HINT] if self.has_wan else [])))
        intro.setWordWrap(True)
        lay.addWidget(intro)
        lay.addWidget(self.search)
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.count)
        lay.addWidget(buttons)
        self.search.textChanged.connect(self._filter)
        self.table.itemChanged.connect(lambda it: self._summary() if it.column() == 0 else None)
        self._filter()

    def _filter(self, *_):
        words = self.search.text().lower().split()
        for i, (name, _s, _v) in enumerate(self.rows):
            self.table.setRowHidden(i, not all(w in name.lower() for w in words))
        self._summary()

    def _tick(self, rule):
        self.table.blockSignals(True)
        for i in range(self.table.rowCount()):
            if rule(i):
                self.table.item(i, 0).setCheckState(Qt.CheckState.Checked)
        self.table.blockSignals(False)
        self._summary()

    def _set_all(self, on):
        self.table.blockSignals(True)
        for i in range(self.table.rowCount()):
            self.table.item(i, 0).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        self.table.blockSignals(False)
        self._summary()

    def _summary(self):
        shown = sum(1 for i in range(self.table.rowCount()) if not self.table.isRowHidden(i))
        self.count.setText(f"{len(self.selected())} chosen   |   {shown} of {len(self.rows)} interfaces shown")

    def wan(self):
        """{name: circuit speed in Mbps, or None for the port speed} for the interfaces ticked as WAN."""
        out = {}
        for i, (name, _s, _v) in enumerate(self.rows):
            if self.has_wan and self.table.item(i, 3).checkState() == Qt.CheckState.Checked:
                try:
                    mbps = float(self.table.cellWidget(i, 4).text())
                except ValueError:
                    mbps = None
                out[name] = mbps if mbps and mbps > 0 else None
        return out

    def selected(self):
        return [self.table.item(i, 0).data(NAME) for i in range(self.table.rowCount())
                if self.table.item(i, 0).checkState() == Qt.CheckState.Checked]
