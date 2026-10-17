"""Choose which of a device's interfaces Toner checks, from the device's own list."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

NAME = Qt.ItemDataRole.UserRole


class InterfacePicker(QDialog):
    COLS = ["", "Interface", "State now"]

    def __init__(self, interfaces, chosen, title="Interfaces to check", hint="", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 520)
        known = {n.lower() for n, _s in interfaces}
        gone = [(n, "Not on the device now") for n in chosen if n.lower() not in known]      # chosen before, but no longer there: kept, so it can be dropped on purpose
        self.rows = gone + list(interfaces)
        picked = {n.lower() for n in chosen}
        from ui.finder import SearchBox
        self.search = SearchBox("Search interfaces", "Type part of an interface name.", page=self)
        self.table = QTableWidget(len(self.rows), len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        for i, (name, state) in enumerate(self.rows):
            box = QTableWidgetItem("")
            box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            box.setCheckState(Qt.CheckState.Checked if name.lower() in picked else Qt.CheckState.Unchecked)
            box.setData(NAME, name)
            self.table.setItem(i, 0, box)
            for j, text in enumerate((name, state), start=1):
                it = QTableWidgetItem(text)
                it.setToolTip(text)
                self.table.setItem(i, j, it)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, hh.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, hh.ResizeMode.ResizeToContents)
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
        bar.addStretch()
        lay = QVBoxLayout(self)
        intro = QLabel(hint or "Tick the interfaces to check. The others are left alone: they are not counted as down, and their errors are not read.")
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
        for i, (name, _s) in enumerate(self.rows):
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

    def selected(self):
        return [self.table.item(i, 0).data(NAME) for i in range(self.table.rowCount())
                if self.table.item(i, 0).checkState() == Qt.CheckState.Checked]
