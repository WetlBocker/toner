"""Choose Windows services from the computer's own list instead of typing their names."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

NAME = Qt.ItemDataRole.UserRole


class ServicePicker(QDialog):
    COLS = ["", "Name", "Display name", "State", "Startup"]

    def __init__(self, services, chosen, title, hint, source="", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        known = {s["name"].lower() for s in services}
        rows = [{"name": n, "display": "", "state": "Not on this computer", "start": ""} for n in chosen if n.lower() not in known]
        self.rows = rows + list(services)                       # what was typed before but is not installed stays visible
        picked = {n.lower() for n in chosen}
        from ui.finder import SearchBox
        self.search = SearchBox("Search services", "Type part of a service's name or display name.", page=self)
        self.running = QCheckBox("Running only")
        self.auto = QCheckBox("Automatic startup only")
        self.table = QTableWidget(len(self.rows), len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        for i, r in enumerate(self.rows):
            box = QTableWidgetItem("")
            box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            box.setCheckState(Qt.CheckState.Checked if r["name"].lower() in picked else Qt.CheckState.Unchecked)
            box.setData(NAME, r["name"])
            self.table.setItem(i, 0, box)
            for j, text in enumerate((r["name"], r["display"], r["state"], r["start"]), start=1):
                it = QTableWidgetItem(text)
                it.setToolTip(text)
                self.table.setItem(i, j, it)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, hh.ResizeMode.Interactive)
        hh.setSectionResizeMode(2, hh.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, hh.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 220)
        self.count = QLabel("")
        self.count.setProperty("muted", True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        top = QHBoxLayout()
        top.addWidget(self.search, 1)
        top.addWidget(self.running)
        top.addWidget(self.auto)
        lay = QVBoxLayout(self)
        intro = QLabel(hint + (f"  {source}" if source else ""))
        intro.setWordWrap(True)
        lay.addWidget(intro)
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.count)
        lay.addWidget(buttons)
        self.search.textChanged.connect(self._filter)
        self.running.toggled.connect(self._filter)
        self.auto.toggled.connect(self._filter)
        self.table.itemChanged.connect(lambda it: self._summary() if it.column() == 0 else None)
        self._filter()

    def _filter(self, *_):
        words = self.search.text().lower().split()
        for i, r in enumerate(self.rows):
            text = f"{r['name']} {r['display']}".lower()
            hide = (not all(w in text for w in words) or (self.running.isChecked() and r["state"] != "Running")
                    or (self.auto.isChecked() and r["start"] and r["start"] != "Auto"))
            checked = self.table.item(i, 0).checkState() == Qt.CheckState.Checked
            self.table.setRowHidden(i, hide and not checked and bool(words or self.running.isChecked() or self.auto.isChecked()))
        self._summary()

    def _summary(self):
        shown = sum(1 for i in range(self.table.rowCount()) if not self.table.isRowHidden(i))
        self.count.setText(f"{len(self.selected())} chosen   |   {shown} of {len(self.rows)} services shown")

    def selected(self):
        return [self.table.item(i, 0).data(NAME) for i in range(self.table.rowCount())
                if self.table.item(i, 0).checkState() == Qt.CheckState.Checked]
