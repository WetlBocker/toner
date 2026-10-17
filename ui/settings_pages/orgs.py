"""Settings page: organizations (create, rename, archive, remove). Shown in Global only; changes happen right away."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QColorDialog, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QRadioButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout)
from core import audit, db, orgs
from ui.settings_base import Page, note
from ui.toast import toast


def swatch(colour, size=12):
    pm = QPixmap(size, size)
    pm.fill(QColor(colour or "#888888"))
    return QIcon(pm)


class OrgDialog(QDialog):
    """New organization, or Rename: a name, a short code and a colour (the dot beside it in the switcher)."""

    def __init__(self, org=None, parent=None):
        super().__init__(parent)
        self.org = org or {}
        self.setWindowTitle("Rename organization" if org else "New organization")
        self.setMinimumWidth(400)
        self.name, self.code = QLineEdit(self.org.get("name", "")), QLineEdit(self.org.get("code", ""))
        self.name.setPlaceholderText("Acme Charter")
        self.code.setPlaceholderText("ACME")
        self.code.setMaxLength(12)
        self.colour = self.org.get("colour") or orgs.COLOURS[len(orgs.list_orgs()) % len(orgs.COLOURS)]
        self.pick = QPushButton("Choose...")
        self.pick.clicked.connect(self.choose)
        self._show_colour()
        self._code_typed = bool(org)
        self.code.textEdited.connect(lambda _t: setattr(self, "_code_typed", True))
        self.name.textChanged.connect(self._suggest)
        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("Code", self.code)
        form.addRow("Colour", self.pick)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.buttons)

    def _suggest(self, text):
        if not self._code_typed:
            self.code.setText(orgs.suggest_code(text) if text.strip() else "")

    def _show_colour(self):
        self.pick.setIcon(swatch(self.colour))

    def choose(self):
        c = QColorDialog.getColor(QColor(self.colour), self, "Organization colour")
        if c.isValid():
            self.colour = c.name()
            self._show_colour()

    def accept(self):
        try:
            orgs.clean(self.name.text(), self.code.text(), ignore=self.org.get("id"))
        except ValueError as e:
            QMessageBox.warning(self, self.windowTitle(), str(e))
            return
        super().accept()

    def values(self):
        return self.name.text().strip(), self.code.text().strip().upper(), self.colour


class RemoveDialog(QDialog):
    """Remove an organization: move what it has to another one, or delete it all; typing the name confirms."""

    def __init__(self, org, parent=None):
        super().__init__(parent)
        self.org = org
        self.setWindowTitle("Remove organization")
        self.setMinimumWidth(460)
        head = QLabel(f"Remove {org['name']}?")
        head.setStyleSheet("font-weight:600;")
        self.move = QRadioButton("Move its devices, sessions and history to:")
        self.delete = QRadioButton("Delete them permanently")
        group = QButtonGroup(self)
        group.addButton(self.move)
        group.addButton(self.delete)
        self.move.setChecked(True)
        self.dest = QComboBox()
        self.dest.addItem("Global", db.GLOBAL)
        for o in orgs.list_orgs():
            if o["id"] != org["id"]:
                self.dest.addItem(swatch(o["colour"]), o["name"], o["id"])
        self.move.toggled.connect(self.dest.setEnabled)
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(org["name"])
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok = self.buttons.addButton("Remove", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setProperty("danger", True)
        self.ok.setEnabled(False)
        self.confirm.textChanged.connect(lambda t: self.ok.setEnabled(t == org["name"]))
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(head)
        row = QHBoxLayout()
        row.addWidget(self.move)
        row.addWidget(self.dest, 1)
        lay.addLayout(row)
        lay.addWidget(self.delete)
        lay.addSpacing(6)
        lay.addWidget(QLabel(f"Type {org['name']} to confirm"))
        lay.addWidget(self.confirm)
        lay.addWidget(self.buttons)

    def destination(self):
        """The organization to move everything to, or None to delete it all."""
        return self.dest.currentData() if self.move.isChecked() else None


class OrganizationsPage(Page):
    title = "Organizations"
    track = False                                  # nothing here waits for Save changes
    changed_orgs = Signal()

    def __init__(self):
        super().__init__()
        self.lay.insertWidget(0, note("Each organization keeps its own devices, checks, results, sessions and settings. Global lists "
                                      "them all. Changes on this page happen right away."))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Code", "Colour", "Devices", "Status"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(220)
        self.table.doubleClicked.connect(lambda *_: self.rename())
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.new_btn = QPushButton("New organization...")
        self.rename_btn = QPushButton("Rename...")
        self.archive_btn = QPushButton("Archive")
        self.remove_btn = QPushButton("Remove...")
        self.new_btn.clicked.connect(self.new)
        self.rename_btn.clicked.connect(self.rename)
        self.archive_btn.clicked.connect(self.toggle_archive)
        self.remove_btn.clicked.connect(self.remove)
        bar = QHBoxLayout()
        for b in (self.new_btn, self.rename_btn, self.archive_btn, self.remove_btn):
            bar.addWidget(b)
        bar.addStretch(1)
        self.lay.insertWidget(1, self.table)
        self.lay.insertLayout(2, bar)
        self.load()

    def load(self):
        rows = orgs.list_orgs()
        keep = self.selected()
        self.table.setRowCount(len(rows))
        for i, o in enumerate(rows):
            n = orgs.counts(o["id"])["devices"]
            cells = [o["name"], o["code"], "", str(n), "Archived" if o["archived"] else "Active"]
            for j, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, o["id"])
                self.table.setItem(i, j, item)
            self.table.item(i, 2).setIcon(swatch(o["colour"]))
            self.table.item(i, 2).setText(o["colour"])
            if keep is not None and o["id"] == keep:
                self.table.selectRow(i)
        self.table.resizeColumnsToContents()
        self.update_buttons()

    def refresh(self):
        self.load()

    def selected(self):
        r = self.table.currentRow()
        if r < 0 or not self.table.selectedItems():
            return None
        return self.table.item(r, 0).data(Qt.ItemDataRole.UserRole)

    def update_buttons(self):
        org = orgs.get(self.selected()) if self.selected() is not None else None
        for b in (self.rename_btn, self.archive_btn, self.remove_btn):
            b.setEnabled(org is not None)
        self.archive_btn.setText("Restore" if org and org["archived"] else "Archive")

    def _done(self):
        self.load()
        self.changed_orgs.emit()

    def new(self):
        dlg = OrgDialog(parent=self)
        if dlg.exec():
            name, code, colour = dlg.values()
            org = orgs.create(name, code, colour)
            audit.log("organization created", name)
            self._done()
            for i in range(self.table.rowCount()):
                if self.table.item(i, 0).data(Qt.ItemDataRole.UserRole) == org:
                    self.table.selectRow(i)
            toast(self, f"{name} created. Pick it in the sidebar to work in it.")

    def rename(self):
        org = orgs.get(self.selected()) if self.selected() is not None else None
        if not org:
            return
        dlg = OrgDialog(org, self)
        if dlg.exec():
            name, code, colour = dlg.values()
            orgs.update(org["id"], name, code, colour)
            audit.log("organization renamed", f"{org['name']} -> {name}" if name != org["name"] else name)
            self._done()

    def toggle_archive(self):
        org = orgs.get(self.selected()) if self.selected() is not None else None
        if not org:
            return
        if org["archived"]:
            orgs.set_archived(org["id"], False)
            audit.log("organization restored", org["name"])
            self._done()
            toast(self, f"{org['name']} restored.")
            return
        text = (f"Archive {org['name']}? Its devices and history stay saved but are hidden, its schedules and alerts stop, and it can "
                "only be viewed in the Global context. Restore it any time in Global from Settings > Organizations.")
        if QMessageBox.question(self, "Archive organization", text) == QMessageBox.StandardButton.Yes:
            orgs.set_archived(org["id"], True)
            audit.log("organization archived", org["name"])
            self._done()

    def remove(self):
        org = orgs.get(self.selected()) if self.selected() is not None else None
        if not org:
            return
        dlg = RemoveDialog(org, self)
        if not dlg.exec():
            return
        dest = dlg.destination()
        try:
            orgs.remove(org["id"], move_to=dest)
        except ValueError as e:
            QMessageBox.warning(self, "Remove organization", str(e))
            return
        audit.log("organization removed", org["name"] + (f" (moved to {db.org_name(dest)})" if dest is not None else " (deleted)"))
        self._done()
        toast(self, f"{org['name']} removed.")
