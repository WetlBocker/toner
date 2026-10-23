"""Settings page: organizations (create, rename, archive, remove). Shown in Global only; changes happen right away. Several
organizations can be selected at once and archived, restored or removed together."""

from PySide6.QtCore import QItemSelection, QItemSelectionModel, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QColorDialog, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QRadioButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout)
from core import audit, db, orgs
from ui.settings_base import Page, note
from ui.toast import toast

MIXED_TIP = "Select only active or only archived organizations."


def swatch(colour, size=12):
    pm = QPixmap(size, size)
    pm.fill(QColor(colour or "#888888"))
    return QIcon(pm)


def listed(names):
    """'Acme', 'Acme and Beta', 'Acme, Beta and Contoso'."""
    names = list(names)
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


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
    """Remove one organization, or several at once: move what they have to another one, or delete it all. One organization is
    confirmed by typing its name, several by typing REMOVE. `org`: one organization's row, or a list of them."""

    def __init__(self, org, parent=None):
        super().__init__(parent)
        self.orgs = [org] if isinstance(org, dict) else list(org)
        self.org = self.orgs[0]
        several = len(self.orgs) > 1
        ids = {o["id"] for o in self.orgs}
        self.setWindowTitle("Remove organizations" if several else "Remove organization")
        self.setMinimumWidth(460)
        head = QLabel(f"Remove {len(self.orgs)} organizations?" if several else f"Remove {self.org['name']}?")
        head.setStyleSheet("font-weight:600;")
        self.names = QLabel(", ".join(o["name"] for o in self.orgs))
        self.names.setWordWrap(True)
        self.move = QRadioButton("Move their devices, sessions and history to:" if several else "Move its devices, sessions and history to:")
        self.delete = QRadioButton("Delete them permanently")
        group = QButtonGroup(self)
        group.addButton(self.move)
        group.addButton(self.delete)
        self.move.setChecked(True)
        self.dest = QComboBox()
        self.dest.addItem("Global", db.GLOBAL)
        for o in orgs.list_orgs():
            if o["id"] not in ids:
                self.dest.addItem(swatch(o["colour"]), o["name"], o["id"])
        self.move.toggled.connect(self.dest.setEnabled)
        self.word = "REMOVE" if several else self.org["name"]
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(self.word)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok = self.buttons.addButton("Remove", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setProperty("danger", True)
        self.ok.setEnabled(False)
        self.confirm.textChanged.connect(lambda t: self.ok.setEnabled(t == self.word))
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(head)
        if several:
            lay.addWidget(self.names)
        row = QHBoxLayout()
        row.addWidget(self.move)
        row.addWidget(self.dest, 1)
        lay.addLayout(row)
        lay.addWidget(self.delete)
        lay.addSpacing(6)
        lay.addWidget(QLabel(f"Type {self.word} to confirm"))
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
                                      "them all. Changes on this page happen right away. Select several (Ctrl or Shift) to archive, "
                                      "restore or remove them together."))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Code", "Colour", "Devices", "Status"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
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
        keep = set(self.selected_ids())
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
        self.table.resizeColumnsToContents()
        self.select_ids(keep)
        self.update_buttons()

    def refresh(self):
        self.load()

    def select_ids(self, ids):
        """Select the rows of these organizations (and nothing else)."""
        model = self.table.selectionModel()
        model.clearSelection()
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).data(Qt.ItemDataRole.UserRole) in ids:
                model.select(QItemSelection(self.table.model().index(i, 0), self.table.model().index(i, self.table.columnCount() - 1)),
                             QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
                self.table.setCurrentCell(i, 0, QItemSelectionModel.SelectionFlag.NoUpdate)

    def selected_ids(self):
        """The organizations whose rows are selected, in the order of the list."""
        rows = sorted({ix.row() for ix in self.table.selectionModel().selectedIndexes()})
        return [self.table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in rows if self.table.item(r, 0) is not None]

    def selected(self):
        """One selected organization's id (the first, when several are), or None."""
        ids = self.selected_ids()
        return ids[0] if ids else None

    def picked(self):
        """The selected organizations' rows."""
        return [o for o in (orgs.get(i) for i in self.selected_ids()) if o]

    def update_buttons(self):
        picked = self.picked()
        states = {bool(o["archived"]) for o in picked}
        self.rename_btn.setEnabled(len(picked) == 1)
        self.remove_btn.setEnabled(bool(picked))
        self.archive_btn.setEnabled(len(states) == 1)
        self.archive_btn.setText("Restore" if states == {True} else "Archive")
        self.archive_btn.setToolTip(MIXED_TIP if len(states) > 1 else "")

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
            self.select_ids({org})
            toast(self, f"{name} created. Pick it in the sidebar to work in it.")

    def rename(self):
        picked = self.picked()
        if len(picked) != 1:
            return
        org = picked[0]
        dlg = OrgDialog(org, self)
        if dlg.exec():
            name, code, colour = dlg.values()
            orgs.update(org["id"], name, code, colour)
            audit.log("organization renamed", f"{org['name']} -> {name}" if name != org["name"] else name)
            self._done()

    def toggle_archive(self):
        picked = self.picked()
        states = {bool(o["archived"]) for o in picked}
        if len(states) != 1:
            return
        several = len(picked) > 1
        if states == {True}:
            for o in picked:
                orgs.set_archived(o["id"], False)
                audit.log("organization restored", o["name"])
            self._done()
            toast(self, f"{len(picked)} organizations restored." if several else f"{picked[0]['name']} restored.")
            return
        if several:
            text = (f"Archive {len(picked)} organizations? {listed(o['name'] for o in picked)}. Their devices and history stay saved but "
                    "are hidden, their schedules and alerts stop, and they can only be viewed in the Global context. Restore them any "
                    "time in Global from Settings > Organizations.")
        else:
            text = (f"Archive {picked[0]['name']}? Its devices and history stay saved but are hidden, its schedules and alerts stop, and it "
                    "can only be viewed in the Global context. Restore it any time in Global from Settings > Organizations.")
        if QMessageBox.question(self, "Archive organizations" if several else "Archive organization", text) == QMessageBox.StandardButton.Yes:
            for o in picked:
                orgs.set_archived(o["id"], True)
                audit.log("organization archived", o["name"])
            self._done()

    def remove(self):
        picked = self.picked()
        if not picked:
            return
        several = len(picked) > 1
        dlg = RemoveDialog(picked if several else picked[0], self)
        if not dlg.exec():
            return
        dest = dlg.destination()
        try:
            if several:
                orgs.remove_many([o["id"] for o in picked], move_to=dest)
            else:
                orgs.remove(picked[0]["id"], move_to=dest)
        except ValueError as e:
            QMessageBox.warning(self, dlg.windowTitle(), str(e))
            return
        where = f" (moved to {db.org_name(dest)})" if dest is not None else " (deleted)"
        for o in picked:
            audit.log("organization removed", o["name"] + where)
        self._done()
        toast(self, f"{len(picked)} organizations removed." if several else f"{picked[0]['name']} removed.")
