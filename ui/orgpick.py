"""Move to organization: the organizations in a list that scrolls and can be searched, instead of a menu that lists every one of
them (with many organizations the menu filled the screen)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout

from core import db, orgs


class OrgPicker(QDialog):
    def __init__(self, devs, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Move to organization")
        self.resize(380, 440)
        n = len(devs)
        self.note = QLabel(f"Move {n} device{'s' if n != 1 else ''} to:")
        self.find = QLineEdit()
        self.find.setPlaceholderText("Search organizations")
        self.find.setClearButtonEnabled(True)
        self.list = QListWidget()
        for text, dest in [("Global", db.GLOBAL)] + [(o["name"], o["id"]) for o in orgs.list_orgs(archived=False)]:
            it = QListWidgetItem(text)
            it.setData(Qt.ItemDataRole.UserRole, dest)
            if all(d.get("org") == dest for d in devs):                 # every device picked is there already
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                it.setToolTip("Already there")
            self.list.addItem(it)
        buttons = QDialogButtonBox()
        self.move_btn = buttons.addButton("Move", QDialogButtonBox.ButtonRole.AcceptRole)
        self.move_btn.setProperty("primary", True)
        self.move_btn.setEnabled(False)
        buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.find.textChanged.connect(self._filter)
        self.list.currentItemChanged.connect(lambda cur, _prev: self.move_btn.setEnabled(self._usable(cur)))
        self.list.itemDoubleClicked.connect(lambda it: self.accept() if self._usable(it) else None)
        lay = QVBoxLayout(self)
        lay.addWidget(self.note)
        lay.addWidget(self.find)
        lay.addWidget(self.list, 1)
        lay.addWidget(buttons)
        self.find.setFocus()

    @staticmethod
    def _usable(item):
        return item is not None and bool(item.flags() & Qt.ItemFlag.ItemIsEnabled)

    def _filter(self, text):
        words = text.lower().split()
        for i in range(self.list.count()):
            it = self.list.item(i)
            it.setHidden(not all(w in it.text().lower() for w in words))

    def chosen(self):
        """The organization picked (its id, 0 for Global), or None."""
        it = self.list.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if self._usable(it) and not it.isHidden() else None
