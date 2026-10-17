"""Link... beside a password: use an item that already exists in the password manager (Bitwarden, Vaultwarden, Keeper,
1Password) instead of typing the password into Toner. Toner keeps a stored copy as a fallback (core/extstore.py).

Shown only while a password manager is chosen in Settings > Security."""
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from core import extstore, extvault, passvault

KEEP = object()                              # the link as it was (nothing chosen in the window)


def wanted():
    """True when a password manager is chosen, so a password can be linked."""
    return passvault.is_open() and extstore.active() != "toner"


class _Search(QThread):
    found = Signal(list, str)

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.text = text

    def run(self):
        try:
            conn = extstore.connector()
            conn.connect()
            extstore.keep_new_secrets(extstore.active(), conn)
            self.found.emit(conn.search(self.text), "")
        except extvault.ExtError as e:
            self.found.emit([], str(e))


class LinkDialog(QDialog):
    """Link to a Bitwarden item: search, pick one, Link."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.label = extvault.LABELS[extstore.active()]
        self.setWindowTitle(f"Link to a {self.label} item")
        self.resize(620, 440)
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search")
        self.query.returnPressed.connect(self.search)
        self.list = QTreeWidget()
        self.list.setHeaderLabels(["Name", "User name", extvault.CONTAINER_WORD[extstore.active()]])
        self.list.setRootIsDecorated(False)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.itemDoubleClicked.connect(lambda *_: self.accept())
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.buttons = QDialogButtonBox()
        self.ok = self.buttons.addButton("Link", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setProperty("primary", True)
        self.buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.list.itemSelectionChanged.connect(lambda: self.ok.setEnabled(bool(self.list.selectedItems())))
        self.ok.setEnabled(False)
        lay = QVBoxLayout(self)
        lay.addWidget(self.query)
        lay.addWidget(self.list, 1)
        lay.addWidget(self.note)
        lay.addWidget(self.buttons)
        self.worker = None
        self.search()

    def search(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.note.setText(f"Connecting to {self.label}...")
        self.worker = _Search(self.query.text().strip(), self)
        self.worker.found.connect(self._show)
        self.worker.start()

    def _show(self, items, error):
        self.list.clear()
        if error:
            self.note.setText(f"Couldn't connect to {self.label}: {error}")
            return
        self.note.setText("")
        for it in sorted(items, key=lambda i: i.title.lower()):
            row = QTreeWidgetItem([it.title, it.username, it.container])
            row.setData(0, Qt.ItemDataRole.UserRole, {"ref": it.ref, "title": it.title})
            self.list.addTopLevelItem(row)
        for c in range(3):
            self.list.resizeColumnToContents(c)

    def chosen(self):
        sel = self.list.selectedItems()
        return sel[0].data(0, Qt.ItemDataRole.UserRole) if sel else None

    def done(self, r):
        if self.worker is not None:
            self.worker.wait(100)
        super().done(r)


class LinkRow(QWidget):
    """'Link...' or 'Linked to: <item>' with Unlink, under a password box."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.link_btn, self.unlink_btn = QPushButton("Link..."), QPushButton("Unlink")
        self.label = QLabel("")
        self.link_btn.clicked.connect(self.pick)
        self.unlink_btn.clicked.connect(self.unlink)
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(self.label)
        h.addWidget(self.link_btn)
        h.addWidget(self.unlink_btn)
        h.addStretch(1)
        self.current = None                  # the link now: {'ref', 'title'} or None
        self.choice = KEEP                   # what to save: KEEP, a new link, or None to unlink
        self._show()

    def load(self, secret_name):
        """The link the password `secret_name` has (a qualified vault name), if any."""
        self.current = extstore.link_of(secret_name) if (secret_name and wanted()) else None
        self.choice = KEEP
        self._show()

    def _now(self):
        return self.current if self.choice is KEEP else self.choice

    def _show(self):
        now = self._now()
        self.label.setText(f"Linked to: {now['title']}" if now else "")
        self.label.setVisible(bool(now))
        self.unlink_btn.setVisible(bool(now))
        self.link_btn.setVisible(not now)

    def pick(self):
        dlg = LinkDialog(self)
        if dlg.exec() and dlg.chosen():
            self.choice = dlg.chosen()
            self._show()

    def unlink(self):
        self.choice = None
        self._show()

    def linked(self):
        return bool(self._now())

    def apply(self, secret_name):
        """Save the choice for the password `secret_name` (its full vault name, as db.secret_name gives it)."""
        if self.choice is KEEP or not secret_name or not wanted():
            return
        extstore.set_link(secret_name, self.choice)
