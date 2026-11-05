"""Settings page: Accounts and sign-in. Account actions apply at once; the idle-lock minutes follow Save."""

from PySide6.QtWidgets import QAbstractItemView, QLabel, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem

from core import audit, datakey, db, passwords, session
from ui.settings_base import Page, compact_row, spin
from ui.setupdlg import RecoveryDialog, _CardDialog
from ui.signinwindow import MISMATCH, error_label, field, primary, say

OWN_ACCOUNT = "You can't remove the account you're signed in with."
NEW_KEY_ASK = "The old recovery key will stop working. Make a new one?"


class AccountDialog(_CardDialog):
    """Add an account, or (with `name`) set a new password for that one. Accepting does it."""

    def __init__(self, name=None, parent=None):
        super().__init__("Reset password" if name else "Add account", "", parent)
        self.fixed = name
        self.name = field(self.lay, "Username")
        self.pw = field(self.lay, "Password", secret=True)
        self.confirm = field(self.lay, "Confirm password", secret=True)
        self.error = error_label()
        self.ok = primary("Reset password" if name else "Add account")
        self.lay.addWidget(self.error)
        self.lay.addSpacing(10)
        self.lay.addWidget(self.ok)
        self.ok.clicked.connect(self.accept)
        self.name.returnPressed.connect(self.pw.setFocus)
        self.pw.returnPressed.connect(self.confirm.setFocus)
        self.confirm.returnPressed.connect(self.accept)
        if name:
            self.name.setText(name)
            self.name.setReadOnly(True)
            self.pw.setFocus()
        else:
            self.name.setFocus()

    def accept(self):
        name, pw = self.name.text().strip(), self.pw.text()
        why = ("Enter a username." if not name else passwords.problem(pw, name)) or (MISMATCH if pw != self.confirm.text() else None)
        if not why:
            try:
                (datakey.set_password if self.fixed else datakey.add_local)(name, pw)
            except ValueError as e:                      # NameTaken and the rules, in datakey's words
                why = str(e)
        if why:
            say(self.error, why)
            return
        super().accept()


class AccountsPage(Page):
    title = "Accounts and sign-in"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Username", "Type", "Created"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(120)
        self.table.setAccessibleName("Accounts")
        self.add, self.reset, self.remove, self.recovery = (QPushButton(t) for t in
            ("Add account...", "Reset password...", "Remove", "Make a new recovery key..."))
        self.add.clicked.connect(self._add)
        self.reset.clicked.connect(self._reset)
        self.remove.clicked.connect(self._remove)
        self.recovery.clicked.connect(self._recovery)
        self.idle = spin(1, 240, " minutes without use")
        self.form.addRow("Lock after", self.idle)
        self.lay.insertWidget(0, QLabel("<b>Accounts</b>  (these actions take effect immediately)"))
        self.lay.insertWidget(1, self.table)
        self.lay.insertWidget(2, compact_row(self.add, self.reset, self.remove))
        self.lay.insertWidget(3, compact_row(self.recovery))

    def load(self):
        self.idle.setValue(int(db.get_setting("signin_idle_minutes") or 15))
        self.refresh()

    def save(self):
        db.set_setting("signin_idle_minutes", self.idle.value())

    def refresh(self):
        self.table.setRowCount(0)
        for a in (datakey.accounts() if datakey.exists() else []):      # (no keys file: sign-in is not set up yet)
            self.table.insertRow(self.table.rowCount())
            for j, v in enumerate((a["name"], a["kind"], str(a["created"]))):
                self.table.setItem(self.table.rowCount() - 1, j, QTableWidgetItem(v))

    def _selected(self):
        r = self.table.currentRow()
        return self.table.item(r, 0).text() if r >= 0 and self.table.selectedIndexes() else None

    def _add(self):
        dlg = AccountDialog(parent=self)
        if dlg.exec():
            audit.log("account added", dlg.name.text().strip())
            self.refresh()

    def _reset(self):
        name = self._selected()
        if name and (dlg := AccountDialog(name, self)).exec():
            audit.log("password reset", name)

    def _remove(self):
        name = self._selected()
        if not name:
            return
        me = session.user()
        if me and name.casefold() == me.casefold():
            QMessageBox.warning(self, self.title, OWN_ACCOUNT)
            return
        try:
            datakey.remove(name)
        except datakey.LastAccount as e:
            QMessageBox.warning(self, self.title, str(e))
            return
        audit.log("account removed", name)
        self.refresh()

    def _recovery(self):
        if QMessageBox.question(self, self.title, NEW_KEY_ASK) != QMessageBox.StandardButton.Yes:
            return
        key = datakey.new_recovery()
        audit.log("recovery key replaced")
        RecoveryDialog(key, self).exec()
