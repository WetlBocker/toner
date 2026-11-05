"""Settings page: Accounts and sign-in. Account actions apply at once; the idle-lock minutes follow Save."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem

from core import audit, datakey, db, passwords, perms, roles, session
from ui.settings_base import Page, compact_row, note, spin
from ui.setupdlg import RecoveryDialog, _CardDialog
from ui.signinwindow import MISMATCH, error_label, field, primary, say

OWN_ACCOUNT = "You can't remove the account you're signed in with."
ROLES_NOTE = "Admins can do everything. Tick what Engineers and Techs can do."
TAMPERED = ("The roles were changed outside Toner, so everyone has a Tech's permissions for now. "
            "Sign in with the recovery key, then save the roles to put them right.")
NEW_KEY_ASK = "The old recovery key will stop working. Make a new one?"


class AccountDialog(_CardDialog):
    """Add an account, or (with `name`) set a new password for that one. Accepting does it."""

    def __init__(self, name=None, parent=None):
        super().__init__("Reset password" if name else "Add account", "", parent)
        self.fixed = name
        self.name = field(self.lay, "Username")
        self.pw = field(self.lay, "Password", secret=True)
        self.confirm = field(self.lay, "Confirm password", secret=True)
        self.role = None
        if not name:
            self.role = QComboBox()
            self.role.addItems(roles.ROLES)
            self.role.setCurrentText("Tech")
            self.role.setAccessibleName("Role")
            self.lay.addWidget(QLabel("Role"))
            self.lay.addWidget(self.role)
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
                if self.fixed:
                    datakey.set_password(name, pw)
                else:
                    datakey.add_local(name, pw, self.role.currentText())
            except (ValueError, datakey.Locked, perms.Denied) as e:    # NameTaken, the rules, "Sign in first.", the role: in their own words
                why = str(e)
        if why:
            say(self.error, why)
            return
        super().accept()


class RoleDialog(_CardDialog):
    """Pick a role for one account."""

    def __init__(self, current, parent=None):
        super().__init__("Change role", "", parent)
        self.role = QComboBox()
        self.role.addItems(roles.ROLES)
        self.role.setCurrentText(current)
        self.role.setAccessibleName("Role")
        self.lay.addWidget(QLabel("Role"))
        self.lay.addWidget(self.role)
        self.lay.addSpacing(10)
        ok = primary("Change role")
        ok.clicked.connect(self.accept)
        self.lay.addWidget(ok)


class AccountsPage(Page):
    title = "Accounts and sign-in"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Username", "Type", "Created", "Role"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(120)
        self.table.setAccessibleName("Accounts")
        self.add, self.change, self.reset, self.remove, self.recovery = (QPushButton(t) for t in
            ("Add account...", "Change role...", "Reset password...", "Remove", "Make a new recovery key..."))
        self.add.clicked.connect(self._add)
        self.change.clicked.connect(self._change)
        self.reset.clicked.connect(self._reset)
        self.remove.clicked.connect(self._remove)
        self.recovery.clicked.connect(self._recovery)
        self.banner = note(TAMPERED)
        self.perm_table = QTableWidget(len(perms.PERMISSIONS), 2)
        self.perm_table.setHorizontalHeaderLabels(["Engineer", "Tech"])
        self.perm_table.setVerticalHeaderLabels([label for _, label in perms.PERMISSIONS])
        self.perm_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.perm_table.setMinimumHeight(200)
        self.perm_table.setAccessibleName("Roles")
        self.save_roles = QPushButton("Save roles")
        self.save_roles.clicked.connect(self._save_roles)
        self._shown = {}
        self.idle = spin(1, 240, " minutes without use")
        self.form.addRow("Lock after", self.idle)
        for i, w in enumerate((self.banner, QLabel("<b>Accounts</b>"), note("Changes to accounts take effect right away."), self.table,
                               compact_row(self.add, self.change, self.reset, self.remove), compact_row(self.recovery),
                               QLabel("<b>Roles</b>"), note(ROLES_NOTE), self.perm_table, compact_row(self.save_roles))):
            self.lay.insertWidget(i, w)

    def load(self):
        self.idle.setValue(int(db.get_setting("signin_idle_minutes") or 15))
        self.refresh()

    def save(self):
        db.set_setting("signin_idle_minutes", self.idle.value())

    def refresh(self):
        self.table.setRowCount(0)
        for a in (datakey.accounts() if datakey.exists() else []):      # (no keys file: sign-in is not set up yet)
            self.table.insertRow(self.table.rowCount())
            for j, v in enumerate((a["name"], a["kind"], str(a["created"]), a["role"])):
                self.table.setItem(self.table.rowCount() - 1, j, QTableWidgetItem(v))
        self.banner.setVisible(roles.state() == "tampered")
        self._shown = {r: roles.stored_permissions(r) for r in ("Engineer", "Tech")}     # as stored, not the Tech fallback
        for i, (key, _) in enumerate(perms.PERMISSIONS):
            for j, r in enumerate(("Engineer", "Tech")):
                it = QTableWidgetItem()
                it.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                it.setCheckState(Qt.CheckState.Checked if self._shown[r][key] else Qt.CheckState.Unchecked)
                self.perm_table.setItem(i, j, it)

    def _selected(self):
        r = self.table.currentRow()
        return self.table.item(r, 0).text() if r >= 0 and self.table.selectedIndexes() else None

    def _add(self):
        dlg = AccountDialog(parent=self)
        if dlg.exec():
            audit.log("account added", dlg.name.text().strip())
            self.refresh()

    def _change(self):
        name = self._selected()
        if not name:
            return
        dlg = RoleDialog(self.table.item(self.table.currentRow(), 3).text(), self)
        if not dlg.exec():
            return
        try:
            roles.set_role(name, dlg.role.currentText())     # roles writes the audit row
        except (ValueError, datakey.Locked, perms.Denied) as e:    # "Toner needs at least one Admin.", "Sign in first.", the role
            QMessageBox.warning(self, self.title, str(e))
        self.refresh()

    def _save_roles(self):
        try:
            for j, r in enumerate(("Engineer", "Tech")):
                now = {k: self.perm_table.item(i, j).checkState() == Qt.CheckState.Checked for i, (k, _) in enumerate(perms.PERMISSIONS)}
                roles.set_permissions(r, {k: v for k, v in now.items() if v != self._shown[r][k]})
        except (ValueError, datakey.Locked, perms.Denied) as e:
            QMessageBox.warning(self, self.title, str(e))
        self.refresh()

    def _reset(self):
        name = self._selected()
        if name and AccountDialog(name, self).exec():
            audit.log("password reset", name)

    def _remove(self):
        name = self._selected()
        if not name:
            return
        me = session.user()
        if me and name.casefold() == me.casefold():
            QMessageBox.warning(self, self.title, OWN_ACCOUNT)
            return
        box = QMessageBox(QMessageBox.Icon.Question, self.title, f"Remove {name}? They won't be able to sign in to this copy of Toner.", parent=self)
        go = box.addButton("Remove", QMessageBox.ButtonRole.AcceptRole)
        box.setDefaultButton(box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole))
        box.exec()
        if box.clickedButton() is not go:
            return
        try:
            datakey.remove(name)
        except (ValueError, datakey.Locked, perms.Denied) as e:        # LastAccount, "Sign in first.", an account the file no longer has
            QMessageBox.warning(self, self.title, str(e))
            self.refresh()
            return
        audit.log("account removed", name)
        self.refresh()

    def _recovery(self):
        if QMessageBox.question(self, self.title, NEW_KEY_ASK) != QMessageBox.StandardButton.Yes:
            return
        try:
            key = datakey.new_recovery()
        except (datakey.Locked, perms.Denied) as e:
            QMessageBox.warning(self, self.title, str(e))
            return
        audit.log("recovery key replaced")
        RecoveryDialog(key, self).exec()
