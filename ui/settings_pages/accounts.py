"""Settings page: Accounts. Account actions apply at once; the idle-lock minutes and the session length follow Save."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QLabel, QMenu, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem)

from core import audit, datakey, db, osstore, passvault, passwords, perms, quiet, roles, session
from ui.directorydlg import service_key
from ui.identitywizard import IdentityWizard
from ui.settings_base import Page, compact_row, note, spin
from ui.setupdlg import RecoveryDialog, _CardDialog
from ui.signinwindow import MISMATCH, error_label, field, primary, say
from ui.testlogindlg import TestLoginDialog
from ui.twofadlg import TwoFactorDialog

OWN_ACCOUNT = "You can't remove the account you're signed in with."
ROLES_NOTE = "Admins can do everything. Tick what Engineers and Techs can do."
TAMPERED = ("The roles were changed outside Toner, so everyone has a Tech's permissions for now. "
            "Sign in with the recovery key, then save the roles to put them right.")
NEW_KEY_ASK = "The old recovery key will stop working. Make a new one?"
REMOVE_DIRECTORY = "Removing this directory signs out its accounts on this copy. Remove {name}?"
KIND_NAMES = {"ad": "Active Directory", "ldap": "LDAP", "oidc": "SSO"}
UNLOCKS = {"chip": "PIN (security chip)", "store": "PIN (protected store)", "pin": "PIN"}


def type_of(a):
    """The Type column: a local account's kind as Part 2 showed it, a directory account's directory."""
    if a["kind"] != "directory":
        return a["kind"]
    return KIND_NAMES.get(a.get("directory_kind"), "")


def unlocks_with(a):
    return UNLOCKS.get(a.get("slot_kind"), "") if a["kind"] == "directory" else "Password"


def ran(dlg):
    """exec(), then delete the dialog, so nothing typed in it outlives it."""
    result = dlg.exec()
    dlg.deleteLater()
    return result


def confirm(parent, title, text):
    box = QMessageBox(QMessageBox.Icon.Question, title, text, parent=parent)
    go = box.addButton("Remove", QMessageBox.ButtonRole.AcceptRole)
    box.setDefaultButton(box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole))
    box.exec()
    return box.clickedButton() is go


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

    def done(self, r):
        for box in (self.pw, self.confirm):            # setText, not clear: no password left in a box's undo history
            box.setText("")
        super().done(r)


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
    title = "Accounts"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Username", "Type", "Created", "Role", "Unlocks with"])
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
        self.table.itemSelectionChanged.connect(self._selection)
        self._directory_rows = set()
        self.idents = QTableWidget(0, 3)
        self.idents.setHorizontalHeaderLabels(["Name", "Type", "2FA"])
        self.idents.horizontalHeader().setStretchLastSection(True)
        self.idents.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.idents.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.idents.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.idents.setMaximumHeight(130)
        self.idents.setAccessibleName("External Identities")
        self.idents.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.idents.customContextMenuRequested.connect(lambda pos: self._ident_menu(pos).exec(self.idents.viewport().mapToGlobal(pos)))
        self._dirs = None                               # the verified list; None: rules that don't check out, so no changes
        self.add_ident, self.edit_ident, self.remove_ident = (QPushButton(t) for t in ("Add", "Edit...", "Remove"))
        self.add_ident.clicked.connect(self._add_ident)
        self.edit_ident.clicked.connect(self._edit_ident)
        self.remove_ident.clicked.connect(self._remove_ident)
        self.idents.itemSelectionChanged.connect(self._ident_buttons)
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
        self.session = spin(1, 72, "")
        self.form.addRow("Session length (hours)", self.session)
        for i, w in enumerate((self.banner, QLabel("<b>Accounts</b>"), note("Changes to accounts take effect right away."), self.table,
                               compact_row(self.add, self.change, self.reset, self.remove), compact_row(self.recovery),
                               QLabel("<b>External Identities</b>"), self.idents, compact_row(self.add_ident, self.edit_ident, self.remove_ident),
                               QLabel("<b>Roles</b>"), note(ROLES_NOTE), self.perm_table, compact_row(self.save_roles))):
            self.lay.insertWidget(i, w)

    def load(self):
        self.idle.setValue(int(db.get_setting("signin_idle_minutes") or 15))
        self.session.setValue(int(db.get_setting("signin_session_hours") or 12))
        self.refresh()

    def save(self):
        if not perms.is_admin():                        # tampered rules show this page to everyone; only an Admin changes these
            self.load()                                 # ...and the boxes show what is stored, not what was typed
            return
        db.set_setting("signin_session_hours", self.session.value())
        db.set_setting("signin_idle_minutes", self.idle.value())

    def refresh(self):
        self.table.setRowCount(0)
        self._directory_rows = set()
        for a in (datakey.accounts() if datakey.exists() else []):      # (no keys file: sign-in is not set up yet)
            self.table.insertRow(self.table.rowCount())
            for j, v in enumerate((a["name"], type_of(a), str(a["created"]), a["role"], unlocks_with(a))):
                self.table.setItem(self.table.rowCount() - 1, j, QTableWidgetItem(v))
            if a["kind"] == "directory":
                self._directory_rows.add(a["name"])
        self._selection()
        doc = roles.verified()                          # only a list whose signature checked out is shown or changed here
        self._dirs = list(doc.get("directories") or []) if doc is not None else None
        self.idents.setRowCount(0)
        for d in self._dirs or []:
            self.idents.insertRow(self.idents.rowCount())
            kind = KIND_NAMES.get(d.get("kind"), "")
            twofa = "N/A" if d.get("kind") == "oidc" else "On" if (d.get("duo") or {}).get("on") else "Off"
            for j, v in enumerate((d.get("name", ""), kind, twofa)):
                self.idents.setItem(self.idents.rowCount() - 1, j, QTableWidgetItem(v))
        self.add_ident.setEnabled(self._dirs is not None)
        self._ident_buttons()
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

    def _selection(self):
        """A directory account's role comes from its groups and its password from its directory."""
        local = self._selected() not in self._directory_rows
        self.change.setEnabled(local)
        self.reset.setEnabled(local)

    def _add(self):
        dlg = AccountDialog(parent=self)
        if ran(dlg):
            audit.log("account added", dlg.name.text().strip())
            self.refresh()

    def _change(self):
        name = self._selected()
        if not name or name in self._directory_rows:
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
        if name and name not in self._directory_rows and ran(AccountDialog(name, self)):
            audit.log("password reset", name)

    def _remove(self):
        name = self._selected()
        if not name:
            return
        me = session.user()
        if me and name.casefold() == me.casefold():
            QMessageBox.warning(self, self.title, OWN_ACCOUNT)
            return
        if not confirm(self, self.title, f"Remove {name}? They won't be able to sign in to this copy of Toner."):
            return
        try:
            datakey.remove(name)                        # a directory account's PIN slot on this computer goes with it
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

    # ---------------------------------------------------------------- directories
    def _dir(self):
        r = self.idents.currentRow()
        return self._dirs[r] if self._dirs and 0 <= r < len(self._dirs) and self.idents.selectedIndexes() else None

    def _ident_buttons(self):
        on = self._dir() is not None
        self.edit_ident.setEnabled(on)
        self.remove_ident.setEnabled(on)

    def _ident_menu(self, pos):
        """The right-click menu, not shown."""
        row = self.idents.rowAt(pos.y()) if pos is not None else -1
        if row >= 0:
            self.idents.selectRow(row)
        elif pos is not None:                           # empty space: the items act on nothing
            self.idents.clearSelection()
        m = QMenu(self.idents)
        self.test_login, self.set_up_2fa = (m.addAction(t) for t in ("Test login...", "Set up 2FA..."))
        self.test_login.setEnabled(self._dir() is not None)
        self.test_login.triggered.connect(self._test_login)
        self.set_up_2fa.setEnabled(self._dir() is not None)
        self.set_up_2fa.setVisible((self._dir() or {}).get("kind") != "oidc")      # the provider does its own 2FA
        self.set_up_2fa.triggered.connect(self._set_up_2fa)
        m.addAction("Edit...", self._edit_ident).setEnabled(self.edit_ident.isEnabled())
        m.addAction("Remove", self._remove_ident).setEnabled(self.remove_ident.isEnabled())
        return m

    def _add_ident(self):
        if self._dirs is not None and ran(IdentityWizard(self._dirs, None, self)):
            self.refresh()

    def _edit_ident(self):
        d = self._dir()
        if d is not None and ran(IdentityWizard(self._dirs, d, self)):
            self.refresh()

    def _test_login(self):
        d = self._dir()
        if d is not None:
            ran(TestLoginDialog(d, self))

    def _set_up_2fa(self):
        d = self._dir()
        if d is not None and ran(TwoFactorDialog(self._dirs, d, self)):
            self.refresh()

    def _remove_ident(self):
        d = self._dir()
        if d is None or not confirm(self, self.title, REMOVE_DIRECTORY.format(name=d.get("name", ""))):
            return
        try:
            roles.set_directories([x for x in self._dirs if x is not d])     # (none re-hashed) its accounts and PIN slots go too
        except (ValueError, datakey.Locked, perms.Denied) as e:            # "Toner needs at least one Admin.", "Sign in first."
            QMessageBox.warning(self, self.title, str(e))
            self.refresh()
            return
        for forget in (lambda: passvault.remove(service_key(d["id"])), lambda: osstore.delete("duo:" + d["id"]),
                       lambda: osstore.delete("oidc:" + d["id"])):
            try:
                forget()
            except Exception:                           # a locked vault or no protected store: nothing of it can be used now
                quiet.ignored()
        self.refresh()
