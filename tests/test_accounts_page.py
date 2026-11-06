# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Accounts: add, reset and remove local accounts, a new recovery key, the idle-lock minutes, the audit rows.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\accts%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, datakey, db, lockdown, perms, roles, session
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL", name, extra)

from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
from ui import setupdlg
from ui.settings_pages import accounts as A

PW, PW2, PW3 = "violet staple orbit 42", "amber kettle meadow 77", "copper willow harbor 58"
old_key = datakey.create("Admin", PW)
lockdown.run()
datakey.close()
session.sign_in("Admin", PW)

page = A.AccountsPage()
page.load()
names = lambda: [a["name"] for a in datakey.accounts()]
rows = lambda: [page.table.item(i, 0).text() for i in range(page.table.rowCount())]
acts = lambda: [r["action"] for r in audit.recent()]
check("lists the account", rows() == ["Admin"], rows())
check("columns: Unlocks with is last; a local account unlocks with its Password",
      [page.table.horizontalHeaderItem(j).text() for j in range(page.table.columnCount())] == ["Username", "Type", "Created", "Role", "Unlocks with"]
      and page.table.item(0, 1).text() == "local" and page.table.item(0, 4).text() == "Password")
check("the External Identities section (tests/test_identitywizard.py covers it): empty, Add on", page.idents.rowCount() == 0 and page.add_ident.isEnabled()
      and not page.edit_ident.isEnabled() and not page.remove_ident.isEnabled())

shown = {}
def fill(name, pw, confirm=None, role=None):
    def run(self):
        if role and self.role:
            self.role.setCurrentText(role)
        self.name.setText(name); self.pw.setText(pw); self.confirm.setText(pw if confirm is None else confirm)
        self.accept()
        shown["error"] = self.error.text()
        shown["result"] = self.result()
        return self.result()
    return run

A.AccountDialog.exec = fill("Bea", "short")
page.add.click()
check("bad password: nothing added", names() == ["Admin"] and "account added" not in acts())
check("bad password: the rule is said", shown["error"] != "" and shown["result"] == 0, shown)
A.AccountDialog.exec = fill("Bea", PW2, "different")
page.add.click()
check("mismatch: nothing added", names() == ["Admin"] and shown["error"] == "The two passwords don't match.", shown)
A.AccountDialog.exec = fill("admin", PW2)
page.add.click()
check("taken name said", names() == ["Admin"] and shown["error"] == "That username is already taken.", shown)
A.AccountDialog.exec = fill("Bea", PW2)
page.add.click()
check("good password adds a row", names() == ["Admin", "Bea"] and rows() == ["Admin", "Bea"], (names(), rows()))
check("account added is audited, without the password", "account added" in acts() and
      all(PW2 not in str(r) for r in audit.recent()))

page.table.selectRow(1)
A.AccountDialog.exec = fill("Bea", PW3)
page.reset.click()
check("reset sets the new password", datakey.check_password("Bea", PW3) and not datakey.check_password("Bea", PW2))
check("password reset is audited", "password reset" in acts() and all(PW3 not in str(r) for r in audit.recent()))

msgs = []
QMessageBox.warning = staticmethod(lambda *a, **k: msgs.append(a[2]) or QMessageBox.StandardButton.Ok)
page.table.selectRow(0)
page.remove.click()
check("own account refused", names() == ["Admin", "Bea"] and msgs == ["You can't remove the account you're signed in with."], msgs)
def answer(text):
    def run(self):
        asked_remove.append(self.text())
        [b for b in self.buttons() if b.text() == text][0].click()
    return run
asked_remove = []
page.table.selectRow(1)
QMessageBox.exec = answer("Cancel")
page.remove.click()
check("Cancel removes nothing, no audit row", names() == ["Admin", "Bea"] and "account removed" not in acts() and
      asked_remove == ["Remove Bea? They won't be able to sign in to this copy of Toner."], asked_remove)
QMessageBox.exec = answer("Remove")
page.remove.click()
check("other account removed", names() == ["Admin"] and rows() == ["Admin"] and "account removed" in acts())

# recovery session: nobody signed in, so the last account is protected by datakey itself
session.sign_out()
datakey.open_with_recovery(old_key)
check("recovery session has no user", session.user() is None)
page.refresh()
page.table.selectRow(0)
msgs.clear()
page.remove.click()
check("last account: said, kept", names() == ["Admin"] and msgs == ["Toner needs at least one account."], msgs)
datakey.close()
session.sign_in("Admin", PW)

# new recovery key
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.No)
shownkey = []
setupdlg.RecoveryDialog.exec = lambda self: shownkey.append(self.key.text()) or 1
page.recovery.click()
check("asks first; no changes nothing", asked == ["The old recovery key will stop working. Make a new one?"] and not shownkey and
      "recovery key replaced" not in acts())
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
page.recovery.click()
check("yes shows the new key", len(shownkey) == 1 and shownkey[0] != old_key and "recovery key replaced" in acts())
check("recovery key replaced is audited without the key", all(shownkey[0] not in str(r) and old_key not in str(r) for r in audit.recent()))
datakey.close()
try:
    datakey.open_with_recovery(old_key); old_works = True
except Exception:
    old_works = False
check("old key stops working", not old_works)
datakey.close()
datakey.open_with_recovery(shownkey[0]); datakey.close()
session.sign_out(); session.sign_in("Admin", PW)

# a closed key: nothing escapes, "Sign in first." is said
A.AccountDialog.exec = fill("Cy", PW2)
datakey.close()
page.add.click()
check("closed key: add says Sign in first.", shown["error"] == "Sign in first." and shown["result"] == 0, shown)
page.table.selectRow(0)
A.AccountDialog.exec = fill("Admin", PW3)
page.reset.click()
check("closed key: reset says Sign in first.", shown["error"] == "Sign in first.", shown)
msgs.clear(); QMessageBox.exec = answer("Remove")
page.table.selectRow(0); session_user = session.user
session.user = lambda: None
page.remove.click(); session.user = session_user
check("closed key: remove says Sign in first.", msgs == ["Sign in first."], msgs)
msgs.clear(); QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
page.recovery.click()
check("closed key: new recovery key says Sign in first.", msgs == ["Sign in first."], msgs)
session.sign_out(); session.sign_in("Admin", PW)

# ---------------------------------------------------------------- roles
import json
from ui.settings_pages.accounts import AccountDialog, RoleDialog
check("Role column", page.table.horizontalHeaderItem(3).text() == "Role" and page.table.item(0, 3).text() == "Admin")
check("buttons", page.change.text() == "Change role..." and page.save_roles.text() == "Save roles")
check("add dialog: Role drop-down Admin, Engineer, Tech, starts at Tech", (lambda d: [d.role.itemText(i) for i in range(d.role.count())] == ["Admin", "Engineer", "Tech"]
      and d.role.currentText() == "Tech")(AccountDialog()))
roles_of = lambda: {a["name"]: a["role"] for a in datakey.accounts()}
A.AccountDialog.exec = fill("Tia", PW2)
page.add.click()
tia_row = rows().index("Tia")
check("added as the default Tech: the column says Tech", roles_of()["Tia"] == "Tech" and page.table.item(tia_row, 3).text() == "Tech")
A.AccountDialog.exec = fill("Enid", PW3, role="Engineer")
page.add.click()
check("added as an Engineer", roles_of()["Enid"] == "Engineer")

def pick(role):
    def run(self):
        self.role.setCurrentText(role)
        self.accept()
        return 1
    return run
A.RoleDialog.exec = pick("Engineer")
n = acts().count("role changed")
page.table.selectRow(rows().index("Tia"))
page.change.click()
check("Change role: Engineer", roles_of()["Tia"] == "Engineer" and page.table.item(rows().index("Tia"), 3).text() == "Engineer")
check("...one audit row", acts().count("role changed") == n + 1, acts())
msgs.clear()
A.RoleDialog.exec = pick("Tech")
page.table.selectRow(rows().index("Admin"))
page.change.click()
check("demoting the only Admin: said, nothing changed", msgs == ["Toner needs at least one Admin."] and roles_of()["Admin"] == "Admin"
      and page.table.item(rows().index("Admin"), 3).text() == "Admin", msgs)

PUSH = [i for i, (k, _) in enumerate(perms.PERMISSIONS) if k == "push"][0]
check("Roles table: PERMISSIONS order, labels, Engineer and Tech columns only",
      [page.perm_table.verticalHeaderItem(i).text() for i in range(page.perm_table.rowCount())] == [l for _, l in perms.PERMISSIONS]
      and [page.perm_table.horizontalHeaderItem(j).text() for j in range(page.perm_table.columnCount())] == ["Engineer", "Tech"]
      and page.perm_table.verticalHeaderItem(PUSH).text() == "Push changes to devices")
from PySide6.QtCore import Qt
check("Roles table shows the defaults", page.perm_table.item(PUSH, 0).checkState() == Qt.CheckState.Checked
      and page.perm_table.item(PUSH, 1).checkState() == Qt.CheckState.Unchecked)
check("no tamper banner", page.banner.isHidden())
n = acts().count("role permissions changed")
page.perm_table.item(PUSH, 0).setCheckState(Qt.CheckState.Unchecked)
page.save_roles.click()
check("Save roles: stored", roles.permissions("Engineer")["push"] is False and roles.permissions("Tech") == perms.DEFAULTS["Tech"])
check("...one audit row", acts().count("role permissions changed") == n + 1, acts())
check("...the table keeps it", page.perm_table.item(PUSH, 0).checkState() == Qt.CheckState.Unchecked)
session.sign_out(); session.sign_in("Enid", PW3)
check("an Engineer signing in afterwards can't push", perms.allowed("push") is False)
from types import SimpleNamespace
from ui.settings import SettingsTab as Settings
check("Accounts is hidden from an Engineer", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is True)
session.sign_out(); session.sign_in("Admin", PW)
check("...and shown to an Admin", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is False)
session.sign_out(); session.sign_in("Enid", PW3)
session.sign_out(); session.sign_in("Admin", PW)

# a refused write is said in roles' or perms' words
session.sign_out(); session.sign_in("Tia", PW2)
page.refresh()
msgs.clear()
page.perm_table.item(PUSH, 1).setCheckState(Qt.CheckState.Checked)
page.save_roles.click()
page.table.selectRow(rows().index("Enid")); A.RoleDialog.exec = pick("Tech"); page.change.click()
A.AccountDialog.exec = fill("Zed", PW3); page.add.click()
check("a Tech (page hidden anyway): Save roles and Change role say why, nothing leaks", msgs == ["Sign in first."] * 2 and "Zed" not in names(), msgs)
check("Denied: Add account shows the reason", shown["error"] == perms.REASON, shown)
session.sign_out(); session.sign_in("Admin", PW)
page.refresh()

# tamper: the banner, the stored (not fallback) ticks, and a recovery sign-in's save repairs it
d = json.loads(datakey.path().read_text(encoding="utf-8"))
d["accounts"]["Enid"]["role"] = "Admin"
datakey.path().write_text(json.dumps(d), encoding="utf-8")
datakey.close(); session.sign_out(); session.sign_in("Admin", PW)
page.refresh()
check("tampered: banner shown, with the approved words", not page.banner.isHidden() and page.banner.text() ==
      "The roles were changed outside Toner, so everyone has a Tech's permissions for now. Sign in with the recovery key, then save the roles to put them right.")
check("tampered: the table shows what is stored", page.perm_table.item(PUSH, 0).checkState() == Qt.CheckState.Unchecked
      and page.perm_table.item(PUSH, 1).checkState() == Qt.CheckState.Unchecked and page.table.item(rows().index("Enid"), 3).text() == "Admin")
msgs.clear()
page.save_roles.click()
check("tampered: an ordinary sign-in can't save, says why", msgs == [perms.REASON], msgs)
session.sign_out(); session.sign_in_recovery(shownkey[0])
page.refresh()
page.perm_table.item(PUSH, 0).setCheckState(Qt.CheckState.Checked)
page.save_roles.click()
check("recovery sign-in saving roles clears the banner", roles.state() == "ok" and page.banner.isHidden(), roles.state())
check("...and signs what was shown", roles.permissions("Engineer")["push"] is True and roles.role_of("Enid") == "Admin")
datakey.close(); session.sign_out(); session.sign_in("Admin", PW)

# idle minutes: the normal Settings save
check("idle default loads 15", (page.load(), page.idle.value())[1] == 15)
page.idle.setValue(30); page.save()
check("idle saves", db.get_setting("signin_idle_minutes") == 30)
check("idle range 1-240", (page.idle.minimum(), page.idle.maximum()) == (1, 240))

check("session length loads 12", (page.load(), page.session.value())[1] == 12)
page.session.setValue(8); page.save()
check("session length saves", db.get_setting("signin_session_hours") == 8)
check("session range 1-72", (page.session.minimum(), page.session.maximum()) == (1, 72))
check("session label", page.form.labelForField(page.session).text() == "Session length (hours)")

from ui import settings

# External Identities: the table, the 2FA column, the right-click menu
def ident(i, name, kind, duo):
    return {"id": i, "name": name, "kind": kind, "servers": ["dc.acme.test"], "port": 636, "security": "ldaps", "ca_file": "",
            "base_dn": "DC=acme,DC=test", "netbios": name[:4].upper(), "suffixes": [], "service_dn": "CN=svc,DC=acme,DC=test",
            "groups": {}, "duo": {"on": duo, "host": "api-x.duosecurity.com" if duo else "", "ikey": "DIX" if duo else ""}}
check("title is Accounts", page.title == "Accounts")
roles.set_directories([ident("a1", "ACME", "ad", True), ident("l1", "Corp LDAP", "ldap", False)])
page.refresh()
cell = lambda r, c: page.idents.item(r, c).text()
check("External Identities: columns", [page.idents.horizontalHeaderItem(j).text() for j in range(3)] == ["Name", "Type", "2FA"])
check("AD with Duo on", [cell(0, j) for j in range(3)] == ["ACME", "Active Directory", "On"], [cell(0, j) for j in range(3)])
check("LDAP with Duo off", [cell(1, j) for j in range(3)] == ["Corp LDAP", "LDAP", "Off"], [cell(1, j) for j in range(3)])
check("buttons", (page.add_ident.text(), page.edit_ident.text(), page.remove_ident.text()) == ("Add", "Edit...", "Remove"))
check("heading", any(l.text() == "<b>External Identities</b>" for l in page.findChildren(A.QLabel)))
check("no selection: Edit and Remove off", not page.edit_ident.isEnabled() and not page.remove_ident.isEnabled())
page.idents.selectRow(1)
menu = page._ident_menu(None)
check("menu items, in order", [a.text() for a in menu.actions()] == ["Test login...", "Set up 2FA...", "Edit...", "Remove"], [a.text() for a in menu.actions()])
check("Test login and Set up 2FA are on", menu.actions()[0].isEnabled() and menu.actions()[1].isEnabled())
tested = []
A.TestLoginDialog.exec = lambda self: tested.append((self.cfg, self.parent())) or 0
menu.actions()[0].trigger()
check("menu Test login opens on the selected identity, from the verified list",
      tested == [(page._dirs[1], page)] and tested[0][0]["name"] == "Corp LDAP", tested)
check("Edit and Remove are on", menu.actions()[2].isEnabled() and menu.actions()[3].isEnabled())
edited = []
A.IdentityWizard.exec = lambda self: edited.append(self.orig["name"]) or 0
menu.actions()[2].trigger()
check("menu Edit opens the selected identity", edited == ["Corp LDAP"], edited)
asked = []
QMessageBox.exec = lambda self: (asked.append(self.text()), self.setDefaultButton(None))[0]
menu.actions()[3].trigger()
check("menu Remove asks the approved question", asked == ["Removing this directory signs out its accounts on this copy. Remove Corp LDAP?"], asked)
check("...and Cancel kept it", len(roles.verified()["directories"]) == 2)
real_verified = roles.verified
roles.verified = lambda: None
page.refresh()
check("rules that don't check out: no rows, Add off", page.idents.rowCount() == 0 and not page.add_ident.isEnabled())
page.idents.clearSelection()
check("no row: Test login off", not page._ident_menu(None).actions()[0].isEnabled())
roles.verified = real_verified
roles.set_directories([]); page.refresh()
check("page is listed", "Accounts" in dict(settings.GROUPS)["Security and data"] and "Accounts" in settings.GLOBAL_PAGES)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
