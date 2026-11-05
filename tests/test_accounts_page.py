# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Accounts and sign-in: add, reset and remove local accounts, a new recovery key, the idle-lock minutes, the audit rows.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\accts%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, datakey, db, lockdown, session
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

shown = {}
def fill(name, pw, confirm=None):
    def run(self):
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
page.table.selectRow(1)
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

# idle minutes: the normal Settings save
check("idle default loads 15", (page.load(), page.idle.value())[1] == 15)
page.idle.setValue(30); page.save()
check("idle saves", db.get_setting("signin_idle_minutes") == 30)
check("idle range 1-240", (page.idle.minimum(), page.idle.maximum()) == (1, 240))

from ui import settings
check("page is listed", "Accounts and sign-in" in dict(settings.GROUPS)["Security and data"] and "Accounts and sign-in" in settings.GLOBAL_PAGES)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
