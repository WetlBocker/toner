# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The final review's sign-in fixes: an upgrade with "Remember on this computer" asks nothing, the old-vault dialog's rare errors,
# encrypted data with netcheck.keys missing is refused (never a new key), and failed sign-ins and recovery resets are audited.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
from pathlib import Path
SP = os.environ["SP"]; os.environ["APPDATA"] = SP
STAMP = int(time.time())
def use(name):                                       # a separate install: its own database, keys file and vault
    os.environ["NETCHECK_DB"] = os.path.join(SP, f"fix{name}{STAMP}.db")
use("remembered")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, datakey, db, passvault, session, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

NATIVE = {}
class _NativeKeyring:                                  # Linux and macOS keep the remembered key in the system keyring: a stand-in
    def set_password(self, s, u, p): NATIVE[(s, u)] = p
    def get_password(self, s, u): return NATIVE.get((s, u))
    def delete_password(self, s, u): NATIVE.pop((s, u), None)
if sys.platform != "win32":
    passvault._native_keyring = lambda: _NativeKeyring()

PW = "violet staple orbit 42"
MISSING = ("Toner's data is encrypted, but netcheck.keys is missing from its data folder. Put netcheck.keys back next to netcheck.db, "
           "then start Toner again.")
DAMAGED = "This file is damaged or was changed outside Toner."
CHANGED = "The vault changed after it was opened. Open it again, then try again."

from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.plain_look(app)
from ui import setupdlg
from ui.signinwindow import SignInWindow

def fill_account(self):
    self.name.setText("Admin"); self.pw.setText(PW); self.confirm.setText(PW); self.ok.click()
    return self.result()
setupdlg.AccountDialog.exec = fill_account
setupdlg.RecoveryDialog.exec = lambda self: 1
asked = []
setupdlg.OldVaultDialog.exec = lambda self: asked.append("old vault") or 0

print("== an upgrade with Remember on this computer: no master password asked")
db.init(); db.release()
passvault.create("old master password!", remember=True, carry={"r": "1"}); passvault.lock()
check("the old vault is remembered", passvault.remembered() and passvault.uses_master())
check("run_first_start finishes", setupdlg.run_first_start() is True)
check("...without the master-password dialog", asked == [], asked)
check("the saved password moved over, onto the data key", passvault.get("r") == "1" and not passvault.uses_master())
check("the remembered -key file is gone", not passvault.key_path().exists())
session.sign_out()

print("== a first start that stopped before the remembered vault moved over: the sign-in window adopts it too")
use("remembered2")
db.init(); db.release()
passvault.create("old master password!", remember=True, carry={"s": "2"}); passvault.lock()
datakey.create("Admin", PW); datakey.close()
w = SignInWindow(); w.show()
w.name.setText("Admin"); w.next.click(); w.pw.setText(PW); w.sign_in.click()
check("signs in with no dialog", w.result() == SignInWindow.DialogCode.Accepted and asked == [], (w.error.text(), asked))
check("...and the password moved over", passvault.get("s") == "2" and not passvault.uses_master() and not passvault.key_path().exists())
session.sign_out()

print("== the old-vault dialog's rare errors")
use("rare")
db.init(); db.release()
passvault.create("old master password!", remember=False, carry={"t": "3"}); passvault.lock()
datakey.create("Admin", PW)
dlg = setupdlg.OldVaultDialog()
real_adopt, real_unlock = passvault.adopt, passvault.unlock
def changed(_k): raise passvault.Locked(CHANGED)
passvault.adopt = changed
dlg.pw.setText("old master password!"); dlg.ok.click()
check("the vault changed meanwhile: says so and stays", dlg.error.text() == CHANGED and dlg.result() == 0, dlg.error.text())
passvault.adopt = real_adopt
def unreadable(_m): raise PermissionError("in use")
passvault.unlock = unreadable
dlg.pw.setText("old master password!"); dlg.ok.click()
check("the vault can't be read: one clear sentence and stays", dlg.error.text() == DAMAGED and dlg.result() == 0, dlg.error.text())
passvault.unlock = real_unlock
real_path = passvault.path
passvault.path = lambda: Path(SP) / "no-such-folder" / "netcheck.vault"
QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok)
dlg.dont_know.click()
check("I don't know it, when the vault can't be put aside: says so and stays", dlg.error.text() == DAMAGED and dlg.result() == 0, dlg.error.text())
passvault.path = real_path
datakey.close()
w = SignInWindow(); w.show()
setupdlg.OldVaultDialog.exec = lambda self: 1          # (accepted, but the vault still isn't adopted: replaced meanwhile)
w.name.setText("Admin"); w.next.click(); w.pw.setText(PW)
try:
    w.sign_in.click(); raised = None
except Exception as e:
    raised = e
check("the sign-in window says so instead of crashing", raised is None and w.error.text() == CHANGED
      and session.state() == "signed_out" and not datakey.is_open(), (raised, w.error.text()))
setupdlg.OldVaultDialog.exec = lambda self: asked.append("old vault") or 0

print("== encrypted data with netcheck.keys missing")
use("nokeys")
datakey.create("Admin", PW); db.init(); db.release(); datakey.close()
datakey.path().unlink()
check("the database is encrypted and the keys file is gone", sqldb.is_encrypted(db.base_path()) and not datakey.exists())
shown = []
QMessageBox.critical = staticmethod(lambda parent, title, text, *a, **k: shown.append(text) or QMessageBox.StandardButton.Ok)
made = []
setupdlg.AccountDialog.exec = lambda self: made.append(1) or 0
check("the first start refuses", setupdlg.run_first_start() is False)
check("...saying so, before any account is asked for", shown == [MISSING] and made == [], (shown, made))
check("...and no key is made", not datakey.exists())
shown.clear()
check("so Toner's start quits", A.sign_in_at_start() is False and shown == [MISSING] and not datakey.exists(), shown)
try:
    datakey.create("Admin", PW); refused = False
except FileExistsError:
    refused = True
check("datakey.create refuses too", refused and not datakey.exists())
use("nokeys2")
datakey.create("Admin", PW); passvault.open_with(sqldb.current_key()); passvault.lock(); datakey.close()
datakey.path().unlink()
shown.clear()
check("the vault already on the data key (no database yet) is refused the same way",
      not db.base_path().exists() and setupdlg.run_first_start() is False and shown == [MISSING] and not datakey.exists(), shown)
setupdlg.AccountDialog.exec = fill_account

print("== failed sign-ins are audited")
use("audit")
datakey.create("Admin", PW); db.init(); session.sign_out()
for _ in range(2):
    try:
        session.sign_in("admin", "wrong password 1234")
    except datakey.WrongPassword:
        pass
try:
    session.sign_in("nobody", "wrong password 1234")
except datakey.WrongPassword:
    pass
session.sign_in("Admin", PW)
acts = lambda: [r["action"] for r in audit.recent()]
check("the next sign-in records how many failed", "3 failed sign-in attempts since the last sign-in" in acts(), acts())
session.sign_out(); session.sign_in("Admin", PW)
check("...once (a clean sign-in records none)", sum("failed sign-in attempts" in a for a in acts()) == 1, acts())
session.sign_out()

print("== a reset with the recovery key is audited")
use("recovery")
recovery = datakey.create("Admin", PW); db.init(); session.sign_out()
w = SignInWindow(); w.show()
w.name.setText("Admin"); w.next.click(); w.use_recovery.click(); w.recovery.setText(recovery); w.recovery_sign_in.click()
PW2 = "amber kettle meadow 77"
w.new_pw.setText(PW2); w.confirm.setText(PW2); w.reset_ok.click()
check("signed in with the new password", w.result() == SignInWindow.DialogCode.Accepted and session.user() == "Admin")
check("the reset is in the audit log", "password reset with the recovery key" in acts(), acts())
session.sign_out()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
