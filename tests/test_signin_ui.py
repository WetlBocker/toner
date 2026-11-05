# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Signing in to Toner: the first start (a new install, and an upgrade with an older master-password vault), the sign-in window
# (password, recovery key, too many tries, a damaged keys file), the lock screen over the window (Ctrl+Shift+L, the idle timer,
# Unlock, Sign in as someone else) and signing out, which starts Toner again.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, re, sys, time
SP = os.environ["SP"]; os.environ["APPDATA"] = SP
STAMP = int(time.time())
def use(name):                                       # a separate install: its own database, keys file and vault
    os.environ["NETCHECK_DB"] = os.path.join(SP, f"{name}{STAMP}.db")
use("upgrade")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, lockdown, passvault, session, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PW, PW2 = "violet staple orbit 42", "amber kettle meadow 77"
KEY_PATTERN = re.compile(r"^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.plain_look(app)                                    # before sign-in: no setting is read (the database is encrypted)
from ui import setupdlg
from ui.signinwindow import SignInWindow

seen = {}
def fill_account(name, pw=PW):
    def run(self):
        self.name.setText("Admin"); self.pw.setText("short"); self.confirm.setText("short"); self.ok.click()
        seen["short"] = self.error.text()
        self.pw.setText(pw); self.confirm.setText(pw + "x"); self.ok.click()
        seen["mismatch"] = (self.error.text(), self.result(), datakey.exists())
        self.name.setText(name); self.pw.setText(pw); self.confirm.setText(pw); self.ok.click()
        return self.result()
    return run
def save_key(self):
    seen["key"] = self.key.text()
    seen["before"] = self.cont.isEnabled()
    self.reject()                                    # Escape: the key is shown only once, so it can't be skipped
    seen["stayed"] = self.result() == 0 and not seen["before"]
    self.saved.setChecked(True)
    seen["after"] = self.cont.isEnabled()
    self.cont.click()
    return self.result()
setupdlg.RecoveryDialog.exec = save_key

print("== the upgrade: an older Toner's plain data and master-password vault")
db.init(); db.set_setting("report_title", "Kept across the upgrade"); db.release()
passvault.create("old master password!", remember=False, carry={"a": "1"}); passvault.lock()
check("before: the database is plain and there is no keys file", not sqldb.is_encrypted(db.base_path()) and not datakey.exists())
setupdlg.AccountDialog.exec = fill_account("Admin")
def old_master(self):
    seen["upgrade_text"] = [l.text() for l in self.findChildren(setupdlg.QLabel)]
    self.pw.setText("not the master password"); self.ok.click()
    seen["wrong_master"] = (self.error.text(), self.result())
    self.pw.setText("old master password!"); self.ok.click()
    return self.result()
setupdlg.OldVaultDialog.exec = old_master
done = setupdlg.run_first_start()
check("run_first_start finishes", done is True)
check("the account exists and is signed in", datakey.exists() and session.state() == "open" and session.user() == "Admin")
check("the upgrade asks for the old master password in the agreed words",
      "Enter the master password you used to unlock Toner's vault. Toner moves your saved passwords into the new account and won't ask for it again."
      in seen["upgrade_text"], seen["upgrade_text"])
check("a wrong master password says so and stays", seen["wrong_master"] == ("That master password isn't right.", 0), seen["wrong_master"])
check("the saved password moved into the new vault", passvault.get("a") == "1")
check("...which opens with the data key now", not passvault.uses_master())
check("everything is encrypted", lockdown.pending() == [] and sqldb.is_encrypted(db.base_path()), lockdown.pending())
db.init()
check("and still readable once signed in", db.get_setting("report_title") == "Kept across the upgrade")
check("a too-short password is refused", seen["short"] == "Use at least 12 characters.", seen["short"])
check("passwords that don't match are refused, and no account is made yet",
      seen["mismatch"][0] == setupdlg.MISMATCH and seen["mismatch"][1] == 0 and not seen["mismatch"][2], seen["mismatch"])
try:
    passvault.create("another master pw!", remember=False); refused = False
except FileExistsError:
    refused = True
check("passvault.create refuses once Toner's accounts exist", refused and passvault.get("a") == "1")
session.sign_out()

print("== the upgrade, when the old master password is forgotten")
use("forgot")
db.init(); db.release()
passvault.create("old master password!", remember=False, carry={"b": "2"}); passvault.lock()
asked = []
def dont_know(self):
    QMessageBox.warning = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Ok)
    self.dont_know.click()
    return self.result()
setupdlg.OldVaultDialog.exec = dont_know
check("finishes", setupdlg.run_first_start() is True)
check("I don't know it warns in the agreed words", asked == ["The saved passwords will be lost. Everything else is kept."], asked)
check("the new vault is empty and opens with the data key", passvault.names() == [] and not passvault.uses_master())
check("the old vault file is kept aside, not deleted", any(p.name.startswith(passvault.path().name + ".old-") for p in passvault.path().parent.iterdir()))
session.sign_out()

print("== a new install")
use("fresh")
setupdlg.AccountDialog.exec = fill_account("  Jordan  ")
check("finishes", setupdlg.run_first_start() is True)
check("the keys file exists, with the account named as typed", datakey.exists() and [a["name"] for a in datakey.accounts()] == ["Jordan"])
check("the recovery key is shown, in its pattern", bool(KEY_PATTERN.match(seen["key"])), seen["key"])
check("Continue is off until the box is ticked, and Escape doesn't skip the key", seen["before"] is False and seen["stayed"] and seen["after"] is True)
check("signed in as that account", session.state() == "open" and session.user() == "Jordan")
recovery = seen["key"]
r = setupdlg.RecoveryDialog("ABCD-EFGH")
labels = [l.text() for l in r.findChildren(setupdlg.QLabel)]
check("the recovery screen's words", "Save your recovery key" in labels and any("Keep netcheck.keys with Toner's data too." in t for t in labels), labels)
QApplication.clipboard().clear(); r.copy.click()
check("Copy puts the key on the clipboard", QApplication.clipboard().text() == "ABCD-EFGH")
QApplication.clipboard().clear()
session.sign_out()
setupdlg.AccountDialog.exec = lambda self: 0
use("cancelled")
check("cancelling the first start makes nothing", setupdlg.run_first_start() is False and not datakey.exists())
use("fresh")

print("== the sign-in window")
w = SignInWindow(); w.show()
check("step 1: Sign in, Username or email, Next", w.pages.currentWidget() is w.name_page and w.next.text() == "Next")
w.next.click()
check("an empty name is refused", w.name_error.text() == "Enter a username." and w.pages.currentWidget() is w.name_page)
w.name.setText("nobody here"); w.next.click()
check("Next with a name that doesn't exist still asks for a password (names aren't revealed)",
      w.pages.currentWidget() is w.password_page and w.who.text() == "nobody here")
w.pw.setText("wrong password 123"); w.sign_in.click()
check("a wrong password shows the agreed message", w.error.text() == datakey.WRONG and session.state() == "signed_out", w.error.text())
check("...and the password box is emptied", w.pw.text() == "")
w.not_you.click()
check("Not you? goes back to the name", w.pages.currentWidget() is w.name_page)
real_sign_in = session.sign_in
def throttled(*_a): raise datakey.Throttled(30)
session.sign_in = throttled
w.name.setText("Jordan"); w.next.click(); w.pw.setText(PW); w.sign_in.click()
check("too many tries: Sign in is off and the countdown shows", not w.sign_in.isEnabled() and w.error.text() == "Too many tries. Wait 30 seconds, then try again.", w.error.text())
w.sign_in_wait.timer.timeout.emit()
check("...counting down", w.error.text() == "Too many tries. Wait 29 seconds, then try again.", w.error.text())
w.sign_in_wait.left = 1; w.sign_in_wait.timer.timeout.emit()
check("...and Sign in comes back when it ends", w.sign_in.isEnabled() and not w.sign_in_wait.timer.isActive())
session.sign_in = real_sign_in
keys = datakey.path().read_bytes()
datakey.path().write_text("{not json", encoding="utf-8")
w.pw.setText(PW); w.sign_in.click()
check("a damaged keys file: one clear sentence, no parser message", w.error.text() == "This file is damaged or was changed outside Toner.", w.error.text())
datakey.path().write_bytes(keys)
w.pw.setText(PW); w.sign_in.click()
check("the right password signs in (any capitals in the name)", w.result() == SignInWindow.DialogCode.Accepted and session.user() == "Jordan")
session.sign_out()

print("== signing in with the recovery key")
w = SignInWindow(); w.show()
w.name.setText("Jordan"); w.next.click(); w.use_recovery.click()
check("Use the recovery key asks for it in the agreed words", w.pages.currentWidget() is w.recovery_page
      and any(l.text() == "Enter the recovery key you saved when Toner was set up." for l in w.recovery_page.findChildren(setupdlg.QLabel)))
w.recovery.setText("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"); w.recovery_sign_in.click()
check("a wrong one says so", w.recovery_error.text() == "That recovery key isn't right." and session.state() == "signed_out", w.recovery_error.text())
w.recovery.setText(recovery.lower()); w.recovery_sign_in.click()
check("the right one goes straight to a new password for an account", w.pages.currentWidget() is w.reset_page and session.state() == "open"
      and [w.account.itemText(i) for i in range(w.account.count())] == ["Jordan"])
w.new_pw.setText("short"); w.confirm.setText("short"); w.reset_ok.click()
check("the password rules apply", w.reset_error.text() == "Use at least 12 characters.")
w.new_pw.setText(PW2); w.confirm.setText(PW2); w.reset_ok.click()
check("then Toner is signed in as that account, with the new password", w.result() == SignInWindow.DialogCode.Accepted
      and session.user() == "Jordan" and datakey.check_password("Jordan", PW2) and not datakey.check_password("Jordan", PW))
session.sign_out()
w = SignInWindow(); w.show()
w.name.setText("Jordan"); w.next.click(); w.use_recovery.click(); w.recovery.setText(recovery); w.recovery_sign_in.click()
w.reject()
check("closing the window during the reset leaves no recovery session open", session.state() == "signed_out")

print("== a first start that stopped before the old vault moved over")
use("halfway")
db.init(); db.release()
passvault.create("old master password!", remember=False, carry={"c": "3"}); passvault.lock()
datakey.create("Admin", PW); datakey.close()
setupdlg.OldVaultDialog.exec = old_master
w = SignInWindow(); w.show()
w.name.setText("Admin"); w.next.click(); w.pw.setText(PW); w.sign_in.click()
check("signing in asks for the master password once, then opens", w.result() == SignInWindow.DialogCode.Accepted and session.user() == "Admin"
      and passvault.get("c") == "3" and not passvault.uses_master())
check("...and the data still to encrypt is left for app.main", lockdown.pending() != [])
session.sign_out()
use("fresh")

print("== the lock screen over Toner's window")
session.sign_in("Jordan", PW2)
db.init()
A.apply_look(app)
win = A.Main(); win.resize(1024, 700); win.show(); app.processEvents()
lock = win.lock_screen
check("open: no lock screen, the idle timer runs", not lock.isVisible() and lock.idle.isActive())
check("the user menu names who is signed in, then Lock and Sign out",
      [a.text() for a in win.user_menu.actions() if not a.isSeparator()] == ["Jordan", "Lock (Ctrl+Shift+L)", "Sign out"])
win.lock_shortcut.activated.emit()
check("Ctrl+Shift+L locks the session and covers the window", session.state() == "locked" and lock.isVisible() and lock.geometry() == win.rect())
check("the lock screen's words", lock.reason.text() == "Locked by Jordan." and lock.who.text() == "Jordan, local account" and lock.unlock.text() == "Unlock")
check("the idle timer stops while locked", not lock.idle.isActive())
check("what's under it can't be reached", not win.centralWidget().isEnabled() and not win.palette_shortcut.isEnabled())
win.hide(); win.show_window(); app.processEvents()
check("the tray's Open Toner shows the lock screen", win.isVisible() and lock.isVisible())
lock.pw.setText("wrong password 123"); lock.unlock.click()
check("a wrong password says so", lock.error.text() == datakey.WRONG and session.state() == "locked")
lock.pw.setText(PW2); lock.unlock.click()
check("the right password uncovers the window", session.state() == "open" and not lock.isVisible() and win.centralWidget().isEnabled() and win.palette_shortcut.isEnabled())

print("== the idle timer")
from ui import lockscreen
check("15 minutes by default", db.get_setting("signin_idle_minutes") == 15)
now = [1000.0]
lockscreen._now = lambda: now[0]
lock.last = now[0]
now[0] += 14 * 60; lock.check_idle()
check("not before", session.state() == "open")
from PySide6.QtGui import QKeyEvent
from PySide6.QtCore import QEvent
QApplication.sendEvent(win, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier))
now[0] += 2 * 60; lock.check_idle()
check("a key press starts the wait again", session.state() == "open")
now[0] += 15 * 60; lock.check_idle()
check("after 15 minutes without use it locks", session.state() == "locked" and lock.isVisible())
check("...and says so", lock.reason.text() == "Locked after 15 minutes without use.", lock.reason.text())
session.unlock(PW2); app.processEvents()
check("unlocking (from anywhere) hides it again", not lock.isVisible())

print("== Settings > Security > Lock now follows the session")
from ui.settings_pages.security import SecurityPage
pg = next(p for p in win.settings.pages if isinstance(p, SecurityPage))
pg.show_vault()
check("on while signed in", pg.lock_now.isEnabled())
win.lock_shortcut.activated.emit()
check("off as soon as Toner locks (no refresh needed)", not pg.lock_now.isEnabled())
session.unlock(PW2)
check("on again once unlocked", pg.lock_now.isEnabled())

print("== signing out")
win.settings.unsaved_count = lambda: 1
win.settings.confirm_leave = lambda *a, **k: False
win.sign_out()
check("a refused question cancels it", win.isVisible() and session.state() == "open" and not win._signing_out and not win._quitting)
del win.settings.unsaved_count, win.settings.confirm_leave
win.lock_shortcut.activated.emit()
lock.other.click()
check("Sign in as someone else signs out and closes the window", session.state() == "signed_out" and win._signing_out and not win.isVisible())

from PySide6.QtCore import QProcess
started = []
QProcess.startDetached = staticmethod(lambda prog, args: started.append((prog, list(args))) or True)
argv = sys.argv
sys.argv = ["app.py", "--minimized", "--x"]
A.restart()
check("Toner starts again: the same program and arguments, without --minimized", started[-1] == (sys.executable, ["app.py", "--x"]), started)
sys.frozen = True
sys.argv = [sys.executable, "--minimized"]
A.restart()
check("a built Toner passes only its own arguments", started[-1] == (sys.executable, []), started)
os.environ["APPIMAGE"] = "/home/me/Toner.AppImage"
A.restart()
check("an AppImage starts the AppImage again", started[-1] == ("/home/me/Toner.AppImage", []), started)
del os.environ["APPIMAGE"], sys.frozen
sys.argv = argv

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
