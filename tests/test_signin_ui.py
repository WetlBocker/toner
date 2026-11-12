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
def undone(box):
    """What undo brings back into a box (Password mode hides undo, so it is read as a show-password switch would)."""
    mode = box.echoMode(); box.setEchoMode(box.EchoMode.Normal); box.undo(); text = box.text(); box.setEchoMode(mode)
    return text

PW, PW2, PW3 = "violet staple orbit 42", "amber kettle meadow 77", "copper willow harbor 58"
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
    seen["wrong_master_undo"] = undone(self.pw)
    self.pw.setText("old master password!"); self.ok.click()
    seen["master_after"] = (self.pw.text(), undone(self.pw))
    return self.result()
setupdlg.OldVaultDialog.exec = old_master
seen["deleted"] = 0
_real_later = setupdlg.OldVaultDialog.deleteLater
setupdlg.OldVaultDialog.deleteLater = lambda self: (seen.__setitem__("deleted", seen["deleted"] + 1), _real_later(self))[1]
done = setupdlg.run_first_start()
check("run_first_start finishes", done is True)
check("the account exists and is signed in", datakey.exists() and session.state() == "open" and session.user() == "Admin")
check("the upgrade asks for the old master password in the agreed words",
      "Enter the master password you used to unlock Toner's vault. Toner moves your saved passwords into the new account and won't ask for it again."
      in seen["upgrade_text"], seen["upgrade_text"])
check("a wrong master password says so and stays", seen["wrong_master"] == ("That master password isn't right.", 0), seen["wrong_master"])
check("...and undo can't bring the wrong one back into its box", seen["wrong_master_undo"] == "", seen["wrong_master_undo"])
check("the saved password moved into the new vault", passvault.get("a") == "1")
check("...and the master-password box is empty after the unlock, undo included", seen["master_after"] == ("", ""), seen["master_after"])
check("...and the dialog is scheduled for deletion", seen["deleted"] > 0, seen["deleted"])
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
check("...and undo can't bring the password back into its box", undone(w.pw) == "")
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

w = SignInWindow(); w.show()
w.name.setText("Jordan"); w.next.click(); w.use_recovery.click(); w.recovery.setText("AAAA-BBBB")
w.recovery_page.findChildren(type(w.not_you))[-1].click()          # the link under the box goes back to the name
check("going back from the recovery page leaves its box empty, and undo can't restore it", w.recovery.text() == "" and undone(w.recovery) == "", undone(w.recovery))
w.reject()

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

print("== the recovery reset after too many password tries")
use("fresh")
doc = datakey._read(); doc["throttle"] = {"fails": 9, "until": time.time() + 600}; datakey._write(doc)     # someone guessed for a while
w = SignInWindow(); w.show()
w.name.setText("Jordan"); w.next.click(); w.use_recovery.click(); w.recovery.setText(recovery); w.recovery_sign_in.click()
w.new_pw.setText(PW3); w.confirm.setText(PW3); w.reset_ok.click()
check("the recovery key's new password signs in at once (the wait is cleared)", w.result() == SignInWindow.DialogCode.Accepted
      and session.user() == "Jordan" and datakey._read()["throttle"] == {"fails": 0, "until": 0})
datakey.set_password("Jordan", PW2); session.sign_out()
w = SignInWindow(); w.show()
w.name.setText("Jordan"); w.next.click(); w.use_recovery.click(); w.recovery.setText(recovery); w.recovery_sign_in.click()
session.sign_in = throttled                          # a wrong try from elsewhere started a wait between the two steps
w.new_pw.setText(PW2); w.confirm.setText(PW2); w.reset_ok.click()
session.sign_in = real_sign_in
check("...and if a wait started anyway, the password step shows the countdown with the name filled in",
      w.pages.currentWidget() is w.password_page and w.who.text() == "Jordan" and not w.sign_in.isEnabled()
      and w.error.text() == "Too many tries. Wait 30 seconds, then try again." and session.state() == "signed_out", w.error.text())
check("...and the new password boxes are empty, undo included", w.new_pw.text() == w.confirm.text() == "" and undone(w.new_pw) == undone(w.confirm) == "")
w.sign_in_wait.timer.stop(); w.sign_in.setEnabled(True)
w.pw.setText(PW2); w.sign_in.click()
check("...after which signing in works", w.result() == SignInWindow.DialogCode.Accepted and session.user() == "Jordan")
session.sign_out()

print("== passwords left in Windows Credential Manager move over at a start, once")
from ui import signinwindow as SW
left = {"cm-x": "9", "cm-y": "old"}
forgotten, scans = [], []
real_left, real_forget = passvault.left_in_credential_manager, passvault.forget_credential_manager
passvault.left_in_credential_manager = lambda: (scans.append(1), dict(left))[1]
passvault.forget_credential_manager = lambda names: (forgotten.extend(names), [left.pop(n, None) for n in names])
real_exec = SW.SignInWindow.exec
def signed_in(self):
    session.sign_in("Jordan", PW2)
    if passvault.get("cm-y") is None:
        passvault.put("cm-y", "newer")                   # changed in the vault since the old copy was kept
    return SignInWindow.DialogCode.Accepted
SW.SignInWindow.exec = signed_in
check("the sign-in start carries them into the vault", A.sign_in_at_start() is True and passvault.get("cm-x") == "9" and sorted(forgotten) == ["cm-x", "cm-y"])
check("...never over a newer password the vault already has (the old copy still goes)", passvault.get("cm-y") == "newer" and "cm-y" not in left)
check("...and the scan isn't marked done while it still found some", db.get_setting("credential_manager_carried") is False)
session.sign_out()
check("the next start finds none left and marks it done", A.sign_in_at_start() is True and db.get_setting("credential_manager_carried") is True and len(scans) == 2)
session.sign_out()
check("later starts don't scan Credential Manager at all", A.sign_in_at_start() is True and len(scans) == 2)
passvault.left_in_credential_manager, passvault.forget_credential_manager = real_left, real_forget
SW.SignInWindow.exec = real_exec

print("== ...and only marked done after Credential Manager was read in full")
import types
from core import orgs
db.init()
real_sys, real_backend = passvault.sys, passvault._old_backend
passvault.sys = types.SimpleNamespace(platform="win32")      # (the real read path, on any system)
class BrokenStore:
    def get_password(self, service, name): raise OSError("no logon session")
    def delete_password(self, service, name): forgotten.append(name)
forgotten.clear()
db.set_setting("credential_manager_carried", False)
passvault._old_backend = BrokenStore()
setupdlg.carry_credential_manager()
check("a read that fails: nothing is carried or forgotten, and the next start tries again",
      db.get_setting("credential_manager_carried") is False and forgotten == [])
passvault._old_backend = None
setupdlg.carry_credential_manager()
check("no way to reach Credential Manager on Windows: not marked done either", db.get_setting("credential_manager_carried") is False)
class EmptyStore:
    def get_password(self, service, name): return None
passvault._old_backend = EmptyStore()
acme, globex = orgs.create("Acme Charter", "ACME"), orgs.create("Globex", "GLBX")
db.set_setting("credential_manager_carried", False)
db.set_home(acme)
setupdlg.carry_credential_manager()
db.set_home(globex)
check("a clean, empty read marks it done, for the whole installation (not one organization)",
      db.get_setting("credential_manager_carried") is True)
db.set_home(db.GLOBAL)

print("== keyring's default chains the vault in front of Credential Manager: carrying never deletes from the vault")
class VaultKeyring:                                        # Toner's vault as keyring sees it, by name and behaviour
    def get_password(self, service, name): return passvault.get(name)
    def delete_password(self, service, name):
        if not passvault.remove(name): raise KeyError(name)
vault_kr = VaultKeyring()
class OldStore:
    def __init__(self): self.d = {"service:proxy": "old-copy-1"}
    def get_password(self, service, name): return self.d.get(name)
    def delete_password(self, service, name): self.d.pop(name)
class ChainerBackend:                                      # keyring's chain, by name and behaviour: first backend that answers
    def __init__(self, backends): self.backends = backends
    def get_password(self, service, name):
        return next((v for v in (b.get_password(service, name) for b in self.backends) if v is not None), None)
    def delete_password(self, service, name):
        for b in self.backends:
            try: return b.delete_password(service, name)
            except Exception: pass
cm = OldStore()
passvault.put("service:ssh-tunnel", "kept-in-vault-1")
check("set-up: the vault holds a password Toner knows", passvault.get("service:ssh-tunnel") == "kept-in-vault-1")
passvault._old_backend = ChainerBackend([vault_kr, cm])
check("without_vault takes Credential Manager out of the chain", passvault.without_vault(passvault._old_backend) is cm)
db.set_setting("credential_manager_carried", False)
setupdlg.carry_credential_manager()
check("the vault's own password is still there", passvault.get("service:ssh-tunnel") == "kept-in-vault-1")
check("Credential Manager's password moved into the vault and left Credential Manager",
      passvault.get("service:proxy") == "old-copy-1" and "service:proxy" not in cm.d)
passvault._old_backend = vault_kr
check("the vault alone is never taken for Credential Manager", passvault.without_vault(passvault._old_backend) is None)
passvault.sys, passvault._old_backend = real_sys, real_backend

print("== the lock screen over Toner's window")
db.init()
A.apply_look(app)
win = A.Main(); win.resize(1024, 700); win.show(); app.processEvents()
lock = win.lock_screen
check("open: no lock screen, the idle timer runs", not lock.isVisible() and lock.idle.isActive())
check("the user menu names who is signed in, then Lock and Sign out",
      [a.text() for a in win.user_menu.actions() if not a.isSeparator()] == ["Jordan", "Lock (Ctrl+Shift+L)", "Sign out"])
win.lock_shortcut.activated.emit(); app.processEvents()
check("Ctrl+Shift+L locks the session and the lock sits over the window", session.state() == "locked" and lock.isVisible()
      and lock.geometry() == win.geometry())
check("the window is covered underneath too", lock.covers[win].isVisible() and lock.covers[win].geometry() == win.rect())
check("the lock screen's words", lock.reason.text() == "Locked by Jordan." and lock.who.text() == "Jordan, local account" and lock.unlock.text() == "Unlock")
check("the idle timer stops while locked", not lock.idle.isActive())
check("what's under it can't be reached: the lock is the newest modal", QApplication.activeModalWidget() is lock)
win.hide(); win.show_window(); app.processEvents()
check("the tray's Open Toner shows the lock screen", win.isVisible() and lock.isVisible())
lock.pw.setText("wrong password 123"); lock.unlock.click()
check("a wrong password says so", lock.error.text() == datakey.WRONG and session.state() == "locked")
lock.pw.setText(PW2); lock.unlock.click()
check("the right password uncovers the window", session.state() == "open" and not lock.isVisible() and not lock.covers
      and QApplication.activeModalWidget() is None)
check("...and undo can't bring the password back into the lock's box", undone(lock.pw) == "")

print("== a dialog that was open when Toner locked")
from PySide6.QtWidgets import QDialog, QLineEdit
from PySide6.QtTest import QTest
from ui.toast import Toast, toast
for parent, kind in ((win, "inside the window"), (None, "on its own")):
    d = QDialog(parent); d.setWindowModality(Qt.WindowModality.ApplicationModal); typed = QLineEdit(d); d.resize(400, 200); d.show(); app.processEvents()
    typed.setText("half typed")
    win.lock(); app.processEvents()
    check(f"a modal dialog {kind}: the lock is above it and takes input", QApplication.activeModalWidget() is lock
          and QApplication.focusWidget() is lock.pw, (QApplication.activeModalWidget(), QApplication.focusWidget()))
    check("...the dialog stays open, covered", d.isVisible() and lock.covers[d].isVisible() and lock.covers[d].geometry() == d.rect())
    QTest.keyClicks(lock.pw, PW2); QTest.keyClick(lock.pw, Qt.Key.Key_Return); app.processEvents()
    check("...unlock gives it back with what was typed", session.state() == "open" and d.isVisible() and typed.text() == "half typed"
          and QApplication.activeModalWidget() is d and not lock.covers)
    d.close(); d.deleteLater(); app.processEvents()

print("== what appears while locked")
win.lock(); app.processEvents()
check("a toast doesn't show over the lock", toast(win.inventory, "Saved") is None
      and not any(t.isVisible() for t in win.findChildren(Toast)))
late = QDialog(win); late.setWindowModality(Qt.WindowModality.ApplicationModal); QLineEdit("a device's details", late); late.show(); app.processEvents()
check("a window opened while locked is covered, and the lock stays on top", late in lock.covers and lock.covers[late].isVisible()
      and QApplication.activeModalWidget() is lock)
session.unlock(PW2); app.processEvents()
check("...and is there after unlocking", late.isVisible() and QApplication.activeModalWidget() is late)
late.close(); late.deleteLater(); app.processEvents()

print("== a proxy's one-time code asked while locked (scheduled work)")
from ui import otpprompt
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QInputDialog
win.lock(); app.processEvents()
seen_otp = {}
def look_at_prompt():
    dlg = next(w for w in QApplication.topLevelWidgets() if isinstance(w, QInputDialog) and w.isVisible())
    seen_otp.update(parent=dlg.parentWidget(), covered=dlg in lock.covers and lock.covers[dlg].isVisible(),
                    modal=QApplication.activeModalWidget(), focus=QApplication.focusWidget(),
                    on_top=bool(dlg.windowHandle().flags() & Qt.WindowType.WindowStaysOnTopHint))
    QTest.keyClicks(QApplication.focusWidget(), "typed at the lock")
    seen_otp["prompt_text"] = dlg.textValue()
    dlg.reject()
QTimer.singleShot(200, look_at_prompt)
real_active = QApplication.activeWindow
QApplication.activeWindow = staticmethod(lambda: lock)  # what a real desktop reports while locked (offscreen has no active window)
answer_otp = otpprompt.ask("Proxy one-time code", "Enter the code for the proxy.", secret=True)
QApplication.activeWindow = real_active
check("it belongs to Toner's window, not the lock", seen_otp.get("parent") is win, seen_otp.get("parent"))
check("...is covered, and the lock stays the active modal with the focus", seen_otp.get("covered") and seen_otp.get("modal") is lock
      and seen_otp.get("focus") is lock.pw, seen_otp)
check("...doesn't stay on top of the lock while covered", seen_otp.get("on_top") is False)
check("...and what is typed goes to the lock's box, not the prompt", seen_otp.get("prompt_text") == "" and lock.pw.text() == "typed at the lock")
lock.pw.clear()
session.unlock(PW2); app.processEvents()

print("== the idle timer")
from ui import lockscreen
check("15 minutes by default", db.get_setting("signin_idle_minutes") == 15)
check("it counts wall-clock time, which goes on while the computer sleeps", lockscreen._now is time.time)
now = [100000.0]
lockscreen._now = lambda: now[0]
lock.last = now[0]
now[0] += 14 * 60; lock.check_idle()
check("not before", session.state() == "open")
from PySide6.QtGui import QKeyEvent
from PySide6.QtCore import QEvent
QApplication.sendEvent(win, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier))
now[0] += 2 * 60; lock.check_idle()
check("a key press starts the wait again", session.state() == "open")
now[0] -= 3600; lock.check_idle()
check("the clock going back starts the wait again too", session.state() == "open" and lock.last == now[0])
now[0] += 14 * 60; lock.check_idle()
check("...from then", session.state() == "open")
now[0] += 3 * 3600; lock.check_idle()
check("a jump forward past the limit (a sleep) locks", session.state() == "locked" and lock.isVisible())
check("...and says so", lock.reason.text() == "Locked after 15 minutes without use.", lock.reason.text())
session.unlock(PW2); app.processEvents()
check("unlocking (from anywhere) hides it again", not lock.isVisible())
lock.last = now[0]
now[0] += 3 * 3600                                   # asleep; Qt's timers don't count that, so the idle check hasn't run
QApplication.sendEvent(win, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier))
check("the first key press after waking from a long sleep locks before anything else", session.state() == "locked" and lock.isVisible())
session.unlock(PW2); app.processEvents()

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
applied = []
win.about.apply_on_exit = lambda: applied.append(1)
from core import roles, assistant as AIm
alive = (len(session._callbacks), len(roles._callbacks), len(AIm._listeners))
lock.other.click()
check("Sign in as someone else signs out and closes the window", session.state() == "signed_out" and win._signing_out and not win.isVisible())
check("...and installs no waiting update (Toner stays open)", applied == [])

print("== Toner stays open: the window goes, the next sign-in gets a new one")
win.deleteLater(); app.sendPostedEvents(None, QEvent.Type.DeferredDelete); app.processEvents()
gone = (len(session._callbacks), len(roles._callbacks), len(AIm._listeners))
check("the old window's listeners went with it (sign-in changes, roles, the assistant)",
      gone[0] < alive[0] and gone[1] < alive[1] and gone[2] < alive[2], (alive, gone))
session.sign_in("Jordan", PW2)                       # what the sign-in page does next
check("...and a sign-in after it tells no dead window (nothing raised)", session.state() == "open")
win = A.Main(); win.show(); app.processEvents()
check("the new window is built for whoever signed in", win.isVisible()
      and (len(session._callbacks), len(roles._callbacks), len(AIm._listeners)) == alive, ((len(session._callbacks), len(roles._callbacks), len(AIm._listeners)), alive))
win.sign_out(); app.processEvents()
win.deleteLater(); app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
check("signing out again leaves no more listeners than the first time (nothing builds up)",
      (len(session._callbacks), len(roles._callbacks), len(AIm._listeners)) == gone, (len(session._callbacks), gone))

print("== Remember me: only the last username, kept for the next sign-in page")
from ui import signinwindow as SW
SW.remember("")
if session.state() != "signed_out":
    session.sign_out()
w1 = SignInWindow()
check("unticked and empty when nothing is remembered", w1.remember.text() == "Remember me" and not w1.remember.isChecked() and w1.name.text() == "")
w1.name.setText("Jordan"); w1.remember.setChecked(True)
session.sign_in("Jordan", PW2); w1.accept()
kept = SW.remembered_path().read_text(encoding="utf-8")
check("ticked and signed in: the username is kept, and nothing else (no password)", SW.remembered() == "Jordan" and PW2 not in kept, kept)
session.sign_out()
w2 = SignInWindow()
check("the next sign-in page shows it, ticked; the password is still asked for", w2.name.text() == "Jordan" and w2.remember.isChecked() and w2.pw.text() == "")
w2.remember.setChecked(False)
session.sign_in("Jordan", PW2); w2.accept()
check("unticked and signed in: it is forgotten", not SW.remembered_path().exists() and SignInWindow().name.text() == "")
session.sign_out()
SW.remember("Jordan")
w3 = SignInWindow(); w3.name.setText("someone"); w3.accept()          # signed out: as the recovery key leaves it, no account
check("a sign-in that is no account (the recovery key) changes nothing", SW.remembered() == "Jordan")
check("an admin approving someone else's sign-in: no Remember me there", SignInWindow(approver_for=object()).remember is None)
SW.remember("")
SW.remembered_path().write_bytes(b"x" * 5000)
check("a file that is not ours is ignored", SW.remembered() == "")
SW.remember("")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
