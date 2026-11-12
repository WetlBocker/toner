# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# "Security keys..." under your name (ui/keysdialog.py) with a fake key: the menu item (never SSO or the recovery key), the list,
# adding (password or PIN proven first, then the touch off the window's thread, then the name), removing, the words of each
# step, Cancel, closing and locking releasing the wait with nothing added, and the forced add at sign-in when keys are required.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\keysdialog%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import logging
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import datakey, db, directory, dirsignin, fidokey, helperclient, pinslot, roles, session
def _no_helper(): raise helperclient.NotRunning()
helperclient._connect, helperclient.installed, helperclient.not_installed = _no_helper, lambda: False, lambda: True   # no helper here

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

captured_log = []
class Grab(logging.Handler):
    def emit(self, record): captured_log.append(self.format(record))
logging.getLogger().addHandler(Grab()); logging.getLogger().setLevel(logging.DEBUG)

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
from ui import keysdialog
from ui.keysdialog import KeysDialog

PW, PW2, PIN, PIN2, KEY_PIN = "correct horse battery 42", "amber kettle meadow 77", "a long pin-only pin 3", "another pin-only pin 8", "key-pin-9071"
TECHS = "CN=Toner Techs,DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [], "Engineer": [], "Tech": [TECHS]}, "duo": {"on": False, "host": "", "ikey": ""}}
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": "https://login.example.com", "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
CAT = directory.User("6f1c2a4e-0000-4000-8000-00000000000c", "cat", "Cat", (TECHS,), True)
SSO_USER = directory.User("sub-sso-user", "sso-user", "SSO User", ("g1",), True)


def new_account(user, directory_id, pin):
    """A directory account (a PIN-alone slot) started and approved by Admin1, as a first sign-in makes one."""
    session.sign_out()
    slot = pinslot.new("pin", datakey.new_slot_id(), pin)
    datakey.start_directory_account(user, directory_id, slot)
    session.sign_in("Admin1", PW)
    roles.approve(user.name, slot)
    session.sign_out()


recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME, SSO])
datakey.add_local("Admin2", PW2, role="Admin")
new_account(CAT, "d1", PIN)
new_account(SSO_USER, "s1", PIN2)
fake = fakekey.install()
real_register = fake.register
said, asked = [], []
QMessageBox.information = staticmethod(lambda *a, **k: said.append(a[2]) or QMessageBox.StandardButton.Ok)
answer = [False]
keysdialog.confirm = lambda parent, text, more="": asked.append((text, more)) or answer[0]


def wait_for(cond, seconds=10):
    end = time.time() + seconds
    while not cond() and time.time() < end:
        app.processEvents(); time.sleep(0.005)
    app.processEvents()
    return cond()


def held(real):
    """`real` that waits until released (or its wait is cancelled), on whatever thread asks it; it notes that thread."""
    gate = threading.Event()
    def call(*a, **kw):
        held.on = threading.current_thread()
        while not gate.is_set() and not (kw.get("cancel") and kw["cancel"].is_set()):
            time.sleep(0.005)
        return real(*a, **kw)
    return call, gate


def heading(page): return page.layout().itemAt(0).widget().text()
def idle(d): return not d._jobs
def on(d, page): return d.pages.currentWidget() is page
def opened(**kw):
    d = KeysDialog(**kw); d.show(); wait_for(lambda: idle(d))
    return d
def rows(d): return [(d.table.item(r, 0).text(), d.table.item(r, 1).text()) for r in range(d.table.rowCount())]


def add_steps(d, secret, name="Blue"):
    """Add a key through the dialog; the heading of each page it shows, in order."""
    steps = []
    d.pages.currentChanged.connect(lambda _i: steps.append(heading(d.pages.currentWidget())))
    d.add.click()
    d.secret.setText(secret); d.secret_next.click()
    if wait_for(lambda: on(d, d.name_page)):
        d.key_name.setText(name); d.name_ok.click()
        wait_for(lambda: idle(d) and on(d, d.list_page))
    d.pages.currentChanged.disconnect()
    return steps


def remove(d, secret, row=0):
    d.table.selectRow(row); d.remove.click()
    if on(d, d.secret_page):
        d.secret.setText(secret); d.secret_next.click()
        wait_for(lambda: idle(d))


today = datetime.now().date().isoformat()

print("== the menu under your name")
session.sign_in("Admin1", PW); A.apply_look(app)
win = A.Main()
def menu_texts(): return [a.text() for a in win.user_menu.actions() if not a.isSeparator()]
check("the menu under your name has Security keys... between Lock and Sign out", menu_texts() == ["Admin1", "Lock (Ctrl+Shift+L)", "Security keys...", "Sign out"], menu_texts())
def menu_texts_for(name):
    session.sign_out()
    if name is None:
        session.sign_in_recovery(recovery)
    else:
        session.sign_in_pin(name, PIN2)
    win.fill_user_menu()
    return menu_texts()
check("not for an SSO account, nor a recovery-key sign-in", "Security keys..." not in menu_texts_for("sso-user") and "Security keys..." not in menu_texts_for(None))
session.sign_out(); session.sign_in_pin("cat", PIN); win.fill_user_menu()
check("...an AD account has it", "Security keys..." in menu_texts())
session.sign_out(); session.sign_in("Admin1", PW)
win.close(); win.deleteLater(); app.processEvents()

print("== a local account")
d = opened()
check("the dialog is headed Security keys, with Add a key... and Remove", d.windowTitle() == "Security keys" and [d.add.text(), d.remove.text()] == ["Add a key...", "Remove"])
check("empty, a local account", d.empty.text() == "No security keys. Add one to need it, with your password, every time you sign in."
      and d.empty.isVisible() and not d.remove.isEnabled() and d.add.isEnabled() and not d.note.isVisible() and not d.reason.isVisible())

fake.calls.clear()
before = datakey.my_keys()
d.add.click(); d.secret.setText("not the password at all"); d.secret_next.click(); wait_for(lambda: idle(d))
error = d.secret_error.text()
check("a wrong password in the add dialog adds nothing", error == "That username or password isn't right." and datakey.my_keys() == before
      and fake.calls == [] and on(d, d.secret_page) and d.secret.text() == "", (error, fake.calls))
d.secret_cancel.click()

fidokey.register, gate = held(real_register)
d.add.click(); d.secret.setText(PW); d.secret_next.click()
check("after the password, the touch page; the key is asked off the window's thread", wait_for(lambda: on(d, d.touch_page))
      and held.on is not threading.main_thread() and d.touch_cancel.isEnabled() and d.secret.text() == "")
d.touch_cancel.click()
check("Cancel releases the wait and adds nothing", wait_for(lambda: idle(d)) and not gate.is_set() and on(d, d.list_page) and datakey.my_keys() == [])
d.add.click(); d.secret.setText(PW); d.secret_next.click(); wait_for(lambda: on(d, d.touch_page))
session.lock(); wait_for(lambda: idle(d))
check("the session locking releases it too", on(d, d.list_page) and datakey.my_keys() == [] and session.state() == "locked")
session.unlock(PW)
d.add.click(); d.secret.setText(PW); d.secret_next.click(); wait_for(lambda: on(d, d.touch_page))
d.reject()
check("closing the dialog during the touch releases it, nothing added", idle(d) and datakey.my_keys() == [])
gate.set(); fidokey.register = real_register

d = opened()
d.add.click(); d.secret.setText(PW); d.secret_next.click(); wait_for(lambda: on(d, d.name_page))
d.name_cancel.click(); wait_for(lambda: idle(d))
check("a key touched, then Cancel at its name: Toner's account is unchanged", datakey.my_keys() == [] and on(d, d.list_page))

said.clear()
steps = add_steps(d, PW)
check("adding asks, in order", steps[:3] == ["Enter your password", "Touch the key you want to add", "Name this key"]
      and d.key_name.placeholderText() == "for example, Blue YubiKey on my keyring", steps)
check("after the first key", said == ["From now on, signing in needs this key. Add a second key and keep it somewhere safe: if you lose your only key, an admin has to reset your account."], said)
check("the list shows each key's name and when it was added", rows(d) == [("Blue", today)] and not d.empty.isVisible(), rows(d))
said.clear(); add_steps(d, PW, "Spare")
check("a second key: no message, both listed", said == [] and [r[0] for r in rows(d)] == ["Blue", "Spare"])

asked.clear(); remove(d, PW, row=0)
check("removing asks first, after the password", asked == [("Remove Blue? You won't be able to sign in with it.", "")]
      and len(datakey.my_keys()) == 2, asked)
answer[0] = True; asked.clear(); remove(d, "not the password at all", row=1)
check("a wrong password removes nothing and asks nothing", asked == [] and d.secret_error.text() == "That username or password isn't right."
      and len(datakey.my_keys()) == 2)
d.secret_cancel.click()
remove(d, PW, row=1)
check("removing with Yes takes it out of the list", [r[0] for r in rows(d)] == ["Blue"] and len(datakey.my_keys()) == 1)
answer[0] = False; asked.clear(); remove(d, PW)
check("the last key, a local account", asked == [("Remove Blue? You won't be able to sign in with it.",
                                                  "This is your last key. Your account will sign in with its password alone.")], asked)
roles.set_require_keys(True)
asked.clear(); remove(d, PW)
refused = d.error.text()
check("the last key while keys are required cannot go", refused == "An admin requires a security key. Add another key before removing this one."
      and len(datakey.my_keys()) == 1 and asked == [] and on(d, d.list_page))
roles.set_require_keys(False)
answer[0] = True; remove(d, PW)
check("the last key removed: the empty list again", datakey.my_keys() == [] and d.empty.isVisible() and rows(d) == [])
d.reject()

datakey.remove("Admin2")
d = opened()
said.clear(); add_steps(d, PW)
check("...the only admin is told about the recovery key instead", said == ["You are the only admin. If you lose your only key, the recovery key is the only way back in."], said)
answer[0] = True; remove(d, PW)
d.reject()

print("== the key's own PIN (Linux and macOS)")
fake.pin = KEY_PIN
d = opened()
d.add.click(); d.secret.setText(PW); d.secret_next.click()
check("the key's PIN is asked in the dialog", wait_for(lambda: on(d, d.keypin_page)) and heading(d.keypin_page) == "Enter your security key's PIN")
d.key_pin.setText("0000"); d.key_pin_ok.click()
check("a wrong key PIN says so and asks again", wait_for(lambda: on(d, d.keypin_page) and d.key_pin_error.text() == "That key PIN isn't right.")
      and d.key_pin.text() == "")
d.key_pin.setText(KEY_PIN); d.key_pin_ok.click()
check("the right one goes on to the name", wait_for(lambda: on(d, d.name_page)) and d.key_pin.text() == "")
d.reject()
check("closing at the name adds nothing", idle(d) and datakey.my_keys() == [])
fake.pin = None

print("== an AD account")
session.sign_out(); session.sign_in_pin("cat", PIN)
d_ad = opened()
check("empty, an AD account", d_ad.empty.text() == "No security keys. Add one to need it, with your PIN, every time you sign in." and d_ad.add.isEnabled())
said.clear(); steps = add_steps(d_ad, PIN)
check("adding asks for the Toner PIN first", steps[0] == "Enter your PIN" and datakey.my_keys()[0]["name"] == "Blue", steps)
answer[0] = False; asked.clear(); remove(d_ad, PIN)
check("the last key, an AD account", asked == [("Remove Blue? You won't be able to sign in with it.",
                                                "This is your last key. Your account will sign in without one.")], asked)
answer[0] = True; remove(d_ad, PIN)
check("...and removed, the account is as before", datakey.my_keys() == [] and not datakey.has_keys("cat"))
d_ad.reject()
real_helper = dirsignin.helper_may_be_on
dirsignin.helper_may_be_on = lambda: True
d_helper = opened()
check("an AD account on a copy with the helper switch on", d_helper.note.text() == 'Security keys can\'t be added to this account while "Let group members sign in without approval" is on.'
      and d_helper.note.isVisible() and not d_helper.add.isEnabled())
d_helper.reject()
dirsignin.helper_may_be_on = real_helper

print("== required at sign-in")
from ui import signinwindow as SW
session.sign_out(); session.sign_in("Admin1", PW)
roles.set_require_keys(True)
session.sign_out()
signins, mains, seen = [], [], {}
def signed_in(self):
    signins.append(session.state())
    if len(signins) > 1:
        return SW.SignInWindow.DialogCode.Rejected           # the person quits at the second sign-in window
    session.sign_in("Admin1", PW)
    return SW.SignInWindow.DialogCode.Accepted
real_exec, real_main = SW.SignInWindow.exec, A.Main
SW.SignInWindow.exec = signed_in
A.Main = lambda *a, **k: mains.append(1)
def when_shown(fn, seconds=20):
    """fn(the keys dialog) once it is the modal on screen; None if none came (polled: must_add's wait runs its own loop first)."""
    end = time.time() + seconds
    def poll():
        d = QApplication.activeModalWidget()
        if isinstance(d, KeysDialog) and d.isVisible():
            return fn(d)
        if time.time() < end:
            QTimer.singleShot(20, poll)
        else:
            fn(None)
    QTimer.singleShot(20, poll)
def close_it(d):
    seen["forced"] = isinstance(d, KeysDialog) and d.must_add and d.reason.text() == "An admin requires a security key. Add one to continue." \
        and d.reason.isVisible() and session.state() == "open"
    d.reject()
when_shown(close_it)
got = A.signed_in_window(app)
check("keys required and none yet: the dialog opens before the main window, saying why", seen.get("forced"), seen)
check("closing it without adding signs out", got is None and signins == ["signed_out", "signed_out"] and session.state() == "signed_out" and mains == [], signins)

signins.clear()
def add_it(d):
    said.clear(); add_steps(d, PW)
SW.SignInWindow.exec = lambda self: (signins.append(1), session.sign_in("Admin1", PW), SW.SignInWindow.DialogCode.Accepted)[2]
when_shown(add_it)
check("adding one lets Toner open", A.sign_in_at_start() is True and session.state() == "open" and len(datakey.my_keys()) == 1 and signins == [1])
session.sign_out()
def not_asked(d):
    seen["dialog"] = d
    if d is not None: d.reject()
seen.clear(); when_shown(not_asked, 1)
SW.SignInWindow.exec = lambda self: (session.sign_in("Admin1", PW, key=fake.value), SW.SignInWindow.DialogCode.Accepted)[1]
check("an account with a key goes straight on", A.sign_in_at_start() is True and session.state() == "open")
wait_for(lambda: "dialog" in seen, 3)
check("...no dialog", seen.get("dialog") is None, seen)
session.sign_out()
def via_recovery(self):                                  # the recovery key, then a new password: as the reset page ends it
    session.sign_in_recovery(recovery); datakey.set_password("Admin1", PW); session.sign_out()
    session.sign_in("Admin1", PW); self.pages.setCurrentWidget(self.reset_page)
    return SW.SignInWindow.DialogCode.Accepted
SW.SignInWindow.exec = via_recovery
seen.clear(); when_shown(not_asked, 1)
check("a recovery-key sign-in (its keys cleared by the reset) is not sent to add one", A.sign_in_at_start() is True
      and session.state() == "open" and datakey.my_keys() == [])
wait_for(lambda: "dialog" in seen, 3)
check("...no dialog", seen.get("dialog") is None, seen)
session.sign_out()
SW.SignInWindow.exec, A.Main = real_exec, real_main

check("no password, PIN or key PIN in the log", not any(s in line for line in captured_log for s in (PW, PW2, PIN, PIN2, KEY_PIN)))
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
