# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The security key step in the sign-in window and on the lock screen (ui/keyask.py), with a fake key: the key page only after the
# password is right, the wait off the window's thread, each failure's words, Use a different account, the key's PIN in Toner's
# window, a directory account's and an approver's key, the touch at unlock, and an account without keys exactly as before.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\signinkeysui%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import datakey, db, dirsignin, fidokey, session

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QApplication, QWidget
app = QApplication([])
from ui.signinwindow import SignInWindow
from ui.lockscreen import LockScreen

PW, PW2, KEY_PIN = "correct horse battery 42", "amber kettle meadow 77", "4321"
fake = fakekey.install()
real_value, real_present = fake.value, fake.present
datakey.create("Admin1", PW)
db.init()
datakey.add_local("Plain", PW2)
cred, val = fake.register("Blue", os.urandom(32))
datakey.add_key(PW, cred, val, "Blue")
session.sign_out()


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


w = None
def window(name="Admin1"):
    global w
    w = SignInWindow(); w.show()
    shown.clear()
    w.pages.currentChanged.connect(lambda _i: shown.append(w.pages.currentWidget()))
    w.name.setText(name); w.next.click()
    return w
shown = []

def heading(page): return page.layout().itemAt(1).widget().text()
def under(page): return page.layout().itemAt(2).widget().text()
def page_title(): return heading(w.pages.currentWidget())
def page_text(): return under(w.pages.currentWidget())
def link_text(): return w.key_back.text()
def error_text(): return w.error.text()
def page_is(name): return w.pages.currentWidget() is {"password": w.password_page, "name": w.name_page, "key": w.key_page,
                                                        "keypin": w.keypin_page, "pin": w.pin_page}[name]
def idle(): return not w._jobs
def sign_in(pw=PW): w.pw.setText(pw); w.sign_in.click()


print("== a local account with a key")
fidokey.value, gate = held(real_value)
window(); sign_in()
check("after a right password the window shows the key page", wait_for(lambda: page_is("key")) and page_title() == "Touch your security key"
      and page_text() == "Plug it in if it isn't already, then touch it." and link_text() == "Use a different account", page_title())
asked_on = held.on
check("the window stays responsive while it waits (the key is asked off the UI thread)", asked_on is not threading.main_thread()
      and w.key_back.isEnabled() and not idle())
gate.set()
check("a touch signs in", wait_for(lambda: w.result() == w.DialogCode.Accepted) and session.state() == "open" and session.user() == "Admin1")
fidokey.value = real_value
session.sign_out()

window(); fake.calls.clear(); sign_in("not the password at all")
wait_for(idle)
check("a wrong password never shows the key page", error_text() == "That username or password isn't right." and page_is("password")
      and w.key_page not in shown and fake.calls == [], (error_text(), fake.calls))
w.reject()


def error_after(plugged=True, touch=True, other_key=False):
    fake.plugged, fake.touch = plugged, touch
    saved = dict(fake.secrets)
    if other_key:
        fake.secrets.clear()
    try:
        window(); sign_in(); wait_for(idle)
        return error_text()
    finally:
        fake.plugged, fake.touch = True, True
        fake.secrets.update(saved)

check("no key plugged in", error_after(plugged=False) == "Toner can't find a security key. Plug yours in and try again.", error_text())
w.reject()
check("another account's key", error_after(other_key=True) == "That key isn't registered to this account.", error_text())
w.reject()
check("not touched: back on the password page, signed out, the box empty", error_after(touch=False) == "The key wasn't touched. Sign in again."
      and page_is("password") and session.state() == "signed_out" and w.pw.text() == "" and w.key_page in shown, error_text())
check("...and the next try works", (sign_in(), wait_for(lambda: w.result() == w.DialogCode.Accepted))[1] and session.state() == "open")
session.sign_out()

fidokey.value, gate = held(real_value)
window(); sign_in(); wait_for(lambda: page_is("key"))
w.key_back.click()
cancelled = wait_for(idle, 5) and not gate.is_set()
check("Use a different account cancels the wait and goes back to the name page", cancelled and page_is("name")
      and session.state() == "signed_out" and w.error.text() == "")
w.reject()

window(); sign_in(); wait_for(lambda: page_is("key"))
w.reject()
check("closing the window during the wait releases it, nothing open", idle() and session.state() == "signed_out" and not datakey.is_open())

fidokey.value = real_value
touched_late = threading.Event()
def touched_anyway(creds, **kw):                                   # the touch was already on its way when the person went back
    held.on = threading.current_thread()
    touched_late.wait(10)
    return real_value(creds)
fidokey.value = touched_anyway
window(); sign_in(); wait_for(lambda: page_is("key"))
opened = []
session.on_change(opened.append)
w.key_back.click(); touched_late.set(); wait_for(idle)
session.off_change(opened.append)
check("a touch that lands after Use a different account: the session it opened is signed out, no page switched",
      opened == ["open", "signed_out"] and page_is("name") and session.state() == "signed_out" and not datakey.is_open(), opened)
w.reject()
fidokey.value = real_value

print("== the key's own PIN in Toner's window (Linux and macOS)")
fake.pin = KEY_PIN
window(); sign_in(); wait_for(lambda: page_is("keypin"))
def pin_page_title(): return heading(w.keypin_page)
def pin_page_text(): return under(w.keypin_page)
check("off Windows the key's PIN is asked in Toner's window", pin_page_title() == "Enter your security key's PIN"
      and pin_page_text() == "This is the PIN set on the key itself, not the one you use for Toner." and page_is("keypin"))

def error_after_pin(wrong_key_pin):
    w.key_pin.setText("0000" if wrong_key_pin else KEY_PIN); w.key_pin_ok.click()
    wait_for(lambda: page_is("keypin") and w.key_pin_error.text())
    return w.key_pin_error.text()
check("a wrong key PIN says so and asks again", error_after_pin(wrong_key_pin=True) == "That key PIN isn't right." and page_is("keypin")
      and w.key_pin.text() == "")
w.key_pin.setText(KEY_PIN); w.key_pin_ok.click()
check("the right key PIN, then the touch, signs in", wait_for(lambda: w.result() == w.DialogCode.Accepted) and session.state() == "open"
      and w.key_pin.text() == "")
session.sign_out()
window(); sign_in(); wait_for(lambda: page_is("keypin"))
w.key_pin.setText("typed, then gone back"); w.key_back.click()
check("Use a different account from the key PIN page: released, the name page, the PIN box empty", wait_for(idle, 5) and page_is("name")
      and w.key_pin.text() == "" and session.state() == "signed_out")
w.reject()
window(); sign_in(); wait_for(lambda: page_is("keypin"))
w.reject()
check("closing the window at the key PIN releases the worker", idle() and session.state() == "signed_out")
fake.pin = None

print("== a directory account, and an approver with a key")


class Attempt:
    def __init__(self):
        self.stage, self.offline, self.name, self.duo_skipped, self.message, self.fresh, self.ticket = "pin", False, "bob@acme.com", True, None, True, None


stages = []
real = {k: getattr(dirsignin, k) for k in ("classify", "begin", "after_password", "finish", "approve_with_account")}
dirsignin.classify = lambda name: ("directory", {"kind": "ad", "id": "d1", "name": "ACME"})
dirsignin.begin = lambda login, pw: stages.append("password") or Attempt()
dirsignin.after_password = lambda a: None
def finish(a, pin, key=None):
    stages.append("pin")
    key([cred])
    a.stage = "done"
dirsignin.finish = finish
w = SignInWindow(); w.show()
w.pages.currentChanged.connect(lambda _i: w.pages.currentWidget() is w.key_page and stages.append("key"))
w.finished.connect(lambda r: stages.append("done"))
w.name.setText("bob@acme.com"); w.next.click(); w.pw.setText("pw-bob"); w.sign_in.click()
wait_for(lambda: page_is("pin")); w.pin.setText("246813"); w.pin_ok.click()
wait_for(lambda: "done" in stages)
check("a directory account: password, no Duo, PIN, then the key page", stages == ["password", "pin", "key", "done"], stages)

order = []
def approve_with_account(a, approver, pin, key=None):
    key([cred]); order.append("approved")
dirsignin.approve_with_account = approve_with_account
fidokey.value = lambda creds, **kw: order.append("touched") or real_value(creds, **kw)
target = Attempt(); target.stage = "approve"
n = SignInWindow(None, approver_for=target); n.show()
n.name.setText("erin@acme.com"); n.next.click(); n.pw.setText("pw-erin"); n.sign_in.click()
wait_for(lambda: n.pages.currentWidget() is n.pin_page); n.pin.setText("802461"); n.pin_ok.click()
wait_for(lambda: n.result() == n.DialogCode.Accepted)
approver_touched_before_approved = order == ["touched", "approved"] and n.result() == n.DialogCode.Accepted
check("an admin with a key approving: their key is asked before the approval lands", approver_touched_before_approved, order)
fidokey.value = real_value
for k, v in real.items():
    setattr(dirsignin, k, v)

print("== the lock screen")


class FakeMain(QWidget):
    signed_out = 0
    def sign_out(self): self.signed_out += 1; session.sign_out()


main = FakeMain(); main.resize(600, 400); main.show()
lock = LockScreen(main)
session.sign_in("Admin1", PW, key=fake.value)
session.lock(); app.processEvents()
fidokey.present, gate = held(real_present)
lock.pw.setText(PW); lock.unlock.click()
def lock_text(): return lock.head.text()
check("unlock: the password, then a touch", wait_for(lambda: lock_text() == "Touch your security key")
      and lock.reason.text() == "Plug it in if it isn't already, then touch it." and held.on is not threading.main_thread()
      and (gate.set() or wait_for(lambda: session.state() == "open")) and not lock.locked)
fidokey.present = real_present

def lock_error(touch):
    session.lock(); app.processEvents()
    fake.touch = touch
    lock.pw.setText(PW); lock.unlock.click()
    wait_for(lambda: not lock._jobs)
    fake.touch = True
    return lock.error.text()
check("not touched at unlock: stays locked, in the unlock words", lock_error(touch=False) == "The key wasn't touched. Try again."
      and session.state() == "locked" and lock.head.text() == "Toner is locked" and lock.pw.isEnabled(), lock.error.text())
lock.pw.setText("not the password at all"); fake.calls.clear(); lock.unlock.click(); wait_for(lambda: not lock._jobs)
check("a wrong password at unlock never asks the key", lock.error.text() == datakey.WRONG and fake.calls == [] and session.state() == "locked")
fidokey.present, gate = held(real_present)
lock.pw.setText(PW); lock.unlock.click(); wait_for(lambda: lock_text() == "Touch your security key")
check("while the key is asked, Sign in as someone else is the way out", lock.other.isEnabled() and not lock.unlock.isEnabled())
lock.other.click()
check("...which releases the wait and signs out", all(j.isFinished() for j in lock._jobs) and main.signed_out == 1 and session.state() == "signed_out")
fidokey.present = real_present
app.processEvents()

print("== an account without keys: as before")
fake.calls.clear()
window("Plain"); sign_in(PW2)
plain_signed_in = wait_for(lambda: w.result() == w.DialogCode.Accepted) and session.user() == "Plain"
session.lock(); app.processEvents()
lock.pw.setText(PW2); lock.unlock.click()
plain_unlocked = wait_for(lambda: session.state() == "open")
plain_account_never_shows_the_key_page = plain_signed_in and plain_unlocked and w.key_page not in shown and fake.calls == [] \
    and lock.head.text() == "Toner is locked"
check("an account without keys signs in and unlocks exactly as before", plain_account_never_shows_the_key_page, (shown, fake.calls))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
