# Run directly (python tests/test_sso_signin_ui.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The sign-in window and the lock screen for an SSO account, against a fake local provider (tests/fake_oidc.py) and a fake
# security chip: the browser page's approved words, Cancel, Open the page again, a finished browser sign-in landing on Choose a
# PIN, the refusals' approved sentences, and the lock screen asking for a full sign-in once the session is over.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ssosigninui%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import json, threading, webbrowser
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import datakey, db, oidc, osstore, pinslot, roles, session, tpm_windows
from core import dirsignin as S
from fake_oidc import FakeProvider

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


# ---------------------------------------------------------------- fakes (as tests/test_sso_signin.py)
PEPPERS, PINS = {}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)


class FakeTpm:
    LockedOut = tpm_windows.LockedOut
    keys, locked = {}, 0

    @classmethod
    def lockout_threshold(cls): return 4
    @classmethod
    def lockout_window(cls): return 28800

    @classmethod
    def available(cls): return True

    @classmethod
    def create(cls, name, pin):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        if name not in cls.keys:
            raise FileNotFoundError(name)
        k, right = cls.keys[name]
        if pin != right:
            raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name): cls.keys.pop(name, None)


pinslot.tpm_windows = FakeTpm
pinslot.best_kind = lambda: "chip"

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()

OPENED = []
def browse(url):
    OPENED.append(url)
    def go():
        try:
            requests.get(url, timeout=10, **oidc._DIRECT)
        except requests.RequestException:
            pass
    threading.Thread(target=go, daemon=True).start()

def nowhere(url):                     # a browser that never comes back
    OPENED.append(url)

SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": ISS, "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["acme.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
P.id_claims = {"preferred_username": "sam@acme.com"}
PW, PIN = "correct horse battery 42", "246813"

datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([SSO])
session.sign_out()

def no_wait():
    d = json.loads(datakey.path().read_text(encoding="utf-8")); d["throttle"] = {"fails": 0, "until": 0}
    datakey.path().write_text(json.dumps(d), encoding="utf-8")


# ---------------------------------------------------------------- the window
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget
app = QApplication([])
from ui import signinwindow
from ui.signinwindow import SignInWindow

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def words_on(page):
    return [lab.text() for lab in page.findChildren(QLabel) if lab.text()] + [b.text() for b in page.findChildren(QPushButton)]

def start(login="sam@acme.com", browser=browse):
    webbrowser.open = browser
    OPENED.clear()
    w = SignInWindow(); w.show()
    w.name.setText(login); w.next.click()
    return w

print("== the browser page")
check("approved wording", signinwindow.SSO_TITLE == "Continue in your browser"
      and signinwindow.SSO_TEXT == "Sign in on the {provider} page that opened in your browser. Toner carries on when you're done."
      and signinwindow.SSO_AGAIN == "Open the page again"
      and S.SSO_CANCELLED == "The sign-in didn't finish in the browser."
      and S.SSO_NOT_FRESH == "{provider} didn't confirm a fresh sign-in. Try again."
      and S.SSO_BAD_ANSWER == "{provider}'s answer couldn't be checked, so the sign-in was refused."
      and S.SSO_UNREACHABLE == "{provider} can't be reached, and this account hasn't been checked online in the last hour.")
w = start(browser=nowhere)
check("typing sam@acme.com shows the browser page, not the password", w.pages.currentWidget() is w.sso_page)
check("...with the approved title and text, Open the page again and Cancel", words_on(w.sso_page) == [
      "Toner", "Continue in your browser",
      "Sign in on the Contoso page that opened in your browser. Toner carries on when you're done.", "Cancel",
      "Open the page again"], words_on(w.sso_page))
pump(lambda: OPENED)
check("...the provider's page opened in the browser", len(OPENED) == 1 and OPENED[0].startswith(ISS + "/authorize?"))
w.sso_again.click()
check("Open the page again opens the same page", len(OPENED) == 2 and OPENED[1] == OPENED[0])
started = time.time()
w.sso_cancel.click()
pump(lambda: w.pages.currentWidget() is w.name_page)
check("Cancel: back to the name, with SSO_CANCELLED, within a second", w.pages.currentWidget() is w.name_page
      and w.name_error.text() == S.SSO_CANCELLED and w.name.text() == "sam@acme.com" and time.time() - started < 2,
      (w.name_error.text(), time.time() - started))
check("...and nothing left running", pump(lambda: not w._jobs))
w.reject()
no_wait()

print("== refusals say the approved sentences, never the provider's details")
for name, setup, text in [
        ("NotFresh", lambda: P.id_claims.update(auth_time=int(time.time()) - 3600), S.SSO_NOT_FRESH.format(provider="Contoso")),
        ("Refused", lambda: setattr(P, "mode", "denied"), S.SSO_BAD_ANSWER.format(provider="Contoso")),
        ("BadAnswer", lambda: setattr(P, "mode", "bad_state"), S.SSO_BAD_ANSWER.format(provider="Contoso")),
        ("Unreachable, never checked here", lambda: setattr(P, "force", 503), S.SSO_UNREACHABLE.format(provider="Contoso"))]:
    setup()
    w = start()
    pump(lambda: w.pages.currentWidget() is w.name_page and w.name_error.text())
    check(name, w.name_error.text() == text, w.name_error.text())
    w.reject()
    P.mode, P.force = "ok", None
    P.id_claims = {"preferred_username": "sam@acme.com"}
    no_wait()

print("== a finished browser sign-in")
w = start()
pump(lambda: w.pages.currentWidget() is w.choose_page)
check("a completed browser flow lands on Choose a PIN", w.pages.currentWidget() is w.choose_page)
w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click()
pump(lambda: w.pages.currentWidget() is w.approve_page)
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click()
pump(lambda: w.pages.currentWidget() is w.pin_page)
w.pin.setText(PIN); w.pin_ok.click()
pump(lambda: session.state() == "open")
check("...then approval and the PIN open the session", session.state() == "open" and session.user() == "sam@acme.com")

print("== the lock screen once the session is over")
from ui.lockscreen import LockScreen


class FakeMain(QWidget):
    signed_out = 0
    def sign_out(self): self.signed_out += 1


def shown(lock):
    return sorted(x.text() for x in lock.findChildren(QWidget) if isinstance(x, (QLabel, QPushButton)) and x is not lock.avatar
                  and x.isVisibleTo(lock) and x.text())

main = FakeMain(); main.resize(600, 400); main.show()
lock = LockScreen(main)
session._full_at = time.time() - 13 * 3600
session.lock(); app.processEvents()
P.force = 503
lock.pw.setText(PIN); lock.unlock.click()
pump(lambda: session.state() == "open")
check("session over, the provider down: the PIN unlocks", session.state() == "open")
P.force = None
session.lock(); app.processEvents()
lock.pw.setText(PIN); lock.unlock.click()
pump(lambda: lock.again.isVisibleTo(lock))
check("session over, the provider reachable: a full sign-in", shown(lock) == sorted(["Please sign in again.", "Sign in"])
      and session.state() == "locked", shown(lock))
lock.again.click()
check("...Sign in signs out, so the next sign-in goes through the browser page", main.signed_out == 1)
session.sign_out(); app.processEvents()

print("== Forgot your PIN? that ends in Cancel doesn't carry over")
no_wait()
w = start()
pump(lambda: w.pages.currentWidget() is w.pin_page)
webbrowser.open = nowhere
w.forgot.click()
check("Forgot your PIN? goes through the browser again", w.pages.currentWidget() is w.sso_page)
w.sso_cancel.click()
pump(lambda: w.pages.currentWidget() is w.name_page and w.name_error.text())
check("...Cancel: back to the name with SSO_CANCELLED", w.name_error.text() == S.SSO_CANCELLED)
webbrowser.open = browse
w.next.click()
pump(lambda: w.pages.currentWidget() in (w.pin_page, w.choose_page))
check("...the next sign-in lands on the PIN, not Choose a PIN", w.pages.currentWidget() is w.pin_page)
w.reject()

P.stop()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
