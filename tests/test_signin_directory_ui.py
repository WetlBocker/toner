# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The sign-in window for directory accounts, on ldap3's MOCK_SYNC, a fake local Duo and a fake security chip: each page's
# approved words and the order of pages for a first and a second sign-in, offline, Duo (cancel, a code, deny, unreachable),
# no group, access changed, Forgot your PIN?, another computer, an Engineer approving, the recovery key, paused, the PIN wait
# and Not you? from every page.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dirsigninui%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import http.server, json, threading, urllib.parse, uuid
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import datakey, db, directory, dirpin, duo, osstore, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def undone(box):
    """What undo brings back into a box (Password mode hides undo, so it is read as a show-password switch would)."""
    mode = box.echoMode(); box.setEchoMode(box.EchoMode.Normal); box.undo(); text = box.text(); box.setEchoMode(mode)
    return text


# ---------------------------------------------------------------- fakes (as tests/test_dirsignin.py)
SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
PEPPERS = {"duo:d1": SKEY.encode()}
PINS = {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)
DIRS = _box(dirpin.pins_file())


class FakeTpm:
    LockedOut = tpm_windows.LockedOut
    keys = {}
    locked = 0

    @classmethod
    def lockout_threshold(cls): return 4
    @classmethod
    def lockout_window(cls): return 28800

    @classmethod
    def available(cls): return True

    @classmethod
    def create(cls, name, pin):
        if cls.locked:
            raise tpm_windows.LockedOut(cls.locked)
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        if cls.locked:
            raise tpm_windows.LockedOut(cls.locked)
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

DUO = {"preauth": "auth", "push": "allow", "code": "135790", "down": False}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_(self):
        n = int(self.headers.get("Content-Length") or 0)
        p = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        if DUO["down"]:
            self.send_response(503); self.send_header("Content-Length", "0"); self.end_headers(); return
        path = urllib.parse.urlsplit(self.path).path
        if path.endswith("preauth"): r = {"result": DUO["preauth"]}
        elif path.endswith("/auth") and p.get("factor") == "passcode": r = {"result": "allow" if p["passcode"] == DUO["code"] else "deny"}
        elif path.endswith("/auth"): r = {"txid": "t"}
        else: r = {"result": DUO["push"], "status": "x"}
        b = json.dumps({"stat": "OK", "response": r}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_POST = do_GET = handle_
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
duo._TEST_ALLOW_HTTP = True

BASE = "DC=acme,DC=com"
ADMINS, ENGINEERS, TECHS = "CN=Toner Admins," + BASE, "CN=Toner Engineers," + BASE, "CN=Toner Techs," + BASE
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
PEOPLE = (("Bob", "bob", [TECHS]), ("Carol", "carol", [TECHS]), ("Erin", "erin", [TECHS]), ("Dave", "dave", []))
for cn, sam, groups in PEOPLE:
    c.strategy.add_entry(f"CN={cn},OU=Users,{BASE}", {
        "objectClass": "user", "userPrincipalName": f"{sam}@acme.com", "sAMAccountName": sam, "cn": cn,
        "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": f"pw-{sam}", "memberOf": groups})
for dn, cn in ((ADMINS, "Toner Admins"), (ENGINEERS, "Toner Engineers"), (TECHS, "Toner Techs")):
    c.strategy.add_entry(dn, {"objectClass": "group", "cn": cn})
for cn, sam, _g in PEOPLE:
    ldap.dit[f"{sam}@acme.com"] = ldap.dit[f"ACME\\{sam}"] = ldap.dit[f"CN={cn},OU=Users,{BASE}"]   # AD binds by UPN or DOMAIN\user
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
UP = lambda cfg, host, *_: ldap
def DOWN(cfg, host, *_): raise OSError("no route")
directory._make_server = UP

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS], "Tech": [TECHS]},
        "duo": {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}}
PW, PW2 = "correct horse battery 42", "engineers have long passwords 7"
PIN, PIN2, PIN3 = "246813", "975318", "802461"

recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")
roles.set_directories([ACME])
session.sign_out()

def no_wait():
    d = json.loads(datakey.path().read_text(encoding="utf-8")); d["throttle"] = {"fails": 0, "until": 0}
    datakey.path().write_text(json.dumps(d), encoding="utf-8")


# ---------------------------------------------------------------- the window
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton
app = QApplication([])
from ui.signinwindow import SignInWindow
Accepted = SignInWindow.DialogCode.Accepted

def pump(w, until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def settle(w):
    return pump(w, lambda: not w._jobs)

NAMES = {}
def open_window():
    w = SignInWindow(); w.show()
    for attr in ("name_page", "password_page", "duo_page", "code_page", "pin_page", "choose_page", "approve_page",
                 "approve_key_page"):
        NAMES[getattr(w, attr)] = attr.replace("_page", "")
    w.seen = ["name"]
    w.pages.currentChanged.connect(lambda i: w.seen.append(NAMES.get(w.pages.widget(i))))
    return w

def at(w):
    return NAMES.get(w.pages.currentWidget())

def words_on(page):
    return [lab.text() for lab in page.findChildren(QLabel) if lab.text()] + [b.text() for b in page.findChildren(QPushButton)]

def not_you(page):
    return next(b for b in page.findChildren(QPushButton) if b.text() == "Not you?")

def start(login, password, push="allow"):
    """Name, then password: settles on the page after Duo (or the Duo page while the push waits)."""
    DUO["push"] = push
    w = open_window()
    w.name.setText(login); w.next.click()
    w.pw.setText(password); w.sign_in.click()
    if push == "waiting":
        pump(w, lambda: at(w) == "duo")
    else:
        settle(w)
    return w

def secrets_left(w, *secrets):
    return [b.text() for b in w.findChildren(QLineEdit) if b.text() and b.text() in secrets]


print("== a first sign-in: password, Duo push, choose a PIN, approval, PIN")
w = start("bob@acme.com", "pw-bob", push="waiting")
check("Next with a directory name asks for the password, under the name", w.seen[:2] == ["name", "password"]
      and w.who.text() == "bob@acme.com", w.seen)
check("the Duo push page's approved words", at(w) == "duo" and words_on(w.duo_page)[1:] == [
    "Approve on your phone", "Duo sent a request to your phone. Approve it to finish signing in.", "Cancel",
    "Enter a code instead", "Not you?"], words_on(w.duo_page))
check("...the password step ran off the window's thread, and the push is still waiting there", w.attempt is not None
      and w.attempt.stage == "duo" and len(w._jobs) == 1)
DUO["push"] = "allow"
pump(w, lambda: at(w) == "choose")
check("an approved push: Choose a PIN, in the approved words", at(w) == "choose" and words_on(w.choose_page)[1:] == [
    "Choose a PIN", "You'll use this PIN to unlock Toner on this computer.", "PIN", "Confirm PIN", "Next", "Not you?"],
    words_on(w.choose_page))
for pin, again, said in (("12345", "12345", "Use 6 digits."), ("123456", "123456", "Avoid simple PINs like 123456."),
                         (PIN, PIN2, "The two PINs don't match.")):
    w.pin1.setText(pin); w.pin2.setText(again); w.choose_ok.click(); settle(w)
    check(f"a PIN that won't do: {said}", at(w) == "choose" and w.choose_error.text() == said
          and w.pin1.text() == w.pin2.text() == "", w.choose_error.text())
w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
check("then the approval page, with the first-sign-in text", at(w) == "approve" and words_on(w.approve_page)[1:] == [
    "An admin needs to approve this",
    "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it.",
    "Admin username", "Password", "Approve", "Not you?", "Approve with a directory account", "Use the recovery key"],
    words_on(w.approve_page))
w.admin.setText("Eng1"); w.admin_pw.setText(PW2); w.approve_ok.click(); settle(w)
check("an Engineer can't approve", at(w) == "approve" and w.approve_error.text() == "That account can't approve sign-ins."
      and w.admin_pw.text() == "", w.approve_error.text())
w.admin.setText("Admin1"); w.admin_pw.setText("not it at all"); w.approve_ok.click(); settle(w)
check("a wrong admin password", at(w) == "approve" and w.approve_error.text() == "That username or password isn't right.",
      w.approve_error.text())
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
check("approved: the PIN page, in the approved words", at(w) == "pin" and words_on(w.pin_page)[1:] == [
    "bob@acme.com", "PIN", "Sign in", "Not you?", "Forgot your PIN?"] and session.state() == "signed_out",
    words_on(w.pin_page))
w.pin.setText("975310"); w.pin_ok.click(); settle(w)
check("a wrong PIN", at(w) == "pin" and w.pin_error.text() == "That PIN isn't right." and w.pin.text() == "", w.pin_error.text())
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
check("the PIN signs in and the window accepts", w.result() == Accepted and session.user() == "bob@acme.com"
      and session.kind() == "directory")
check("the pages, in order", w.seen == ["name", "password", "duo", "choose", "approve", "pin"], w.seen)
check("no password, PIN or code left in any box", secrets_left(w, "pw-bob", PIN, PIN2, PW, PW2, "not it at all") == [])
check("...nor in any box's undo history", [undone(b) for b in (w.pw, w.pin, w.pin1, w.pin2, w.admin_pw)] == [""] * 5)
session.sign_out()

print("== a second sign-in: password, push, PIN")
w = start("ACME\\bob", "pw-bob")
check("straight to the PIN after Duo", at(w) == "pin" and w.seen == ["name", "password", "duo", "pin"], w.seen)
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
check("...and signs in", w.result() == Accepted and session.user() == "bob@acme.com")
session.sign_out()

print("== Duo: Cancel, Enter a code instead, the code page")
w = start("bob@acme.com", "pw-bob", push="waiting")
cancel = w._cancel
w.duo_cancel.click()
check("Cancel stops the push and goes back to the password", at(w) == "password" and cancel.is_set() and w.attempt is None)
settle(w)
check("...and the push ending later doesn't move the window", at(w) == "password" and w.error.text() == "")
w.pw.setText("pw-bob"); w.sign_in.click(); pump(w, lambda: at(w) == "duo")
cancel = w._cancel
w.use_code.click()
check("Enter a code instead stops the push: the code page, in the approved words", at(w) == "code" and cancel.is_set()
      and words_on(w.code_page)[1:] == ["bob@acme.com", "Duo code", "Sign in", "Not you?"], words_on(w.code_page))
settle(w)
check("...the cancelled push doesn't move it either", at(w) == "code" and w.attempt.stage == "duo")
w.code.setText("000000"); w.code_ok.click(); settle(w)
check("a wrong code", at(w) == "code" and w.code_error.text() == "That code isn't right." and w.code.text() == "", w.code_error.text())
w.code.setText(DUO["code"]); w.code_ok.click(); settle(w)
check("the right code: the PIN", at(w) == "pin")
check("...and undo can't bring the Duo code back", undone(w.code) == "")
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
check("...and signs in", w.result() == Accepted and session.user() == "bob@acme.com")
session.sign_out()

print("== Duo denies, Duo or the directory can't be reached, no group, a wrong password")
w = start("bob@acme.com", "pw-bob", push="deny")
check("a denied push: back to the password, with the approved sentence", at(w) == "password"
      and w.error.text() == "Duo didn't approve the sign-in." and w.attempt is None, w.error.text())
DUO["down"] = True
w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
DUO["down"] = False
check("Duo unreachable", at(w) == "password"
      and w.error.text() == "Toner can't reach Duo, so you can't sign in right now. Try again in a minute.", w.error.text())
directory._make_server = DOWN
datakey.set_online("bob@acme.com", time.time() - 3700)
w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
directory._make_server = UP
check("the directory unreachable past the offline hour", at(w) == "password"
      and w.error.text() == "Toner can't reach the directory. Connect to the network, then try again.", w.error.text())
w.not_you.click()
w.name.setText("dave@acme.com"); w.next.click(); w.pw.setText("pw-dave"); w.sign_in.click(); settle(w)
check("not in a Toner group", at(w) == "password" and w.error.text() == "Your account isn't in a Toner group. Ask an admin.",
      w.error.text())
w.pw.setText("nope"); w.sign_in.click(); settle(w)
check("a wrong directory password", at(w) == "password" and w.error.text() == "That username or password isn't right.")
no_wait()

print("== offline within the hour: the PIN alone")
directory._make_server = DOWN
datakey.set_online("bob@acme.com", time.time() - 50 * 60)
w = start("bob@acme.com", "anything")
check("offline: password, then the PIN", at(w) == "pin" and w.seen == ["name", "password", "pin"] and w.attempt.offline, w.seen)
w.forgot.click()
check("Forgot your PIN? offline: the directory can't be reached", at(w) == "pin"
      and w.pin_error.text() == "Toner can't reach the directory. Connect to the network, then try again.", w.pin_error.text())
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
directory._make_server = UP
check("...the PIN signs in", w.result() == Accepted and session.user() == "bob@acme.com")
session.sign_out()

print("== access changed: approval before the PIN opens")
ldap.dit["bob@acme.com"]["memberOf"] = [ENGINEERS.encode()]
w = start("bob@acme.com", "pw-bob")
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
check("the approval page with the access-changed text", at(w) == "approve"
      and w.approve_text.text() == "Your access changed. Ask an admin to sign in here to approve it.", w.approve_text.text())
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
check("approved: the PIN again", at(w) == "pin" and w.pin.text() == "")
w.pin.setText(PIN); w.pin_ok.click(); settle(w)
check("...opens as an Engineer", w.result() == Accepted and roles.role_of("bob@acme.com") == "Engineer")
check("the pages, in order", w.seen == ["name", "password", "duo", "pin", "approve", "pin"], w.seen)
session.sign_out()

print("== Forgot your PIN?: the password and Duo again, a new PIN, approval")
w = start("bob@acme.com", "pw-bob")
w.forgot.click()
check("Forgot your PIN? goes back to the password", at(w) == "password" and w.who.text() == "bob@acme.com" and w.attempt is None)
w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
check("...then Duo and Choose a PIN", at(w) == "choose" and w.seen[-3:] == ["password", "duo", "choose"], w.seen)
w.pin1.setText(PIN2); w.pin2.setText(PIN2); w.choose_ok.click(); settle(w)
check("...then approval, access changed", at(w) == "approve"
      and w.approve_text.text() == "Your access changed. Ask an admin to sign in here to approve it.")
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
w.pin.setText(PIN2); w.pin_ok.click(); settle(w)
check("...and the new PIN signs in", w.result() == Accepted and session.user() == "bob@acme.com")
session.sign_out()

print("== Forgot your PIN? when a key hint skipped Duo: Duo first, then Choose a PIN")
d = json.loads(datakey.path().read_text(encoding="utf-8")); d["accounts"]["bob@acme.com"]["keys_n"] = 1      # (a forged hint)
datakey.path().write_text(json.dumps(d), encoding="utf-8")
w = start("bob@acme.com", "pw-bob")
check("(the hint skips Duo: the PIN page)", at(w) == "pin" and w.seen == ["name", "password", "pin"], w.seen)
w.forgot.click()
w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
check("...Forgot your PIN? then asks Duo before Choose a PIN", at(w) == "choose" and w.seen[-3:] == ["password", "duo", "choose"], w.seen)
w.reject()
w = start("bob@acme.com", "pw-bob")
w.forgot.click()
DUO["preauth"] = "deny"
w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
check("...Duo refusing it: today's words on the password page", at(w) == "password" and w.error.text() == "Duo didn't approve the sign-in.",
      (at(w), w.error.text()))
DUO["preauth"] = "auth"
w.reject()
d = json.loads(datakey.path().read_text(encoding="utf-8")); d["accounts"]["bob@acme.com"].pop("keys_n")
datakey.path().write_text(json.dumps(d), encoding="utf-8")

print("== another computer: the chip has no key")
FakeTpm.keys.clear()
w = start("bob@acme.com", "pw-bob")
w.pin.setText(PIN2); w.pin_ok.click(); settle(w)
check("the PIN with no key here: Choose a PIN", at(w) == "choose")
w.pin1.setText(PIN3); w.pin2.setText(PIN3); w.choose_ok.click(); settle(w)
check("...approval, access changed", at(w) == "approve"
      and w.approve_text.text() == "Your access changed. Ask an admin to sign in here to approve it.")
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
w.pin.setText(PIN3); w.pin_ok.click(); settle(w)
check("...and the new PIN signs in", w.result() == Accepted and session.user() == "bob@acme.com")
check("the pages, in order", w.seen == ["name", "password", "duo", "pin", "choose", "approve", "pin"], w.seen)
session.sign_out()

print("== the recovery key approves; a lost box key asks for the PIN again")
w = start("carol@acme.com", "pw-carol")
w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
datakey._started.clear()                              # Toner restarted since the PIN was chosen
w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
check("the started key gone: Choose a PIN again", at(w) == "choose" and w.pin1.text() == "")
w.pin1.setText(PIN2); w.pin2.setText(PIN2); w.choose_ok.click(); settle(w)
w.approve_recovery.click()
check("Use the recovery key: its page", at(w) == "approve_key" and words_on(w.approve_key_page)[1:] == [
    "An admin needs to approve this", "Enter the recovery key you saved when Toner was set up.", "Recovery key", "Approve",
    "Not you?"], words_on(w.approve_key_page))
w.approve_key.setText("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"); w.approve_key_ok.click(); settle(w)
check("a wrong recovery key", at(w) == "approve_key" and w.approve_key_error.text() == "That recovery key isn't right."
      and w.approve_key.text() == "", w.approve_key_error.text())
w.approve_key.setText(recovery); w.approve_key_ok.click(); settle(w)
check("the recovery key approves: the PIN", at(w) == "pin")
w.pin.setText(PIN2); w.pin_ok.click(); settle(w)
check("...and signs in", w.result() == Accepted and session.user() == "carol@acme.com")
check("no key left in any box", secrets_left(w, recovery, PIN, PIN2, PW) == [])
session.sign_out()
no_wait()

print("== too many wrong PINs: the wait")
FakeTpm.locked = 28800                                 # the chip's own lockout (controller's Ruling 7: shown as given)
w = start("bob@acme.com", "pw-bob")
w.pin.setText(PIN3); w.pin_ok.click(); settle(w)
check("the approved sentence, and Sign in off", w.pin_error.text() == "Too many wrong PINs. Wait 28800 seconds, then try again."
      and not w.pin_ok.isEnabled(), w.pin_error.text())
w.pin_wait.timer.timeout.emit()
check("...counting down", w.pin_error.text() == "Too many wrong PINs. Wait 28799 seconds, then try again.", w.pin_error.text())
FakeTpm.locked = 0
w.pin_wait.left = 1; w.pin_wait.timer.timeout.emit()
check("...and Sign in comes back when it ends", w.pin_ok.isEnabled() and w.pin_error.text() == "")
w.pin.setText(PIN3); w.pin_ok.click(); settle(w)
check("...then the PIN signs in", w.result() == Accepted)
session.sign_out()

print("== the chip can't be used: Choose a PIN asks for 8 characters")
import pathlib
CHIPFAILS = pathlib.Path(os.environ["APPDATA"], "Toner", "chipfails.json")
CHIPFAILS.parent.mkdir(parents=True, exist_ok=True)
for locked, record, pin in ((0, [time.time()] * 3, "a long store pin 1"), (1234, [], "a long store pin 2")):
    CHIPFAILS.write_text(json.dumps(record), "utf-8")   # one more wrong PIN could lock it / Windows refuses a new chip key
    FakeTpm.locked = locked
    w = start("bob@acme.com", "pw-bob")
    w.forgot.click(); w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
    w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
    check(f"chip {'locked' if locked else 'at risk'}: a 6-digit PIN gets the 8-character rule", at(w) == "choose"
          and w.choose_error.text() == "Use at least 8 characters.", w.choose_error.text())
    w.pin1.setText(pin); w.pin2.setText(pin); w.choose_ok.click(); settle(w)
    check("...a longer one goes to approval", at(w) == "approve", at(w))
    w.admin.setText("Admin1"); w.admin_pw.setText(PW); w.approve_ok.click(); settle(w)
    w.pin.setText(pin); w.pin_ok.click(); settle(w)
    check("...and signs in with the protected store", w.result() == Accepted
          and datakey.directory_account("bob@acme.com")["slot_kind"] == "store")
    session.sign_out()
FakeTpm.locked = 0
CHIPFAILS.unlink()

print("== paused")
remembered = DIRS[dirpin.store_name()]
DIRS[dirpin.store_name()] = b"a list remembered before"
w = open_window()
w.name.setText("bob@acme.com"); w.next.click()
check("a changed directories list: the paused sentence on the name page", at(w) == "name"
      and w.name_error.text() == "Directory sign-in is paused on this computer. An admin needs to sign in first.", w.name_error.text())
w.name.setText("Admin1"); w.next.click(); w.pw.setText(PW); w.sign_in.click(); settle(w)
check("...a local name still signs in, as today", w.result() == Accepted and session.user() == "Admin1")
session.sign_out()
DIRS[dirpin.store_name()] = remembered

print("== Choose a PIN: the name belongs to another account")
real_start = datakey.start_directory_account
def taken(*a, **k): raise datakey.NameTaken("That username is already taken.")
datakey.start_directory_account = taken
ldap.dit["dave@acme.com"]["memberOf"] = [TECHS.encode()]
w = start("dave@acme.com", "pw-dave")
w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
check("the name text on Choose a PIN, not 'That username is already taken.'", at(w) == "choose"
      and w.choose_error.text() == "That name already belongs to another account on this copy. Ask an admin.", w.choose_error.text())
datakey.start_directory_account = real_start
w.reject()
ldap.dit["dave@acme.com"]["memberOf"] = []

print("== the CA file changed since the directory was saved")
import hashlib
ca = os.path.join(SP, "ui-ca.pem")
with open(ca, "w") as f: f.write("one CA")
session.sign_in("Admin1", PW); roles.set_directories([{**ACME, "ca_file": ca}], edited="d1"); session.sign_out()
with open(ca, "w") as f: f.write("another CA")
w = open_window()
w.name.setText("bob@acme.com"); w.next.click(); w.pw.setText("pw-bob"); w.sign_in.click(); settle(w)
check("the password page says the CA file changed", at(w) == "password"
      and w.error.text() == "The directory's CA file changed. An admin needs to save the directory again.", w.error.text())
w.reject()
session.sign_in("Admin1", PW); roles.set_directories([ACME], edited="d1"); session.sign_out()
no_wait()

print("== Not you? from every page")
def back(w, page, *boxes):
    cancel = w._cancel
    not_you(page).click()
    return (at(w) == "name" and w.attempt is None and (cancel is None or cancel.is_set())
            and all(b.text() == "" for b in boxes))
w = start("bob@acme.com", "pw-bob", push="waiting")
check("from the Duo page: the push stops", back(w, w.duo_page))
settle(w)
check("...and stays on the name page when the push ends", at(w) == "name")
w.next.click(); w.pw.setText("half")
check("from the password page", back(w, w.password_page, w.pw))
w = start("bob@acme.com", "pw-bob", push="waiting"); w.use_code.click(); w.code.setText("12")
check("from the code page", back(w, w.code_page, w.code))
settle(w)
w = start("bob@acme.com", "pw-bob"); w.pin.setText("12")
check("from the PIN page", back(w, w.pin_page, w.pin))
w = start("erin@acme.com", "pw-erin"); w.pin1.setText("12"); w.pin2.setText("12")
check("from Choose a PIN", at(w) == "choose" and back(w, w.choose_page, w.pin1, w.pin2))
w = start("erin@acme.com", "pw-erin"); w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
w.admin.setText("Admin1"); w.admin_pw.setText("half")
check("from the approval page", at(w) == "approve" and back(w, w.approve_page, w.admin_pw))
w = start("erin@acme.com", "pw-erin"); w.pin1.setText(PIN); w.pin2.setText(PIN); w.choose_ok.click(); settle(w)
w.approve_recovery.click(); w.approve_key.setText("half")
check("from the recovery key's approval page", at(w) == "approve_key" and back(w, w.approve_key_page, w.approve_key))
w.name.setText("erin@acme.com"); w.next.click(); w.pw.setText("pw-erin"); w.sign_in.click(); settle(w)
check("...and a new attempt starts from the password", at(w) == "choose")
w.reject()
check("closing the window waits for nothing left running", not w._jobs and session.state() == "signed_out")

srv.shutdown(); srv.server_close()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
