# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The lock screen for directory accounts: the PIN, a wrong PIN, the wait, a refused account, the 12-hour workday (the directory
# probed off the UI thread; reachable: "Please sign in again.", unreachable: the PIN unlocks) and directory.reachable (never binds).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\lockdir%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import threading, uuid
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import datakey, db, directory, dirpin, osstore, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


# ---------------------------------------------------------------- fakes (as tests/test_dirsignin.py)
PEPPERS, PINS = {}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)


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

BASE = "DC=acme,DC=com"
TECHS = "CN=Toner Techs," + BASE
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
c.strategy.add_entry(f"CN=Bob,OU=Users,{BASE}", {
    "objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
    "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-bob", "memberOf": [TECHS]})
c.strategy.add_entry(TECHS, {"objectClass": "group", "cn": "Toner Techs"})
ldap.dit["bob@acme.com"] = ldap.dit[f"CN=Bob,OU=Users,{BASE}"]
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
UP = lambda cfg, host, *_: ldap
def DOWN(cfg, host, *_): raise OSError("no route")
directory._make_server = UP

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [], "Engineer": [], "Tech": [TECHS]}}
PW, PIN = "correct horse battery 42", "246813"

datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME])
session.sign_out()

a = S.begin("bob@acme.com", "pw-bob"); S.after_password(a); S.choose_pin(a, PIN); S.approve(a, "Admin1", PW); S.finish(a, PIN)
session.sign_out()


def sign_in_bob():
    a = S.begin("bob@acme.com", "pw-bob")
    if a.stage == "password": S.after_password(a)     # (offline, it is at the PIN already)
    S.finish(a, PIN)


# ---------------------------------------------------------------- the lock screen
from PySide6.QtWidgets import QApplication, QWidget, QPushButton
app = QApplication([])
from ui.lockscreen import LockScreen


class FakeMain(QWidget):
    signed_out = 0
    def sign_out(self): self.signed_out += 1


def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def shown(lock):
    """Every text the lock shows: its labels and buttons that are visible."""
    from PySide6.QtWidgets import QLabel
    return sorted(w.text() for w in lock.findChildren(QWidget) if isinstance(w, (QLabel, QPushButton)) and w is not lock.avatar
                  and w.isVisibleTo(lock) and w.text())

main = FakeMain(); main.resize(600, 400); main.show()
lock = LockScreen(main)

print("== reachable: opens the connection, never binds")
binds = []
real_bind = ldap3.Connection.bind
ldap3.Connection.bind = lambda self, *a, **k: binds.append(1) or real_bind(self, *a, **k)
check("a server that answers", directory.reachable(ACME) is True and binds == [])
directory._make_server = DOWN
check("no server answers: False, nothing bound", directory.reachable(ACME) is False and binds == [])
directory._make_server = UP
check("a config with no TLS is False", directory.reachable({**ACME, "security": "none"}) is False)
check("the second server answers when the first doesn't", directory.reachable({**ACME, "servers": ["x", "y"]}) is True)
tried = []
def FIRST_DOWN(cfg, host, *_):
    tried.append(host)
    if host == "x": raise OSError("no route")
    return ldap
directory._make_server = FIRST_DOWN
check("...trying them in order", directory.reachable({**ACME, "servers": ["x", "y"]}) is True and tried == ["x", "y"], tried)
directory._make_server = UP
check("connect still binds", directory.connect(ACME, "bob@acme.com", "pw-bob").bound and binds == [1], binds)
ldap3.Connection.bind = real_bind
made, RealConnection = [], ldap3.Connection
class Spy(RealConnection):
    def __init__(self, *a, **k): made.append(k); super().__init__(*a, **k)
    ok_tls = True
    def start_tls(self, *a, **k): started.append(1); self.tls_started = self.ok_tls; return self.ok_tls     # (the mock has no TLS)
started = []
ldap3.Connection = Spy
ldap3.Connection.bind = lambda self, *a, **k: binds.append(1) or real_bind(self, *a, **k)
binds.clear()
check("LDAPS: the connection gets no user and no password", directory.reachable(ACME) is True and binds == []
      and not made[-1].get("user") and not made[-1].get("password"), made)
tls = {**ACME, "security": "starttls", "port": 389}
check("StartTLS: it starts TLS, never binds, and sends no credential", directory.reachable(tls) is True and started and binds == []
      and not made[-1].get("user") and not made[-1].get("password"), (started, binds, made[-1]))
Spy.ok_tls = False
check("StartTLS that fails: not reachable", directory.reachable(tls) is False and binds == [])
ldap3.Connection = RealConnection
ldap3.Connection.bind = real_bind

print("== a directory user's lock screen")
sign_in_bob()
session.lock(); app.processEvents()
check("it shows the field PIN", lock.locked and lock.pw.placeholderText() == "PIN" and lock.pw.accessibleName() == "PIN"
      and lock.pw.isVisibleTo(lock))
check("...and the same buttons as ever", shown(lock) == sorted(["Toner is locked", "Locked by bob@acme.com.", "bob@acme.com",
                                                                  "Unlock", "Sign in as someone else"]), shown(lock))
lock.pw.setText("975310"); lock.unlock.click(); app.processEvents()
check("a wrong PIN says so and empties the field", lock.error.text() == pinslot.WRONG and lock.pw.text() == ""
      and session.state() == "locked", lock.error.text())
FakeTpm.locked = 28800
lock.pw.setText(PIN); lock.unlock.click(); app.processEvents()
check("a wait is worded as the PIN's wait, and Unlock is off", lock.error.text() == str(pinslot.PinLocked(28800))
      and not lock.unlock.isEnabled(), lock.error.text())
FakeTpm.locked = 0
lock.wait.timer.stop(); lock.unlock.setEnabled(True)
lock.pw.setText(PIN); lock.unlock.click(); app.processEvents()
check("the right PIN unlocks, the field is empty", session.state() == "open" and lock.pw.text() == "" and not lock.locked)

print("== a refused account")
session.lock(reason="refused"); app.processEvents()
check("only the sentence and Sign in as someone else show", shown(lock) == sorted(["Your account can't sign in to Toner any more. Ask an admin.",
                                                                                     "Sign in as someone else"]), shown(lock))
check("...no PIN field, no password field", not lock.pw.isVisibleTo(lock) and not lock.unlock.isVisibleTo(lock))
lock.other.click()
check("...and the button goes to the full sign-in", main.signed_out == 1)
session.sign_out(); app.processEvents()

print("== a directory user who is refused while the lock is already up")
sign_in_bob(); session.lock(); app.processEvents()
check("first the usual PIN screen", lock.pw.isVisibleTo(lock))
session.lock(reason="refused"); app.processEvents()
check("...then only the refusal", shown(lock) == sorted(["Your account can't sign in to Toner any more. Ask an admin.",
                                                          "Sign in as someone else"]), shown(lock))
session.sign_out(); app.processEvents()

print("== the workday is over")
calls, threads, spy = [], [], []
real_unlock_pin = session.unlock_pin
session.unlock_pin = lambda pin: spy.append(pin) or real_unlock_pin(pin)
def probe(up):
    def fn(cfg):
        threads.append(threading.current_thread()); calls.append(cfg["id"])
        return up
    return fn
real_reachable = directory.reachable

sign_in_bob(); session._full_at = time.time() - 13 * 3600
session.lock(); app.processEvents()
directory.reachable = probe(True)
lock.pw.setText(PIN); lock.unlock.click()
check("the field and Unlock are off while the directory is probed", not lock.pw.isEnabled() and not lock.unlock.isEnabled())
pump(lambda: calls and lock.again.isVisibleTo(lock))
check("the probe ran for the account's directory, off the UI thread", calls == ["d1"] and threads[0] is not threading.main_thread()
      and threads[0] is not threading.current_thread(), (calls, threads))
check("reachable: the PIN was not tried, so nothing is counted", spy == [] and session.state() == "locked")
check("...the screen says Please sign in again. with a Sign in button", shown(lock) == sorted(["Please sign in again.", "Sign in"]), shown(lock))
check("...and the PIN is gone from the field", lock.pw.text() == "" and lock.pw.isEnabled())
lock.again.click()
check("Sign in goes the way Sign in as someone else does", main.signed_out == 2)
session.sign_out(); app.processEvents()

sign_in_bob(); session._full_at = time.time() - 13 * 3600
session.lock(); app.processEvents()
check("a new lock starts from the PIN screen again", lock.pw.isVisibleTo(lock) and not lock.again.isVisibleTo(lock))
calls.clear(); threads.clear()
directory.reachable = probe(False)
lock.pw.setText("975310"); lock.unlock.click(); pump(lambda: spy)
check("unreachable: the PIN is tried (a wrong one is counted and said)", spy == ["975310"] and lock.error.text() == pinslot.WRONG
      and lock.pw.isEnabled() and lock.unlock.isEnabled() and lock.pw.text() == "", (spy, lock.error.text()))
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: session.state() == "open")
check("...and the right PIN unlocks", session.state() == "open" and not lock.locked and calls == ["d1", "d1"])
session.lock(); app.processEvents()
directory._make_server = DOWN
directory.reachable = real_reachable
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: session.state() == "open")
check("with the real probe and no server answering, the PIN unlocks", session.state() == "open")
session.lock(); app.processEvents()
directory._make_server = UP
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: lock.again.isVisibleTo(lock))
check("with the real probe and a server answering: Please sign in again.", shown(lock) == sorted(["Please sign in again.", "Sign in"]))
session.sign_out(); app.processEvents()

print("== within the workday there is no probe")
sign_in_bob(); calls.clear(); spy.clear()
directory.reachable = probe(True)
session.lock(); app.processEvents()
lock.pw.setText(PIN); lock.unlock.click(); app.processEvents()
check("the PIN is tried at once", spy == [PIN] and calls == [] and session.state() == "open")
session.sign_out(); app.processEvents()
directory.reachable = real_reachable
session.unlock_pin = real_unlock_pin

print("== the probe and what happens meanwhile")
def slow(up=True):
    gate = threading.Event()
    directory.reachable = lambda cfg: gate.wait(20) and up
    return gate
def relock():
    session.sign_out(); app.processEvents(); sign_in_bob(); session._full_at = time.time() - 13 * 3600
    session.lock(); app.processEvents()

relock(); gate = slow()
lock.pw.setText(PIN); lock.unlock.click()
check("Sign in as someone else is off while the probe runs, with the field and Unlock",
      not lock.other.isEnabled() and not lock.pw.isEnabled() and not lock.unlock.isEnabled())
before = main.signed_out
threading.Timer(0.3, gate.set).start()
lock._sign_out()
check("leaving waits for the probe to end first", not lock._jobs or all(j.isFinished() for j in lock._jobs) and main.signed_out == before + 1)
pump(lambda: not lock._jobs)

relock(); gate = slow(); spy.clear()
lock.pw.setText(PIN); lock.unlock.click()
session.lock(reason="refused"); app.processEvents()
gate.set(); pump(lambda: not lock._jobs)
check("refused during a probe stays refused, and the PIN isn't tried", shown(lock) == sorted([session.REFUSED, "Sign in as someone else"])
      and spy == [] and session.state() == "locked", shown(lock))

relock(); gate = slow(); spy.clear()
lock.pw.setText(PIN); lock.unlock.click()
session.sign_out(); app.processEvents(); sign_in_bob(); session._full_at = time.time() - 13 * 3600; session.lock(); app.processEvents()
gate.set(); pump(lambda: not lock._jobs)
check("a probe's answer after a new lock is ignored", lock.pw.isVisibleTo(lock) and not lock.again.isVisibleTo(lock) and spy == []
      and lock.pw.isEnabled() and lock.other.isEnabled() and session.state() == "locked", shown(lock))

relock(); directory.reachable = real_reachable; session._full_at = time.time()      # (inside the workday: no probe)
FakeTpm.locked = 30
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: lock.wait.timer.isActive())
check("a PIN wait is running", lock.wait.timer.isActive() and "30 seconds" in lock.error.text(), lock.error.text())
FakeTpm.locked = 0
session.lock(reason="refused"); app.processEvents()
check("the countdown stops on the refused screen", not lock.wait.timer.isActive() and lock.error.text() == "")

directory._make_server = DOWN
real_changed = dirpin.changed
relock(); dirpin.changed = lambda dirs: True
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: lock.again.isVisibleTo(lock))
check("a changed directories list counts as reachable: Please sign in again.", shown(lock) == sorted(["Please sign in again.", "Sign in"]), shown(lock))
dirpin.changed = real_changed
relock(); real_account = datakey.directory_account
datakey.directory_account = lambda name: {**real_account(name), "directory": "gone"}
lock.pw.setText(PIN); lock.unlock.click(); pump(lambda: lock.again.isVisibleTo(lock))
check("so does a directory config that can't be found", shown(lock) == sorted(["Please sign in again.", "Sign in"]), shown(lock))
datakey.directory_account = real_account
directory._make_server = UP
session.sign_out(); app.processEvents()

print("== a local account's lock screen is as it was")
datakey.close()
session.sign_in("Admin1", PW)
session.lock(); app.processEvents()
check("Password, not PIN", lock.pw.placeholderText() == "Password" and lock.pw.accessibleName() == "Password"
      and shown(lock) == sorted(["Toner is locked", "Locked by Admin1.", "Admin1, local account", "Unlock", "Sign in as someone else"]), shown(lock))
lock.pw.setText(PW); lock.unlock.click(); app.processEvents()
check("...and the password unlocks", session.state() == "open")
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
