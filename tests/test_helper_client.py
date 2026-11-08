# Run directly (python tests/test_helper_client.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched. Nothing is installed.
# Toner's client for the helper service (core/helperclient.py), against an in-process core.helper.server.Helper: the switch's
# eight states, enroll and forget, sign-in without approval turned off when the rules key is replaced, the Duo keys following
# Set up 2FA; then over a real local pipe/socket: a server that isn't the helper's own (LocalSystem/root) gets nothing.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hclient%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, json, pathlib, subprocess, threading, uuid
from core import audit, datakey, db, envelope, helperclient, osstore, roles, session, updates
from core.helper import protocol, server, store

NT = os.name == "nt"
if NT:
    from core.helper import windows as plat
else:
    from core.helper import linux as plat

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None


# ---------------------------------------------------------------- fakes: the protected store, and the helper in this process
SKEY, SKEY2 = b"Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep", b"Qq1eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Zz"
PEPPERS, PINS = {"duo:d1": SKEY}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)

b64 = lambda b: base64.b64encode(b).decode()
xor = lambda b: bytes(x ^ 0x5A for x in b)
HDIR = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_helper_"))
HSTORE = store.Store(HDIR / "helper.json", xor, xor)
HELPER = server.Helper(HSTORE)
PEER, SENT, UP, INSTALLED = ["me"], [], [True], [True]
ANSWER = [lambda req, peer: HELPER.handle(req, peer)]


class FakeConn:
    """What _connect hands back: the in-process helper, as the transport would call it (peer from 'the OS': PEER)."""
    ans = None
    def send_bytes(self, b):
        req = protocol.decode(b)
        SENT.append(req)
        self.ans = protocol.encode(ANSWER[0](req, PEER[0]))
    def poll(self, timeout): return self.ans is not None
    def recv_bytes(self, n): return self.ans
    def close(self): pass

def fake_connect():
    if not UP[0]:
        raise helperclient.NotRunning()
    return FakeConn()

REAL_CONNECT = helperclient._connect
REAL_INSTALLED = helperclient.installed
helperclient._connect = fake_connect
helperclient.installed = lambda: INSTALLED[0]

BASE = "DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Tech": ["CN=Toner Techs," + BASE]}, "duo": {"on": True, "host": "api-x.duosecurity.com", "ikey": "IK"}}
PW = "correct horse battery 42"
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME])
KEYS = datakey.path()
doc = lambda: json.loads(KEYS.read_text(encoding="utf-8"))
acts = lambda: [(r["action"], r["detail"]) for r in audit.recent()]
SECRETS = lambda: [b64(datakey._key), b64(roles._held["rules"]), b64(SKEY), b64(SKEY2)]

print("== ADDRESS")
check("the pipe or socket the helper serves on (Task 9's)", helperclient.ADDRESS == plat.ADDRESS
      and helperclient.ADDRESS == (r"\\.\pipe\TonerHelper" if NT else "/run/toner-helper/helper.sock"))

print("== state(): the eight cases")
real_kind = updates.installed_kind
updates.installed_kind = lambda: "portable"
check("portable: a portable copy, whatever the helper says", helperclient.state(KEYS) == "portable")
updates.installed_kind = lambda: "installed"
UP[0], INSTALLED[0] = False, False
check("absent: nothing answers and nothing is installed", helperclient.state(KEYS) == "absent")
INSTALLED[0] = True
check("not_running: installed, nothing answers", helperclient.state(KEYS) == "not_running")
UP[0] = True
check("off: running, not enrolled", helperclient.state(KEYS) == "off")
SENT.clear()
helperclient.enroll()
check("on: enrolled by this copy", helperclient.state(KEYS) == "on")
PEER[0] = "someone-else"
check("other_user: enrolled by another user", helperclient.state(KEYS) == "other_user")
PEER[0] = "me"
check("...and the same user with another copy's keys file sees other_user too", helperclient.state(KEYS.with_name("other.keys")) == "other_user")
ANSWER[0] = lambda req, peer: {**HELPER.handle(req, peer), "protocol": 2}
check("outdated: a helper on another protocol", helperclient.state(KEYS) == "outdated")
ANSWER[0] = lambda req, peer: HELPER.handle(req, peer)

print("== enroll")
e = next(r for r in SENT if r["op"] == "enroll")
check("enroll sends this copy's keys file, the data key and the rules key", e["keys_path"] == str(KEYS) and e["data_key"] == b64(datakey._key)
      and e["rules_private"] == b64(roles._held["rules"]) and e["v"] == protocol.PROTOCOL, {k: v for k, v in e.items() if k not in ("data_key", "rules_private", "duo")})
check("...and the Duo secret key of each directory with Duo on", e["duo"] == {"d1": b64(SKEY)}, list(e["duo"]))
rec = HSTORE.load()
check("the helper pinned this copy's rules key", rec["rules_pub"] == b64(roles._public("rules", roles._held["rules"]))
      and rec["spare"] == datakey._key + roles._held["rules"])
check("no key in the audit", not any(s in str(acts()) for s in SECRETS()))

print("== forget")
helperclient.forget()
check("forget clears the helper's spare copy", HSTORE.load() is None and helperclient.state(KEYS) == "off")
check("forget with nothing enrolled is nothing to do", raises(helperclient.forget, Exception) is None)

print("== call: cancel, and the timeout")
class Silent(FakeConn):
    """A helper that never answers (a Duo push still waiting at the phone)."""
    closed = False
    def send_bytes(self, b): pass
    def poll(self, timeout): time.sleep(timeout); return False
    def close(self): Silent.closed = True
helperclient._connect = lambda: Silent()
cancel = threading.Event()
threading.Timer(0.3, cancel.set).start()
t0 = time.monotonic()
e = raises(lambda: helperclient.call({"op": "duo_push", "pending": "p"}, timeout=60, cancel=cancel), helperclient.NotRunning)
check("cancel set while waiting: NotRunning within half a second, the connection closed (the helper stops the push)",
      e is not None and time.monotonic() - t0 < 1.3 and Silent.closed, time.monotonic() - t0)
t0 = time.monotonic()
e = raises(lambda: helperclient.call({"op": "status", "keys_path": ""}, timeout=1), helperclient.NotRunning)
check("no answer within the timeout: NotRunning", e is not None and 0.9 <= time.monotonic() - t0 < 2, time.monotonic() - t0)
helperclient._connect = fake_connect

print("== a keys file signed before the count: signed once, then enrolled")
d = doc(); d.pop("rules_version")
payload = roles._signed(d); d["rules_sig"] = envelope.sign(roles._held["rules"], payload)
KEYS.write_text(json.dumps(d), encoding="utf-8"); db.set_setting("rules_signed", payload.decode("utf-8")); roles._invalidate()
check("(the file has no rules_version, and the rules check out)", "rules_version" not in doc() and roles.state() == "ok")
helperclient.enroll()
check("enroll signed it first (rules_version 1) and the helper took it", doc().get("rules_version") == 1 and helperclient.state(KEYS) == "on")

print("== Set up 2FA saves through set_directories: the helper gets the new Duo key")
PEPPERS["duo:d1"] = SKEY2
roles.set_directories(roles.verified()["directories"])
check("re-enrolled with the Duo key as it is now", HSTORE.load()["duo"] == {"d1": SKEY2}, list(HSTORE.load()["duo"]))
check("...and still on", helperclient.state(KEYS) == "on")

print("== rules_changed: an older signed file put back")
old = KEYS.read_bytes()
roles.set_permissions("Tech", {"push": not roles.permissions("Tech")["push"]})
check("(a newer signing, still on)", helperclient.state(KEYS) == "on")
new = KEYS.read_bytes()
KEYS.write_bytes(old); roles._invalidate()
db.set_setting("helper_off_notice", False)
n = len(acts())
check("rules_changed: the helper refuses the older rules", helperclient.state(KEYS) == "rules_changed")
check("...and Toner forgets the spare copy", HSTORE.load() is None and helperclient.state(KEYS) == "off")
check("...audited", ("sign-in without approval turned off", "the rules key was replaced") in acts()[:len(acts()) - n], acts()[:3])
check("...with the note for the Accounts page", db.get_setting("helper_off_notice") is True)
KEYS.write_bytes(new); roles._invalidate()

print("== the rules key replaced (the recovery key's repair) while on: turned off")
helperclient.enroll()
db.set_setting("helper_off_notice", False)
check("(on)", helperclient.state(KEYS) == "on")
d = doc(); d["roles"]["Tech"]["push"] = not d["roles"]["Tech"].get("push", False)
KEYS.write_text(json.dumps(d), encoding="utf-8"); roles._invalidate()
session.sign_out()
session.sign_in_recovery(recovery)
check("(tampered, signed in with the recovery key)", roles.state() == "tampered")
old_key = db.get_setting("rules_key")
n = len(acts())
roles.set_permissions("Tech", {})
check("(the repair made a new rules key)", db.get_setting("rules_key") not in (old_key, "") and roles.state() == "ok")
check("the helper's spare copy is gone", HSTORE.load() is None)
check("...audited: turned off, the rules key was replaced", ("sign-in without approval turned off", "the rules key was replaced") in acts()[:len(acts()) - n], acts()[:3])
check("...the Accounts page's note is set", db.get_setting("helper_off_notice") is True)
check("...and the helper refuses nothing it shouldn't: it is just off", helperclient.state(KEYS) == "off")
session.sign_out()
session.sign_in("Admin1", PW)

print("== a helper that can't be reached changes nothing of a change")
UP[0] = False
roles.set_directories(roles.verified()["directories"])
check("set_directories still lands", roles.state() == "ok")
UP[0] = True
updates.installed_kind = real_kind

print("== install_elevated")
real_elevate = helperclient._elevate
helperclient._elevate = lambda t: 0
check("installs, then waits for the helper to answer", raises(helperclient.install_elevated, Exception) is None)
helperclient._elevate = lambda t: 3
e = raises(helperclient.install_elevated, helperclient.InstallFailed)
check("a failed install: InstallFailed with its exit code", e is not None and e.reason == helperclient.EXITED.format(code=3), e and e.reason)
def cancelled(t): raise OSError(1223, "The operation was canceled by the user.")
helperclient._elevate = cancelled
e = raises(helperclient.install_elevated, helperclient.InstallFailed)
check("the prompt cancelled: InstallFailed with the system's reason", e is not None and e.reason == "The operation was canceled by the user.")
def slow(t): raise subprocess.TimeoutExpired("x", t)
helperclient._elevate = slow
e = raises(helperclient.install_elevated, helperclient.InstallFailed)
check("no answer to the prompt in time: InstallFailed", e is not None and e.reason == helperclient.TOO_LONG)
helperclient._elevate = lambda t: 0
UP[0] = False
clock = [0.0]
real_time = helperclient.time
class FakeTime:
    @staticmethod
    def monotonic(): return clock[0]
    @staticmethod
    def sleep(s): clock[0] += s
helperclient.time = FakeTime
e = raises(helperclient.install_elevated, helperclient.InstallFailed)
check("installed but never answering within 15 s: InstallFailed", e is not None and e.reason == helperclient.NO_ANSWER and 15 <= clock[0] <= 16, clock)
helperclient.time = real_time
UP[0] = True
helperclient._elevate = real_elevate
if not NT:
    app = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_appdir_"))
    (app / "usr" / "lib" / "toner-helper").mkdir(parents=True)
    (app / "usr" / "lib" / "toner-helper" / "toner-helper").write_text("#!/bin/sh\n")
    os.environ["APPDIR"] = str(app)
    ran = []
    real_run = helperclient.subprocess.run
    def fake_run(cmd, **kw):
        p = pathlib.Path(cmd[1])
        ran.append((cmd, p.exists(), oct(os.stat(p.parent.parent).st_mode & 0o777), p.parent.parent))
        return subprocess.CompletedProcess(cmd, 0)
    helperclient.subprocess.run = fake_run
    check("Linux: pkexec runs the helper copied out of the AppImage", helperclient._elevate(5) == 0 and ran and ran[0][0][0] == "pkexec"
          and ran[0][0][2:] == ["--install"] and ran[0][1] and not ran[0][0][1].startswith(str(app)), ran)
    check("...from a fresh folder only this user can open", ran and ran[0][2] == "0o700", ran)
    check("...deleted afterwards", ran and not ran[0][3].exists(), ran)
    helperclient.subprocess.run = real_run

print("== over a real pipe/socket: only the helper's own process is spoken to")
helperclient._connect = REAL_CONNECT
if NT:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    ME = out.strip().split(",")[-1].strip('"')
    ADDR = r"\\.\pipe\TonerHelperTest-" + uuid.uuid4().hex
else:
    ME = os.getuid()
    ADDR = str(HDIR / "helper.sock")
seen = []
class Counting(server.Helper):
    def handle(self, req, peer, cancel=None, read=None):
        seen.append(req.get("op"))
        return super().handle(req, peer, cancel, read)
STOP = threading.Event()
threading.Thread(target=plat.serve, args=(Counting(HSTORE), STOP), kwargs={"address": ADDR}, daemon=True).start()
helperclient.ADDRESS = ADDR
for _ in range(100):
    try:
        from multiprocessing import connection
        connection.Client(ADDR).close()
        break
    except OSError:
        time.sleep(0.05)
if ME not in (0, "S-1-5-18"):
    check("a server running as this user (not LocalSystem/root) is refused: NotRunning", raises(
        lambda: helperclient.call({"op": "status", "keys_path": str(KEYS)}), helperclient.NotRunning) is not None)
    time.sleep(0.3)
    check("...and it was sent nothing", seen == [], seen)
helperclient._TRUSTED.add(ME)
a = raises(lambda: helperclient.call({"op": "status", "keys_path": str(KEYS)}), Exception) or helperclient.call({"op": "status", "keys_path": str(KEYS)})
check("with this user allowed (tests only), the same server answers", isinstance(a, dict) and a.get("ok") and a.get("protocol") == 1, a)
helperclient._TRUSTED.discard(ME)
if NT:
    real_pid = helperclient._service_pid
    helperclient._service_pid = lambda: os.getpid()
    a = helperclient.call({"op": "status", "keys_path": str(KEYS)})
    check("Windows: the TonerHelper service's own process (as the service manager names it) is spoken to", a.get("ok"), a)
    helperclient._service_pid = lambda: os.getpid() + 4
    check("...another process is not", raises(lambda: helperclient.call({"op": "status", "keys_path": ""}), helperclient.NotRunning) is not None)
    helperclient._service_pid = real_pid
    check("the real service lookup: no TonerHelper service here, so no process", real_pid() == 0 or REAL_INSTALLED())
STOP.set()
helperclient.ADDRESS = r"\\.\pipe\TonerHelperNone-" + uuid.uuid4().hex if NT else str(HDIR / "none.sock")
check("nothing listening: NotRunning", raises(lambda: helperclient.call({"op": "status", "keys_path": ""}), helperclient.NotRunning) is not None)
check("no key in the audit, at the end", not any(s in str(acts()) for s in SECRETS()))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
