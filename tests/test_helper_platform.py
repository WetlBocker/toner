# Run directly (python tests/test_helper_platform.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched. Nothing is installed: the
# install steps are only planned, and the refusals are checked with the steps replaced.
# The helper's channel on this platform (core/helper/windows.py or linux.py): the caller's identity from the OS, the keys file
# read with the caller's rights, messages over 64 KiB or not JSON closing the connection, errors answered without logging the
# request, Cancel on disconnect, and the install plan (service command line, systemd unit, admin-only folders).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hplat%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, ctypes, logging, pathlib, pickle, subprocess, threading, uuid
from multiprocessing import connection
from core import datakey, db, osstore, roles, session
from core.helper import linux, protocol, server, store

NT = os.name == "nt"
if NT:
    from core.helper import windows
    plat = windows
else:
    plat = linux

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return False


# ---------------------------------------------------------------- fakes and a keys file made the usual way
PEPPERS, PINS = {}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)

LOG = []
class Keep(logging.Handler):
    def emit(self, record): LOG.append(self.format(record))
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.DEBUG)

PW = "correct horse battery 42"
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
DATA_KEY = datakey._key
RULES = roles._held["rules"]
RULES = RULES if isinstance(RULES, bytes) else RULES.private_bytes_raw()
session.sign_out()
KEYS = str(datakey.path())
b64 = lambda b: base64.b64encode(b).decode()
xor = lambda b: bytes(x ^ 0x5A for x in b)
HDIR = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_helper_"))
ST = store.Store(HDIR / "helper.json", xor, xor)
HELPER = server.Helper(ST)

if NT:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    ME = out.strip().split(",")[-1].strip('"')
    ADDR = r"\\.\pipe\TonerHelperTest-" + uuid.uuid4().hex
else:
    ME = str(os.getuid())
    ADDR = str(HDIR / "helper.sock")

SEEN = []                                               # what the test hook saw inside the read
if NT:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentThread.restype = ctypes.c_void_p
    adv.OpenThreadToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    def thread_user():
        """The user of this thread's impersonation token, or None when it has none (it runs as the process)."""
        tok = ctypes.c_void_p()
        if not adv.OpenThreadToken(k32.GetCurrentThread(), 0x8, True, ctypes.byref(tok)):     # TOKEN_QUERY, as self
            return None
        try:
            return windows._token_sid(tok)
        finally:
            k32.CloseHandle(tok)
    windows._on_read = lambda: SEEN.append(thread_user())
else:
    libc = ctypes.CDLL(None)
    def fs_ids():
        return libc.setfsuid(ctypes.c_uint(0xFFFFFFFF)), libc.setfsgid(ctypes.c_uint(0xFFFFFFFF))
    linux._on_read = lambda: SEEN.append(fs_ids())

def err(ans):
    return ans.get("error") if not ans.get("ok") else None

def client():
    for _ in range(100):
        try:
            return connection.Client(ADDR)
        except OSError:
            time.sleep(0.05)
    return connection.Client(ADDR)

def ask(c, op, **fields):
    req = {"op": op, "v": protocol.PROTOCOL, "keys_path": KEYS, **fields}
    c.send_bytes(protocol.encode(req))
    return protocol.decode(c.recv_bytes(protocol.MAX))

def closed(c):
    """True when the server has closed the connection."""
    try:
        return c.poll(3) and raises(lambda: c.recv_bytes(), (EOFError, OSError))
    except (EOFError, OSError):
        return True


# ---------------------------------------------------------------- the channel
check("ADDRESS: the pipe or socket the plan names", windows.ADDRESS == r"\\.\pipe\TonerHelper" if NT
      else linux.ADDRESS == "/run/toner-helper/helper.sock")
check("STORE_PATH: in the admin-only data folder", str(windows.STORE_PATH) == os.path.join(os.environ["ProgramData"], "Toner Helper",
      "helper.json") if NT else str(linux.STORE_PATH) == "/var/lib/toner-helper/helper.json")
STOP = threading.Event()
SERVE = threading.Thread(target=plat.serve, args=(HELPER, STOP), kwargs={"address": ADDR}, daemon=True)
SERVE.start()
c = client()
a = ask(c, "status")
check("status over the channel: ok, not enrolled", a.get("ok") and a["enrolled"] is False and a["protocol"] == 1, a)
if NT:
    check("a second helper can't take the pipe name while it is served", raises(
        lambda: windows.serve(server.Helper(ST), threading.Event(), address=ADDR), OSError))
else:
    check("the socket is 0666 (who connects is checked by SO_PEERCRED)", (os.stat(ADDR).st_mode & 0o777) == 0o666)

a = ask(c, "enroll", data_key=b64(DATA_KEY), rules_private=b64(RULES))
check("enroll over the channel, from a keys file the client can read: ok", a == {"ok": True}, a)
rec = ST.load()
check("...the owner is the client's identity from the OS (SID from whoami, or the uid)", rec and rec["owner"] == ME,
      (rec and rec["owner"], ME))
if NT:
    check("...the keys file was read impersonating the client (a thread token for the client's SID)", SEEN and set(SEEN) == {ME}, SEEN)
else:
    check("...the keys file was read with the client's fsuid and fsgid", SEEN and set(SEEN) == {(os.getuid(), os.getgid())}, SEEN)
SEEN.clear()
a = ask(c, "status")
check("status on the same connection: the owner", a.get("owner") is True and a["rules_changed"] is False, a)
check("...the rules were read with the client's rights again", len(SEEN) == 1)
c.close()

c = client()
try:
    c.send_bytes(b"x" * 70000)
    gone = closed(c)
except OSError:                                         # closed while it was still being written
    gone = True
check("a 70,000-byte message closes the connection", gone)
c = client()
check("...and the helper keeps serving", ask(c, "status").get("ok") is True)
c.close()

c = client()
c.send_bytes(pickle.dumps({"op": "status", "v": 1, "keys_path": KEYS}))
check("a pickled object: bad_request", protocol.decode(c.recv_bytes(protocol.MAX)) == {"ok": False, "error": "bad_request"})
check("...and the connection closes", closed(c))
c = client()
c.send_bytes(b"[1]")
check("a JSON list: bad_request, then closed", protocol.decode(c.recv_bytes()) == {"ok": False, "error": "bad_request"} and closed(c))

SECRET = "pw-never-in-the-log-7x"
real = HELPER.handle
def boom(req, peer, cancel=None, read=None):
    raise OSError("disk full " + SECRET)
HELPER.handle = boom
LOG.clear()
c = client()
a = ask(c, "check_directory", connection="d1", login="bob", password=SECRET)
check("handle raising: bad_request, and the helper keeps serving", a == {"ok": False, "error": "bad_request"}
      and ask(c, "status") == {"ok": False, "error": "bad_request"})
check("...the log names the op and the error type only", any("check_directory" in m and "OSError" in m for m in LOG)
      and not any(SECRET in m or "disk full" in m for m in LOG), LOG)
c.close()

CANCELS = []
def slow(req, peer, cancel=None, read=None):
    CANCELS.append(cancel)
    cancel.wait(5)
    return {"ok": False, "error": "refused"}
HELPER.handle = slow
c = client()
c.send_bytes(protocol.encode({"op": "duo_push", "v": 1, "pending": "p"}))
for _ in range(50):
    if CANCELS: break
    time.sleep(0.05)
t0 = time.time()
c.close()
for _ in range(60):
    if CANCELS and CANCELS[0].is_set(): break
    time.sleep(0.05)
check("the client going while its request runs sets cancel (stops a Duo push)", CANCELS and CANCELS[0].is_set()
      and time.time() - t0 < 2, CANCELS)
HELPER.handle = real

STOP.set()
SERVE.join(5)
check("stop: serve returns", not SERVE.is_alive())
check("...and the channel is gone", raises(lambda: connection.Client(ADDR), OSError) if NT else not os.path.exists(ADDR))


# ---------------------------------------------------------------- the reader, on its own
if NT:
    L = windows._Pipes(ADDR)
    def talk():
        c = connection.Client(ADDR); c.send_bytes(b"hi"); c.recv_bytes(); c.close()
    th = threading.Thread(target=talk, daemon=True); th.start()
    conn = L.accept()
    conn.recv_bytes()
    SEEN.clear()
    data = windows._reader(conn.fileno())(KEYS)
    check("reader: the keys file's bytes, read as the client", data == pathlib.Path(KEYS).read_bytes() and SEEN == [ME], SEEN)
    check("...and this thread is back to itself afterwards (no thread token)", thread_user() is None)
    SEEN.clear()
    check("reader: a missing file is OSError, and the thread is back to itself",
          raises(lambda: windows._reader(conn.fileno())(KEYS + ".missing"), OSError) and SEEN == [ME] and thread_user() is None)
    SEEN.clear()
    check("reader: no impersonation (a bad handle) reads nothing as SYSTEM: OSError, the hook never ran",
          raises(lambda: windows._reader(0)(KEYS), OSError) and SEEN == [] and thread_user() is None)
    conn.send_bytes(b"bye"); th.join(5); conn.close(); L.close()
else:
    SEEN.clear()
    data = linux._reader(os.getuid(), os.getgid())(KEYS)
    check("reader: the keys file's bytes, read with the caller's fsuid/fsgid", data == pathlib.Path(KEYS).read_bytes()
          and SEEN == [(os.getuid(), os.getgid())], SEEN)
    check("...and the fsuid/fsgid are back to the process's afterwards", fs_ids() == (os.geteuid(), os.getegid()))
    if os.geteuid() == 0:
        os.chmod(HDIR, 0o711)
        ROOTS = HDIR / "root-only.keys"
        ROOTS.write_bytes(b"{}"); os.chmod(ROOTS, 0o640)    # group root too: serve dropped root's supplementary groups
        check("reader (root): a root-only file can't be read as uid 65534", raises(lambda: linux._reader(65534, 65534)(str(ROOTS)), OSError)
              and fs_ids() == (0, 0) and os.getgroups() == [])
        OPEN = HDIR / "open.keys"
        OPEN.write_bytes(b"{}"); os.chmod(OPEN, 0o644)
        MAIN = threading.main_thread().native_id
        def main_fsuid():
            line = next(l for l in open(f"/proc/self/task/{MAIN}/status") if l.startswith("Uid:"))
            return int(line.split()[4])
        box = []
        linux._on_read = lambda: box.append((fs_ids(), main_fsuid()))
        th = threading.Thread(target=lambda: box.append(linux._reader(65534, 65534)(str(OPEN)))); th.start(); th.join(5)
        check("reader (root): setfsuid is per thread (the reader is 65534, the main thread still root)",
              box == [((65534, 65534), 0), b"{}"], box)
        linux._on_read = lambda: SEEN.append(fs_ids())
    else:
        print("  skip  reader as another uid (needs root)")


# ---------------------------------------------------------------- install: the plan and the refusals (nothing is run)
if NT:
    PF = os.path.join(os.environ["ProgramFiles"], "Toner Helper")
    PD = os.path.join(os.environ["ProgramData"], "Toner Helper")
    plan = windows.install_plan(pathlib.Path(r"C:\x\TonerHelper"))
    create = ["sc.exe", "create", "TonerHelper", "binPath=", f'"{PF}\\TonerHelper.exe" --service', "start=", "auto",
              "obj=", "LocalSystem", "DisplayName=", "Toner helper"]
    acl = ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]
    want = [["sc.exe", "stop", "TonerHelper"], ["sc.exe", "delete", "TonerHelper"], ["copy", r"C:\x\TonerHelper", PF],
            ["mkdir", PD], ["icacls", PF, *acl], ["icacls", PD, *acl], create,
            ["sc.exe", "failure", "TonerHelper", "reset=", "86400", "actions=", "restart/5000"], ["sc.exe", "start", "TonerHelper"]]
    check("install_plan: stop and delete, copy, admin-only folders, sc create, failure, start", plan == want, plan)
    check("...the service runs %ProgramFiles%\\Toner Helper\\TonerHelper.exe, quoted",
          create[4].startswith('"' + os.environ["ProgramFiles"] + "\\"))
    r = []
    try:
        windows.run_service()
    except OSError as e:
        r.append(e.winerror)
    check("run_service outside the SCM: OSError 1063 (not started as a service)", r == [1063], r)
check("the unit: root, its state folder 0700, the program in /opt/toner-helper",
      "\nUser=root\n" in linux.UNIT and "\nStateDirectoryMode=0700\n" in linux.UNIT and "\nRuntimeDirectory=toner-helper\n" in linux.UNIT
      and "\nRuntimeDirectoryMode=0755\n" in linux.UNIT and "\nStateDirectory=toner-helper\n" in linux.UNIT
      and "\nExecStart=/opt/toner-helper/toner-helper --service\n" in linux.UNIT, linux.UNIT)
check("...the service path starts with /opt/toner-helper/", linux.UNIT.split("ExecStart=")[1].startswith("/opt/toner-helper/"))
if not NT:
    lplan = linux.install_plan(pathlib.Path("/x/toner-helper"))
    check("linux install_plan: stop, copy to /opt/toner-helper, the unit, reload, enable --now",
          lplan == [["systemctl", "stop", "toner-helper"], ["copy", "/x/toner-helper", "/opt/toner-helper"],
                    ["write", "/etc/systemd/system/toner-helper.service", linux.UNIT], ["systemctl", "daemon-reload"],
                    ["systemctl", "enable", "--now", "toner-helper"]], lplan)

RAN = []
plat._step = RAN.append
SRC = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_src_"))
plat._elevated = lambda: False
check("install: refused when not elevated, nothing run", raises(lambda: plat.install(SRC), PermissionError) and RAN == [])
plat._elevated = lambda: True
keep = plat.PROGRAM_DIR, plat.DATA_DIR
plat.PROGRAM_DIR = pathlib.Path.home() / "Toner Helper"
check("install: refused for a program folder in the user's profile, nothing run", raises(lambda: plat.install(SRC), ValueError) and RAN == [])
plat.PROGRAM_DIR, plat.DATA_DIR = keep[0], pathlib.Path.home() / "AppData" / "Toner Helper"
check("install: refused for a data folder in the user's profile, nothing run", raises(lambda: plat.install(SRC), ValueError) and RAN == [])
plat.DATA_DIR = keep[1]
check("install: refused from inside the program folder itself", raises(lambda: plat.install(keep[0] / "x"), ValueError) and RAN == [])
plat.install(SRC)
check("install (elevated, mocked): runs the plan in order", RAN == plat.install_plan(SRC.resolve()), RAN)
RAN.clear()
plat._elevated = lambda: False
check("uninstall: refused when not elevated, nothing run", raises(plat.uninstall, PermissionError) and RAN == [])

print(f"\n{ok} passed, {bad} failed")
