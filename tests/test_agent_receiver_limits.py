# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched. The receiver listens on 127.0.0.1.
# The agent receiver: a revoked computer can't be signed up again with the sign-up key, a report's text fields are text (in what
# is stored and in what the Agents list is handed), and a caller that never finishes a request can't hold a thread for good or
# take more than a fixed number of them (core/agents.py _enroll, overview, _Server, _Handler; core/winmon.py parse_report).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time, json, socket, ssl, threading, urllib.request, urllib.error
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "agentlimits%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import agents, db

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

db.init()
agents._announce_new = lambda name, source, org=None: None
agents.REQUEST_SECONDS = 2                                  # the total time one request may take (30 s when not under test)
agents._slots = threading.BoundedSemaphore(4)               # connections served at once (64 when not under test)
db.set_setting("agent_enabled", True); db.set_setting("agent_port", 0); db.set_setting("agent_bind", "127.0.0.1")
agents.apply()
port = agents.status()["port"]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def call(path, body, token=None):
    h = {"Authorization": "Bearer " + token} if token else {}
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def ping():
    try:
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="x")
        s.sendall(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        line = s.recv(200).split(b"\r\n")[0].decode(); s.close()
        return line
    except OSError as e:
        return type(e).__name__

def held():
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="x")
    s.sendall(b"POST /report HTTP/1.1\r\nX-A: ")              # a request that never finishes its headers
    return s

def is_open(s):
    try:
        s.settimeout(0.3); s.sendall(b"a")                  # keeps the per-read timeout from ever running out
        return s.recv(1) != b""
    except (TimeoutError, ssl.SSLWantReadError):
        return True
    except OSError:
        return False

# ---------------------------------------------------------------- a revoked computer stays closed to the sign-up key
db.set_setting("agent_enroll", True)
key = agents.enroll_key()
code, a = call("/enroll", {"computer": "PC-ONE", "key": key}); token = a.get("token")
check("a new computer signs up and reports", code == 200 and call("/report", {"computer": "PC-ONE", "os": "Windows 11"}, token)[0] == 200)
agents.revoke("PC-ONE")
code, a = call("/enroll", {"computer": "pc-one", "key": key})
check("after Revoke the sign-up key can't claim that computer again", code == 409 and not a.get("token"), (code, a))
db.save_device(dict(name="PC-HAND", vendor="windows", host="10.0.0.9", port=0, platform="agent", username="", site="default", verify_ssl=0,
                    ha_expected=0, enabled=1, location="", details="", folder_id=None, tags=""))
check("a computer added by hand, never given a token, is still claimed", call("/enroll", {"computer": "PC-HAND", "key": key})[0] == 200)

# ---------------------------------------------------------------- a report's text fields are text
code, a = call("/enroll", {"computer": "PC-TWO", "key": key}); token = a.get("token")
check("a report with a number for the computer name is refused", call("/report", {"computer": 1, "os": "x"}, token)[0] == 400)
check("so is one with a list for the system", call("/report", {"computer": "PC-TWO", "os": ["a"]}, token)[0] == 400)
agents.store("PC-TWO", {"computer": 7, "os": 8, "domain": 9, "joined": True}, "127.0.0.1", "")     # one stored by an older Toner
row = next(r for r in agents.overview() if r["device"] == "PC-TWO")
check("the Agents list is always handed text", all(isinstance(row[k], str) for k in ("computer", "os", "domain")), row)

# ---------------------------------------------------------------- a finished connection is closed at once
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="x")
s.sendall(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
s.settimeout(3); got, ended = b"", False
try:
    while True:
        block = s.recv(4096)
        if not block:
            ended = True
            break
        got += block
except OSError:
    pass
s.close()
check("when a request is over the receiver closes the connection itself (an agent's next report must not wait on a dead one)",
      ended and got.startswith(b"HTTP/1.1 200"), (ended, got[:40]))

# ---------------------------------------------------------------- one request has a total time, and connections a cap
conns = [held() for _ in range(4)]
time.sleep(0.5)
check("with every slot held, one more caller is turned away without a new thread", not ping().startswith("HTTP/1.1 200"), ping())
deadline = time.time() + 6
while time.time() < deadline and any(is_open(s) for s in conns):
    time.sleep(0.3)
check("a request that never finishes is cut after the total time, however often it sends a byte", not any(is_open(s) for s in conns))
time.sleep(0.5)
check("and its slot is free again", ping().startswith("HTTP/1.1 200"), ping())
for s in conns:
    s.close()
agents.stop()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
