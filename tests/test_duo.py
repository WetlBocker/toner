# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Duo Auth API client against a fake local Duo (signature vector from Duo docs) and the OS protected store.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hard%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication
import base64, json, threading, http.server, urllib.parse
from core import duo, osstore, passvault
ok = bad = 0
def check(name, cond):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL", name)

SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
body = '{"device":"auto","factor":"push","hostname":"wks01","ipaddr":"10.2.3.4","username":"narroway"}'
sig = duo.sign(SKEY, "Tue, 21 Aug 2012 17:29:18 -0000", "POST", "api-xxxxxxxx.duosecurity.com", "/auth/v2/auth", "", body)
want = "RElXSjhYNkFFWU9SNU9NQzZUUTE6NWI3NTg5MzA4Y2JiYWE5MzYwOWM1ZGQ5MTljYmY2ZDI0ZjlkYTkxNTQ2YzgxY2ZkYmQ1OTI2MjNmYzM2ZTU1Y2QzYmQ0NzBiYWQyMzBhYzQ1YTA2ODZkYWVlMGU1YmE4YjViZGVlM2ZmMzI1ODUwNWQyZDBlYTI3YzAxNGRlYTM="
check("docs v5 vector", base64.b64encode(f"DIWJ8X6AEYOR5OMC6TQ1:{sig}".encode()).decode() == want)
check("http off by default", duo._TEST_ALLOW_HTTP is False)

STATE = {"status": "allow", "code": "123456", "badsig": 0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, d):
        b = json.dumps({"stat": "OK", "response": d}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def handle_(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        u = urllib.parse.urlsplit(self.path)
        s = duo.sign(SKEY, self.headers["Date"], method, self.headers["Host"], u.path, u.query, raw)
        if base64.b64decode(self.headers["Authorization"][6:]).decode() != "IK:" + s:
            STATE["badsig"] += 1
        p = json.loads(raw) if raw else {}
        if u.path.endswith("preauth"): self.reply({"result": {"u_allow": "allow", "u_enroll": "enroll"}.get(p["username"], "auth")})
        elif u.path.endswith("/auth"):
            if p["factor"] == "passcode": self.reply({"result": "allow" if p["passcode"] == STATE["code"] else "deny"})
            else: self.reply({"txid": "t"})
        else: self.reply({"result": STATE["status"], "status": "x"})
    def do_POST(self): self.handle_("POST")
    def do_GET(self): self.handle_("GET")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
duo._TEST_ALLOW_HTTP = True
REAL_GET = osstore.get
osstore.get = lambda n: SKEY.encode() if n == "duo:c1" else None
cfg = {"id": "c1", "duo": {"host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}}
ev = threading.Event()
check("preauth auth", duo.preauth(cfg, "bob") == "auth")
check("preauth allow", duo.preauth(cfg, "u_allow") == "allow")
check("preauth enroll", duo.preauth(cfg, "u_enroll") == "enroll")
duo.push(cfg, "bob", ev); check("push allow", True)
def raises(exc, f):
    try: f()
    except exc as e: return str(e)
    return None
STATE["status"] = "deny"; check("push deny", raises(duo.Denied, lambda: duo.push(cfg, "bob", ev)) is not None)
STATE["status"] = "waiting"; duo.PUSH_SECONDS = 1
t = time.time(); check("push timeout", raises(duo.Denied, lambda: duo.push(cfg, "bob", ev)) is not None and time.time() - t < 3)
duo.PUSH_SECONDS = 30; threading.Timer(0.3, ev.set).start(); t = time.time()
check("push cancel", raises(duo.Denied, lambda: duo.push(cfg, "bob", ev)) is not None and time.time() - t < 1.3)
duo.passcode(cfg, "bob", "123456"); check("passcode right", True)
msg = raises(duo.Denied, lambda: duo.passcode(cfg, "bob", "999999")); check("passcode wrong", msg is not None)
check("requests signed", STATE["badsig"] == 0)
srv.shutdown(); srv.server_close()
msgs = [raises(duo.Unavailable, lambda: duo.preauth(cfg, "bob")), raises(duo.Unavailable, lambda: duo.passcode(cfg, "bob", "999999")), msg]
check("closed port Unavailable", msgs[0] is not None)
osstore.get = lambda n: None
msgs.append(raises(duo.Unavailable, lambda: duo.preauth(cfg, "bob"))); check("no secret Unavailable", msgs[-1] is not None)
check("secret/ikey/code not in messages", not any(x and (SKEY in x or "IK" in x or "999999" in x) for x in msgs))

osstore.get = REAL_GET
if osstore.available():
    osstore.put("duo:test", b"s3cret"); check("osstore round trip", osstore.get("duo:test") == b"s3cret")
    osstore.delete("duo:test"); check("osstore delete", osstore.get("duo:test") is None)
else:
    check("osstore unavailable without keyring", sys.platform != "win32")

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
