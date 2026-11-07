# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Duo Auth API client against a fake local Duo (signatures checked by an independent v5 implementation) and the OS protected store.
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
import hashlib, hmac
def ref_sign(skey, date, method, host, path, params, body, xduo=""):
    """Duo's documented v5 algorithm, written apart from duo.sign: date, METHOD, host lowercased, path, canonical params,
    sha512(body), sha512(canonical X-Duo headers); HMAC-SHA512 keyed by skey."""
    lines = [date, method.upper(), host.lower(), path, params,
             hashlib.sha512(body.encode()).hexdigest(), hashlib.sha512(xduo.encode()).hexdigest()]
    return hmac.new(skey.encode(), "\n".join(lines).encode(), hashlib.sha512).hexdigest()
def ref_header(ikey, sig):
    return "Basic " + base64.b64encode(f"{ikey}:{sig}".encode()).decode()
body = '{"device":"auto","factor":"push","hostname":"wks01","ipaddr":"10.2.3.4","username":"narroway"}'
args = ("Tue, 21 Aug 2012 17:29:18 -0000", "POST", "API-xxxxxxxx.duosecurity.com", "/auth/v2/auth", "", body)
check("v5 matches the documented algorithm", duo.sign(SKEY, *args) == ref_sign(SKEY, *args))
check("http off by default", duo._TEST_ALLOW_HTTP is False)

STATE = {"status": "allow", "code": "123456", "badsig": 0, "hold": 0, "hold_n": 0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, d):
        b = json.dumps({"stat": "OK", "response": d}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def reply_raw(self, b):
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def handle_(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        u = urllib.parse.urlsplit(self.path)
        s = ref_sign(SKEY, self.headers["Date"], method, self.headers["Host"], u.path, u.query, raw)
        if self.headers["Authorization"] != ref_header("IK", s):
            STATE["badsig"] += 1
        p = json.loads(raw) if raw else {}
        if p.get("username") == "u_redirect":
            self.send_response(302); self.send_header("Location", "http://127.0.0.1:1/"); self.send_header("Content-Length", "0"); self.end_headers(); return
        if p.get("username") == "u_list": return self.reply_raw(b"[1]")
        if p.get("username") == "u_notxid" and u.path.endswith("/auth"): return self.reply({})
        if u.path.endswith("auth_status") and STATE["hold"]: STATE["hold_n"] += 1; (STATE["hold_n"] == 1 or STATE["status"] == "waiting") and time.sleep(STATE["hold"])
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
# long poll held longer than the request timeout: still waiting, then allow; and Denied at the deadline
duo.REQUEST_TIMEOUT = 0.5; STATE["hold"] = 1.2; STATE["status"] = "allow"; ev.clear(); duo.PUSH_SECONDS = 30
duo.push(cfg, "bob", ev); check("long poll beyond request timeout still succeeds", True)
STATE["status"] = "waiting"; duo.PUSH_SECONDS = 2; t = time.time()
check("long poll deadline Denied", raises(duo.Denied, lambda: duo.push(cfg, "bob", ev)) is not None and time.time() - t < 4)
duo.REQUEST_TIMEOUT = 10; STATE["hold"] = 0; duo.PUSH_SECONDS = 30
check("redirect Unavailable", raises(duo.Unavailable, lambda: duo.preauth(cfg, "u_redirect")) is not None)
check("non-dict body Unavailable", raises(duo.Unavailable, lambda: duo.preauth(cfg, "u_list")) is not None)
check("missing txid Unavailable", raises(duo.Unavailable, lambda: duo.push(cfg, "u_notxid", threading.Event())) is not None)
for bad_host in ["api.duosecurity.com@evil.com", "evil.com/x", "a.com\b", "a b.com", "a.com?x", "a.com#x"]:
    for flag in (False, True):
        duo._TEST_ALLOW_HTTP = flag
        check("bad host " + bad_host, raises(duo.Unavailable, lambda: duo.preauth({"id": "c1", "duo": {"host": bad_host, "ikey": "IK"}}, "bob")) is not None)
duo._TEST_ALLOW_HTTP = False
check("port refused without test flag", raises(duo.Unavailable, lambda: duo.preauth({"id": "c1", "duo": {"host": "a.com:80", "ikey": "IK"}}, "bob")) is not None)
duo._TEST_ALLOW_HTTP = True
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
if sys.platform != "win32":
    import keyring.backends.null
    was = passvault._old_backend
    passvault._old_backend = keyring.backends.null.Keyring()
    check("a keyring that keeps nothing is not a protected store", not osstore.available())
    passvault._old_backend = was
if osstore.available():
    osstore.put("duo:test", b"s3cret"); check("osstore round trip", osstore.get("duo:test") == b"s3cret")
    osstore.delete("duo:test"); check("osstore delete", osstore.get("duo:test") is None)
else:
    check("osstore unavailable without keyring", sys.platform != "win32")

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
