# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Test login (core/dirsignin.TestLogin) on ldap3's MOCK_SYNC, a fake local Duo and a fake security chip: an Admin checks a
# directory user's password and Duo, and nothing is kept: no data key, PIN slot, account record, session or counter reset.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\testlogin%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")       # as installed: the keys file isn't directly in %APPDATA%
os.environ["LOCALAPPDATA"] = _tmp.mkdtemp(prefix="netcheck_localappdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import http.server, json, logging, threading, urllib.parse, uuid
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, dirpin, duo, osstore, perms, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

RAISED = []
def raises(fn, exc):
    try:
        fn()
    except exc as e:
        RAISED.append(e)
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None

LOG = []
class Grab(logging.Handler):
    def emit(self, r): LOG.append(self.format(r))
logging.getLogger().addHandler(Grab(logging.DEBUG))
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger("toner").setLevel(logging.DEBUG)


# ---------------------------------------------------------------- fakes: the protected store, the chip, Duo, the directory
SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
PEPPERS = {"duo:d1": SKEY.encode()}
PINS = {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)


class FakeTpm:
    LockedOut = tpm_windows.LockedOut
    keys = {}

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

DUO = {"preauth": "auth", "push": "allow", "code": "135790", "down": False, "users": []}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_(self):
        n = int(self.headers.get("Content-Length") or 0)
        p = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        if DUO["down"]:
            self.send_response(503); self.send_header("Content-Length", "0"); self.end_headers(); return
        path = urllib.parse.urlsplit(self.path).path
        if "username" in p: DUO["users"].append(p["username"])
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
G_BOB = uuid.UUID("41424344-4546-4748-494a-4b4c4d4e4f50")      # fixed ASCII-safe bytes: the ldap3 mock can't match some random GUIDs
G_DAVE = uuid.UUID("51525354-5556-5758-595a-616263646566")
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
for dn, attrs in [
        ("CN=Bob,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                     "objectGUID": G_BOB.bytes_le, "userAccountControl": 512, "userPassword": "pw-bob",
                                     "memberOf": [ENGINEERS]}),
        ("CN=Dave,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "dave@acme.com", "sAMAccountName": "dave", "cn": "Dave",
                                      "objectGUID": G_DAVE.bytes_le, "userAccountControl": 512, "userPassword": "pw-dave"}),
        (ADMINS, {"objectClass": "group", "cn": "Toner Admins"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"})]:
    c.strategy.add_entry(dn, attrs)
for upn, cn in (("bob@acme.com", "Bob"), ("dave@acme.com", "Dave")):
    ldap.dit[upn] = ldap.dit["CN=%s,OU=Users,%s" % (cn, BASE)]       # AD binds by UPN; the mock only knows DNs
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._make_server = lambda cfg, host, *_: ldap
BINDS = []
real_connect = directory.connect
def counting_connect(cfg, who, password):
    BINDS.append(who)
    return real_connect(cfg, who, password)
directory.connect = counting_connect

DUO_ON = {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS], "Tech": [TECHS]}, "duo": {"on": False}}
PW, PW2, PW3 = "correct horse battery 42", "engineers have long passwords 7", "another admin's long password 9"
PIN = "246813"
SECRETS = ["pw-bob", "pw-dave", "not bob's password", PW, PW2, PW3, DUO["code"], "000000", SKEY, PIN]

def keys_bytes():
    return datakey.path().read_bytes()

def fails():
    return json.loads(datakey.path().read_text(encoding="utf-8"))["throttle"]["fails"]

def rows():
    return [r for r in audit.recent(5000) if r["action"] == "test login"]

def as_(name, pw):
    session.sign_out()
    session.sign_in(name, pw)

def cfg():
    """As the window gets it: from the verified list."""
    return next(d for d in roles.verified()["directories"] if d["id"] == "d1")

def held():
    return (session.state(), session.user(), datakey.is_open(), datakey.signed_in_name(), datakey._key, datakey.box_private(),
            tuple(roles.holds(k) for k in ("rules", "backups", "vault")), dict(FakeTpm.keys), dict(PINS))

def ok_text(name="bob@acme.com", role="Engineer"):
    return S.TEST_OK.format(name=name, role=role)

def last_row(sentence, name="bob@acme.com"):
    r = rows()
    return bool(r) and r[0]["detail"] == f"{name}, {sentence}"

def password_in_frames(e):
    """True when any frame an exception (or one it chains to) holds still has a password among its locals."""
    while e is not None:
        tb = e.__traceback__
        while tb is not None:
            if any(isinstance(v, str) and v in SECRETS[:6] for v in tb.tb_frame.f_locals.values()):
                return True
            tb = tb.tb_next
        e = e.__cause__ or e.__context__
    return False


# ---------------------------------------------------------------- set up: two Admins, an Engineer, the directory (Duo off)
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
as_("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")
datakey.add_local("Admin2", PW3, role="Admin")
roles.set_directories([ACME])
session.sign_out()
finished = 0                                            # tests that ended: one "test login" row each

check("the approved sentences", S.TEST_OK == "Signed in as {name}. Role: {role}. Signed out."
      and S.TEST_NOT_MAPPED == "{name} isn't in an OU or group that Toner maps to a role.")

# ---------------------------------------------------------------- only an Admin, before any bind
as_("Eng1", PW2)
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "pw-bob"), perms.Denied)
check("an Engineer: perms.Denied before any bind", e is not None and BINDS == [] and t.stage == "password" and t.result is None)
check("...and no audit row", rows() == [])
session.sign_out()

# ---------------------------------------------------------------- an Admin tests Bob (no Toner account), Duo off
as_("Admin1", PW)
before, keys, count = held(), keys_bytes(), fails()
t = S.TestLogin(cfg())
check("a new test starts at the password", t.stage == "password" and t.result is None)
t.check_password("bob@acme.com", "pw-bob")
finished += 1
check("Duo off: done, with the role", t.stage == "done" and t.result == ok_text(), t.result)
check("...one bind, as Bob", BINDS == ["bob@acme.com"], BINDS)
check("...the keys file is byte-identical", keys_bytes() == keys)
check("...no account record, no PIN slot", datakey.directory_account("bob@acme.com") is None and FakeTpm.keys == {})
check("...Admin1's session, key and role keys are as they were", held() == before)
check("...audited", len(rows()) == finished and last_row(ok_text()) and rows()[0]["actor"] == "Admin1", rows()[:1])
check("...nothing kept on the test but the result", not any(isinstance(v, str) and "pw-bob" in v for v in vars(t).values()))
check("a step can't be repeated", raises(lambda: t.check_password("bob@acme.com", "pw-bob"), RuntimeError) is not None
      and len(rows()) == finished)

# ---------------------------------------------------------------- a wrong password counts; a right one doesn't clear it
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "not bob's password"), datakey.WrongPassword)
finished += 1
check("a wrong password: WrongPassword, with the approved sentence", e is not None and str(e) == datakey.WRONG
      and t.result == datakey.WRONG and t.stage == "done")
check("...counted on the shared counter", fails() == count + 1, fails())
check("...audited with the name as typed", len(rows()) == finished and last_row(datakey.WRONG))
check("...the password isn't held by the exception's frames", not password_in_frames(e))
check("...nor chained to the directory's exception", e.__context__ is None)
S.TestLogin(cfg()).check_password("bob@acme.com", "pw-bob")
finished += 1
check("a right password after it doesn't clear the count (a test isn't a sign-in)", fails() == count + 1, fails())

# ---------------------------------------------------------------- a person no OU or group maps
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("dave@acme.com", "pw-dave"), S.NotInGroup)
finished += 1
not_mapped = S.TEST_NOT_MAPPED.format(name="dave@acme.com")
check("unmapped: NotInGroup with the approved sentence", e is not None and str(e) == not_mapped and t.result == not_mapped)
check("...counted as begin counts it", fails() == count + 2, fails())
check("...audited", len(rows()) == finished and last_row(not_mapped, "dave@acme.com"))

# ---------------------------------------------------------------- the shared wait is honoured before the bind
d = json.loads(datakey.path().read_text(encoding="utf-8"))
d["throttle"] = {"fails": 9, "until": time.time() + 100}
datakey.path().write_text(json.dumps(d), encoding="utf-8")
binds, t = len(BINDS), S.TestLogin(cfg())
check("while a wait runs: Throttled, no bind, no row", raises(lambda: t.check_password("bob@acme.com", "pw-bob"), datakey.Throttled)
      is not None and len(BINDS) == binds and len(rows()) == finished and t.stage == "password")
d["throttle"] = {"fails": 0, "until": 0}
datakey.path().write_text(json.dumps(d), encoding="utf-8")

# ---------------------------------------------------------------- the directory can't be reached: no offline path
directory._make_server = lambda cfg, host, *_: (_ for _ in ()).throw(OSError("no route"))
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "pw-bob"), directory.Unreachable)
finished += 1
check("unreachable: the approved sentence", e is not None and str(e) == S.UNREACHABLE and t.result == S.UNREACHABLE
      and last_row(S.UNREACHABLE) and not password_in_frames(e))
directory._make_server = lambda cfg, host, *_: ldap

# ---------------------------------------------------------------- the CA file changed since the list was signed
def ca_changed(cfg, who, password): raise directory.CaChanged("CA file changed")
directory.connect = ca_changed
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "pw-bob"), S.CaChanged)
directory.connect = counting_connect
finished += 1
check("a changed CA file: the approved sentence, one row", e is not None and str(e) == S.CA_CHANGED and t.result == S.CA_CHANGED
      and last_row(S.CA_CHANGED) and len(rows()) == finished)

# ---------------------------------------------------------------- the audit name: the typed login on one plain line
typed = "bob@acme.com\r\nforged row\t" + chr(127) + "x" * 300
t = S.TestLogin(cfg())
raises(lambda: t.check_password(typed, "not bob's password"), datakey.WrongPassword)
finished += 1
clean = ("bob@acme.comforged row" + "x" * 300)[:256]
check("a login with control characters: removed, cut to 256", len(rows()) == finished and last_row(datakey.WRONG, clean)
      and not any(ch < " " or ch == chr(127) for ch in rows()[0]["detail"]), repr(rows()[0]["detail"][:60]))

# ---------------------------------------------------------------- the test's own wrong password starts the wait
d = json.loads(datakey.path().read_text(encoding="utf-8"))
d["throttle"] = {"fails": datakey.FREE_TRIES, "until": 0}
datakey.path().write_text(json.dumps(d), encoding="utf-8")
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "not bob's password"), datakey.Throttled)
finished += 1
wait_text = str(e)
check("a wrong password past the free tries: the wait's sentence shown and audited", e is not None
      and wait_text.startswith("Too many tries. Wait ") and t.result == wait_text and last_row(wait_text) and len(rows()) == finished)
binds, t = len(BINDS), S.TestLogin(cfg())
check("...and the wait is honoured by the next test: no bind, no row",
      raises(lambda: t.check_password("bob@acme.com", "pw-bob"), datakey.Throttled) is not None and len(BINDS) == binds
      and len(rows()) == finished)
d = json.loads(datakey.path().read_text(encoding="utf-8"))
d["throttle"] = {"fails": 0, "until": 0}
datakey.path().write_text(json.dumps(d), encoding="utf-8")

# ---------------------------------------------------------------- Duo on
roles.set_directories([dict(ACME, duo=DUO_ON)], edited="d1")
keys, count = keys_bytes(), fails()
before = held()
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
check("Duo on: the Duo step after the password", t.stage == "duo" and t.result is None and DUO["users"][-1] == "bob@acme.com")
t.duo_push(threading.Event())
finished += 1
check("an approved push: done", t.stage == "done" and t.result == ok_text() and last_row(ok_text()) and len(rows()) == finished)
check("...nothing written to the keys file, the slots or the session", keys_bytes() == keys and held() == before)

DUO["push"] = "deny"
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
e = raises(lambda: t.duo_push(threading.Event()), duo.Denied)
finished += 1
check("a denied push: Denied, with the approved sentence", e is not None and str(e) == S.DUO_DENIED and t.result == S.DUO_DENIED
      and last_row(S.DUO_DENIED) and len(rows()) == finished)
DUO["push"] = "allow"

t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
t.duo_code(DUO["code"])
finished += 1
check("a right code: done", t.result == ok_text() and len(rows()) == finished)
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
e = raises(lambda: t.duo_code("000000"), duo.Denied)
finished += 1
check("a wrong code: Denied, with the approved sentence", e is not None and str(e) == S.WRONG_CODE and last_row(S.WRONG_CODE)
      and len(rows()) == finished)

t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
stop = threading.Event(); stop.set()
check("a push cancelled for a code: Denied, no row, still at Duo", raises(lambda: t.duo_push(stop), duo.Denied) is not None
      and t.stage == "duo" and len(rows()) == finished)
t.duo_code(DUO["code"])
finished += 1
check("...the code then finishes it, one row", t.result == ok_text() and len(rows()) == finished)
real_push = duo.push
def late_push(cfg, user, cancel):          # while the push waits, the Admin enters a code and it finishes first
    t.duo_code(DUO["code"])
duo.push = late_push
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
t.duo_push(threading.Event())
duo.push = real_push
finished += 1
check("a push that comes back after a code finished the test: still one row", t.result == ok_text() and len(rows()) == finished)
def late_deny(cfg, user, cancel):          # the code finishes the test, then the push comes back refused
    t.duo_code(DUO["code"])
    raise duo.Denied("push not approved")
duo.push = late_deny
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
e = raises(lambda: t.duo_push(threading.Event()), duo.Denied)
duo.push = real_push
finished += 1
check("a push refused after a code finished the test: one row, the result stays a pass", e is not None
      and t.result == ok_text() and t.stage == "done" and len(rows()) == finished and last_row(ok_text()))
def cancelled_down(cfg, user, cancel):     # the Admin chose a code just as Duo stopped answering the push
    cancel.set()
    raise duo.Unavailable("no answer")
duo.push = cancelled_down
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
e = raises(lambda: t.duo_push(threading.Event()), duo.Unavailable)
duo.push = real_push
check("a cancelled push that can't reach Duo: no row, still at Duo", e is not None and t.stage == "duo" and t.result is None
      and len(rows()) == finished)
t.duo_code(DUO["code"])
finished += 1
check("...a code then works, one row", t.result == ok_text() and len(rows()) == finished)

for result in ("deny", "enroll"):
    DUO["preauth"] = result
    t = S.TestLogin(cfg())
    e = raises(lambda: t.check_password("bob@acme.com", "pw-bob"), duo.Denied)
    finished += 1
    check("preauth %s: Denied" % result, e is not None and str(e) == S.DUO_DENIED and last_row(S.DUO_DENIED)
          and len(rows()) == finished)
DUO["preauth"] = "allow"
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
finished += 1
check("Duo's bypass: done at the password", t.stage == "done" and t.result == ok_text() and len(rows()) == finished)
DUO["preauth"] = "auth"
DUO["down"] = True
t = S.TestLogin(cfg())
e = raises(lambda: t.check_password("bob@acme.com", "pw-bob"), duo.Unavailable)
finished += 1
check("Duo unreachable: Unavailable, with the approved sentence", e is not None and str(e) == S.DUO_DOWN and last_row(S.DUO_DOWN)
      and len(rows()) == finished)
DUO["down"] = False
check("a test writes no Duo-denied sign-in row", not [r for r in audit.recent(5000) if r["action"] == "Duo denied a sign-in"])
session.sign_out()

# ---------------------------------------------------------------- Bob has a Toner account; Admin2 tests him with a held session
a = S.begin("bob@acme.com", "pw-bob")
S.after_password(a)
S.duo_push(a, threading.Event())
S.choose_pin(a, PIN)
S.approve(a, "Admin1", PW)
S.finish(a, PIN)
check("(Bob signs in for real once)", session.user() == "bob@acme.com")
as_("Admin2", PW3)
datakey.set_online("bob@acme.com", time.time() - 5000)          # an offline hour a sign-in would renew
rec, keys, before, count = datakey.directory_account("bob@acme.com"), keys_bytes(), held(), fails()
check("(Admin2 holds the role keys)", before[6][0])
t = S.TestLogin(cfg())
t.check_password("bob@acme.com", "pw-bob")
t.duo_push(threading.Event())
finished += 1
check("an existing account is tested the same way", t.result == ok_text() and last_row(ok_text()) and rows()[0]["actor"] == "Admin2")
check("...its record isn't touched (no online, full or groups' role write)", datakey.directory_account("bob@acme.com") == rec)
check("...the keys file is byte-identical", keys_bytes() == keys)
check("...Admin2's session, key and role keys are as they were", held() == before)

# ---------------------------------------------------------------- nothing secret anywhere
check("one row per finished test", len(rows()) == finished, (len(rows()), finished))
everything = [r["detail"] + r["action"] for r in audit.recent(5000)]
check("no password, code or secret in the audit", not [s for s in SECRETS if any(s in x for x in everything)])
check("...nor in the log", not [s for s in SECRETS if any(s in x for x in LOG)])
def chain(e):                                          # each exception's text and arguments, and those it chains to
    while e is not None:
        yield repr(e.args) + str(e)
        e = e.__cause__ or e.__context__
texts = [x for e in RAISED for x in chain(e)]
check("...nor in any exception's text or arguments", not [s for s in SECRETS if any(s in x for x in texts)])
check("...nor in the frames a failed test's exception holds", not any(password_in_frames(e) for e in RAISED))
check("every row is a name and the sentence shown", all(r["detail"].split(", ", 1)[1] in
      (ok_text(), datakey.WRONG, not_mapped, S.UNREACHABLE, S.CA_CHANGED, wait_text, S.DUO_DENIED, S.WRONG_CODE,
       S.DUO_DOWN) for r in rows()))
session.sign_out()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
