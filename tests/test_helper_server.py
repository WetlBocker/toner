# Run directly (python tests/test_helper_server.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The helper's core (core/helper): its messages, its store, and the checks it makes itself before it releases the spare keys:
# enrollment against the signed rules, owner-only ops, SSO answers with nonces it issued, directory passwords and Duo, tickets,
# the rules pinned at enrollment, the failure count, and no secret in an answer or the log.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\helper%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, http.server, json, logging, pathlib, pickle, subprocess, threading, urllib.parse, uuid
import ldap3
from core import datakey, db, directory, duo, envelope, oidc, osstore, roles, session
from core.helper import protocol, server, store
from core.version import VERSION
from fake_oidc import FakeProvider, leaks

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
        print("   (raised", type(e).__name__, ")")
    return False


# ---------------------------------------------------------------- fakes: the protected store, Duo, the directory, the provider, the log
PEPPERS, PINS = {}, {}          # no duo:d1 here: the helper must use the Duo key it was given
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)

SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
DUO = {"preauth": "auth", "push": "allow", "code": "135790"}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_(self):
        n = int(self.headers.get("Content-Length") or 0)
        p = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
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
TECHS = "CN=Toner Techs," + BASE
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
for dn, attrs in [
        ("CN=Bob,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                     "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-bob",
                                     "memberOf": [TECHS]}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"})]:
    c.strategy.add_entry(dn, attrs)
ldap.dit["bob@acme.com"] = ldap.dit["CN=Bob,OU=Users," + BASE]       # AD binds by UPN; the mock only knows DNs
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._make_server = lambda cfg, host, *_: ldap

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()
oidc.GRAPH = ISS + "/graph"

LOG = []
class Keep(logging.Handler):
    def emit(self, record): LOG.append(self.format(record))
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.DEBUG)

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Tech": [TECHS]}, "duo": {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}}
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": ISS, "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
PW = "correct horse battery 42"


# ---------------------------------------------------------------- set up: a keys file made the part 3 way, its keys
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME, SSO])
DATA_KEY = datakey._key
RULES = roles._held["rules"]
RULES = RULES if isinstance(RULES, bytes) else RULES.private_bytes_raw()
KEYS = str(datakey.path())
d = json.loads(pathlib.Path(KEYS).read_bytes()); d.pop("rules_version")      # as a Part 2/3 copy signed it, before the count
payload = roles._signed(d)
d["rules_sig"] = envelope.sign(RULES, payload)
pathlib.Path(KEYS).write_text(json.dumps(d), encoding="utf-8")
db.set_setting("rules_signed", payload.decode("utf-8"))
roles._invalidate()
session.sign_out()
UNVERSIONED = pathlib.Path(KEYS).read_bytes()
ORIGINAL = UNVERSIONED                                  # (set to the versioned file once an Admin has signed in)

b64 = lambda b: base64.b64encode(b).decode()
xor = lambda b: bytes(x ^ 0x5A for x in b)     # reversible, so the stored file can be checked for the raw keys
HDIR = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_helper_"))
ST = store.Store(HDIR / "helper.json", xor, xor)
T = [time.time()]
def now(): return T[0]
HELPER = server.Helper(ST, now=now)
OWNER, OTHER = "S-1-5-21-1-1001", "S-1-5-21-1-1002"
ANSWERS, RELEASED, TOKENS = [], [], []

def ask(op, peer=OWNER, cancel=None, **fields):
    req = {"op": op, "v": protocol.PROTOCOL, **fields}
    if op not in ("duo_push", "duo_code"):
        req.setdefault("keys_path", KEYS)
    ans = HELPER.handle(protocol.decode(protocol.encode(req)), peer, cancel)
    protocol.encode(ans)            # every answer fits the channel
    (RELEASED if op == "release" and ans.get("ok") else ANSWERS).append(ans)
    return ans

def err(ans):
    return ans.get("error") if not ans.get("ok") else None

def enroll(peer=OWNER, rules=RULES, **fields):
    return ask("enroll", peer, data_key=b64(DATA_KEY), rules_private=b64(rules), duo={"d1": b64(SKEY.encode())}, **fields)

def sso_token(**claims):
    n = ask("nonce", connection="s1")["nonce"]
    return n, P.token(nonce=n, **claims)

def check_sso(token):
    TOKENS.append(token)
    return ask("check_sso", connection="s1", id_token=token, access_token="at-1")

def to_ticket():
    DUO.update(preauth="allow")
    t = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")["ticket"]
    DUO.update(preauth="auth")
    return t


# ---------------------------------------------------------------- the messages
check("protocol: version 1, 64 KiB", protocol.PROTOCOL == 1 and protocol.MAX == 65536)
check("decode: a dict back", protocol.decode(protocol.encode({"op": "status", "v": 1})) == {"op": "status", "v": 1})
check("decode: 70,000 bytes raise ValueError", raises(lambda: protocol.decode(b" " * 69990 + b'{"a": 1}'), ValueError)
      and raises(lambda: protocol.decode(json.dumps({"a": "x" * 70000}).encode()), ValueError))
check("decode: a pickle raises ValueError", raises(lambda: protocol.decode(pickle.dumps({"op": "status"})), ValueError))
check("decode: a list, a number, NaN or bad UTF-8 raise ValueError",
      all(raises(lambda b=b: protocol.decode(b), ValueError) for b in (b"[1]", b"7", b'{"a": NaN}', b'{"a": "\xff"}')))
check("encode: too big raises ValueError", raises(lambda: protocol.encode({"a": "x" * 70000}), ValueError))

# ---------------------------------------------------------------- the import: no Qt, no database
NODB = _tmp.mkdtemp(prefix="netcheck_nodb_")
env = {**os.environ, "NETCHECK_DB": os.path.join(NODB, "never.db"), "APPDATA": NODB}
r = subprocess.run([sys.executable, "-c", "import sys, core.helper.server; print('PySide6' in sys.modules)"],
                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), env=env, capture_output=True, text=True)
check("import core.helper.server: no PySide6, no database file", r.returncode == 0 and r.stdout.strip() == "False"
      and os.listdir(NODB) == [], (r.stdout, r.stderr[-500:], os.listdir(NODB)))

# ---------------------------------------------------------------- enrollment
a = ask("status")
check("status before enrollment: not enrolled, the version", a == {"ok": True, "protocol": 1, "version": VERSION, "enrolled": False,
                                                                   "owner": False, "rules_changed": False}, a)
check("an op before enrollment: not_enrolled", err(ask("nonce", connection="s1")) == "not_enrolled")
check("enroll with another Ed25519 key: refused", err(enroll(rules=envelope.new_signing_key()[0])) == "refused" and ST.load() is None)
check("enroll with a bad request: bad_request", err(ask("enroll", data_key="!!", rules_private=b64(RULES))) == "bad_request"
      and err(ask("enroll", data_key=b64(DATA_KEY))) == "bad_request")
far = ([r"\\server\share\netcheck.keys", "//server/share/netcheck.keys", r"\\.\pipe\toner", r"\\?\C:\x\netcheck.keys",
        "netcheck.keys", r"\x\netcheck.keys"] if os.name == "nt" else ["//server/share/netcheck.keys", "netcheck.keys"])
check("enroll from a UNC, device or relative path: bad_request", [err(enroll(keys_path=f)) for f in far] == ["bad_request"] * len(far))
BIG = HDIR / "big.keys"
BIG.write_bytes(ORIGINAL + b" " * (1 << 20))
check("enroll from a keys file over 1 MiB: bad_request", err(enroll(keys_path=str(BIG))) == "bad_request")
check("enroll from a folder: bad_request", err(enroll(keys_path=str(HDIR))) == "bad_request")
if os.name != "nt":
    FIFO = HDIR / "fifo.keys"
    os.mkfifo(FIFO)
    box = []
    th = threading.Thread(target=lambda: box.append(enroll(keys_path=str(FIFO))), daemon=True)
    th.start(); th.join(5)
    check("enroll from a FIFO: bad_request, without hanging", bool(box) and err(box[0]) == "bad_request", box)
check("enroll on a keys file signed before rules_version: rules_changed", err(enroll()) == "rules_changed" and ST.load() is None)
session.sign_in("Admin1", PW)                           # the first Admin signing since the upgrade starts the count
session.sign_out()
ORIGINAL = pathlib.Path(KEYS).read_bytes()
check("...an Admin's sign-in signs it as version 1", json.loads(ORIGINAL).get("rules_version") == 1)
check("enroll with the copy's rules key: ok", enroll() == {"ok": True})
rec = ST.load()
check("...the record: owner, path, rules_pub pinned, spare and Duo key", rec["owner"] == OWNER
      and rec["keys_path"] == os.path.normcase(os.path.abspath(KEYS)) and rec["rules_pub"] == json.loads(ORIGINAL)["rules_pub"]
      and rec["spare"] == DATA_KEY + RULES and rec["duo"] == {"d1": SKEY.encode()} and abs(rec["enrolled_at"] - T[0]) < 1
      and rec["rules_version"] == json.loads(ORIGINAL)["rules_version"] >= 1)
raw = ST.path.read_text(encoding="utf-8")
check("...the stored file holds the keys only protected", not any(s in raw for s in (b64(DATA_KEY), b64(RULES), b64(DATA_KEY + RULES),
                                                                                     SKEY, b64(SKEY.encode()))))
a = ask("status")
check("status from the owner: owner, rules unchanged", a["enrolled"] and a["owner"] and not a["rules_changed"], a)
check("status from the owner with another copy's keys file: not owner",
      not ask("status", keys_path=os.path.join(SP, "other", "netcheck.keys"))["owner"])
check("a keys path with a NUL in it: not owner", not ask("status", keys_path=KEYS + "\0")["owner"]
      and err(ask("nonce", keys_path=KEYS + "\0", connection="s1")) == "not_owner")

# ---------------------------------------------------------------- another peer gets nothing but status
a = ask("status", OTHER)
check("status from another peer: enrolled, not owner", a["enrolled"] and not a["owner"] and not a["rules_changed"], a)
check("forget, nonce, release from another peer: not_owner", [err(ask("forget", OTHER)), err(ask("nonce", OTHER, connection="s1")),
      err(ask("release", OTHER, ticket="x", name="bob@acme.com"))] == ["not_owner"] * 3)
check("enroll from another peer while enrolled: other_user", err(enroll(OTHER)) == "other_user" and ST.load()["owner"] == OWNER)
check("a request without the protocol version: bad_request", HELPER.handle({"op": "nonce", "keys_path": KEYS, "connection": "s1"},
                                                                           OWNER) == {"ok": False, "error": "bad_request"})
check("an unknown op: bad_request", err(ask("unpickle")) == "bad_request")

# ---------------------------------------------------------------- SSO
n, tok = sso_token()
a = check_sso(tok)
check("check_sso: a good token with an issued nonce gives a ticket", a.get("ok") and a["name"] == "ann@example.com"
      and a["role"] == "Tech" and a["guid"] == "sub-1" and a["display"] == "ann@example.com" and isinstance(a.get("ticket"), str), a)
SSO_TICKET = a["ticket"]
check("check_sso: the same nonce twice gives bad_answer", err(check_sso(tok)) == "bad_answer")
check("check_sso: a nonce the helper never issued gives bad_answer", err(check_sso(P.token(nonce="made-up-by-toner"))) == "bad_answer")
check("check_sso: a nonce issued for another connection gives bad_answer",
      err(check_sso(P.token(nonce=ask("nonce", connection="d1")["nonce"]))) == "bad_answer")
check("check_sso: auth_time 400 s old gives not_fresh", err(check_sso(sso_token(auth_time=int(time.time()) - 400)[1])) == "not_fresh")
check("check_sso: a group not mapped gives not_in_group", err(check_sso(sso_token(groups=["g9"])[1])) == "not_in_group")
check("check_sso: a good one clears the count", check_sso(sso_token()[1]).get("ok") and OWNER not in HELPER._fails)
check("check_sso: an account outside the connection's email domains gives bad_answer",
      err(check_sso(sso_token(preferred_username="ann@evil.example")[1])) == "bad_answer")
check("check_sso: the domain is compared in any case", check_sso(sso_token(preferred_username="Ann@Example.COM")[1]).get("ok"))
check("check_sso: a sign-in from before the nonce was issued (a browser session reused quietly) gives not_fresh",
      err(check_sso(sso_token(auth_time=int(time.time()) - 100)[1])) == "not_fresh")
check("check_sso: a sign-in within the clock leeway before the nonce is fresh",
      check_sso(sso_token(auth_time=int(time.time()) - 30)[1]).get("ok"))
n, tok = sso_token()
T[0] += 299
check("check_sso: a nonce used within 300 s works", check_sso(tok).get("ok"))
n, tok = sso_token()
T[0] += 301
check("check_sso: a nonce used after 300 s gives bad_answer", err(check_sso(tok)) == "bad_answer")
T[0] = time.time()
P.graph_member_ids = ["g1"]
real_cfg = HELPER._cfg
HELPER._cfg = lambda rec, conn, sso, read: {**real_cfg(rec, conn, sso, read), "provider": "entra"}     # (Graph is Entra's only)
a = check_sso(sso_token(groups=None, _claim_names={"groups": "src1"})[1])
check("check_sso: over 200 Entra groups, the list from Graph for the same person", a.get("role") == "Tech", a)
P.graph_me_id = "someone-else"
check("check_sso: Graph's /me is someone else: bad_answer", err(check_sso(sso_token(groups=None, _claim_names={"groups": "src1"})[1]))
      == "bad_answer")
P.graph_me_id = "oid-1"
HELPER._cfg = real_cfg
check("check_sso: another provider's _claim_names: no Graph call, no groups", err(check_sso(sso_token(groups=None,
      _claim_names={"groups": "src1"})[1])) == "not_in_group")
check("check_sso: a directory connection is not an SSO one: bad_request",
      err(ask("check_sso", connection="d1", id_token=sso_token()[1], access_token="at-1")) == "bad_request")

# ---------------------------------------------------------------- the rules pinned at enrollment
ticket = to_ticket()
doc = json.loads(ORIGINAL)
next(d for d in doc["directories"] if d["id"] == "s1")["groups"]["Admin"] = ["g1"]     # a mapping added without re-signing
pathlib.Path(KEYS).write_text(json.dumps(doc), encoding="utf-8")
check("edited directories: status says rules_changed", ask("status")["rules_changed"])
check("edited directories: check_sso gives rules_changed", err(check_sso(sso_token()[1])) == "rules_changed")
check("edited directories: release gives rules_changed and releases nothing", ask("release", ticket=ticket, name="bob@acme.com")
      == {"ok": False, "error": "rules_changed"})
priv, pub = envelope.new_signing_key()
doc = json.loads(ORIGINAL)
doc["rules_pub"], doc["rules_sig"] = b64(pub), envelope.sign(priv, roles._signed(doc))       # a new rules key, signed by it
pathlib.Path(KEYS).write_bytes(json.dumps(doc).encode())
check("a replaced rules key: status says rules_changed", ask("status")["rules_changed"])
check("a replaced rules key: check_sso gives rules_changed", err(check_sso(sso_token()[1])) == "rules_changed")
check("a replaced rules key: check_directory gives rules_changed",
      err(ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")) == "rules_changed")
check("a replaced rules key: enroll with it from another peer is still other_user", err(enroll(OTHER, rules=priv)) == "other_user")
pathlib.Path(KEYS).unlink()
check("the keys file gone: rules_changed", ask("status")["rules_changed"])
pathlib.Path(KEYS).write_bytes(ORIGINAL)
check("the file put back: rules unchanged", not ask("status")["rules_changed"])

# ---------------------------------------------------------------- directory and Duo
a = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")
check("check_directory: Duo on, preauth auth: pending, who it is, no ticket", a.get("ok") and a["duo"] == "auth"
      and isinstance(a["pending"], str) and a["name"] == "bob@acme.com" and a["role"] == "Tech" and a["display"] == "Bob"
      and "ticket" not in a, a)
b = ask("duo_push", pending=a["pending"], cancel=threading.Event())
check("duo_push allowed: a ticket", b.get("ok") and isinstance(b.get("ticket"), str), b)
PUSH_TICKET = b["ticket"]
check("duo_push: the pending check is used up", err(ask("duo_push", pending=a["pending"])) == "refused")
a = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")
check("duo_code: a wrong code gives refused", err(ask("duo_code", pending=a["pending"], code="000000")) == "refused")
check("duo_code: the right code gives a ticket", isinstance(ask("duo_code", pending=a["pending"], code="135790").get("ticket"), str))
DUO["push"] = "deny"
a = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")
check("duo_push denied: refused", err(ask("duo_push", pending=a["pending"])) == "refused")
DUO["push"] = "allow"
check("duo_push: one push per password check, a second gives refused", err(ask("duo_push", pending=a["pending"])) == "refused")
check("...a code may still follow it", isinstance(ask("duo_code", pending=a["pending"], code="135790").get("ticket"), str))
a = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")
ev = threading.Event(); ev.set()
check("duo_push cancelled (the client went): refused, and it counts", err(ask("duo_push", pending=a["pending"], cancel=ev))
      == "refused" and HELPER._fails[OWNER][0] == 1, HELPER._fails.get(OWNER))
check("duo_push from another peer: not_owner", err(ask("duo_push", "S-1-5-21-1-1003", pending=a["pending"])) == "not_owner")
DUO["preauth"] = "deny"
check("Duo preauth deny: duo_denied", err(ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")) == "duo_denied")
DUO["preauth"] = "enroll"
check("Duo preauth enroll: duo_denied", err(ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")) == "duo_denied")
check("...and a wrong password is still refused", err(ask("check_directory", connection="d1", login="bob@acme.com", password="nope")) == "refused")
DUO["preauth"] = "auth"
check("Duo preauth allow: a ticket", isinstance(to_ticket(), str))
check("check_directory: an SSO connection is not a directory: bad_request",
      err(ask("check_directory", connection="s1", login="bob@acme.com", password="pw-bob")) == "bad_request")

# ---------------------------------------------------------------- the directory's CA file: read with the caller's rights, never SYSTEM's
import hashlib
CAF = HDIR / "ca.pem"
CAF.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot a real one\n-----END CERTIFICATE-----\n")
real_cfg, real_sign_in, CA_SEEN, READ = HELPER._cfg, directory.sign_in, [], []
def with_ca(path, sha=None):
    HELPER._cfg = lambda rec, conn, sso, read: {**real_cfg(rec, conn, sso, read), "ca_file": str(path),
                                                "ca_sha256": sha or hashlib.sha256(CAF.read_bytes()).hexdigest()}
directory.sign_in = lambda cfg, login, pw, ca_data=None, **k: (CA_SEEN.append(ca_data), real_sign_in(cfg, login, pw, ca_data=ca_data, **k))[1]
def reader(path):
    READ.append(path)
    return server._read(path)
def check_dir():
    return HELPER.handle({"op": "check_directory", "v": protocol.PROTOCOL, "keys_path": KEYS, "connection": "d1",
                          "login": "bob@acme.com", "password": "pw-bob"}, OWNER, None, reader)
with_ca(CAF)
a = check_dir()
check("a CA file: read through the caller's reader, its bytes handed to the bind", a.get("ok") and CA_SEEN[-1] == CAF.read_bytes()
      and os.path.normcase(str(CAF)) in READ, (a, READ))
BIG = HDIR / "big.pem"
BIG.write_bytes(b"x" * (server.MAX_KEYS + 1))
with_ca(BIG, "0" * 64)
n = len(CA_SEEN)
check("a CA file over 1 MiB: bad_request, no bind", check_dir() == {"ok": False, "error": "bad_request"} and len(CA_SEEN) == n)
with_ca(HDIR / "missing.pem", "0" * 64)
check("a CA file that can't be read: bad_request (Toner then binds itself)", check_dir() == {"ok": False, "error": "bad_request"})
with_ca("relative.pem", "0" * 64)
check("a CA path that isn't absolute and local: bad_request", check_dir() == {"ok": False, "error": "bad_request"})
if hasattr(os, "mkfifo"):
    FIFO = HDIR / "ca.fifo"
    os.mkfifo(FIFO)
    started = time.time()
    with_ca(FIFO, "0" * 64)
    check("a CA path that is a FIFO: bad_request at once, nothing waits on it", check_dir() == {"ok": False, "error": "bad_request"}
          and time.time() - started < 5)
HELPER._cfg, directory.sign_in = real_cfg, real_sign_in

# ---------------------------------------------------------------- release
a = ask("release", ticket=PUSH_TICKET, name="bob@acme.com")
check("release with a Tech's ticket: the enrolled data key, never the rules key", a.get("ok") and base64.b64decode(a["data_key"])
      == DATA_KEY and "rules_private" not in a and a["role"] == "Tech", a)
BOB_GUID = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")["guid"]
CUR = json.loads(roles._signed(json.loads(pathlib.Path(KEYS).read_bytes())))
BOX = b64(os.urandom(32))

def proposal(change=None, **acct):
    """The signed part Toner would propose for Bob's approval as a Tech, `change(body)` applied to it."""
    new = json.loads(json.dumps(CUR))
    new["accounts"]["bob@acme.com"] = {"approved_role": "Tech", "box_pub": BOX, "directory": "d1", "guid": BOB_GUID, **acct}
    new["rules_version"] += 1
    if change:
        change(new)
    return envelope.canonical(new).decode("utf-8")

def sign(signed, ticket=None):
    return ask("sign_approval", ticket=ticket or to_ticket(), name="bob@acme.com", signed=signed)

b = sign(proposal(), PUSH_TICKET)
check("sign_approval: the Tech's one approval is signed with the rules key", b.get("ok") and set(b) == {"ok", "rules_sig"}
      and envelope.verify(roles._public("rules", RULES), proposal().encode(), b["rules_sig"]), b)
check("...the ticket used up by it", err(ask("release", ticket=PUSH_TICKET, name="bob@acme.com")) == "refused"
      and err(sign(proposal(), PUSH_TICKET)) == "refused")
check("sign_approval refuses another account changed", err(sign(proposal(lambda n: n["accounts"]["Admin1"].update(role="Tech"))))
      == "refused")
check("...another account added", err(sign(proposal(lambda n: n["accounts"].__setitem__("eve@acme.com", n["accounts"]["bob@acme.com"]))))
      == "refused")
check("...a role permission changed", err(sign(proposal(lambda n: n["roles"]["Tech"].__setitem__("unmasked", True)))) == "refused")
check("...a directory changed", err(sign(proposal(lambda n: n["directories"][0].__setitem__("servers", ["evil.example"])))) == "refused")
check("...the backups key or the recovery key changed", err(sign(proposal(lambda n: n.__setitem__("backups_pub", BOX)))) == "refused"
      and err(sign(proposal(lambda n: n.__setitem__("recovery_box_pub", BOX)))) == "refused")
check("...a grant (or anything else) added to what is signed", err(sign(proposal(lambda n: n.__setitem__("grants", {"bob@acme.com":
      {"rules": "x"}})))) == "refused")
check("...the version skipped or kept", err(sign(proposal(lambda n: n.__setitem__("rules_version", n["rules_version"] + 1))))
      == "refused" and err(sign(proposal(lambda n: n.__setitem__("rules_version", n["rules_version"] - 1)))) == "refused")
check("...another role than the ticket's", err(sign(proposal(approved_role="Admin"))) == "refused")
check("...another guid or connection than the ticket's", err(sign(proposal(guid="someone-else"))) == "refused"
      and err(sign(proposal(directory="s1"))) == "refused")
check("...a box key that isn't one, or an extra field", err(sign(proposal(box_pub="AAAA"))) == "refused"
      and err(sign(proposal(sealed="x"))) == "refused")
# the name's existing record: only the same directory account (same connection and guid) may be re-approved under it
from core.helper.server import _only_approval
WANT = {"approved_role": "Tech", "directory": "d1", "guid": BOB_GUID}
def cur_with(rec):
    c = json.loads(json.dumps(CUR)); c["accounts"]["bob@acme.com"] = rec; return c
NEW = json.loads(proposal())
check("...a name that is another account's (local, no directory): refused", not _only_approval(cur_with({"role": "Admin"}), NEW,
      "bob@acme.com", WANT))
check("...a name held by another connection or guid: refused", not _only_approval(cur_with({**WANT, "guid": "other"}), NEW,
      "bob@acme.com", WANT) and not _only_approval(cur_with({**WANT, "directory": "s1"}), NEW, "bob@acme.com", WANT))
check("...the same directory account approved again (a forgotten PIN): signed", _only_approval(cur_with({**WANT, "box_pub": b64(os.urandom(32))}),
      NEW, "bob@acme.com", WANT) and _only_approval(CUR, NEW, "bob@acme.com", WANT))
to_ticket()
check("...another name than the ticket's", err(ask("sign_approval", ticket=to_ticket(), name="eve@acme.com", signed=proposal()))
      == "refused")
check("...a proposal that isn't canonical JSON: bad_request", err(sign(proposal() + " ")) == "bad_request"
      and err(sign("[1]")) == "bad_request" and err(sign("not json")) == "bad_request")
to_ticket()
check("release: a ticket for another name gives refused", err(ask("release", ticket=to_ticket(), name="eve@acme.com")) == "refused")
t = to_ticket(); T[0] += 601
check("release: an expired ticket gives refused", err(ask("release", ticket=t, name="bob@acme.com")) == "refused")
T[0] = time.time()
a = ask("release", ticket=SSO_TICKET, name="ann@example.com")
check("release: an SSO ticket gives the keys too", a.get("ok") and base64.b64decode(a["data_key"]) == DATA_KEY)

# ---------------------------------------------------------------- the failure count
to_ticket()                                         # a checked sign-in clears the count
answers = [ask("check_directory", connection="d1", login="bob@acme.com", password="wrong-pw") for _ in range(6)]
check("a wrong password gives refused and counts", [err(x) for x in answers[:5]] == ["refused"] * 5
      and HELPER._fails[OWNER][0] >= 5, [err(x) for x in answers])
check("six failures give throttled, 30 s", answers[5] == {"ok": False, "error": "throttled", "wait": 30}, answers[5])
a = ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")
check("throttled: even the right password waits", err(a) == "throttled" and 0 < a["wait"] <= 30, a)
check("throttled: status still answers", ask("status")["ok"])
check("throttled: another peer isn't", err(ask("nonce", "S-1-5-21-1-1003", connection="s1")) == "not_owner")
T[0] += 31
check("the wait over, the next failure waits 60 s", ask("check_directory", connection="d1", login="bob@acme.com", password="wrong-pw")
      == {"ok": False, "error": "throttled", "wait": 60})
T[0] += 61
check("the wait over: the right password works again", isinstance(to_ticket(), str))
T[0] = time.time()

# ---------------------------------------------------------------- an older signed keys file put back
session.sign_in("Admin1", PW)
roles.set_directories([ACME, {**SSO, "groups": {"Tech": ["g1"], "Engineer": ["g2"]}}])
session.sign_out()
NEWER = pathlib.Path(KEYS).read_bytes()
old_v, new_v = json.loads(ORIGINAL)["rules_version"], json.loads(NEWER)["rules_version"]
check("a newer signed file: accepted, its rules_version kept as the newest seen", new_v > old_v
      and not ask("status")["rules_changed"] and ST.load()["rules_version"] == new_v, (old_v, new_v, ST.load().get("rules_version")))
t = to_ticket()
pathlib.Path(KEYS).write_bytes(ORIGINAL)            # the older file, validly signed by the same key, put back
check("an older signed file put back: status says rules_changed", ask("status")["rules_changed"])
check("...release gives rules_changed and releases nothing", ask("release", ticket=t, name="bob@acme.com")
      == {"ok": False, "error": "rules_changed"})
check("...check_directory gives rules_changed",
      err(ask("check_directory", connection="d1", login="bob@acme.com", password="pw-bob")) == "rules_changed")
check("...a new helper on the same store refuses it too",
      server.Helper(ST, now=now).handle({"op": "status", "keys_path": KEYS}, OWNER)["rules_changed"])
pathlib.Path(KEYS).write_bytes(UNVERSIONED)         # the copy's file from before the count, signed by the same key
check("the unversioned original put back: rules_changed, release gives nothing", ask("status")["rules_changed"]
      and ask("release", ticket=t, name="bob@acme.com") == {"ok": False, "error": "rules_changed"})
pathlib.Path(KEYS).write_bytes(NEWER)
check("the newer file back: release works", ask("release", ticket=t, name="bob@acme.com").get("ok"))

# ---------------------------------------------------------------- forget
check("forget from the owner: ok, the store cleared", ask("forget") == {"ok": True} and ST.load() is None
      and not ST.path.exists() and not ask("status")["enrolled"])
check("after forget: another peer may enroll", enroll(OTHER) == {"ok": True} and ask("status", OTHER)["owner"])

# ---------------------------------------------------------------- no secret in an answer or the log
SECRETS = ["pw-bob", "wrong-pw", "135790", "000000", SKEY, b64(SKEY.encode()), b64(DATA_KEY), b64(RULES), PW]
seen = json.dumps(ANSWERS) + "\n".join(LOG)
FOUND = [s for s in SECRETS if s in seen] + [t for t in ["at-1"] if leaks([seen], [t])]    # "at-1" as a whole value: a released key is random
check("no password, code, Duo key or spare key in an answer or the log", not FOUND, FOUND)
check("released keys not in the log", not any(r["data_key"] in "\n".join(LOG) for r in RELEASED) and len(RELEASED) == 3)
check("no ID token in an answer or the log", len(TOKENS) > 10 and not any(t in seen for t in TOKENS))

P.stop()
srv.shutdown()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
