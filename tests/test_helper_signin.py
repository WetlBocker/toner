# Run directly (python tests/test_helper_signin.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched. Nothing is installed.
# First sign-ins through the helper service (core/dirsignin.py with core/helperclient.py), against an in-process
# core.helper.server.Helper, ldap3's MOCK_SYNC, a fake local Duo, a fake SSO provider and a fake security chip: with sign-in
# without approval on, the helper checks the sign-in and Toner approves as "group membership"; anything the helper can't or
# won't do falls back to the approval page, and the helper's keys never outlive the approval.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hsignin%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, http.server, json, logging, pathlib, threading, urllib.parse, uuid
import ldap3, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, duo, helperclient, oidc, osstore, pinslot, roles, session, tpm_windows, updates
from core import dirsignin as S
from core.helper import protocol, server, store
from fake_oidc import FakeProvider

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


# ---------------------------------------------------------------- fakes: the protected store, the chip, Duo, the directory, SSO
SKEY = b"Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
PEPPERS, PINS = {"duo:d1": SKEY}, {}
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

DUO = {"preauth": "auth", "push": "allow", "pushes": 0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_(self):
        n = int(self.headers.get("Content-Length") or 0)
        p = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        path = urllib.parse.urlsplit(self.path).path
        if path.endswith("preauth"): r = {"result": DUO["preauth"]}
        elif path.endswith("/auth") and p.get("factor") == "passcode": r = {"result": "allow" if p["passcode"] == "135790" else "deny"}
        elif path.endswith("/auth"): DUO["pushes"] += 1; r = {"txid": "t"}
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
PEOPLE = {"bob": TECHS, "carol": TECHS, "dan": TECHS, "frank": TECHS, "gus": TECHS, "hal": TECHS, "ivy": TECHS, "jay": TECHS, "kim": TECHS, "erin": ENGINEERS, "alice": ADMINS}
for who, group in PEOPLE.items():
    dn = f"CN={who},OU=Users,{BASE}"
    c.strategy.add_entry(dn, {"objectClass": "user", "userPrincipalName": f"{who}@acme.com", "sAMAccountName": who, "cn": who,
                              "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-" + who,
                              "memberOf": [group]})
    ldap.dit[f"{who}@acme.com"] = ldap.dit[dn]                         # AD binds by UPN; the mock only knows DNs
for dn, cn in ((ADMINS, "Toner Admins"), (ENGINEERS, "Toner Engineers"), (TECHS, "Toner Techs")):
    c.strategy.add_entry(dn, {"objectClass": "group", "cn": cn})
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._make_server = lambda cfg, host, *_: ldap

BINDS, IN_HELPER = [], [False]
real_connect = directory.connect
def counting_connect(cfg, who, password, *a, **k):
    BINDS.append("helper" if IN_HELPER[0] else "toner")
    return real_connect(cfg, who, password, *a, **k)
directory.connect = counting_connect

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()

def browse(url):
    """The person's browser: follows the provider's redirect back to Toner's loopback port."""
    def go():
        try:
            requests.get(url, timeout=10, **oidc._DIRECT)
        except requests.RequestException:
            pass
    threading.Thread(target=go, daemon=True).start()

LOG = []
class Keep(logging.Handler):
    def emit(self, record): LOG.append(self.format(record))
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.DEBUG)

# the helper, in this process, over the fake connect (as tests/test_helper_client.py)
xor = lambda b: bytes(x ^ 0x5A for x in b)
HSTORE = store.Store(pathlib.Path(_tmp.mkdtemp(prefix="netcheck_helper_")) / "helper.json", xor, xor)
HELPER = server.Helper(HSTORE)
UP, SENT = [True], []
ANSWER = [None]                         # a stand-in answer for some ops: fn(req) -> answer, or None for the helper's own

class FakeConn:
    ans = None
    def send_bytes(self, b):
        req = protocol.decode(b)
        SENT.append(req["op"])
        IN_HELPER[0] = True
        try:
            self.ans = protocol.encode((ANSWER[0] and ANSWER[0](req)) or HELPER.handle(req, "me"))
        finally:
            IN_HELPER[0] = False
    def poll(self, timeout): return self.ans is not None
    def recv_bytes(self, n): return self.ans
    def close(self): pass

def fake_connect():
    if not UP[0]:
        raise helperclient.NotRunning()
    return FakeConn()
helperclient._connect = fake_connect
helperclient.installed = lambda: True
updates.installed_kind = lambda: "installed"

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS], "Tech": [TECHS]},
        "duo": {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}}
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": ISS, "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
PW, PIN, PIN2 = "correct horse battery 42", "246813", "975318"
ANN = "ann@example.com"

def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))

def approvals():
    session.sign_in("Admin1", PW)
    try:
        return [r["detail"] for r in audit.recent(5000) if r["action"] == "sign-in approved"]
    finally:
        session.sign_out()

def no_keys():
    """Nothing of the helper's keys kept in this process: signed out, the data key closed, no role key held."""
    return session.state() == "signed_out" and datakey._key is None and datakey._box is None and roles._held == {}

def to_duo(who):
    a = S.begin(f"{who}@acme.com", "pw-" + who)
    S.after_password(a)
    return a

def first(who, pin=PIN):
    """A directory first sign-in up to choose_pin."""
    a = to_duo(who)
    S.duo_push(a, threading.Event())
    S.choose_pin(a, pin)
    return a

def sso():
    a = S.sso_start(SSO, ANN, open_url=browse)
    S.sso_wait(a, threading.Event())
    return a


# ---------------------------------------------------------------- set up: an Admin, the directory, the SSO connection, the helper
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME, SSO])
helperclient.enroll()
SPARE = HSTORE.load()["spare"]
SECRETS = [base64.b64encode(SPARE[:32]).decode(), base64.b64encode(SPARE[32:]).decode(), SPARE[:32].hex(), "pw-bob", PIN]
session.sign_out()
check("(sign-in without approval is on)", helperclient.state(datakey.path()) == "on" and S.helper_ready())
check("HELPER_APPROVER is the approved wording", S.HELPER_APPROVER == "group membership")

print("== an AD Tech's first sign-in: password and Duo push by the helper, then straight to the PIN")
class Watch(dict):
    """roles._held, noting every role key it is ever given."""
    seen = set()
    def __setitem__(self, k, v): Watch.seen.add(k); super().__setitem__(k, v)
    def update(self, *a, **k): Watch.seen.update(dict(*a, **k)); super().update(*a, **k)
roles._held = Watch(roles._held)
BINDS.clear(); SENT.clear()
a = to_duo("bob")
check("begin: the helper checked the password, Duo is pending at the helper", a.stage == "duo" and a.helper and a.ticket is None
      and a.name == "bob@acme.com" and a.role == "Tech" and a.user.guid, vars(a))
check("...Toner itself never bound to the directory: only the helper did", BINDS == ["helper"], BINDS)
S.duo_push(a, threading.Event())
check("the push through the helper: Choose a PIN, with the helper's ticket", a.stage == "choose-pin" and a.ticket and a.fresh)
S.choose_pin(a, PIN)
check("choose_pin: approved at once, no approval page: the PIN comes next", a.stage == "pin" and a.ticket is None and a.slot is None)
check("...the ops asked of the helper: the helper signed the approval", SENT == ["status", "check_directory", "duo_push", "release",
      "sign_approval"], SENT)
check("...the rules key was never held in this process", "rules" not in Watch.seen, Watch.seen)
check("...no key kept in this process after the approval", no_keys(), (datakey._key is None, list(roles._held)))
rec = datakey.directory_account("bob@acme.com")
check("...sealed and approved as a Tech", rec["sealed"] and rec["approved_role"] == "Tech" and rec["groups_role"] == "Tech", rec)
check("...no role key granted to it", "bob@acme.com" not in (doc().get("grants") or {}))
session.sign_in("Admin1", PW)
check("...and the rules the helper signed verify", roles.state() == "ok" and roles.verified()["accounts"]["bob@acme.com"]["approved_role"]
      == "Tech")
session.sign_out()
S.finish(a, PIN)
check("the PIN signs Bob in", a.stage == "done" and session.user() == "bob@acme.com")
session.sign_out()
check("...and once signed out, nothing is held", no_keys())
check("audited: approved by group membership", "bob@acme.com, approved by group membership" in approvals(), approvals())
check("still Toner's only bind count: one, the helper's", BINDS == ["helper"], BINDS)
check("the rules still check out after the helper's approval", (session.sign_in("Admin1", PW), roles.state())[1] == "ok")
session.sign_out()

print("== an SSO first sign-in: the nonce from the helper")
issued = set(HELPER._nonces)
a = S.sso_start(SSO, ANN, open_url=browse)
check("sso_start: the nonce is one the helper issued", a.browser.nonce in set(HELPER._nonces) - issued)
S.sso_wait(a, threading.Event())
check("...the provider was asked with it", P.authorize_seen[-1].get("nonce") == a.browser.nonce)
check("sso_wait: the helper checked the same sign-in (its nonce used up): a ticket", a.stage == "choose-pin" and a.ticket
      and a.name == ANN and a.browser.nonce not in HELPER._nonces)
S.choose_pin(a, PIN)
check("choose_pin: approved at once", a.stage == "pin" and no_keys())
S.finish(a, PIN)
check("...and the PIN signs Ann in", a.stage == "done" and session.user() == ANN)
session.sign_out()
check("audited: approved by group membership", f"{ANN}, approved by group membership" in approvals())

print("== a forgotten PIN while on: re-approved by the helper")
n = len(approvals())
a = to_duo("bob")
S.duo_push(a, threading.Event())
check("(an approved account: straight to the PIN, with a ticket)", a.stage == "pin" and a.ticket)
S.restart_pin(a)
S.choose_pin(a, PIN2)
check("the new PIN is approved by the helper", a.stage == "pin" and no_keys())
S.finish(a, PIN2)
check("...and signs in", a.stage == "done" and session.user() == "bob@acme.com")
session.sign_out()
after = approvals()
check("...audited once more, approved by group membership", len(after) == n + 1 and after[0] == "bob@acme.com, approved by group membership")

print("== the helper's no: counted once, and Toner never binds a second time")
BINDS.clear()
before = doc()["throttle"]["fails"]
try:
    S.begin("ivy@acme.com", "wrong")
    e = None
except Exception as x:
    e = x
check("a wrong password: WrongPassword, as today", isinstance(e, datakey.WrongPassword) and str(e) == datakey.WRONG, repr(e))
check("...counted once on the shared counter, one bind (the helper's)", doc()["throttle"]["fails"] == before + 1
      and BINDS == ["helper"], (BINDS, doc()["throttle"]))

print("== Duo says no at the helper's preauth: as today's Duo deny")
for i, answer in enumerate(("deny", "enroll")):
    DUO["preauth"] = answer
    BINDS.clear()
    before = doc()["throttle"]["fails"]
    try:
        S.begin("ivy@acme.com", "pw-ivy")
        e = None
    except Exception as x:
        e = x
    DUO["preauth"] = "auth"
    check(f"preauth {answer}: Denied with DUO_DENIED", isinstance(e, duo.Denied) and str(e) == S.DUO_DENIED, repr(e))
    check("...the right password is not counted as a failure", doc()["throttle"]["fails"] == before, doc()["throttle"])
    check("...and Toner never bound itself", BINDS == ["helper"], BINDS)
    session.sign_in("Admin1", PW)
    denied = [r for r in audit.recent(5000) if r["action"] == "Duo denied a sign-in"]
    session.sign_out()
    check("...audited as today: Duo denied a sign-in, by its name", len(denied) == i + 1 and denied[0]["detail"] == "ivy@acme.com"
          and denied[0]["actor"] == "ivy@acme.com", denied[:1])

print("== a Duo code through the helper")
a = to_duo("ivy")
try:
    S.duo_code(a, "000000")
    e = None
except Exception as x:
    e = x
check("a wrong code: Denied with WRONG_CODE", isinstance(e, duo.Denied) and str(e) == S.WRONG_CODE and a.stage == "duo", repr(e))
a = to_duo("ivy")
S.duo_code(a, "135790")
check("the right code: Choose a PIN, with a ticket", a.stage == "choose-pin" and a.ticket)
S.choose_pin(a, PIN)
check("...approved by the helper", a.stage == "pin" and no_keys())

print("== the helper stopped (NotRunning): today's flow, the approval page with FIRST")
UP[0] = False
ASKED = []
helperclient.installed = lambda: ASKED.append(1) or True
check("helper_ready: False, without asking the service manager whether it is installed", S.helper_ready() is False and not ASKED)
helperclient.installed = lambda: True
BINDS.clear()
a = first("carol")
check("Toner checked the password itself", BINDS == ["toner"], BINDS)
DOWN = "Toner's helper service isn't running, so an admin has to approve this one."
check("the approval page: FIRST, then why the helper didn't approve it; no ticket", a.stage == "approve" and S.HELPER_DOWN == DOWN
      and a.message == S.FIRST + " " + DOWN and a.ticket is None and not a.helper, a.message)
helperclient.installed = lambda: False
a = first("kim")
check("...the helper not installed at all (the switch was never on): FIRST alone", a.stage == "approve" and a.message == S.FIRST,
      a.message)
helperclient.installed = lambda: True
UP[0] = True

print("== the helper stops after the password: Toner's own Duo, the approval page")
a = to_duo("dan")
check("(the helper checked the password; Duo pending there)", a.stage == "duo" and a.helper)
UP[0] = False
pushes = DUO["pushes"]
S.duo_push(a, threading.Event())
check("Toner's own push went through: Choose a PIN, no ticket", a.stage == "choose-pin" and a.ticket is None
      and DUO["pushes"] == pushes + 1)
S.choose_pin(a, PIN)
check("...then the approval page with FIRST, and why", a.stage == "approve" and a.message == S.FIRST + " " + DOWN, a.message)
UP[0] = True

print("== a helper rules_changed answer: the approval page, and no keys")
ANSWER[0] = lambda req: {"ok": False, "error": "rules_changed"} if req["op"] == "release" else None
a = first("frank")
check("release refused: the approval page with FIRST", a.stage == "approve" and a.message == S.FIRST and a.ticket is None)
check("...and no key opened", no_keys())
ANSWER[0] = lambda req: {"ok": False, "error": "rules_changed"} if req["op"] == "check_directory" else None
BINDS.clear()
a = first("gus")
check("check_directory refused with rules_changed: Toner's own checks, the same password, nothing asked again",
      BINDS == ["toner"] and a.stage == "approve" and a.message == S.FIRST, (BINDS, a.stage))
ANSWER[0] = lambda req: {**HELPER.handle(req, "me"), "role": "Admin"} if req["op"] == "release" else None
a = first("hal")
check("release for another role than the attempt's: the approval page, no keys", a.stage == "approve" and no_keys())
other_rules = base64.b64encode(os.urandom(32)).decode()
ANSWER[0] = lambda req: {**HELPER.handle(req, "me"), "rules_private": other_rules} if req["op"] == "release" else None
ldap.dit["hal@acme.com"]["memberOf"] = [ADMINS.encode()]       # an Admin's ticket: the one kind that releases the rules key
a = to_duo("hal")
S.duo_push(a, threading.Event())
S.choose_pin(a, PIN)
check("a released rules key that isn't this copy's: the approval page, no keys, the rules untouched", a.stage == "approve"
      and a.message == S.FIRST and no_keys() and not datakey.directory_account("hal@acme.com")["sealed"])
ldap.dit["hal@acme.com"]["memberOf"] = [TECHS.encode()]
ANSWER[0] = lambda req: {"ok": False, "error": "refused"} if req["op"] == "sign_approval" else None
before = doc()
a = first("jay")
check("the helper won't sign the approval: the approval page, no keys, the file untouched", a.stage == "approve"
      and a.message == S.FIRST and no_keys() and not datakey.directory_account("jay@acme.com")["sealed"]
      and doc()["rules_sig"] == before["rules_sig"])
ANSWER[0] = lambda req: {"ok": True, "rules_sig": base64.b64encode(os.urandom(64)).decode()} if req["op"] == "sign_approval" else None
a = to_duo("jay")
S.duo_push(a, threading.Event())
S.choose_pin(a, PIN)
check("a signature that doesn't verify: the approval page, nothing written", a.stage == "approve" and no_keys()
      and not datakey.directory_account("jay@acme.com")["sealed"] and doc()["rules_sig"] == before["rules_sig"])
ANSWER[0] = lambda req: {**HELPER.handle(req, "me"), "data_key": base64.b64encode(os.urandom(32)).decode()} if req["op"] == "release" else None
real_get = db.get_setting
READS = []
db.get_setting = lambda key: (READS.append(key), real_get(key))[1]
a = to_duo("jay")
S.duo_push(a, threading.Event())
saved, nul = os.dup(2), os.open(os.devnull, os.O_WRONLY)
os.dup2(nul, 2)                         # (SQLCipher writes its own wrong-key lines to stderr)
try:
    S.choose_pin(a, PIN)
finally:
    os.dup2(saved, 2); os.close(saved); os.close(nul)
db.get_setting = real_get
check("a released data key that isn't this copy's: refused at the opener's database read, the approval page, nothing written",
      a.stage == "approve" and no_keys() and READS[:1] == ["rules_key"] and not datakey.directory_account("jay@acme.com")["sealed"]
      and doc()["rules_sig"] == before["rules_sig"], READS)
ANSWER[0] = None

print("== SSO: the helper names another guid than Toner's own check: refused, the approval page")
ANSWER[0] = lambda req: {**HELPER.handle(req, "me"), "guid": "someone-else"} if req["op"] == "check_sso" else None
P.id_claims = {"sub": "sub-2", "preferred_username": "zoe@example.com"}
a = S.sso_start(SSO, "zoe@example.com", open_url=browse)
S.sso_wait(a, threading.Event())
check("no ticket", a.stage == "choose-pin" and a.ticket is None)
S.choose_pin(a, PIN)
check("...the approval page with FIRST", a.stage == "approve" and a.message == S.FIRST)
ANSWER[0], P.id_claims = None, {}

print("== a helper-approved Engineer: masked backups until an Admin signs in")
check("(Engineers see unmasked backups)", roles._perms_in(doc().get("roles"), "Engineer")["unmasked"])
a = first("erin")
check("approved by the helper", a.stage == "pin")
g = doc().get("grants", {}).get("erin@acme.com", {})
check("no backups grant yet (the helper holds no backups key)", "backups" not in g, g)
session.sign_in("Admin1", PW)
check("after a local Admin signs in, the grant exists", "backups" in doc()["grants"].get("erin@acme.com", {}))
check("...and the signature still verifies", roles.state() == "ok")
session.sign_out()
S.finish(a, PIN)
check("Erin then holds the backups key", a.stage == "done" and roles.holds("backups"))
session.sign_out()

print("== a helper-approved person in an Admin group holds the rules key")
a = first("alice")
check("approved by the helper", a.stage == "pin" and no_keys())
S.finish(a, PIN)
session.sign_out()
a = to_duo("alice")
S.duo_push(a, threading.Event())
S.finish(a, PIN)
check("at the next sign-in: holds the rules key", a.stage == "done" and roles.holds("rules"))
session.sign_out()

print("== an approved Tech now in the Admin group: the change approved by the helper at the PIN")
ldap.dit["bob@acme.com"]["memberOf"] = [ADMINS.encode()]
a = to_duo("bob")
S.duo_push(a, threading.Event())
check("(at the PIN, a ticket in hand)", a.stage == "pin" and a.role == "Admin" and a.ticket)
S.finish(a, PIN2)
check("finish: approved by the helper and signed in, no approval page", a.stage == "done" and roles.holds("rules")
      and datakey.directory_account("bob@acme.com")["approved_role"] == "Admin")
session.sign_out()
check("...and nothing held once signed out", no_keys())

print("== no secret anywhere")
session.sign_in("Admin1", PW)
rows = json.dumps(audit.recent(5000))
check("the audit holds no helper key, password or PIN", not any(s in rows for s in SECRETS))
check("the log holds none", not any(s in line for line in LOG for s in SECRETS))
session.sign_out()

P.stop()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
