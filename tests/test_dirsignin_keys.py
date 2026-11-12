# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Directory sign-in with security keys (core/dirsignin.py), on test_dirsignin's fakes and a fake key: an account with a key skips
# Duo and the key proves it at the PIN; a forged key hint goes to Duo with nothing signed in; approvers' keys; SSO never has keys.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dirsigninkeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")       # as installed: the keys file isn't directly in %APPDATA%
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import builtins, hashlib, http.server, json, pathlib, threading, urllib.parse, uuid
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, dirpin, duo, fidokey, helperclient, osstore, passvault, pinslot, roles, session, tpm_windows, updates
from core.helper import protocol
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

MESSAGES = []
def raises(fn, exc):
    try:
        fn()
    except exc as e:
        MESSAGES.append(str(e))
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None


# ---------------------------------------------------------------- fakes: the protected store, the chip, Duo, the directory
SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
REAL_PUT, REAL_GET = osstore.put, osstore.get
PEPPERS = {"duo:d1": SKEY.encode()}     # netcheck.store on Windows; the keyring elsewhere
PINS = {}                               # a file the caller names (dirpins.json on Windows)
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)
DIRS = _box(dirpin.pins_file())         # where the directories fingerprint lives on this platform


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
        if cls.locked:
            raise tpm_windows.LockedOut(cls.locked)
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
G_BOB = uuid.uuid4()
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
for dn, attrs in [
        ("CN=Bob,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                     "objectGUID": G_BOB.bytes_le, "userAccountControl": 512, "userPassword": "pw-bob",
                                     "memberOf": [TECHS]}),
        ("CN=Carol,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "carol@acme.com", "sAMAccountName": "carol",
                                       "cn": "Carol", "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512,
                                       "userPassword": "pw-carol", "memberOf": [TECHS]}),
        ("CN=Dave,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "dave@acme.com", "sAMAccountName": "dave", "cn": "Dave",
                                      "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-dave"}),
        ("CN=Erin,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "erin@acme.com", "sAMAccountName": "erin", "cn": "Erin",
                                      "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-erin",
                                      "memberOf": [ADMINS]}),
        (ADMINS, {"objectClass": "group", "cn": "Toner Admins"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"})]:
    c.strategy.add_entry(dn, attrs)
for upn, cn in (("bob@acme.com", "Bob"), ("carol@acme.com", "Carol"), ("dave@acme.com", "Dave"), ("erin@acme.com", "Erin")):
    ldap.dit[upn] = ldap.dit["CN=%s,OU=Users,%s" % (cn, BASE)]       # AD binds by UPN; the mock only knows DNs
    ldap.dit["ACME\\" + upn.split("@")[0]] = ldap.dit[upn]              # ...or as DOMAIN\user, as typed
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

def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))

def rows(action):
    return [r for r in audit.recent(5000) if r["action"] == action]

def fails():
    return doc()["throttle"]["fails"]

CHIPFAILS = pathlib.Path(os.environ["APPDATA"], "Toner", "chipfails.json")      # Windows' wrong chip PINs, as Toner counts them

def as_(name, pw):
    session.sign_out()
    session.sign_in(name, pw)

def to_pin(login="bob@acme.com", password="pw-bob"):
    a = S.begin(login, password)
    S.after_password(a)
    S.duo_push(a, threading.Event())
    return a


# the helper switch, as helperclient.state reads it (tests/test_helper_client.py fakes the transport the same way)
HELPER_ON = [False]


class FakeConn:
    ans = None
    def send_bytes(self, b):
        req = protocol.decode(b)
        self.ans = protocol.encode({"protocol": protocol.PROTOCOL, "owner": True, "enrolled": True} if req["op"] == "status" else {})
    def poll(self, timeout): return True
    def recv_bytes(self, n): return self.ans
    def close(self): pass


def fake_connect():
    if not HELPER_ON[0]:
        raise helperclient.NotRunning()
    return FakeConn()


helperclient._connect = fake_connect
helperclient.installed = lambda: False
updates.installed_kind = lambda: "installed"

SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": "https://login.example.com", "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
SSO_USER = directory.User("sub-sso-user", "sso-user", "SSO User", ("g1",), True)
SPIN = "a long pin-only pin 3"
PIN4, PIN5, PIN6 = "531864", "697420", "813579"


def first_sign_in(login, password, pin):
    """A first sign-in through Duo, approved by Admin1 (no key yet), signed in, then signed out."""
    a = to_pin(login, password)
    S.choose_pin(a, pin)
    S.approve(a, "Admin1", PW, key=fake.value)
    S.finish(a, pin)
    session.sign_out()


def sign_in_until_pin(login, password):
    a = S.begin(login, password)
    S.after_password(a)
    return a


def forge_keys_n(name, n):
    d = doc()
    d["accounts"][name]["keys_n"] = n
    datakey.path().write_text(json.dumps(d), encoding="utf-8")


def lock_free():
    """True when another thread can take session's lock now (the caller is inside a touch)."""
    got = []
    def take():
        if session._lock.acquire(timeout=2):
            got.append(1)
            session._lock.release()
    t = threading.Thread(target=take); t.start(); t.join()
    return got == [1]


STATES = ("portable", "absent", "not_running", "outdated", "other_user", "rules_changed", "off", "on", "raises")
ALLOWED = {"off", "absent", "portable", "other_user"}             # helperclient.state: this copy is positively not enrolled


def state_is(st):
    def state(*a, **k):
        if st == "raises":
            raise OSError("the helper's state can't be read")
        return st
    return state


def signed_in_rows(who):
    return [r for r in rows("signed in") if r["actor"] == who]


# ---------------------------------------------------------------- set up: a keyed Admin, the directory with Duo, bob with a key
fake = fakekey.install()
recovery = datakey.create("Admin1", PW)
db.init()
cred, val = fake.register("Admin's key", os.urandom(32))
datakey.add_key(PW, cred, val, "Admin's key")
datakey.close()
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
roles.set_directories([ACME, SSO])
session.sign_out()
first_sign_in("bob@acme.com", "pw-bob", PIN)
first_sign_in("carol@acme.com", "pw-carol", PIN2)
first_sign_in("erin@acme.com", "pw-erin", PIN3)
session.sign_out()
slot = pinslot.new("pin", datakey.new_slot_id(), SPIN)
datakey.start_directory_account(SSO_USER, "s1", slot)
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
roles.approve("sso-user", slot)
session.sign_out()
a = sign_in_until_pin("bob@acme.com", "pw-bob")
a.stage = "duo"; S.duo_push(a, threading.Event())                  # (no key yet: Duo, as today)
S.finish(a, PIN)
bcred, bval = fake.register("Blue", os.urandom(32))
datakey.add_key(PIN, bcred, bval, "Blue")
session.sign_out()
seen = []
session.on_change(seen.append)

# ---------------------------------------------------------------- an account with a key skips Duo; the key proves it at the PIN
DUO["users"].clear()
full_at_before = datakey.directory_account("bob@acme.com")["full_at"]
online_before = datakey.directory_account("bob@acme.com")["online_at"]
time.sleep(0.01)
a = sign_in_until_pin("bob@acme.com", "pw-bob")
check("an account with a key is not asked for Duo", a.stage == "pin" and DUO["users"] == [] and a.duo_skipped and a.fresh)
check("the full check is not recorded before the key", datakey.directory_account("bob@acme.com")["full_at"] == full_at_before
      and datakey.directory_account("bob@acme.com")["online_at"] == online_before)
fake.touch = False
check("no touch: not signed in, nothing recorded, the PIN step stays", raises(lambda: S.finish(a, PIN, key=fake.value), fidokey.NotTouched)
      is not None and a.stage == "pin" and session.state() == "signed_out" and not datakey.is_open() and seen == []
      and datakey.directory_account("bob@acme.com")["full_at"] == full_at_before)
fake.touch = True
S.finish(a, PIN, key=fake.value)
check("after the key it is", a.stage == "done" and datakey.directory_account("bob@acme.com")["full_at"] > full_at_before
      and session.state() == "open" and session.user() == "bob@acme.com" and not session.session_over() and seen == ["open"])
session.lock()
fake.calls.clear()
session.unlock_pin(PIN, present=fake.present)
check("unlock with the PIN and a touch", session.state() == "open" and fake.calls == ["present"])
HELPER_ON[0] = True
e = raises(lambda: datakey.add_key(PIN, *fake.register("Red", os.urandom(32)), "Red"), ValueError)
check("with the helper switch on an AD account cannot add a key, in the approved words", e is not None and e.args[0]
      == 'Security keys can\'t be added to this account while "Let group members sign in without approval" is on.'
      and len(datakey.my_keys()) == 1)
check("...and keys_allowed says so; a local account is unaffected", not S.keys_allowed("bob@acme.com") and S.keys_allowed("Admin1"))
HELPER_ON[0] = False
check("with it off they are allowed again", S.keys_allowed("bob@acme.com"))
real_state, allowed, refused = helperclient.state, {}, {}
for st in STATES:
    helperclient.state = state_is(st)
    allowed[st] = S.keys_allowed("bob@acme.com")
    if st not in ALLOWED:
        e = raises(lambda: datakey.add_key(PIN, *fake.register("Red", os.urandom(32)), "Red"), ValueError)
        refused[st] = e is not None and e.args[0] == datakey.KEYS_HELPER_ON
helperclient.state = real_state
check("keys are allowed only when the helper's state says this copy isn't enrolled (fail closed)",
      allowed == {st: st in ALLOWED for st in STATES}, allowed)
check("...and add_key refuses in every other state, an unreadable one too", refused == {st: True for st in STATES if st not in ALLOWED}
      and len(datakey.my_keys()) == 1, refused)
session.sign_out()

# ---------------------------------------------------------------- a forged hint: Duo after all, and nothing saw a sign-in
forge_keys_n("carol@acme.com", 1)                                  # carol has no key; her record's hint is edited
DUO["users"].clear()
seen.clear()
full_at_carol = datakey.directory_account("carol@acme.com")["full_at"]
b = sign_in_until_pin("carol@acme.com", "pw-carol")
check("(the hint skips Duo)", b.stage == "pin" and b.duo_skipped and DUO["users"] == [])
fake.calls.clear()
S.finish(b, PIN2, key=fake.value)
check("a forged hint is sent back to Duo with nothing open", b.stage == "duo" and session.state() == "signed_out" and not datakey.is_open()
      and not b.duo_skipped and DUO["users"] == ["carol@acme.com"])
check("...no listener was told, the full check is not recorded, the key was never asked", seen == []
      and datakey.directory_account("carol@acme.com")["full_at"] == full_at_carol and fake.calls == [])
S.duo_push(b, threading.Event())
check("after Duo the full check is recorded and the PIN comes next", b.stage == "pin"
      and datakey.directory_account("carol@acme.com")["full_at"] > full_at_carol)
S.finish(b, PIN2)
check("and the PIN signs her in", b.stage == "done" and session.user() == "carol@acme.com" and seen == ["open"])
session.sign_out()

# ---------------------------------------------------------------- a skipped Duo is good only for the key at the PIN
# (a) a forged hint, then "Forgot your PIN?": Duo first, nothing written before it, then a new PIN and the approval as today
DUO["users"].clear()
full_at_carol = datakey.directory_account("carol@acme.com")["full_at"]
c = sign_in_until_pin("carol@acme.com", "pw-carol")               # (her hint is still forged)
S.restart_pin(c)
check("Forgot your PIN? on a skipped attempt: Duo next", c.stage == "duo" and DUO["users"] == ["carol@acme.com"] and not c.duo_skipped)
check("...no new PIN or approval before it, nothing written", raises(lambda: S.choose_pin(c, PIN2), RuntimeError) is not None
      and raises(lambda: S.approve(c, "Admin1", PW, key=fake.value), RuntimeError) is not None and c.stage == "duo"
      and datakey.directory_account("carol@acme.com")["full_at"] == full_at_carol)
S.duo_push(c, threading.Event())
check("after Duo: a new PIN to choose, with today's text, and the full check written", c.stage == "choose-pin" and c.reset
      and c.message == S.CHANGED and datakey.directory_account("carol@acme.com")["full_at"] > full_at_carol)
S.choose_pin(c, PIN2)
check("...then the approval as today", c.stage == "approve")

# (d) Duo refusing on these paths: still out, in today's words
DUO["preauth"] = "deny"
x = sign_in_until_pin("carol@acme.com", "pw-carol")
e = raises(lambda: S.restart_pin(x), duo.Denied)
check("Duo denies Forgot your PIN?: today's words, back at the PIN, still skipped", e is not None and str(e) == S.DUO_DENIED
      and x.stage == "pin" and x.duo_skipped and not x.reset and x.message is None)
e = raises(lambda: S.finish(x, PIN2, key=fake.value), duo.Denied)
check("...and a forged hint at the PIN: the same, nothing signed in", e is not None and str(e) == S.DUO_DENIED
      and x.stage == "pin" and session.state() == "signed_out" and not datakey.is_open())
DUO["preauth"], DUO["push"] = "auth", "deny"
S.restart_pin(x)
e = raises(lambda: S.duo_push(x, threading.Event()), duo.Denied)
check("a push denied after Forgot your PIN?: today's words, no new PIN", e is not None and str(e) == S.DUO_DENIED and x.stage == "duo")
DUO["push"] = "allow"

# a forged hint on an Admin approving with their own sign-in: refused
forge_keys_n("erin@acme.com", 1)
approver = sign_in_until_pin("erin@acme.com", "pw-erin")
check("(the approver's hint skips Duo)", approver.duo_skipped and approver.stage == "pin" and approver.fresh)
e = raises(lambda: S.approve_with_account(c, approver, PIN3, key=fake.value), S.CannotApprove)
check("an approver whose seal holds no key can't approve with a forged hint", e is not None and c.stage == "approve"
      and session.state() == "signed_out" and not datakey.is_open())

# ---------------------------------------------------------------- the approver's key, and a signed-in approver's session after it
# a sign-in, a lock or a sign-out while the approver touches their key: no approval, and the session as that left it
unsealed = lambda: datakey.directory_account("carol@acme.com")["slot_id"] != c.slot.slot_id
e = raises(lambda: S.approve(c, "Admin1", PW, key=lambda creds: session.sign_in("Admin1", PW, key=fake.value) or fake.value(creds)), RuntimeError)
check("a sign-in during the approver's touch: no approval, the new session intact", e is not None and c.stage == "approve" and unsealed()
      and session.state() == "open" and session.user() == "Admin1" and len(datakey.my_keys()) == 1 and roles.holds("rules"))
e = raises(lambda: S.approve(c, "Admin1", PW, key=lambda creds: session.lock() or fake.value(creds)), RuntimeError)
check("a lock during it: no approval, still locked with its keys", e is not None and c.stage == "approve" and unsealed()
      and session.state() == "locked" and datakey.is_open() and datakey.signed_in_name() == "Admin1" and len(datakey.my_keys()) == 1)
session.unlock(PW, present=fake.present)
e = raises(lambda: S.approve(c, "Admin1", PW, key=lambda creds: session.sign_out() or fake.value(creds)), RuntimeError)
check("a sign-out during it: no approval, nothing open", e is not None and c.stage == "approve" and unsealed()
      and session.state() == "signed_out" and not datakey.is_open())

# the approver's proof: never shown, opens once, as that account only
proof = datakey.prove_password("Admin1", PW, key=fake.value)
check("a proof shows nothing of itself", repr(proof) == "<datakey.Proof>" and not datakey.is_open())
check("...doesn't open as another account", raises(lambda: datakey.open_proof(proof, "bob@acme.com"), ValueError) is not None
      and not datakey.is_open())
proof = datakey.prove_password("Admin1", PW, key=fake.value)
check("...opens as its own account, once", datakey.open_proof(proof, "admin1") == 0 and datakey.signed_in_name() == "Admin1"
      and raises(lambda: datakey.open_proof(proof, "Admin1"), ValueError) is not None)
del proof
session.sign_out()

session.sign_in("Admin1", PW, key=fake.value)
fake.calls.clear()
free = []
S.approve(c, "Admin1", PW, key=lambda creds: free.append(lock_free()) or fake.value(creds))
check("an admin with a key approving someone: their key is asked, with session's lock free", c.stage == "pin" and fake.calls == ["value"]
      and free == [True])
check("...and their own session is as it was", session.user() == "Admin1" and len(datakey.my_keys()) == 1)
session.lock()
session.unlock(PW, present=fake.present)
check("the approver then unlocks with presence", session.state() == "open")
datakey.add_key(PW, *fake.register("Spare", os.urandom(32)), "Spare")
check("...and adds a key", [k["name"] for k in datakey.my_keys()] == ["Admin's key", "Spare"])
session.sign_out()
S.finish(c, PIN2)
check("(Carol signs in with her new PIN, audited as a reset)", c.stage == "done" and rows("PIN reset")[0]["detail"] == "carol@acme.com")
datakey.add_key(PIN2, *fake.register("Green", os.urandom(32)), "Green")
session.sign_out()

# a keyed account whose PIN slot is missing on this computer (its hint intact): Duo before the new PIN
FakeTpm.keys.pop("Toner-" + datakey.directory_account("carol@acme.com")["slot_id"])
DUO["users"].clear()
d = sign_in_until_pin("carol@acme.com", "pw-carol")
S.finish(d, PIN2, key=fake.value)
check("a missing slot on a skipped attempt: Duo first, nothing open", d.stage == "duo" and DUO["users"] == ["carol@acme.com"]
      and session.state() == "signed_out" and not datakey.is_open())
S.duo_push(d, threading.Event())
check("...then a new PIN, as for any missing slot", d.stage == "choose-pin" and d.message == S.CHANGED and not d.reset)
S.choose_pin(d, PIN4)
S.approve(d, "Admin1", PW, key=fake.value)
S.finish(d, PIN4)
check("...approved, signed in", d.stage == "done" and session.user() == "carol@acme.com")
session.sign_out()

# a changed role on a skipped attempt: Duo before the approval, then the approval as today
forge_keys_n("carol@acme.com", 1)
DUO["users"].clear()
k = sign_in_until_pin("carol@acme.com", "pw-carol")
k.role = "Admin"                                                    # (as if her groups now made her an Admin)
datakey.set_groups_role("carol@acme.com", "Admin")
S.finish(k, PIN4, key=fake.value)
check("a changed role on a skipped attempt: Duo first, no approval page", k.stage == "duo" and DUO["users"] == ["carol@acme.com"]
      and session.state() == "signed_out")
S.duo_push(k, threading.Event())
S.finish(k, PIN4)
check("...after Duo, the approval as today", k.stage == "approve" and k.message == S.CHANGED)

# (c) a keyed account's "Forgot your PIN?": Duo, a new PIN, the approval, and the approved record has no keys
DUO["users"].clear()
f = sign_in_until_pin("bob@acme.com", "pw-bob")
S.restart_pin(f)
check("a keyed account's Forgot your PIN?: Duo first", f.stage == "duo" and DUO["users"] == ["bob@acme.com"])
S.duo_push(f, threading.Event())
S.choose_pin(f, PIN5)
S.approve(f, "Admin1", PW, key=fake.value)
r = datakey.directory_account("bob@acme.com")
check("...then a new PIN and the approval; the approved record has no keys", f.stage == "pin" and "keyed" not in r and "keys_n" not in r)
fake.calls.clear()
S.finish(f, PIN5, key=fake.value)
check("...and the new PIN signs in without the key", f.stage == "done" and datakey.my_keys() == [] and fake.calls == [])
datakey.add_key(PIN5, *fake.register("Blue again", os.urandom(32)), "Blue again")
session.sign_out()

# (b) a keyed account whose keys an admin cleared: Duo is asked (no hint left), before the new PIN
session.sign_in("Admin1", PW, key=fake.value)
datakey.clear_keys("bob@acme.com")
session.sign_out()
DUO["users"].clear()
g = sign_in_until_pin("bob@acme.com", "pw-bob")
check("after an admin's clear: Duo, as for any account without a key", g.stage == "duo" and not g.duo_skipped and DUO["users"] == ["bob@acme.com"])
S.duo_push(g, threading.Event())
S.finish(g, PIN5)
check("...then a new PIN", g.stage == "choose-pin" and g.message == S.CHANGED)

# (e) a directory with Duo off: the paths are as before
session.sign_in("Admin1", PW, key=fake.value)
roles.set_directories([{**ACME, "duo": {**ACME["duo"], "on": False}}, SSO])
session.sign_out()
DUO["users"].clear()
h = sign_in_until_pin("erin@acme.com", "pw-erin")                  # (her hint is forged)
check("Duo off: nothing to skip, straight to the PIN", h.stage == "pin" and not h.duo_skipped)
S.restart_pin(h)
check("...and Forgot your PIN? goes straight to a new PIN, Duo never asked", h.stage == "choose-pin" and h.reset and DUO["users"] == [])
session.sign_in("Admin1", PW, key=fake.value)
roles.set_directories([ACME, SSO])
session.sign_out()

# ---------------------------------------------------------------- a keyed directory Admin approves with their own sign-in
d_ = doc(); d_["accounts"]["erin@acme.com"].pop("keys_n"); datakey.path().write_text(json.dumps(d_), encoding="utf-8")
e2 = to_pin("erin@acme.com", "pw-erin")
S.finish(e2, PIN3)
datakey.add_key(PIN3, *fake.register("Erin's key", os.urandom(32)), "Erin's key")
session.sign_out()
S.choose_pin(g, PIN6)                                               # (bob's new PIN, from the admin's clear)
approver = sign_in_until_pin("erin@acme.com", "pw-erin")
check("(a keyed Admin skips Duo)", approver.duo_skipped and approver.stage == "pin")
e = raises(lambda: S.approve_with_account(g, approver, PIN3, key=lambda creds: session.sign_in("Admin1", PW, key=fake.value)
                                          or fake.value(creds)), RuntimeError)
check("a sign-in during that approver's touch: no approval, the new session intact", e is not None and g.stage == "approve"
      and session.user() == "Admin1" and len(datakey.my_keys()) == 2)
session.sign_out()
free = []
S.approve_with_account(g, approver, PIN3, key=lambda creds: free.append(lock_free()) or fake.value(creds))
check("approve_with_account: the approver's key asked with session's lock free, and approved", g.stage == "pin" and free == [True]
      and session.state() == "signed_out" and not datakey.is_open())
S.finish(g, PIN6)
check("...and the approved PIN signs in", g.stage == "done" and session.user() == "bob@acme.com")
session.sign_out()

# ---------------------------------------------------------------- SSO: never asked for a key, never allowed one
fake.calls.clear()
s = S.Attempt(SSO, "sso-user")
s.user, s.name, s.role, s.stage, s.fresh = SSO_USER, "sso-user", "Tech", "pin", True
S.finish(s, SPIN, key=fake.value)
sso_sign_in_calls_no_key = s.stage == "done" and session.user() == "sso-user" and fake.calls == []
check("an SSO account is never asked for a key or allowed one", not S.keys_allowed("sso-user") and sso_sign_in_calls_no_key)
session.sign_out()

session.sign_in("Admin1", PW, key=fake.value)
check("the forged attempt left no signed-in row of its own", len(signed_in_rows("carol@acme.com")) == 4, len(signed_in_rows("carol@acme.com")))
check("no secret in the audit log", not any(x in str(r["detail"]) for r in audit.recent(5000) for x in (PW, PIN, PIN2, PIN3, PIN4, PIN5, PIN6, SPIN)))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
