# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The background directory check (core/dircheck.py): each outcome, the timer, and that the service password is never written down.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dircheck%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import io, logging, threading, uuid
from dataclasses import replace
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, dircheck, osstore, passvault, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

_box = {}
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box.__setitem__((n, file), v)
osstore.get = lambda n, file=None: _box.get((n, file))
osstore.delete = lambda n: None


class FakeTpm:
    LockedOut = tpm_windows.LockedOut
    keys = {}

    @classmethod
    def lockout_threshold(cls): return 4

    @classmethod
    def available(cls): return True

    @classmethod
    def create(cls, name, pin):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        k, right = cls.keys[name]
        if pin != right: raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name): cls.keys.pop(name, None)


pinslot.tpm_windows = FakeTpm
pinslot.best_kind = lambda: "chip"

BASE = "DC=acme,DC=com"
TECHS, ENGINEERS = "CN=Toner Techs," + BASE, "CN=Toner Engineers," + BASE
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
G_BOB = uuid.uuid4()
SVC = "svc-pass-SECRET-4711"
for dn, attrs in [
        ("CN=Bob,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                     "objectGUID": G_BOB.bytes_le, "userAccountControl": 512, "userPassword": "pw-bob",
                                     "memberOf": [ENGINEERS]}),
        ("CN=svc," + BASE, {"objectClass": "user", "sAMAccountName": "svc", "cn": "svc", "objectGUID": uuid.uuid4().bytes_le,
                            "userAccountControl": 512, "userPassword": SVC}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"})]:
    c.strategy.add_entry(dn, attrs)
ldap.dit["bob@acme.com"] = ldap.dit["CN=Bob,OU=Users," + BASE]
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._make_server = lambda cfg, host, *_: ldap

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Tech": [TECHS], "Engineer": [ENGINEERS]}, "duo": {"on": False, "host": "", "ikey": ""}}
PW, PIN = "correct horse battery 42", "246813"
REFUSED_ROW = "locked: the directory refused the account"

def rows(action):
    return [r for r in audit.recent(5000) if r["action"] == action]

logs = io.StringIO()
logging.getLogger().addHandler(logging.StreamHandler(logs)); logging.getLogger().setLevel(1)

# ---------------------------------------------------------------- set up: an Admin, the directory, Bob signed in (Duo off)
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME])
session.sign_out()
a = S.begin("ACME\\bob", "pw-bob")
S.after_password(a)
S.choose_pin(a, PIN)
S.approve(a, "Admin1", PW)
S.finish(a, PIN)
check("set-up: Bob is signed in as a directory account", session.kind() == "directory" and session.user() == "bob@acme.com")

def put_svc():
    passvault.put("service:directory-d1", SVC)

def reopen():
    """A fresh Bob session after a refusal (the service password stays in the vault)."""
    session.sign_out()
    b = S.begin("bob@acme.com", "pw-bob"); S.after_password(b); S.finish(b, PIN)
    put_svc()

real_look_up, real_verified, real_state = directory.look_up, roles.verified, roles.state

def lookup_as(**kw):
    u = real_look_up(ACME, str(G_BOB), SVC)
    directory.look_up = lambda cfg, guid, pw: replace(u, **kw)

def boom(exc):
    def f(*a): raise exc
    return f

def snap():
    r = datakey.directory_account("bob@acme.com")
    return r["online_at"], r["groups_role"]

# ---------------------------------------------------------------- a missing service password: offline, nothing changed
datakey.set_online("bob@acme.com", 1000.0); datakey.set_groups_role("bob@acme.com", "Tech")
check("missing service password: offline", dircheck.run_once() == "offline")
check("...nothing changed", snap() == (1000.0, "Tech") and session.state() == "open")

# ---------------------------------------------------------------- ok
put_svc()
check("ok", dircheck.run_once() == "ok")
rec = datakey.directory_account("bob@acme.com")
check("ok: online_at and the groups role updated", time.time() - rec["online_at"] < 60 and rec["groups_role"] == "Engineer", rec)

# ---------------------------------------------------------------- unreachable, a config problem, a refused service bind
datakey.set_online("bob@acme.com", 1000.0); datakey.set_groups_role("bob@acme.com", "Tech")
for label, exc in (("unreachable", directory.Unreachable("x")), ("InsecureConfig", directory.InsecureConfig("ca changed")),
                   ("a refused service bind", directory.BadCredentials("bad"))):
    directory.look_up = boom(exc)
    check(label + ": offline, nothing changed", dircheck.run_once() == "offline" and session.state() == "open"
          and snap() == (1000.0, "Tech"))
directory.look_up = real_look_up

# ---------------------------------------------------------------- skipped: rules not verified
calls = []
directory.look_up = lambda *a: calls.append(a)
roles.state = lambda: "tampered"
check("tampered rules: skipped, and no look_up", dircheck.run_once() == "skipped" and not calls)
roles.state = real_state
roles.verified = lambda: None
check("no verified doc: skipped, and no look_up", dircheck.run_once() == "skipped" and not calls)
directory.look_up = real_look_up

# ---------------------------------------------------------------- the directory is gone from the verified list
roles.verified = lambda: {**real_verified(), "directories": []}
check("directory removed: refused", dircheck.run_once() == "refused")
check("...locked as refused, and audited", session.state() == "locked" and session.refused() and len(rows(REFUSED_ROW)) == 1)
roles.verified = real_verified
reopen()
check("a new sign-in opens again", session.state() == "open" and not session.refused())

# ---------------------------------------------------------------- not found, disabled, no group
directory.look_up = lambda *a: None
check("not found: refused", dircheck.run_once() == "refused" and session.refused())
reopen()
directory.look_up = boom(directory.NotFound("x"))
check("NotFound raised: refused", dircheck.run_once() == "refused" and session.refused())
for label, kw in (("disabled", {"enabled": False}), ("no group", {"groups": ()})):
    reopen()
    directory.look_up = real_look_up; lookup_as(**kw)
    check(label + ": refused", dircheck.run_once() == "refused" and session.state() == "locked" and session.refused())
check("every refusal audited", len(rows(REFUSED_ROW)) == 5, len(rows(REFUSED_ROW)))
check("an already-locked screen is refused again", dircheck.run_once() == "refused" and session.refused() and session.state() == "locked")
directory.look_up = real_look_up

# ---------------------------------------------------------------- not a directory session
session.sign_out()
check("signed out: skipped", dircheck.run_once() == "skipped")
session.sign_in("Admin1", PW)
check("a local session: skipped", dircheck.run_once() == "skipped" and session.state() == "open")
session.sign_out()

# ---------------------------------------------------------------- start / stop
n = []
dircheck.run_once = lambda: n.append(threading.current_thread().name) or "ok"
dircheck.start(interval=0.05, first=0.01)
dircheck.start(interval=0.05, first=0.01)
time.sleep(0.5)
check("start runs it soon and again, on the worker thread", len(n) >= 3 and set(n) == {"dircheck"}, n)
check("starting twice makes one timer", sum(t.name == "dircheck" for t in threading.enumerate()) == 1)
t0 = time.time(); dircheck.stop()
check("stop returns promptly and ends the thread", time.time() - t0 < 1 and not any(t.name == "dircheck" for t in threading.enumerate()))
k = len(n); time.sleep(0.2)
check("...and nothing runs after", len(n) == k)
dircheck.stop()
dircheck.start(interval=3600, first=0.01); time.sleep(0.2)
t0 = time.time(); dircheck.stop()
check("stop does not wait out a long interval", time.time() - t0 < 1 and len(n) == k + 1)

# ---------------------------------------------------------------- the service password is nowhere
session.sign_in("Admin1", PW)
check("the service password is in no log", SVC not in logs.getvalue())
check("the service password is in no audit row", not any(SVC in str(r) for r in audit.recent(5000)))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
