# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Directory sign-in steps (core/dirsignin.py) on ldap3's MOCK_SYNC, a fake local Duo and a fake security chip: the first sign-in
# with an admin's approval, the PIN after it, the offline hour, Duo refusals, a role change, a forgotten PIN, another computer.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dirsignin%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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
from core import audit, datakey, db, directory, dirpin, duo, osstore, passvault, pinslot, roles, session, tpm_windows
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
        (ADMINS, {"objectClass": "group", "cn": "Toner Admins"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"})]:
    c.strategy.add_entry(dn, attrs)
for upn, cn in (("bob@acme.com", "Bob"), ("carol@acme.com", "Carol"), ("dave@acme.com", "Dave")):
    ldap.dit[upn] = ldap.dit["CN=%s,OU=Users,%s" % (cn, BASE)]       # AD binds by UPN; the mock only knows DNs
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


# ---------------------------------------------------------------- set up: an Admin, an Engineer, the directory
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
as_("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")
roles.set_directories([ACME])
session.sign_out()

# ---------------------------------------------------------------- classify
check("classify DOMAIN\\user", S.classify("ACME\\bob")[0] == "directory" and S.classify("ACME\\bob")[1]["id"] == "d1"
      and S.classify("ACME\\bob")[2] == "ACME\\bob")
check("classify the domain in any case", S.classify("acme\\bob")[0] == "directory")
check("classify user@suffix", S.classify("bob@acme.com")[:1] == ("directory",) and S.classify("bob@ACME.com")[1]["id"] == "d1")
check("classify a suffix no directory lists: local", S.classify("bob@other.com") == ("local", "bob@other.com"))
check("classify a domain no directory has: local", S.classify("OTHER\\bob") == ("local", "OTHER\\bob"))
check("classify a plain name: local", S.classify(" admin ") == ("local", "admin"))
check("a local name can't begin a directory sign-in", raises(lambda: S.begin("admin", PW), ValueError) is not None)
as_("Admin1", PW)
datakey.add_local("ops@acme.com", PW2, role="Tech")
datakey.add_local("ACME\\ops", PW2, role="Tech")
session.sign_out()
check("a local account named like a directory suffix stays local", S.classify("OPS@Acme.com") == ("local", "OPS@Acme.com"))
check("...and one named like DOMAIN\\user", S.classify("acme\\OPS") == ("local", "acme\\OPS"))
check("...other names with that suffix are still the directory's", S.classify("bob@acme.com")[0] == "directory")

# ---------------------------------------------------------------- the first sign-in: password, Duo push, choose a PIN, approval, PIN
check("set_directories remembers the list on this computer",
      DIRS.get(dirpin.store_name()) == dirpin.fingerprint([ACME]).encode())
DIRS.pop(dirpin.store_name())
check("a local login never looks at it", S.classify("admin") == ("local", "admin") and dirpin.store_name() not in DIRS)
a = S.begin("ACME\\bob", "pw-bob")
check("the first directory sign-in remembers the list", DIRS.get(dirpin.store_name()) == dirpin.fingerprint([ACME]).encode())
check("begin: the password is checked online", a.stage == "password" and not a.offline and a.user.name == "bob@acme.com"
      and a.cfg["id"] == "d1", vars(a))
check("begin writes nothing before a PIN is chosen", datakey.directory_account("bob@acme.com") is None)
S.after_password(a)
check("Duo on: the Duo step", a.stage == "duo" and DUO["users"][-1] == "bob@acme.com")
check("a PIN can't be finished before Duo", raises(lambda: S.finish(a, PIN), RuntimeError) is not None)
S.duo_push(a, threading.Event())
check("an approved push: choose a PIN, with the first-sign-in text", a.stage == "choose-pin" and a.message ==
      "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it.", vars(a))
e = raises(lambda: S.choose_pin(a, "123456"), ValueError)
check("a simple PIN is refused with the approved sentence", e is not None and str(e) == "Avoid simple PINs like 123456."
      and a.stage == "choose-pin")
S.choose_pin(a, PIN)
rec = datakey.directory_account("bob@acme.com")
check("choose_pin: a chip slot and an unapproved record", a.stage == "approve" and rec["slot_kind"] == "chip"
      and rec["sealed"] is None and rec["groups_role"] == "Tech" and "Toner-" + rec["slot_id"] in FakeTpm.keys, rec)
e = raises(lambda: S.approve(a, "Eng1", PW2), S.CannotApprove)
check("an Engineer can't approve", e is not None and str(e) == "That account can't approve sign-ins." and a.stage == "approve"
      and datakey.directory_account("bob@acme.com")["sealed"] is None)
check("...and the key is closed again", session.state() == "signed_out" and not datakey.is_open() and not roles.holds("rules"))
before = fails()
check("a wrong admin password is refused", raises(lambda: S.approve(a, "Admin1", "not it at all"), datakey.WrongPassword) is not None
      and a.stage == "approve")
check("...and counted on the shared counter", fails() == before + 1, fails())
S.approve(a, "Admin1", PW)
check("approved: the PIN comes next, and nobody is signed in", a.stage == "pin" and session.state() == "signed_out"
      and not datakey.is_open() and not roles.holds("rules"))
check("...sealed with the approved role", datakey.directory_account("bob@acme.com")["approved_role"] == "Tech")
check("a wrong PIN is refused", raises(lambda: S.finish(a, "975310"), pinslot.WrongPin) is not None and a.stage == "pin")
S.finish(a, PIN)
check("the PIN signs Bob in", a.stage == "done" and session.state() == "open" and session.user() == "bob@acme.com"
      and session.kind() == "directory" and not session.workday_over())
check("audited: signed in (with the directory), approved, PIN set",
      rows("signed in")[0]["actor"] == "bob@acme.com" and rows("signed in")[0]["detail"] == "directory ACME"
      and rows("sign-in approved")[0]["detail"] == "bob@acme.com, approved by Admin1"
      and len(rows("PIN set")) == 1 and rows("PIN set")[0]["detail"] == "bob@acme.com", rows("signed in")[:1])
check("the wrong admin password before the approval is audited while the key was open",
      any(r["actor"] == "Admin1" for r in rows("1 failed sign-in attempts since the last sign-in")),
      rows("1 failed sign-in attempts since the last sign-in"))

# ---------------------------------------------------------------- the session's own steps for a directory account
session.lock()
check("unlock_pin: a wrong PIN", raises(lambda: session.unlock_pin("975310"), pinslot.WrongPin) is not None
      and session.state() == "locked")
session.unlock_pin(PIN)
check("unlock_pin: the right PIN opens", session.state() == "open")
session._full_at = time.time() - 12 * 3600 - 5
check("the workday is over after 12 hours", session.workday_over())
session.lock(reason="refused")
check("refused: the PIN can't unlock", raises(lambda: session.unlock_pin(PIN), session.Refused) is not None
      and session.refused() and session.state() == "locked")
check("refused: nor a password", raises(lambda: session.unlock(PW), session.Refused) is not None)
check("refused: the approved sentence", str(session.Refused(session.REFUSED)) ==
      "Your account can't sign in to Toner any more. Ask an admin.")
session.sign_out()
as_("Admin1", PW)
check("kind: a local account", session.kind() == "local" and not session.refused())
session.lock(); session.unlock(PW)
check("a new sign-in clears the refusal", session.state() == "open")
session.sign_out()
session.sign_in_recovery(recovery)
check("kind: the recovery key", session.kind() == "recovery")
session.sign_out()
check("kind: signed out", session.kind() is None)

# ---------------------------------------------------------------- the second sign-in: password, push, PIN
datakey.set_online("bob@acme.com", time.time() - 5000)
a = to_pin("bob@acme.com")
check("a second sign-in goes straight to the PIN", a.stage == "pin" and a.fresh
      and time.time() - datakey.directory_account("bob@acme.com")["online_at"] < 60)
S.finish(a, PIN)
check("...and opens", a.stage == "done" and session.user() == "bob@acme.com")
session.sign_out()

# ---------------------------------------------------------------- offline: within the hour the PIN alone, past it refused
directory._make_server = DOWN
checked = time.time() - 50 * 60
datakey.set_online("bob@acme.com", checked)
datakey.set_groups_role("bob@acme.com", "Engineer")            # a move up seen by the background check: "changed"
a = S.begin("ACME\\bob", "anything")
check("offline within the hour: the PIN", a.offline and a.stage == "pin" and a.user is None and not a.fresh)
check("offline: no Forgot your PIN?", raises(lambda: S.restart_pin(a), RuntimeError) is not None and a.stage == "pin")
S.finish(a, PIN)
check("offline: the PIN opens, never the approval (with the keys it already has)", a.stage == "done"
      and session.user() == "bob@acme.com" and not roles.holds("backups"))
real_time = time.time
time.time = lambda: real_time() + 11 * 3600 + 15 * 60
over = session.workday_over()
time.time = real_time
check("offline: the workday runs from the last online check, not the offline sign-in", over and not session.workday_over())
session.sign_out()
datakey.set_groups_role("bob@acme.com", "Tech")
datakey.set_online("bob@acme.com", time.time() - 3700)
e = raises(lambda: S.begin("bob@acme.com", "pw-bob"), directory.Unreachable)
check("offline past the hour: Unreachable, with the approved sentence",
      e is not None and str(e) == "Toner can't reach the directory. Connect to the network, then try again.")
check("offline, a name with no account here: Unreachable", raises(lambda: S.begin("ACME\\carol", "x"), directory.Unreachable) is not None)
directory._make_server = UP

# ---------------------------------------------------------------- wrong passwords, no group, and the wait
before = fails()
check("a wrong directory password: WrongPassword", str(raises(lambda: S.begin("bob@acme.com", "nope"), datakey.WrongPassword))
      == "That username or password isn't right.")
check("...counted", fails() == before + 1)
e = raises(lambda: S.begin("dave@acme.com", "pw-dave"), S.NotInGroup)
check("not in a Toner group: NotInGroup, with the approved sentence",
      e is not None and str(e) == "Your account isn't in a Toner group. Ask an admin." and fails() == before + 2)
d = doc(); d["throttle"] = {"fails": 9, "until": time.time() + 100}; datakey.path().write_text(json.dumps(d), encoding="utf-8")
check("while a wait runs the directory isn't asked", raises(lambda: S.begin("bob@acme.com", "pw-bob"), datakey.Throttled) is not None)
d = doc(); d["throttle"] = {"fails": 0, "until": 0}; datakey.path().write_text(json.dumps(d), encoding="utf-8")

for _ in range(4):
    raises(lambda: S.begin("bob@acme.com", "typo"), datakey.WrongPassword)
check("four typos counted", fails() == 4, fails())
a = to_pin()
check("the full online check clears the count", fails() == 0, fails())
S.finish(a, PIN)
check("...and the earlier count is audited once", len(rows("4 failed sign-in attempts since the last sign-in")) == 1)
session.sign_out()

# ---------------------------------------------------------------- Duo: unreachable, deny, enroll, a code
datakey.set_online("bob@acme.com", time.time() - 4000)
datakey.set_groups_role("bob@acme.com", "Engineer")            # the directory says Tech: written only once Duo passes
a = S.begin("bob@acme.com", "pw-bob")
DUO["down"] = True
e = raises(lambda: S.after_password(a), duo.Unavailable)
check("Duo unreachable: refused, with the approved sentence", e is not None and a.stage == "password"
      and str(e) == "Toner can't reach Duo, so you can't sign in right now. Try again in a minute.")
DUO["down"] = False
S.after_password(a)
DUO["push"] = "deny"
e = raises(lambda: S.duo_push(a, threading.Event()), duo.Denied)
check("Duo deny: refused, with the approved sentence", e is not None and str(e) == "Duo didn't approve the sign-in."
      and a.stage == "duo")
check("...the password alone doesn't start a new offline hour", time.time() - datakey.directory_account("bob@acme.com")["online_at"] > 3600)
check("...nor writes the groups' role", datakey.directory_account("bob@acme.com")["groups_role"] == "Engineer")
DUO["push"] = "allow"
e = raises(lambda: S.duo_code(a, "000000"), duo.Denied)
check("a wrong Duo code: refused", e is not None and str(e) == "That code isn't right." and a.stage == "duo")
S.duo_code(a, DUO["code"])
check("the right Duo code: the PIN, a new offline hour and the groups' role", a.stage == "pin"
      and time.time() - datakey.directory_account("bob@acme.com")["online_at"] < 60
      and datakey.directory_account("bob@acme.com")["groups_role"] == "Tech")
for result in ("deny", "enroll"):
    DUO["preauth"] = result
    a = S.begin("bob@acme.com", "pw-bob")
    check("preauth %s: refused" % result, raises(lambda: S.after_password(a), duo.Denied) is not None and a.stage == "password")
DUO["preauth"] = "auth"
a = S.begin("bob@acme.com", "pw-bob")
S.after_password(a)
real_push = duo.push
def late_push(cfg, user, cancel):          # while the push waits, the person enters a code and moves on
    cancel.set(); S.duo_code(a, DUO["code"]); S.restart_pin(a)
duo.push = late_push
S.duo_push(a, threading.Event())
duo.push = real_push
check("a push that comes back approved after the attempt moved on changes nothing", a.stage == "choose-pin" and a.reset)
a = to_pin()
S.finish(a, PIN)
check("Duo's refusals are audited once the key opens", len(rows("Duo denied a sign-in")) == 4
      and rows("Duo denied a sign-in")[0]["detail"] == "bob@acme.com", rows("Duo denied a sign-in"))
pin_rows = len(rows("PIN set"))
session.sign_out()

# ---------------------------------------------------------------- the groups move Bob to Engineer: approve again first
ldap.dit["bob@acme.com"]["memberOf"] = [ENGINEERS.encode()]
a = to_pin()
check("the groups' role is written at sign-in", datakey.directory_account("bob@acme.com")["groups_role"] == "Engineer")
before = fails()
check("changed: a wrong PIN is refused before the approval", raises(lambda: S.finish(a, "975310"), pinslot.WrongPin) is not None
      and a.stage == "pin" and fails() == before + 1)
CHIPFAILS.unlink()                                      # (three wrong chip PINs so far: the next try would wait for hours)
S.finish(a, PIN)
check("a role that may see unmasked backups: approval before the PIN opens", a.stage == "approve"
      and a.message == "Your access changed. Ask an admin to sign in here to approve it." and session.state() == "signed_out")
S.approve(a, "Admin1", PW)
check("approved: the PIN again", a.stage == "pin" and session.state() == "signed_out")
S.finish(a, PIN)
check("...opens as an Engineer holding the backups key", a.stage == "done" and roles.role_of("bob@acme.com") == "Engineer"
      and roles.holds("backups") and len(rows("PIN set")) == pin_rows)
session.sign_out()

# ---------------------------------------------------------------- forgot the PIN (approved while another session is open)
a = S.begin("bob@acme.com", "pw-bob")
S.after_password(a)
check("Forgot your PIN? needs Duo first", raises(lambda: S.restart_pin(a), RuntimeError) is not None and a.stage == "duo")
S.duo_push(a, threading.Event())
old_slot = datakey.directory_account("bob@acme.com")["slot_id"]
S.restart_pin(a)
check("Forgot your PIN?: choose a new one", a.stage == "choose-pin"
      and a.message == "Your access changed. Ask an admin to sign in here to approve it.")
check("...the old slot stays until the approval", "Toner-" + old_slot in FakeTpm.keys)
S.choose_pin(a, PIN2)
check("...still the old slot in the file", datakey.directory_account("bob@acme.com")["slot_id"] == old_slot and a.stage == "approve")

as_("Eng1", PW2)
was = (datakey._key, datakey.box_private(), datakey.signed_in_name(), roles.holds("backups"), roles.holds("rules"))
check("approval while a session is open: an Engineer still can't", raises(lambda: S.approve(a, "Eng1", PW2), S.CannotApprove)
      is not None)
check("...the session is untouched", (datakey._key, datakey.box_private(), datakey.signed_in_name(), roles.holds("backups"),
                                      roles.holds("rules")) == was and session.state() == "open" and session.user() == "Eng1")
raises(lambda: S.approve(a, "Admin1", "not it at all"), datakey.WrongPassword)
check("...nor by a wrong password", (datakey._key, datakey.box_private(), datakey.signed_in_name()) == was[:3] and a.stage == "approve")
S.approve(a, "Admin1", PW)
check("an Admin approves while Eng1 is signed in: Eng1's session is as it was",
      (datakey._key, datakey.box_private(), datakey.signed_in_name(), roles.holds("backups"), roles.holds("rules")) == was
      and session.state() == "open" and session.user() == "Eng1" and datakey.is_open() and a.stage == "pin")
check("...the old slot is gone, the new one sealed", "Toner-" + old_slot not in FakeTpm.keys
      and datakey.directory_account("bob@acme.com")["slot_id"] != old_slot)
check("...audited: PIN reset", len(rows("PIN reset")) == 1 and rows("PIN reset")[0]["detail"] == "bob@acme.com")
check("...credited to the Admin who approved, not the session's user",
      rows("sign-in approved")[0]["detail"] == "bob@acme.com, approved by Admin1" and rows("sign-in approved")[0]["actor"] == "Admin1")
session.sign_out()
check("the old PIN no longer opens", raises(lambda: S.finish(a, PIN), pinslot.WrongPin) is not None)
S.finish(a, PIN2)
check("the new PIN opens", a.stage == "done" and session.user() == "bob@acme.com")
session.sign_out()

# ---------------------------------------------------------------- another computer (the chip has no key): a new PIN, approved
FakeTpm.keys.clear()
a = to_pin()
S.finish(a, PIN2)
check("no key on this chip: choose a new PIN, with the access-changed text", a.stage == "choose-pin"
      and a.message == "Your access changed. Ask an admin to sign in here to approve it." and session.state() == "signed_out")
S.choose_pin(a, PIN3)
as_("Eng1", PW2)
S.approve_recovery(a, recovery)
check("the recovery key approves while Eng1 is signed in", a.stage == "pin" and session.user() == "Eng1"
      and datakey.signed_in_name() == "Eng1")
import getpass
check("...credited to the recovery key and the Windows user", rows("sign-in approved")[0]["detail"]
      == f"bob@acme.com, approved by recovery key ({getpass.getuser()})", rows("sign-in approved")[0]["detail"])
session.sign_out()
S.finish(a, PIN3)
check("the new PIN opens on this computer", a.stage == "done" and session.user() == "bob@acme.com")
check("audited: PIN set again", len(rows("PIN set")) == pin_rows + 1)
session.sign_out()
directory._make_server = DOWN
datakey.set_online("bob@acme.com", time.time() - 60)
FakeTpm.keys.clear()
a = S.begin("bob@acme.com", "pw-bob")
check("offline with no key on the chip: Unreachable (a new PIN needs the directory)",
      raises(lambda: S.finish(a, PIN3), directory.Unreachable) is not None and a.stage == "pin")
directory._make_server = UP

# ---------------------------------------------------------------- the chip can't be used: Forgot your PIN? falls back to the store
LONG, LONG2 = "a long store pin 1", "a long store pin 2"
CHIPFAILS.parent.mkdir(parents=True, exist_ok=True)
CHIPFAILS.write_text(json.dumps([time.time()] * 3), "utf-8")      # one more wrong PIN could lock the chip for hours
a = to_pin()
S.restart_pin(a)
check("the next chip PIN could lock it: Choose a PIN asks for the store's PIN", S.pin_kind(a) == "store")
e = raises(lambda: S.choose_pin(a, PIN), ValueError)
check("...a 6-digit PIN is refused with the 8-character rule", e is not None and str(e) == "Use at least 8 characters."
      and a.stage == "choose-pin")
S.choose_pin(a, LONG)
check("...a store slot, then approval as today", a.stage == "approve" and a.slot.rec["kind"] == "store")
S.approve(a, "Admin1", PW)
S.finish(a, LONG)
check("...and it signs in", a.stage == "done" and datakey.directory_account("bob@acme.com")["slot_kind"] == "store")
session.sign_out()
CHIPFAILS.unlink()
FakeTpm.locked = 1234                                  # Windows refuses even a new chip key while it is locked out
a = to_pin()
S.restart_pin(a)
check("a locked chip isn't known until it refuses a new key", S.pin_kind(a) == "chip")
e = raises(lambda: S.choose_pin(a, PIN2), ValueError)
check("...then the 6-digit PIN gets the 8-character rule", e is not None and str(e) == "Use at least 8 characters."
      and S.pin_kind(a) == "store" and a.stage == "choose-pin")
S.choose_pin(a, LONG2)
check("...a store slot, with approval", a.stage == "approve" and a.slot.rec["kind"] == "store")
S.approve(a, "Admin1", PW)
S.finish(a, LONG2)
check("...and it signs in", a.stage == "done" and datakey.directory_account("bob@acme.com")["slot_kind"] == "store")
FakeTpm.locked = 0
session.sign_out()

# ---------------------------------------------------------------- the held box key lost before approval (Toner restarted)
a = to_pin("carol@acme.com", "pw-carol")
S.choose_pin(a, PIN)
datakey._started.clear()
dropped = "Toner-" + datakey.directory_account("carol@acme.com")["slot_id"]
S.approve(a, "Admin1", PW)
check("the started box key gone: choose the PIN again, nothing approved", a.stage == "choose-pin" and a.slot is None
      and datakey.directory_account("carol@acme.com")["sealed"] is None and not datakey.is_open())
check("...the dropped slot's chip key is removed", dropped not in FakeTpm.keys)
S.choose_pin(a, PIN2)
S.approve(a, "Admin1", PW)
S.finish(a, PIN2)
check("...then approved and signed in", a.stage == "done" and session.user() == "carol@acme.com")
session.sign_out()

# ---------------------------------------------------------------- another approval error propagates; cleanup always runs
a = to_pin("carol@acme.com", "pw-carol")
S.restart_pin(a)
S.choose_pin(a, PIN3)
real_approve = roles.approve
def last_admin(*args, **kw): raise ValueError(roles.LAST_ADMIN)
roles.approve = last_admin
real_release = db.release
def broken_release(*args): raise RuntimeError("release failed")
db.release = broken_release
e = raises(lambda: S.approve(a, "Admin1", PW), ValueError)
roles.approve, db.release = real_approve, real_release
check("any other approval error propagates, the attempt stays at approve", e is not None and str(e) == roles.LAST_ADMIN
      and a.stage == "approve" and a.slot is not None)
check("...and the key is closed even when a cleanup step fails", not datakey.is_open() and not roles.holds("rules"))

# ---------------------------------------------------------------- the waiting audit rows are capped
session._soon.clear()
for i in range(500):
    session.audit_soon("Duo denied a sign-in", "x")
check("rows waiting for a sign-in are capped", 0 < len(session._soon) <= 100, len(session._soon))
session._soon.clear()

# ---------------------------------------------------------------- two directories can't claim one suffix or NetBIOS name
as_("Admin1", PW)
before = datakey.path().read_bytes()
check("two directories with one suffix are refused", raises(lambda: roles.set_directories(
    [ACME, {**ACME, "id": "d2", "name": "Other", "netbios": "OTHER", "suffixes": ["other.com", "ACME.com"]}]), ValueError) is not None)
check("two directories with one NetBIOS name are refused", raises(lambda: roles.set_directories(
    [ACME, {**ACME, "id": "d2", "name": "Other", "netbios": "acme", "suffixes": ["other.com"]}]), ValueError) is not None)
check("...nothing written", datakey.path().read_bytes() == before)
roles.set_directories([ACME, {**ACME, "id": "d2", "name": "Other", "netbios": "", "suffixes": ["other.com"]},
                       {**ACME, "id": "d3", "name": "Third", "netbios": "", "suffixes": ["third.com"]}])
check("two with no NetBIOS name are fine", len(doc()["directories"]) == 3)
roles.set_directories([ACME])
session.sign_out()

# ---------------------------------------------------------------- a hand-edited directories list pauses directory sign-in
PAUSED = "Directory sign-in is paused on this computer. An admin needs to sign in first."
binds = []
def COUNTING(cfg, host, *_): binds.append(host); return ldap
directory._make_server = COUNTING
good = datakey.path().read_bytes()

def edited(change):
    d = doc(); change(d["directories"][0]); datakey.path().write_text(json.dumps(d), encoding="utf-8")

opened = []
real_open, real_read_bytes, real_path_open = builtins.open, pathlib.Path.read_bytes, pathlib.Path.open
def recording(real):
    def fn(f, *a, **k):
        if "evil" in str(f):
            opened.append(str(f)); raise OSError("would block")
        return real(f, *a, **k)
    return fn
for what, change in (("a server", lambda c: c.update(servers=["ldap.evil.example"])),
                     ("a suffix", lambda c: c["suffixes"].append("evil.example")),
                     ("the CA file", lambda c: c.update(ca_file=r"\\evil\x"))):
    edited(change)
    builtins.open, pathlib.Path.read_bytes, pathlib.Path.open = recording(real_open), recording(real_read_bytes), recording(real_path_open)
    try:
        e = raises(lambda: S.begin("bob@acme.com", "pw-bob"), S.Paused)
    finally:
        builtins.open, pathlib.Path.read_bytes, pathlib.Path.open = real_open, real_read_bytes, real_path_open
    check("editing %s pauses directory sign-in, with the approved sentence, and binds nothing" % what,
          e is not None and str(e) == PAUSED and binds == [])
    check("...a local login still classifies", S.classify("admin") == ("local", "admin"))
    datakey.path().write_bytes(good)
check("...an edited CA path is never opened (a UNC path could block, or reach someone else)", opened == [], opened)
check("the list as remembered signs in again", S.begin("bob@acme.com", "pw-bob").stage == "password" and len(binds) == 1)

ca = os.path.join(SP, "acme-ca.pem")
with open(ca, "w") as f: f.write("one CA")
as_("Admin1", PW)
roles.set_directories([{**ACME, "ca_file": ca}], edited="d1")
session.sign_out()
check("set_directories remembers the new list (with its CA file)", S.classify("bob@acme.com")[0] == "directory")
check("...and signs the CA file's SHA-256 into it", doc()["directories"][0].get("ca_sha256") == hashlib.sha256(b"one CA").hexdigest())
with open(ca, "w") as f: f.write("another CA")
binds.clear()
e = raises(lambda: S.begin("bob@acme.com", "pw-bob"), S.CaChanged)
check("changing only the CA file's contents: refused in the approved words, and nothing binds",
      e is not None and str(e) == "The directory's CA file changed. An admin needs to save the directory again." and binds == [], (e, binds))
as_("Admin1", PW)
session.sign_out()
check("...a local Admin's 'ok' sign-in doesn't make it work again",
      raises(lambda: S.begin("bob@acme.com", "pw-bob"), S.CaChanged) is not None and binds == [], binds)
as_("Admin1", PW)
SIGNED = hashlib.sha256(b"one CA").hexdigest()
BETA = {**ACME, "id": "d2", "name": "Beta", "netbios": "BETA", "suffixes": ["beta.com"], "ca_file": ""}
roles.set_directories([{**ACME, "ca_file": ca}, BETA], edited="d2")
check("saving another directory keeps this one's signed CA hash (Ruling 32)", doc()["directories"][0].get("ca_sha256") == SIGNED)
session.sign_out()
check("...so its swapped CA file is still refused at connect",
      raises(lambda: S.begin("bob@acme.com", "pw-bob"), S.CaChanged) is not None and binds == [], binds)
as_("Admin1", PW)
check("another directory's save can't change this one's CA file path", raises(lambda: roles.set_directories(
    [{**ACME, "ca_file": os.path.join(SP, "other-ca.pem")}, BETA], edited="d2"), ValueError) is not None
    and doc()["directories"][0].get("ca_file") == ca)
roles.set_directories([{**ACME, "ca_file": ca}])
check("removing the other directory re-hashes none", [d["id"] for d in doc()["directories"]] == ["d1"]
      and doc()["directories"][0].get("ca_sha256") == SIGNED)
roles.set_directories([{**ACME, "ca_file": ca}], edited="d1")
check("saving this directory again re-hashes it", doc()["directories"][0].get("ca_sha256") == hashlib.sha256(b"another CA").hexdigest())
session.sign_out()
check("...set_directories again does", S.begin("bob@acme.com", "pw-bob").stage == "password" and len(binds) == 1, binds)
as_("Admin1", PW)
before = datakey.path().read_bytes()
check("a CA file that can't be read is refused", raises(lambda: roles.set_directories(
    [{**ACME, "ca_file": os.path.join(SP, "no-such-ca.pem")}], edited="d1"), ValueError) is not None)
check("...before anything is written", datakey.path().read_bytes() == before)
roles.set_directories([ACME], edited="d1")
session.sign_out()
check("no CA file: no ca_sha256 kept", "ca_sha256" not in doc()["directories"][0])
good = datakey.path().read_bytes()

edited(lambda c: c.update(servers=["ldap.evil.example"]))
as_("Admin1", PW)
check("a hand-edited file is tampered, and a sign-in doesn't remember it", roles.state() == "tampered"
      and raises(lambda: S.classify("bob@acme.com"), S.Paused) is not None)
session.sign_out()
datakey.path().write_bytes(good)
DIRS[dirpin.store_name()] = b"a list remembered before"
check("a list changed elsewhere pauses here", raises(lambda: S.classify("bob@acme.com"), S.Paused) is not None)
as_("Admin1", PW)
check("a local Admin's sign-in with the rules ok remembers the list", roles.state() == "ok"
      and DIRS.get(dirpin.store_name()) == dirpin.fingerprint([ACME]).encode())
session.sign_out()
check("...and directory sign-in works again", S.classify("bob@acme.com")[0] == "directory")

real_remember = dirpin.remember
def swap_first(*a, **k):                                         # the file changes after roles verified it, before the refresh
    edited(lambda c: c.update(servers=["ldap.evil.example"]))
    return real_remember(*a, **k)
dirpin.remember = swap_first
as_("Admin1", PW)
dirpin.remember = real_remember
session.sign_out()
check("a keys file swapped between the rules check and the refresh isn't pinned",
      DIRS.get(dirpin.store_name()) == dirpin.fingerprint([ACME]).encode()
      and raises(lambda: S.classify("bob@acme.com"), S.Paused) is not None)
datakey.path().write_bytes(good)
DIRS[dirpin.store_name()] = dirpin.fingerprint([ACME]).encode()

kp, other = datakey.path(), datakey.path().with_name("other.keys")
name = dirpin.store_name()
d = json.loads(good); d["directories"][0]["servers"] = ["ldap.evil.example"]; other.write_text(json.dumps(d), encoding="utf-8")
kp.unlink()
try:
    os.symlink(other, kp)
except (OSError, NotImplementedError):
    kp.write_bytes(good)
    print("  (skipped: symlinks can't be made here)")
else:
    check("netcheck.keys replaced by a symlink to another file keeps the folder's store name, and pauses",
          dirpin.store_name() == name and raises(lambda: S.classify("bob@acme.com"), S.Paused) is not None)
    kp.unlink(); kp.write_bytes(good)
other.unlink()
for k in [k for k in DIRS if k != name]: del DIRS[k]
check("...the real file again signs in", S.classify("bob@acme.com")[0] == "directory")

if sys.platform == "win32":
    check("Windows: the fingerprint file is outside the data folder, under %APPDATA%",
          dirpin.pins_file() == pathlib.Path(os.environ["APPDATA"], "Toner", "dirpins.json")
          and datakey.path().parent not in dirpin.pins_file().parents)
    edited(lambda c: c.update(servers=["ldap.evil.example"]))
    kept = dict(PEPPERS); PEPPERS.clear()                       # netcheck.store deleted along with the edit
    check("Windows: deleting netcheck.store doesn't re-pin an edited list", raises(lambda: S.classify("bob@acme.com"), S.Paused)
          is not None and dirpin.store_name() not in PEPPERS)
    PEPPERS.update(kept)
    datakey.path().write_bytes(good)
    store = datakey.path().with_name("netcheck.store")
    before = store.read_bytes() if store.exists() else None
    REAL_PUT("dirs:test", b"a fingerprint", dirpin.pins_file())
    check("Windows: the real store writes the named file (DPAPI), not netcheck.store",
          REAL_GET("dirs:test", dirpin.pins_file()) == b"a fingerprint" and dirpin.pins_file().exists()
          and b"a fingerprint" not in dirpin.pins_file().read_bytes()
          and (store.read_bytes() if store.exists() else None) == before and REAL_GET("dirs:test") is None)
    fake_put, fake_get = osstore.put, osstore.get
    osstore.put = lambda n, v, file=None: REAL_PUT(n, v, file) if file else PEPPERS.__setitem__(n, v)
    osstore.get = lambda n, file=None: REAL_GET(n, file) if file else PEPPERS.get(n)
    as_("Admin1", PW)
    session.sign_out()
    dirpin.pins_file().write_bytes(b"{not json")
    check("Windows: a corrupt dirpins.json pauses", raises(lambda: S.classify("bob@acme.com"), S.Paused) is not None)
    as_("Admin1", PW)
    session.sign_out()
    check("...until an ok sign-in writes a fresh one", S.classify("bob@acme.com")[0] == "directory"
          and json.loads(dirpin.pins_file().read_text("utf-8")).keys() == {dirpin.store_name()})
    osstore.put, osstore.get = fake_put, fake_get
else:
    check("elsewhere: the keyring, no file", dirpin.pins_file() is None)
    real_get = osstore.get
    def keyring_broke(name, file=None): raise RuntimeError("the Secret Service went away")
    osstore.get = keyring_broke
    check("elsewhere: a keyring error other than NoKeyring is no store (unguarded)", S.classify("bob@acme.com")[0] == "directory")
    osstore.get = real_get

name = dirpin.store_name()
DIRS.pop(name, None)
dirpin._avail = False                                            # no store when this process first asked; one came since
dirpin.remember(doc())
check("a stale 'no store' doesn't skip the put: it looks again off the thread",
      dirpin._looking.acquire(timeout=10) and DIRS.get(name) == dirpin.fingerprint([ACME]).encode() and dirpin._avail is True)
dirpin._looking.release()

DIRS[dirpin.store_name()] = b"a list remembered before"
osstore.available = lambda: False
dirpin._avail = None
check("no protected store: sign-in goes on unguarded", S.classify("bob@acme.com")[0] == "directory")
osstore.available = lambda: True
dirpin._avail = None
real_get = osstore.get
def no_keyring(name, file=None): raise passvault.NoKeyring("no keyring")
osstore.get = no_keyring
check("no keyring: sign-in goes on unguarded", S.classify("bob@acme.com")[0] == "directory")
osstore.get = real_get
del DIRS[dirpin.store_name()]

real_path = datakey.path
datakey.path = lambda: pathlib.Path(SP) / "one" / "netcheck.keys"
one = dirpin.store_name()
datakey.path = lambda: pathlib.Path(SP) / "two" / "netcheck.keys"
two = dirpin.store_name()
datakey.path = lambda: pathlib.Path(SP.upper()) / "ONE" / "NETCHECK.KEYS"
upper = dirpin.store_name()
datakey.path = real_path
check("two keys files get two store names", one != two and one.startswith("dirs:") and len(one) == 5 + 64)
check("...the same file in another case is the same one on Windows", (upper == one) == (sys.platform == "win32"))
directory._make_server = UP

# ---------------------------------------------------------------- nothing secret anywhere
as_("Admin1", PW)
text = datakey.path().read_text(encoding="utf-8") + json.dumps(audit.recent(5000)) + " ".join(MESSAGES)
secrets = [PW, PW2, PIN, PIN2, PIN3, LONG, LONG2, "pw-bob", "pw-carol", "pw-dave", "not it at all", DUO["code"], "000000", SKEY, recovery]
check("no password, PIN, Duo code or key in the keys file, the audit or a message", not any(s in text for s in secrets),
      [s for s in secrets if s in text])
session.sign_out()

srv.shutdown(); srv.server_close()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
