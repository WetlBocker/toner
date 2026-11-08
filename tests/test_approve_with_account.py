# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A directory or SSO Admin who has signed in on this computer before approves someone's first sign-in with their own sign-in and
# Toner PIN (core/dirsignin.py approve_with_account, and the sign-in window's nested approver window), on ldap3's MOCK_SYNC, a
# fake local Duo, a fake local SSO provider (tests/fake_oidc.py) and a fake security chip.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\approvewith%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import http.server, json, pathlib, threading, urllib.parse, uuid
import ldap3
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, duo, oidc, osstore, pinslot, roles, session, tpm_windows
from core import dirsignin as S
from fake_oidc import FakeProvider

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


# ---------------------------------------------------------------- fakes (as tests/test_dirsignin.py and tests/test_sso_signin.py)
PEPPERS, PINS = {"duo:d1": b"Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"}, {}
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
CHIPFAILS = pathlib.Path(os.environ["APPDATA"], "Toner", "chipfails.json")      # Windows' wrong chip PINs, as Toner counts them

DUO = {"push": "allow"}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        path = urllib.parse.urlsplit(self.path).path
        r = {"result": "auth"} if path.endswith("preauth") else {"txid": "t"} if path.endswith("/auth") else {"result": DUO["push"]}
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
PEOPLE = {"alice": ADMINS, "bob": TECHS, "carol": ENGINEERS, "dave": ADMINS, "erin": TECHS, "frank": TECHS}
for who, group in PEOPLE.items():
    dn = "CN=%s,OU=Users,%s" % (who.title(), BASE)
    c.strategy.add_entry(dn, {"objectClass": "user", "userPrincipalName": who + "@acme.com", "sAMAccountName": who, "cn": who.title(),
                              "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-" + who,
                              "memberOf": [group]})
    ldap.dit[who + "@acme.com"] = ldap.dit[dn]                         # AD binds by UPN; the mock only knows DNs
for dn, cn in ((ADMINS, "Toner Admins"), (ENGINEERS, "Toner Engineers"), (TECHS, "Toner Techs")):
    c.strategy.add_entry(dn, {"objectClass": "group", "cn": cn})
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
UP = lambda cfg, host, *_: ldap
def DOWN(cfg, host, *_): raise OSError("no route")
directory._make_server = UP

ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS], "Tech": [TECHS]},
        "duo": {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}}

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()
P.id_claims = {"groups": ["gA"]}                                        # ann@example.com is in the connection's Admin group
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": ISS, "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Admin": ["gA"], "Tech": ["g1"]},
       "group_names": {"gA": "Admins", "g1": "Techs"}, "everyone": None}
ANN = "ann@example.com"

def browse(url):
    """The person's browser: follows the provider's redirect back to Toner's loopback port."""
    def go():
        try:
            requests.get(url, timeout=10, **oidc._DIRECT)
        except requests.RequestException:
            pass
    threading.Thread(target=go, daemon=True).start()

PW = "correct horse battery 42"
PIN_A, PIN_B, PIN_C, PIN_E, PIN_ANN, PIN_F = "246813", "975318", "802461", "531642", "864209", "417529"
WRONG = "975310"

def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))

def fails():
    return doc()["throttle"]["fails"]

def rows(action):
    return [r for r in audit.recent(5000) if r["action"] == action]

def to_pin(who):
    a = S.begin(who + "@acme.com", "pw-" + who)
    S.after_password(a)
    S.duo_push(a, threading.Event())
    return a

def sso():
    a = S.sso_start(SSO, ANN, open_url=browse)
    S.sso_wait(a, threading.Event())
    return a

def first_time(a, pin):
    """A first sign-in approved by the local Admin, then signed in and out: the account has signed in here before."""
    S.choose_pin(a, pin)
    S.approve(a, "Admin1", PW)
    S.finish(a, pin)
    session.sign_out()

def closed():
    return session.state() == "signed_out" and not datakey.is_open() and not roles.holds("rules")

def sealed(name):
    return bool(datakey.directory_account(name)["sealed"])


# ---------------------------------------------------------------- set up: a local Admin; alice (Admin), carol (Engineer), ann (SSO Admin)
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME, SSO])
session.sign_out()
first_time(to_pin("alice"), PIN_A)
first_time(to_pin("carol"), PIN_C)
first_time(sso(), PIN_ANN)
check("set up: alice, carol and ann have signed in here before", all(sealed(n) for n in ("alice@acme.com", "carol@acme.com", ANN))
      and datakey.directory_account("alice@acme.com")["approved_role"] == "Admin"
      and datakey.directory_account(ANN)["approved_role"] == "Admin")

print("== approved wording")
check("NOT_HERE_BEFORE", S.NOT_HERE_BEFORE == "That account hasn't signed in on this computer before, so it can't approve here.")
check("CANNOT_APPROVE", S.CANNOT_APPROVE == "That account can't approve sign-ins.")

print("== who can't approve")
b = to_pin("bob")
S.choose_pin(b, PIN_B)
check("bob waits for an admin", b.stage == "approve" and not sealed("bob@acme.com"))

d = to_pin("dave")
e = raises(lambda: S.approve_with_account(b, d, PIN_A), S.CannotApprove)
check("an Admin with no record here: NOT_HERE_BEFORE", e is not None and str(e) == S.NOT_HERE_BEFORE, e)
check("...nothing approved, the key closed", b.stage == "approve" and not sealed("bob@acme.com") and closed())

e = raises(lambda: S.approve_with_account(b, to_pin("carol"), PIN_C), S.CannotApprove)
check("an Engineer who has signed in here: CANNOT_APPROVE", e is not None and str(e) == S.CANNOT_APPROVE, e)
check("...nothing approved, the key closed", b.stage == "approve" and not sealed("bob@acme.com") and closed())

ldap.dit["alice@acme.com"]["memberOf"] = [TECHS.encode()]
al = to_pin("alice")
datakey.set_groups_role("alice@acme.com", "Admin")                  # the stored role still says Admin; this sign-in's groups don't
e = raises(lambda: S.approve_with_account(b, al, PIN_A), S.CannotApprove)
check("an Admin whose groups no longer map to Admin: CANNOT_APPROVE", e is not None and str(e) == S.CANNOT_APPROVE
      and al.role == "Tech" and datakey.directory_account("alice@acme.com")["approved_role"] == "Admin", e)
check("...nothing approved, the key closed", b.stage == "approve" and not sealed("bob@acme.com") and closed())
ldap.dit["alice@acme.com"]["memberOf"] = [ADMINS.encode()]

al = to_pin("alice")
S.restart_pin(al)
S.choose_pin(al, PIN_F)
e = raises(lambda: S.approve_with_account(al, to_pin("alice"), PIN_A), S.CannotApprove)
check("an Admin can't approve their own new PIN: CANNOT_APPROVE", e is not None and str(e) == S.CANNOT_APPROVE, e)
check("...the old PIN slot is still the sealed one", al.stage == "approve"
      and datakey.directory_account("alice@acme.com")["slot_id"] != al.slot.slot_id and closed())

directory._make_server = DOWN
al = S.begin("alice@acme.com", "pw-alice")
directory._make_server = UP
e = raises(lambda: S.approve_with_account(b, al, PIN_A), S.CannotApprove)
check("an approver signed in offline (not checked online in this sign-in): CANNOT_APPROVE", al.offline and e is not None
      and str(e) == S.CANNOT_APPROVE, e)
check("...nothing approved", b.stage == "approve" and not sealed("bob@acme.com") and closed())

al = to_pin("alice")
before = fails()
e = raises(lambda: S.approve_with_account(b, al, WRONG), pinslot.WrongPin)
check("a wrong PIN: WrongPin, as at unlock", e is not None and str(e) == str(pinslot.WrongPin()), e)
check("...counted on the shared throttle", fails() == before + 1, (before, fails()))
check("...and approves nothing", b.stage == "approve" and not sealed("bob@acme.com") and closed())
CHIPFAILS.unlink(missing_ok=True)

print("== an AD Admin approves")
S.approve_with_account(b, al, PIN_A)
check("bob's record is sealed, and bob's PIN comes next", b.stage == "pin" and sealed("bob@acme.com")
      and datakey.directory_account("bob@acme.com")["approved_role"] == "Tech")
check("the session is unchanged: still signed out", closed())
check("...and alice's own sign-in never opened one", al.stage == "pin")
S.finish(b, PIN_B)
check("bob's PIN signs bob in", b.stage == "done" and session.user() == "bob@acme.com")
check("audited: approved by alice", rows("sign-in approved")[0]["detail"] == "bob@acme.com, approved by alice@acme.com"
      and rows("sign-in approved")[0]["actor"] == "alice@acme.com", rows("sign-in approved")[:1])
session.sign_out()

print("== an SSO Admin approves")
er = to_pin("erin")
S.choose_pin(er, PIN_E)
S.approve_with_account(er, sso(), PIN_ANN)
check("erin's record is sealed", er.stage == "pin" and sealed("erin@acme.com"))
check("the session is unchanged: still signed out", closed())
session.sign_in("Admin1", PW)
check("audited: approved by ann", rows("sign-in approved")[0]["detail"] == "erin@acme.com, approved by ann@example.com")
session.sign_out()

print("== approval while another session is open")
session.sign_in("Admin1", PW)
was = (datakey._key, datakey.box_private(), datakey.signed_in_name(), roles.holds("rules"))
er = to_pin("erin")
S.restart_pin(er)
S.choose_pin(er, PIN_F)
S.approve_with_account(er, to_pin("alice"), PIN_A)
check("Admin1's session is as it was", (datakey._key, datakey.box_private(), datakey.signed_in_name(), roles.holds("rules")) == was
      and session.user() == "Admin1" and er.stage == "pin")
session.sign_out()

# ---------------------------------------------------------------- the window
from PySide6.QtWidgets import QApplication, QLabel, QPushButton
app = QApplication([])
from ui import signinwindow
from ui.signinwindow import SignInWindow
Accepted = SignInWindow.DialogCode.Accepted

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def settle(w):
    return pump(lambda: not w._jobs)

def words_on(page):
    return [lab.text() for lab in page.findChildren(QLabel) if lab.text()] + [b.text() for b in page.findChildren(QPushButton)
                                                                               if not b.isHidden()]

print("== the window: approved wording")
check("APPROVE_WITH_ACCOUNT, APPROVER_TITLE, APPROVER_TEXT", signinwindow.APPROVE_WITH_ACCOUNT == "Approve with a directory account"
      and signinwindow.APPROVER_TITLE == "Admin approval" and signinwindow.APPROVER_TEXT ==
      "An admin who has signed in on this computer before signs in with their own account, then types their Toner PIN.")

w = SignInWindow(); w.show()
w.name.setText("frank@acme.com"); w.next.click()
w.pw.setText("pw-frank"); w.sign_in.click()
pump(lambda: w.pages.currentWidget() is w.choose_page)
w.pin1.setText(PIN_F); w.pin2.setText(PIN_F); w.choose_ok.click(); settle(w)
check("the approval page offers the link", w.pages.currentWidget() is w.approve_page and "Approve with a directory account"
      in words_on(w.approve_page), words_on(w.approve_page))
w.approve_with_account.click()
n = w.approver
check("the link opens the nested window on its name page", n is not None and n.isVisible() and n.approver_for is w.attempt
      and n.pages.currentWidget() is n.name_page)
check("...with the approved title and text", words_on(n.name_page)[1:] == [
    "Admin approval", "An admin who has signed in on this computer before signs in with their own account, then types their Toner PIN.",
    "Username or email", "Next"], words_on(n.name_page))

print("== the window: who can't approve")
n.name.setText("Admin1"); n.next.click()
check("a local name: CANNOT_APPROVE, on the name page", n.pages.currentWidget() is n.name_page
      and n.name_error.text() == S.CANNOT_APPROVE, n.name_error.text())
n.name.setText("dave@acme.com"); n.next.click()
check("a directory name: its password page, with no recovery key", n.pages.currentWidget() is n.password_page
      and "Use the recovery key" not in words_on(n.password_page), words_on(n.password_page))
n.pw.setText("pw-dave"); n.sign_in.click()
pump(lambda: n.pages.currentWidget() is n.name_page and n.name_error.text())
check("an Admin who hasn't signed in here: NOT_HERE_BEFORE, and the window stays", n.isVisible()
      and n.pages.currentWidget() is n.name_page and n.name_error.text() == S.NOT_HERE_BEFORE, n.name_error.text())
check("...no Choose a PIN for the approver", n.attempt is None and w.attempt.stage == "approve")

print("== the window: alice approves")
n.name.setText("alice@acme.com"); n.next.click()
n.pw.setText("pw-alice"); n.sign_in.click()
pump(lambda: n.pages.currentWidget() is n.pin_page)
check("the approver's PIN page: Approve, no Forgot your PIN?", n.pages.currentWidget() is n.pin_page
      and words_on(n.pin_page)[1:] == ["alice@acme.com", "PIN", "Approve", "Not you?"], words_on(n.pin_page))
n.pin.setText(WRONG); n.pin_ok.click(); settle(n)
check("a wrong PIN: the PIN page's own wording", n.pin_error.text() == "That PIN isn't right." and n.isVisible()
      and w.attempt.stage == "approve", n.pin_error.text())
CHIPFAILS.unlink(missing_ok=True)
n.pin.setText(PIN_A); n.pin_ok.click(); settle(n)
check("the right PIN approves and the nested window closes", n.result() == Accepted and not n.isVisible()
      and sealed("frank@acme.com"))
check("...the outer window routes frank to his PIN", w.pages.currentWidget() is w.pin_page and w.attempt.stage == "pin")
check("...no session was opened", closed())
w.pin.setText(PIN_F); w.pin_ok.click(); settle(w)
check("frank's PIN signs frank in", w.result() == Accepted and session.user() == "frank@acme.com")
check("...audited: approved by alice", rows("sign-in approved")[0]["detail"] == "frank@acme.com, approved by alice@acme.com")
session.sign_out()

# ---------------------------------------------------------------- nothing secret anywhere
session.sign_in("Admin1", PW)
text = datakey.path().read_text(encoding="utf-8") + json.dumps(audit.recent(5000)) + " ".join(MESSAGES)
secrets = [PW, PIN_A, PIN_B, PIN_C, PIN_E, PIN_ANN, PIN_F, WRONG] + ["pw-" + p for p in PEOPLE]
check("no password or PIN in the keys file, the audit or a message", not any(s in text for s in secrets),
      [s for s in secrets if s in text])
session.sign_out()

srv.shutdown(); srv.server_close()
P.stop()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
