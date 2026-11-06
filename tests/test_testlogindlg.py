# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Test login window (ui/testlogindlg.py) on ldap3's MOCK_SYNC and a fake local Duo: an Admin checks one directory user's
# password and Duo; every step on a Job; the password and code boxes emptied at the click and on close; nothing kept.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\testlogindlg%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
os.environ["LOCALAPPDATA"] = _tmp.mkdtemp(prefix="netcheck_localappdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import http.server, json, threading, urllib.parse, uuid
import ldap3
from core import audit, datakey, db, directory, duo, osstore, perms, pinslot, roles, session
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


# ---------------------------------------------------------------- fakes: the protected store, Duo, the directory
SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
PEPPERS = {"duo:d1": SKEY.encode()}
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: PEPPERS.__setitem__(n, v)
osstore.get = lambda n, file=None: PEPPERS.get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)
def no_slot(*a, **k): raise AssertionError("a test login made a PIN slot")
pinslot.new = no_slot                                   # (and never the real chip)

DUO = {"preauth": "auth", "push": "allow", "code": "135790", "down": False}
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

GATE = threading.Event()                                # a push waits for GATE (approved) or its cancel (refused)
PUSHES = []
real_push = duo.push
def gated_push(cfg, user, cancel):
    PUSHES.append(cancel)
    while not (GATE.is_set() or cancel.is_set()):
        time.sleep(0.01)
    if cancel.is_set():
        raise duo.Denied("cancelled")
    return real_push(cfg, user, cancel)
duo.push = gated_push

BASE = "DC=acme,DC=com"
ADMINS, ENGINEERS = "CN=Toner Admins," + BASE, "CN=Toner Engineers," + BASE
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
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"})]:
    c.strategy.add_entry(dn, attrs)
for upn, cn in (("bob@acme.com", "Bob"), ("dave@acme.com", "Dave")):
    ldap.dit[upn] = ldap.dit["CN=%s,OU=Users,%s" % (cn, BASE)]       # AD binds by UPN; the mock only knows DNs
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._make_server = lambda cfg, host, *_: ldap

DUO_ON = {"on": True, "host": f"127.0.0.1:{srv.server_port}", "ikey": "IK"}
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS]}, "duo": {"on": False}}
PW, PW2 = "correct horse battery 42", "engineers have long passwords 7"

from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui import signinwindow as W
from ui import testlogindlg as T
from ui import status
FAIL_INK = status.ink("FAIL")

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def rows():
    return [r for r in audit.recent(5000) if r["action"] == "test login"]

def as_(name, pw):
    session.sign_out()
    session.sign_in(name, pw)

def cfg():
    return next(d for d in roles.verified()["directories"] if d["id"] == "d1")

def held():
    return (session.state(), session.user(), datakey.is_open(), datakey.signed_in_name(), datakey._key, datakey.box_private(),
            tuple(roles.holds(k) for k in ("rules", "backups", "vault")))

def clear_wait():
    d = json.loads(datakey.path().read_text(encoding="utf-8"))
    d["throttle"] = {"fails": 0, "until": 0}
    datakey.path().write_text(json.dumps(d), encoding="utf-8")

def test(d, login, pw):
    """Type and press Test; True once every Job has landed."""
    d.user.setText(login)
    d.pw.setText("")
    d.pw.insert(pw)                                     # typed: on the box's undo history
    d.test_btn.click()
    d.cleared_at_click = d.pw.text() == ""
    return pump(lambda: not d._jobs)

def idle(d):
    return not d._jobs

recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
as_("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")
roles.set_directories([ACME])

# ---------------------------------------------------------------- the words
d = T.TestLoginDialog(cfg())
d.show()
check("title", d.windowTitle() == "Test login")
check("fields", (d.user.accessibleName(), d.pw.accessibleName(), d.test_btn.text()) == ("Username", "Password", "Test"))
check("the password is hidden", d.pw.echoMode() == W.QLineEdit.EchoMode.Password)
texts = [w.text() for w in d.push_page.findChildren(W.QLabel)] + [b.text() for b in d.push_page.findChildren(W.QPushButton)]
check("the push page", texts == [W.DUO_TITLE, W.DUO_TEXT, "Cancel", "Enter a code instead"], texts)
check("the code page", (d.code.accessibleName(), d.code_ok.text()) == ("Duo code", "Sign in"))
check("opens on the first page, no result", d.pages.currentWidget() is d.form_page and d.result.isHidden())

# ---------------------------------------------------------------- Duo off: a pass, a wrong password, an unmapped person
before, keys, n = held(), datakey.path().read_bytes(), len(rows())
check("a good test lands", test(d, "bob@acme.com", "pw-bob"))
check("...the password box empty after Test", d.cleared_at_click and d.pw.text() == "")
check("...shows TEST_OK", d.result.text() == S.TEST_OK.format(name="bob@acme.com", role="Engineer") and d.result.isVisible(),
      d.result.text())
check("...one row", len(rows()) == n + 1)
check("...the session, key and role keys in this process unchanged", held() == before)
check("...the keys file byte-identical", datakey.path().read_bytes() == keys)
check("...the finished test isn't kept", d.test is None)
d.pw.undo()
check("...undo can't bring the password back", d.pw.text() == "", d.pw.text())
check("...a pass isn't styled as a failure", FAIL_INK not in d.result.styleSheet(), d.result.styleSheet())

test(d, "bob@acme.com", "not bob's password")
check("a wrong password: the approved sentence", d.result.text() == "That username or password isn't right.", d.result.text())
check("...shown as a failure (signinwindow's error colour)", FAIL_INK in d.result.styleSheet(), d.result.styleSheet())
test(d, "dave@acme.com", "pw-dave")
check("an unmapped person: TEST_NOT_MAPPED", d.result.text() == S.TEST_NOT_MAPPED.format(name="dave@acme.com"), d.result.text())
clear_wait()

directory._make_server = lambda cfg, host, *_: (_ for _ in ()).throw(OSError("no route"))
test(d, "bob@acme.com", "pw-bob")
check("the directory unreachable: its sentence", d.result.text() == S.UNREACHABLE, d.result.text())
directory._make_server = lambda cfg, host, *_: ldap

doc = json.loads(datakey.path().read_text(encoding="utf-8"))
doc["throttle"] = {"fails": 9, "until": time.time() + 100}
datakey.path().write_text(json.dumps(doc), encoding="utf-8")
test(d, "bob@acme.com", "pw-bob")
check("a wait running: the wait sentence, Test off", d.result.text().startswith("Too many tries. Wait ")
      and not d.test_btn.isEnabled(), d.result.text())
d.close()
clear_wait()

as_("Eng1", PW2)
d = T.TestLoginDialog(cfg())
d.show()
test(d, "bob@acme.com", "pw-bob")
check("not an Admin: perms' sentence", d.result.text() == perms.REASON, d.result.text())
d.close()
as_("Admin1", PW)

# ---------------------------------------------------------------- Duo on
roles.set_directories([dict(ACME, duo=DUO_ON)], edited="d1")
before, n = held(), len(rows())
d = T.TestLoginDialog(cfg())
d.show()
GATE.clear()
d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
check("Duo: the push page while the push waits", pump(lambda: d.pages.currentWidget() is d.push_page and len(PUSHES) == 1))
check("...the push runs on a Job, the page stays on", len(d._jobs) == 1 and d.push_page.isEnabled())
GATE.set()
check("an approved push: back on the first page", pump(lambda: idle(d) and d.pages.currentWidget() is d.form_page))
check("...with TEST_OK", d.result.text() == S.TEST_OK.format(name="bob@acme.com", role="Engineer"), d.result.text())
check("...one row", len(rows()) == n + 1)

GATE.clear()
d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: d.pages.currentWidget() is d.push_page)
check("a new Test clears the last result", d.result.isHidden())
d.use_code.click()
check("Enter a code instead: the code page, the push cancelled", d.pages.currentWidget() is d.code_page and PUSHES[-1].is_set())
pump(lambda: idle(d))
check("...the cancelled push lands on nothing", d.pages.currentWidget() is d.code_page and len(rows()) == n + 1)
d.code.insert(DUO["code"]); d.code_ok.click()
check("...the code box empty at Sign in", d.code.text() == "")
check("a right code: the first page, TEST_OK", pump(lambda: idle(d) and d.pages.currentWidget() is d.form_page)
      and d.result.text() == S.TEST_OK.format(name="bob@acme.com", role="Engineer"), d.result.text())
check("...one row for the test", len(rows()) == n + 2)

d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: d.pages.currentWidget() is d.push_page)
d.use_code.click()
d.code.undo()
check("the code page again: undo can't bring the last code back", d.pages.currentWidget() is d.code_page and d.code.text() == "",
      d.code.text())
d.code.setText("000000"); d.code_ok.click()
check("a wrong code: the first page, its sentence", pump(lambda: idle(d) and d.pages.currentWidget() is d.form_page)
      and d.result.text() == S.WRONG_CODE, d.result.text())

n = len(rows())
d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: d.pages.currentWidget() is d.push_page)
d.duo_cancel.click()
check("Cancel: the first page, no result", d.pages.currentWidget() is d.form_page and d.result.isHidden()
      and PUSHES[-1].is_set())
check("...the push ends and lands on nothing, no row", pump(lambda: idle(d)) and d.result.isHidden() and len(rows()) == n)

d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: d.pages.currentWidget() is d.push_page)
d.use_code.click()
check("the code page has Cancel", d.code_cancel.text() == "Cancel" and d.code_cancel.isVisible())
d.code.setText("135"); d.code_cancel.click()
check("...it goes back to the first page, no result, the box empty", d.pages.currentWidget() is d.form_page and d.result.isHidden()
      and d.code.text() == "")
check("...nothing lands, no row", pump(lambda: idle(d)) and d.result.isHidden() and len(rows()) == n and d.test is None)

GOT = []
real_hook, real_check = sys.excepthook, S.TestLogin.check_password
sys.excepthook = lambda t, v, tb: GOT.append(v)
def odd(self, login, password):
    held_here = password                                # a frame that would keep the password
    raise ZeroDivisionError("unexpected")
S.TestLogin.check_password = odd
d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: idle(d) and GOT)
sys.excepthook, S.TestLogin.check_password = real_hook, real_check
def frames(e):
    tb = e.__traceback__
    while tb is not None:
        yield tb.tb_frame
        tb = tb.tb_next
check("an unexpected error: re-raised", len(GOT) == 1 and isinstance(GOT[0], ZeroDivisionError), GOT)
check("...with no frame keeping the password", GOT and not any("pw-bob" in [v for v in f.f_locals.values() if isinstance(v, str)]
                                                          for f in frames(GOT[0])))
GOT.clear()

d.user.setText("bob@acme.com"); d.pw.setText("pw-bob"); d.test_btn.click()
pump(lambda: d.pages.currentWidget() is d.push_page)
jobs = list(d._jobs)
d.code.setText("123")
d.close()
check("closing during a push cancels it and leaves no thread", PUSHES[-1].is_set() and not d._jobs
      and jobs and not any(j.isRunning() for j in jobs))
check("...the password and code boxes empty after close", d.pw.text() == "" and d.code.text() == "")
d.show(); d.pw.setText("left behind"); d.close()
check("...the password box is emptied on close as well", d.pw.text() == "")
check("the session in this process unchanged by every test", held() == before)
session.sign_out()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
