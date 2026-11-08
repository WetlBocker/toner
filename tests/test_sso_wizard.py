# Run directly (python tests/test_sso_wizard.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# External Identities for SSO (ui/identitywizard.py) against a fake local provider and fake Microsoft Graph (tests/fake_oidc.py):
# the approved words, Entra's group search through an admin's sign-in, typed groups (Okta), a role for everyone (Google), a provider
# that can't be read, the client secret only on Save, no access token kept anywhere, Edit, and Test login on an SSO row.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ssowizard%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import json, threading, webbrowser
import requests
from core import audit, datakey, db, oidc, osstore, roles, session, ssopresets
from core import dirsignin as S
from fake_oidc import FakeProvider

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


# ---------------------------------------------------------------- fakes: the protected store, the provider, the browser
OS = {}
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: OS.__setitem__((n, file), v)
osstore.get = lambda n, file=None: OS.get((n, file))
osstore.delete = lambda n: OS.pop((n, None), None)

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()
oidc.GRAPH = ISS + "/graph"
P.graph_groups = [("id-net", "Network Admins"), ("id-help", "Helpdesk"), ("id-net2", "Network Admins")]
TENANT = "contoso-tenant"
real_issuer_for = ssopresets.issuer_for
ssopresets.issuer_for = lambda p, v: ISS if p == "entra" and v.strip() == TENANT else real_issuer_for(p, v)   # Entra's is https only

OPENED = []
def browse(url):
    OPENED.append(url)
    def go():
        try:
            requests.get(url, timeout=10, **oidc._DIRECT)
        except requests.RequestException:
            pass
    threading.Thread(target=go, daemon=True).start()
webbrowser.open = browse

PW = "correct horse battery 42"
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)


# ---------------------------------------------------------------- the window
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel
app = QApplication([])
from ui import identitywizard as IW
from ui import testlogindlg as TL
from ui.settings_pages import accounts as A

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def settle(w):
    return pump(lambda: not w._jobs)

KEEP = []
def wizard(*a):
    KEEP.append(IW.IdentityWizard(*a))
    return KEEP[-1]

def nxt(w):
    w.next_btn.click(); settle(w)
    return w.message.text()

def dirs():
    return list((roles.verified() or {}).get("directories") or [])

def to_connection(w, provider):
    """Choose a type (SSO) and the provider; leaves the flow on Connection."""
    next(r for r in w.kinds if r.text() == "SSO (OpenID Connect)").setChecked(True)
    nxt(w)
    w.providers[provider].setChecked(True)
    nxt(w)

def fill(w, issuer, client="toner-app", domains="acme.com", secret=""):
    w.issuer.setText(issuer); w.client_id.setText(client); w.domains.setText(domains); w.secret.setText(secret)

def group_rows(w):
    lst = w.lists["groups"]
    return [(lst.item(i).data(IW.GROUP_ID), lst.item(i).text()) for i in range(lst.count())]

def tick(w, gid):
    lst = w.lists["groups"]
    next(lst.item(i) for i in range(lst.count()) if lst.item(i).data(IW.GROUP_ID) == gid).setCheckState(Qt.CheckState.Checked)

def label_of(w, box):
    return w.sso_form.labelForField(box).text()

print("== the approved words")
check("constants", IW.SSO_TITLES == ("Choose a type", "Provider", "Connection", "Who can sign in", "Roles")
      and IW.FOUND == "Toner found {provider}'s sign-in settings."
      and IW.NOT_FOUND == "Toner couldn't read sign-in settings from {url}."
      and IW.LIST_GROUPS == "Sign in to list groups"
      and IW.LIST_GROUPS_TEXT == "Sign in with an Entra admin account. Toner uses it only to list and search groups, and keeps nothing but the groups you choose."
      and IW.TYPE_GROUPS_TEXT == "Type each group exactly as {provider} sends it, one per line."
      and IW.EVERYONE == "Role for everyone who signs in"
      and IW.SECRET == "Client secret (only if the provider requires one)")
w = wizard([], None)
to_connection(w, "entra")
w.back_btn.click()
check("step 2 is Provider: the five presets, Entra's note shown", w.title.text() == "Provider"
      and [r.text() for r in w.providers.values()] == ["Entra", "Okta", "Google Workspace", "Duo SSO", "Other"]
      and w.provider_note.text() == ssopresets.PRESETS["entra"]["note"] and w.provider_note.wordWrap())
w.providers["okta"].setChecked(True)
check("...another provider shows its own note", w.provider_note.text() == ssopresets.PRESETS["okta"]["note"])
nxt(w)
check("step 3 is Connection, with the approved labels (Okta: Issuer URL)", w.title.text() == "Connection"
      and [label_of(w, b) for b in (w.issuer, w.client_id, w.secret, w.domains, w.claim)]
      == ["Issuer URL", "App (client) ID", "Client secret (only if the provider requires one)", "Email domains", "Groups claim"]
      and w.claim.text() == "groups" and w.secret.echoMode() == w.secret.EchoMode.Password)
w.back_btn.click(); w.providers["entra"].setChecked(True); nxt(w)
check("...Entra asks for the Tenant ID", label_of(w, w.issuer) == "Tenant ID" and w.issuer.accessibleName() == "Tenant ID")
w.back_btn.click(); w.providers["google"].setChecked(True); nxt(w)
check("...Google's groups claim is empty", w.claim.text() == "")
w.reject()

print("== a provider that can't be read")
w = wizard([], None)
to_connection(w, "okta")
fill(w, "http://127.0.0.1:1/nothing-here")
check("NOT_FOUND with the URL, still on Connection", nxt(w) == "Toner couldn't read sign-in settings from http://127.0.0.1:1/nothing-here."
      and w.step == 2 and w.title.text() == "Connection", w.message.text())
fill(w, "not a url")
check("...a URL that isn't one: NOT_FOUND too", nxt(w) == "Toner couldn't read sign-in settings from not a url." and w.step == 2)
w.reject()

print("== Entra: an admin's sign-in lists groups, the filter searches Graph")
w = wizard([], None)
to_connection(w, "entra")
fill(w, TENANT, secret="")
check("FOUND, on Who can sign in", nxt(w) == "Toner found Entra's sign-in settings." and w.step == 3
      and w.title.text() == "Who can sign in", w.message.text())
check("...the Entra sign-in button and its text, Groups only (no OUs)", w.list_btn.text() == "Sign in to list groups"
      and w.list_btn.isVisibleTo(w) and w.list_text.text() == IW.LIST_GROUPS_TEXT and w.list_text.isVisibleTo(w)
      and not w.lists["ous"].isVisibleTo(w) and not w.filters["ous"].isVisibleTo(w) and w.lists["groups"].isVisibleTo(w))
check("Next with nothing ticked is refused", nxt(w) == "Choose at least one OU or group." and w.step == 3)
P.authorize_seen.clear(); OPENED.clear()
w.list_btn.click()
pump(lambda: group_rows(w) and not w._jobs)
q = P.authorize_seen[-1] if P.authorize_seen else {}
check("the admin's sign-in: Graph's scope, fresh, with a nonce", q.get("scope") == "openid profile GroupMember.Read.All"
      and q.get("prompt") == "login" and q.get("max_age") == "0" and q.get("nonce") and q.get("code_challenge_method") == "S256", q)
check("...the first page of groups listed, by id (two share a name)", group_rows(w) == P.graph_groups, group_rows(w))
check("...the token is on the window only", w._token == "at-1")
P.graph_seen.clear()
w.filters["groups"].setText("Net")
check("the filter narrows at once", [w.lists["groups"].item(i).text() for i in range(3) if not w.lists["groups"].item(i).isHidden()]
      == ["Network Admins", "Network Admins"])
check("...and Graph is searched after the pause", pump(lambda: any("$search" in s[1] for s in P.graph_seen)) and settle(w))
seen = next((s for s in P.graph_seen if "$search" in s[1]), None)
check("...for the typed text", seen and seen[1]["$search"] == '"displayName:Net"' and seen[0] == "/graph/groups", seen)
tick(w, "id-net")
nxt(w)
check("Roles: the group's name, not its id", w.step == 4 and w.title.text() == "Roles" and list(w.role_boxes) == ["id-net"]
      and w.role_labels["id-net"].text() == "Network Admins" and not w.base_dn.isVisibleTo(w) and w.name.text() == "Entra")
w.role_boxes["id-net"].setCurrentText("Admin")
w.name.setText("Contoso")
w.save_btn.click(); settle(w)
d = next((x for x in dirs() if x.get("kind") == "oidc"), {})
check("Saved: kind oidc, the issuer from issuer_for, groups and group_names", d.get("issuer") == ssopresets.issuer_for("entra", TENANT)
      and d.get("provider") == "entra" and d.get("client_id") == "toner-app" and d.get("groups") == {"Admin": ["id-net"], "Engineer": [], "Tech": []}
      and d.get("group_names") == {"id-net": "Network Admins"} and d.get("everyone") is None and d.get("id_claim") == "oid"
      and d.get("groups_claim") == "groups" and d.get("suffixes") == ["acme.com"] and d.get("name") == "Contoso", d)
check("...no secret typed, none stored", not any(k[0].startswith("oidc:") for k in OS))
check("...and the token dropped with the window", w._token is None and w.result())
ENTRA = d

def no_token_anywhere():
    rows = db.connect().execute("SELECT key, value FROM settings").fetchall()
    text = (datakey.path().read_text(encoding="utf-8") + json.dumps([list(r) for r in rows]) + repr(OS) + repr(STORE)
            + json.dumps([dict(r) for r in audit.recent(5000)]))
    return all(t not in text for t in ("at-1", "at-2", "rt-1", "rt-2"))
check("no access or refresh token in the keys file, the settings, the protected store, the vault or the audit", no_token_anywhere())

print("== Okta: typed groups, and a client secret on Save only")
w = wizard(dirs(), None)
to_connection(w, "okta")
fill(w, ISS + "/", domains="okta.example, OKTA.example, b.example", secret="s3cret-typed")
check("FOUND (the trailing slash dropped)", nxt(w) == "Toner found Okta's sign-in settings." and w.step == 3)
check("...the typed groups box and its words, no Entra button, no role for everyone", w.typed.isVisibleTo(w)
      and w.typed_text.text() == "Type each group exactly as Okta sends it, one per line." and not w.everyone.isVisibleTo(w)
      and not w.list_btn.isVisibleTo(w))
check("...the secret not stored before Save", not any(k[0].startswith("oidc:") for k in OS))
check("Next with nothing typed is refused", nxt(w) == "Choose at least one OU or group." and w.step == 3)
w.typed.setPlainText("Toner Admins\n  Toner Techs \n\nToner Admins\n")
nxt(w)
check("Roles: each typed group once", list(w.role_boxes) == ["Toner Admins", "Toner Techs"])
w.role_boxes["Toner Admins"].setCurrentText("Admin")
w.name.setText("Okta")
w.save_btn.click(); settle(w)
d = next((x for x in dirs() if x.get("provider") == "okta"), {})
check("Saved: the typed groups by role, no group names, no everyone", d.get("groups") == {"Admin": ["Toner Admins"], "Engineer": [], "Tech": ["Toner Techs"]}
      and d.get("group_names") == {} and d.get("everyone") is None and d.get("issuer") == ISS and d.get("suffixes") == ["okta.example", "b.example"], d)
check("...the secret in the protected store, the box emptied", OS.get(("oidc:" + d.get("id", ""), None)) == b"s3cret-typed"
      and w.secret.text() == "")
check("...and nowhere else", "s3cret-typed" not in datakey.path().read_text(encoding="utf-8") + json.dumps([dict(r) for r in audit.recent(5000)]))
OKTA = d

print("== Google: a role for everyone, no groups")
w = wizard(dirs(), None)
to_connection(w, "google")
fill(w, ISS, domains="gmail.example")
nxt(w)
check("Who can sign in shows only the role for everyone", w.step == 3 and w.everyone.isVisibleTo(w) and w.everyone_label.text() == "Role for everyone who signs in"
      and not w.typed.isVisibleTo(w) and not w.list_btn.isVisibleTo(w) and w.everyone.currentText() == "Tech")
w.everyone.setCurrentText("Engineer")
nxt(w)
check("...Roles has no group rows", w.step == 4 and not w.role_boxes)
w.name.setText("Google")
w.save_btn.click(); settle(w)
d = next((x for x in dirs() if x.get("provider") == "google"), {})
check("Saved: everyone and no groups", d.get("everyone") == "Engineer" and d.get("groups") == {"Admin": [], "Engineer": [], "Tech": []}
      and d.get("groups_claim") is None and d.get("group_names") == {}, d)

print("== an email domain another connection has")
w = wizard(dirs(), None)
to_connection(w, "other")
fill(w, ISS, domains="acme.com")
nxt(w); w.typed.setPlainText("x"); nxt(w); w.name.setText("Dup")
w.save_btn.click(); settle(w)
check("TAKEN, not saved", w.message.text() == "Another directory already uses acme.com." and not w.result()
      and len(dirs()) == 3, w.message.text())
w.reject()

print("== Edit opens with the saved values")
w = wizard(dirs(), OKTA)
check("SSO, the type and provider fixed", w.kinds[2].isChecked() and not w.kinds[2].isEnabled() and w.providers["okta"].isChecked()
      and not w.providers["okta"].isEnabled())
nxt(w); nxt(w)
check("...Connection as saved, the secret box empty", w.step == 2 and w.issuer.text() == ISS and w.client_id.text() == "toner-app"
      and w.domains.text() == "okta.example, b.example" and w.claim.text() == "groups" and w.secret.text() == "")
nxt(w)
check("...the typed groups", w.step == 3 and w.typed.toPlainText() == "Toner Admins\nToner Techs")
nxt(w)
check("...and their roles", {g: b.currentText() for g, b in w.role_boxes.items()} == {"Toner Admins": "Admin", "Toner Techs": "Tech"}
      and w.name.text() == "Okta")
w.save_btn.click(); settle(w)
check("Saving with the secret box empty keeps the stored secret", OS.get(("oidc:" + OKTA["id"], None)) == b"s3cret-typed" and w.result())
w = wizard(dirs(), ENTRA)
check("Entra Edit: the Tenant ID read back from Entra's issuer", wizard(dirs(), {**ENTRA, "issuer": real_issuer_for("entra", "t-42")}).issuer.text()
      == "t-42")
nxt(w); nxt(w); w.issuer.setText(TENANT); nxt(w)
check("...the saved group listed by name and ticked, before any sign-in", w.step == 3 and group_rows(w) == [("id-net", "Network Admins")]
      and w.lists["groups"].item(0).checkState() == Qt.CheckState.Checked and w._token is None)
w.filters["groups"].setText("Help")
time.sleep(0.6); app.processEvents()
check("...with no admin sign-in, typing only narrows (no Graph search)", not w._jobs)
w.reject()

print("== closing during the admin's sign-in")
webbrowser.open = lambda url: None                              # a browser that never comes back
w = wizard(dirs(), None)
to_connection(w, "entra")
fill(w, TENANT, domains="c.example")
nxt(w)
w.list_btn.click()
pump(lambda: w._jobs)
started = time.time()
w.reject()
check("closes within a second, the Job ended", time.time() - started < 2 and not w._jobs, time.time() - started)
webbrowser.open = browse

print("== the Accounts page: Edit and Test login on an SSO row")
page = A.AccountsPage(); page.load(); page.refresh()
row = [page.idents.item(i, 0).text() for i in range(page.idents.rowCount())].index("Contoso")
page.idents.selectRow(row)
opened = []
def look(self):
    opened.append((self._sso(), self._provider(), self.issuer.text()))
    return 0
IW.IdentityWizard.exec = look
page._edit_ident()
check("Edit opens the wizard in SSO mode with the saved values", opened == [(True, "entra", "")], opened)   # (the fake's issuer has no tenant)
del IW.IdentityWizard.exec

shown = {}
def run_test(self):
    shown["boxes"] = self.user.isVisibleTo(self) or self.pw.isVisibleTo(self)
    shown["labels"] = [x.text() for x in self.form_page.findChildren(QLabel) if x.isVisibleTo(self) and x.text()]
    self.test_btn.click()
    pump(lambda: not self._jobs and self.result.text())
    shown["result"] = self.result.text()
    return 0
TL.TestLoginDialog.exec = run_test
P.id_claims = {"preferred_username": "ann@acme.com", "groups": ["id-net"]}
OPENED.clear()
page.idents.selectRow(row)
m = page._ident_menu(None)
page.test_login.trigger()
check("Test login: no username or password boxes, the browser opened once", not shown.get("boxes") and len(OPENED) == 1, shown)
check("...shows the role", shown.get("result") == "Signed in as ann@acme.com. Role: Admin. Signed out.", shown)
check("...written to the audit", any(r["action"] == "test login" and r["detail"] == "ann@acme.com, Signed in as ann@acme.com. Role: Admin. Signed out."
                                     for r in audit.recent(50)))
P.id_claims = {"preferred_username": "bea@acme.com", "groups": ["other"]}
page.test_login.trigger()
check("...not in a mapped group", shown.get("result") == "bea@acme.com isn't in an OU or group that Toner maps to a role.", shown)
P.mode = "bad_state"
page.test_login.trigger()
check("...a bad answer: the approved sentence with the connection's name", shown.get("result")
      == "Contoso's answer couldn't be checked, so the sign-in was refused.", shown)
P.mode = "ok"
P.id_claims = {"preferred_username": "ann@acme.com", "groups": ["id-net"], "auth_time": int(time.time()) - 3600}
page.test_login.trigger()
check("...an old sign-in: not fresh", shown.get("result") == "Contoso didn't confirm a fresh sign-in. Try again.", shown)
P.id_claims = {}
check("...and still no token anywhere", no_token_anywhere())
d = json.loads(datakey.path().read_text(encoding="utf-8")); d["throttle"] = {"fails": 0, "until": 0}
datakey.path().write_text(json.dumps(d), encoding="utf-8")

print("== Test login: closing the dialog stops the browser wait, keeping nothing")
webbrowser.open = lambda url: None
del TL.TestLoginDialog.exec
cfg = next(x for x in dirs() if x.get("name") == "Contoso")
dlg = TL.TestLoginDialog(cfg)
n = len(audit.recent(5000))
dlg.test_btn.click()
pump(lambda: dlg._jobs)
started = time.time()
dlg.reject()
check("closes within a second, no audit row", time.time() - started < 2 and not dlg._jobs and len(audit.recent(5000)) == n)
webbrowser.open = browse

print("== TestLogin.check_sso directly")
t = S.TestLogin(cfg)
P.id_claims = {"preferred_username": "ann@acme.com", "groups": ["id-net"]}
t.check_sso(browse, threading.Event())
check("passes with the role and ends", t.stage == "done" and t.role == "Admin" and t.result == "Signed in as ann@acme.com. Role: Admin. Signed out.")
P.force = 503
t = S.TestLogin(cfg)
try:
    t.check_sso(browse, threading.Event()); got = None
except Exception as e:
    got = e
check("a provider down: UNREACHABLE (no offline path in a test)", isinstance(got, S.directory.Unreachable) and str(got) == S.UNREACHABLE, repr(got))
P.force = None

P.stop()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
