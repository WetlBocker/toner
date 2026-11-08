# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Accounts > External Identities: the five-step Add flow (and Edit, filled in) on ldap3's MOCK_SYNC, a fake protected
# store and a fake security chip: the steps' words, a connection that works or fails, OUs and groups ticked and given roles, where
# the secrets go, duplicates, the CA file, a blank NetBIOS name, 3000 OUs, searching a large directory, closing during a Job, and
# the page around it (a directory account in the accounts table, removing a directory, an Engineer never seeing it).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\identwiz%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import json, socket, threading
from types import SimpleNamespace
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, osstore, passvault, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def undone(box):
    """What undo brings back into a box (Password mode hides undo, so it is read as a show-password switch would)."""
    mode = box.echoMode(); box.setEchoMode(box.EchoMode.Normal); box.undo(); text = box.text(); box.setEchoMode(mode)
    return text


# ---------------------------------------------------------------- fakes: the protected store, the chip, the directory
OS = {}                                     # (name, file) -> value
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: OS.__setitem__((n, file), v)
osstore.get = lambda n, file=None: OS.get((n, file))
osstore.delete = lambda n: OS.pop((n, None), None)


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
        k, right = cls.keys[name]
        if pin != right: raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name): cls.keys.pop(name, None)


pinslot.tpm_windows = FakeTpm
pinslot.best_kind = lambda: "chip"

BASE = "DC=acme,DC=com"
ADMINS, ENGINEERS, TECHS = "CN=Toner Admins," + BASE, "CN=Toner Engineers," + BASE, "CN=Toner Techs," + BASE
OU_IT, OU_USERS, OU_ZETA = "OU=IT," + BASE, "OU=Users," + BASE, "OU=Zeta," + BASE
SVC = "svc-pass-SECRET-4711"
G_BOB, G_SVC = (c * 16 for c in (b"B", b"S"))   # fixed GUIDs of plain letters: the mock mismatches some random ones
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
for dn, attrs in [
        (OU_IT, {"objectClass": "organizationalUnit", "ou": "IT"}),
        (OU_USERS, {"objectClass": "organizationalUnit", "ou": "Users"}),
        ("OU=One," + BASE, {"objectClass": "organizationalUnit", "ou": "One"}),
        ("OU=Two," + BASE, {"objectClass": "organizationalUnit", "ou": "Two"}),
        ("OU=Ops," + OU_IT, {"objectClass": "organizationalUnit", "ou": "Ops"}),
        ("OU=Lab," + BASE, {"objectClass": "organizationalUnit", "ou": "Lab"}),
        (OU_ZETA, {"objectClass": "organizationalUnit", "ou": "Zeta"}),     # 7 OUs: a cap of 5 leaves some to be searched for
        ("CN=Bob," + OU_USERS, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                "objectGUID": G_BOB, "userAccountControl": 512, "userPassword": "pw-bob"}),
        ("CN=svc," + BASE, {"objectClass": "user", "sAMAccountName": "svc", "cn": "svc", "objectGUID": G_SVC,
                            "userAccountControl": 512, "userPassword": SVC}),
        (ADMINS, {"objectClass": "group", "cn": "Toner Admins"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"}),
        ("CN=Desk,OU=One," + BASE, {"objectClass": "group", "cn": "Desk"}),
        ("CN=Desk,OU=Two," + BASE, {"objectClass": "group", "cn": "Desk"}),
        ("CN=ACME,CN=Partitions,CN=Configuration," + BASE, {"objectClass": "crossRef", "cn": "ACME", "nCName": BASE,
                                                            "nETBIOSName": "ACME"})]:
    c.strategy.add_entry(dn, attrs)
ldap.dit["bob@acme.com"] = ldap.dit["CN=Bob," + OU_USERS]
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
directory._config_nc = lambda conn: "CN=Configuration," + BASE          # the mock has no rootDSE
directory._base_dn = lambda conn, ad: BASE
REAL_MAKE_SERVER = directory._make_server
directory._make_server = lambda cfg, host, *_: ldap

PW, PW2, PIN = "correct horse battery 42", "engineers have long passwords 7", "246813"
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")

def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))

def acts():
    return [r["action"] for r in audit.recent(5000)]

def no_secret_written():
    text = datakey.path().read_text(encoding="utf-8") + json.dumps([dict(r) for r in audit.recent(5000)])
    return SVC not in text and "typed-after-the-click" not in text


# ---------------------------------------------------------------- the page and the flow
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
from ui import identitywizard as IW
from ui.settings_pages import accounts as A

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def settle(w):
    return pump(lambda: not w._jobs)

KEEP = []                                   # a widget left to Python's collector could be freed on a Job's thread
def wizard(*a):
    KEEP.append(IW.IdentityWizard(*a))
    return KEEP[-1]

step = lambda w: w.stack.currentIndex()
texts = lambda box: [box.itemText(i) for i in range(box.count())]
rows = lambda w, which: [w.lists[which].item(i).text() for i in range(w.lists[which].count())]
shown = lambda w, which: [w.lists[which].item(i).text() for i in range(w.lists[which].count()) if not w.lists[which].item(i).isHidden()]
ticked = lambda w, which: [w.lists[which].item(i).text() for i in range(w.lists[which].count())
                           if w.lists[which].item(i).checkState() == Qt.CheckState.Checked]

def nxt(w):
    w.next_btn.click(); settle(w)
    return w.message.text()

def to_connection(w, kind="Active Directory", servers="dc1.acme.com, dc2.acme.com", service_dn="CN=svc," + BASE, pw=SVC,
                  security="LDAPS", port=636, ca=""):
    """Steps 1 and 2 as a person fills them; leaves the flow on step 3 with the security, port and certificate set."""
    if step(w) == 0:
        next(r for r in w.kinds if r.text() == kind).setChecked(True)
        nxt(w)
    w.servers.setText(servers); w.service_dn.setText(service_dn); w.service_pw.setText(pw)
    nxt(w)
    w.security.setCurrentText(security); w.port.setValue(port)
    if ca:
        QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (ca, ""))
        choose(w, "CA file...")

def choose(w, text):
    """Picks a Certificate item as a person does (activated fires even when it is already the current one)."""
    i = w.cert.findText(text)
    w.cert.setCurrentIndex(i); w.cert.activated.emit(i)

PICKED = []                                 # the start path of each file picker opened
def picker(path):
    QFileDialog.getOpenFileName = staticmethod(lambda parent, caption="", start="", *a, **k: (PICKED.append(start), (path, ""))[1])

def connect(w, **kw):
    to_connection(w, **kw)
    return nxt(w)

def tick(w, which, dn, on=True):
    found = w.lists[which].findItems(dn, Qt.MatchFlag.MatchExactly)
    assert found, (dn, step(w), w.message.text(), rows(w, which))
    item = found[0]
    item.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

def answers(fn):
    def run(self):
        settle(self)
        fn(self)
        settle(self)
        return self.result()
    return run

TICKS = (("ous", OU_IT, "Engineer"), ("groups", ADMINS, "Admin"), ("ous", OU_USERS, "Tech"))
said = {}
def add_with(ticks=TICKS, name=None, netbios=None, suffixes=None, base_dn=None, **kw):
    def go(w):
        said["msg"] = connect(w, **kw)
        if step(w) != 3:
            return
        for which, dn, _ in ticks:
            tick(w, which, dn)
        said["msg"] = nxt(w)
        for _, dn, role in ticks:
            w.role_boxes[dn].setCurrentText(role)
        for box, v in ((w.name, name), (w.netbios, netbios), (w.suffixes, suffixes), (w.base_dn, base_dn)):
            if v is not None:
                box.setText(v)
        w.save_btn.click(); settle(w)
        said["msg"], said["pw"] = w.message.text(), w.service_pw.text()
    return go

page = A.AccountsPage()
page.load()
dir_rows = lambda: [page.idents.item(i, 0).text() for i in range(page.idents.rowCount())]
_remove_box = lambda self: [b for b in self.buttons() if b.text() == "Remove"][0].click()

print("== the steps' words")
w = wizard([], None)
check("the five step titles, the first shown", IW.TITLES == ("Choose a type", "Server and service account", "Connection",
      "Who can sign in", "Roles") and w.title.text() == "Choose a type" and w.stack.count() == 8)   # (3 more are SSO's)
check("step 1: Active Directory, LDAP or SSO, AD first", [r.text() for r in w.kinds] == ["Active Directory", "LDAP", "SSO (OpenID Connect)"] and w.kinds[0].isChecked())
check("buttons: Back, Next, Save", (w.back_btn.text(), w.next_btn.text(), w.save_btn.text()) == ("Back", "Next", "Save"))
check("...step 1 has no Back and no Save", w.back_btn.isHidden() and w.save_btn.isHidden() and not w.next_btn.isHidden())
nxt(w)
check("step 2's title and fields", w.title.text() == "Server and service account" and [b.accessibleName() for b in (w.servers, w.service_dn,
      w.service_pw)] == ["Host name, IP address or FQDN", "Service account", "Password"] and not w.back_btn.isHidden())
check("...the password is hidden as typed", w.service_pw.echoMode() == w.service_pw.EchoMode.Password)
w.back_btn.click()
check("Back goes back a step", step(w) == 0 and w.title.text() == "Choose a type")
nxt(w); nxt(w)
check("step 3's title and fields, prefilled LDAPS / 636 / the system trust store", w.title.text() == "Connection"
      and [b.accessibleName() for b in (w.security, w.port, w.cert)] == ["Security", "Port", "Certificate"]
      and texts(w.security) == ["LDAPS", "StartTLS"] and texts(w.cert) == ["System trust store", "CA file..."]
      and (w.security.currentText(), w.port.value(), w.cert.currentText()) == ("LDAPS", 636, "System trust store"))
w.security.setCurrentText("StartTLS")
check("StartTLS moves the port to 389", w.port.value() == 389)
w.security.setCurrentText("LDAPS")
check("...and LDAPS back to 636", w.port.value() == 636)
check("step 4's headings, and no hint text in the filter boxes", [h.text() for h in w.headings] == ["OUs", "Groups"]
      and all(f.placeholderText() == "" for f in w.filters.values()))
w.reject()

print("== a connection that fails stays on step 3")
w = wizard([], None)
check("a wrong service password", connect(w, pw="wrong") == "Toner couldn't connect: bind refused" and step(w) == 2, w.message.text())
w.port.setValue(389)
check("plain LDAP (LDAPS on 389), with the reason", nxt(w) == "Toner couldn't connect: port 389 is not LDAPS" and step(w) == 2, w.message.text())
directory._STRATEGY, directory._make_server = ldap3.SYNC, REAL_MAKE_SERVER
s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
w.back_btn.click(); w.servers.setText("127.0.0.1"); nxt(w); w.port.setValue(closed)
check("a closed port", nxt(w) == "Toner couldn't connect: cannot use 127.0.0.1" and step(w) == 2, w.message.text())
directory._STRATEGY, directory._make_server = ldap3.MOCK_SYNC, (lambda cfg, host, *_: ldap)
missing = os.path.join(SP, "no-such-ca.pem")
picker(missing)
w.back_btn.click(); w.servers.setText("dc1.acme.com"); nxt(w); w.port.setValue(636)
choose(w, "CA file...")
check("choosing a CA file shows its path", w.ca_path == missing and w.ca_label.text() == missing)
check("a CA file that can't be read", nxt(w) == "Toner can't read that CA file." and step(w) == 2, w.message.text())
PICKED.clear(); choose(w, "CA file...")
check("choosing CA file... again opens the picker again, at the file there is", PICKED == [missing], PICKED)
choose(w, "System trust store")
check("the system trust store again: no CA file", w.ca_path == "" and w.ca_label.text() == "")
w.reject()

print("== add")
w = wizard([], None)
ran_on, real_discover = [], directory.discover
directory.discover = lambda *a: ran_on.append(threading.get_ident()) or real_discover(*a)
to_connection(w)
w.next_btn.click()
check("Next on step 3 runs on a Job, the form off meanwhile", bool(w._jobs) and not w.stack.isEnabled() and not w.next_btn.isEnabled()
      and not w.back_btn.isEnabled())
w.service_pw.setText("typed-after-the-click")
settle(w)
directory.discover = real_discover
check("...off the window's thread", ran_on and ran_on[0] != threading.get_ident())
check("...with the password at the click: Connected, on step 4", w.message.text() == "Connected. Choose who can sign in."
      and step(w) == 3 and w.title.text() == "Who can sign in" and w.stack.isEnabled(), w.message.text())
check("step 4 lists the OUs and groups as the server wrote them", rows(w, "ous") == sorted([OU_IT, "OU=Lab," + BASE, "OU=One," + BASE,
      "OU=Ops," + OU_IT, "OU=Two," + BASE, OU_USERS, OU_ZETA], key=str.lower) and rows(w, "groups") == sorted([ADMINS, ENGINEERS, TECHS,
      "CN=Desk,OU=One," + BASE, "CN=Desk,OU=Two," + BASE], key=str.lower), (rows(w, "ous"), rows(w, "groups")))
check("...none ticked", ticked(w, "ous") == [] and ticked(w, "groups") == [])
check("Next with nothing ticked", nxt(w) == "Choose at least one OU or group." and step(w) == 3, w.message.text())
w.filters["groups"].setText("toner")
check("the filter narrows the list at once, ignoring case", shown(w, "groups") == [ADMINS, ENGINEERS, TECHS] and not w._jobs,
      shown(w, "groups"))
w.filters["groups"].setText("")
check("...and empty shows all again", len(shown(w, "groups")) == 5)
w.reject()

print("== add from the page")
IW.IdentityWizard.exec = answers(add_with())
page.add_ident.click()
d = (doc().get("directories") or [{}])[0]
check("saved: the list shows it, named after the DNS domain", dir_rows() == ["acme.com"], (dir_rows(), said))
check("...OUs and groups by role, as the server wrote them", d.get("ous") == {"Admin": [], "Engineer": [OU_IT], "Tech": [OU_USERS]}
      and d.get("groups") == {"Admin": [ADMINS], "Engineer": [], "Tech": []}, d)
check("...the settings, filled in from the directory", d.get("kind") == "ad" and d.get("servers") == ["dc1.acme.com", "dc2.acme.com"]
      and d.get("port") == 636 and d.get("security") == "ldaps" and d.get("ca_file") == "" and d.get("base_dn") == BASE
      and d.get("netbios") == "ACME" and d.get("suffixes") == ["acme.com"] and d.get("service_dn") == "CN=svc," + BASE, d)
check("...a new identity's 2FA is off", d.get("duo") == {"on": False, "host": "", "ikey": ""}, d.get("duo"))
check("...one audit row", acts().count("directory added") == 1)
DID = d.get("id")
check("the service password is in the vault", passvault.get(f"service:directory-{DID}") == SVC)
check("...and not in netcheck.keys or the audit", no_secret_written())
check("...nor anywhere in the database file", SVC.encode() not in open(db.base_path(), "rb").read())
check("the password box is cleared on Save", said.get("pw") == "", said)

print("== step 5")
w = wizard([], None)
connect(w)
for which, dn, _ in TICKS:
    tick(w, which, dn)
check("Next: one row per ticked OU or group, the DN shown", nxt(w) == "" and step(w) == 4 and w.title.text() == "Roles"
      and list(w.role_boxes) == [OU_IT, OU_USERS, ADMINS] and all(texts(b) == ["Admin", "Engineer", "Tech"] for b in w.role_boxes.values())
      and [w.role_labels[dn].text() for dn in w.role_boxes] == [OU_IT, OU_USERS, ADMINS], list(w.role_boxes))
check("...below them Name, Base DN, Domain (NetBIOS), suffixes, prefilled", [b.accessibleName() for b in (w.name, w.base_dn, w.netbios,
      w.suffixes)] == ["Name", "Base DN", "Domain (NetBIOS)", "Email and UPN suffixes"] and (w.name.text(), w.base_dn.text(),
      w.netbios.text(), w.suffixes.text()) == ("acme.com", BASE, "ACME", "acme.com"))
check("...Save instead of Next", not w.save_btn.isHidden() and w.next_btn.isHidden())
w.role_boxes[OU_IT].setCurrentText("Engineer")
w.back_btn.click()
check("Back to step 4 keeps the ticks", step(w) == 3 and ticked(w, "ous") == [OU_IT, OU_USERS] and ticked(w, "groups") == [ADMINS])
tick(w, "ous", OU_USERS, False)
nxt(w)
check("...and Next again keeps the roles chosen", list(w.role_boxes) == [OU_IT, ADMINS] and w.role_boxes[OU_IT].currentText() == "Engineer")
w.reject()
check("closing clears the password box", w.service_pw.text() == "")
check("...and undo can't bring it back", undone(w.service_pw) == "")

print("== duplicates")
for kw, value in ((dict(netbios="acme"), "acme"), (dict(netbios="OTHER", suffixes="other.com, ACME.com"), "ACME.com")):
    IW.IdentityWizard.exec = answers(add_with(name="Other", **kw))
    page.add_ident.click()
    check(f"another directory's name: {value}", said["msg"] == f"Another directory already uses {value}." and len(doc()["directories"]) == 1, said)

print("== edit")
page.idents.selectRow(0)
seen = {}
def edit(w):
    seen.update(locked=not any(r.isEnabled() for r in w.kinds), kind=w.kinds[0].isChecked())
    nxt(w)
    seen.update(servers=w.servers.text(), svc=w.service_dn.text(), pw=w.service_pw.text())
    nxt(w)
    said["msg"] = nxt(w)
    seen.update(ous=ticked(w, "ous"), groups=ticked(w, "groups"))
    nxt(w)
    seen.update(roles={dn: b.currentText() for dn, b in w.role_boxes.items()}, name=w.name.text())
    w.name.setText("ACME Corp")
    w.save_btn.click(); settle(w)
    said["save"] = w.message.text()
IW.IdentityWizard.exec = answers(edit)
page.edit_ident.click()
check("Edit: the type is shown and can't change", seen.get("locked") and seen.get("kind"), seen)
check("...what is stored is filled in, but no password", (seen.get("servers"), seen.get("svc"), seen.get("pw"))
      == ("dc1.acme.com, dc2.acme.com", "CN=svc," + BASE, ""), seen)
check("...an empty password connects with the stored one", said["msg"] == "Connected. Choose who can sign in.", said)
check("...the ticks come back from the saved list", seen.get("ous") == [OU_IT, OU_USERS] and seen.get("groups") == [ADMINS], seen)
check("...and the roles", seen.get("roles") == {OU_IT: "Engineer", OU_USERS: "Tech", ADMINS: "Admin"} and seen.get("name") == "acme.com", seen)
d = doc()["directories"][0]
check("...saved, keeping the password", d["name"] == "ACME Corp" and d["id"] == DID and dir_rows() == ["ACME Corp"]
      and passvault.get(f"service:directory-{DID}") == SVC and d["duo"] == {"on": False, "host": "", "ikey": ""}, (said, d))
check("...one audit row", acts().count("directory changed") == 1)
signed_duo = {"on": True, "host": "api-1234.duosecurity.com", "ikey": "DIXXXXXXXXXXXXXXXXXX"}
roles.set_directories([dict(d, duo=signed_duo)], edited=DID)
page.refresh(); page.idents.selectRow(0)
def resave(w):
    for _ in range(3): nxt(w)
    nxt(w); w.save_btn.click(); settle(w)
    said["save"] = w.message.text()
IW.IdentityWizard.exec = answers(resave)
page.edit_ident.click()
check("Edit keeps the 2FA settings as they were (Set up 2FA owns them)", doc()["directories"][0]["duo"] == signed_duo, said)
roles.set_directories([dict(doc()["directories"][0], duo={"on": False, "host": "", "ikey": ""})], edited=DID)
page.refresh()

print("== the CA file")
ca, ca2 = os.path.join(SP, "acme-ca.pem"), os.path.join(SP, "beta-ca.pem")
for path, text in ((ca, "one CA"), (ca2, "beta CA")):
    with open(path, "w") as f: f.write(text)
def with_cert(path):
    def go(w):
        picker(path)
        nxt(w); nxt(w)
        seen["cert"], seen["path"] = w.cert.currentText(), w.ca_label.text()
        choose(w, "CA file..." if path else "System trust store")
        said["msg"] = nxt(w)
        if step(w) == 3:
            nxt(w); w.save_btn.click(); settle(w)
    return go
def test_only(w):
    picker("")                              # (a picker opened is cancelled)
    PICKED.clear()
    nxt(w); nxt(w)
    seen["cert"], seen["path"] = w.cert.currentText(), w.ca_label.text()
    said["msg"] = nxt(w)
    seen["step"] = step(w)
IW.IdentityWizard.exec = answers(with_cert(ca))
page.idents.selectRow(0); page.edit_ident.click()
signed_a = doc()["directories"][0].get("ca_sha256")
check("a CA file is signed into the list", doc()["directories"][0].get("ca_file") == ca and signed_a, said)
with open(ca, "w") as f: f.write("another CA")
IW.IdentityWizard.exec = answers(test_only)
page.idents.selectRow(0); page.edit_ident.click()
check("Edit shows the CA file", seen["cert"] == "CA file..." and seen["path"] == ca, seen)
check("the CA file changed since: step 3 says so", said["msg"] == "The directory's CA file changed. An admin needs to save the directory again.", said)
check("...and opens the file picker at the stored path; cancelled, it stays on step 3", PICKED == [ca] and seen.get("step") == 2, (PICKED, seen))
e = None
session.sign_out()
try: S.begin("bob@acme.com", "pw-bob")
except S.CaChanged as x: e = x
check("...and so does the sign-in", e is not None and str(e) == "The directory's CA file changed. An admin needs to save the directory again.")
session.sign_in("Admin1", PW)
page.refresh()
print("== saving another directory keeps this one's CA hash (Ruling 32)")
IW.IdentityWizard.exec = answers(add_with(name="Beta", netbios="BETA", suffixes="beta.com", ca=ca2))
page.add_ident.click()
check("Beta added with its own CA file; ACME's hash is the one signed before", [x["name"] for x in doc()["directories"]] == ["ACME Corp", "Beta"]
      and doc()["directories"][0]["ca_sha256"] == signed_a and doc()["directories"][1].get("ca_file") == ca2, said)
signed_b = doc()["directories"][1]["ca_sha256"]
with open(ca2, "w") as f: f.write("beta CA, changed")
def repick(w):
    picker(ca)
    PICKED.clear()
    nxt(w); nxt(w)
    said["msg"] = nxt(w)                    # CA_CHANGED, the picker, the file chosen again, connected
    if step(w) == 3:
        nxt(w); w.save_btn.click(); settle(w)
IW.IdentityWizard.exec = answers(repick)
page.idents.selectRow(0); page.edit_ident.click()
check("choosing the file in the picker step 3 opened, then Save, signs it anew", PICKED == [ca]
      and said["msg"] == "Connected. Choose who can sign in."
      and doc()["directories"][0]["ca_sha256"] not in (None, signed_a), said)
check("...and only this directory is re-hashed", doc()["directories"][1]["ca_sha256"] == signed_b)
IW.IdentityWizard.exec = answers(test_only)
page.idents.selectRow(0); page.edit_ident.click()
check("...so its step 3 works again", said["msg"] == "Connected. Choose who can sign in.", said)
signed_a = doc()["directories"][0]["ca_sha256"]
before_exec, QMessageBox.exec = QMessageBox.exec, _remove_box
page.idents.selectRow(1); page.remove_ident.click()
QMessageBox.exec = before_exec
check("removing the other directory re-hashes none", [x["name"] for x in doc()["directories"]] == ["ACME Corp"]
      and doc()["directories"][0]["ca_sha256"] == signed_a)
IW.IdentityWizard.exec = answers(with_cert(""))
page.idents.selectRow(0); page.edit_ident.click()
check("back to the system trust store", doc()["directories"][0].get("ca_file") == "" and "ca_sha256" not in doc()["directories"][0], said)

print("== a directory account in the accounts table")
session.sign_out()
a = S.begin("bob@acme.com", "pw-bob"); S.after_password(a); S.choose_pin(a, PIN); S.approve(a, "Admin1", PW); S.finish(a, PIN)
check("set-up: Bob signs in with a PIN on the chip", session.user() == "bob@acme.com" and session.kind() == "directory")
session.sign_out(); session.sign_in("Admin1", PW)
page.refresh()
table = {page.table.item(i, 0).text(): [page.table.item(i, j).text() for j in range(page.table.columnCount())] for i in range(page.table.rowCount())}
check("Bob: Active Directory, his OU's role, PIN (security chip)", table["bob@acme.com"][1] == "Active Directory"
      and table["bob@acme.com"][3] == "Tech" and table["bob@acme.com"][4] == "PIN (security chip)", table)
check("a local account: Password", table["Admin1"][4] == "Password", table)
from ui.settings_pages.accounts import unlocks_with
check("the other PIN kinds", [unlocks_with({"kind": "directory", "slot_kind": k}) for k in ("store", "pin")] == ["PIN (protected store)", "PIN"])
check("an LDAP directory's Type", A.type_of({"kind": "directory", "directory_kind": "ldap"}) == "LDAP")
names = [page.table.item(i, 0).text() for i in range(page.table.rowCount())]
page.table.selectRow(names.index("bob@acme.com"))
check("a directory row: Change role and Reset password are off", not page.change.isEnabled() and not page.reset.isEnabled())
page.table.selectRow(names.index("Eng1"))
check("a local row: on again", page.change.isEnabled() and page.reset.isEnabled())
slot_key = "Toner-" + datakey.directory_account("bob@acme.com")["slot_id"]
asked = []
def answer(text):
    def run(self):
        asked.append(self.text())
        [b for b in self.buttons() if b.text() == text][0].click()
    return run
real_exec = QMessageBox.exec
QMessageBox.exec = answer("Remove")
page.table.selectRow(names.index("bob@acme.com"))
page.remove.click()
check("removing a directory account asks as for any account", asked == ["Remove bob@acme.com? They won't be able to sign in to this copy of Toner."], asked)
check("...removes it and its PIN key on this computer", datakey.directory_account("bob@acme.com") is None and slot_key not in FakeTpm.keys
      and "account removed" in acts())

print("== remove a directory")
session.sign_out()
a = S.begin("bob@acme.com", "pw-bob"); S.after_password(a); S.choose_pin(a, PIN); S.approve(a, "Admin1", PW); S.finish(a, PIN)
slot_key = "Toner-" + datakey.directory_account("bob@acme.com")["slot_id"]
session.sign_out(); session.sign_in("Admin1", PW)
OS[("duo:" + DID, None)] = b"duo-secret"
page.refresh(); page.idents.selectRow(0)
asked.clear(); QMessageBox.exec = answer("Cancel")
page.remove_ident.click()
check("asks, in the approved words; Cancel keeps it", asked == ["Removing this directory signs out its accounts on this copy. Remove ACME Corp?"]
      and len(doc()["directories"]) == 1, asked)
QMessageBox.exec = answer("Remove")
page.remove_ident.click()
check("Remove: gone from the list and the file", dir_rows() == [] and doc()["directories"] == [])
check("...its accounts and their PIN keys go", datakey.directory_account("bob@acme.com") is None and slot_key not in FakeTpm.keys)
check("...the service password and the Duo secret go", passvault.get(f"service:directory-{DID}") is None and ("duo:" + DID, None) not in OS)
check("...one audit row (Beta's removal above was the first)", acts().count("directory removed") == 2)
check("no secret was ever written to netcheck.keys or the audit", no_secret_written())
QMessageBox.exec = real_exec

print("== a blank NetBIOS name is read from the directory at Save")
directory._config_nc = lambda conn: None
w = wizard([], None)
connect(w)
tick(w, "groups", ADMINS); nxt(w)
check("discovery that can't read it leaves the box empty to type", w.netbios.text() == "" and w.name.text() == "acme.com")
directory._config_nc = lambda conn: "CN=Configuration," + BASE
w.role_boxes[ADMINS].setCurrentText("Admin")
w.save_btn.click(); settle(w)
check("Save reads it and stores it", [x.get("netbios") for x in doc()["directories"]] == ["ACME"] and w.result(), w.message.text())
QMessageBox.exec = answer("Remove"); page.refresh(); page.idents.selectRow(0); page.remove_ident.click(); QMessageBox.exec = real_exec
directory._config_nc = lambda conn: None
IW.IdentityWizard.exec = answers(add_with())
page.add_ident.click()
check("a read that fails: Save refuses, in the approved words", said["msg"] == "Toner couldn't connect: no NetBIOS name found"
      and doc()["directories"] == [], said)
directory._config_nc = lambda conn: "CN=Configuration," + BASE

print("== Save takes the password as it was at the click, and the form waits")
w = wizard([], None)
connect(w)
tick(w, "groups", ADMINS); nxt(w)
w.save_btn.click()
check("while Save runs the form is off", not w.stack.isEnabled() and not w.save_btn.isEnabled() and not w.back_btn.isEnabled())
w.service_pw.setText("typed-after-the-click")
settle(w)
d = (doc().get("directories") or [{}])[0]
check("...the service password saved is the one at the click", passvault.get(f"service:directory-{d.get('id')}") == SVC, d)
check("...and nothing typed after it is written anywhere", no_secret_written())
w2 = wizard([d], d)
w2.next_btn.click(); w2.next_btn.click(); settle(w2)
w2.service_pw.setText("wrong")
nxt(w2)
check("a step 3 that fails turns the form on again", w2.message.text() == "Toner couldn't connect: bind refused" and w2.stack.isEnabled()
      and w2.next_btn.isEnabled(), w2.message.text())
w2.reject()
QMessageBox.exec = answer("Remove"); page.refresh(); page.idents.selectRow(0); page.remove_ident.click(); QMessageBox.exec = real_exec

print("== a failed Save turns the form on again")
def to_roles(w, **kw):
    connect(w, **kw); tick(w, "groups", ADMINS); nxt(w)
form_on = lambda w: w.stack.isEnabled() and w.save_btn.isEnabled() and w.back_btn.isEnabled()
directory._config_nc = lambda conn: None
w = wizard([], None); to_roles(w)
w.save_btn.click(); settle(w)
check("a NetBIOS read that fails: said, the form on, nothing written", w.message.text() == "Toner couldn't connect: no NetBIOS name found"
      and form_on(w) and doc()["directories"] == [] and step(w) == 4, w.message.text())
w.reject()
directory._config_nc = lambda conn: "CN=Configuration," + BASE
gone = os.path.join(SP, "gone-ca.pem")
with open(gone, "w") as f: f.write("a CA")
w = wizard([], None); to_roles(w, ca=gone)
os.remove(gone)
w.save_btn.click(); settle(w)
check("a CA file that can't be read by Save", w.message.text() == "Toner can't read that CA file." and form_on(w)
      and doc()["directories"] == [], w.message.text())
w.reject()

print("== a Base DN changed on step 5 is read before Save (Ruling R9)")
w = wizard([], None); to_roles(w)
w.base_dn.setText("OU=Nope," + BASE)
w.save_btn.click(); settle(w)
check("one that isn't there: refused, nothing written", w.message.text() == "Toner couldn't connect: no base DN found" and form_on(w)
      and doc()["directories"] == [], w.message.text())
w.base_dn.setText(OU_IT)
w.save_btn.click(); settle(w)
check("one that is: saved", w.result() and [x["base_dn"] for x in doc()["directories"]] == [OU_IT], w.message.text())
roles.set_directories([])

print("== step 3 again, to another server (Ruling R9)")
real_tree = directory.tree
w = wizard([], None)
connect(w, servers="dc1.acme.com")
tick(w, "ous", OU_IT); tick(w, "ous", OU_USERS); nxt(w)
w.name.setText("Typed"); w.netbios.setText("TYPED")
directory.tree = lambda cfg, pw, cap=5000, text="": dict(real_tree(cfg, pw, cap, text), ous=[d for d in real_tree(cfg, pw, cap, text)["ous"] if d != OU_USERS])
w.back_btn.click(); w.back_btn.click(); w.back_btn.click()
w.servers.setText("dc9.acme.com"); nxt(w)
check("...the settings are read anew", nxt(w) == "Connected. Choose who can sign in." and (w.name.text(), w.netbios.text()) == ("acme.com", "ACME"),
      (w.name.text(), w.netbios.text()))
check("...a tick the new tree lacks is dropped, the others kept", ticked(w, "ous") == [OU_IT] and OU_USERS not in rows(w, "ous"), ticked(w, "ous"))
directory.tree = real_tree
w.back_btn.click(); w.name.setText("Typed")
nxt(w)
check("the same server again: what was typed stays", w.name.text() == "Typed" and ticked(w, "ous") == [OU_IT])
w.reject()

print("== a search error that lands after step 4 is left (Ruling R9)")
IW.CAP = 5
def boom_tree(cfg, pw, cap=5000, text=""):
    if text == "boom":
        time.sleep(0.6)
        raise directory.Unreachable("read failed")
    return real_tree(cfg, pw, cap, text)
directory.tree = boom_tree
w = wizard([], None); connect(w); tick(w, "ous", rows(w, "ous")[0])          # (which 5 load depends on the mock's order)
w.filters["ous"].setText("boom"); settle(w)
check("on step 4 it is said", pump(lambda: w.message.text() == "Toner couldn't connect: read failed", 3), w.message.text())
w.filters["ous"].setText(""); w.filters["ous"].setText("boom")
pump(lambda: bool(w._jobs), 3)
w.next_btn.click(); settle(w)
check("...on step 5 it is ignored", step(w) == 4 and w.message.text() == "", w.message.text())
w.reject()
directory.tree = real_tree

print("== Edit of a capped directory keeps what lies past the cap")
CAPPED = {"id": "capped1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
          "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
          "groups": {"Admin": [], "Engineer": [ADMINS], "Tech": []}, "ous": {"Admin": [OU_ZETA], "Engineer": [], "Tech": []},
          "duo": {"on": False, "host": "", "ikey": ""}}
roles.set_directories([CAPPED])
passvault.put("service:directory-capped1", SVC)
d = doc()["directories"][0]
w = wizard([d], d)
nxt(w); nxt(w); nxt(w)
check("a saved OU past the cap comes back ticked", w.more and OU_ZETA in rows(w, "ous") and ticked(w, "ous") == [OU_ZETA]
      and ticked(w, "groups") == [ADMINS], (rows(w, "ous"), ticked(w, "ous")))
nxt(w); w.save_btn.click(); settle(w)
d = doc()["directories"][0]
check("...and is saved unchanged", w.result() and d["ous"] == CAPPED["ous"] and d["groups"] == CAPPED["groups"], d)
roles.set_directories([])
IW.CAP = 5000

print("== 3000 OUs (Review Focus 1)")
real_tree = directory.tree
MANY = ["OU=Site-%04d,%s" % (i, BASE) for i in range(3000)]
directory.tree = lambda cfg, pw, cap=5000, text="": {"ous": list(MANY), "groups": [ADMINS], "more": False}
w = wizard([], None)
t0 = time.time()
connect(w)
check("all 3000 render", len(rows(w, "ous")) == 3000 and step(w) == 3, (len(rows(w, "ous")), time.time() - t0))
t0 = time.time()
w.filters["ous"].setText("site-2999")
took = time.time() - t0
check("the filter narrows them at once", shown(w, "ous") == [MANY[2999]] and took < 2, took)
check("...a list loaded whole is never searched", pump(lambda: bool(w._jobs), 0.8) is False)
w.reject()
directory.tree = real_tree

print("== searching a large directory (owner, 2026-11-06)")
IW.CAP = 5
asked_for = []
def spy_tree(cfg, pw, cap=5000, text=""):
    asked_for.append((text, threading.get_ident()))
    if text == "slow":
        time.sleep(1.0)
        return {"ous": ["OU=Slow," + BASE], "groups": [], "more": False}
    return real_tree(cfg, pw, cap, text)
directory.tree = spy_tree
w = wizard([], None)
connect(w)
# which 5 of the 7 OUs load depends on the order the mock sends them; one not loaded (a name no other DN contains) is searched for
lost = next(n for n in ("Zeta", "Lab", "One", "Two", "Users") if "OU=%s,%s" % (n, BASE) not in rows(w, "ous"))
LOST, first = "OU=%s,%s" % (lost, BASE), rows(w, "ous")[0]
check("a capped list: 5 OUs", len(rows(w, "ous")) == 5 and w.more, rows(w, "ous"))
tick(w, "ous", first)
asked_for.clear()
w.filters["ous"].setText(lost)
check("typing narrows at once and doesn't search yet", shown(w, "ous") == [] and not w._jobs and asked_for == [])
check("...after the pause it searches on a Job", pump(lambda: bool(asked_for), 3) and asked_for[0][0] == lost
      and asked_for[0][1] != threading.get_ident(), asked_for)
settle(w)
check("...and adds the match, keeping the ticks", LOST in rows(w, "ous") and shown(w, "ous") == [LOST] and ticked(w, "ous") == [first],
      rows(w, "ous"))
asked_for.clear()
w.filters["ous"].setText("slow")
pump(lambda: bool(asked_for), 3)
w.filters["ous"].setText("Lab")
settle(w)
check("a slower, older search lands after a newer one and is dropped", [t for t, _ in asked_for] == ["slow", "Lab"]
      and "OU=Slow," + BASE not in rows(w, "ous") and shown(w, "ous") == ["OU=Lab," + BASE], (asked_for, rows(w, "ous")))
w.reject()
directory.tree, IW.CAP = real_tree, 5000

print("== closing during the step 3 Job (Review Focus 5)")
def slow_discover(*a):
    time.sleep(0.5)
    return real_discover(*a)
directory.discover = slow_discover
w = wizard([], None)
to_connection(w)
w.next_btn.click()
jobs = list(w._jobs)
w.reject()
app.processEvents()
check("no crash, no thread left, the password box cleared", jobs and all(j.isFinished() for j in jobs) and not w._jobs
      and w.service_pw.text() == "" and w.result() == 0)
pump(lambda: False, 0.3)
check("...and the late result changes nothing", step(w) == 2 and w.message.text() == "")
directory.discover = real_discover

print("== an Engineer never reaches the page (Part 2)")
from ui.settings import SettingsTab as Settings
session.sign_out(); session.sign_in("Eng1", PW2)
check("Accounts is hidden from an Engineer", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is True)
session.sign_out(); session.sign_in("Admin1", PW)
check("...and shown to an Admin", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is False)

print("== a server whose certificate this computer doesn't trust: shown, and trusted by the admin")
import datetime as _dtm
import pathlib
from PySide6.QtWidgets import QLabel
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.x509.oid import NameOID as _N
from core import certpeek, paths
_key = _ec.generate_private_key(_ec.SECP256R1()); _nm = _x509.Name([_x509.NameAttribute(_N.COMMON_NAME, "dc1.acme.com")])
_now = _dtm.datetime.now(_dtm.timezone.utc)
from cryptography.hazmat.primitives import serialization as _ser
SDER = (_x509.CertificateBuilder().subject_name(_nm).issuer_name(_nm).public_key(_key.public_key()).serial_number(1)
        .not_valid_before(_now - _dtm.timedelta(days=400)).not_valid_after(_now - _dtm.timedelta(days=40))
        .add_extension(_x509.SubjectAlternativeName([_x509.DNSName("dc1.acme.com")]), False).sign(_key, _h.SHA256())).public_bytes(_ser.Encoding.DER)
try:
    from ui import certtrust
    d = certtrust.TrustDialog("10.0.0.10", SDER)
    words_shown = d.findChildren(QLabel)
    texts_ = [l.text() for l in words_shown]
    info = certpeek.describe(SDER)
    check("the prompt: its title, sentence, the certificate's rows, the expiry, and Trust / Cancel",
          d.windowTitle() == "Trust this certificate?"
          and "10.0.0.10 presented a certificate this computer doesn't trust. Trust it only if it's your directory server's." in texts_
          and all(x in texts_ for x in ("Made out to", "Issued by", "Valid", "SHA-256", "dc1.acme.com", f"{info['valid_from']} to {info['valid_to']}",
                                        info["sha256"], f"This certificate expired on {info['valid_to']}."))
          and d.trust_btn.text() == "Trust" and d.cancel_btn.text() == "Cancel", texts_)
except Exception as e:
    check("the prompt: its title, sentence, the certificate's rows, the expiry, and Trust / Cancel", False, repr(e))
    certtrust = None
fetched, asked = [], []
real_discover2, real_fetch = directory.discover, certpeek.fetch
first = [True]
def untrusted_once(*a):
    if first[0]:
        first[0] = False
        raise directory.Untrusted("dc1.acme.com")
    return real_discover2(*a)
directory.discover = untrusted_once
certpeek.fetch = lambda host, port, security, *a: fetched.append((host, port, security)) or SDER
if certtrust:
    certtrust.ask = lambda parent, host, der: asked.append((host, der)) or True
real_pinned = directory._is_pinned; directory._is_pinned = lambda conn, ca: True     # (the byte comparison: test_directory, on real TLS)
w = wizard([], None)
got_msg = connect(w)
directory.discover, certpeek.fetch, directory._is_pinned = real_discover2, real_fetch, real_pinned
check("Next on step 3, the certificate refused: it is read (only the handshake) and shown to the admin",
      fetched == [("dc1.acme.com", 636, "ldaps")] and asked == [("dc1.acme.com", SDER)], (fetched, asked))
pem_path = w.ca_path
check("...trusted: saved in Toner's data folder as the directory's CA file, pinned, and step 3 tried again (Connected)",
      bool(pem_path) and pathlib.Path(pem_path).parent == paths.data_dir() / "certs" and pathlib.Path(pem_path).read_bytes() == certpeek.pem(SDER)
      and w.ca_label.text() == pem_path and w.cert.currentIndex() == 1 and w._cfg().get("tls_pinned") is True
      and got_msg == "Connected. Choose who can sign in." and step(w) == 3, (pem_path, got_msg, w._cfg().get("tls_pinned")))
w.back_btn.click(); choose(w, "System trust store")
check("...choosing the system trust store again un-pins it", "tls_pinned" not in w._cfg() and w.ca_path == "")
w.reject()
first[0] = True; asked.clear()
directory.discover = untrusted_once
certpeek.fetch = lambda *a: SDER
if certtrust:
    certtrust.ask = lambda parent, host, der: asked.append(host) or False
w = wizard([], None)
got_msg = connect(w)
directory.discover, certpeek.fetch = real_discover2, real_fetch
check("...Cancel: nothing is trusted, step 3 stays, saying it couldn't connect", asked == ["dc1.acme.com"] and w.ca_path == "" and step(w) == 2
      and got_msg.startswith("Toner couldn't connect:"), (asked, got_msg))
w.reject()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
