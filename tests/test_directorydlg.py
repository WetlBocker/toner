# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Accounts and sign-in, the Directories section and the Directory dialog, on ldap3's MOCK_SYNC, a fake protected store
# and a fake security chip: add, test, edit and remove a directory (the keys file, the audit, where the secrets go), group names,
# duplicates, the CA file, plain LDAP and a closed port, Duo with no protected store, and a directory account in the accounts table.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dirdlg%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import json, socket, threading, uuid
from types import SimpleNamespace
import ldap3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, dirpin, osstore, passvault, pinslot, roles, session, tpm_windows
from core import dirsignin as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


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
SVC, SKEY = "svc-pass-SECRET-4711", "duo-SECRET-key-0815"
directory._STRATEGY = ldap3.MOCK_SYNC
ldap = ldap3.Server("mock", get_info=ldap3.NONE)
c = ldap3.Connection(ldap, client_strategy=ldap3.MOCK_SYNC)
for dn, attrs in [
        ("CN=Bob,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@acme.com", "sAMAccountName": "bob", "cn": "Bob",
                                     "objectGUID": uuid.uuid4().bytes_le, "userAccountControl": 512, "userPassword": "pw-bob",
                                     "memberOf": [TECHS]}),
        ("CN=svc," + BASE, {"objectClass": "user", "sAMAccountName": "svc", "cn": "svc", "objectGUID": uuid.uuid4().bytes_le,
                            "userAccountControl": 512, "userPassword": SVC}),
        (ADMINS, {"objectClass": "group", "cn": "Toner Admins"}),
        (ENGINEERS, {"objectClass": "group", "cn": "Toner Engineers"}),
        (TECHS, {"objectClass": "group", "cn": "Toner Techs"}),
        ("CN=Desk,OU=One," + BASE, {"objectClass": "group", "cn": "Desk"}),
        ("CN=Desk,OU=Two," + BASE, {"objectClass": "group", "cn": "Desk"})]:
    c.strategy.add_entry(dn, attrs)
ldap.dit["bob@acme.com"] = ldap.dit["CN=Bob,OU=Users," + BASE]
directory._who_am_i = lambda conn: "u:ACME\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()
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
    return SVC not in text and SKEY not in text and "other-svc-pw" not in text


# ---------------------------------------------------------------- the page and the dialog
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
from ui import directorydlg as DD
from ui.settings_pages import accounts as A

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

def settle(dlg):
    return pump(lambda: not dlg._jobs)

def fill(dlg, **kw):
    """Type into the dialog's boxes as a person would."""
    v = dict(name="ACME", kind="Active Directory", servers="dc1.acme.com, dc2.acme.com", security="LDAPS", port=636,
             base_dn=BASE, netbios="ACME", suffixes="acme.com, ACME.example", service_dn="CN=svc," + BASE, service_pw=SVC,
             admin="Toner Admins", engineer="Toner Engineers", tech="Toner Techs", second="Off", host="", ikey="", skey="")
    v.update(kw)
    dlg.name.setText(v["name"]); dlg.kind.setCurrentText(v["kind"]); dlg.servers.setText(v["servers"])
    dlg.security.setCurrentText(v["security"]); dlg.port.setValue(v["port"]); dlg.base_dn.setText(v["base_dn"])
    dlg.netbios.setText(v["netbios"]); dlg.suffixes.setText(v["suffixes"]); dlg.service_dn.setText(v["service_dn"])
    dlg.service_pw.setText(v["service_pw"])
    for role, key in (("Admin", "admin"), ("Engineer", "engineer"), ("Tech", "tech")):
        dlg.groups[role].setPlainText(v[key])
    dlg.second.setCurrentText(v["second"]); dlg.duo_host.setText(v["host"]); dlg.duo_ikey.setText(v["ikey"]); dlg.duo_skey.setText(v["skey"])

def tested(dlg):
    dlg.test_btn.click(); settle(dlg)
    return dlg.message.text()

def saved(dlg):
    dlg.save_btn.click(); settle(dlg)
    return dlg.message.text()

KEEP = []                                   # a widget left to Python's collector could be freed on a Job's thread
def dialog(*a):
    KEEP.append(DD.DirectoryDialog(*a))
    return KEEP[-1]

page = A.AccountsPage()
page.load()
dir_rows = lambda: [page.dirs.item(i).text() for i in range(page.dirs.count())]

print("== the section")
check("the heading and buttons, in the approved words", page.add_dir.text() == "Add directory..." and page.edit_dir.text() == "Edit..."
      and page.remove_dir.text() == "Remove" and any(l.text() == "<b>Directories</b>" for l in page.findChildren(A.QLabel)))
check("no directories yet; Add on, Edit and Remove off", dir_rows() == [] and page.add_dir.isEnabled()
      and not page.edit_dir.isEnabled() and not page.remove_dir.isEnabled())
real_verified = roles.verified
roles.verified = lambda: None
page.refresh()
check("rules that don't check out: no list, no changes", dir_rows() == [] and not page.add_dir.isEnabled())
roles.verified = real_verified
page.refresh()

print("== the dialog's words")
dlg = dialog([], None)
check("title", dlg.windowTitle() == "Directory")
from PySide6.QtWidgets import QFormLayout
labels = [dlg.form.itemAt(i, QFormLayout.ItemRole.LabelRole).widget().text() for i in range(dlg.form.rowCount())]
check("fields, in the approved words", labels == [
    "Name", "Kind", "Servers", "Port", "Security", "Certificate", "Base DN", "Domain (NetBIOS)", "Email and UPN suffixes",
    "Service account", "Service account password", "Admin groups", "Engineer groups", "Tech groups", "Second step",
    "Duo API hostname", "Integration key", "Secret key"], labels)
items = lambda box: [box.itemText(i) for i in range(box.count())]
check("the choices", items(dlg.kind) == ["Active Directory", "LDAP"] and items(dlg.security) == ["LDAPS", "StartTLS"]
      and items(dlg.cert) == ["System trust store", "CA file..."] and items(dlg.second) == ["Off", "Duo"])
check("hints", dlg.servers.placeholderText() == "One or more, separated by commas" and dlg.suffixes.placeholderText() == "Separated by commas"
      and all(g.placeholderText() == "Group names, one per line" for g in dlg.groups.values()))
check("buttons", dlg.test_btn.text() == "Test connection" and dlg.save_btn.text() == "Save")
check("the secrets are hidden as typed", dlg.service_pw.echoMode() == dlg.service_pw.EchoMode.Password
      and dlg.duo_skey.echoMode() == dlg.duo_skey.EchoMode.Password)
dlg.security.setCurrentText("StartTLS")
check("StartTLS moves the port to 389", dlg.port.value() == 389)
dlg.security.setCurrentText("LDAPS")
check("...and LDAPS back to 636", dlg.port.value() == 636)

print("== Test connection")
fill(dlg)
ran_on, real_test = [], directory.test
directory.test = lambda *a: ran_on.append(threading.get_ident()) or real_test(*a)
check("on the mock: Connected, with the number of groups", tested(dlg) == "Connected. Found 5 groups.", dlg.message.text())
check("...it ran off the window's thread", ran_on and ran_on[0] != threading.get_ident())
directory.test = real_test
fill(dlg, port=389)
check("plain LDAP (LDAPS on 389) is refused, with the reason", tested(dlg) == "Toner couldn't connect: port 389 is not LDAPS", dlg.message.text())
fill(dlg, service_pw="wrong")
check("a wrong service password", tested(dlg) == "Toner couldn't connect: bind refused", dlg.message.text())
directory._STRATEGY, directory._make_server = ldap3.SYNC, REAL_MAKE_SERVER
s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
fill(dlg, servers="127.0.0.1", port=closed)
check("a closed port", tested(dlg) == "Toner couldn't connect: cannot use 127.0.0.1", dlg.message.text())
directory._STRATEGY, directory._make_server = ldap3.MOCK_SYNC, (lambda cfg, host, *_: ldap)
missing = os.path.join(SP, "no-such-ca.pem")
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (missing, ""))
fill(dlg); dlg.cert.setCurrentText("CA file...")
check("choosing a CA file shows its path", dlg.ca_path == missing and dlg.ca_label.text() == missing)
check("a CA file that can't be read", tested(dlg) == "Toner can't read that CA file.", dlg.message.text())
check("...nor saved", saved(dlg) == "Toner can't read that CA file." and not doc().get("directories"))
dlg.cert.setCurrentText("System trust store")
check("the system trust store again: no CA file", dlg.ca_path == "" and dlg.ca_label.text() == "")
dlg.close()

print("== Duo with no protected store")
dirpin._avail = None
asked = []
osstore.available = lambda: asked.append(threading.get_ident()) or False
dlg = dialog([], None)
check("the store is asked off the window's thread", pump(lambda: asked) and asked[0] != threading.get_ident())
settle(dlg)
duo_item = dlg.second.model().item(1)
check("Duo is off, with the approved sentence", not duo_item.isEnabled() and not dlg.duo_note.isHidden()
      and dlg.duo_note.text() == "This computer has no protected store, so Duo can't be turned on here.")
dlg.close()
dirpin._avail = None
osstore.available = lambda: True
dlg = dialog([], None)
settle(dlg)
check("with a store: Duo can be chosen, no sentence", dlg.second.model().item(1).isEnabled() and dlg.duo_note.isHidden())
dlg.close()

print("== add")
def answers(fn):
    def run(self):
        settle(self)
        fn(self)
        settle(self)
        return self.result()
    return run

said = {}
def add_with(**kw):
    def go(dlg):
        fill(dlg, **kw)
        said["msg"] = saved(dlg)
    return go
DD.DirectoryDialog.exec = answers(add_with(admin="Nope"))
page.add_dir.click()
check("an unknown group name: said, nothing written", said["msg"] == "Toner couldn't find a group named Nope." and not doc().get("directories"), said)
DD.DirectoryDialog.exec = answers(add_with(engineer="Desk"))
page.add_dir.click()
check("a group name used twice", said["msg"] == "More than one group is named Desk. Type its full DN instead." and not doc().get("directories"), said)
DD.DirectoryDialog.exec = answers(add_with(second="Duo", host="api-1234.duosecurity.com", ikey="DIXXXXXXXXXXXXXXXXXX", skey=SKEY,
                                         admin="Toner Admins\n\n", tech="Toner Techs\n" + ENGINEERS))
page.add_dir.click()
d = (doc().get("directories") or [{}])[0]
check("saved: the list shows it", dir_rows() == ["ACME"], dir_rows())
check("...the groups are the DNs the server wrote, not the names typed", d.get("groups") == {"Admin": [ADMINS], "Engineer": [ENGINEERS],
      "Tech": [TECHS, ENGINEERS]}, d.get("groups"))
check("...the settings as typed", d.get("kind") == "ad" and d.get("servers") == ["dc1.acme.com", "dc2.acme.com"] and d.get("port") == 636
      and d.get("security") == "ldaps" and d.get("ca_file") == "" and d.get("base_dn") == BASE and d.get("netbios") == "ACME"
      and d.get("suffixes") == ["acme.com", "ACME.example"] and d.get("service_dn") == "CN=svc," + BASE
      and d.get("duo") == {"on": True, "host": "api-1234.duosecurity.com", "ikey": "DIXXXXXXXXXXXXXXXXXX"}, d)
check("...one audit row", acts().count("directory added") == 1)
DID = d.get("id")
check("the service password is in the vault", passvault.get(f"service:directory-{DID}") == SVC)
check("the Duo secret is in the protected store", OS.get(("duo:" + DID, None)) == SKEY.encode())
check("neither is in netcheck.keys or the audit", no_secret_written())
check("...nor anywhere in the database file", SVC.encode() not in open(db.base_path(), "rb").read())

print("== duplicates")
for kw, value in ((dict(netbios="acme"), "acme"), (dict(netbios="OTHER", suffixes="other.com, ACME.com"), "ACME.com")):
    DD.DirectoryDialog.exec = answers(add_with(name="Other", **kw))
    page.add_dir.click()
    check(f"another directory's name: {value}", said["msg"] == f"Another directory already uses {value}." and len(doc()["directories"]) == 1, said)

print("== edit")
page.dirs.setCurrentRow(0)
check("a selected directory: Edit and Remove on", page.edit_dir.isEnabled() and page.remove_dir.isEnabled())
shown = {}
def edit(dlg):
    shown.update(name=dlg.name.text(), pw=dlg.service_pw.text(), skey=dlg.duo_skey.text(), tech=dlg.groups["Tech"].toPlainText(),
                 servers=dlg.servers.text(), second=dlg.second.currentText())
    dlg.name.setText("ACME Corp"); dlg.second.setCurrentText("Off")
    said["msg"] = tested(dlg)
    said["save"] = saved(dlg)
DD.DirectoryDialog.exec = answers(edit)
page.edit_dir.click()
check("Edit shows what is stored, the groups as DNs, and no secret", shown == {"name": "ACME", "pw": "", "skey": "", "tech": TECHS + "\n" + ENGINEERS,
      "servers": "dc1.acme.com, dc2.acme.com", "second": "Duo"}, shown)
check("an empty password tests with the stored one", said["msg"] == "Connected. Found 5 groups.", said)
d = doc()["directories"][0]
check("...and saves, keeping it", d["name"] == "ACME Corp" and d["id"] == DID and d["duo"]["on"] is False and dir_rows() == ["ACME Corp"]
      and passvault.get(f"service:directory-{DID}") == SVC, (said, d))
check("...one audit row", acts().count("directory changed") == 1)

print("== the CA file")
ca = os.path.join(SP, "acme-ca.pem")
with open(ca, "w") as f: f.write("one CA")
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (ca, ""))
def with_ca(dlg):
    dlg.cert.setCurrentText("CA file...")
    said["save"] = saved(dlg)
DD.DirectoryDialog.exec = answers(with_ca)
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("a CA file is signed into the list", doc()["directories"][0].get("ca_file") == ca and doc()["directories"][0].get("ca_sha256"), said)
with open(ca, "w") as f: f.write("another CA")
def test_only(dlg):
    shown["cert"], shown["path"] = dlg.cert.currentText(), dlg.ca_label.text()
    said["msg"] = tested(dlg)
DD.DirectoryDialog.exec = answers(test_only)
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("Edit shows the CA file", shown["cert"] == "CA file..." and shown["path"] == ca, shown)
check("the CA file changed since: Test connection says so", said["msg"] == "The directory's CA file changed. An admin needs to save the directory again.", said)
e = None
session.sign_out()
try: S.begin("bob@acme.com", "pw-bob")
except S.CaChanged as x: e = x
check("...and so does the sign-in", e is not None and str(e) == "The directory's CA file changed. An admin needs to save the directory again.")
session.sign_in("Admin1", PW)
page.refresh()
def save_again(dlg):
    said["save"] = saved(dlg)
DD.DirectoryDialog.exec = answers(save_again)
page.dirs.setCurrentRow(0); page.edit_dir.click()
DD.DirectoryDialog.exec = answers(test_only)
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("saving the directory again signs the new file; Test connection works again", said["msg"] == "Connected. Found 5 groups.", said)
def new_file(dlg):
    with open(ca, "w") as f: f.write("a third CA")
    other = os.path.join(SP, "other-ca.pem")
    with open(other, "w") as f: f.write("other CA")
    QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (other, ""))
    dlg.cert.setCurrentText("System trust store"); dlg.cert.setCurrentText("CA file...")
    said["msg"] = tested(dlg)
DD.DirectoryDialog.exec = answers(new_file)
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("a CA file just chosen is tested with its own hash", said["msg"] == "Connected. Found 5 groups.", said)
print("== saving or removing another directory keeps this one's CA hash (Ruling 32)")
signed_a = doc()["directories"][0]["ca_sha256"]                      # (its file now holds "a third CA")
DD.DirectoryDialog.exec = answers(add_with(name="Beta", netbios="BETA", suffixes="beta.com"))
page.add_dir.click()
check("another directory saved: this one's hash is the one signed before", [d["name"] for d in doc()["directories"]] == ["ACME Corp", "Beta"]
      and doc()["directories"][0]["ca_sha256"] == signed_a, said)
DD.DirectoryDialog.exec = answers(test_only)
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("...so its Test connection still says the CA file changed", said["msg"] == "The directory's CA file changed. An admin needs to save the directory again.", said)
def remove_box(self):
    [b for b in self.buttons() if b.text() == "Remove"][0].click()
before_exec, QMessageBox.exec = QMessageBox.exec, remove_box
page.dirs.setCurrentRow(1); page.remove_dir.click()
QMessageBox.exec = before_exec
check("removing the other directory re-hashes none", [d["name"] for d in doc()["directories"]] == ["ACME Corp"]
      and doc()["directories"][0]["ca_sha256"] == signed_a)
DD.DirectoryDialog.exec = answers(lambda dlg: (dlg.cert.setCurrentText("System trust store"), saved(dlg)))
page.dirs.setCurrentRow(0); page.edit_dir.click()
check("back to the system trust store", doc()["directories"][0].get("ca_file") == "" and "ca_sha256" not in doc()["directories"][0])

print("== a directory account in the accounts table")
session.sign_out()
a = S.begin("bob@acme.com", "pw-bob"); S.after_password(a); S.choose_pin(a, PIN); S.approve(a, "Admin1", PW); S.finish(a, PIN)
check("set-up: Bob signs in with a PIN on the chip", session.user() == "bob@acme.com" and session.kind() == "directory")
session.sign_out(); session.sign_in("Admin1", PW)
page.refresh()
rows = {page.table.item(i, 0).text(): [page.table.item(i, j).text() for j in range(page.table.columnCount())] for i in range(page.table.rowCount())}
check("the columns", [page.table.horizontalHeaderItem(j).text() for j in range(page.table.columnCount())]
      == ["Username", "Type", "Created", "Role", "Unlocks with"])
check("Bob: Active Directory, his groups' role, PIN (security chip)", rows["bob@acme.com"][1] == "Active Directory"
      and rows["bob@acme.com"][3] == "Tech" and rows["bob@acme.com"][4] == "PIN (security chip)", rows)
check("a local account: Password", rows["Admin1"][4] == "Password", rows)
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
OS[("duo:" + DID, None)] = SKEY.encode()
page.refresh(); page.dirs.setCurrentRow(0)
asked.clear(); QMessageBox.exec = answer("Cancel")
page.remove_dir.click()
check("asks, in the approved words; Cancel keeps it", asked == ["Removing this directory signs out its accounts on this copy. Remove ACME Corp?"]
      and len(doc()["directories"]) == 1, asked)
QMessageBox.exec = answer("Remove")
page.remove_dir.click()
check("Remove: gone from the list and the file", dir_rows() == [] and doc()["directories"] == [])
check("...its accounts and their PIN keys go", datakey.directory_account("bob@acme.com") is None and slot_key not in FakeTpm.keys)
check("...the service password and the Duo secret go", passvault.get(f"service:directory-{DID}") is None and ("duo:" + DID, None) not in OS)
check("...one audit row (Beta's removal above was the first)", acts().count("directory removed") == 2)
check("no secret was ever written to netcheck.keys or the audit", no_secret_written())
QMessageBox.exec = real_exec

print("== an Engineer never reaches the page (Part 2)")
from ui.settings import SettingsTab as Settings
session.sign_out(); session.sign_in("Eng1", PW2)
check("Accounts and sign-in is hidden from an Engineer", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is True)
session.sign_out(); session.sign_in("Admin1", PW)
check("...and shown to an Admin", Settings._role_hidden(SimpleNamespace(pages=[page]), 0) is False)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
