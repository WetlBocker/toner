# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and vault; the password managers are stand-ins (nothing is sent anywhere, no bw.exe or op.exe is run).
# Password managers: keeping Toner's passwords in Bitwarden, Vaultwarden, Keeper or 1Password, a collection per organization,
# the copies Toner keeps when the manager can't be reached, links to existing items, and Settings > Security's vault section.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, base64
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "extv%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring, keyring.backend
from core import db, extstore, extvault, orgs, passvault
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

class OldStore(keyring.backend.KeyringBackend):
    priority = 1
    def __init__(self): self.d = {}
    def get_password(self, s, u): return self.d.get(u)
    def set_password(self, s, u, p): self.d[u] = p
    def delete_password(self, s, u): self.d.pop(u)
keyring.set_keyring(OldStore())
passvault.create("test master password", remember=False)
passvault.install()

# ---------------------------------------------------------------- a stand-in password manager
SERVER = {"online": True, "containers": {}, "items": {}, "may_create": True, "seq": 0, "calls": []}

class FakeManager(extvault.Provider):
    kind = "bitwarden"
    def connect(self):
        SERVER["calls"].append("connect")
        if not SERVER["online"]:
            raise extvault.ExtError("the server did not answer")
    def containers(self):
        return {n: cid for cid, n in SERVER["containers"].items()}
    def create_container(self, name):
        if not SERVER["may_create"]:
            raise extvault.NotAllowed(name, self.label)
        cid = f"c{len(SERVER['containers']) + 1}"
        SERVER["containers"][cid] = name
        return cid
    def items(self, cid):
        return {i["tid"]: extvault.Item(ref=r, title=i["title"], username=i["user"], value=i["pw"], toner_id=i["tid"],
                                        container=SERVER["containers"][cid], raw=i)
                for r, i in SERVER["items"].items() if i["cid"] == cid and i["tid"]}
    def put(self, cid, toner_id, title, username, value, item=None):
        SERVER["calls"].append(("put", toner_id))
        ref = item.ref if item else f"i{(SERVER.__setitem__('seq', SERVER['seq'] + 1) or SERVER['seq'])}"
        SERVER["items"].setdefault(ref, {}).update({"cid": cid, "tid": toner_id, "title": title, "user": username, "pw": value})
        return ref
    def delete(self, item):
        SERVER["items"].pop(item.ref, None)
    def search(self, text):
        return [extvault.Item(ref=r, title=i["title"], username=i["user"], container=SERVER["containers"].get(i["cid"], ""))
                for r, i in SERVER["items"].items() if text.lower() in i["title"].lower()]
    def read(self, ref):
        if ref not in SERVER["items"]:
            raise extvault.ExtError("no such item")
        return SERVER["items"][ref]["pw"]

extvault.CONNECTORS["bitwarden"] = FakeManager
extstore.start = lambda: None                 # each round is run by the test itself (no background thread)

def dev(name, **kw):
    return dict(dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="admin", site="default", verify_ssl=0,
                     ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw)

acme = orgs.create("Acme", "ACME")
db.save_device(dev("core-sw"))
with db.within(acme):
    db.save_device(dev("edge-fw", username="fwadmin"))
    db.set_secret(db.secret_name("edge-fw"), "acme-fw-pw")
db.set_secret(db.secret_name("core-sw"), "global-sw-pw")
db.set_secret("service:proxy", "proxy-pw")

print("== Toner's vault alone")
check("Toner's vault is the store to begin with", extstore.active() == "toner")
check("nothing is queued while it is", extstore.pending() == {})
check("the choices, in order", [k for k, _ in extvault.KINDS] == ["toner", "bitwarden", "vaultwarden", "keeper", "onepassword"]
      and [l for _, l in extvault.KINDS] == ["Toner's vault", "Bitwarden", "Vaultwarden", "Keeper", "1Password"])

print("== choosing a password manager")
ok_, text, _c = extstore.test("bitwarden", {}, {})
check("Test connection says how many Toner items it found", ok_ and text == "Connected to Bitwarden. 0 Toner items found.", text)
SERVER["online"] = False
ok_, text, _c = extstore.test("bitwarden", {}, {})
check("...or why it couldn't connect", not ok_ and text == "Couldn't connect to Bitwarden: the server did not answer", text)
SERVER["online"] = True
extstore.use("bitwarden")
check("before the first round the status says it is connecting", extstore.status_text() == "Connecting to Bitwarden...", extstore.status_text())
st = extstore.sync_once()
check("every saved password is sent", st["connected"] and st["sent"] == 3 and len(SERVER["items"]) == 3, (st, SERVER["items"]))
check("each organization has its own collection, named after it", sorted(SERVER["containers"].values()) == ["Toner - Acme", "Toner - Global"])
by_tid = {i["tid"]: i for i in SERVER["items"].values()}
acme_fw = by_tid[f"org{acme}/edge-fw"]
check("an organization's password is in its collection", SERVER["containers"][acme_fw["cid"]] == "Toner - Acme")
check("items have readable titles and user names", acme_fw["title"] == "edge-fw (Acme) – Password" and acme_fw["user"] == "fwadmin"
      and by_tid["core-sw"]["title"] == "core-sw – Password" and by_tid["service:proxy"]["title"] == "Toner proxy password", by_tid)
check("Toner's own name is in the hidden field, so titles can change", acme_fw["tid"] == f"org{acme}/edge-fw")
check("the status line", extstore.status_text() == "Connected to Bitwarden. 3 changes sent.", extstore.status_text())
check("Toner keeps its own copy", passvault.get("core-sw") == "global-sw-pw")
st = extstore.sync_once()
check("nothing to send the next time", st["sent"] == 0 and len(SERVER["items"]) == 3)

print("== while it can't be reached")
SERVER["online"] = False
db.set_secret(db.secret_name("core-sw"), "changed-offline")
check("a change is kept and queued", passvault.get("core-sw") == "changed-offline" and extstore.pending() == {"core-sw": "put"})
check("Toner reads its copy meanwhile", keyring.get_password(db.SERVICE, "core-sw") == "changed-offline")
st = extstore.sync_once()
check("the status says so, in the agreed words", not st["connected"]
      and extstore.status_text() == "Can't reach Bitwarden. Toner is using its saved copies; 1 changes will be sent when it can.", extstore.status_text())
check("the queue survives (it is in the vault)", json.loads(passvault.get(extstore.PENDING)) == {"core-sw": "put"})
SERVER["online"] = True
st = extstore.sync_once()
check("once it can be reached the change is sent", st["sent"] == 1 and by_tid["core-sw"]["pw"] == "changed-offline" and extstore.pending() == {})

print("== changes made in the password manager")
by_tid["core-sw"]["pw"] = "rotated-in-bitwarden"
extstore.sync_once()
check("are copied back to Toner", passvault.get("core-sw") == "rotated-in-bitwarden")
by_tid["core-sw"]["pw"] = "bitwarden-side"
SERVER["online"] = False
db.set_secret(db.secret_name("core-sw"), "toner-side")
SERVER["online"] = True
extstore.sync_once()
check("when both changed, Toner's queued change wins (the newer edit)", by_tid["core-sw"]["pw"] == "toner-side" and passvault.get("core-sw") == "toner-side")
db.delete_secret("service:proxy")
extstore.sync_once()
check("a password Toner deletes is deleted there too", "service:proxy" not in {i["tid"] for i in SERVER["items"].values()})

print("== a collection Toner may not create")
beta = orgs.create("Beta", "BETA")
with db.within(beta):
    db.save_device(dev("beta-sw"))
    db.set_secret(db.secret_name("beta-sw"), "beta-pw")
SERVER["may_create"] = False
st = extstore.sync_once()
check("is said, in the agreed words", "Toner - Beta doesn't exist and Toner isn't allowed to create it. Create it in Bitwarden, or pick another." in extstore.status_text(),
      extstore.status_text())
check("the other organizations still sync", st["connected"])
SERVER["containers"]["cx"] = "Beta passwords"
cfg = extstore.config("bitwarden"); cfg["containers"] = {str(beta): "Beta passwords"}; extstore.set_config("bitwarden", cfg)
st = extstore.sync_once()
check("another collection can be picked for an organization", any(i["cid"] == "cx" and i["tid"] == f"org{beta}/beta-sw" for i in SERVER["items"].values()))
SERVER["may_create"] = True

print("== links")
SERVER["items"]["team-1"] = {"cid": "c1", "tid": "", "title": "Core switch (team)", "user": "admin", "pw": "team-pw"}
found = FakeManager({}, {}).search("core switch")
check("Link... finds items Toner did not make", [i.title for i in found] == ["Core switch (team)"])
extstore.set_link("core-sw", {"ref": "team-1", "title": "Core switch (team)"})
extstore.sync_once()
check("a linked password is read from the linked item", passvault.get("core-sw") == "team-pw")
check("...and kept as Toner's stored copy, in its own item too", by_tid["core-sw"]["pw"] == "team-pw")
SERVER["items"]["team-1"]["pw"] = "team-pw-2"
extstore.sync_once()
check("a change to the linked item is followed", passvault.get("core-sw") == "team-pw-2")
del SERVER["items"]["team-1"]
extstore.sync_once()
check("when the linked item can't be read, the stored copy stays", passvault.get("core-sw") == "team-pw-2" and extstore.link_failed("core-sw"))
check("and the result says so, in the agreed words",
      extstore.fallback_note("core-sw", ["core-sw"]) == "core-sw: the linked Bitwarden item couldn't be read, so Toner used its stored copy.")
from core import runner
rows = runner.stored_copy_note(db.list_devices()[0] if db.list_devices()[0]["name"] == "core-sw" else next(d for d in db.list_devices() if d["name"] == "core-sw"))
check("checks add a WARN row for it", rows and rows[0].status == "WARN" and rows[0].check == "credentials", rows)
db.move_secret("core-sw", "core-sw2")
check("a renamed password keeps its link", extstore.link_of("core-sw2") and not extstore.link_of("core-sw"))
extstore.set_link("core-sw2", None)
check("Unlink removes it", extstore.link_of("core-sw2") is None and not extstore.link_failed("core-sw2"))

print("== back to Toner's vault")
extstore.use("toner")
db.set_secret("after", "x")
check("nothing is queued any more, and every password is still in Toner's vault", extstore.pending() == {} and passvault.get(f"org{acme}/edge-fw") == "acme-fw-pw")
check("the internal entries are not passwords", not any(n.startswith("~ext/") for n in extstore.local_names()))

print("== Bitwarden and Vaultwarden through bw.exe")
extvault.CONNECTORS["bitwarden"] = extvault.Bitwarden
class FakeBw(extvault.Vaultwarden):
    def __init__(self, *a):
        super().__init__(*a); self.log = []; self.answers = {}
    def run(self, *args, stdin=None, extra=None):
        self.log.append((args, stdin, dict(extra or {})))
        key = " ".join(args[:2])
        return self.answers.get(key, self.answers.get(args[0], ""))
bw = FakeBw({"server": "vw.example.com", "client_id": "user.abc", "organization": "MSP"}, {"client_secret": "cs", "master_password": "mp"})
bw.answers = {"status": json.dumps({"serverUrl": "https://other.example.com", "status": "locked"}), "unlock": "SESSIONKEY\n",
              "list organizations": json.dumps([{"id": "o1", "name": "MSP"}]), "list collections": json.dumps([{"id": "col1", "name": "Toner - Global"}]),
              "create item": json.dumps({"id": "new1"}), "list items": json.dumps([
                  {"id": "x1", "type": 1, "name": "core-sw – Password", "login": {"username": "admin", "password": "pw"}, "collectionIds": ["col1"],
                   "fields": [{"name": "toner_id", "value": "core-sw", "type": 1}]},
                  {"id": "x2", "type": 1, "name": "someone else's", "login": {"password": "nope"}, "collectionIds": ["col1"], "fields": []}])}
bw.connect()
cmds = [" ".join(a) for a, _s, _e in bw.log]
check("Vaultwarden: a login on another server is logged out, then the server is set", cmds[:3] == ["status", "logout", "config server https://vw.example.com"], cmds)
login = next(e for a, _s, e in bw.log if a[:2] == ("login", "--apikey"))
check("it logs in with the API key from the environment, never the command line", login == {"BW_CLIENTID": "user.abc", "BW_CLIENTSECRET": "cs"}
      and not any(a in ("cs", "mp") for args, _s, _e in bw.log for a in args))
check("it unlocks with the master password from the environment", any(a[:2] == ("unlock", "--passwordenv") and e.get("TONER_BW_PASSWORD") == "mp" for a, _s, e in bw.log))
check("the session is used, and the organization found by name", bw.session == "SESSIONKEY" and bw.org_id == "o1")
check("it keeps its own bw settings folder", bw.env()["BITWARDENCLI_APPDATA_DIR"].endswith("bitwarden-cli") and bw.env()["BW_SESSION"] == "SESSIONKEY")
items = bw.items("col1")
check("only Toner's items are its items", list(items) == ["core-sw"] and items["core-sw"].value == "pw")
bw.put("col1", "org2/x", "x (Acme) – Password", "u", "s3cret")
args, stdin, _e = bw.log[-1]
body = json.loads(base64.b64decode(stdin))
check("a new item goes in through standard input, in the collection, with the hidden field", args == ("create", "item") and body["collectionIds"] == ["col1"]
      and body["organizationId"] == "o1" and body["login"]["password"] == "s3cret" and body["fields"] == [{"name": "toner_id", "value": "org2/x", "type": 1}])
check("Bitwarden's region is its address", extvault.Bitwarden({"region": "https://vault.bitwarden.eu"}, {}).server() == "https://vault.bitwarden.eu"
      and extvault.Bitwarden({}, {}).server() == "https://vault.bitwarden.com")
try:
    extvault.Bitwarden({}, {}).connect(); check("missing settings are said", False)
except extvault.ExtError as e:
    check("missing settings are said", str(e) == "Enter the client ID.", str(e))

import shutil as _sh
real_which = _sh.which
_sh.which = lambda name, path=None: (r"C:\Toolsw.exe" if path == "SAVED" else None)
real_saved = extvault.saved_path; extvault.saved_path = lambda: "SAVED"
check("a bw.exe added to PATH after Toner started is found (PATH as Windows has it saved now)", extvault.Bitwarden({}, {}).exe() == r"C:\Toolsw.exe")
_sh.which = real_which; extvault.saved_path = real_saved
check("the saved PATH is read from Windows", "system32" in extvault.saved_path().lower())
print("== 1Password through op.exe")
class FakeOp(extvault.OnePassword):
    def __init__(self, *a):
        super().__init__(*a); self.log = []; self.answers = {}
    def run(self, *args, stdin=None, extra=None):
        self.log.append((args, stdin)); return self.answers.get(" ".join(args[:2]), "")
op = FakeOp({}, {"token": "ops_tok"})
check("the service account token goes in the environment", op.env()["OP_SERVICE_ACCOUNT_TOKEN"] == "ops_tok")
op.answers = {"item list": json.dumps([{"id": "a"}, {"id": "b"}]),
              "item get": json.dumps({"id": "a", "title": "t", "vault": {"id": "v1", "name": "Toner - Global"}, "fields": [
                  {"purpose": "USERNAME", "value": "u"}, {"purpose": "PASSWORD", "value": "p"}, {"label": "toner_id", "value": "core-sw"}]})
              + "\n" + json.dumps({"id": "b", "title": "other", "vault": {"id": "v1"}, "fields": [{"purpose": "PASSWORD", "value": "q"}]}),
              "item create": json.dumps({"id": "n1"})}
items = op.items("v1")
check("every item is read in one call (the list goes to item get on standard input)", op.log[-1][0][:3] == ("item", "get", "-") and json.loads(op.log[-1][1]) == [{"id": "a"}, {"id": "b"}])
check("Toner's items are found by their hidden field", list(items) == ["core-sw"] and items["core-sw"].value == "p" and items["core-sw"].ref == "v1/a")
ref = op.put("v1", "core-sw", "core-sw – Password", "u", "newpw", items["core-sw"])
created = [s for a, s in op.log if a[:2] == ("item", "create")][-1]
check("a change is a new item from standard input, then the old one is deleted (op edits take values on the command line)",
      json.loads(created)["fields"][1]["value"] == "newpw" and op.log[-1][0][:3] == ("item", "delete", "a") and ref == "v1/n1")
check("no password is ever on op's command line", not any("newpw" in a for args, _s in op.log for a in args))

print("== Keeper through Secrets Manager")
import keeper_secrets_manager_core as KSM
class FakeFolder:
    def __init__(self, uid, name, parent=""): self.folder_uid, self.name, self.parent_uid = uid, name, parent
class FakeRecord:
    def __init__(self, uid, title, pw, folder, tid=""):
        self.uid, self.title, self.password, self.folder_uid, self.inner_folder_uid = uid, title, pw, folder, None
        self.dict = {"fields": [{"type": "login", "value": ["u"]}, {"type": "password", "value": [pw]}],
                     "custom": [{"type": "text", "label": "toner_id", "value": [tid]}] if tid else []}
    def field(self, kind, value=None, single=False):
        f = next(x for x in self.dict["fields"] if x["type"] == kind)
        if value is not None:
            f["value"] = [value]
            if kind == "password": self.password = value
        return f["value"][0] if single else f["value"]
    def _update(self): pass
KEEPER = {"bound": [], "created": [], "saved": []}
class FakeSM:
    def __init__(self, token=None, hostname=None, config=None, log_level=None, **k):
        KEEPER["bound"].append((token, hostname)); self.config = config
        if token: config.config = {"clientId": "cid", "privateKey": "pk"}
    def get_folders(self): return [FakeFolder("sf1", "Toner - Global"), FakeFolder("sub1", "Toner - Acme", "sf1")]
    def get_secrets(self, uids=None):
        recs = [FakeRecord("r1", "core-sw – Password", "kpw", "sf1", "core-sw"), FakeRecord("r2", "team item", "tpw", "sf1")]
        return [r for r in recs if not uids or r.uid in uids]
    def create_secret_with_options(self, opts, rec, folders=None): KEEPER["created"].append((opts.folder_uid, opts.subfolder_uid, rec)); return "r9"
    def save(self, rec): KEEPER["saved"].append(rec)
    def delete_secret(self, uids): pass
KSM.SecretsManager = FakeSM
from keeper_secrets_manager_core import storage as KS
class FakeStorage:
    def __init__(self, cfg=None): self.config = {}
    def read_storage(self): return dict(self.config)
KS.InMemoryKeyValueStorage = FakeStorage
k = extvault.Keeper({"region": "EU"}, {"token": "abc123"})
k.connect()
check("the one-time token is used once, with the chosen region", KEEPER["bound"][-1] == ("abc123", "keepersecurity.eu"))
check("...and the configuration Keeper gives back replaces it", k.new_secrets == {"config": json.dumps({"clientId": "cid", "privateKey": "pk"}), "token": ""})
k2 = extvault.Keeper({}, {"token": "US:xyz"}); k2.connect()
check("a token with its region in front needs no region", KEEPER["bound"][-1] == ("US:xyz", None))
check("shared folders are the containers", k.containers() == {"Toner - Global": "sf1", "Toner - Acme": "sub1"})
check("Toner's records are found by their hidden field", list(k.items("sf1")) == ["core-sw"] and k.items("sf1")["core-sw"].value == "kpw")
k.put("sub1", "org2/x", "x (Acme) – Password", "u", "pw")
check("a record for a folder inside a shared folder names both", KEEPER["created"][-1][:2] == ("sf1", "sub1"))
check("...with the hidden field", KEEPER["created"][-1][2].custom[0].label == "toner_id" and KEEPER["created"][-1][2].custom[0].value == ["org2/x"])
check("a linked record is read", k.read("r2") == "tpw")
try:
    k.ensure("Toner - Nowhere"); check("Keeper does not make shared folders", False)
except extvault.NotAllowed as e:
    check("Keeper does not make shared folders: it says to create it", "Create it in Keeper, or pick another." in str(e))

print("== Settings > Security")
extvault.CONNECTORS["bitwarden"] = FakeManager
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
import ui.settings as ST
S = ST.SettingsTab(); S.resize(1200, 900); S.show(); S.select_page("Security"); app.processEvents()
sec = next(p for p in S.pages if p.title == "Security")
v = sec.vault
check("Store passwords in lists each choice with its icon", [v.kind.itemText(i) for i in range(v.kind.count())] == ["Toner's vault", "Bitwarden", "Vaultwarden", "Keeper", "1Password"]
      and all(not v.kind.itemIcon(i).isNull() for i in range(v.kind.count())))
check("Toner's vault needs nothing filled in", v.chosen() == "toner" and not v.stack.isVisibleTo(sec) and not v.table.isVisibleTo(sec))
v.kind.setCurrentIndex(v.kind.findData("bitwarden")); app.processEvents()
f = v.fields["bitwarden"]
labels = [lab.text() for i in range(f.form.rowCount()) for lab in [f.form.labelForField(f.form.itemAt(i, f.form.ItemRole.FieldRole).widget())] if lab and lab.text()]
check("Bitwarden asks for its region, API key, master password, organization and CLI", labels == ["Region", "Client ID", "Client secret", "Master password", "Organization", "Bitwarden CLI"], labels)
check("the table: an organization per row, its collection named after it", v.table.horizontalHeaderItem(1).text() == "Collection" and v.table.item(1, 1).text() == "Toner - Acme"
      and v.where.text() == "<b>Where each organization's passwords go</b>")
for kind, word in (("onepassword", "Vault"), ("keeper", "Shared folder")):
    v.kind.setCurrentIndex(v.kind.findData(kind)); app.processEvents()
    check(f"{extvault.LABELS[kind]} calls it {word}", v.table.horizontalHeaderItem(1).text() == word)
vw = v.fields["vaultwarden"]
check("Vaultwarden asks for the server address instead of a region", vw.form.labelForField(vw.form.itemAt(0, vw.form.ItemRole.FieldRole).widget()).text() == "Server address")
v.kind.setCurrentIndex(v.kind.findData("bitwarden")); app.processEvents()
f.boxes["client_id"].setText("user.typed"); f.secret_boxes["master_password"].setText("typed-secret")
S.check_dirty(True)
check("typing here is not an unsaved setting (these act through their own buttons)", S.dirty_pages() == [] and S.pending_changes() == [])
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
v.use()
n = len(extstore.local_names())
check("Use this vault asks first", asked and asked[-1] == f"Move Toner's {n:,} saved passwords to Bitwarden? Toner keeps an encrypted copy of each in its own vault, for when Bitwarden can't be reached.", asked)
check("...then uses it, keeping what was typed (the secret in the vault, not in settings)", extstore.active() == "bitwarden"
      and extstore.config("bitwarden")["client_id"] == "user.typed" and extstore.secret("bitwarden", "master_password") == "typed-secret"
      and "typed-secret" not in json.dumps(db.get_setting("vault_config")))
check("a kept secret is never shown again", f.secret_boxes["master_password"].text() == "" and f.secret_boxes["master_password"].placeholderText() == "saved in the vault - leave blank to keep it")
extstore.sync_once()
v.show_status()
check("the status line follows the sync", v.status.text().startswith("Connected to Bitwarden."), v.status.text())

print("== Link... in the windows")
from ui import linkitem
import ui.inventory as INV
d = INV.DeviceDialog(next(x for x in db.list_devices() if x["name"] == "core-sw2" or x["name"] == "core-sw"))
d.show(); d.tabs.setCurrentWidget(d.page_access); app.processEvents()
check("a device's password has Link... under it while a manager is chosen", d.link_row.isVisibleTo(d) and d.link_row.link_btn.text() == "Link...")
SERVER["items"]["team-2"] = {"cid": "c1", "tid": "", "title": "Shared admin", "user": "admin", "pw": "shared-pw"}
linkitem.LinkDialog.exec = lambda self: (self.worker.wait(3000), app.processEvents(), self.list.topLevelItem(0).setSelected(True), 1)[-1]
dlg_title = []
real_init = linkitem.LinkDialog.__init__
def spy(self, *a, **k):
    real_init(self, *a, **k); dlg_title.append((self.windowTitle(), [self.list.headerItem().text(i) for i in range(3)]))
linkitem.LinkDialog.__init__ = spy
d.link_row.pick()
check("Link... opens 'Link to a Bitwarden item' with Name, User name and Collection", dlg_title and dlg_title[-1] == ("Link to a Bitwarden item", ["Name", "User name", "Collection"]), dlg_title)
check("once picked it reads 'Linked to: ...' with Unlink", d.link_row.label.text().startswith("Linked to: ") and d.link_row.unlink_btn.isVisibleTo(d.link_row))
d.link_row.apply(db.secret_name(d.dev["name"]) if hasattr(d, "dev") and d.dev else db.secret_name("core-sw2"))
check("saving keeps the link", any(n.startswith("~ext/link/") for n in passvault.names()))
extstore.use("toner")
d2 = INV.DeviceDialog(); d2.show(); d2.tabs.setCurrentWidget(d2.page_access); app.processEvents()
check("with Toner's vault there is no Link...", not d2.link_row.isVisibleTo(d2))
print("== ignoring the proxy: updates and the password manager")
from core import proxy, updates
db.set_setting("proxy", {"mode": "manual", "kind": "http", "host": "px.corp", "port": 3128, "username": "", "bypass": "*.internal"})
env = proxy.child_env({"PATH": "x", "HTTPS_PROXY": "http://old:1", "no_proxy": "y"}, "vault.bitwarden.com")
check("bw and op get Toner's proxy in the variables they read (replacing any set before Toner started)",
      env["HTTPS_PROXY"] == "http://px.corp:3128" and env["HTTP_PROXY"] == "http://px.corp:3128" and "no_proxy" not in env and env["PATH"] == "x", env)
env = proxy.child_env({"HTTPS_PROXY": "http://old:1"}, "vault.bitwarden.com", direct=True)
check("connecting directly gives them no proxy at all", "HTTPS_PROXY" not in env and env["NO_PROXY"] == "*", env)
env = proxy.child_env({}, "pw.internal")
check("an address on the bypass list is reached directly", "HTTPS_PROXY" not in env and env["NO_PROXY"] == "*")
import core.extvault as EV
seen_env = []
real_run = EV.subprocess.run
EV.subprocess.run = lambda args, **k: (seen_env.append(k["env"]), type("P", (), {"returncode": 0, "stdout": "{}", "stderr": ""})())[1]
tool = extvault.Bitwarden({"cli": sys.executable}, {})
tool.run("status")
check("the password manager follows Settings > Proxy by default", seen_env[-1].get("HTTPS_PROXY") == "http://px.corp:3128")
db.set_setting("vault_direct", True)
tool.run("status")
check("...and connects directly once its tick box is on", "HTTPS_PROXY" not in seen_env[-1] and seen_env[-1]["NO_PROXY"] == "*")
EV.subprocess.run = real_run
posted = []
import requests as _rq
real_post = _rq.post
_rq.post = lambda url, **k: posted.append(k.get("proxies")) or type("R", (), {"status_code": 200, "content": b"", "text": ""})()
class SM: pass
sm = SM(); extvault._route(sm)
class TK: publicKeyId = 10; encryptedKey = b"k"
class PL: encrypted_payload = b"p"; signature = b"s"
sm.post_function("https://keepersecurity.com/api/rest/sm/v1/get_secret", TK(), PL())
check("Keeper connects directly with the tick box on", posted[-1] == {"http": "", "https": ""}, posted)
db.set_setting("vault_direct", False)
sm.post_function("https://keepersecurity.com/api/rest/sm/v1/get_secret", TK(), PL())
check("...and through Toner's proxy with it off", posted[-1] == {"http": "http://px.corp:3128", "https": "http://px.corp:3128"}, posted)
_rq.post = real_post
check("updates follow Settings > Proxy by default", updates._proxies("https://api.github.com/repos/x") == {"proxies": {"http": "http://px.corp:3128", "https": "http://px.corp:3128"}})
db.set_setting("update_direct", True)
check("...and connect directly with About's tick box on", updates._proxies("https://api.github.com/repos/x") == {"proxies": {"http": "", "https": ""}})
db.set_setting("update_direct", False)
import ui.about as AB
ab = AB.AboutTab()
check("About has the tick box, in the agreed words", ab.direct_box.text() == "Connect directly for updates (ignore the proxy settings)" and not ab.direct_box.isChecked())
ab.direct_box.setChecked(True)
check("ticking it is kept", db.get_setting("update_direct") is True)
v.kind.setCurrentIndex(v.kind.findData("bitwarden")); app.processEvents()
check("Settings > Security has the password manager's tick box, in the agreed words",
      v.direct.text() == "Connect directly to the password manager (ignore the proxy settings)" and v.direct.isVisibleTo(sec))
v.direct.setChecked(True)
check("ticking it is kept right away, and is not an unsaved setting", db.get_setting("vault_direct") is True and (S.check_dirty(True), S.dirty_pages())[1] == [])
v.kind.setCurrentIndex(v.kind.findData("toner")); app.processEvents()
check("it is not offered for Toner's vault (nothing to connect to)", not v.direct.isVisibleTo(sec))
print("== which bw.exe / op.exe, and the indicator at the bottom")
fake_bw = os.path.join(SP, "bw.exe"); open(fake_bw, "w").close()
from core import platforms
bwf = v.fields["bitwarden"]
bwf.boxes["cli"].setText(fake_bw)
check("a chosen bw.exe shows in its box, with no line under it", bwf.boxes["cli"].text() == fake_bw and bwf.where.isHidden())
bwf.boxes["cli"].setText("")
_sh.which = lambda name, path=None: fake_bw
bwf.show_where()
check("one found on PATH is named inside the empty box", bwf.boxes["cli"].placeholderText() == f"Using bw: {fake_bw}" and bwf.where.isHidden(),
      bwf.boxes["cli"].placeholderText())
_sh.which = lambda name, path=None: None
bwf.boxes["cli"].setText(""); bwf.show_where()            # (the box was already empty: look again, as opening the page does)
check("...or, when there is none, the line under it says how to get one", not bwf.where.isHidden() and bwf.boxes["cli"].placeholderText() == f"{platforms.exe('bw')} (found automatically when it is on the PATH)" and bwf.where.text().replace(".exe", "") == "bw was not found. Download the Bitwarden CLI, then choose bw with Browse..., or put it in a folder on your PATH.", bwf.where.text())
opf = v.fields["onepassword"]; opf.show_where()
check("the same for op.exe", opf.where.text().replace(".exe", "").startswith("op was not found. Download the 1Password CLI, then choose op"), opf.where.text())
_sh.which = real_which
check("Keeper has no CLI line", not hasattr(v.fields["keeper"], "where"))
import types
from ui.statusstrip import StatusStrip
strip = StatusStrip(types.SimpleNamespace())
went = []
strip.navigate.connect(lambda a, b: went.append((a, b)))
plain = lambda: __import__("re").sub("<[^>]+>", "", strip.vault.text()).replace("&#9679;", "*")
extstore.use("toner"); strip.show_vault()
check("with Toner's vault it says so", strip.vault.text() == "Passwords: Toner's vault")
extstore.use("bitwarden"); strip.show_vault()
check("before the first round: connecting", strip.vault.text() == "Bitwarden: connecting...")
SERVER["online"] = True; extstore.sync_once(); strip.show_vault()
check("connected: a green dot", plain() == "* Bitwarden connected" and "Connected to Bitwarden." in strip.vault.toolTip(), (plain(), strip.vault.toolTip()))
SERVER["online"] = False; db.set_secret("waiting-one", "w"); extstore.sync_once(); strip.show_vault()
check("unreachable: a red dot, and the tooltip says what Toner does meanwhile", plain() == "* Bitwarden disconnected"
      and strip.vault.toolTip() == "Can't reach Bitwarden. Toner is using its saved copies; 1 changes will be sent when it can. Click to try again.", (plain(), strip.vault.toolTip()))
strip._vault_clicked()
check("clicking it tries again and opens Settings > Security", went[-1] == ("Settings", "Security"))
SERVER["online"] = True; extstore._status["waiting"] = 0
from core import extstore as ES
real_status = ES.status
ES.status = lambda: {**real_status(), "connected": True, "waiting": 3, "problems": []}; strip.show_vault()
check("changes waiting: amber, with how many", plain() == "* Bitwarden connected, 3 changes waiting", plain())
ES.status = lambda: {**real_status(), "connected": True, "waiting": 0, "problems": ["Toner - Beta doesn't exist ..."]}; strip.show_vault()
check("a collection missing: amber", plain() == "* Bitwarden connected, but a collection is missing", plain())
ES.status = real_status
extstore.use("toner")

print("== without copies in Toner's vault")
extvault.CONNECTORS["bitwarden"] = FakeManager
SERVER["online"] = True
extstore.use("bitwarden")
check("copies are kept unless turned off", extstore.keep_copies() and not extstore.memory_only())
db.set_secret("not-yet-sent", "x")
try:
    extstore.set_keep_copies(False); check("copies can't be removed before everything is in the manager", False)
except extstore.CannotSwitch as e:
    check("copies can't be removed before everything is in the manager, in the agreed words", str(e) ==
          "Toner can't remove its copies until every password is in Bitwarden. Connect to Bitwarden and wait for the waiting changes to be sent, then try again.", str(e))
extstore.sync_once()
before = {n: passvault.get(n) for n in extstore.local_names()}
extstore.set_keep_copies(False)
check("turned off: Toner's vault keeps only its own entries (its Bitwarden login, links)", extstore.memory_only()
      and all(n.startswith("~ext/") for n in passvault.names()) and any(n.startswith("~ext/bitwarden/") for n in passvault.names()) or
      not any(n in before for n in passvault.names()), passvault.names())
check("...and the passwords are still there, in memory", keyring.get_password(db.SERVICE, "not-yet-sent") == "x" and len(extstore.local_names()) == len(before))
db.set_secret("made-now", "m1")
check("a new password goes to memory and waits to be sent, never to Toner's vault", passvault.get("made-now") is None and extstore.pending() == {"made-now": "put"})
extstore.sync_once()
check("...then it is sent", any(i["tid"] == "made-now" and i["pw"] == "m1" for i in SERVER["items"].values()) and extstore.pending() == {})
SERVER["online"] = False
db.set_secret("made-offline", "m2")
extstore.sync_once()
check("unreachable: the tooltip says passwords are unavailable, in the agreed words",
      extstore.status_text() == "Can't reach Bitwarden. Without copies, saved passwords are unavailable until it can; 1 change will be sent when it can.", extstore.status_text())
check("the unsent change is counted (Toner asks before closing)", extstore.unsent() == 1)
extstore._mem.clear(); extstore._mem_pending.clear(); extstore._loaded = False           # Toner starts again
check("after a restart, nothing is known until the manager answers", keyring.get_password(db.SERVICE, "made-now") is None)
try:
    extstore.use("toner"); check("switching back needs the manager", False)
except extstore.CannotSwitch as e:
    check("switching back needs the manager, in the agreed words",
          str(e) == "Toner can't switch back to its own vault while Bitwarden can't be reached: the passwords are only in Bitwarden.", str(e))
SERVER["online"] = True
extstore.sync_once()
check("once it answers, the passwords are read into memory", keyring.get_password(db.SERVICE, "made-now") == "m1" and passvault.get("made-now") is None)
db.set_secret("last-edit", "le")
extstore.use("toner")
check("switching back copies every password into Toner's vault first", extstore.active() == "toner" and passvault.get("made-now") == "m1"
      and passvault.get("last-edit") == "le" and extstore.keep_copies())
check("...and copies are on again for next time", db.get_setting("vault_keep_copies") is True)

print("== Keep a copy in Settings")
extstore.use("bitwarden"); extstore.sync_once()
v.load(); v.kind.setCurrentIndex(v.kind.findData("bitwarden")); v._show(); app.processEvents()
check("the tick box and its note, in the agreed words", v.copies.text() == "Keep a copy of each password in Toner's vault" and v.copies.isChecked()
      and v.copies_note.text() == "Checks keep working when the password manager can't be reached. Without copies, Toner reads passwords from the password manager each time it starts and keeps them only in memory.")
v.kind.setCurrentIndex(v.kind.findData("keeper")); app.processEvents()
check("it is shown for the password manager in use", not v.copies.isVisibleTo(sec))
v.kind.setCurrentIndex(v.kind.findData("bitwarden")); app.processEvents()
asked, told = [], []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.No)
QMessageBox.information = staticmethod(lambda *a, **k: told.append(a[2]))
v.copies.setChecked(False)
n = len(extstore.local_names())
check("unticking asks first, in the agreed words", asked and asked[-1] == f"Remove Toner's copies of {n:,} passwords? Toner will read them from Bitwarden each time it starts. While Bitwarden can't be reached, checks that need a password will fail.", asked[-1:])
check("No keeps them", extstore.keep_copies() and v.copies.isChecked())
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
SERVER["online"] = False; extstore.sync_once()
v.copies.setChecked(False)
check("while the manager can't be reached it says why it can't, and stays ticked", told and told[-1].startswith("Toner can't remove its copies until every password is in Bitwarden.") and v.copies.isChecked())
SERVER["online"] = True; extstore.sync_once()
v.copies.setChecked(False)
check("Yes removes them", extstore.memory_only() and not v.copies.isChecked())
v.copies.setChecked(True)
check("ticking it again writes the copies back", extstore.keep_copies() and passvault.get("made-now") == "m1")
extstore.use("toner")
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
