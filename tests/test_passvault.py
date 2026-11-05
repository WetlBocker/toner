# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database; the vault here is a throw-away file beside it, and nothing is written to Windows Credential Manager.
# Toner's vault: the encrypted file every password lives in, an older Toner's master password and Remember on this computer
# (still read, for the upgrade), its windows, Settings > Security, and importing passwords again to fill in sessions that have none.
# Opening it with the data key is in test_vault_datakey.py.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "pvault%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring, keyring.backend
from core import db, passvault
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

class OldStore(keyring.backend.KeyringBackend):
    """Stands in for Windows Credential Manager (so nothing real is touched)."""
    priority = 1
    def __init__(self): self.d = {}
    def get_password(self, s, u): return self.d.get(u)
    def set_password(self, s, u, p): self.d[u] = p
    def delete_password(self, s, u): self.d.pop(u)
old = OldStore()
keyring.set_keyring(old)

print("== the file")
check("there is no vault to begin with", not passvault.exists() and not passvault.is_open())
try:
    passvault.create("short")
    check("a short master password is refused", False)
except ValueError as e:
    check("a short master password is refused, saying what to do", str(e) == "Use at least 12 characters.", str(e))
passvault.create("correct horse battery", remember=False)
check("a new vault is made beside the database, and opened", passvault.path().exists() and passvault.path().parent == db.base_path().parent and passvault.is_open())
passvault.put("edge-fw", "s3cret-pw"); passvault.put("org2/session:5", "another")
raw = open(passvault.path(), encoding="utf-8").read()
check("the file never shows a password or an entry's name", "s3cret-pw" not in raw and "edge-fw" not in raw and "session:5" not in raw)
check("it is Toner's vault format", json.loads(raw)["format"] == "toner-vault")
check("entries read back", passvault.get("edge-fw") == "s3cret-pw" and passvault.names() == ["edge-fw", "org2/session:5"])
passvault.lock()
try:
    passvault.get("edge-fw"); check("a locked vault gives nothing", False)
except passvault.Locked:
    check("a locked vault gives nothing", True)
try:
    passvault.unlock("wrong password here"); check("a wrong master password is refused", False)
except passvault.WrongPassword as e:
    check("a wrong master password is refused, in the agreed words", str(e) == "That master password isn't right.", str(e))
passvault.unlock("correct horse battery")
check("the right one opens it with everything still there", passvault.get("edge-fw") == "s3cret-pw")
check("remove says whether there was one", passvault.remove("edge-fw") and not passvault.remove("edge-fw") and passvault.get("edge-fw") is None)

print("== the master password can no longer be changed")
passvault.put("edge-fw", "s3cret-pw")
check("there is no change_master or set_remembered any more", not hasattr(passvault, "change_master") and not hasattr(passvault, "set_remembered"))

print("== Remember on this computer")
if sys.platform != "win32":                       # Linux and macOS keep the remembered key in the system keyring: a stand-in
    class _NativeKeyring:
        d = {}
        def set_password(self, s, u, p): self.d[(s, u)] = p
        def get_password(self, s, u): return self.d.get((s, u))
        def delete_password(self, s, u): self.d.pop((s, u), None)
    _nk = _NativeKeyring(); passvault._native_keyring = lambda: _nk
def remember():                                   # what an older Toner's Remember on this computer left beside the vault
    open(passvault.key_path(), "wb").write(passvault._protect(passvault._key))
check("not remembered: Toner cannot open it alone", not passvault.remembered() and (passvault.lock() or not passvault.unlock_remembered()))
passvault.unlock("correct horse battery")
remember()
keyfile = open(passvault.key_path(), "rb").read()
check("remembered: a key file beside the vault, protected by Windows (not the key itself)" if sys.platform == "win32" else
      "remembered: the key is in the system keyring, and the file beside the vault says so",
      passvault.remembered() and (len(keyfile) > 100 if sys.platform == "win32" else keyfile == passvault.KEYRING_MARK and _nk.d))
passvault.lock()
check("...so Toner (and its scheduled service) open it without asking", passvault.unlock_remembered() and passvault.get("edge-fw") == "s3cret-pw")
open(passvault.key_path(), "wb").write(b"not a windows-protected key")
passvault.lock()
check("a damaged or foreign key file just means asking for the master password", not passvault.unlock_remembered())
passvault.unlock("correct horse battery"); remember()
passvault._forget_remembered()
check("forgetting it removes the key file", not passvault.key_path().exists() and not passvault.remembered())

print("== many at once, and two programs")
writes = []
real_write = passvault._write
passvault._write = lambda doc: (writes.append(1), real_write(doc))[1]
with passvault.batch():
    for i in range(500):
        passvault.put(f"session:{i}", f"pw{i % 7}")
    check("inside a batch the new entries can be read already", passvault.get("session:499") == "pw2")
    passvault.remove("session:0")
check("500 passwords are one write of the file", len(writes) == 1, len(writes))
passvault._write = real_write
check("and all are there", passvault.get("session:1") == "pw1" and passvault.get("session:0") is None and sum(n.startswith("session:") for n in passvault.names()) == 499)
doc = json.load(open(passvault.path(), encoding="utf-8"))       # another program (the scheduled service) adds one
data = passvault._unseal(passvault._key, doc["data"]); data["from-service"] = "agent-token"
doc["data"] = passvault._seal(passvault._key, data)
time.sleep(0.05)
json.dump(doc, open(passvault.path(), "w", encoding="utf-8"))
check("what another program wrote is seen", passvault.get("from-service") == "agent-token")
passvault.put("mine", "x")
check("and kept when this one writes", passvault.get("from-service") == "agent-token" and passvault.get("mine") == "x")

print("== Toner's code reaches it through keyring")
passvault.install()
keyring.set_password(db.SERVICE, "via-keyring", "kv")
check("keyring writes go to the vault", passvault.get("via-keyring") == "kv" and keyring.get_password(db.SERVICE, "via-keyring") == "kv")
keyring.delete_password(db.SERVICE, "via-keyring")
check("...and deletes", passvault.get("via-keyring") is None)
db.set_secret("dev1", "pw1"); db.delete_secret("nothing-there")
check("db's secret helpers work unchanged", keyring.get_password(db.SERVICE, "dev1") == "pw1")
check("nothing went to the old store (Credential Manager)", old.d == {})

print("== an older Toner's passwords come along")
db.save_device(dict(name="core-sw", vendor="cisco", host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0,
                    ha_expected=0, enabled=1, location="", details="", folder_id=None))
old.d.update({"core-sw": "old-pw", "service:proxy": "proxy-pw", "unrelated-app": "keep"})
carry = passvault.left_in_credential_manager()
if sys.platform == "win32":
    check("Toner's own entries are found (and nothing else)", carry == {"core-sw": "old-pw", "service:proxy": "proxy-pw"}, carry)
    passvault.forget_credential_manager(carry)
    check("...and removed from Credential Manager once moved", old.d == {"unrelated-app": "keep"})
else:
    check("off Windows there is no Credential Manager to bring passwords from", carry == {})
    old.d.pop("core-sw"); old.d.pop("service:proxy")

print("== the windows")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
print("== Settings > Security")
import ui.settings_pages.security as SEC
from ui import toast as T
pg = SEC.SecurityPage(); pg.load()
check("the Vault section: only Lock now, and not while nobody is signed in", pg.lock_now.text() == "Lock now" and not pg.lock_now.isEnabled()
      and not hasattr(pg, "change_master") and not hasattr(pg, "remember"))
check("the credentials table says the vault", pg.creds.horizontalHeaderItem(2).text() == "Stored in the vault")

os.remove(passvault.path()); passvault.lock(); passvault.create("fresh master pw!", remember=False)     # a clean vault: earlier sections left old session passwords in it
print("== importing the passwords again fills in sessions that have none")
from core import sessionimport as SI, sessions
keyring.set_keyring(old) if False else None
found = SI.Found("MobaXterm", [{"kind": "ssh", "name": "sw1", "folder": ["Site"], "host": "10.1.1.1", "port": 22, "username": "admin", "options": {}},
                                {"kind": "ssh", "name": "sw2", "folder": ["Site"], "host": "10.1.1.2", "port": 22, "username": "admin", "options": {}}])
r = SI.save(found, {})
check("first import: the sessions, no passwords", r["added"] == 2 and r["passwords"] == 0)
ids = {s["name"]: s["id"] for s in sessions.list_sessions()}
sessions.set_password(ids["sw2"], "kept-pw")
r = SI.save(found, {("ssh", "22", "admin", "10.1.1.1"): "pw-one", ("ssh", "22", "admin", "10.1.1.2"): "other"})
check("again with passwords: nothing new, the missing one filled in", r["added"] == 0 and r["existing"] == 2 and r["passwords"] == 1, r)
check("sw1 has its password now, and remembers it", sessions.password(ids["sw1"]) == "pw-one" and sessions.get(ids["sw1"])["options"]["remember"])
check("a password already saved is left alone", sessions.password(ids["sw2"]) == "kept-pw")
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
