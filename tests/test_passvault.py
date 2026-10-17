# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database; the vault here is a throw-away file beside it, and nothing is written to Windows Credential Manager.
# Toner's vault: the encrypted file every password lives in, its master password, Remember on this computer, its windows,
# Settings > Security, and importing passwords again to fill in sessions that have none.
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

print("== changing the master password")
passvault.put("edge-fw", "s3cret-pw")
passvault.change_master("a brand new master pw")
passvault.lock()
try:
    passvault.unlock("correct horse battery"); check("the old master password no longer opens it", False)
except passvault.WrongPassword:
    check("the old master password no longer opens it", True)
passvault.unlock("a brand new master pw")
check("the new one does, and the passwords are unchanged", passvault.get("edge-fw") == "s3cret-pw")

print("== Remember on this computer")
check("not remembered: Toner cannot open it alone", not passvault.remembered() and (passvault.lock() or not passvault.unlock_remembered()))
passvault.unlock("a brand new master pw")
passvault.set_remembered(True)
keyfile = open(passvault.key_path(), "rb").read()
check("remembered: a key file beside the vault, protected by Windows (not the key itself)", passvault.remembered() and len(keyfile) > 100)
passvault.lock()
check("...so Toner (and its scheduled service) open it without asking", passvault.unlock_remembered() and passvault.get("edge-fw") == "s3cret-pw")
open(passvault.key_path(), "wb").write(b"not a windows-protected key")
passvault.lock()
check("a damaged or foreign key file just means asking for the master password", not passvault.unlock_remembered())
passvault.unlock("a brand new master pw"); passvault.set_remembered(True)
passvault.set_remembered(False)
check("turning it off removes the key file", not passvault.key_path().exists() and not passvault.remembered())

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
check("Toner's own entries are found (and nothing else)", carry == {"core-sw": "old-pw", "service:proxy": "proxy-pw"}, carry)
passvault.forget_credential_manager(carry)
check("...and removed from Credential Manager once moved", old.d == {"unrelated-app": "keep"})

print("== the windows")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
from ui import vaultdlg
d = vaultdlg.MasterDialog("create")
labels = [w.text() for w in d.findChildren(vaultdlg.QLabel)]
check("first start: the agreed text", "Toner stores its passwords in its own encrypted vault. Choose a master password to lock it." in labels, labels)
check("the requirements are listed", "Password requirements:" in labels and d.rule.text() == "• At least 12 characters", d.rule.text())
d.first.setText("long enough pw")
check("...and ticked off once met", d.rule.text() == "✓ At least 12 characters")
check("the fields, the tick box (on) and the buttons", d.remember.text() == "Remember on this computer" and vaultdlg.REMEMBER_NOTE in labels and d.remember.isChecked()
      and [b.text() for b in d.buttons.buttons()] == ["Create vault", "Quit"] or sorted(b.text() for b in d.buttons.buttons()) == ["Create vault", "Quit"])
check("the warning about forgetting it", vaultdlg.FORGOT_WARNING in labels)
d.second.setText("something else"); d.accept()
check("mismatched entries are said, and it stays open", d.error.isVisibleTo(d) and d.error.text() == "The two passwords don't match." and d.result() == 0)
d.first.setText("short"); d.second.setText("short"); d.accept()
check("too short is said", d.error.text() == "Use at least 12 characters.")
d.first.setText("long enough pw"); d.second.setText("long enough pw"); d.accept()
check("a good one is accepted", d.result() == 1 and d.master() == "long enough pw")
c = vaultdlg.MasterDialog("change")
check("Change master password has no first-start text and no tick box", c.windowTitle() == "Change master password"
      and not c.remember.isVisibleTo(c) and sorted(b.text() for b in c.buttons.buttons()) == ["Cancel", "Change"])

passvault.lock()
u = vaultdlg.UnlockDialog()
check("Unlock Toner: the agreed words", u.windowTitle() == "Unlock Toner" and any(w.text() == "Enter the master password to open Toner's vault." for w in u.findChildren(vaultdlg.QLabel))
      and sorted(b.text() for b in u.buttons.buttons()) == ["Quit", "Unlock"])
u.word.setText("nope nope nope"); u.accept()
check("a wrong one says so and stays open", u.error.isVisibleTo(u) and u.error.text() == "That master password isn't right." and not passvault.is_open())
u.word.setText("a brand new master pw"); u.accept()
check("the right one opens the vault", u.result() == 1 and passvault.is_open())

asked = []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
vaultdlg.MasterDialog.exec = lambda self: (self.first.setText("fresh master pw!"), self.second.setText("fresh master pw!"), 1)[2]
passvault.lock()
u = vaultdlg.UnlockDialog(); u.forgot()
check("Forgot it? asks first, in the agreed words", asked and asked[-1] == "Start a new, empty vault? Every saved password is lost. Devices, sessions and settings stay.", asked)
check("...then a new, empty vault with the new master password", u.reset_done and passvault.is_open() and passvault.names() == [])
passvault.lock()
check("which opens with it", (passvault.unlock("fresh master pw!") or True) and passvault.is_open())

print("== the first start")
os.remove(passvault.path()); passvault.lock()
old.d.update({"core-sw": "old-pw"})
check("with no vault, the master password is asked and the vault made", vaultdlg.open_at_start() and passvault.exists() and passvault.is_open())
check("an older Toner's password came along, quietly, and left Credential Manager", passvault.get("core-sw") == "old-pw" and "core-sw" not in old.d)
passvault.lock()
vaultdlg.UnlockDialog.exec = lambda self: 0
check("next start, not remembered: Unlock is asked, and Quit stops Toner", passvault.remembered() or not vaultdlg.open_at_start())
passvault.unlock("fresh master pw!"); passvault.set_remembered(True); passvault.lock()
check("remembered: nothing is asked", vaultdlg.open_at_start() and passvault.is_open())

print("== Settings > Security")
import ui.settings_pages.security as SEC
from ui import toast as T
pg = SEC.SecurityPage(); pg.load()
check("the Vault section: Change master password, Remember on this computer", pg.change_master.text() == "Change master password..."
      and pg.remember.text() == "Remember on this computer" and pg.remember.isChecked())
check("Lock now is offered only when it is not remembered", pg.lock_now.isHidden())
pg.remember.setChecked(False)
check("unticking forgets the key on this computer, right away", not passvault.remembered() and not pg.lock_now.isHidden())
check("the tick box is not a setting waiting for Save", pg.remember.property("notSetting"))
check("the credentials table says the vault", pg.creds.horizontalHeaderItem(2).text() == "Stored in the vault")
vaultdlg.UnlockDialog.exec = lambda self: (self.word.setText("fresh master pw!"), self.accept(), 1)[2]
pg._lock()
check("Lock now closes the vault and asks again", passvault.is_open())
pg.remember.setChecked(True)

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
print("== buttons fit their words in the Ops console look")
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import QPushButton
db.set_setting("ui_style", "Ops console"); db.set_setting("theme", "Dark"); A.apply_look(app)
import importlib; importlib.reload(vaultdlg)
md, ud = vaultdlg.MasterDialog("create"), vaultdlg.UnlockDialog()
for w in (md, ud):
    w.show()
app.processEvents()
short = [(b.text(), b.width(), QFontMetrics(b.font()).horizontalAdvance(b.text())) for w in (md, ud) for b in w.findChildren(QPushButton)
         if b.width() < QFontMetrics(b.font()).horizontalAdvance(b.text()) + 8]
check("no button's text is cut off (a dialog's default button used to turn bold after it was sized)", not short, short)
check("Create vault and Unlock are the bold, coloured ones", md.ok.font().bold() and md.ok.isDefault()
      and any(b.text() == "Unlock" and b.font().bold() for b in ud.findChildren(QPushButton)))
check("a default button that is not marked primary keeps its colour but not bold, so it fits", "QPushButton:default { font-weight" not in app.styleSheet())
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
