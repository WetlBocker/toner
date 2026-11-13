# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings a role may only view stay unchanged on two side paths, the Reset to Global link above a locked page and Import
# settings; and a settings file can't move where a saved key or password is sent (ui/settings.py, ui/settings_pages/security.py,
# core/db.py NOT_PORTABLE).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "settingsside%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
from core import datakey, orgs, perms, roles, session
import app as A
A.plain_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

SHOWN = []
for n in ("question", "warning", "information"):
    setattr(QMessageBox, n, staticmethod(lambda *a, _n=n, **k: SHOWN.append((_n, a[2])) or QMessageBox.StandardButton.Yes))
PW, PW2 = "correct horse battery 42", "amber kettle meadow 77"

datakey.create("Admin1", PW); db.init()
session.sign_out(); session.sign_in("Admin1", PW)

# ---------------------------------------------------------------- a settings file can't move where saved secrets go
db.set_setting("iplookup_url", "https://lookup.example/{ip}?k={key}")
FILE = {"iplookup_url": "https://other.example/{ip}?k={key}", "proxy": {"type": "http", "host": "other.example"},
        "ssh_tunnel": {"host": "other.example"}, "retention_days": 31}
for name in ("ipstack", "service:proxy", "service:ssh-tunnel"):
    db.set_secret(name, "saved-secret")
applied, skipped = db.import_settings(FILE)
check("with a key and passwords saved, an import leaves the look-up address, the proxy and the tunnel alone",
      db.get_setting("iplookup_url") == "https://lookup.example/{ip}?k={key}" and {"iplookup_url", "proxy", "ssh_tunnel"} <= set(skipped), (applied, skipped))
check("and still applies an ordinary setting", "retention_days" in applied and db.get_setting("retention_days") == 31, applied)
check("the same address as now is no change", "iplookup_url" in db.import_settings({"iplookup_url": "https://lookup.example/{ip}?k={key}"})[0])
for name in ("ipstack", "service:proxy", "service:ssh-tunnel"):
    db.delete_secret(name)
applied, skipped = db.import_settings(FILE)
check("with nothing saved they travel as before", {"iplookup_url", "proxy", "ssh_tunnel"} <= set(applied), (applied, skipped))

# ---------------------------------------------------------------- a Tech, with only Data and logs open among the locked pages
datakey.add_local("Tech1", PW2, role="Tech")
roles.set_permissions("Tech", {"settings:Data and logs": True})
acme = orgs.create("Acme", "ACME")
with db.within(acme):
    db.set_setting("backup_mask", False)                     # the Admin gives Acme its own value
roles.sync_grants()
session.sign_out(); session.sign_in("Tech1", PW2)
check("signed in as a Tech who may change Data and logs but not Config backups or Security",
      perms.allowed("settings:Data and logs") and not perms.allowed("settings:Config backups") and not perms.allowed("settings:Security"))

w = A.Main(); w.resize(1100, 800); w.show(); app.processEvents()
st = w.settings
w.set_org(acme); app.processEvents()
w.go("Settings"); st.select_page("Config backups"); app.processEvents()
titles = [p.title for p in st.pages]
i = titles.index("Config backups")
def own():
    db._forget_settings()
    with db.within(acme):
        return db.overridden("backup_mask"), db.get_setting("backup_mask")
check("the locked page offers no Reset to Global link", i in st.locked and "Reset to Global" not in st.own_lines[i].text(), st.own_lines[i].text())
st.reset_to_global(i, "backup_mask"); app.processEvents()
check("and a reset on a locked page changes nothing", own() == (True, False), own())

path = os.path.join(SP, "settings-in.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump({"hostkey_mode": "Always trust", "ai_run_commands": True, "backup_mask": False}, f)
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (path, ""))
before = (db.get_setting("hostkey_mode"), db.get_setting("ai_run_commands"))
del SHOWN[:]
st.pages[titles.index("Data and logs")].import_settings(); app.processEvents()
check("an import by a role that can't change every page is refused with the role's reason",
      (db.get_setting("hostkey_mode"), db.get_setting("ai_run_commands")) == before and SHOWN == [("warning", perms.REASON)], (SHOWN, before))
w.close(); session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
