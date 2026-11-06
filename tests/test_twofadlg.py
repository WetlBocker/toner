# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake protected store, so nothing on this computer is touched.
# Settings > Accounts > External Identities > Set up 2FA: Duo on or off on its own, the secret only in the protected store.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\twofa%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
from core import audit, datakey, db, lockdown, osstore, roles, session
db.init()

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

OS, AVAIL = {}, [True]
osstore.available = lambda: AVAIL[0]
osstore.put = lambda n, v, file=None: OS.__setitem__((n, file), v)
osstore.get = lambda n, file=None: OS.get((n, file))
osstore.delete = lambda n: OS.pop((n, None), None)

from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui import twofadlg
from ui.settings_pages import accounts as A

def pump(until, seconds=30):
    end = time.time() + seconds
    while not until() and time.time() < end:
        app.processEvents(); time.sleep(0.01)
    app.processEvents()
    return until()

PW, SECRET, SECRET2 = "violet staple orbit 42", "duo-secret-SKEY-9981", "duo-secret-OTHER-5512"
datakey.create("Admin", PW); lockdown.run(); datakey.close(); session.sign_in("Admin", PW)

def ident(i, name, kind):
    return {"id": i, "name": name, "kind": kind, "servers": ["dc.acme.test"], "port": 636, "security": "ldaps", "ca_file": "",
            "base_dn": "DC=acme,DC=test", "netbios": name[:4].upper(), "suffixes": [], "service_dn": "CN=svc,DC=acme,DC=test",
            "groups": {}, "duo": {"on": False, "host": "", "ikey": ""}}
roles.set_directories([ident("a1", "ACME", "ad"), ident("l1", "Corp", "ldap")])

def open_dlg(i=0):
    d = twofadlg.TwoFactorDialog(roles.verified()["directories"], roles.verified()["directories"][i])
    pump(lambda: d.store is not None)
    return d

def save(d):
    d.save_btn.click()
    return pump(lambda: not d._jobs)

def text_of_files():
    return datakey.path().read_text(encoding="utf-8") + json.dumps([dict(r) for r in audit.recent(5000)])

d = open_dlg()
check("labels", [d.second.itemText(i) for i in range(2)] == ["Off", "Duo"] and d.save_btn.text() == "Save")
check("Duo offered with a store", d.second.model().item(1).isEnabled() and not d.duo_note.isVisibleTo(d))
check("Off: Save is allowed, fields off", d.save_btn.isEnabled() and not d.host.isEnabled())
d.second.setCurrentIndex(1)
check("Duo, nothing typed: Save off", not d.save_btn.isEnabled())
d.host.setText("https://api-x.duosecurity.com/"); d.ikey.setText("DIX")
check("Duo, no secret anywhere: Save stays off", not d.save_btn.isEnabled())
d.host.setText("bad host!")
d.skey.setText(SECRET)
check("bad host: Save off", not d.save_btn.isEnabled())
d.host.setText("https://api-x.duosecurity.com/path?x=1")
check("Save on", d.save_btn.isEnabled())
d.save_btn.click()
d.skey.setText("typed-after-the-click")
pump(lambda: not d._jobs)
check("secret only in the fake store", OS.get(("duo:a1", None)) == SECRET.encode())
duo = roles.verified()["directories"][0]["duo"]
check("host cleaned, saved", duo == {"on": True, "host": "api-x.duosecurity.com", "ikey": "DIX"}, duo)
check("no secret in keys file or audit", SECRET not in text_of_files() and "typed-after-the-click" not in text_of_files())
check("box cleared on close", (d.reject(), d.skey.text())[1] == "")

page = A.AccountsPage(); page.load()
check("column shows On", page.idents.item(0, 2).text() == "On" and page.idents.item(1, 2).text() == "Off")

d = open_dlg()
check("reopened: Duo, stored secret makes Save possible", d.second.currentIndex() == 1 and d.save_btn.isEnabled() and d.skey.text() == "")
d.ikey.setText("DIY"); save(d)
check("empty box keeps the stored secret", OS.get(("duo:a1", None)) == SECRET.encode() and roles.verified()["directories"][0]["duo"]["ikey"] == "DIY")
d = open_dlg(); d.skey.setText(SECRET2); save(d)
check("a typed secret replaces it", OS.get(("duo:a1", None)) == SECRET2.encode())
d = open_dlg(); d.second.setCurrentIndex(0); save(d)
check("off: saved off, secret kept", not roles.verified()["directories"][0]["duo"]["on"] and OS.get(("duo:a1", None)) == SECRET2.encode())
page.refresh()
check("column shows Off", page.idents.item(0, 2).text() == "Off")
check("other directory untouched", roles.verified()["directories"][1] == ident("l1", "Corp", "ldap"))

AVAIL[0] = False
d = open_dlg(1)
check("no store: Duo disabled, approved note shown", not d.second.model().item(1).isEnabled() and not d.duo_note.isHidden()
      and d.duo_note.text() == "This computer has no protected store, so Duo can't be turned on here.")
check("...Off can still be saved", d.save_btn.isEnabled()); d.reject()
AVAIL[0] = True

d = twofadlg.TwoFactorDialog(roles.verified()["directories"], roles.verified()["directories"][1])
d.reject()
check("close during the probe Job is safe", not d._jobs)
check("no secret in the audit or keys file at the end", SECRET not in text_of_files() and SECRET2 not in text_of_files())

# the page menu
page.refresh(); page.idents.selectRow(1)
menu = page._ident_menu(None)
check("menu: Set up 2FA and Test login on", menu.actions()[1].isEnabled() and menu.actions()[0].isEnabled())
opened = []
A.TwoFactorDialog.exec = lambda self: opened.append(self.cfg["name"]) or 1
menu.actions()[1].trigger()
check("menu opens the dialog for the selected identity", opened == ["Corp"], opened)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
