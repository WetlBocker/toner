# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# An approval signs the role the directory gave this sign-in, not the unsigned groups_role in netcheck.keys, which the person
# being approved can edit while the approval page waits (core/roles.py approve, core/dirsignin.py _approve_as).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "approvalrole%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, directory, osstore, perms, pinslot, roles, session, dirpin, dirsignin, helperclient

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PEPPERS = {}
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: PEPPERS.__setitem__(n, v)
osstore.get = lambda n, file=None: PEPPERS.get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)
dirpin.changed = lambda dirs: False
pinslot.best_kind = lambda: "store"                              # the same slot kind on every platform
dirsignin.helper_ready = lambda: False
helperclient.state = lambda *a, **k: "off"

PW, PIN = "correct horse battery 42", "a long pin 4321"
ADMINS, TECHS = "CN=Toner Admins,DC=acme,DC=com", "CN=Toner Techs,DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [ADMINS], "Engineer": [], "Tech": [TECHS]}, "duo": {"on": False, "host": "", "ikey": ""}}
BOB = directory.User("6f1c2a4e-0000-4000-8000-000000000001", "bob@acme.com", "Bob Jones", (TECHS,), True)

datakey.create("Admin1", PW); db.init(); datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([ACME])
session.sign_out()

directory.sign_in = lambda cfg, login, pw, **k: BOB           # the directory says Tech
a = dirsignin.begin("bob@acme.com", "bob directory pw")
dirsignin.after_password(a)
dirsignin.choose_pin(a, PIN)
check("the sign-in waits for approval as a Tech", a.stage == "approve" and a.role == "Tech")

p = datakey.path(); d = json.loads(p.read_text("utf-8"))
d["accounts"]["bob@acme.com"]["groups_role"] = "Admin"       # edited by hand while the approval page waits
p.write_text(json.dumps(d), "utf-8")

dirsignin.approve(a, "Admin1", PW)
rec = datakey.directory_account("bob@acme.com")
check("the approval signs the directory's role, not the edited one", rec["approved_role"] == "Tech", rec.get("approved_role"))
dirsignin.finish(a, PIN)
check("the approved Tech is no admin and holds no role key",
      session.state() == "open" and not perms.is_admin() and not roles.holds("rules") and not roles.holds("backups"))
grants = (json.loads(p.read_text("utf-8")).get("grants") or {}).get("bob@acme.com", {})
check("no role key was wrapped to the account", not grants, sorted(grants))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
