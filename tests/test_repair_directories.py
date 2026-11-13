# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The recovery key's repair of a tampered keys file signs the directories last signed, not the ones in the edited file, which
# the Accounts page never shows while the rules don't verify (core/roles.py _rekey, set_directories).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "repairdirs%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, dirpin, osstore, roles, session

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PEPPERS, PINS = {}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)
def remembered(): return _box(dirpin.pins_file()).get(dirpin.store_name())

BASE = "DC=acme,DC=com"
def acme(server):
    return {"id": "d1", "name": "ACME", "kind": "ad", "servers": [server], "port": 636, "security": "ldaps", "ca_file": "",
            "base_dn": BASE, "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc," + BASE,
            "groups": {"Admin": ["CN=Toner Admins," + BASE], "Engineer": [], "Tech": ["CN=Toner Techs," + BASE]},
            "duo": {"on": False, "host": "", "ikey": ""}}
PW, PW2 = "correct horse battery 42", "amber kettle meadow 77"
def filedoc(): return json.loads(datakey.path().read_text(encoding="utf-8"))
def servers(d): return [x.get("servers") for x in (d or {}).get("directories") or []]
def edit_file(server):
    d = filedoc(); d["directories"][0]["servers"] = [server]
    datakey.path().write_text(json.dumps(d), encoding="utf-8")

recovery = datakey.create("Admin1", PW)
db.init(); datakey.close()
session.sign_in("Admin1", PW)
datakey.add_local("Tech1", PW2, role="Tech")
roles.set_directories([acme("dc1.acme.com")])
session.sign_out()
good = remembered()
check("set up: the signed list is remembered", good == dirpin.fingerprint(filedoc()["directories"]).encode())

# ---------------------------------------------------------------- a repair signs the list last signed
edit_file("ldap.other.example")
session.sign_in_recovery(recovery)
check("the edit is seen as tampered", roles.state() == "tampered", roles.state())
roles.set_permissions("Tech", {})                                 # the Accounts page's Save roles: the repair
check("the repair lands", roles.state() == "ok", roles.state())
check("the repair signs the directories last signed, not the file's", servers(roles.verified()) == [["dc1.acme.com"]], servers(roles.verified()))
check("and keeps them as the last-signed copy", servers(roles.last_signed()) == [["dc1.acme.com"]], servers(roles.last_signed()))
session.sign_out()
session.sign_in("Tech1", PW2); session.sign_out()                 # any sign-in with the rules ok refreshes the remembered list
check("the remembered list is still the signed one", remembered() == good)

# ---------------------------------------------------------------- the recovery key's own save of a new list still signs that list
edit_file("ldap.other.example")
session.sign_in_recovery(recovery)
check("tampered again", roles.state() == "tampered", roles.state())
roles.set_directories([acme("dc2.acme.com")])
check("a list saved by the recovery key during a repair is the one signed", roles.state() == "ok" and servers(roles.verified()) == [["dc2.acme.com"]],
      (roles.state(), servers(roles.verified())))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
