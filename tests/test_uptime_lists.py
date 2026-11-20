# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Proxmox and Mist got their own Uptime check: a device or monitoring profile saved before that, with its own list of checks, keeps the
# uptime row it had (the upgrade adds uptime once, in Global's file and in every organization's).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "upl%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import db, orgs
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, vendor, checks=None, org=0):
    return dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="", verify_ssl=0, ha_expected=0, enabled=1,
                location="", details="", folder_id=None, org=org, checkopts={"checks": checks} if checks is not None else {})
def prof(name, vendor, checks):
    return {"id": name, "name": name, "vendor": vendor, "checks": checks, "thresholds": {}, "scopes": ["All devices"]}

acme = orgs.create("Acme", "ACME")
SEED = {"pve-old": ("proxmox", ["reachability", "nodes", "storage"]), "pve-has": ("proxmox", ["nodes", "uptime"]), "pve-none": ("proxmox", ["reachability"]),
        "mist-old": ("mist", ["devices", "alarms"]), "mist-none": ("mist", ["alarms"]), "sw": ("cisco", ["cpu", "nodes", "devices"]),
        "pve-global": ("proxmox", None)}
for org in (0, acme):
    for name, (vendor, lst) in SEED.items():
        db.save_device(dev(f"{name}-{org}", vendor, lst, org))
    with db.within(org):
        db.set_setting("monitoring_profiles", [prof("p-pve", "proxmox", ["nodes", "guests"]), prof("p-mist", "mist", ["devices"]),
                                                prof("p-pve-none", "proxmox", ["guests"]), prof("p-fg", "fortinet", ["resources", "nodes", "devices"]),
                                                prof("p-mist-has", "mist", ["devices", "uptime"])])
for org in (0, acme):
    with db.within(org), db.connect() as c:
        c.execute("PRAGMA user_version = 17")           # the file as Toner kept it before the upgrade
db.init()

def lists(org):
    with db.within(org):
        d = {x["name"].rsplit("-", 1)[0]: db.normalize_checkopts(x.get("checkopts")).get("checks") for x in db.list_devices()}
        return d, {p["name"]: p["checks"] for p in db.get_setting("monitoring_profiles")}
for org, label in ((0, "Global"), (acme, "Acme")):
    d, p = lists(org)
    check(f"{label}: a Proxmox device's own list with nodes gains uptime", d["pve-old"] == ["reachability", "nodes", "storage", "uptime"], d["pve-old"])
    check(f"{label}: a Mist device's own list with devices gains uptime", d["mist-old"] == ["devices", "alarms", "uptime"], d["mist-old"])
    check(f"{label}: lists that have uptime, lack nodes/devices, or belong to another vendor are untouched",
          d["pve-has"] == ["nodes", "uptime"] and d["pve-none"] == ["reachability"] and d["mist-none"] == ["alarms"] and d["sw"] == ["cpu", "nodes", "devices"], d)
    check(f"{label}: a device that follows the global list still has none", d["pve-global"] is None)
    check(f"{label}: monitoring profiles of Proxmox and Mist gain it too", p["p-pve"] == ["nodes", "guests", "uptime"] and p["p-mist"] == ["devices", "uptime"], p)
    check(f"{label}: profiles without nodes/devices, with uptime already, or of another vendor are untouched",
          p["p-pve-none"] == ["guests"] and p["p-mist-has"] == ["devices", "uptime"] and p["p-fg"] == ["resources", "nodes", "devices"], p)
    with db.within(org):
        dv = next(x for x in db.list_devices() if x["name"].startswith("pve-old"))
        check(f"{label}: so the uptime row stays on (not switched off for the device)", "proxmox:uptime" not in db.disabled_for(dv, set()))

# unticked on purpose afterwards: it stays unticked (the upgrade ran once)
with db.within(0):
    old = next(x for x in db.list_devices() if x["name"].startswith("pve-old"))
    db.save_device({**old, "checkopts": {"checks": ["reachability", "nodes"]}, "org": 0})
db.init(); db.init()
check("a later untick survives the next starts", lists(0)[0]["pve-old"] == ["reachability", "nodes"], lists(0)[0]["pve-old"])
check("the files are at the newest version", db.schema_version() == db.SCHEMA_VERSION and db.SCHEMA_VERSION >= 18)

# a file stamped past step 4 whose devices table the start-up just created without checkopts (test_demarc's 1.6.1 file: only orgs, version 6)
import sqlite3
old = os.path.join(SP, "noopts%d.db" % int(time.time() * 1000))
c = sqlite3.connect(old)
c.executescript("CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE, code TEXT UNIQUE NOT NULL COLLATE NOCASE, "
                "colour TEXT DEFAULT '', archived INTEGER DEFAULT 0, created TEXT DEFAULT '');")
c.execute("PRAGMA user_version = 6"); c.commit(); c.close()
saved = os.environ["NETCHECK_DB"]; os.environ["NETCHECK_DB"] = old
db._wal_set.clear(); db.forget_orgs()
try:
    db.init(); db.forget_orgs()
    with db.connect() as c:
        cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
    check("a file that skipped step 4 opens, and its devices table has checkopts", "checkopts" in cols and db.schema_version() == db.SCHEMA_VERSION, cols)
except Exception as e:
    check("a file that skipped step 4 opens, and its devices table has checkopts", False, repr(e))
finally:
    os.environ["NETCHECK_DB"] = saved
    db._wal_set.clear(); db.forget_orgs(); db._forget_settings(); db._invalidate_folders()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
