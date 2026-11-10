# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Windows settings snapshot: what winsettings keeps, how it is stored per device, and that both collectors name the same values.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, types
from datetime import datetime
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\wset%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, orgs, runner, winmon, winsettings as W
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from drivers import DRIVERS

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_FILE = os.path.join(ROOT, "agent", "internal", "collect", "windows_settings.go")
R, R2 = W.REG[0][0], W.REG[1][0]
G = sorted(W.AUDIT)[0]

print("== clean")
check("junk is refused", W.clean("x") is None and W.clean([1]) is None)
check("over 64 KB is refused", W.clean({"v": 1, "reg": {"a": "x" * 70000}}) is None)
check("only the known names survive", W.clean({"v": 1, "reg": {R: 1, "Evil": 2}, "policy": {"PasswordHistorySize": 24, "NewAdministratorName": "root"}})
      == {"v": 1, "reg": {R: 1}, "policy": {"PasswordHistorySize": 24}, "audit": {}})
check("a value read but not set is kept as null, a set one keeps its value", W.clean({"v": 1, "reg": {R: None, R2: 0}})["reg"] == {R: None, R2: 0})
check("a value that is not a number is dropped", W.clean({"v": 1, "reg": {R: "text", R2: 4}, "policy": {"MinimumPasswordLength": "root"}})
      == {"v": 1, "reg": {R2: 4}, "policy": {}, "audit": {}})
check("audit keeps the known GUIDs, any case, with their setting", W.clean({"v": 1, "audit": {G.lower(): "Success and Failure", "{00000000-0000-0000-0000-000000000000}": "x"}})["audit"]
      == {G: "Success and Failure"})
check("a wrong version is refused", W.clean({"v": 2, "reg": {R: 1}}) is None)
check("firewall and defender ride along when well formed", W.clean({"v": 1, "firewall": [{"name": "Domain", "on": True}, "x"], "defender": {"realtime": True, "mode": "Normal", "evil": 1},
      "joined": True, "build": "20348.2527"})
      == {"v": 1, "reg": {}, "policy": {}, "audit": {}, "firewall": [{"name": "Domain", "on": True}], "defender": {"realtime": True, "mode": "Normal"},
          "joined": True, "build": "20348.2527"})
check("the lists have the rule list's counts", len(W.POLICY) == 8 and len(W.AUDIT) == 13 and "NewAdministratorName" not in W.POLICY
      and len({n for n, _p, _v in W.REG}) == len(W.REG))

print("== the two collectors name the same things")
go = open(GO_FILE, encoding="utf-8").read() if os.path.exists(GO_FILE) else ""
check("the Go list is the Python list", bool(go) and all(f'"{n}"' in go and v in go for n, _p, v in W.REG) and all(f'"{k}"' in go for k in W.POLICY))
check("the Go list has the paths and the audit GUIDs", bool(go) and all(p.replace("\\", "\\\\") in go or p in go for _n, p, _v in W.REG) and all(g.lower() in go.lower() for g in W.AUDIT))
ps = winmon.COLLECTOR
check("the PowerShell script reads every name, path and policy key and audit GUID", all(n in ps and p in ps for n, p, _v in W.REG)
      and all(k in ps for k in W.POLICY) and all(g in ps.upper() for g in W.AUDIT) and "/mergedpolicy" in ps)
check("the Go agent uses the merged policy too", "/mergedpolicy" in go and "SECURITYPOLICY" in go)
check("the Go report names the part", 'json:"hardening,omitempty"' in open(os.path.join(ROOT, "agent", "internal", "report", "report.go"), encoding="utf-8").read())

print("== storage")
def dev(name):
    d = dict(name=name, vendor="windows", host=name, port=0, platform="agent", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None, winopts="")
    d["id"] = db.save_device(d)
    return db.get_device(d["id"])
SNAP = {"v": 1, "reg": {R: 1, R2: None}, "policy": {"MinimumPasswordLength": 14}, "audit": {G: "Success"}}
d = dev("w1")
check("nothing read yet", db.device_settings(d) == (None, None))
db.set_device_settings(d, SNAP, when=datetime(2026, 11, 9, 10, 0, 0))
check("stored and read back", db.device_settings(d) == ("2026-11-09 10:00:00", SNAP), db.device_settings(d))
db.set_device_settings(d, {**SNAP, "policy": {}})
check("a newer one replaces it", db.device_settings(d)[1]["policy"] == {})
with db.connect() as c:
    c.execute("DROP TABLE device_settings"); c.execute("PRAGMA user_version = 16")
db.init()
check("migration 17 makes the table on an existing database", db.schema_version() == db.SCHEMA_VERSION >= 17 and db.device_settings(d) == (None, None))
db.set_device_settings(d, SNAP)

print("== kept after a run")
def drv_for(device, rep):
    x = DRIVERS["windows"](device, db.get_thresholds(), {"disabled": frozenset()})
    x.fetch = lambda: (rep, 1.0, "agent")
    x.run()
    return x
now = time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime())
base = {"v": 1, "at": now, "computer": "SRV1", "domain": "corp.example.com", "joined": True, "os": "Microsoft Windows Server 2022 Standard", "build": "20348.2527", "cpu": 1.0,
        "firewall": [{"name": "Domain", "on": True}], "defender": {"enabled": True, "realtime": True, "sig_days": 0, "mode": "Normal"}}
good = drv_for(d, {**base, "hardening": {"v": 1, "reg": {R: 0}, "policy": {"LockoutBadCount": 3}, "audit": {}}})
ws = good.facts.get("windows_settings")
check("the driver merges firewall and defender into the settings", ws and ws["firewall"] == base["firewall"] and ws["defender"]["realtime"] is True and ws["reg"] == {R: 0}, ws)
runner.keep_software(d, good)
got = (db.device_settings(d)[1] or {})
check("keep_software keeps it, though the run read no software version", got.get("reg") == {R: 0} and got.get("policy") == {"LockoutBadCount": 3}
      and got.get("firewall") == base["firewall"], got)
before = db.device_settings(d)
runner.keep_software(d, drv_for(d, {**base, "hardening": "junk"}))
check("a report with a bad hardening leaves the earlier snapshot", db.device_settings(d) == before)
none_drv = drv_for(d, base)
runner.keep_software(d, none_drv)
check("a report with none leaves it too", "windows_settings" not in none_drv.facts and db.device_settings(d) == before)
orig = db.set_device_settings
def boom(*a, **k): raise RuntimeError("disk full")
db.set_device_settings = boom
try:
    runner.keep_software(d, types.SimpleNamespace(facts={"windows_settings": {"v": 1, "reg": {R: 5}}})); raised = False
except Exception:
    raised = True
db.set_device_settings = orig
check("a failure saving never raises", not raised)

print("== moves and deletes")
acme = orgs.create("Acme", "ACM")
orgs.move_devices([d], acme)
with db.within(acme):
    moved = next(x for x in db.list_devices() if x["name"] == "w1")
    check("a moved device carries its snapshot into the new organization's file", db.device_settings(moved) == before, db.device_settings(moved))
    db.delete_device(moved["id"], acme)
    with db.connect() as c:
        left = c.execute("SELECT COUNT(*) FROM device_settings").fetchone()[0]
check("deleting the device deletes its snapshot", left == 0, left)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
