# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\mp%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import checks, db, runner
from drivers.base import Driver
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host="127.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])
def profile(name, vendor, scopes, checks_=("cpu",), thresholds=None):
    return {"id": name, "name": name, "vendor": vendor, "checks": list(checks_), "thresholds": thresholds or {}, "scopes": list(scopes)}
ALL = {checks.key("cisco", c) for c, _ in checks.CATALOG["cisco"]}

access = dev("access-sw", tags="access", location="HQ")
core_ = dev("core-rtr", tags="core", location="HQ")
fw = dev("edge-fw", vendor="fortinet", tags="access")
glob = db.get_thresholds()
off = {"cisco:memory", "fortinet:cpu"}

print("== with no profiles nothing changes")
check("no profile applies", db.profile_for(access) is None and db.get_setting("monitoring_profiles") == [])
check("the checks that run are the global ones", db.disabled_for(access, off) == off)
check("and so are the limits", db.thresholds_for(access) == glob)

print("== a profile is for one vendor, and applies where it is assigned")
switches = profile("Access switches", "cisco", ["Tag: access"], ("cpu", "memory"), {"cpu": {"warn": 50, "fail": 60}})
db.set_setting("monitoring_profiles", [switches])
check("it applies to a device of its vendor in the group", (db.profile_for(access) or {}).get("name") == "Access switches")
check("not to one of its vendor outside the group", db.profile_for(core_) is None)
check("and not to another vendor's device in the group", db.profile_for(fw) is None)
check("its list of checks replaces the global one for that device, for its vendor only", db.disabled_for(access, off) == (ALL - {"cisco:cpu", "cisco:memory"}) | {"fortinet:cpu"}, db.disabled_for(access, off))
check("so it can run a check that is off globally", "cisco:memory" not in db.disabled_for(access, off))
check("the other devices still follow the global list", db.disabled_for(core_, off) == off and db.disabled_for(fw, off) == off)
th = db.thresholds_for(access)
check("its limits replace the global ones, and the ones it leaves alone stay global", th["cpu"] == {"warn": 50, "fail": 60} and th["memory"] == glob["memory"], th["cpu"])
check("the other devices keep the global limits", db.thresholds_for(core_) == glob and db.thresholds_for(fw) == glob)

print("== it can be assigned to any group, or to single devices")
for scope, hit, miss in (("All devices", access, None), ("Vendor: Cisco", core_, None), ("Location: HQ", core_, None), ("Device: core-rtr", core_, access), ("Tag: core", core_, access)):
    ps = [profile("p", "cisco", [scope])]
    check(f"assigned to {scope}", db.profile_for(hit, ps) is not None and (miss is None or db.profile_for(miss, ps) is None) and db.profile_for(fw, ps) is None)
check("a profile can be assigned to several", db.profile_for(access, [profile("p", "cisco", ["Tag: core", "Device: access-sw"])]) is not None)
check("one assigned to nothing applies to nothing", db.profile_for(access, [profile("p", "cisco", [])]) is None)
check("nor does one assigned to something that is not a group", db.profile_for(access, [profile("p", "cisco", ["Everything", "Rack: 4"])]) is None)

print("== when two apply, the more specific assignment wins")
wide, tagged, single = profile("wide", "cisco", ["All devices"]), profile("tagged", "cisco", ["Tag: access"]), profile("single", "cisco", ["Device: access-sw"])
check("a tag beats All devices, whatever the order", db.profile_for(access, [wide, tagged])["name"] == "tagged" and db.profile_for(access, [tagged, wide])["name"] == "tagged")
check("a single device beats a tag", db.profile_for(access, [tagged, single, wide])["name"] == "single")
check("a vendor beats All devices", db.profile_for(access, [wide, profile("vendor", "cisco", ["Vendor: Cisco"])])["name"] == "vendor")

print("== where it sits: global, then Settings' overrides, then the profile, then the device's own")
rules = [{"scope": "Vendor: Cisco", "check": "cpu", "warn": 10, "fail": 20}, {"scope": "Vendor: Cisco", "check": "memory", "warn": 11, "fail": 22}]
th = db.thresholds_for(access, overrides=rules)
check("the profile beats an override; an override still sets what the profile leaves alone", th["cpu"] == {"warn": 50, "fail": 60} and th["memory"] == {"warn": 11, "fail": 22}, th)
own = dev("own-sw", tags="access", checkopts={"checks": ["uptime"], "thresholds": {"cpu": {"warn": 90, "fail": 95}}})
check("a device's own limits beat the profile", db.thresholds_for(own)["cpu"] == {"warn": 90.0, "fail": 95.0})
check("and so does its own list of checks", db.disabled_for(own, off) == (ALL - {"cisco:uptime"}) | {"fortinet:cpu"})
lim = dev("lim-sw", tags="access", checkopts={"thresholds": {"memory": {"warn": 1, "fail": 2}}})
check("a device with only its own limits still takes the profile's checks and its other limits",
      db.disabled_for(lim, off) == (ALL - {"cisco:cpu", "cisco:memory"}) | {"fortinet:cpu"} and db.thresholds_for(lim)["cpu"] == {"warn": 50, "fail": 60} and db.thresholds_for(lim)["memory"] == {"warn": 1.0, "fail": 2.0})

print("== what is stored is not trusted")
junk = ["text", {"vendor": "cisco"}, {"name": "no vendor", "scopes": ["All devices"], "checks": ["cpu"]}, {"vendor": "cisco", "scopes": "All devices", "checks": ["cpu"]},
        {"vendor": "cisco", "scopes": ["All devices"], "checks": "cpu"}]
check("entries that are not profiles are passed over", db.profile_for(access, junk) is None and db.disabled_for(access, off, junk) == off and db.thresholds_for(access, profiles=junk) == glob)
odd = profile("odd", "cisco", ["All devices"], thresholds={"cpu": {"warn": "x"}, "bogus": {"warn": 1, "fail": 2}, "memory": {"warn": "5", "fail": 6}})
check("limits that are not numbers, or not thresholds, are dropped", db.thresholds_for(access, profiles=[odd]) == {**glob, "memory": {"warn": 5.0, "fail": 6.0}})

print("== a real run uses it")
class Probe(Driver):
    def run(self):
        return [self.level_check(k, 55.0) if k != "uptime" else self.result("uptime", "OK", "1") for k in ("cpu", "memory", "uptime") if self.enabled(k)]
real = runner.DRIVERS["cisco"]; runner.DRIVERS["cisco"] = Probe
opts = {**db.runtime_options(), "retries": 0, "tls_sweep": False, "custom": [], "disabled": {"cisco:memory"}}
check("the run is handed the profiles with its other settings", opts["profiles"] == [switches])
ra = {r.check: r.status for r in runner.run_one(access, db.thresholds_for(access), opts) if r.check != "reachability"}
rc = {r.check: r.status for r in runner.run_one(core_, db.thresholds_for(core_), opts) if r.check != "reachability"}
check("the device with the profile runs its checks against its limits (55% is over the profile's 50)", ra == {"cpu": "WARN", "memory": "OK"}, ra)
check("the device without it runs the global checks against the global limits", rc == {"cpu": "OK", "uptime": "OK"}, rc)
runner.DRIVERS["cisco"] = real

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
