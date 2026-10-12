# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\sd%d.db" % int(time.time())
from core import db, snmp, profiles
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pysnmp.proto.rfc1902 import Integer32, Gauge32, OctetString, ObjectIdentifier, TimeTicks, Counter32, Counter64
from drivers import DRIVERS

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

N = snmp.NAMES
class Fake:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get(self, *oids):
        got = {o: self.data[o] for o in oids if o in self.data}
        return got
    try_get = get
    def walk(self, root, max_rows=0):
        return sorted(((o, v) for o, v in self.data.items() if o.startswith(root + ".")), key=lambda kv: [int(x) for x in kv[0].split(".")])
    def column(self, root): return {o[len(root) + 1:]: v for o, v in self.walk(root)}
    try_column = column

def col(root, values):
    return {f"{root}.{i}": v for i, v in values.items()}

BASE = {}
BASE[N["sysDescr"] + ".0"] = OctetString("Cisco IOS Software, C2960 Version 15.2")
BASE[N["sysObjectID"] + ".0"] = ObjectIdentifier("1.3.6.1.4.1.9.1.1745")
BASE[N["sysName"] + ".0"] = OctetString("sw-lab")
BASE[N["sysUpTime"] + ".0"] = TimeTicks(8640000 + 360000)           # 1 day + 1 hour
# interfaces: 1 Gi0/1 up, 2 Gi0/2 admin-up but down, 3 Gi0/3 admin-down, 4 loopback
BASE.update(col(N["ifDescr"], {1: OctetString("Gi0/1"), 2: OctetString("Gi0/2"), 3: OctetString("Gi0/3"), 4: OctetString("Lo0")}))
BASE.update(col(N["ifType"], {1: Integer32(6), 2: Integer32(6), 3: Integer32(6), 4: Integer32(24)}))
BASE.update(col(N["ifAdminStatus"], {1: Integer32(1), 2: Integer32(1), 3: Integer32(2), 4: Integer32(1)}))
BASE.update(col(N["ifOperStatus"], {1: Integer32(1), 2: Integer32(2), 3: Integer32(2), 4: Integer32(1)}))
BASE.update(col(N["ifInErrors"], {1: Counter32(10), 2: Counter32(0), 3: Counter32(0), 4: Counter32(0)}))
BASE.update(col(N["ifOutErrors"], {1: Counter32(5), 2: Counter32(0), 3: Counter32(0), 4: Counter32(0)}))
BASE.update(col(N["ifHighSpeed"], {1: Gauge32(1000), 2: Gauge32(1000), 3: Gauge32(1000), 4: Gauge32(0)}))
BASE.update(col(N["ifHCInOctets"], {1: Counter64(1000000), 2: Counter64(0), 3: Counter64(0), 4: Counter64(0)}))
BASE.update(col(N["ifHCOutOctets"], {1: Counter64(2000000), 2: Counter64(0), 3: Counter64(0), 4: Counter64(0)}))
# host resources
BASE.update(col(N["hrProcessorLoad"], {196608: Integer32(35), 196609: Integer32(55)}))
hr = N["hrStorageType"][:-2]
BASE.update(col(hr + ".2", {1: ObjectIdentifier("1.3.6.1.2.1.25.2.1.2"), 2: ObjectIdentifier("1.3.6.1.2.1.25.2.1.4"), 3: ObjectIdentifier("1.3.6.1.2.1.25.2.1.4")}))
BASE.update(col(hr + ".3", {1: OctetString("Physical memory"), 2: OctetString("C:\\"), 3: OctetString("D:\\")}))
BASE.update(col(hr + ".4", {1: Integer32(1024), 2: Integer32(4096), 3: Integer32(4096)}))
BASE.update(col(hr + ".5", {1: Integer32(1000), 2: Integer32(1000), 3: Integer32(1000)}))
BASE.update(col(hr + ".6", {1: Integer32(600), 2: Integer32(850), 3: Integer32(300)}))
# entity sensor: celsius sensor 7 = 52.5 (value 525, precision 1, scale units=9), a non-temperature sensor 8
es = "1.3.6.1.2.1.99.1.1.1"
BASE.update(col(es + ".1", {7: Integer32(8), 8: Integer32(3)}))
BASE.update(col(es + ".2", {7: Integer32(9), 8: Integer32(9)}))
BASE.update(col(es + ".3", {7: Integer32(1), 8: Integer32(0)}))
BASE.update(col(es + ".4", {7: Integer32(525), 8: Integer32(12)}))

TH = db.thresholds_for({"name": "x", "vendor": "snmp", "location": ""})
OPTS = {**db.runtime_options()}
def run(data, **dev):
    d = {"name": "lab", "vendor": "snmp", "host": "10.0.0.1", **dev}
    drv = DRIVERS["snmp"](d, TH, {**OPTS, **dev.pop("opts", {})})
    snmp.Client = lambda *a, **k: Fake(data)
    snmp.credentials_for = lambda dev: (snmp.Credentials(community="public"), 161)
    res = drv.run()
    drv.flush_baselines()
    return {r.check: r for r in res}

print("== generic SNMP driver")
r = run(BASE)
check("identity row names the device and vendor", r["reachability"].value == "sw-lab" and "Cisco IOS" in r["reachability"].message and "[cisco]" in r["reachability"].message, r["reachability"])
check("cpu = busiest core (55%)", r["cpu"].value == "55%" and r["cpu"].status == "OK", r["cpu"])
check("memory from hrStorage RAM (60%)", r["memory"].value == "60%", r["memory"])
check("storage = fullest disk (85% -> WARN)", r["storage"].value == "85%" and r["storage"].status == "WARN" and r["storage"].message == "C:\\", r["storage"])
check("uptime 1d 1h", r["uptime"].value == "1:01:00:00" and r["uptime"].status == "OK", r["uptime"])
check("temperature from entity sensor with precision", r["temperature"].value == "52C" or r["temperature"].value == "53C", r["temperature"])
check("interfaces: loopback excluded, admin-down ignored", r["interfaces"].value == "1/2 up" and "Gi0/2" in r["interfaces"].message, r["interfaces"])
check("interface errors total mode lists ports with errors", r["interface errors"].status == "WARN" and "Gi0/1" in r["interface errors"].message, r["interface errors"])
check("bandwidth: first run sets a baseline", r["bandwidth"].value == "baseline set", r["bandwidth"])

print("== bandwidth is a rate between two runs")
time.sleep(0.2)
# pretend the previous run was 10s ago: rewrite the stored time baseline and counters
b = db.get_baselines("lab"); db.set_baselines("lab", {"bw:t": b["bw:t"] - 10})
D2 = dict(BASE)
D2.update(col(N["ifHCInOctets"], {1: Counter64(1000000 + 62_500_000), 2: Counter64(0), 3: Counter64(0), 4: Counter64(0)}))   # +50 Mbit in 10 s -> 50 Mbps
r = run(D2)
check("utilisation = busiest direction / link speed", r["bandwidth"].value in ("5%", "4%") and "Gi0/1" in r["bandwidth"].message and "Mbps" in r["bandwidth"].message, r["bandwidth"])
b = db.get_baselines("lab"); db.set_baselines("lab", {"bw:t": b["bw:t"] - 10})
D3 = dict(D2); D3.update(col(N["ifHCInOctets"], {1: Counter64(1000000 + 62_500_000 + 1_400_000_000), 2: Counter64(0), 3: Counter64(0), 4: Counter64(0)}))
r = run(D3)
check("a saturated link grades FAIL", r["bandwidth"].status == "FAIL", r["bandwidth"])

print("== delta mode for errors")
db2 = {"counter_mode": "delta"}
run(BASE, opts=db2)
r = run(BASE, opts=db2)
check("delta: no new errors", r["interface errors"].status == "OK" and r["interface errors"].value in ("0", 0), r["interface errors"])
D4 = dict(BASE); D4.update(col(N["ifInErrors"], {1: Counter32(110), 2: Counter32(0), 3: Counter32(0), 4: Counter32(0)}))
r = run(D4, opts=db2)
check("delta: +100 errors on Gi0/1", r["interface errors"].status == "WARN" and "+100" in r["interface errors"].message, r["interface errors"])

print("== fallbacks and missing pieces")
M = {k: v for k, v in BASE.items() if not (k.startswith(N["hrProcessorLoad"]) or k.startswith(hr))}
M[N["ssCpuIdle"] + ".0"] = Integer32(80)
M[N["memTotalReal"] + ".0"] = Integer32(1000); M[N["memAvailReal"] + ".0"] = Integer32(300)
M[N["memBuffer"] + ".0"] = Integer32(50); M[N["memCached"] + ".0"] = Integer32(150)
r = run(M)
check("UCD cpu idle -> 20%", r["cpu"].value == "20%", r["cpu"])
check("UCD memory excludes buffers and cache (50%)", r["memory"].value == "50%", r["memory"])
check("no disks -> no storage row", "storage" not in r)
M2 = {k: v for k, v in M.items() if k not in (N["ssCpuIdle"] + ".0",)}
M2[N["fgSysCpuUsage"] + ".0"] = Gauge32(77)
r = run(M2)
check("Fortinet MIB cpu fallback", r["cpu"].value == "77%", r["cpu"])
ONLY = {k: v for k, v in BASE.items() if k.startswith("1.3.6.1.2.1.1.")}
r = run(ONLY)
check("a bare device still gives identity and uptime, nothing invented", set(r) == {"reachability", "uptime"}, set(r))
try:
    run({}); check("silent device is an error, not a pass", False)
except ValueError as e:
    check("silent device is an error, not a pass", "no system information" in str(e), e)

print("== switched-off checks")
r = run(BASE, opts={"disabled": {"snmp:cpu", "snmp:bandwidth"}})
check("disabled checks are not run", "cpu" not in r and "bandwidth" not in r and "memory" in r)

print("== profiles and credentials")
pid = profiles.save({"name": "Lab SNMP", "username": "admin", "snmp": {"version": "3", "user": "authuser", "level": "authPriv"}},
                    {"main": "sshpass", "snmp_auth": "authpass123", "snmp_priv": "privpass123"})
db.save_device(dict(name="lab", vendor="snmp", host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, profile_id=pid))
dev = [d for d in db.list_devices() if d["name"] == "lab"][0]
check("profile saved with its secrets in the credential store", profiles.has_secret("Lab SNMP") and profiles.has_secret("Lab SNMP", "snmp_auth") and not profiles.has_secret("Lab SNMP", "snmp"))
check("device inherits username, secret and SNMP settings", profiles.username(dev) == "admin" and profiles.secret(dev) == "sshpass" and profiles.snmp_settings(dev)["user"] == "authuser" and profiles.snmp_settings(dev)["version"] == "3")
check("device's own secret wins over the profile's", (db.set_secret("lab", "own") or True) and profiles.secret(dev) == "own")
db.set_secret("lab:snmp", "communityX"); check("device's own SNMP community", profiles.secret(dev, "snmp") == "communityX")
import importlib; importlib.reload(snmp)
creds, port = snmp.credentials_for(dev)
check("credentials_for builds v3 settings from the profile", creds.version == "3" and creds.user == "authuser" and creds.level == "authPriv" and creds.auth_key == "authpass123" and creds.priv_key == "privpass123" and port == 161, creds)
dev2 = dict(dev, snmp={"version": "2c"} and '{"version": "2c"}')
check("a device can override just the SNMP version", profiles.snmp_settings(dev2)["version"] == "2c" and profiles.snmp_settings(dev2)["user"] == "authuser")
check("resolve fills the profile's username", profiles.resolve(dev)["username"] == "admin")
try: profiles.save({"name": "lab snmp"}); check("duplicate profile names refused (case-insensitive)", False)
except ValueError: check("duplicate profile names refused (case-insensitive)", True)
profiles.save({"id": pid, "name": "Renamed", "username": "admin"})
check("renaming a profile keeps its secrets", profiles.has_secret("Renamed", "snmp_auth") and not profiles.has_secret("Lab SNMP", "snmp_auth"))
profiles.delete(pid)
dev = [d for d in db.list_devices() if d["name"] == "lab"][0]
check("deleting a profile detaches devices and removes its secrets", dev["profile_id"] is None and not profiles.has_secret("Renamed", "snmp_auth"))
check("tags: split, de-duplicate, keep order", db.split_tags("core, Edge ;core,  wan ") == ["core", "Edge", "wan"])
db.save_device({**dev, "tags": "core, Edge, core"})
dev = [d for d in db.list_devices() if d["name"] == "lab"][0]
check("tags saved tidy and usable as groups", dev["tags"] == "core, Edge" and "Tag: core" in db.group_labels() and db.in_group(dev, "Tag: edge") and not db.in_group(dev, "Tag: wan"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
