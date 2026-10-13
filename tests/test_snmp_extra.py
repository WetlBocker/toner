# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# SNMP checks for fans and power supplies, UPS, printers, NAS boxes and load, against simulated devices.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "snmpx%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingsnmpx%d" % int(time.time()))
from core import checks, db, snmp
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pysnmp.proto.rfc1902 import Integer32, Gauge32, OctetString, ObjectIdentifier, TimeTicks
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
    def get(self, *oids): return {o: self.data[o] for o in oids if o in self.data}
    try_get = get
    def walk(self, root, max_rows=0):
        return sorted(((o, v) for o, v in self.data.items() if o.startswith(root + ".")), key=lambda kv: [int(x) for x in kv[0].split(".")])
    def column(self, root): return {o[len(root) + 1:]: v for o, v in self.walk(root)}
    try_column = column
def col(root, values): return {f"{root}.{i}": v for i, v in values.items()}
def S(s): return OctetString(s)

BASE = {N["sysDescr"] + ".0": S("a device"), N["sysObjectID"] + ".0": ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10"), N["sysName"] + ".0": S("box"),
        N["sysUpTime"] + ".0": TimeTicks(8640000)}
TH = db.thresholds_for({"name": "x", "vendor": "snmp", "location": ""})
OPTS = {**db.runtime_options(), "disabled": set()}
def run(data, opts=None, **dev):
    d = {"name": "lab", "vendor": "snmp", "host": "10.0.0.1", **dev}
    drv = DRIVERS["snmp"](d, TH, {**OPTS, **(opts or {})})
    snmp.Client = lambda *a, **k: Fake({**BASE, **data})
    snmp.credentials_for = lambda dev: (snmp.Credentials(community="public"), 161)
    res = drv.run(); drv.flush_baselines()
    return {r.check: r for r in res}

print("== what the catalog and limits say")
check("the SNMP type lists the new checks", {"environment", "load", "ups", "printer", "nas"} <= {k for k, _ in checks.CATALOG["snmp"]})
check("the limits exist, and the ones where lower is worse are known", all(k in db.DEFAULT_THRESHOLDS for k in ("load_per_core", "ups_battery", "ups_runtime", "ups_load", "toner"))
      and {"ups_battery", "ups_runtime", "toner"} <= db.LOWER_IS_WORSE)
check("more makers are named in the identity row", all(snmp.vendor_from_oid(f"1.3.6.1.4.1.{n}.1") == v for n, v in ((8741, "sonicwall"), (3097, "watchguard"), (21067, "sophos"), (6574, "synology"), (318, "apc"), (24681, "qnap"), (25053, "ruckus"))))
check("a device with none of these just has no extra rows", not ({"environment", "load", "ups", "supplies", "paper", "nas"} & set(run({}))))

print("== fans, power supplies and sensors")
es = "1.3.6.1.2.1.99.1.1.1.5"
r = run({**col(es, {1: Integer32(1), 2: Integer32(1)}), **col("1.3.6.1.2.1.47.1.1.1.1.7", {1: S("Fan 1"), 2: S("PSU 2")})})
check("healthy sensors say how many are fine", r["environment"].status == "OK" and r["environment"].value == "2 ok", r["environment"])
r = run({**col(es, {1: Integer32(1), 2: Integer32(3)}), **col("1.3.6.1.2.1.47.1.1.1.1.7", {1: S("Fan 1"), 2: S("PSU 2")})})
check("a sensor that has stopped operating is a failure, named", r["environment"].status == "FAIL" and "PSU 2" in r["environment"].message and r["environment"].value == "1 of 2 not ok", r["environment"])
cisco = {**col("1.3.6.1.4.1.9.9.13.1.4.1.3", {1: Integer32(1), 2: Integer32(3)}), **col("1.3.6.1.4.1.9.9.13.1.4.1.2", {1: S("Fan A"), 2: S("Fan B")}),
         **col("1.3.6.1.4.1.9.9.13.1.5.1.3", {1: Integer32(1), 2: Integer32(5)}), **col("1.3.6.1.4.1.9.9.13.1.5.1.2", {1: S("PS 1"), 2: S("PS 2")}),
         **col("1.3.6.1.4.1.9.9.13.1.3.1.6", {1: Integer32(2)}), **col("1.3.6.1.4.1.9.9.13.1.3.1.2", {1: S("Inlet")})}
r = run(cisco)
check("Cisco: a critical fan fails, a warning temperature warns, an empty power-supply bay is ignored", r["environment"].status == "FAIL" and "Fan B: critical" in r["environment"].message
      and "Inlet: warning" in r["environment"].message and "PS 2" not in r["environment"].message and r["environment"].value == "2 of 4 not ok", r["environment"])
jnx = {**col("1.3.6.1.4.1.2636.3.1.13.1.6", {1: Integer32(2), 2: Integer32(6)}), **col("1.3.6.1.4.1.2636.3.1.13.1.5", {1: S("Routing Engine 0"), 2: S("Power Supply 1")})}
r = run(jnx)
check("Juniper: a component that is down fails", r["environment"].status == "FAIL" and "Power Supply 1: down" in r["environment"].message)

print("== load average")
la = "1.3.6.1.4.1.2021.10.1.3"
cores = col("1.3.6.1.2.1.25.3.3.1.2", {1: Integer32(5), 2: Integer32(5), 3: Integer32(5), 4: Integer32(5)})
r = run({**col(la, {1: S("0.50"), 2: S("2.00"), 3: S("1.00")}), **cores})
check("5-minute load is judged per core (2.00 on 4 cores is calm)", r["load"].status == "OK" and r["load"].value == "2.00" and "4 cores" in r["load"].message, r["load"])
r = run({**col(la, {1: S("9.0"), 2: S("9.50"), 3: S("8.0")}), **cores})
check("9.5 on 4 cores (2.4 each) is a warning", r["load"].status == "WARN", r["load"])
r = run({**col(la, {1: S("14"), 2: S("14.0"), 3: S("12.0")}), **cores})
check("and 14 on 4 cores (3.5 each) fails", r["load"].status == "FAIL", r["load"])
check("a device without the UCD MIB has no load row", "load" not in run({}))

print("== UPS")
u = "1.3.6.1.2.1.33.1"
std = {f"{u}.2.1.0": Integer32(2), f"{u}.2.3.0": Integer32(45), f"{u}.2.4.0": Integer32(100), f"{u}.4.1.0": Integer32(3), **col(f"{u}.4.4.1.5", {1: Integer32(35)})}
r = run(std)
check("a healthy UPS: online, charge and runtime fine, load low", r["ups"].status == "OK" and r["ups"].value == "normal" and r["ups battery"].status == "OK" and "45 min left" in r["ups battery"].value
      and r["ups load"].value == "35%", [(k, v.value, v.status) for k, v in r.items() if "ups" in k])
r = run({**std, f"{u}.4.1.0": Integer32(5), f"{u}.2.3.0": Integer32(4), f"{u}.2.4.0": Integer32(18)})
check("on battery with 4 minutes left: warning, and the battery row fails", r["ups"].status == "WARN" and r["ups"].value == "running on battery" and r["ups battery"].status == "FAIL", [(k, v.value, v.status) for k, v in r.items() if "ups" in k])
r = run({**std, f"{u}.2.1.0": Integer32(4)})
check("a depleted battery fails", r["ups"].status == "FAIL" and r["ups"].value == "battery depleted")
r = run({**std, **col(f"{u}.4.4.1.5", {1: Integer32(97)})})
check("an overloaded UPS fails", r["ups load"].status == "FAIL")
apc = "1.3.6.1.4.1.318.1.1.1"
a = {f"{apc}.2.1.1.0": Integer32(2), f"{apc}.2.2.1.0": Gauge32(90), f"{apc}.2.2.3.0": TimeTicks(30 * 60 * 100), f"{apc}.2.2.4.0": Integer32(1), f"{apc}.4.1.1.0": Integer32(2), f"{apc}.4.2.3.0": Gauge32(40)}
r = run(a)
check("an APC UPS is read through PowerNet when UPS-MIB is missing", r["ups"].status == "OK" and "90%" in r["ups battery"].value and "30 min left" in r["ups battery"].value and r["ups load"].value == "40%", [(k, v.value) for k, v in r.items() if "ups" in k])
r = run({**a, f"{apc}.2.2.4.0": Integer32(2)})
check("APC: a battery that needs replacing is a warning", r["ups"].status == "WARN" and "replacing" in r["ups"].value)
r = run({**a, f"{apc}.4.1.1.0": Integer32(3)})
check("APC: on battery warns", r["ups"].status == "WARN" and "battery" in r["ups"].value)

print("== printers")
sup = "1.3.6.1.2.1.43.11.1.1"
base = {**col(f"{sup}.6", {1: S("Black Toner"), 2: S("Cyan Toner"), 3: S("Waste Toner Box")}), **col(f"{sup}.8", {1: Integer32(100), 2: Integer32(100), 3: Integer32(100)}),
        **col(f"{sup}.9", {1: Integer32(60), 2: Integer32(15), 3: Integer32(20)}), **col(f"{sup}.4", {1: Integer32(3), 2: Integer32(3), 3: Integer32(4)})}
r = run(base)
check("the lowest supply decides: cyan at 15% is a warning, and is named", r["supplies"].status == "WARN" and r["supplies"].value == "15%" and "Cyan Toner 15%" in r["supplies"].message, r["supplies"])
r = run({**base, **col(f"{sup}.9", {1: Integer32(60), 2: Integer32(3), 3: Integer32(20)})})
check("under 5% fails", r["supplies"].status == "FAIL")
r = run({**base, **col(f"{sup}.9", {1: Integer32(60), 2: Integer32(70), 3: Integer32(98)})})
check("a waste box that is nearly full counts as nearly empty", r["supplies"].status == "FAIL" and "Waste Toner Box" in r["supplies"].message, r["supplies"])
r = run({**base, **col(f"{sup}.9", {1: Integer32(-3), 2: Integer32(-2), 3: Integer32(-3)})})
check("'some remaining' and 'unknown' levels are not guessed at", "supplies" not in r)
inp = "1.3.6.1.2.1.43.8.2.1"
r = run({**col(f"{inp}.10", {1: Integer32(0), 2: Integer32(250)}), **col(f"{inp}.9", {1: Integer32(500), 2: Integer32(500)}), **col(f"{inp}.13", {1: S("Tray 1"), 2: S("Tray 2")})})
check("an empty paper tray is a warning, named", r["paper"].status == "WARN" and "Tray 1" in r["paper"].message and r["paper"].value == "1 empty", r["paper"])
r = run({**col(f"{inp}.10", {1: Integer32(100)}), **col(f"{inp}.9", {1: Integer32(500)})})
check("trays with paper are fine", r["paper"].status == "OK")

print("== NAS")
sy = "1.3.6.1.4.1.6574"
healthy = {f"{sy}.1.1.0": Integer32(1), f"{sy}.1.2.0": Integer32(38), f"{sy}.1.3.0": Integer32(1), f"{sy}.1.4.1.0": Integer32(1), f"{sy}.1.4.2.0": Integer32(1), f"{sy}.1.5.4.0": Integer32(2),
           **col(f"{sy}.2.1.1.2", {1: S("Disk 1"), 2: S("Disk 2")}), **col(f"{sy}.2.1.1.5", {1: Integer32(1), 2: Integer32(1)}), **col(f"{sy}.2.1.1.6", {1: Integer32(35), 2: Integer32(36)}),
           **col(f"{sy}.3.1.1.2", {1: S("Volume 1")}), **col(f"{sy}.3.1.1.3", {1: Integer32(1)})}
r = run(healthy)
check("a healthy Synology says so, with the disks and volumes counted", r["nas"].status == "OK" and "2 disk(s), 1 volume(s)" in r["nas"].value, r["nas"])
r = run({**healthy, **col(f"{sy}.3.1.1.3", {1: Integer32(11)})})
check("a degraded volume fails, named", r["nas"].status == "FAIL" and "Volume 1: degraded" in r["nas"].message, r["nas"])
r = run({**healthy, **col(f"{sy}.2.1.1.5", {1: Integer32(1), 2: Integer32(5)})})
check("a crashed disk fails, named", r["nas"].status == "FAIL" and "Disk 2: crashed" in r["nas"].message)
r = run({**healthy, **col(f"{sy}.3.1.1.3", {1: Integer32(2)})})
check("a rebuild is a warning", r["nas"].status == "WARN" and "repairing" in r["nas"].message)
r = run({**healthy, f"{sy}.1.4.1.0": Integer32(2)})
check("a failed fan fails", r["nas"].status == "FAIL" and "fan" in r["nas"].message)
r = run({**healthy, f"{sy}.1.5.4.0": Integer32(1)})
check("an available update is a warning", r["nas"].status == "WARN" and "update" in r["nas"].message)
qn = "1.3.6.1.4.1.24681.1.2"
r = run({f"{qn}.6.0": S("41 C/105 F"), **col(f"{qn}.11.1.2", {1: S("HDD1"), 2: S("HDD2")}), **col(f"{qn}.11.1.4", {1: Integer32(0), 2: Integer32(-9)})})
check("QNAP: a disk with a read/write error fails", r["nas"].status == "FAIL" and "HDD2: read/write error" in r["nas"].message, r["nas"])
r = run({f"{qn}.6.0": S("41 C/105 F"), **col(f"{qn}.11.1.2", {1: S("HDD1"), 2: S("HDD2")}), **col(f"{qn}.11.1.4", {1: Integer32(0), 2: Integer32(-5)})})
check("QNAP: an empty bay is not a fault", r["nas"].status == "OK", r["nas"])

print("== switching them off")
r = run({**std, **cisco, **healthy}, {"disabled": {"snmp:ups", "snmp:environment", "snmp:nas"}})
check("each check can be switched off in Settings > Checks", not ({"ups", "ups battery", "environment", "nas"} & set(r)))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
