# Run directly (python tests/test_driver_items.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Task 6 of the history charts: the drivers' rows carry per-disk, per-certificate, per-component and per-interface items,
# and the rows themselves (value, status, message, numeric) are as they were.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import datetime, timezone
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ditems%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingditems%d" % int(time.time()))
from core import db, snmp, custom
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pysnmp.proto.rfc1902 import Integer32, OctetString, ObjectIdentifier, TimeTicks
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5}

print("== interfaces and error counters (drivers/base.py)")
def arista(name="sw", **o):
    return DRIVERS["arista"]({"name": name, "vendor": "arista", "host": "h", "username": "u", "password": "p"}, TH, {**OPTS, **o})
r = arista().interfaces_row([("Gi1", "up"), ("Gi2", "down"), ("Gi3", "off"), ("Gi4", "errdisabled")])
check("interfaces: the row is as before", (r.status, r.value, r.message, r.numeric) == ("FAIL", "1/3 up", "down: Gi2; err-disabled: Gi4", 1.0), r)
check("interfaces: an item per counted interface, admin-off left out", [(i["name"], i["status"], i["text"]) for i in r.items] == [("Gi1", "OK", "up"), ("Gi2", "FAIL", "down"), ("Gi4", "WARN", "errdisabled")], r.items)
check("an item has exactly the agreed keys", set(r.items[0]) == {"name", "numeric", "status", "text", "data"})
r = arista().error_counter_rows("interface errors", {"Gi1": 3, "Gi2": 0})
check("lifetime errors: the row is as before and each interface has its count", r.status == "WARN" and r.value == "1" and r.message == "Gi1" and r.numeric == 1.0
      and [(i["name"], i["numeric"]) for i in r.items] == [("Gi1", 3.0), ("Gi2", 0.0)], r)
dl = arista("sw-delta", counter_mode="delta")
check("delta mode is on", dl.delta_mode)
first = dl.error_counter_rows("interface errors", {"Gi1": 3, "Gi2": 0}); dl.flush_baselines()
check("delta, first run: baseline set and no items", first.value == "baseline set" and first.items is None, first)
second = arista("sw-delta", counter_mode="delta").error_counter_rows("interface errors", {"Gi1": 8, "Gi2": 0})
check("delta, later run: the count is what is new", second.value == "1" and second.message == "Gi1 (+5)" and [(i["name"], i["numeric"]) for i in second.items] == [("Gi1", 5.0), ("Gi2", 0.0)], second)

print("== Windows disks and certificates")
NOW = time.time()
_WIN = {}
def win(rep):
    d = dict(name="SRV1", vendor="windows", host="SRV1", port=0, platform="agent", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, winopts="")
    d["id"] = _WIN.get("id") or _WIN.setdefault("id", db.save_device(d))
    drv = DRIVERS["windows"](db.get_device(d["id"]), TH, {"disabled": frozenset()})
    drv.fetch = lambda: (rep, 1.0, "agent")
    return {x.check: x for x in drv.run()}
rep = {"v": 1, "at": "2026-11-08T10:00:00.0000000Z", "computer": "SRV1", "uptime_h": 400.0, "mem_total_mb": 16384, "mem_free_mb": 12288, "cpu": 12.0,
       "disks": [{"drive": "C:", "size": 100 * 2**30, "free": 40 * 2**30}, {"drive": "D:", "size": 500 * 2**30, "free": 300 * 2**30}],
       "certs": [{"subject": "CN=web", "days": 20, "thumb": "AA"}, {"subject": "CN=old", "days": 300, "thumb": "BB", "expires": "2027-09-05"}]}
r = win(rep)
d = r["disks"]
check("disks: the row is as before", (d.status, d.value, d.numeric) == ("OK", "60%", 60.0) and d.message.startswith("fullest C:"), d)
check("disks: an item per drive with used and total", [(i["name"], round(i["numeric"]), i["data"]) for i in d.items] == [("C:", 60, {"used": 60 * 2**30, "total": 100 * 2**30}), ("D:", 40, {"used": 200 * 2**30, "total": 500 * 2**30})], d.items)
c = r["certificates"]
check("certificates: the row is as before", (c.status, c.value, c.numeric) == ("WARN", "20 days", 20.0) and c.message.startswith("CN=web (20 d)"), c)
check("certificates: days, expiry (empty when the report has none) and where", [(i["name"], i["numeric"], i["data"]) for i in c.items]
      == [("CN=web", 20.0, {"expires": "", "where": "store"}), ("CN=old", 300.0, {"expires": "2027-09-05", "where": "store"})], c.items)
check("no certificates: an empty list, not None", win({**rep, "certs": []})["certificates"].items == [])

print("== Fortinet and TLS certificates")
fg = DRIVERS["fortinet"]({"name": "fw", "vendor": "fortinet", "host": "h", "password": "x"}, TH, OPTS)
fg._optional = lambda path: [{"name": "vpn.corp", "source": "user", "valid_to": NOW + 12 * 86400 + 60}, {"name": "web", "source": "user", "valid_to": NOW + 90 * 86400}]
c = fg.certificates(); c_items = c.items
check("fortinet certificates: the row is as before", (c.value, c.message, round(c.numeric)) == ("12 days", "vpn.corp", 12), c)
check("fortinet certificates: an item per certificate, in the store", [(i["name"], round(i["numeric"]), i["data"]["where"]) for i in c.items] == [("vpn.corp", 12, "store"), ("web", 90, "store")], c.items)
class _S:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def getpeercert(self, binary_form=False): return b"der"
class _Ctx:
    def wrap_socket(self, raw, server_hostname=None): return _S()
custom.ssl.create_default_context = lambda: _Ctx()
custom.proxy.create_connection = lambda dev, addr, timeout: _S()
custom.cert_info = lambda der: {"subject": "CN=tls.example", "not_after": datetime(2027, 1, 15, tzinfo=timezone.utc), "days_left": 70}
t = custom.run_tls({"name": "tls", "kind": "tls", "port": 8443, "warn": None, "fail": None}, {"name": "dev", "host": "10.0.0.1"})
check("TLS row: the row is as before", (t.value, t.numeric, t.message) == ("70 days", 70.0, "CN=tls.example, expires 2027-01-15"), t)
check("TLS row: one item with the date and the port", [(i["name"], i["numeric"], i["data"]) for i in t.items] == [("CN=tls.example", 70.0, {"expires": "2027-01-15", "where": "port 8443"})], t.items)

print("== environment, flash and storage readers")
class FakeConn:
    def __init__(self, answers): self.answers = answers
    def send_command(self, command, *a, **k):
        for key, text in self.answers.items():
            if command.startswith(key):
                return text
        return ""
def ssh_rows(vendor, platform, answers):
    drv = DRIVERS[vendor]({"name": "sw", "vendor": vendor, "host": "h", "username": "u", "password": "p", "platform": platform}, TH, OPTS)
    drv.plat, drv._cache = platform, {}
    c = FakeConn(answers)
    out = []
    for name, fn in drv.checks():
        drv.safe(out, name, lambda fn=fn: fn(c))
    return {x.check: x for x in out}
AR = {"show system environment cooling | json": json.dumps({"systemStatus": "coolingOk", "fanTraySlots": [{"status": "ok", "fans": [{"status": "failed"}]}]}),
      "show system environment power | json": json.dumps({"powerSupplies": {"1": {"state": "ok"}}}),
      "dir flash:": "4000000000 bytes total (1000000000 bytes free)"}
r = ssh_rows("arista", "arista_eos", AR)
e = r["environment"]
check("Arista environment: the row is as before", (e.status, e.value, e.numeric) == ("FAIL", "1 not ok", 1.0), e)
check("Arista environment: an item for every state read, the OK ones too", [(i["status"], i["text"]) for i in e.items] == [("OK", "coolingOk"), ("OK", "ok"), ("FAIL", "failed"), ("OK", "ok")]
      and all(i["name"] for i in e.items), e.items)
f = r["flash"]
check("flash: the row is as before, one item with used and total", (f.status, f.value, f.numeric) == ("OK", "75%", 75.0)
      and [(i["name"], i["numeric"], i["data"]) for i in f.items] == [("flash:", 75.0, {"used": 3000000000, "total": 4000000000})], f)
def cli_rows(vendor, table):
    class Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def enable(self): pass
        def send_command(self, cmd, **kw): return table.get(cmd, "% Invalid input detected at '^' marker.")
    drv = DRIVERS[vendor]({"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": "", "password": "p"}, TH, OPTS)
    drv.connect = lambda: Conn()
    return {x.check: x for x in drv.run()}
r = cli_rows("cisco", {"show environment all": "SYSTEM FAN is OK\nSYSTEM TEMPERATURE is NOT OK\n"})
e = r["environment"]
check("Cisco environment (clirows): the row is as before and each part is an item", e.status == "FAIL" and e.value == "1 of 2 not ok"
      and sorted(i["status"] for i in e.items) == ["FAIL", "OK"], (e, e.items))
r = cli_rows("cisco", {"show environment all": "% Invalid input"})
check("no sensors: an N/A row without items", r["environment"].status == "N/A" and r["environment"].items is None)
DL = {"show environment": "Unit  Fan Tray  Status\n1     1         up\n1     2         up\nPSU   Status\n1     up\n2     fail\n"}
e = ssh_rows("dell", "dell_os10", DL)["environment"]
check("Dell environment: the row is as before", (e.status, e.value, e.numeric) == ("FAIL", "1 not ok", 1.0), e)
check("Dell environment: an item per fan and power supply, with the state read", [(i["status"], i["text"]) for i in e.items] == [("OK", "up"), ("OK", "up"), ("OK", "up"), ("FAIL", "fail")], e.items)
EX = {"show fans": "FanTray-1 information:\n State:   Operational\nFan-1 operational at 3000 RPM\nFan-2 not operational\n",
      "show power": "PowerSupply 1 State: Powered On\nPowerSupply 2 State: Empty\n"}
e = ssh_rows("extreme", "extreme_exos", EX)["environment"]
check("Extreme environment: the row is as before; an item per fan and supply, the empty bay left out", e.status == "WARN" and e.numeric == 1.0
      and {i["status"] for i in e.items} == {"OK", "WARN"} and len(e.items) == 3, (e, e.items))

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
S = OctetString
BASE = {N["sysDescr"] + ".0": S("a device"), N["sysObjectID"] + ".0": ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10"), N["sysName"] + ".0": S("box"), N["sysUpTime"] + ".0": TimeTicks(8640000)}
THS = db.thresholds_for({"name": "x", "vendor": "snmp", "location": ""})
def snmp_rows(data):
    drv = DRIVERS["snmp"]({"name": "lab", "vendor": "snmp", "host": "10.0.0.1"}, THS, OPTS)
    snmp.Client = lambda *a, **k: Fake({**BASE, **data})
    snmp.credentials_for = lambda dev: (snmp.Credentials(community="public"), 161)
    return {x.check: x for x in drv.run()}
cisco = {**col("1.3.6.1.4.1.9.9.13.1.4.1.3", {1: Integer32(1), 2: Integer32(3)}), **col("1.3.6.1.4.1.9.9.13.1.4.1.2", {1: S("Fan A"), 2: S("Fan B")}),
         **col("1.3.6.1.4.1.9.9.13.1.5.1.3", {1: Integer32(1), 2: Integer32(5)}), **col("1.3.6.1.4.1.9.9.13.1.5.1.2", {1: S("PS 1"), 2: S("PS 2")})}
e = snmp_rows(cisco)["environment"]
check("SNMP environment: the row is as before", (e.status, e.value, e.numeric) == ("FAIL", "1 of 3 not ok", 1.0), e)
check("SNMP environment: an item per component tested, OK ones too, the empty bay left out", [(i["name"], i["status"], i["text"]) for i in e.items]
      == [("Fan A", "OK", "normal"), ("Fan B", "FAIL", "critical"), ("PS 1", "OK", "normal")], e.items)
hr = N["hrStorageType"][:-2]
disk = ObjectIdentifier("1.3.6.1.2.1.25.2.1.4")
st = {**col(f"{hr}.2", {1: disk, 2: disk}), **col(f"{hr}.3", {1: S("C:\\"), 2: S("D:\\")}), **col(f"{hr}.4", {1: Integer32(4096), 2: Integer32(4096)}),
      **col(f"{hr}.5", {1: Integer32(1000), 2: Integer32(2000)}), **col(f"{hr}.6", {1: Integer32(850), 2: Integer32(500)})}
s_ = snmp_rows(st)["storage"]
check("SNMP storage: the row is as before", (s_.value, s_.status, s_.message) == ("85%", "WARN", "C:\\"), s_)
check("SNMP storage: an item per disk with used and total in bytes", [(i["name"], i["numeric"], i["data"]) for i in s_.items]
      == [("C:\\", 85.0, {"used": 850 * 4096, "total": 1000 * 4096}), ("D:\\", 25.0, {"used": 500 * 4096, "total": 2000 * 4096})], s_.items)

from drivers import clichecks as C
def parts_of(text):
    p = []; C.scan_environment(text, p); return p
nx = "Power Supply:\nVoltage: 12 Volts\nPS  Model          Output    Current   Status\n--  -------------- --------- --------- ----------\n1   N9K-PAC-650W   650.00 W  54.16 A   Ok\n\nTemperature:\n-----------------------------------\nModule   Sensor        MajorThresh   MinorThres   CurTemp     Status\n                       (Celsius)     (Celsius)    (Celsius)\n-----------------------------------\n1        Outlet        75            70           %d           Ok\n"
a, b = parts_of(nx % 38), parts_of(nx % 52)
check("CLI environment names carry no live readings: the same sensor at two temperatures keeps its name", [x[0] for x in a] == [x[0] for x in b] and "1 Outlet" in [x[0] for x in a], (a, b))
jn = "Class Item Status Measurement\nTemp PEM 0 OK %d degrees C / %d degrees F\n"
a, b = parts_of(jn % (37, 98)), parts_of(jn % (52, 125))
check("Junos: the same", [x[0] for x in a] == [x[0] for x in b] == ["Temp PEM 0"], (a, b))
check("the text is the word that decided the status", parts_of("Fans Fan Tray 0 Fan 1 OK High speed\n") == [("Fans Fan Tray 0 Fan 1", "OK", "OK")]
      and parts_of("Fan Tray 0 Fan 2 Check Stopped\n")[0][1:] == ("FAIL", "Check"), parts_of("Fans Fan Tray 0 Fan 1 OK High speed\n"))
check("fortinet certificates: the expiry date is filled", [i["data"]["expires"] for i in c_items] == [datetime.fromtimestamp(NOW + 12 * 86400 + 60, timezone.utc).strftime("%Y-%m-%d"), datetime.fromtimestamp(NOW + 90 * 86400, timezone.utc).strftime("%Y-%m-%d")], c_items)
ent = {**col("1.3.6.1.2.1.99.1.1.1.5", {1: Integer32(1), 2: Integer32(2)}), **col("1.3.6.1.2.1.47.1.1.1.1.7", {1: S("Fan 1"), 2: S("Temp 2")})}
e = snmp_rows(ent)["environment"]
check("SNMP: a state that is not a fault says what it is (unavailable), not 'ok'", [(i["name"], i["status"], i["text"]) for i in e.items] == [("Fan 1", "OK", "ok"), ("Temp 2", "OK", "unavailable")], e.items)
jx = col("1.3.6.1.4.1.2636.3.1.13.1.6", {1: Integer32(2), 2: Integer32(7)}); jx.update(col("1.3.6.1.4.1.2636.3.1.13.1.5", {1: S("FPC 0"), 2: S("FPC 1")}))
e = snmp_rows(jx)["environment"]
check("Juniper: running and standby are read as such", [(i["status"], i["text"]) for i in e.items] == [("OK", "running"), ("OK", "standby")], e.items)

print("== TrueNAS pools, datasets and disks")
import drivers.restapi as RA, requests as _rq
class Resp:
    def __init__(self, status=200, js=None): self.status_code, self._js, self.text, self.headers, self.content = status, js, json.dumps(js), {}, json.dumps(js).encode()
    def raise_for_status(self): pass
    def json(self): return self._js
TN = {"/system/info": {"version": "TrueNAS-SCALE-24.04.2", "hostname": "nas", "loadavg": [0.1, 0.2, 0.3], "cores": 4, "uptime_seconds": 400000},
      "/pool": [{"name": "tank", "status": "ONLINE", "healthy": True, "size": 10 * 2 ** 40, "allocated": 2 * 2 ** 40}], "/alert/list": [],
      "/disk": [{"name": "sda"}, {"name": "sdb"}, {"name": "sdc"}],
      "/smart/test/results": [{"disk": "sdb", "tests": [{"status": "SUCCESS"}, {"status": "FAILED"}]}, {"disk": "sda", "tests": [{"status": "SUCCESS"}]}],
      "/pool/dataset": [{"name": "tank", "used": {"parsed": 2 * 2 ** 40}, "available": {"parsed": 8 * 2 ** 40}, "children": [{"name": "tank/backups", "used": {"parsed": 95 * 2 ** 30}, "available": {"parsed": 5 * 2 ** 30}}]}],
      "/service": []}
RA.requests.get = lambda url, **kw: Resp(js=TN[url.split("/api/v2.0")[-1]]) if url.split("/api/v2.0")[-1] in TN else Resp(404)
_rq.post = lambda url, **kw: Resp(js={"sda": 31, "sdb": 44})                 # sdc's temperature is unknown
res = DRIVERS["truenas"]({"name": "nas", "vendor": "truenas", "host": "10.0.0.5", "password": "KEY"}, TH, OPTS).run()
rows = {x.check: x for x in res if x.device == "nas"}
ps = [x for x in res if x.check == "pool space"][0]
check("pool space: the row is as before", (ps.value, ps.status, ps.numeric) == ("20%", "OK", 20.0), ps)
check("pool space: one item for the pool", [(i["name"], i["numeric"], i["status"], i["text"], i["data"]) for i in ps.items] == [("tank", 20.0, "OK", "", {"used": float(2 * 2 ** 40), "total": float(10 * 2 ** 40)})], ps.items)
ds = rows["datasets"]
check("datasets: the row is as before", ds.status == "FAIL" and "tank/backups (95%)" in ds.message and ds.value == "2 dataset(s)", ds)
check("datasets: one item per dataset with used and total", {i["name"]: (round(i["numeric"]), i["data"]["used"], i["data"]["total"]) for i in ds.items}
      == {"tank/backups": (95, 95 * 2 ** 30, 100 * 2 ** 30), "tank": (20, 2 * 2 ** 40, 10 * 2 ** 40)}, ds.items)
dk = rows["disks"]
check("disks: the row is as before", dk.status == "FAIL" and dk.message == "SMART failed: sdb" and dk.value == "3 disk(s)" and dk.numeric == 44.0, dk)
check("disks: an item per drive; the failed one says so, an unknown temperature is None", [(i["name"], i["numeric"], i["status"], i["text"], i["data"]) for i in dk.items]
      == [("sda", 31.0, "OK", "", {}), ("sdb", 44.0, "FAIL", "SMART failed", {}), ("sdc", None, "OK", "", {})], dk.items)

print("\n%d passed, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
