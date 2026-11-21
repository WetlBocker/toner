# Run directly (python tests/test_fill_gaps.py) or all together (python tests/run_all.py).
# Which tick box governs each subject (CPU, memory, storage, uptime, interfaces, interface errors) for each vendor.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "fill%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingfill%d" % int(time.time()))
from core import checks, db, vendors
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== governs")
for v, s, want in [("fortinet", "cpu", "resources"), ("fortinet", "memory", "resources"), ("fortinet", "interface errors", "interfaces"),
                   ("fortinet", "storage", "storage"), ("paloalto", "interface errors", "interface errors"), ("cisco", "cpu", "cpu"),
                   ("juniper", "storage", "storage"), ("paloalto", "storage", "disk"), ("mikrotik", "storage", "disk"), ("opnsense", "storage", "disk"),
                   ("cisco", "storage", "flash"), ("arista", "storage", "flash"), ("fortinet", "storage", "storage"), ("truenas", "storage", "storage")]:
    check(f"{v} {s} -> {want}", checks.governs(v, s) == want, checks.governs(v, s))

print("== the catalogue gains the SNMP entries")
fg = checks.CATALOG["fortinet"]
check("fortinet gains storage via SNMP", ("storage", "Disk and storage (via SNMP)") in fg)
check("fortinet has no interface errors key", "interface errors" not in [k for k, _ in fg])
check("paloalto gains interface errors via SNMP", ("interface errors", "Interface errors (via SNMP)") in checks.CATALOG["paloalto"])
jun = [e for e in checks.CATALOG["juniper"] if e[0] == "storage"]
for v in ("paloalto", "mikrotik", "opnsense", "cisco", "arista"):
    check(f"{v} gains no storage key beside its own disk check", "storage" not in [k for k, _ in checks.CATALOG[v]], [k for k, _ in checks.CATALOG[v]])
check("juniper keeps its own storage label, once", jun == [("storage", "Storage space")], jun)
def _dups(l):
    ks = [k for k, _ in l]; return {k for k in ks if ks.count(k) > 1}
check("no key twice in a vendor's list, except sonicwall's own uptime and interfaces",
      all(_dups(l) == ({"uptime", "interfaces"} if v == "sonicwall" else set()) for v, l in checks.CATALOG.items()))
check("proxmox gains exactly cpu, memory, interfaces and interface errors",
      [k for k, _ in checks.CATALOG["proxmox"][-4:]] == ["cpu", "memory", "interfaces", "interface errors"])
check("the six labels say via SNMP", [l for _, l in checks.SNMP_EXTRA] == ["CPU (via SNMP, when set up)", "Memory (via SNMP)", "Disk and storage (via SNMP)",
      "Uptime and recent reboots (via SNMP)", "Interface status (via SNMP)", "Interface errors (via SNMP)"])

print("== fills")
for v in ("fortinet", "paloalto", "cisco", "proxmox"): check(f"fills {v}", vendors.fills(v) is True)
for v in ("sonicwall", "ciscoise", "meraki", "mist", "unifi_cloud", "windows", "snmp", "esxi", "cloud", "wifi", ""): check(f"does not fill {v!r}", vendors.fills(v) is False)

print("== the other lists are unchanged")
SNMP6 = ["cpu", "memory", "storage", "uptime", "interfaces", "interface errors"]
BEFORE = {
    "sonicwall": ["reachability", "uptime", "resources", "interfaces", "ha", "licenses"] + SNMP6 + ["wan usage"],
    "ciscoise": ["reachability", "nodes", "patches", "licensing", "sessions"] + SNMP6,
    "ciscofmc": ["reachability", "devices", "deployment", "ha"] + SNMP6,
    "ciscosdwan": ["reachability", "devices", "control connections", "bfd", "alarms", "resources"] + SNMP6,
    "vmware": ["reachability", "hosts", "vms", "datastores", "health"] + SNMP6,
    "meraki": ["devices", "uplinks", "licenses", "alerts", "config changes", "vpn", "uplink quality"],
    "windows": ["reachability", "cpu", "memory", "disks", "uptime", "pending reboot", "services", "events", "certificates", "patches", "changes", "disk health",
                "bitlocker", "antivirus", "firewall", "clock", "logons", "activation", "sessions", "tasks", "ad replication", "hyper-v", "backup"],
}
for v, keys in BEFORE.items(): check(f"{v} keeps its keys", [k for k, _ in checks.CATALOG[v]] == keys)

print("== SNMP fills what the main method lacks or failed at")
from core import profiles, runner
import drivers.snmpdev as SD
from drivers.base import AuthRejected, Result as R
TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5, "retries": 0}
SN = {"calls": 0, "skip": set(), "error": set(), "msg": {}, "raise": None}
def fake_snmp(self):                                   # (what a live agent would answer)
    SN["calls"] += 1
    if SN["raise"]: raise SN["raise"]
    return [R(self.name, "reachability", "OK", "x")] + [R(self.name, k, "ERROR" if k in SN["error"] else "OK", "v", SN["msg"].get(k, "") if k not in SN["error"] else "timed out")
                                                       for k, _fn in self.check_list() if k not in SN["skip"]]
SD.SnmpDriver.run = fake_snmp
SNMP_ON = [True]
profiles.snmp_configured = lambda d: SNMP_ON[0]
def reset(): SN.update({"calls": 0, "skip": set(), "error": set(), "msg": {}, "raise": None}); SNMP_ON[0] = True
fw = {"name": "fw", "vendor": "fortinet", "host": "h"}
def api(*rows): return [R("fw", c, s, "1", m) for c, s, m in rows]
def fill(res, dev=fw, disabled=(), **kw): return runner.fill_gaps(dev, TH, {**OPTS, "disabled": set(disabled)}, res, **kw)
def named(rows, c): return [r for r in rows if r.check == c]
FOUR = [("cpu", "OK", ""), ("memory", "OK", ""), ("uptime", "OK", ""), ("interfaces", "OK", "")]

reset(); res = api(*FOUR); out = fill(res)
check("API gave cpu, memory, uptime, interfaces: only storage is added, via SNMP",
      [r.check for r in out] == ["cpu", "memory", "uptime", "interfaces", "storage"] and out[-1].message == "via SNMP" and out[:4] == res, [(r.check, r.message) for r in out])
reset(); out = fill(api(*[x for x in FOUR if x[0] != "uptime"]))
check("no uptime row from the API: uptime is added via SNMP", [r.message for r in named(out, "uptime")] == ["via SNMP"], [(r.check, r.message) for r in out])
reset(); SN["msg"] = {"uptime": "recent reboot"}; out = fill(api(*[x for x in FOUR if x[0] != "uptime"]))
check("a filled row with a message of its own: 'recent reboot, via SNMP'", [r.message for r in named(out, "uptime")] == ["recent reboot, via SNMP"], [(r.check, r.message) for r in out])
reset(); out = fill(api(*FOUR[:2], ("uptime", "ERROR", "HTTP 403"), FOUR[3]))
up = named(out, "uptime")
check("API uptime ERROR HTTP 403: one uptime row, OK, says the API check failed, no ERROR uptime row left",
      len(up) == 1 and up[0].status == "OK" and up[0].message == "via SNMP; the API check failed: HTTP 403", [(r.check, r.status, r.message) for r in out])
reset(); out = fill(api(("resources", "ERROR", "HTTP 500"), *FOUR[2:]))
check("API resources ERROR HTTP 500: cpu and memory filled with that reason, no resources row left",
      [r.message for r in named(out, "cpu") + named(out, "memory")] == ["via SNMP; the API check failed: HTTP 500"] * 2 and not named(out, "resources"),
      [(r.check, r.status, r.message) for r in out])
reset(); SN["skip"] = {"memory"}; out = fill(api(("resources", "ERROR", "HTTP 500"), *FOUR[2:]))
check("review focus 1: SNMP gives cpu but not memory: cpu filled and tagged, the resources ERROR row stays",
      [r.message for r in named(out, "cpu")] == ["via SNMP; the API check failed: HTTP 500"] and [r.status for r in named(out, "resources")] == ["ERROR"]
      and not named(out, "memory"), [(r.check, r.status, r.message) for r in out])
reset(); SN["error"] = {"uptime"}; out = fill(api(*FOUR[:2], ("uptime", "ERROR", "HTTP 403"), FOUR[3]))
up = named(out, "uptime")
check("review focus 2: API uptime ERROR and SNMP's uptime ERROR too: exactly one ERROR uptime row, the API's",
      len(up) == 1 and up[0].status == "ERROR" and up[0].message == "HTTP 403", [(r.check, r.status, r.message) for r in out])
reset(); SN["error"] = {"uptime"}; out = fill(api(*[x for x in FOUR if x[0] != "uptime"]))
check("...but SNMP's ERROR row is kept for a subject the main method had no row for", [r.status for r in named(out, "uptime")] == ["ERROR"], [(r.check, r.status) for r in out])
reset(); out = fill([], disabled={"fortinet:resources"})
check("fortinet:resources switched off: no cpu or memory row from any method", not named(out, "cpu") and not named(out, "memory") and named(out, "storage"), [r.check for r in out])
reset(); out = fill(api(*FOUR), disabled={"fortinet:storage"})
check("fortinet:storage switched off: no storage row", not named(out, "storage"), [r.check for r in out])
check("nothing wanted (all covered, storage switched off, errors covered by interfaces): SNMP is not run", SN["calls"] == 0, SN["calls"])
reset(); sw = {"name": "sw", "vendor": "cisco", "host": "h"}
out = fill([R("sw", "cpu", "ERROR", "", "unexpected output"), R("sw", "interfaces", "OK", "2/2 up")], dev=sw)
check("a Cisco cpu ERROR: 'via SNMP; the SSH check failed: unexpected output'",
      [r.message for r in named(out, "cpu")] == ["via SNMP; the SSH check failed: unexpected output"], [(r.check, r.status, r.message) for r in out])
check("...and its interfaces row covers interface errors: none added", not named(out, "interface errors"), [r.check for r in out])
reset(); SNMP_ON[0] = False; res = api(*FOUR[:2]); out = fill(res)
check("SNMP not set up: the rows come back as they came, SNMP not run", out is res and SN["calls"] == 0)
reset(); SN["raise"] = OSError("no answer"); res = api(*FOUR[:2], ("uptime", "ERROR", "HTTP 403"), FOUR[3]); out = fill(res)
check("SNMP raises: the main rows intact (the uptime ERROR too) plus one snmp ERROR row",
      out[:4] == res and len(out) == 5 and out[4].check == "snmp" and out[4].status == "ERROR", [(r.check, r.status, r.message) for r in out])
reset(); out = fill([], signed_in=False)
check("signed_in=False: six rows tagged exactly 'via SNMP'", [r.check for r in out] == list(checks.SUBJECTS) and all(r.message == "via SNMP" for r in out),
      [(r.check, r.message) for r in out])
check("another device's rows do not cover this one's", [r.check for r in fill([R("other", "cpu", "OK", "1")])] == ["cpu"] + list(checks.SUBJECTS))
pve = {"name": "pve", "vendor": "proxmox", "host": "h"}
reset(); out = fill([R("pve / n1", c, "OK", "1") for c in ("cpu", "memory", "uptime")], dev=pve)
check("a Proxmox's rows labelled 'pve / n1' cover cpu, memory and uptime: none of them added via SNMP",
      not [r for r in out if r.check in ("cpu", "memory", "uptime") and "via SNMP" in r.message], [(r.device, r.check, r.message) for r in out])
reset(); out = fill([R("pve2", "cpu", "OK", "1"), R("pvx / n1", "cpu", "OK", "1")], dev=pve)
check("...but rows of 'pve2' or 'pvx / n1' do not cover 'pve'", [r.message for r in named(out, "cpu") if r.device == "pve"] == ["via SNMP"], [(r.device, r.check, r.message) for r in out])
pa = {"name": "pa", "vendor": "paloalto", "host": "h"}
PA = [R("pa", c, "OK", "1") for c in ("resources", "uptime", "interfaces", "interface errors")]
reset(); out = fill(PA + [R("pa", "disk", "OK", "1")], dev=pa)
check("a Palo Alto whose API disk row is OK gets no storage row via SNMP", not named(out, "storage"), [(r.check, r.message) for r in out])
reset(); out = fill(PA + [R("pa", "disk", "ERROR", "", "HTTP 500")], dev=pa)
check("a Palo Alto disk ERROR HTTP 500: storage filled, 'via SNMP; the API check failed: HTTP 500', no disk ERROR row left",
      [r.message for r in named(out, "storage")] == ["via SNMP; the API check failed: HTTP 500"] and not named(out, "disk"), [(r.check, r.status, r.message) for r in out])
reset(); out = fill(PA, dev=pa, disabled={"paloalto:disk"})
check("paloalto:disk switched off: no storage row", not named(out, "storage"), [(r.check, r.message) for r in out])

print("== run_one")
class Fake:
    rows = []
    def __init__(self, d, t, o): self.name = d["name"]
    def run(self):
        if isinstance(Fake.rows, Exception): raise Fake.rows
        return [R(self.name, *x) for x in Fake.rows]
    def flush_baselines(self): pass
runner.reachability = lambda d, o: []
runner.resolve_host = lambda h: None
runner.DRIVERS["sonicwall"] = Fake; runner.DRIVERS["fortinet"] = Fake
reset(); Fake.rows = [("uptime", "OK", "3 days"), ("resources", "ERROR", "", "HTTP 500"), ("interfaces", "OK", "2/2 up")]
out = runner.run_one({"name": "sonic", "vendor": "sonicwall", "host": "h"}, TH, dict(OPTS))
# (recorded on the code before SNMP filled gaps)
check("a SonicWall keeps exactly its checks, in their order, and no message says via",
      [r.check for r in out] == ['uptime', 'resources', 'interfaces', 'cpu', 'memory', 'storage', 'interface errors'] and not any("via" in r.message for r in out), [r.check for r in out])
reset(); Fake.rows = AuthRejected("x")
out = runner.run_one(dict(fw), TH, dict(OPTS))
check("a rejected login: the connection ERROR row, then the filled rows",
      [r.check for r in out] == ["connection"] + list(checks.SUBJECTS) and out[0].status == "ERROR" and out[0].message == "x"
      and all(r.message == "via SNMP" for r in out[1:]), [(r.check, r.message) for r in out])
reset(); Fake.rows = [("cpu", "OK", "1"), ("memory", "OK", "1")]
out = runner.run_one(dict(fw), TH, dict(OPTS))
check("a FortiGate that signs in gains what its API lacks", [r.check for r in out] == ["cpu", "memory", "storage", "uptime", "interfaces", "interface errors"], [r.check for r in out])
for exc in (TimeoutError("timed out"), ConnectionError("refused")):
    reset(); Fake.rows = exc
    out = runner.run_one(dict(fw), TH, dict(OPTS))
    check(f"a connection that failed ({type(exc).__name__}): the connection row, nothing filled, SNMP not run",
          [r.check for r in out] == ["connection"] and SN["calls"] == 0, ([(r.check, r.message) for r in out], SN["calls"]))
reset(); Fake.rows = [("cpu", "OK", "1")]; called = []; real_fill = runner.fill_gaps
runner.fill_gaps = lambda *a, **k: called.append(a) or []
runner.reachability = lambda d, o: [R(d["name"], "reachability", "FAIL", "", "no answer on port 443")]
out = runner.run_one(dict(fw), TH, dict(OPTS))
runner.fill_gaps = real_fill; runner.reachability = lambda d, o: []
check("a FortiGate whose port did not answer: fill_gaps not called, no filled row",
      called == [] and [r.check for r in out] == ["reachability", "connection"] and not any("via" in r.message for r in out), [(r.check, r.message) for r in out])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
