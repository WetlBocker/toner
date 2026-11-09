# Run directly (python tests/test_wan.py). WAN usage: the check's rates and grades, the per-device WAN choice, and the picker's WAN columns.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "wan%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, ifaces
db.init()
from drivers.base import Driver, OK, WARN, FAIL
import drivers.base as B
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui.interfacepicker import InterfacePicker

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.DEFAULT_THRESHOLDS
check("the limits are 80 and 95 and can be set per device", TH["wan_usage"] == {"warn": 80, "fail": 95} and db.THRESHOLD_LABELS["wan_usage"] == "WAN usage %"
      and "wan_usage" in dict(db.THRESHOLD_GROUPS)["Network devices"]
      and db.normalize_checkopts({"thresholds": {"wan_usage": {"warn": 70, "fail": 90}}})["thresholds"] == {"wan_usage": {"warn": 70.0, "fail": 90.0}})
check("the WAN choice is kept, cleaned",
      db.normalize_checkopts({"wan": {"wan1": 300, "port2": None, "": 5}}) == {"wan": {"wan1": 300.0, "port2": None}})
NETWORK = ("arista", "cisco", "dell", "extreme", "fortinet", "hpe", "juniper", "mikrotik", "paloalto", "snmp", "sonicwall", "sophos")
check("every network device offers it", all(ifaces.wan_capable(v) for v in NETWORK), [v for v in NETWORK if not ifaces.wan_capable(v)])
check("...servers, managers and hosts do not", not any(ifaces.wan_capable(v) for v in ("windows", "ciscoise", "ciscofmc", "ciscosdwan", "vmware", "esxi",
                                                                                         "truenas", "proxmox", "cloud")))

class Fake(Driver):
    counters = {}
    def interface_counters(self): return self.counters

def run(wan, mbytes, name="fw-wan", port="wan1", speed=1e9, seconds=10):
    """Two runs `seconds` apart with `mbytes` MB moving out; returns the second run's row."""
    dev = {"name": name, "vendor": "fortinet", "host": "h", "checkopts": {"wan": wan}}
    real = B.time.time
    rows = []
    try:
        for n, now in enumerate((1000.0, 1000.0 + seconds)):
            B.time.time = lambda now=now: now
            d = Fake(dev, TH, {})
            d.counters = {port: (0, int(n * mbytes * 1e6), speed), "lan": (0, 0, speed)}
            rows.append(d.wan_usage()); d.flush_baselines()
    finally:
        B.time.time = real
    return rows

first, r = run({"wan1": None}, 375, name="a")
check("the first run only records the counters", first.value == "baseline set" and first.status == OK and "next run" in first.message, first)
check("375 MB in 10 s on a 1 Gbps port is 30% and OK", r.status == OK and round(r.numeric) == 30 and r.items[0]["name"] == "wan1"
      and round(r.items[0]["numeric"]) == 30 and round(r.items[0]["data"]["out_bps"]) == 300_000_000 and r.items[0]["data"]["available_bps"] == 1e9, r)
r = run({"wan1": 300}, 375, name="b")[1]
check("with a 300 Mbps circuit the same traffic is 100% and FAIL", r.status == FAIL and round(r.numeric) == 100 and r.items[0]["data"]["available_bps"] == 300e6, r)
r = run({"wan1": 300}, 312.5, name="c")[1]
check("250 Mbps on that circuit is 83% and WARN", r.status == WARN and round(r.numeric) == 83, r)
check("a WAN name the device no longer has is skipped, and with none left there is no row", run({"gone": None}, 375, name="d")[1] == [])
check("a device with no WAN chosen has no row", run({}, 375, name="e")[1] == [])
first, r = run({"wan1": None}, 375, name="f", speed=0)
check("no speed known: 'baseline set' on the first run only, then no row (not 'baseline set' forever)",
      first.value == "baseline set" and r == [], (first, r))
check("a second run under 5 s after the first: no row", run({"wan1": None}, 375, name="g", seconds=2)[1] == [])
try:
    Driver({"name": "x", "vendor": "x", "host": "x"}, TH, {}).interface_counters(); check("a driver without counters says so", False)
except NotImplementedError:
    check("a driver without counters says so", True)

print("== one read per link")
from core import snmp
from drivers import DRIVERS
from pysnmp.proto.rfc1902 import Integer32, Gauge32, OctetString, Counter64
N = snmp.NAMES
def col(root, values): return {f"{root}.{i}": v for i, v in values.items()}
DATA = {}
DATA.update(col(N["ifDescr"], {1: OctetString("Gi0/1")})); DATA.update(col(N["ifType"], {1: Integer32(6)}))
DATA.update(col(N["ifAdminStatus"], {1: Integer32(1)})); DATA.update(col(N["ifOperStatus"], {1: Integer32(1)}))
DATA.update(col(N["ifHighSpeed"], {1: Gauge32(1000)}))
DATA.update(col(N["ifHCInOctets"], {1: Counter64(5)})); DATA.update(col(N["ifHCOutOctets"], {1: Counter64(7)}))
DATA[N["sysDescr"] + ".0"] = OctetString("x"); DATA[N["sysObjectID"] + ".0"] = OctetString("1.3"); DATA[N["sysName"] + ".0"] = OctetString("sw")
DATA[N["sysUpTime"] + ".0"] = Gauge32(100)
walks = []
class FakeClient:
    closed = False
    def __init__(self, *a, **k): FakeClient.opened = getattr(FakeClient, "opened", 0) + 1
    def __enter__(self): return self
    def __exit__(self, *a): self.closed = True; return False
    def get(self, *oids): return {o: DATA[o] for o in oids if o in DATA}
    def column(self, root):
        assert not self.closed, "walked on a closed client"
        walks.append(root)
        return {o[len(root) + 1:]: v for o, v in DATA.items() if o.startswith(root + ".")}
    try_column = column
snmp.Client = FakeClient
snmp.credentials_for = lambda dev: (snmp.Credentials(community="public"), 161)
dev = {"name": "sw-wan", "vendor": "snmp", "host": "10.0.0.1", "checkopts": {"wan": {"Gi0/1": None}}}
drv = DRIVERS["snmp"](dev, TH, {**db.runtime_options()})
rows = {r.check: r for r in drv.run()}
check("bandwidth and wan usage both ran", "bandwidth" in rows and "wan usage" in rows, list(rows))
check("the byte counters and speeds are walked once for both", walks.count(N["ifHCInOctets"]) == 1 and walks.count(N["ifHighSpeed"]) == 1, walks)
got = ifaces.listing({"name": "sw2", "vendor": "snmp", "host": "10.0.0.1"})
check("Choose interfaces gets the port speed through the real listing path", got == [("Gi0/1", "Up", 1e9)], got)

import drivers.fortinet as FG
reads = []
class Resp:
    status_code = 200
    def raise_for_status(self): pass
    def json(self): return {"results": {"wan1": {"type": "physical", "link": True, "rx_bytes": 11, "tx_bytes": 22, "speed": 1000},
                                         "dmz": {"type": "physical", "link": True}, "ssl.root": {"type": "tunnel", "rx_bytes": 1}}}
FG.requests.get = lambda url, *a, **k: (reads.append(url), Resp())[1]
fg = FG.FortinetDriver({"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "T"}, TH, {**db.runtime_options()})
fg.interfaces()
check("Fortinet counters: bytes and speed (Mbps to bps), tunnels and ports without counters left out", fg.interface_counters() == {"wan1": (11, 22, 1e9)}, fg.interface_counters())
check("and the interface list is read once for the interfaces check and wan usage", len(reads) == 1, reads)

print("== the picker")
LIST = [("wan1", "Up", 1e9), ("lan", "Up", 100e6), ("old", "Down")]
pk = InterfacePicker(LIST, [], wan={"wan1": 300})
t = pk.table
check("the WAN columns are named", [t.horizontalHeaderItem(c).text() for c in (3, 4)] == ["WAN", "Available bandwidth"])
check("wan1 is ticked WAN with 300; the others show the port speed",
      pk.wan() == {"wan1": 300} and t.cellWidget(0, 4).text() == "300" and t.cellWidget(1, 4).placeholderText() == "100 Mbps (port speed)"
      and t.cellWidget(0, 4).placeholderText() == "1 Gbps (port speed)" and t.cellWidget(1, 4).text() == "", pk.wan())
from PySide6.QtCore import Qt
t.item(1, 3).setCheckState(Qt.CheckState.Checked); t.cellWidget(0, 4).setText("")
check("it round-trips: an empty box means the port speed", pk.wan() == {"wan1": None, "lan": None}, pk.wan())
pk.resize(880, 500); pk.show(); app.processEvents()
edits = [t.cellWidget(i, 4) for i in range(t.rowCount())]
check("each bandwidth box sits inside its own row, every box as wide, and the port speed shows whole",
      all(t.rowViewportPosition(i) <= e.y() and e.geometry().bottom() < t.rowViewportPosition(i) + t.rowHeight(i) for i, e in enumerate(edits))
      and len({e.width() for e in edits}) == 1 and all(e.width() > e.fontMetrics().horizontalAdvance(e.placeholderText()) + 16 for e in edits),
      [(t.rowViewportPosition(i), t.rowHeight(i), e.geometry().getRect()) for i, e in enumerate(edits)])
pk.hide()
check("without wan there are no WAN columns", InterfacePicker(LIST, []).table.columnCount() == 3 and InterfacePicker(LIST, []).wan() == {})
check("without the check-only tick the first column is hidden", InterfacePicker(LIST, [], wan={}, choose_checked=False).table.isColumnHidden(0))

print("== Edit device > Checks")
from ui.devicechecks import DeviceChecks
w = DeviceChecks(); w.set_vendor("fortinet"); w.load(None)
w.fetch_interfaces = lambda: LIST
def pick(self):
    self.table.item(0, 3).setCheckState(Qt.CheckState.Checked); self.table.cellWidget(0, 4).setText("300"); return 1
InterfacePicker.exec = pick
check("Choose is open without the check-only tick", not w.pick_ifs.isChecked() and w.if_choose.isEnabled())
w.if_choose.click()
w2 = DeviceChecks(); w2.set_vendor("fortinet"); w2.load(w.values())
check("the WAN choice is saved without it, and loads back", w.values() == {"wan": {"wan1": 300.0}} and not w.pick_ifs.isChecked() and w2._wan == {"wan1": 300.0}, w.values())
w.set_vendor("windows")
check("a device that cannot read traffic drops it", w.values() == {})

print("== every network device")
NOSNMP = {"name": "pa-nosnmp", "vendor": "paloalto", "host": "10.0.0.9", "checkopts": {"wan": {"ethernet1/1": None}}}
r = DRIVERS["paloalto"](NOSNMP, TH, {**db.runtime_options()}).wan_usage()
check("WAN chosen but no SNMP set up: an N/A row that says how", r.status == "N/A" and r.value == "no traffic counters"
      and r.message == "Set up SNMP on this device's SNMP tab so Toner can read WAN traffic.", r)
check("...and no WAN chosen: no row at all", DRIVERS["paloalto"]({**NOSNMP, "checkopts": {}}, TH, {**db.runtime_options()}).wan_usage() == [])
PA = {"name": "pa-snmp", "vendor": "paloalto", "host": "10.0.0.1", "snmp": '{"version": "2c"}', "checkopts": {"wan": {"Gi0/1": None}}}
walks.clear()
pa = DRIVERS["paloalto"](PA, TH, {**db.runtime_options()})
check("Palo Alto with SNMP set up reads the standard interface counters", pa.interface_counters() == {"Gi0/1": (5, 7, 1e9)}, pa.interface_counters())
check("...walked once however often it is asked", walks.count(N["ifHCInOctets"]) == 1, walks)

from core import runner as R
R.reachability = lambda dev, opts: []
R.resolve_host = lambda host: None
real_pa_run = DRIVERS["paloalto"].run
DRIVERS["paloalto"].run = lambda self: []
try:
    rows = {x.check: x for x in R.run_one({**PA, "name": "pa-run"}, TH)}
    check("the runner adds WAN usage after a Palo Alto run (its first run sets the baseline)", rows.get("wan usage") is not None
          and rows["wan usage"].value == "baseline set", list(rows))
    rows = {x.check: x for x in R.run_one({**NOSNMP, "name": "pa-run2"}, TH)}
    check("...and the N/A row when SNMP is not set up", rows.get("wan usage") is not None and rows["wan usage"].status == "N/A", list(rows))
    rows = {x.check: x for x in R.run_one({**PA, "name": "pa-run3", "checkopts": {}}, TH)}
    check("...and nothing when no WAN interface is chosen", "wan usage" not in rows, list(rows))
finally:
    DRIVERS["paloalto"].run = real_pa_run
check("FortiGate, SNMP devices and Cisco make the row in their own run, so the runner leaves them alone",
      DRIVERS["fortinet"].wan_in_run and DRIVERS["snmp"].wan_in_run and DRIVERS["sophos"].wan_in_run and DRIVERS["cisco"].wan_in_run
      and not DRIVERS["paloalto"].wan_in_run)

print("== Cisco: show interface")
from drivers import clichecks
IOS = """GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is 5254.0012.3456 (bia 5254.0012.3456)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 2000 bits/sec, 3 packets/sec
     123456 packets input, 98765432 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     65432 packets output, 12345678 bytes, 0 underruns
GigabitEthernet0/1 is administratively down, line protocol is down
  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 10 usec,
     0 packets input, 0 bytes, 0 no buffer
     0 packets output, 0 bytes, 0 underruns
Loopback0 is up, line protocol is up
  MTU 1514 bytes, BW 8000000 Kbit/sec, DLY 5000 usec,
"""
ASA = """Interface GigabitEthernet0/0 "outside", is up, line protocol is up
  Hardware is net_vmxnet3, BW 1000 Mbps, DLY 10 usec
	Full-Duplex(Full-duplex), 1000 Mbps(1000 Mbps)
	2000 packets input, 300000 bytes, 0 no buffer
	0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
	1500 packets output, 200000 bytes, 0 underruns
  Traffic Statistics for "outside":
	2000 packets input, 999 bytes
	1500 packets output, 888 bytes
Interface Management0/0 "", is administratively down, line protocol is down
  Hardware is net_vmxnet3, BW 1000 Mbps, DLY 10 usec
"""
check("IOS: bytes in and out and the BW of each interface with counters", clichecks.interface_bytes(IOS)
      == {"GigabitEthernet0/0": (98765432, 12345678, 1e9), "GigabitEthernet0/1": (0, 0, 1e8)}, clichecks.interface_bytes(IOS))
check("ASA: the interface's own counters, not the Traffic Statistics repeat; BW in Mbps", clichecks.interface_bytes(ASA)
      == {"GigabitEthernet0/0": (300000, 200000, 1e9)}, clichecks.interface_bytes(ASA))
check("nothing readable: nothing", clichecks.interface_bytes("") == {} and clichecks.interface_bytes("% Invalid input") == {})
class Conn:
    def __init__(self, text): self.text, self.sent = text, []
    def send_command(self, cmd, **k): self.sent.append(cmd); return self.text
cs = DRIVERS["cisco"]({"name": "asa", "vendor": "cisco", "host": "h", "platform": "cisco_asa", "checkopts": {"wan": {"GigabitEthernet0/0": None}}},
                       TH, {**db.runtime_options()})
cs.plat, conn = "cisco_asa", Conn(ASA)
first = cs._wan_on(conn)
check("an ASA's run reads `show interface` on its own connection", conn.sent == ["show interface"] and first.value == "baseline set", (conn.sent, first))
cs.plat, conn = "cisco_ios", Conn(IOS)
cs._live = conn
check("IOS asks `show interfaces`", cs.interface_counters()["GigabitEthernet0/0"][2] == 1e9 and conn.sent == ["show interfaces"], conn.sent)
cs.plat, conn = "cisco_nxos", Conn(IOS)
cs._live = conn
try:
    cs.interface_counters(); check("NX-OS goes to SNMP (none set up here: says so)", False)
except B.NoCounters:
    check("NX-OS goes to SNMP (none set up here: says so)", conn.sent == [], conn.sent)
cs._live = None

print("== the hint")
from ui import interfacepicker as IP
check("with port speeds read, the bandwidth starts at them", IP.WAN_HINT in InterfacePicker(LIST, [], wan={}).findChild(IP.QLabel).text())
nospeed = InterfacePicker([("ethernet1/1", "Up"), ("ethernet1/2", "Down")], [], wan={})
check("with none, type each circuit speed; traffic comes by SNMP once set up", nospeed.wan_hint() ==
      "Tick the interfaces that connect to the internet and type each one's circuit speed in Mbps. Toner reads their traffic by SNMP "
      "once it is set up on the SNMP tab." and nospeed.wan_hint() in nospeed.findChild(IP.QLabel).text())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
