# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import asyncio, os, socket, sys, threading, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\nt%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, pinger, oui, listeners, topology, cmdrun
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== ping / trace / MTR")
ms = pinger.ping_once("127.0.0.1", 1000); check("ping localhost", ms is not None and ms >= 0, ms)
check("no reply -> None", pinger.ping_once("192.0.2.1", 400) is None)
import shutil as _shutil
hops = pinger.trace("127.0.0.1", max_hops=3, timeout_ms=300)
if _shutil.which(pinger.trace_args("x")[0]):
    check("traceroute to localhost is one hop", hops and hops[0][1] == "127.0.0.1", hops)
else:
    check("without traceroute installed: no hops, and no crash", hops == [])
h = pinger.HopStats(1, "10.0.0.1")
for v in (10.0, None, 30.0): h.add(v)
check("hop statistics", h.sent == 3 and h.lost == 1 and abs(h.loss - 33.33) < 0.1 and h.best == 10.0 and h.worst == 30.0 and h.avg == 20.0 and h.last == 30.0 and h.history == [10.0, None, 30.0])
updates = []
m = pinger.Mtr("127.0.0.1", interval=0.3, timeout_ms=500); m.start(lambda: updates.append(1))
for _ in range(60):
    time.sleep(0.1)
    if m.cycles >= 3: break
m.stop()
snap = m.snapshot()
check("MTR discovers the path and measures every hop each cycle", snap and snap[0].sent >= 3 and snap[0].loss == 0 and len(updates) >= 3, (len(snap), m.cycles))

print("== MAC tools")
check("MAC formats", oui.normalize("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF" and oui.normalize("AA-BB-CC-DD-EE-FF") == "AABBCCDDEEFF" and oui.normalize("aabb.ccdd.eeff") == "AABBCCDDEEFF" and oui.pretty("aabbccddeeff", "-") == "AA-BB-CC-DD-EE-FF")
for bad_mac in ("", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"):
    try: oui.normalize(bad_mac); check(f"rejects '{bad_mac}'", False)
    except ValueError: check(f"rejects '{bad_mac}'", True)
check("built-in vendors", oui.lookup("00:0c:29:11:22:33") == "VMware" and oui.lookup("B8:27:EB:00:00:01") == "Raspberry Pi Foundation" and oui.lookup("00-00-0C-11-22-33") == "Cisco Systems")
check("random (locally administered) addresses are named as such", "randomised" in oui.lookup("02:11:22:33:44:55") and oui.lookup("00:11:22:33:44:55") == "")
oui.cache_path().write_text("AA-BB-CC   (hex)\t\tTest Vendor Inc.\nAABBCC     (base 16)\t\tTest Vendor Inc.\n", encoding="utf-8"); oui.reload()
check("a downloaded IEEE list is used when present", oui.lookup("aa:bb:cc:00:00:01") == "Test Vendor Inc.")
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
n = oui.send_wol("aa:bb:cc:dd:ee:ff", "127.0.0.1", rx.getsockname()[1]); data, _ = rx.recvfrom(512)
check("Wake-on-LAN packet: 6x FF then the MAC 16 times", n == 102 and data[:6] == b"\xff" * 6 and data[6:] == bytes.fromhex("AABBCCDDEEFF") * 16)

print("== syslog")
m1 = listeners.parse_syslog(b"<189>Oct  9 12:00:00 sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", ("10.0.0.5", 514))
check("priority is split into facility and severity", m1["facility"] == "local7" and m1["severity"] == "notice" and "LINK-3-UPDOWN" in m1["text"] and m1["source"] == "10.0.0.5", m1)
m2 = listeners.parse_syslog(b"<11>kernel: panic", ("1.1.1.1", 1)); check("severity names", m2["severity"] == "error" and m2["facility"] == "user")
m3 = listeners.parse_syslog(b"plain text no priority", ("1.1.1.1", 1)); check("a message with no priority still parses", m3["text"] == "plain text no priority" and m3["facility"] == "user")
def dev(name, vendor="cisco", host="10.0.0.1"):
    db.save_device(dict(name=name, vendor=vendor, host=host, port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
dev("sw1", host="127.0.0.1")
got = []
sl = listeners.SyslogListener(port=0, on_message=got.append, bind="127.0.0.1"); sl.start()
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); tx.sendto(b"<14>hello from the lab", ("127.0.0.1", sl.port))
for _ in range(30):
    if got: break
    time.sleep(0.1)
check("a UDP datagram is received, parsed and matched to the inventory device", got and got[0]["text"] == "hello from the lab" and got[0]["device"] == "sw1" and got[0]["severity"] == "info", got)
sl.stop(); check("listener stops cleanly", True)
busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if hasattr(socket, "SO_EXCLUSIVEADDRUSE"): busy.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
busy.bind(("127.0.0.1", 0)); bp = busy.getsockname()[1]
try:
    sl2 = listeners.SyslogListener(port=bp, bind="127.0.0.1"); sl2.start(); sl2.stop(); check("a port already in use is reported", False)
except OSError: check("a port already in use is reported", True)

print("== SNMP traps")
TP = 18100 + os.getpid() % 500
traps = []
tl = listeners.TrapListener(port=TP, communities=("trapcomm",), on_trap=traps.append, bind="127.0.0.1"); tl.start()
async def send(community):
    from pysnmp.hlapi.v3arch import asyncio as h
    eng = h.SnmpEngine()
    target = await h.UdpTransportTarget.create(("127.0.0.1", TP))
    await h.send_notification(eng, h.CommunityData(community, mpModel=1), target, h.ContextData(), "trap",
                              h.NotificationType(h.ObjectIdentity("1.3.6.1.6.3.1.1.5.3")).add_varbinds(
                                  h.ObjectType(h.ObjectIdentity("1.3.6.1.2.1.2.2.1.1.5"), h.Integer32(5))))
    eng.close_dispatcher()
asyncio.run(send("wrongcomm")); time.sleep(0.5)
check("a trap with the wrong community is ignored", traps == [])
asyncio.run(send("trapcomm"))
for _ in range(30):
    if traps: break
    time.sleep(0.1)
check("a v2c trap is received with its OID and source", bool(traps) and traps[0]["source"] == "127.0.0.1" and traps[0]["device"] == "sw1" and "1.3.6.1.6.3.1.1.5.3" in traps[0]["text"], traps)
tl.stop()

print("== topology")
for n in ("core1", "dist1", "dist2"):
    dev(n)
rows = [{"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/1", "remote_name": "dist1.corp.example.com", "remote_port": "Te1/1", "remote_addr": ""},
        {"device": "dist1", "protocol": "LLDP", "local_port": "Te1/1", "remote_name": "core1", "remote_port": "Gi1/0/1", "remote_addr": ""},
        {"device": "dist1", "protocol": "CDP", "local_port": "Te1/1", "remote_name": "core1", "remote_port": "GigabitEthernet1/0/1", "remote_addr": "10.0.0.1"},
        {"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/2", "remote_name": "DIST2", "remote_port": "", "remote_addr": ""},
        {"device": "dist2", "protocol": "LLDP", "local_port": "Te1/1", "remote_name": "core1", "remote_port": "Gi1/0/2", "remote_addr": ""},
        {"device": "dist2", "protocol": "LLDP", "local_port": "Gi0/24", "remote_name": "ap-lobby", "remote_port": "eth0", "remote_addr": "10.2.2.2"},
        {"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/9", "remote_name": "core1", "remote_port": "x", "remote_addr": ""}]
nodes, links = topology.build_graph(rows)
check("inventory names are matched case- and domain-insensitively", set(nodes) == {"core1", "dist1", "dist2", "ap-lobby"} and nodes["core1"]["inventory"] and not nodes["ap-lobby"]["inventory"] and nodes["ap-lobby"]["addr"] == "10.2.2.2", nodes)
check("the same cable seen from both ends is one link", len(links) == 3, [(l["a"], l["b"], l["a_port"], l["b_port"]) for l in links])
l1 = next(l for l in links if {l["a"], l["b"]} == {"core1", "dist1"}); check("both protocols recorded", l1["protocols"] == {"LLDP", "CDP"})
l2 = next(l for l in links if {l["a"], l["b"]} == {"core1", "dist2"}); check("a missing port on one side is filled in from the other", sorted([l2["a_port"], l2["b_port"]]) == ["Gi1/0/2", "Te1/1"], l2)
check("a device listing itself is dropped", all(l["a"] != l["b"] for l in links))
pos = topology.layout(nodes, links, 800, 500)
check("layout places every node inside the box", set(pos) == set(nodes) and all(40 <= x <= 760 and 30 <= y <= 470 for x, y in pos.values()))
import math
dist = lambda a, b: math.dist(pos[a], pos[b])
mn = min(dist(a, b) for a in pos for b in pos if a < b)
check("nodes do not sit on top of each other", mn > 30, mn)
check("layout is repeatable", topology.layout(nodes, links, 800, 500) == pos)
check("single and empty graphs", topology.layout({"a": {}}, [], 100, 100) == {"a": (50, 50)} and topology.layout({}, []) == {})
fixed = topology.layout(nodes, links, 800, 500, fixed={"core1": (123.0, 45.0)})
check("a box the user placed stays put while the rest are laid out", fixed["core1"] == (123.0, 45.0) and fixed["dist1"] != pos["dist1"])

print("== neighbours over SSH and the APIs: the parsers")
CDP = """-------------------------
Device ID: dist1.corp.example.com
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1
Holdtime : 155 sec
-------------------------
Device ID: ap-1
Entry address(es):
  IP address: 10.5.5.5
Platform: cisco AIR-AP2802I-B-K9,  Capabilities: Trans-Bridge Source-Route-Bridge IGMP
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): GigabitEthernet0
"""
rows = topology.parse("cisco_ios", "show cdp neighbors detail", CDP)
check("CDP detail: device, both ports, address and platform", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows]
      == [("GigabitEthernet1/0/1", "dist1.corp.example.com", "TenGigabitEthernet1/1/1", "10.0.0.2"), ("GigabitEthernet1/0/5", "ap-1", "GigabitEthernet0", "10.5.5.5")]
      and rows[0]["remote_desc"].startswith("cisco WS-C3850") and rows[0]["protocol"] == "CDP", rows)
LLDP_IOS = """------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 0011.2233.4455
Port id: Gi0/2
Port Description: GigabitEthernet0/2
System Name: dist2

System Description:
Cisco IOS Software, C2960 Software

Time remaining: 95 seconds
Management Addresses:
    IP: 10.0.0.3
"""
rows = topology.parse("cisco_xe", "show lldp neighbors detail", LLDP_IOS)
check("LLDP detail (IOS): local port, port id, system name, management address", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"], r["protocol"]) for r in rows]
      == [("Gi1/0/2", "dist2", "Gi0/2", "10.0.0.3", "LLDP")], rows)
NXOS = """Chassis id: 0011.2233.4466
Port id: Ethernet1/2
Local Port id: Eth1/1
Port Description: to core
System Name: n9k-2
System Description: Cisco Nexus Operating System (NX-OS) Software 9.3(8)
Management Address: 10.0.0.4
"""
rows = topology.parse("cisco_nxos", "show lldp neighbors detail", NXOS)
check("LLDP detail (NX-OS): the local port comes after the remote port, and still pairs up", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows] == [("Eth1/1", "n9k-2", "Ethernet1/2", "10.0.0.4")], rows)
ARISTA = """Interface Ethernet1 detected 2 LLDP neighbors:

  Neighbor 0011.2233.4477/"Ethernet2", age 5 seconds
  Discovered 0:10:00 ago; Last changed 0:10:00 ago
  - Chassis ID type: MAC address (4)
  - Port ID type: Interface name (5)
  - Port ID     : "Ethernet2"
  - System Name: "dist1"
  - Management Address Subtype: IPv4
  - Management Address        : 10.0.0.2

  Neighbor 0011.2233.4488/"eth0", age 9 seconds
  - Port ID     : "eth0"
  - System Name: "ap-2"
"""
rows = topology.parse("arista_eos", "show lldp neighbors detail", ARISTA)
check("LLDP detail (Arista): two neighbours on one port", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows] == [("Ethernet1", "dist1", "Ethernet2", "10.0.0.2"), ("Ethernet1", "ap-2", "eth0", "")], rows)
JUNOS = """Local Interface    Parent Interface    Chassis Id          Port info          System Name
ge-0/0/0.0         -                   00:11:22:33:44:55   ge-0/0/1.0         dist1
xe-0/1/0.0         ae0.0               00:11:22:33:44:66   Te1/1/1            core1
"""
rows = topology.parse("juniper_junos", "show lldp neighbors | no-more", JUNOS)
check("Junos table: local interface, port info, system name", [(r["local_port"], r["remote_name"], r["remote_port"]) for r in rows] == [("ge-0/0/0.0", "dist1", "ge-0/0/1.0"), ("xe-0/1/0.0", "core1", "Te1/1/1")], rows)
MT = """ 0 interface=ether1 address=10.0.0.2 mac-address=00:11:22:33:44:55 identity="dist1" platform="MikroTik" version="7.14"
   board=CRS326 interface-name="ether24" discovered-by=cdp,lldp

 1 interface=ether2,bridge address=10.0.0.9 identity="ap-3" interface-name="eth0" discovered-by=lldp
"""
rows = topology.parse("mikrotik_routeros", "/ip neighbor print detail", MT)
check("MikroTik: identity, interface-name and address, one entry per blank-line block", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows] == [("ether1", "dist1", "ether24", "10.0.0.2"), ("ether2", "ap-3", "eth0", "10.0.0.9")] and rows[0]["remote_desc"] == "MikroTik CRS326", rows)
rows = topology.parse_fortinet({"results": [{"port": "port1", "system_name": "dist1", "port_id": "Gi1/0/7", "system_description": "Cisco IOS", "mgmt_address": "10.0.0.2"}, {"port": "port2"}]})
check("FortiOS JSON: a row per neighbour with a name or port", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows] == [("port1", "dist1", "Gi1/0/7", "10.0.0.2")], rows)
PAN = """<response status="success"><result><entry name="ethernet1/1"><neighbors><entry><port-id>Gi1/0/8</port-id><system-name>dist1</system-name>
<system-description>Cisco IOS</system-description><management-address>10.0.0.2</management-address></entry></neighbors></entry>
<entry name="ethernet1/2"><neighbors/></entry></result></response>"""
rows = topology.parse_panos(PAN)
check("PAN-OS XML: an entry per local port, its neighbours under it", [(r["local_port"], r["remote_name"], r["remote_port"], r["remote_addr"]) for r in rows] == [("ethernet1/1", "dist1", "Gi1/0/8", "10.0.0.2")], rows)
check("not XML: no rows, no error", topology.parse_panos("nope") == [])
check("the vendor a neighbour's description points at", topology.guess_vendor("cisco WS-C3850") == "cisco" and topology.guess_vendor("Arista DCS-7050") == "arista" and topology.guess_vendor("FortiGate-60F") == "fortinet"
      and topology.guess_vendor("MikroTik CRS326") == "mikrotik" and topology.guess_vendor("") == "")

print("== which devices are asked, what changed, and what is kept")
import json as _json
def dev2(name, vendor, platform="", snmp_=""):
    d = {"name": name, "vendor": vendor, "host": "10.0.0.50", "platform": platform, "enabled": 1, "snmp": snmp_}
    d["id"] = db.save_device(d); return d
dev2("sw-ssh", "cisco", "cisco_ios"); dev2("asa", "cisco", "cisco_asa"); dev2("fw", "fortinet"); dev2("pa", "paloalto"); dev2("win", "windows"); dev2("mt", "mikrotik")
names = {d["name"] for d in topology.devices()}
check("asked: SSH vendors with commands, the API firewalls, SNMP devices; not an ASA or a Windows computer", {"sw-ssh", "fw", "pa", "mt"} <= names and "asa" not in names and "win" not in names, names)
first = [{"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/1", "remote_name": "dist1", "remote_port": "Te1/1", "remote_addr": "", "local_up": True, "local_speed": "10 Gbps"},
         {"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/2", "remote_name": "dist2", "remote_port": "Te1/1", "remote_addr": "", "local_up": False, "local_speed": "1 Gbps"}]
second = [first[0], {"device": "dist1", "protocol": "LLDP", "local_port": "Gi0/24", "remote_name": "ap-lobby", "remote_port": "eth0", "remote_addr": "10.2.2.2"}]
n1, l1 = topology.build_graph(first)
check("a link carries its rows, the port state and the speed", l1[0]["rows"] == [0] and l1[0]["speed"] == "10 Gbps" and not l1[0]["down"] and l1[1]["down"] and l1[1]["speed"] == "1 Gbps")
n2, l2 = topology.build_graph(second)
n2, l2 = topology.mark_changes(n2, l2, l1)
by_change = {(l["a"], l["b"]): l["change"] for l in l2}
check("against the discovery before: the kept link is plain, the added one new, the missing one gone (and drawn from the old rows)",
      by_change == {("core1", "dist1"): "", ("dist1", "ap-lobby"): "new", ("core1", "dist2"): "gone"} and "dist2" in n2 and next(l for l in l2 if l["change"] == "gone")["rows"] == [], by_change)
check("nothing kept yet", topology.last() == ([], "", []))
topology.remember(first); topology.remember(second)
rows_, at, prev = topology.last()
check("the latest discovery is kept with its time, and the one before it", rows_ == second and at[:2] == "20" and prev == first)
check("...per organization, not portable", "topology_last" in db.NOT_PORTABLE and "topology_last" not in db.export_settings())
topology.save_positions({"core1": (10.26, 20.0), "dist1": (30.0, 40.44)})
check("dragged positions are kept, rounded", topology.positions() == {"core1": (10.3, 20.0), "dist1": (30.0, 40.4)})
topology.save_positions(None); check("...and forgotten by Tidy up", topology.positions() == {})

print("== command runner")
check("read-only guard", cmdrun.read_only("show version") and cmdrun.read_only("display current-configuration") and cmdrun.read_only("  SHOW ip route") and cmdrun.read_only("/system resource print") and not cmdrun.read_only("reload") and not cmdrun.read_only("configure terminal") and not cmdrun.read_only("no shutdown") and not cmdrun.read_only("clear counters") and not cmdrun.read_only("write erase") and not cmdrun.read_only("copy run start") and not cmdrun.read_only("conf t"))
check("commands are split, comments and blanks dropped", cmdrun.split_commands("show a\n\n# note\n  show b  \n") == ["show a", "show b"])
from drivers import DRIVERS
class Conn:
    def __init__(self, name): self.name = name
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, **k):
        if self.name == "dist2": raise RuntimeError("boom")
        return f"{self.name}: output of {cmd}"
orig = DRIVERS["cisco"].connect
DRIVERS["cisco"].connect = lambda self: Conn(self.name)
devs = [x for x in db.list_devices() if x["name"] in ("core1", "dist1", "dist2")]
seen = []
res = cmdrun.run_many(devs, ["show version", "show clock"], workers=3, on_result=seen.append)
DRIVERS["cisco"].connect = orig
by = {r["device"]: r for r in res}
check("every device runs every command in one session, results sorted by name", [r["device"] for r in res] == ["core1", "dist1", "dist2"] and by["core1"]["ok"] and by["core1"]["outputs"] == [("show version", "core1: output of show version"), ("show clock", "core1: output of show clock")] and len(seen) == 3)
check("one device failing does not stop the others", not by["dist2"]["ok"] and "boom" in by["dist2"]["error"] and by["dist1"]["ok"])
dev("cloud", "meraki", "x")
r = cmdrun.run_on_device([x for x in db.list_devices() if x["name"] == "cloud"][0], ["show x"]); check("non-SSH devices are refused with a reason", not r["ok"] and "SSH" in r["error"])
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
