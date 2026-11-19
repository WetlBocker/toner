# Run directly (python tests/test_routing_hpe.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# BGP and OSPF neighbours on HPE Aruba switches (AOS-CX and AOS-S). The sample outputs are the ones HPE's own guides print (the
# address is beside each); where a sample was changed to make a case the guides do not show, the comment says so.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rhpe%d.db" % int(time.time()))
from core import db
db.init()
from drivers import DRIVERS
import drivers.hpe as H

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.thresholds_for({"name": "x", "vendor": "hpe", "location": ""})
OPTS = {**db.runtime_options()}

class Conn:
    def __init__(self, table): self.t = table; self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        return self.t.get(cmd, "Invalid input: " + cmd.split()[-1])

SENT = []
def ssh_run(vendor, table, platform="", **dev):
    d = {"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": platform, "password": "p", **dev}
    drv = DRIVERS[vendor](d, TH, OPTS)
    conn = Conn(table)
    drv.connect = lambda: conn
    res = drv.run()
    SENT[:] = conn.sent
    return {r.check: r for r in res}

def show(r, *keys):
    return {k: (r[k].status, r[k].value, r[k].message) if k in r else None for k in keys}

# ---------------------------------------------------------------- AOS-CX
# https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/ip_route_8400/Content/Chp_BGP/BGP_cmds/sho-bgp-sum-10.htm
CX_BGP = """Codes: * Dynamic Neighbor
VRF : default
BGP Summary
 Local AS               : 100          BGP Router Identifier  : 9.0.0.1
 Peers                  : 1            Log Neighbor Changes   : No
 Cfg. Hold Time         : 180          Cfg. Keep Alive        : 60
 Confederation Id       : 0

Address-family : IPv4 Unicast
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
 9.0.0.2         200       25      23      00h:17m:50s  Established Up
*10.1.1.5        11        26      24      00h:20m:26s  Established Up

Address-family : IPv6 Unicast
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
*2001::2002      11        3       3       00h:00m:14s  Established Up
 9000::2         200       25      23      00h:17m:50s  Established Up

Address-family : VPNv4 Unicast
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
 1.1.1.1         100       207     208     02h:54m:18s  Established Up
*3.3.3.4         11        26      24      00h:20m:26s  Established Up

Address-family : L2VPN EVPN
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
 10.0.0.2        200       25      23      00h:17m:50s  Established Up
*10.1.1.6        11        26      24      00h:20m:26s  Established Up

VRF : v1
BGP Summary
 Local AS               : 100          BGP Router Identifier  : 9.0.0.1
 Peers                  : 1            Log Neighbor Changes   : No
 Cfg. Hold Time         : 180          Cfg. Keep Alive        : 60

Address-family : IPv4 Unicast
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
*4.4.4.4         11        26      24      00h:20m:26s  Established Up
 9.0.0.2         200       25      23      00h:17m:50s  Established Up

Address-family : IPv6 Unicast
-----------------------------
 Neighbor        Remote-AS MsgRcvd MsgSent Up/Down Time State       AdminStatus
*3001::3002      11        3       3       00h:00m:14s  Established Up
 9000::2         200       25      23      00h:17m:50s  Established Up
"""
# The same screen with no neighbor rows: not in the guide, made here from its header lines.
CX_BGP_EMPTY = CX_BGP.split("Address-family")[0]
# https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/ip_route_4100i-5420-6000-6100-6200/Content/Chp_OSPFv2/OSPFv2_cmds/sho-ip-osp-nei-10.htm
CX_OSPF = """OSPF Process ID 1 VRF default
==============================

Total Number of Neighbors: 1

Neighbor ID      Priority  State             Nbr Address       Interface
-------------------------------------------------------------------------
2.2.2.2          1         FULL/DR           10.1.1.2           1/1/1
"""
# https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/ip_route_4100i-5420-6000-6100-6200/Content/Chp_OSPFv2/OSPFv2_cmds/sho-ip-osp-10.htm
CX_OSPF_GENERAL = """VRF : Default                         Process : 200
-------------------------------------------------------------------

Router ID              : 1.1.1.1             OSPFv2                : Enabled
BFD                    : Disabled            SPF Start Interval    : 5000 ms
SPF Hold Interval      : 1000 ms             SPF Max Wait Interval : 1000 ms
"""
# The base screens of a whole run, as in tests/test_vendors.py.
AOSCX = {"show system resource-utilization": "System Resource Utilization\n CPU usage       : 7 %\n Memory usage    : 41 %\n",
         "show system": "Hostname : cx1\nUp Time : 12 days, 3 hours\nCPU : x\n",
         "show interface brief": "Port  Native  Mode  Type  Enabled  Status\n1/1/1  1  access  1GbT  yes  up  1000\n1/1/2  1  access  1GbT  yes  down  --\nlag1  --  routed  --  yes  up  --\n"}
CXB, CXO, CXG = "show bgp all summary", "show ip ospf neighbors all-vrfs", "show ip ospf all-vrfs"

print("== AOS-CX: reading the screens")
peers = H.cx_bgp_peers(CX_BGP)
check("BGP: every neighbor of every VRF and address family, all Established", len(peers) == 12 and all(s == "Established" for _n, s in peers), peers)
check("BGP: a dynamic neighbor (the * in front) and an IPv6 one are read by address", ("10.1.1.5", "Established") in peers and ("2001::2002", "Established") in peers, peers)
check("BGP: the same address in two VRFs is two neighbors", [n for n, _s in peers].count("9.0.0.2") == 2, peers)
twice = CX_BGP.replace(" 10.0.0.2        200", " 9.0.0.2         200")          # the EVPN family now lists the IPv4 neighbor again
check("BGP: a neighbor in two address families of one VRF counts once", len(H.cx_bgp_peers(twice)) == 11, H.cx_bgp_peers(twice))
check("BGP: a neighbor shut down by an admin is left out", len(H.cx_bgp_peers(CX_BGP.replace("00h:20m:26s  Established Up\n\nAddress-family : IPv6", "00h:20m:26s  Idle        Down\n\nAddress-family : IPv6", 1))) == 11)
check("BGP: no rows, nothing read", H.cx_bgp_peers(CX_BGP_EMPTY) == [] and H.cx_bgp_peers("Invalid input: bgp") == [] and H.cx_bgp_peers("") == [])
check("OSPF: router ID and the state without the /DR part", H.cx_ospf_neighbors(CX_OSPF) == [("2.2.2.2", "FULL")], H.cx_ospf_neighbors(CX_OSPF))
check("OSPF: no rows, nothing read", H.cx_ospf_neighbors("Invalid input: ospf") == [] and H.cx_ospf_neighbors("") == [])
check("Full and 2-Way are adjacent however they are spelled, the rest are not", all(H.clichecks.adjacent(s) for s in ("FULL", "Full", "2WAY", "2-Way", "TwoWay"))
      and not any(H.clichecks.adjacent(s) for s in ("INIT", "EXSTART", "EXCHANGE", "LOADING", "Down")))

print("== AOS-CX: the rows of a run")
r = ssh_run("hpe", AOSCX)
check("a switch that does not know the commands: both not configured (N/A)", r["bgp"].status == "N/A" and r["ospf"].status == "N/A" and r["bgp"].value == "not configured", show(r, "bgp", "ospf"))
check("every VRF asked in one command each", CXB in SENT and CXO in SENT, SENT)
check("the other rows are still there", r["cpu"].value == "7%" and r["interfaces"].value == "2/3 up" and list(r) == ["cpu", "memory", "uptime", "interfaces", "bgp", "ospf", "environment"], list(r))
r = ssh_run("hpe", {**AOSCX, CXB: "", CXO: "", CXG: ""})
check("commands known, nothing configured: N/A", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", show(r, "bgp", "ospf"))
r = ssh_run("hpe", {**AOSCX, CXB: CX_BGP_EMPTY, CXO: "", CXG: CX_OSPF_GENERAL})
check("running with no neighbors: WARN", r["bgp"].status == "WARN" and r["bgp"].value == "no neighbors" and r["ospf"].status == "WARN" and "OSPF is running" in r["ospf"].message, show(r, "bgp", "ospf"))
r = ssh_run("hpe", {**AOSCX, CXB: CX_BGP, CXO: CX_OSPF})
check("all up: OK", r["bgp"].status == "OK" and r["bgp"].value == "12/12 established" and r["bgp"].numeric == 12 and r["ospf"].status == "OK" and r["ospf"].value == "1/1 established", show(r, "bgp", "ospf"))
check("neighbors found: OSPF is not asked a second time", CXG not in SENT, SENT)
# One neighbor moved out of Established / Full: the states are the protocol's own, the guide shows only the good ones.
r = ssh_run("hpe", {**AOSCX, CXB: CX_BGP.replace("00h:20m:26s  Established Up", "00h:00m:00s  Active      Up", 1),
                    CXO: CX_OSPF + "3.3.3.3          1         EXSTART/BDR       10.1.2.2           1/1/2\n4.4.4.4          1         2-WAY/DROther     10.1.2.4           1/1/2\n"})
check("one BGP neighbor down: FAIL, named", r["bgp"].status == "FAIL" and r["bgp"].value == "11/12 established" and r["bgp"].message == "down: 10.1.1.5", show(r, "bgp"))
check("one OSPF neighbor not Full: FAIL, named with its state; 2-Way is fine", r["ospf"].status == "FAIL" and r["ospf"].value == "2/3 established" and r["ospf"].message == "down: 3.3.3.3 (EXSTART)", show(r, "ospf"))

# ---------------------------------------------------------------- AOS-S
# https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/MRG/KB/content/kb/cnf-pro3.htm
S_BGP = """
Peer Information

Remote Address Remote-AS Local-AS State        Admin Status
-------------- --------- -------- --------     ------------
2.2.2.2        65009     65009    Established  Start
3.1.1.2        65008     65009    Established  Start
"""
S_BGP_EMPTY = S_BGP.split("2.2.2.2")[0]                                   # the heading alone: not in the guide
# The guide names `show ip bgp general` but prints no sample: the line is the one its `show ip bgp` screen starts with
# (https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/MRG/KB/content/kb/bgp-sho-rou.htm).
S_BGP_GENERAL = "\nLocal AS  : 100              Local Router-id : 10.0.102.138\n"
# https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MRG/WC/content/common%20files/vie-osp-nei-inf.htm
S_OSPF = """
 OSPF Neighbor Information

                                                         Rxmt         Helper
  Router ID       Pri IP Address     NbIfState State     QLen  Events Status
  --------------- --- -------------- --------- --------- ----- ------ ------
  10.0.8.34       1   10.3.18.34     DR        FULL      0     6      none
  10.3.53.38      1   10.3.53.38     DR        FULL      0     6      none
"""
S_OSPF_EMPTY = S_OSPF.split("  10.0.8.34")[0]                             # the heading alone: not in the guide
# https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MRG/WC/content/common%20files/vie-gen-osp-cnf-inf.htm
S_OSPF_GENERAL = """
 OSPF General Status

  OSPF protocol          : enabled
  Router ID              : 17.255.134.231
  RFC 1583 compatability : compatible
"""
AOSS = {"show system information": "\n Status and Counters - General System Information\n\n  System Name        : sw1\n  Up Time            : 6 days   Memory   - Total   : 134,217,728\n  CPU Util (%)       : 12                          Free    : 85,214,308\n",
        "show interfaces brief": "\n  Port   Type      | Alert     Enabled Status Mode\n  ------ --------- + --------- ------- ------ ----\n  1      100/1000T | No        Yes     Up     1000FDx\n  2      100/1000T | No        Yes     Down    1000FDx\n  A1     SFP+SR    | No        Yes     Up     10GigFD\n"}
SB, SBG, SO, SOG = "show ip bgp summary", "show ip bgp general", "show ip ospf neighbor", "show ip ospf general"

print("== AOS-S: reading the screens")
check("BGP: both peers with their state", H.aoss_bgp_peers(S_BGP) == [("2.2.2.2", "Established"), ("3.1.1.2", "Established")], H.aoss_bgp_peers(S_BGP))
check("BGP: a peer stopped by an admin is left out", H.aoss_bgp_peers(S_BGP.replace("Established  Start\n3.1.1.2", "Idle         Stop\n3.1.1.2")) == [("3.1.1.2", "Established")])
check("BGP: no rows, nothing read", H.aoss_bgp_peers(S_BGP_EMPTY) == [] and H.aoss_bgp_peers("Invalid input: bgp") == [])
check("OSPF: both neighbors with their state", H.aoss_ospf_neighbors(S_OSPF) == [("10.0.8.34", "FULL"), ("10.3.53.38", "FULL")], H.aoss_ospf_neighbors(S_OSPF))
blank = S_OSPF.replace("10.3.53.38     DR        FULL", "10.3.53.38               2WAY")   # NbIfState is blank for a neighbor that is neither DR nor BDR
check("OSPF: a neighbor with a blank NbIfState is read too", H.aoss_ospf_neighbors(blank) == [("10.0.8.34", "FULL"), ("10.3.53.38", "2WAY")], H.aoss_ospf_neighbors(blank))
check("OSPF: no rows, nothing read", H.aoss_ospf_neighbors(S_OSPF_EMPTY) == [] and H.aoss_ospf_neighbors("Invalid input: ospf") == [])

print("== AOS-S: the rows of a run")
P = "aruba_osswitch"
r = ssh_run("hpe", AOSS, platform=P)
check("a switch that does not know the commands: both not configured (N/A)", r["bgp"].status == "N/A" and r["ospf"].status == "N/A" and r["ospf"].value == "not configured", show(r, "bgp", "ospf"))
check("the other rows are still there", r["cpu"].value == "12%" and r["interfaces"].value == "2/3 up" and list(r) == ["cpu", "memory", "uptime", "interfaces", "bgp", "ospf", "environment"], list(r))
r = ssh_run("hpe", {**AOSS, SB: S_BGP_EMPTY, SBG: "", SO: S_OSPF_EMPTY, SOG: S_OSPF_GENERAL.replace("enabled", "disabled")}, platform=P)
check("commands known, protocols off: N/A", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", show(r, "bgp", "ospf"))
r = ssh_run("hpe", {**AOSS, SB: S_BGP_EMPTY, SBG: S_BGP_GENERAL, SO: S_OSPF_EMPTY, SOG: S_OSPF_GENERAL}, platform=P)
check("running with no neighbors: WARN", r["bgp"].status == "WARN" and "BGP is running" in r["bgp"].message and r["ospf"].status == "WARN" and r["ospf"].value == "no neighbors", show(r, "bgp", "ospf"))
r = ssh_run("hpe", {**AOSS, SB: S_BGP, SO: S_OSPF}, platform=P)
check("all up: OK", r["bgp"].status == "OK" and r["bgp"].value == "2/2 established" and r["ospf"].status == "OK" and r["ospf"].value == "2/2 established", show(r, "bgp", "ospf"))
check("neighbors found: neither protocol is asked a second time", SBG not in SENT and SOG not in SENT, SENT)
r = ssh_run("hpe", {**AOSS, SB: S_BGP.replace("3.1.1.2        65008     65009    Established", "3.1.1.2        65008     65009    Active     "),
                    SO: S_OSPF.replace("10.3.53.38     DR        FULL  ", "10.3.53.38     DR        EXSTART")}, platform=P)
check("one BGP peer down: FAIL, named", r["bgp"].status == "FAIL" and r["bgp"].value == "1/2 established" and r["bgp"].message == "down: 3.1.1.2", show(r, "bgp"))
check("one OSPF neighbor not Full: FAIL, named with its state", r["ospf"].status == "FAIL" and r["ospf"].value == "1/2 established" and r["ospf"].message == "down: 10.3.53.38 (EXSTART)", show(r, "ospf"))
r = ssh_run("hpe", {**AOSS, SO: blank}, platform=P)
check("2-Way with a router that is neither DR nor BDR is fine", r["ospf"].status == "OK" and r["ospf"].value == "2/2 established", show(r, "ospf"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
