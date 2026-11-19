# Run directly (python tests/test_routing_extreme.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# BGP and OSPF neighbours on Extreme Networks switches (Switch Engine / EXOS and Fabric Engine / VOSS). The sample outputs are the
# ones Extreme's own guides print (the address is beside each); where a sample was changed to make a case the guides do not show,
# the comment says so.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rext%d.db" % int(time.time()))
from core import db
db.init()
from drivers import DRIVERS
import drivers.extreme as X

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.thresholds_for({"name": "x", "vendor": "extreme", "location": ""})
OPTS = {**db.runtime_options()}

class Conn:
    def __init__(self, table): self.t = table; self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        return self.t.get(cmd, "%% Invalid input detected at '^' marker.")

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

DOC = "https://documentation.extremenetworks.com/Switch%20Engine%20v33.1.1%20Command%20References/"
# ---------------------------------------------------------------- Switch Engine / EXOS
# DOC + GUID-713161F1-3F0D-4ABC-BCD4-3419EAE5C861.shtml  (show bgp neighbor; "ESTABLISEHD" is the guide's own misprint)
E_BGP = """Peer                AS    Weight      State        InMsgs OutMsgs(InQ)  Up/Down
-------------------------------------------------------------------------------
Ie-- 11.0.0.2       100   0           OPENSENT     0      9      (0    ) 0:8:27:21
Ie-- 3001::1        100   0           ESTABLISEHD  4      3      (0    ) 0:8:27:21
Flags:  (d) disabled, (e) enabled, (E) external peer, (I) internal peer
        (m) EBGP multihop, (r) route reflector client
BGP Peer Statistics
Total Peers      : 2
EBGP Peers       : 0
IBGP Peers       : 2
RR Client        : 0
EBGP Multihop    : 0
Enabled          : 2
Disabled         : 0
"""
# The same page: two peers an admin has disabled (the d flag).
E_BGP_DISABLED = """     Peer                                    AS         Weight State        InMsgs OutMsgs(InQ)  Up/Down
------------------------------------------------------------------------------------------------------------
Id-- 10.1.1.1                                10         1      IDLE         0      0     (0    ) 0:0:13:53
Id-- 20.1.1.1                                10         1      IDLE         0      0     (0    ) 0:0:00:07
Flags: (d) disabled, (e) enabled, (E) external peer, (I) internal peer
"""
E_BGP_UP = E_BGP.replace("OPENSENT   ", "ESTABLISHED")                      # both peers up, spelled as the peer's own screen spells it
# DOC + GUID-8F82D6A2-348F-4A4F-9D33-9CE9DAA0147B.shtml  (show bgp)
E_BGP_GLOBAL = """Enabled             : No                OperStatus          : Down
RouterId            : 3.3.3.3           AS                  : 200
LocalPref           : 100               MED                 : None
"""
E_BGP_GLOBAL_ON = E_BGP_GLOBAL.replace(": No ", ": Yes").replace(": Down", ": Up  ")   # switched on: the guide shows it off
# DOC + GUID-4B109146-3A92-4476-9168-B2895E4F3039.shtml  (show ospf neighbor)
E_OSPF = """Neighbor ID     Pri State              Up/Dead Time             Address      Interface
          BFD Session State
=========================================================================================
160.26.26.2      10 FULL      /BDR     10:16:42:57/00:00:00:00  160.26.26.2   CHI_160_26_26
          Disabled
10.0.2.2         10 FULL      /BDR     07:17:55:29/00:00:00:09  10.0.2.2      HQ_10_0_2
          Active
10.0.3.2         10 FULL      /BDR     07:17:54:56/00:00:00:03  10.0.3.2      HQ_10_0_3
          Error (Session Limit Exceeded)
Total number of neighbors: 3 (All neighbors in Full state)
"""
# DOC + GUID-44C277E3-456D-4DE4-A998-473B7B0101C2.shtml  (show ospf)
E_OSPF_GLOBAL = """OSPF                : Disabled         MPLS LSP as Next-Hop: No
RouterId            : 0.0.0.0          RouterId Selection  : Automatic
InstanceId          : 22
ASBR                : No               ABR                 : No
"""
E_OSPF_GLOBAL_ON = E_OSPF_GLOBAL.replace("Disabled", "Enabled ")            # switched on: the guide shows it off
# The base screens of a whole run, as in tests/test_newvendors.py.
EXOS = {"show version": "Switch      : 800516-00-05 1234 Rev 5.0 BootROM: 1.0.4.0    IMG: 31.7.1.4\nImage   : ExtremeXOS version 31.7.1.4 by release-manager\n",
        "show switch": "SysName:          core-sw\nSystem UpTime:    12 days 3 hours 4 minutes 5 seconds\n",
        "show cpu-monitoring": "CPU Utilization Statistics - Monitored every 5 seconds\nProcess      5   10   30   60   90  120  180  240  300  600  Max\n-----\nSystem      4.2  4.0  3.9  3.8  3.8  3.7  3.7  3.7  3.6  3.6  12.1\naaa         0.0  0.0\n",
        "show memory": "System Memory Information\nTotal DRAM (KB): 2097152\nSystem      (KB): 400000\nUser        (KB): 600000\nFree        (KB): 1097152\n",
        "show ports no-refresh": "Port   Display String   VLAN Name   Port  Link  Speed  Duplex\n                                    State State Actual Actual\n1                       Default     E     A     1000   FULL\n2                       Default     E     R\n3                       Default     D     R\n",
        "show fans": "FanTray-1 information:\n State:   Operational\nFan-1 operational at 3000 RPM\nFan-2 operational at 3000 RPM\n",
        "show power": "PowerSupply 1 information:\n State             : Powered On\nPowerSupply 2 information:\n State             : Empty\n"}
EB, EBG, EO, EOG = "show bgp neighbor", "show bgp", "show ospf neighbor", "show ospf"

print("== EXOS: reading the screens")
check("BGP: both peers (one IPv6) with their state", X.exos_bgp_peers(E_BGP) == [("11.0.0.2", "OPENSENT"), ("3001::1", "ESTABLISEHD")], X.exos_bgp_peers(E_BGP))
check("BGP: peers disabled by an admin are left out", X.exos_bgp_peers(E_BGP_DISABLED) == [] and X.exos_bgp_peers(E_BGP_DISABLED.replace("Id-- 20", "Ee-- 20")) == [("20.1.1.1", "IDLE")])
check("BGP: no rows, nothing read", X.exos_bgp_peers("%% Invalid input detected at '^' marker.") == [] and X.exos_bgp_peers("") == [])
check("OSPF: the three neighbors, the state without the /BDR part, the BFD lines skipped", X.exos_ospf_neighbors(E_OSPF) == [("160.26.26.2", "FULL"), ("10.0.2.2", "FULL"), ("10.0.3.2", "FULL")], X.exos_ospf_neighbors(E_OSPF))
check("OSPF: no rows, nothing read", X.exos_ospf_neighbors("%% Invalid input detected at '^' marker.") == [] and X.exos_ospf_neighbors("") == [])
check("Full and 2-Way are adjacent however they are spelled, the rest are not", all(X.clichecks.adjacent(s) for s in ("FULL", "Full", "2WAY", "2 Way", "TwoWay"))
      and not any(X.clichecks.adjacent(s) for s in ("INIT", "EX_START", "EXCHANGE", "LOADING", "Restart", "Down")))

print("== EXOS: the rows of a run")
r = ssh_run("extreme", EXOS)
check("a switch that does not know the commands: both not configured (N/A)", r["bgp"].status == "N/A" and r["ospf"].status == "N/A" and r["bgp"].value == "not configured", show(r, "bgp", "ospf"))
check("the other rows are still there", r["cpu"].value == "4%" and r["interfaces"].value == "1/2 up" and list(r) == ["cpu", "memory", "uptime", "interfaces", "bgp", "ospf", "environment"], list(r))
r = ssh_run("extreme", {**EXOS, EB: "", EBG: E_BGP_GLOBAL, EO: "", EOG: E_OSPF_GLOBAL})
check("commands known, protocols off: N/A", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", show(r, "bgp", "ospf"))
r = ssh_run("extreme", {**EXOS, EB: E_BGP_DISABLED, EBG: E_BGP_GLOBAL_ON, EO: "", EOG: E_OSPF_GLOBAL_ON})
check("running with no neighbors: WARN", r["bgp"].status == "WARN" and r["bgp"].value == "no neighbors" and r["ospf"].status == "WARN" and "OSPF is running" in r["ospf"].message, show(r, "bgp", "ospf"))
r = ssh_run("extreme", {**EXOS, EB: E_BGP_UP, EO: E_OSPF})
check("all up: OK", r["bgp"].status == "OK" and r["bgp"].value == "2/2 established" and r["ospf"].status == "OK" and r["ospf"].value == "3/3 established" and r["ospf"].numeric == 3, show(r, "bgp", "ospf"))
check("neighbors found: neither protocol is asked a second time", EBG not in SENT and EOG not in SENT, SENT)
r = ssh_run("extreme", {**EXOS, EB: E_BGP, EO: E_OSPF.replace("10.0.2.2         10 FULL      /BDR", "10.0.2.2         10 EX_START  /BDR").replace("10.0.3.2         10 FULL      /BDR", "10.0.3.2         10 2WAY      /DROTHER")})
check("one BGP peer down: FAIL, named; the guide's misprinted ESTABLISHED still counts as up", r["bgp"].status == "FAIL" and r["bgp"].value == "1/2 established" and r["bgp"].message == "down: 11.0.0.2", show(r, "bgp"))
check("one OSPF neighbor not Full: FAIL, named with its state; 2-Way is fine", r["ospf"].status == "FAIL" and r["ospf"].value == "2/3 established" and r["ospf"].message == "down: 10.0.2.2 (EX_START)", show(r, "ospf"))

# ---------------------------------------------------------------- Fabric Engine / VOSS
VDOC = "https://documentation.extremenetworks.com/Fabric%20Engine%20v9.1%20User%20Guide/"
# VDOC + GUID-EE02A2AD-ECBE-421F-A587-4DAF3ED917DF.shtml  (show ip bgp summary)
V_BGP = """====================================================================================================
                           BGP Summary - VRF vrf1
====================================================================================================
                                     BGP version - 4
                                        local-as - 22610
                                      Identifier - 27.82.217.1
                                  Decision state - Idle
                   The total number of routes is   0
BGP NEIGHBOR INFO :
   NEIGHBOR       RMTAS     STATE    HLDTM  KPALV  HLDCFG KPCFG   WGHT  CONRTY ADVINT UPTime
----------------------------------------------------------------------------------------------------
192.0.2.1        22620      Active      0     0     180    60    100   120    5     0 day(s), 07:25:09
Total bgp neighbors: 1
BGP CONFEDERATION INFO :
confederation identifier 0
confederation peer as
"""
V_BGP_EMPTY = V_BGP.replace("192.0.2.1        22620      Active      0     0     180    60    100   120    5     0 day(s), 07:25:09\n", "").replace("neighbors: 1", "neighbors: 0")   # not in the guide
# The state of an established peer is spelled as on the neighbor's own screen ("BGP state [Established]",
# VDOC + GUID-6456100B-EAA6-4BFC-8F1E-91092437EE98.shtml); the second row is added here.
V_BGP_UP = V_BGP.replace("Active     ", "Established").replace("Total bgp", "192.0.2.9        22620      Established 30    10     180    60    100   120    5     3 day(s), 01:02:03\nTotal bgp")
# VDOC + GUID-078B889E-3F4C-41A8-9180-F28151208FA1.shtml  (show ip bgp conf)
V_BGP_CONF = """================================================================================
                        BGP Configuration - VRF vrf1
================================================================================
                                     BGP version - 4
                                        local-as - 22610
                                      Identifier - 27.82.217.1
                                      BGP on/off - ON
                                       as-4-byte - disable
"""
# VDOC + GUID-7E890D6C-1BAF-4A80-BC1E-4E30A254A997.shtml  (show ip ospf neighbor)
V_OSPF = """================================================================================
                         OSPF Neighbors - GlobalRouter
================================================================================
INTERFACE       NBRROUTERID     NBRIPADDR       PRIO_STATE    RTXQLEN PERM TTL
--------------------------------------------------------------------------------
192.0.2.5       192.0.2.1       192.0.2.6       1    Full     0       Dyn   31
198.51.100.7    198.51.100.1    198.51.100.8    128  Restart  0       Dyn   147 H
Total ospf neighbors: 2
H = Helping a Restarting neighbor
"""
V_OSPF_EMPTY = "\n".join(l for l in V_OSPF.splitlines() if "Dyn" not in l).replace("neighbors: 2", "neighbors: 0")   # not in the guide
# VDOC + GUID-CED96278-3291-4329-A447-FF4B0FC45833.shtml  (show ip ospf)
V_OSPF_GLOBAL = """================================================================================
                          OSPF General - GlobalRouter
================================================================================
            RouterId: 192.0.2.2
           AdminStat: disabled
       VersionNumber: 2
"""
V_OSPF_GLOBAL_ON = V_OSPF_GLOBAL.replace("disabled", "enabled")            # switched on: the guide shows it off
# The base screens of a whole run, as in tests/test_newvendors.py.
VOSS = {"show sys-info": "SysDescr : VSP-7432CQ (8.10.1.0) BoxType: VSP-7400\nSysUpTime : 3 day(s), 04:05:06\nSysName : fabric-1\n",
        "show khi performance cpu": "CPU Utilization\n  Cpu-Utilization Percent : 9\n",
        "show khi performance memory": "Memory Utilization\n  Used : 1500 MB\n  Free : 2500 MB\n",
        "show interfaces gigabitEthernet": "PORT  LINK  PORT    PHYSICAL  STATUS\nNUM   TRAP  LOCK    ADDRESS   \n1/1   true  false   aa:bb     up\n1/2   true  false   aa:bc     down\n"}
VB, VBG, VO, VOG = "show ip bgp summary", "show ip bgp conf", "show ip ospf neighbor", "show ip ospf"
P = "extreme_vsp"

print("== VOSS: reading the screens")
check("BGP: the neighbor with its state", X.voss_bgp_peers(V_BGP) == [("192.0.2.1", "Active")], X.voss_bgp_peers(V_BGP))
check("BGP: no rows, nothing read (the Identifier line is not a neighbor)", X.voss_bgp_peers(V_BGP_EMPTY) == [] and X.voss_bgp_peers("") == [])
check("OSPF: the neighbors by router ID with their state", X.voss_ospf_neighbors(V_OSPF) == [("192.0.2.1", "Full"), ("198.51.100.1", "Restart")], X.voss_ospf_neighbors(V_OSPF))
check("OSPF: a state of two words is read whole", X.voss_ospf_neighbors(V_OSPF.replace("Full   ", "2 Way  "))[0] == ("192.0.2.1", "2 Way"))
check("OSPF: no rows, nothing read", X.voss_ospf_neighbors(V_OSPF_EMPTY) == [] and X.voss_ospf_neighbors("") == [])

print("== VOSS: the rows of a run")
r = ssh_run("extreme", VOSS, platform=P)
check("a switch that does not know the commands: both not configured (N/A)", r["bgp"].status == "N/A" and r["ospf"].status == "N/A" and r["ospf"].value == "not configured", show(r, "bgp", "ospf"))
check("the other rows are still there", r["cpu"].value == "9%" and r["interfaces"].status == "FAIL" and list(r) == ["cpu", "memory", "uptime", "interfaces", "bgp", "ospf"], list(r))
r = ssh_run("extreme", {**VOSS, VB: V_BGP_EMPTY, VBG: V_BGP_CONF.replace("- ON", "- OFF"), VO: V_OSPF_EMPTY, VOG: V_OSPF_GLOBAL}, platform=P)
check("commands known, protocols off: N/A", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", show(r, "bgp", "ospf"))
r = ssh_run("extreme", {**VOSS, VB: V_BGP_EMPTY, VBG: V_BGP_CONF, VO: V_OSPF_EMPTY, VOG: V_OSPF_GLOBAL_ON}, platform=P)
check("running with no neighbors: WARN", r["bgp"].status == "WARN" and "BGP is running" in r["bgp"].message and r["ospf"].status == "WARN" and r["ospf"].value == "no neighbors", show(r, "bgp", "ospf"))
r = ssh_run("extreme", {**VOSS, VB: V_BGP_UP, VO: V_OSPF.replace("Restart", "Full   ")}, platform=P)
check("all up: OK", r["bgp"].status == "OK" and r["bgp"].value == "2/2 established" and r["ospf"].status == "OK" and r["ospf"].value == "2/2 established", show(r, "bgp", "ospf"))
check("neighbors found: neither protocol is asked a second time", VBG not in SENT and VOG not in SENT, SENT)
r = ssh_run("extreme", {**VOSS, VB: V_BGP_UP.replace("192.0.2.9        22620      Established", "192.0.2.9        22620      Idle       "), VO: V_OSPF}, platform=P)
check("one BGP neighbor down: FAIL, named", r["bgp"].status == "FAIL" and r["bgp"].value == "1/2 established" and r["bgp"].message == "down: 192.0.2.9", show(r, "bgp"))
check("one OSPF neighbor not Full: FAIL, named with its state", r["ospf"].status == "FAIL" and r["ospf"].value == "1/2 established" and r["ospf"].message == "down: 198.51.100.1 (Restart)", show(r, "ospf"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
