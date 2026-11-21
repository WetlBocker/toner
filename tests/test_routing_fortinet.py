# Run directly (python tests/test_routing_fortinet.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; the firewall is a stand-in (no network).
# FortiGate BGP and OSPF neighbours, read from the FortiOS REST API. The paths are Fortinet's own; the reply fields are not published
# outside Fortinet's developer network (login), so the samples follow replies captured from real units by others (source beside each).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rtfg%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingrtfg%d" % int(time.time()))
from core import db
db.init()
import drivers.fortinet as FG
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5}

# Paths: router/bgp/neighbors, router/bgp/neighbors6 and router/ospf/neighbors are in Fortinet's own Ansible collection
# https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/blob/main/plugins/modules/fortios_monitor_fact.py
# and named by Fortinet staff in https://community.fortinet.com/t5/Support-Forum/How-to-query-BGP-Community-information-via-SNMP-or-REST-API/m-p/354959
# Reply of GET /api/v2/monitor/router/bgp/neighbors on v7.0.0 (not Fortinet's documentation: a captured reply)
# https://github.com/prometheus-community/fortigate_exporter/blob/main/pkg/probe/testdata/router-bgp-neighbors-v4.jsonnet
BGP = [{"neighbor_ip": "10.0.0.1", "local_ip": "10.0.0.0", "remote_as": "1337", "admin_status": True, "state": "Established", "type": "ipv4"},
       {"neighbor_ip": "10.0.0.2", "local_ip": "10.0.0.0", "remote_as": "1337", "admin_status": True, "state": "Active", "type": "ipv4"}]
BGP6 = [{"neighbor_ip": "fd00::5", "local_ip": "fd00::1", "remote_as": "1337", "admin_status": True, "state": "Established", "type": "ipv6"},
        {"neighbor_ip": "fd00::7", "local_ip": "fd00::1", "remote_as": "1337", "admin_status": True, "state": "Connect", "type": "ipv6"}]
# Reply of GET /api/v2/monitor/router/ospf/neighbors, one neighbour per state FortiOS names (not Fortinet's documentation: a captured reply)
# https://github.com/prometheus-community/fortigate_exporter/blob/main/pkg/probe/testdata/router-ospf-neighbors.jsonnet
OSPF = [{"neighbor_ip": "10.0.0.%d" % n, "priority": 3, "state": s, "router_id": "1234%d" % n}
        for n, s in enumerate(("Down", "Attempt", "Init", "Two way", "Exchange start", "Exchange", "Loading", "Full"), 1)]
# GET /api/v2/cmdb/router/bgp and .../router/ospf answer "config router bgp" / "config router ospf": as (0 disables BGP), router-id (default 0.0.0.0)
# https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/528620/config-router-bgp
# https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/526620/config-router-ospf
BGP_OFF, BGP_ON = {"as": "0", "router-id": "0.0.0.0", "neighbor": []}, {"as": "65001", "router-id": "1.1.1.1", "neighbor": [{"ip": "10.0.0.1", "remote-as": "1337"}]}
OSPF_OFF, OSPF_ON = {"router-id": "0.0.0.0", "area": [], "network": []}, {"router-id": "1.1.1.1", "area": [{"id": "0.0.0.0"}], "network": [{"id": 1, "prefix": "10.0.0.0 255.255.255.0", "area": "0.0.0.0"}]}

print("== the readers, on the API's answers")
check("BGP: both peers counted, the one that is not Established named by its address", FG.bgp_neighbors(BGP) == (2, ["10.0.0.2"]), FG.bgp_neighbors(BGP))
check("BGP: all Established, whatever the case", FG.bgp_neighbors([BGP[0], {**BGP6[0], "state": "ESTABLISHED"}]) == (2, []))
check("BGP: IPv4 and IPv6 lists joined, a peer in both counted once", FG.bgp_neighbors(BGP + BGP6 + BGP6) == (4, ["10.0.0.2", "fd00::7"]), FG.bgp_neighbors(BGP + BGP6 + BGP6))
check("BGP: nothing, or something that is not a list of peers, is no peers", FG.bgp_neighbors([]) == (0, []) and FG.bgp_neighbors(None) == (0, []) and FG.bgp_neighbors({"x": 1}) == (0, []) and FG.bgp_neighbors(["x", {}]) == (0, []))
total, down = FG.ospf_neighbors(OSPF)
check("OSPF: Full is up, and so is Two way (a neighbour that is neither DR nor BDR stays there)", total == 8 and len(down) == 6 and not [d for d in down if "Full" in d or "Two way" in d], down)
check("OSPF: the others are named by router ID with their state", down[:3] == ["12341 (Down)", "12342 (Attempt)", "12343 (Init)"] and "12345 (Exchange start)" in down, down)
check("OSPF: the command line's spellings read the same", FG.ospf_neighbors([{"router_id": "1.1.1.1", "state": "Full/DR"}, {"router_id": "2.2.2.2", "state": "2-Way/DROther"}, {"router_id": "3.3.3.3", "state": "ExStart/BDR"}]) == (3, ["3.3.3.3 (ExStart/BDR)"]))
check("OSPF: no router ID: the neighbour's address names it", FG.ospf_neighbors([{"neighbor_ip": "10.0.0.3", "state": "Init"}]) == (1, ["10.0.0.3 (Init)"]))
check("OSPF: nothing is no neighbours", FG.ospf_neighbors([]) == (0, []) and FG.ospf_neighbors(None) == (0, []) and FG.ospf_neighbors(["x", {}]) == (0, []))
check("BGP is on when the router has an AS", FG.bgp_running(BGP_ON) and FG.bgp_running({"as": 65001}) and FG.bgp_running({"as": "65000.1"}) and FG.bgp_running([BGP_ON]))
check("...and off with AS 0, no AS, or no answer", not any(FG.bgp_running(c) for c in (BGP_OFF, {"as": 0}, {"as": ""}, {}, None, [], "x")))
check("OSPF is on with a router ID, or with an area or a network", FG.ospf_running(OSPF_ON) and FG.ospf_running({"router-id": "1.1.1.1"}) and FG.ospf_running({**OSPF_OFF, "area": [{"id": "0.0.0.0"}]}) and FG.ospf_running([OSPF_ON]))
check("...and off with router ID 0.0.0.0 and nothing else, or no answer", not any(FG.ospf_running(c) for c in (OSPF_OFF, {}, None, [], "x")))

print("== the driver, against a stand-in FortiGate")
class Resp:
    def __init__(self, status=200, js=None):
        self.status_code, self._js, self.headers = status, js, {}
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests; e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
    def json(self): return self._js
BASE = {"system/resource/usage?scope=global": {"cpu": [{"current": 10}], "mem": [{"current": 30}]}, "system/status": {"hostname": "fw"},
        "system/interface?scope=global": {"port1": {"type": "physical", "link": True, "role": "lan"}}, "system/ha-peer": [], "vpn/ipsec": []}
MONITOR, CMDB, CODES, CALLS = {}, {}, {}, []
def fg_get(url, headers=None, **kw):
    api, path = url.split("/api/v2/", 1)[1].split("/", 1)
    CALLS.append(f"{api}/{path}")
    if f"{api}/{path}" in CODES: return Resp(status=CODES[f"{api}/{path}"])
    data = {**BASE, **MONITOR} if api == "monitor" else CMDB
    if path in data: return Resp(js={"http_method": "GET", "results": data[path], "vdom": "root", "status": "success", "http_status": 200, "serial": "FGVM000000000001", "version": "v7.4.0", "build": 2360})   # (the envelope FortiOS answers with)
    return Resp(status=404)
FG.requests.get = fg_get
def run(monitor=None, cmdb=None, codes=None, disabled=()):
    MONITOR.clear(); MONITOR.update(monitor or {}); CMDB.clear(); CMDB.update(cmdb or {}); CODES.clear(); CODES.update(codes or {}); CALLS.clear()
    d = {"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "TOK"}
    return {r.check: r for r in DRIVERS["fortinet"](d, TH, {**OPTS, "disabled": set(disabled)}).run()}
row = lambda r: (r.status, r.value, r.message)
EMPTY = {"router/bgp/neighbors": [], "router/bgp/neighbors6": [], "router/ospf/neighbors": []}
NOT_BGP, NOT_OSPF = ("N/A", "not configured", "BGP is not configured on this device"), ("N/A", "not configured", "OSPF is not configured on this device")

r = run(EMPTY, {"router/bgp": BGP_OFF, "router/ospf": OSPF_OFF})
check("not configured: empty lists and a configuration that is off give the N/A rows", row(r["bgp"]) == NOT_BGP and row(r["ospf"]) == NOT_OSPF, (r.get("bgp"), r.get("ospf")))
check("the rest of the run is as before, with nothing in error", {"cpu", "memory", "firmware", "wan links", "ha", "interfaces"} <= set(r) and not [k for k, v in r.items() if v.status == "ERROR"], {k: v.status for k, v in r.items()})
r = run()
check("not configured: a firewall that answers 404 to all of it gets the N/A rows too, not an error", row(r["bgp"]) == NOT_BGP and row(r["ospf"]) == NOT_OSPF, (r.get("bgp"), r.get("ospf")))
r = run(None, {"router/bgp": BGP_OFF, "router/ospf": OSPF_OFF}, {"monitor/router/bgp/neighbors": 500, "monitor/router/bgp/neighbors6": 500, "monitor/router/ospf/neighbors": 500})
check("not configured: FortiOS 7.4.9 answers 500 where there are no neighbours, and that is still N/A", row(r["bgp"]) == NOT_BGP and row(r["ospf"]) == NOT_OSPF, (r.get("bgp"), r.get("ospf")))

r = run(EMPTY, {"router/bgp": BGP_ON, "router/ospf": OSPF_ON})
check("configured with no neighbours: BGP warns", row(r["bgp"]) == ("WARN", "no neighbors", "BGP is running but has no neighbors") and r["bgp"].numeric == 0.0, r.get("bgp"))
check("configured with no neighbours: OSPF warns", row(r["ospf"]) == ("WARN", "no neighbors", "OSPF is running but has no neighbors"), r.get("ospf"))
r = run(None, {"router/bgp": BGP_ON, "router/ospf": OSPF_ON}, {"monitor/router/bgp/neighbors": 500, "monitor/router/bgp/neighbors6": 500, "monitor/router/ospf/neighbors": 500})
check("...and the same when the empty list comes as a 500", r["bgp"].value == "no neighbors" and r["ospf"].value == "no neighbors", (r.get("bgp"), r.get("ospf")))

r = run({"router/bgp/neighbors": [BGP[0]], "router/bgp/neighbors6": [BGP6[0]], "router/ospf/neighbors": [OSPF[7], OSPF[3]]})
check("all up: BGP is OK, IPv6 peers counted with the IPv4 ones", row(r["bgp"]) == ("OK", "2/2 established", "") and r["bgp"].numeric == 2.0, r.get("bgp"))
check("all up: OSPF is OK, Two way counted as up", row(r["ospf"]) == ("OK", "2/2 established", "") and r["ospf"].numeric == 2.0, r.get("ospf"))
check("with neighbours there, the configuration is not asked for", not [c for c in CALLS if c.startswith("cmdb/")], CALLS)
check("the calls are the documented ones, in the token's own VDOM (no vdom or scope asked)", {"monitor/router/bgp/neighbors", "monitor/router/bgp/neighbors6", "monitor/router/ospf/neighbors"} <= set(CALLS), CALLS)

r = run({"router/bgp/neighbors": BGP, "router/ospf/neighbors": [OSPF[7], OSPF[3], OSPF[2]]})
check("one down: BGP fails and names it (no IPv6 endpoint on this one: no matter)", row(r["bgp"]) == ("FAIL", "1/2 established", "down: 10.0.0.2") and r["bgp"].numeric == 1.0, r.get("bgp"))
check("one down: OSPF fails and names it with its state", row(r["ospf"]) == ("FAIL", "2/3 established", "down: 12343 (Init)") and r["ospf"].numeric == 2.0, r.get("ospf"))

r = run(None, {"router/bgp": BGP_ON, "router/ospf": OSPF_ON})
check("configured, but this FortiOS has no such list (before 7.0): the row says the API's answer, not 'no neighbors'",
      r["bgp"].status == "ERROR" and "404" in r["bgp"].message and r["ospf"].status == "ERROR" and "404" in r["ospf"].message, (r.get("bgp"), r.get("ospf")))
r = run(EMPTY, {"router/bgp": BGP_ON, "router/ospf": OSPF_ON}, {"cmdb/router/bgp": 403, "cmdb/router/ospf": 403})
check("a token that may not read the configuration: no neighbours reads as not configured, not as an error", row(r["bgp"]) == NOT_BGP and row(r["ospf"]) == NOT_OSPF, (r.get("bgp"), r.get("ospf")))
r = run({"router/bgp/neighbors": BGP, "router/ospf/neighbors": OSPF}, disabled=("fortinet:bgp",))
check("switched off in Settings: no row and no call; the other one still runs", "bgp" not in r and not [c for c in CALLS if "router/bgp" in c] and r["ospf"].value == "2/8 established", (list(r), CALLS))

print("== uptime, from web-ui/state (snapshot_utc_time and utc_last_reboot: milliseconds on FortiOS 8.0.0; seconds are still read)")
from core import checks
check("Fortinet lists the uptime check, with the label the other vendors use", ("uptime", "Uptime and recent reboots") in checks.CATALOG["fortinet"])
T0 = 1_700_000_000
r = run({"web-ui/state": {"snapshot_utc_time": (T0 + 90 * 3600) * 1000, "utc_last_reboot": T0 * 1000}})
check("milliseconds: 90 hours up is OK, shown like the others", "uptime" in r and row(r["uptime"]) == ("OK", "3:18:00:00", "") and abs(r["uptime"].numeric - 90) < 1e-6, r.get("uptime"))
r = run({"web-ui/state": {"snapshot_utc_time": T0 + 1800, "utc_last_reboot": T0}})
# the two values a FortiGate VM on FortiOS v8.0.0 (build 167) returned on 2026-11-21, while its CLI said "Uptime: 31 days,  4 hours"
r_real = run({"web-ui/state": {"model": "FGVM64", "snapshot_utc_time": 1795243719000, "utc_last_reboot": 1792550067000, "time_zone_offset": 360, "ha_mode": 0}})
check("a real FortiOS 8.0.0 reply: 31 days and 4 hours up, as its own CLI reports", "uptime" in r_real and row(r_real["uptime"]) == ("OK", "31:04:14:12", "")
      and abs(r_real["uptime"].numeric - 2693652 / 3600) < 1e-6, r_real.get("uptime"))
check("seconds: half an hour up is a recent reboot", "uptime" in r and row(r["uptime"])[0] == "WARN" and r["uptime"].message == "recent reboot" and abs(r["uptime"].numeric - 0.5) < 1e-6, r.get("uptime"))
r = run({"web-ui/state": {"utc_last_reboot": T0}})
check("a reply without the snapshot time gives no uptime row and no error", "web-ui/state" in " ".join(CALLS) and "uptime" not in r and not [k for k, v in r.items() if v.status == "ERROR"], list(r))
for bad_boot in (0, -5):
    r = run({"web-ui/state": {"snapshot_utc_time": T0, "utc_last_reboot": bad_boot}})
    check(f"a utc_last_reboot of {bad_boot} gives no uptime row", "web-ui/state" in " ".join(CALLS) and "uptime" not in r, r.get("uptime"))
r = run({"web-ui/state": {"snapshot_utc_time": "x", "utc_last_reboot": None}})
check("fields that are not numbers give no row either", "web-ui/state" in " ".join(CALLS) and "uptime" not in r)
r = run(codes={"monitor/web-ui/state": 404})
check("a FortiOS without the call gives no row", "monitor/web-ui/state" in CALLS and "uptime" not in r)
r = run({"web-ui/state": {"snapshot_utc_time": T0 + 7200, "utc_last_reboot": T0}}, disabled=("fortinet:uptime",))
off_calls = list(CALLS)
r2 = run({"web-ui/state": {"snapshot_utc_time": T0 + 7200, "utc_last_reboot": T0}})
check("switched off in Settings: no row and no call (the same reply, ticked, gives the row)", "uptime" in r2 and "uptime" not in r and "monitor/web-ui/state" not in off_calls, off_calls)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
