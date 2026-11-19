# Run directly (python tests/test_routing_opnsense.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; the firewall is a stand-in (no network).
# OPNsense BGP and OSPF neighbours, read from the FRR plugin (os-frr; its API controller is still named "quagga"). The paths are in OPNsense's
# API reference and the plugin's source; the replies are FRR's own JSON, whose keys FRR documents nowhere but in its source (beside each sample).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
from urllib.parse import urlparse
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rtop%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingrtop%d" % int(time.time()))
from core import db
db.init()
import requests
import drivers.restapi as RA
import drivers.opnsense as OP
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5, "counter_mode": "total"}

# GET /api/quagga/diagnostics/bgpsummary: https://docs.opnsense.org/development/api/plugins/quagga.html
# It answers {"response": <vtysh -c "show bgp summary json">}: bgpsummaryAction in
# https://github.com/opnsense/plugins/blob/master/net/frr/src/opnsense/mvc/app/controllers/OPNsense/Quagga/Api/DiagnosticsController.php
# and [diagnostics.bgp_summary] in https://github.com/opnsense/plugins/blob/master/net/frr/src/opnsense/service/conf/actions.d/actions_quagga.conf
# FRR's keys (a block per address family; routerId, as, peers by address, each with state and peerState) are those bgp_show_summary writes in
# https://github.com/FRRouting/frr/blob/master/bgpd/bgp_vty.c and FRR's own tests read (verify_bgp_convergence):
# https://github.com/FRRouting/frr/blob/master/tests/topotests/lib/bgp.py   Not a captured reply: built from those keys.
def family(**peers):
    return {"routerId": "10.0.0.1", "as": 65001, "vrfId": 0, "vrfName": "default", "tableVersion": 3,
            "peers": {a.replace("_", "."): {"remoteAs": 65002, "localAs": 65001, "version": 4, "msgRcvd": 10, "msgSent": 11, "pfxRcd": 2, "state": s, "peerState": "OK", "idType": "ipv4"} for a, s in peers.items()},
            "failedPeers": sum(s != "Established" for s in peers.values()), "displayedPeers": len(peers), "totalPeers": len(peers), "dynamicPeers": 0}
BGP_UP = {"response": {"ipv4Unicast": family(**{"10_0_0_2": "Established", "10_0_0_3": "Established"})}}
BGP_ONE_DOWN = {"response": {"ipv4Unicast": family(**{"10_0_0_2": "Established", "10_0_0_3": "Active"}), "ipv6Unicast": family(**{"10_0_0_2": "Established"})}}
BGP_NONE = {"response": []}        # no neighbors, no BGP, or bgpd not running: FRR prints {} or plain words, which the plugin turns into an empty list

# GET /api/quagga/diagnostics/search_ospfneighbor (the same page; searchOspfneighborAction): FRR's "show ip ospf neighbor json", its "neighbors"
# flattened into rows with the router ID added as "neighborid". The keys are the columns of the plugin's own page
# https://github.com/opnsense/plugins/blob/master/net/frr/src/opnsense/mvc/app/views/OPNsense/Quagga/diagnostics.volt
# and what show_ip_ospf_neighbour_brief writes in https://github.com/FRRouting/frr/blob/master/ospfd/ospf_vty.c (nbrState, converged, role, ...).
def nbr(state, role="DR"):
    return {"nbrPriority": 1, "nbrState": f"{state}/{role}", "converged": state, "role": role, "upTimeInMsec": 5000, "routerDeadIntervalTimerDueMsec": 35000, "upTime": "5.000s", "deadTime": "35.000s",
            "ifaceAddress": "10.0.0.2", "ifaceName": "igb1:10.0.0.1", "linkStateRetransmissionListCounter": 0, "linkStateRequestListCounter": 0, "databaseSummaryListCounter": 0}
def rows(*found):
    return {"rows": [{**nbr(*f[1:]), "neighborid": f[0]} for f in found], "rowCount": len(found), "total": len(found), "current": 1}
OSPF_UP = rows(("10.0.0.2", "Full", "DR"), ("10.0.0.3", "Full", "Backup"), ("10.0.0.4", "2-Way", "DROther"))
OSPF_ONE_DOWN = rows(("10.0.0.2", "Full", "DR"), ("10.0.0.3", "ExStart", "Backup"))
# The plugin up to 22.7 had GET /api/quagga/diagnostics/ospfneighbor instead, answering FRR's JSON as it is, under "response" (ospfneighborAction):
# https://github.com/opnsense/plugins/blob/stable/22.7/net/frr/src/opnsense/mvc/app/controllers/OPNsense/Quagga/Api/DiagnosticsController.php
OSPF_OLD = {"response": {"neighbors": {"10.0.0.2": [nbr("Full")], "10.0.0.3": [nbr("Init", "DROther")]}}}
# The settings: GET /api/quagga/general/get is in the API reference; bgp/get and ospfsettings/get are what the plugin's own pages load
# https://github.com/opnsense/plugins/blob/master/net/frr/src/opnsense/mvc/app/views/OPNsense/Quagga/bgp.volt (and ospf.volt)
# "enabled" is a BooleanField in General.xml, BGP.xml and OSPF.xml: https://github.com/opnsense/plugins/tree/master/net/frr/src/opnsense/mvc/app/models/OPNsense/Quagga
def settings(frr="1", bgp="1", ospf="1"):
    return {"/api/quagga/general/get": {"general": {"enabled": frr, "profile": "traditional"}}, "/api/quagga/bgp/get": {"bgp": {"enabled": bgp, "asnumber": "65001"}},
            "/api/quagga/ospfsettings/get": {"ospf": {"enabled": ospf, "routerid": "10.0.0.1"}}}

print("== the readers, on the API's answers")
check("BGP: both peers Established", OP.bgp_neighbors(BGP_UP) == (2, []), OP.bgp_neighbors(BGP_UP))
check("BGP: the one that is not Established is named; a peer in both address families counts once", OP.bgp_neighbors(BGP_ONE_DOWN) == (2, ["10.0.0.3"]), OP.bgp_neighbors(BGP_ONE_DOWN))
check("BGP: an empty answer, or none, is no neighbors", OP.bgp_neighbors(BGP_NONE) == (0, []) and OP.bgp_neighbors({"response": {}}) == (0, []) and OP.bgp_neighbors(None) == (0, []) and OP.bgp_neighbors({"response": None}) == (0, []))
check("OSPF: Full is up, and so is 2-Way (two routers that are neither DR nor BDR stay there)", OP.ospf_neighbors(OSPF_UP) == (3, []), OP.ospf_neighbors(OSPF_UP))
check("OSPF: ExStart is down, named with its state", OP.ospf_neighbors(OSPF_ONE_DOWN) == (2, ["10.0.0.3 (ExStart)"]), OP.ospf_neighbors(OSPF_ONE_DOWN))
check("OSPF: the older plugin's answer reads the same", OP.ospf_neighbors(OSPF_OLD) == (2, ["10.0.0.3 (Init)"]), OP.ospf_neighbors(OSPF_OLD))
check("OSPF: the state is read from nbrState when converged is not there", OP.ospf_neighbors({"rows": [{"neighborid": "1.1.1.1", "nbrState": "Full/DR"}, {"neighborid": "2.2.2.2", "nbrState": "Init/DROther"}]}) == (2, ["2.2.2.2 (Init)"]))
check("OSPF: an empty answer, or none, is no neighbors", OP.ospf_neighbors(rows()) == (0, []) and OP.ospf_neighbors(None) == (0, []) and OP.ospf_neighbors({"response": []}) == (0, []) and OP.ospf_neighbors({"response": None}) == (0, []))

print("== a whole run")
ROUTES, CALLS = {}, []
class Resp:
    def __init__(self, status=200, js=None): self.status_code, self._js, self.content = status, js, b"{}"
    def json(self): return self._js
    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
def fake_get(url, params=None, headers=None, auth=None, **kw):
    path = urlparse(url).path
    CALLS.append(path)
    hit = ROUTES.get(path)
    if hit is None: return Resp(404, {})
    if isinstance(hit, int): return Resp(hit, {})
    return Resp(200, hit)
RA.requests.get = fake_get
BASE = {"/api/core/firmware/status": {"status": "none", "product_version": "24.7.9"}}
BGP_PATH, OSPF_PATH, OSPF_PATH_OLD = "/api/quagga/diagnostics/bgpsummary", "/api/quagga/diagnostics/searchOspfneighbor", "/api/quagga/diagnostics/ospfneighbor"
def run(routes):
    ROUTES.clear(); ROUTES.update(BASE); ROUTES.update(routes); CALLS.clear()
    d = {"name": "box", "vendor": "opnsense", "host": "10.0.0.5", "password": "k:s", "verify_ssl": 0}
    return {r.check: (r.status, r.value, r.message) for r in DRIVERS["opnsense"](d, TH, OPTS).run()}
NA = lambda p: ("N/A", "not configured", f"{p} is not configured on this device")
QUIET = lambda p: ("WARN", "no neighbors", f"{p} is running but has no neighbors")

r = run({})
check("without the plugin (404): BGP and OSPF are N/A rows that say so", r.get("bgp") == NA("BGP") and r.get("ospf") == NA("OSPF"), (r.get("bgp"), r.get("ospf")))
check("...and the settings are not asked for", not [p for p in CALLS if p.endswith("/get")], CALLS)
check("the other rows are still there", r.get("reachability") == ("OK", "OPNsense 24.7.9", "") and "firmware" in r, r)
r = run({BGP_PATH: BGP_NONE, OSPF_PATH: rows(), **settings(bgp="0", ospf="0")})
check("the plugin with BGP and OSPF not ticked: N/A", r.get("bgp") == NA("BGP") and r.get("ospf") == NA("OSPF"), (r.get("bgp"), r.get("ospf")))
r = run({BGP_PATH: BGP_NONE, OSPF_PATH: rows(), **settings(frr="0")})
check("both ticked but FRR itself switched off: N/A", r.get("bgp") == NA("BGP") and r.get("ospf") == NA("OSPF"), (r.get("bgp"), r.get("ospf")))
r = run({BGP_PATH: BGP_NONE, OSPF_PATH: rows(), **settings()})
check("switched on with no neighbors: both warn", r.get("bgp") == QUIET("BGP") and r.get("ospf") == QUIET("OSPF"), (r.get("bgp"), r.get("ospf")))
r = run({BGP_PATH: BGP_UP, OSPF_PATH: OSPF_UP})
check("all up: OK, counted", r.get("bgp") == ("OK", "2/2 established", "") and r.get("ospf") == ("OK", "3/3 established", ""), (r.get("bgp"), r.get("ospf")))
check("...and with neighbors there the settings are not asked for", not [p for p in CALLS if p.endswith("/get")] and OSPF_PATH_OLD not in CALLS, CALLS)
r = run({BGP_PATH: BGP_ONE_DOWN, OSPF_PATH: OSPF_ONE_DOWN})
check("one down: FAIL naming it", r.get("bgp") == ("FAIL", "1/2 established", "down: 10.0.0.3") and r.get("ospf") == ("FAIL", "1/2 established", "down: 10.0.0.3 (ExStart)"), (r.get("bgp"), r.get("ospf")))
r = run({BGP_PATH: BGP_UP, OSPF_PATH_OLD: OSPF_OLD})
check("an older plugin: OSPF from its own path", r.get("ospf") == ("FAIL", "1/2 established", "down: 10.0.0.3 (Init)"), r.get("ospf"))
r = run({BGP_PATH: 403, OSPF_PATH: OSPF_UP})
check("a key that may not read the diagnostics: an ERROR row for that check, the other still answers", r.get("bgp", ("",))[0] == "ERROR" and "403" in r["bgp"][2] and r.get("ospf", ("",))[0] == "OK", (r.get("bgp"), r.get("ospf")))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
