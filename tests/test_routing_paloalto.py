# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; the devices are stand-ins (no network, no SSH).
# Palo Alto: BGP peers and OSPF neighbours through the XML API, on the legacy routing engine and on the Advanced Routing Engine.
# The replies are built from what Palo Alto publishes; where it publishes no reply (see each sample) the shape is an inference and says so.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import json, os, sys, time
import xml.etree.ElementTree as ET
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rtpa%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingrtpa%d" % int(time.time()))
from core import checks, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from drivers import DRIVERS
import drivers.paloalto as PA
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5}

# The op commands. Legacy BGP is spelled out on https://pan.dev/panos/docs/panos-upgrade-assurance/api/firewall_proxy/ (get_bgp_peers); the others are
# the CLI commands of https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-cli-quick-start/cli-cheat-sheets/cli-cheat-sheet-networking (show advanced-routing ...)
# and https://docs.paloaltonetworks.com/pan-os/u-v/pan-os-device-telemetry-metrics-reference/product-usage/metric-dt-pu-82 (show routing protocol ...), each word
# an element, as https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/run-operational-mode-commands-api says to build them.
SYS = "<show><system><info/></system></show>"
BGP = "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"
BGP_SUM = "<show><routing><protocol><bgp><summary></summary></bgp></protocol></routing></show>"
OSPF = "<show><routing><protocol><ospf><neighbor></neighbor></ospf></protocol></routing></show>"
OSPF_SUM = "<show><routing><protocol><ospf><summary></summary></ospf></protocol></routing></show>"
A_BGP = "<show><advanced-routing><bgp><peer><status></status></peer></bgp></advanced-routing></show>"
A_BGP_SUM = "<show><advanced-routing><bgp><summary></summary></bgp></advanced-routing></show>"
A_OSPF = "<show><advanced-routing><ospf><neighbor></neighbor></ospf></advanced-routing></show>"
A_OSPF_SUM = "<show><advanced-routing><ospf><summary></summary></ospf></advanced-routing></show>"

# Legacy BGP: the sample output of get_bgp_peers on https://pan.dev/panos/docs/panos-upgrade-assurance/api/firewall_proxy/ put back into XML
# ('@peer' and '@vr' are attributes of <entry>; the entry inside <prefix-counter> is not a peer).
def bgp_peer(name="Peer1", status="Established"):
    return (f'<entry peer="{name}" vr="default"><peer-group>Peer-Group1</peer-group><peer-router-id>169.254.8.2</peer-router-id><remote-as>64512</remote-as>'
            f"<status>{status}</status><status-duration>3804</status-duration><password-set>no</password-set><passive>no</passive><multi-hop-ttl>2</multi-hop-ttl>"
            "<peer-address>169.254.8.2:35355</peer-address><local-address>169.254.8.1:179</local-address><reflector-client>not-client</reflector-client>"
            "<last-error>None</last-error><status-flap-counts>2</status-flap-counts><established-counts>1</established-counts><config><remove-private-as>no</remove-private-as></config>"
            '<prefix-counter><entry afi-safi="bgpAfiIpv4-unicast"><incoming-total>2</incoming-total><incoming-accepted>2</incoming-accepted><outgoing-total>0</outgoing-total></entry></prefix-counter></entry>')

# Legacy OSPF: Palo Alto publishes the command's text (https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClrHCAS), not its XML. The elements here
# are those labels with hyphens ("neighbor router ID" -> neighbor-router-id), which is how the BGP reply above names its own; a real firewall's reply is still to be seen.
def ospf_nbr(rid="1.1.1.1", status="full", addr="192.168.73.11"):
    return (f"<entry><virtual-router>default</virtual-router><neighbor-address>{addr}</neighbor-address><local-address-binding>0.0.0.0</local-address-binding><type>dynamic</type>"
            f"<status>{status}</status><neighbor-router-id>{rid}</neighbor-router-id><area-id>0.0.0.0</area-id><neighbor-priority>1</neighbor-priority><lifetime-remain>34</lifetime-remain>"
            "<messages-pending>0</messages-pending><lsa-request-pending>0</lsa-request-pending><options>0x52: O EA E</options><hello-suppressed>no</hello-suppressed></entry>")

# Legacy summaries: no published reply. Only "a router ID is named" is read (the text of both commands prints one per virtual router); nothing at all = not configured.
BGP_ON = '<entry virtual-router="default"><router-id>169.254.8.1</router-id><local-as>64513</local-as></entry>'
OSPF_ON = '<entry virtual-router="default"><router-id>2.2.2.2</router-id></entry>'

# Advanced Routing Engine: the JSON-as-text inside <result><json>, keyed by logical router, is how get_are_routes is documented on
# https://pan.dev/panos/docs/panos-upgrade-assurance/api/firewall_proxy/ (its sample is the routing daemon's own JSON, untouched). No reply is published for
# `bgp peer status` or `ospf neighbor`: the fields below are the same daemon's (FRRouting: bgpState per peer, nbrState "Full/DR" per neighbour, routerId in a
# summary), an inference. The states are the ones in https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000XhtSCAS ("BGP State: Idle").
def are(data): return "<json>" + json.dumps(data).replace("&", "&amp;").replace("<", "&lt;") + "</json>"
A_PEERS = {"lr-public": {"ISP1": {"remoteAs": 64512, "localAs": 64540, "bgpState": "Established", "bgpTimerUpString": "00:10:50", "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}}},
                         "ISP2": {"remoteAs": 64513, "localAs": 64540, "bgpState": "Idle", "lastResetDueTo": "Waiting for NHT"}}}
A_NBRS = {"lr-public": {"neighbors": {"1.1.1.1": [{"nbrPriority": 1, "nbrState": "Full/DR", "converged": "Full", "role": "DR", "ifaceAddress": "10.0.0.1", "ifaceName": "ethernet1/1:10.0.0.2"}],
                                      "3.3.3.3": [{"nbrPriority": 0, "nbrState": "2-Way/DROther", "role": "DROther", "ifaceAddress": "10.0.0.3", "ifaceName": "ethernet1/1:10.0.0.2"}],
                                      "4.4.4.4": [{"nbrPriority": 1, "nbrState": "ExStart/Backup", "role": "Backup", "ifaceAddress": "10.0.0.4", "ifaceName": "ethernet1/1:10.0.0.2"}]}}}
A_BGP_ON = {"lr-public": {"ipv4Unicast": {"routerId": "172.16.1.2", "as": 64540, "peers": {}}}}
A_OSPF_ON = {"lr-public": {"routerId": "172.16.1.2", "areas": {}}}

def el(body): return ET.fromstring(f"<result>{body}</result>")

print("== the readers, on the replies alone")
check("legacy BGP: each peer by name with its state; the prefix counter's entry is not a peer", PA.pan_neighbors(el(bgp_peer() + bgp_peer("Peer2", "Active"))) == [("Peer1", "Established"), ("Peer2", "Active")],
      PA.pan_neighbors(el(bgp_peer() + bgp_peer("Peer2", "Active"))))
check("legacy OSPF: each neighbour by router ID with its state", PA.pan_neighbors(el(ospf_nbr() + ospf_nbr("3.3.3.3", "init"))) == [("1.1.1.1", "full"), ("3.3.3.3", "init")], PA.pan_neighbors(el(ospf_nbr())))
check("no entries, or no reply at all, is no neighbours", PA.pan_neighbors(el("")) == [] and PA.pan_neighbors(None) == [])
check("Advanced Routing BGP: the peers of every logical router, by name", PA.pan_neighbors(el(are(A_PEERS))) == [("ISP1", "Established"), ("ISP2", "Idle")], PA.pan_neighbors(el(are(A_PEERS))))
check("Advanced Routing OSPF: the neighbours by router ID", PA.pan_neighbors(el(are(A_NBRS))) == [("1.1.1.1", "Full/DR"), ("3.3.3.3", "2-Way/DROther"), ("4.4.4.4", "ExStart/Backup")], PA.pan_neighbors(el(are(A_NBRS))))
check("Advanced Routing with nothing in it", PA.pan_neighbors(el(are({}))) == [] and PA.pan_neighbors(el(are({"lr-public": {}}))) == [] and PA.pan_neighbors(el("<json></json>")) == [])
check("a protocol is running when its summary names a router ID, on either engine", PA.pan_routing_runs(el(BGP_ON)) and PA.pan_routing_runs(el(OSPF_ON)) and PA.pan_routing_runs(el(are(A_BGP_ON))) and PA.pan_routing_runs(el(are(A_OSPF_ON))))
check("...and not when the summary is empty", not PA.pan_routing_runs(el("")) and not PA.pan_routing_runs(None) and not PA.pan_routing_runs(el(are({}))) and not PA.pan_routing_runs(el(are({"lr-public": {}}))))

print("== the driver, against a stand-in firewall")
class Resp:
    def __init__(self, content=b"", status=200): self.content, self.status_code = content, status
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests; e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
def xml(body): return f'<response status="success"><result>{body}</result></response>'.encode()
# An op command the firewall does not have: error 17 "Invalid command" (1 is "Unknown command"), https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/pan-os-xml-api-error-codes
UNKNOWN = b'<response status="error" code="17"><msg><line>invalid command</line></msg></response>'
def system(advanced=None):
    return "<system><hostname>fw</hostname><sw-version>11.1.2</sw-version><model>PA-440</model><uptime>12 days, 3:04:05</uptime>" + (f"<advanced-routing>{advanced}</advanced-routing>" if advanced else "") + "</system>"
PAN, asked = {}, []
def pan_get(url, params=None, headers=None, **kw):
    asked.append(params["cmd"])
    body = PAN.get(params["cmd"])
    return Resp(body if isinstance(body, bytes) else xml(body)) if body is not None else Resp(UNKNOWN)
PA.requests.get = pan_get
def run(replies, advanced="off", opts=OPTS):
    PAN.clear(); PAN.update({SYS: system(advanced), **replies}); asked.clear()
    return {r.check: r for r in DRIVERS["paloalto"]({"name": "pa", "vendor": "paloalto", "host": "10.0.0.5", "password": "KEY"}, TH, opts).run()}
NONE = {BGP: "", BGP_SUM: "", OSPF: "", OSPF_SUM: ""}

r = run(NONE)
check("legacy, neither protocol configured: both are N/A, not errors", r["bgp"].status == "N/A" and r["bgp"].value == "not configured" and r["bgp"].message == "BGP is not configured on this device"
      and r["ospf"].status == "N/A" and r["ospf"].message == "OSPF is not configured on this device", (r["bgp"], r["ospf"]))
check("...and the Advanced Routing commands were not tried on a firewall that says it is off", not [c for c in asked if "advanced-routing" in c], asked)
r = run({**NONE, BGP_SUM: BGP_ON, OSPF_SUM: OSPF_ON})
check("configured with no neighbours warns", r["bgp"].status == "WARN" and r["bgp"].value == "no neighbors" and r["bgp"].message == "BGP is running but has no neighbors"
      and r["ospf"].status == "WARN" and r["ospf"].message == "OSPF is running but has no neighbors", (r["bgp"], r["ospf"]))
r = run({BGP: bgp_peer() + bgp_peer("Peer2"), OSPF: ospf_nbr() + ospf_nbr("3.3.3.3", "2way", "192.168.73.13")})
check("all up: counted, OK, nothing to say; a 2-Way neighbour on a shared segment is up", r["bgp"].status == "OK" and r["bgp"].value == "2/2 established" and r["bgp"].message == "" and r["bgp"].numeric == 2.0
      and r["ospf"].status == "OK" and r["ospf"].value == "2/2 established" and r["ospf"].message == "", (r["bgp"], r["ospf"]))
check("...and the summary is not asked for when there are neighbours", BGP_SUM not in asked and OSPF_SUM not in asked, asked)
r = run({BGP: bgp_peer() + bgp_peer("Peer2", "Active") + bgp_peer("Peer3", "Idle"), OSPF: ospf_nbr() + ospf_nbr("3.3.3.3", "init", "192.168.73.13")})
check("one or more down fails and names them", r["bgp"].status == "FAIL" and r["bgp"].value == "1/3 established" and r["bgp"].message == "down: Peer2, Peer3" and r["bgp"].numeric == 1.0
      and r["ospf"].status == "FAIL" and r["ospf"].value == "1/2 established" and r["ospf"].message == "down: 3.3.3.3 (init)", (r["bgp"], r["ospf"]))

print("== the Advanced Routing Engine")
r = run({A_BGP: are(A_PEERS), A_OSPF: are(A_NBRS)}, advanced="on")
check("its peers and neighbours are read, the down ones named (2-Way with a DROther is up)", r["bgp"].status == "FAIL" and r["bgp"].value == "1/2 established" and r["bgp"].message == "down: ISP2"
      and r["ospf"].status == "FAIL" and r["ospf"].value == "2/3 established" and r["ospf"].message == "down: 4.4.4.4 (ExStart/Backup)", (r["bgp"], r["ospf"]))
check("...with its own commands only", A_BGP in asked and A_OSPF in asked and BGP not in asked and OSPF not in asked, asked)
r = run({A_BGP: are({}), A_BGP_SUM: are({}), A_OSPF: are({"lr-public": {}}), A_OSPF_SUM: are({"lr-public": {}})}, advanced="on")
check("neither protocol on it: N/A", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", (r["bgp"], r["ospf"]))
r = run({A_BGP: are({}), A_BGP_SUM: are(A_BGP_ON), A_OSPF: are({}), A_OSPF_SUM: are(A_OSPF_ON)}, advanced="on")
check("running with no neighbours warns", r["bgp"].status == "WARN" and r["bgp"].value == "no neighbors" and r["ospf"].status == "WARN", (r["bgp"], r["ospf"]))

print("== a firewall that does not have the command")
r = run({A_BGP: are(A_PEERS), A_OSPF: are(A_NBRS)}, advanced=None)
check("the legacy command is unknown: the other engine is asked", r["bgp"].value == "1/2 established" and r["ospf"].value == "2/3 established" and asked.index(BGP) < asked.index(A_BGP), (r["bgp"], r["ospf"], asked))
r = run({}, advanced=None)
check("neither engine has it: N/A, not an error", r["bgp"].status == "N/A" and r["ospf"].status == "N/A", (r["bgp"], r["ospf"]))
r = run({BGP: b'<response status="error" code="16"><msg><line>unauthorized</line></msg></response>', OSPF: b"<response status='error'><msg>something else</msg></response>"})
check("any other refusal stays an ERROR row with the firewall's words", r["bgp"].status == "ERROR" and "unauthorized" in r["bgp"].message and r["ospf"].status == "ERROR" and "something else" in r["ospf"].message, (r["bgp"], r["ospf"]))
r = run({A_BGP: "<json>{not json</json>", A_OSPF: are(A_NBRS)}, advanced="on")
check("a reply that cannot be read is an ERROR row, and the next check still runs", r["bgp"].status == "ERROR" and r["ospf"].value == "2/3 established", (r["bgp"], r["ospf"]))

print("== a whole run")
r = run({BGP: bgp_peer(), OSPF: ospf_nbr(),
         "<show><session><info/></session></show>": "<num-active>100</num-active><num-max>100000</num-max>",
         "<show><interface>all</interface></show>": "<hw><entry><name>ethernet1/1</name><state>up</state></entry></hw>"})
check("BGP and OSPF rows sit with the firewall's other rows", r["bgp"].status == "OK" and r["bgp"].value == "1/1 established" and r["ospf"].status == "OK" and r["ospf"].value == "1/1 established"
      and r["firmware"].value == "11.1.2" and r["sessions"].status == "OK" and r["interfaces"].value == "1/1 up", r)
check("system info is still asked once", asked.count(SYS) == 1, asked)
r = run({BGP: bgp_peer(), OSPF: ospf_nbr()}, opts={**OPTS, "disabled": {checks.key("paloalto", "bgp")}})
check("a check that is switched off is not asked", "bgp" not in r and BGP not in asked and r["ospf"].status == "OK", (list(r), asked))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
