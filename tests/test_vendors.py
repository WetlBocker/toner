# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\vend%d.db" % int(time.time())
from core import db, importer, vendors, display
db.init()
from drivers import DRIVERS
import drivers.sshbase as SB
import drivers.paloalto as PA, drivers.meraki as ME

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.thresholds_for({"name": "x", "vendor": "cisco", "location": ""})
OPTS = {**db.runtime_options()}

class Conn:
    def __init__(self, table): self.t = table; self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        for k, v in self.t.items():
            if cmd == k: return v
        return "% Invalid input"

def ssh_run(vendor, table, platform="", **dev):
    d = {"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": platform, "password": "p", **dev}
    drv = DRIVERS[vendor](d, TH, OPTS)
    drv.connect = lambda: Conn(table)
    res = drv.run()
    return {r.check: r for r in res}

print("== registry / importer")
check("sixteen vendors, none without a driver", len(vendors.VENDORS) == 16 and set(DRIVERS) == set(vendors.VENDORS))
check("display names", display.vendor_name("paloalto") == "Palo Alto" and display.platform_name("aruba_aoscx") == "AOS-CX")
for v, info in vendors.VENDORS.items():
    check(f"checks catalog has {v}", v in __import__("core.checks", fromlist=["x"]).CATALOG)
def norm(**kw):
    base = {"name": "a", "vendor": "cisco", "host": "10.0.0.9"}; base.update(kw); return importer.normalize(base)[0]
check("short platform names", norm(platform="ios")["platform"] == "cisco_ios" and norm(vendor="hpe", platform="osswitch")["platform"] == "aruba_osswitch"
      and norm(vendor="hpe", platform="aoscx")["platform"] == "aruba_aoscx")
check("vendor without platforms drops it", norm(vendor="meraki", platform="x")["platform"] == "")
try: norm(vendor="hpe", platform="bogus"); check("bad platform rejected", False)
except ValueError as e: check("bad platform rejected", "must be one of" in str(e), e)
try: norm(vendor="nokia"); check("unknown vendor rejected", False)
except ValueError as e: check("unknown vendor rejected", "juniper" in str(e) and "meraki" in str(e))
check("paging per vendor", vendors.paging_command("juniper", "terminal length 0") == "set cli screen-length 0"
      and vendors.paging_command("juniper", "custom") == "custom" and vendors.paging_command("mikrotik", "terminal length 0") == ""
      and vendors.paging_command("cisco", "terminal length 0") == "terminal length 0")
check("ssh login reuse", vendors.uses_ssh_login("juniper") and vendors.uses_ssh_login("unifi") and not vendors.uses_ssh_login("meraki")
      and not vendors.uses_ssh_login("paloalto") and not vendors.uses_ssh_login("fortinet"))

print("== Juniper")
RE = """Routing Engine status:
  Slot 0:
    Current state                  Master
    Temperature                 36 degrees C / 96 degrees F
    DRAM                      2048 MB (2048 MB installed)
    Memory utilization          28 percent
    5 sec CPU utilization:
      User                       2 percent
      Idle                      97 percent
    1 min CPU utilization:
      Idle                      95 percent
    5 min CPU utilization:
      User                      10 percent
      Background                 0 percent
      Kernel                    20 percent
      Idle                      70 percent
    Uptime                      10 days, 4 hours, 20 minutes, 3 seconds
  Slot 1:
    Memory utilization          85 percent
    5 min CPU utilization:
      Idle                      60 percent
"""
JT = {"show chassis routing-engine": RE,
      "show chassis alarms": "2 alarms currently active\nAlarm time               Class  Description\n2024-01-01 10:00:00 UTC  Major  PEM 1 Not OK\n2024-01-01 10:00:00 UTC  Minor  Fan speed low\n",
      "show interfaces terse": "Interface               Admin Link Proto    Local                 Remote\nge-0/0/0                up    up\nge-0/0/0.0              up    up   inet     10.0.0.1/24\nge-0/0/1                up    down\nge-0/0/2                down  down\nxe-0/1/0                up    up\nlo0                     up    up\nlo0.0                   up    up   inet     1.1.1.1 --> 0/0\n",
      "show bgp summary": "Groups: 1 Peers: 3 Down peers: 1\nTable          Tot Paths  Act Paths Suppressed\nPeer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...\n192.168.1.1           65000       1234       1235       0       0     1w2d 3:04:05 Establ\n  inet.0: 3/3/3/0\n192.168.1.2           65001          0          2       0       1        5:00 Active\n2001:db8::1           65002       2000       2000       0       0     2d 1:00:00 0/0/0/0\n",
      "show ospf neighbor": "Address          Interface              State           ID               Pri  Dead\n10.0.0.2         ge-0/0/1.0             Full            10.0.0.2         128    33\n10.0.0.3         ge-0/0/2.0             ExStart         10.0.0.3         128    35\n"}
r = ssh_run("juniper", JT)
check("cpu = worst slot (40%)", r["cpu"].value == "40%" and r["cpu"].status == "OK", r["cpu"])
check("memory = worst slot", r["memory"].value == "85%" and r["memory"].status == "FAIL" or r["memory"].status == "WARN", r["memory"])
check("uptime parsed", r["uptime"].numeric and abs(r["uptime"].numeric - (10*24+4+20/60)) < 0.01, r["uptime"])
check("alarms: major -> FAIL", r["alarms"].status == "FAIL" and "PEM" in r["alarms"].message, r["alarms"])
check("interfaces: admin-up ports only", r["interfaces"].value == "2/3 up", r["interfaces"])
check("bgp: 2 of 3 up, one down", r["bgp"].value == "2/3 established" and r["bgp"].status == "FAIL" and "192.168.1.2" in r["bgp"].message, r["bgp"])
check("ospf: ExStart is bad", r["ospf"].status == "FAIL" and "10.0.0.3" in r["ospf"].message, r["ospf"])
r = ssh_run("juniper", {**JT, "show chassis alarms": "No alarms currently active\n", "show bgp summary": "error: bgp is not running\n", "show ospf neighbor": "OSPF instance is not running\n"})
check("no alarms / no bgp / no ospf", r["alarms"].status == "OK" and "bgp" not in r and "ospf" not in r)
r = ssh_run("juniper", {"show chassis routing-engine": "garbage"})
check("unreadable output becomes ERROR rows, not silence", r["cpu"].status == "ERROR" and "unexpected output" in r["cpu"].message, r.get("cpu"))
r = ssh_run("juniper", {**JT, "show chassis routing-engine": RE.replace("    Uptime                      10 days, 4 hours, 20 minutes, 3 seconds\n", ""),
                        "show system uptime": "Current time: x\nSystem booted: 2024-01-01 10:00:00 UTC (13w3d 22:40 ago)\n"})
check("uptime fallback (compact format)", abs(r["uptime"].numeric - (13*168 + 3*24 + 22 + 40/60)) < 0.01, r["uptime"])

print("== Arista")
AT = {"show processes top once": "top - 10:00:00 up 3 days\n%Cpu(s):  2.0 us,  1.0 sy,  0.0 ni, 90.5 id,  0.0 wa\n",
      "show version | json": json.dumps({"memTotal": 4000000, "memFree": 1000000, "version": "4.30"}),
      "show uptime | json": json.dumps({"upTime": 190000.5}),
      "show system environment temperature | json": json.dumps({"systemStatus": "temperatureOk", "tempSensors": [{"name": "a", "currentTemperature": 41.5}, {"name": "b", "currentTemperature": 72.0}]}),
      "show interfaces status | json": json.dumps({"interfaceStatuses": {"Ethernet1": {"linkStatus": "connected"}, "Ethernet2": {"linkStatus": "notconnect"}, "Ethernet3": {"linkStatus": "errdisabled"}, "Management1": {"linkStatus": "connected"}}}),
      "show ip bgp summary | json": json.dumps({"vrfs": {"default": {"peers": {"10.0.0.1": {"peerState": "Established"}, "10.0.0.2": {"peerState": "Active"}}}}}),
      "show ip ospf neighbor | json": json.dumps({"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [{"routerId": "1.1.1.1", "adjacencyState": "full"}, {"routerId": "2.2.2.2", "adjacencyState": "exchange"}]}}}}})}
r = ssh_run("arista", AT)
check("cpu 9.5%", r["cpu"].value == "10%" and r["cpu"].status == "OK", r["cpu"])
check("memory 75%", r["memory"].value == "75%" and r["memory"].status == "OK", r["memory"])
check("uptime 2d", r["uptime"].value == "2:04:46:40" and r["uptime"].status == "OK", r["uptime"])
check("temperature graded (72C -> WARN)", r["temperature"].status == "WARN" and r["temperature"].value == "72C", r["temperature"])
check("interfaces + err-disabled", r["interfaces"].value == "2/4 up" and r["interfaces"].status == "WARN" and "Ethernet3" in r["interfaces"].message, r["interfaces"])
check("bgp down", r["bgp"].status == "FAIL" and r["bgp"].value == "1/2 established", r["bgp"])
check("ospf nested json", r["ospf"].status == "FAIL" and "2.2.2.2" in r["ospf"].message, r["ospf"])
r = ssh_run("arista", {**AT, "show ip bgp summary | json": "BGP inactive", "show ip ospf neighbor | json": "% OSPF not enabled"})
check("bgp/ospf not configured -> nothing", "bgp" not in r and "ospf" not in r)
r = ssh_run("arista", {})
check("invalid command -> ERROR rows", r["memory"].status == "ERROR" and "unexpected output" in r["memory"].message, r["memory"])

print("== HPE Aruba")
AOSS = {"show system information": "\n Status and Counters - General System Information\n\n  System Name        : sw1\n  Up Time            : 6 days   Memory   - Total   : 134,217,728\n  CPU Util (%)       : 12                          Free    : 85,214,308\n",
        "show interfaces brief": "\n  Port   Type      | Alert     Enabled Status Mode\n  ------ --------- + --------- ------- ------ ----\n  1      100/1000T | No        Yes     Up     1000FDx\n  2      100/1000T | No        Yes     Down    1000FDx\n  A1     SFP+SR    | No        Yes     Up     10GigFD\n"}
r = ssh_run("hpe", AOSS, platform="aruba_osswitch")
check("AOS-S cpu", r["cpu"].value == "12%", r["cpu"])
check("AOS-S memory 36.5%", r["memory"].value == "37%", r["memory"])
check("AOS-S uptime 6 days", r["uptime"].value == "6:00:00:00" and abs(r["uptime"].numeric - 144) < 0.01, r["uptime"])
check("AOS-S interfaces", r["interfaces"].value == "2/3 up", r["interfaces"])
AOSCX = {"show system resource-utilization": "System Resource Utilization\n CPU usage       : 7 %\n Memory usage    : 41 %\n",
         "show system": "Hostname : cx1\nUp Time : 12 days, 3 hours\nCPU : x\n",
         "show interface brief": "Port  Native  Mode  Type  Enabled  Status\n1/1/1  1  access  1GbT  yes  up  1000\n1/1/2  1  access  1GbT  yes  down  --\nlag1  --  routed  --  yes  up  --\n"}
r = ssh_run("hpe", AOSCX)
check("AOS-CX default platform; cpu/mem", r["cpu"].value == "7%" and r["memory"].value == "41%", (r["cpu"], r["memory"]))
check("AOS-CX uptime", abs(r["uptime"].numeric - (12*24+3)) < 0.01, r["uptime"])
check("AOS-CX interfaces", r["interfaces"].value == "2/3 up", r["interfaces"])

print("== MikroTik")
MT = {"/system resource print": "                   uptime: 3w2d4h5m6s\n                  version: 7.11.2 (stable)\n               free-memory: 256.0MiB\n              total-memory: 1024.0MiB\n                 cpu-load: 35%\n               board-name: RB5009UG+S+\n",
      "/interface print terse": " 0  R  name=ether1 default-name=ether1 type=ether mtu=1500\n 1     name=ether2 default-name=ether2 type=ether\n 2  X  name=ether3 default-name=ether3 type=ether\n 3  RS name=ether4 type=ether\n",
      "/routing ospf neighbor print terse": " 0 instance=default address=10.0.0.2 state=Full\n 1 instance=default address=10.0.0.3 state=Init\n"}
r = ssh_run("mikrotik", MT)
check("cpu", r["cpu"].value == "35%", r["cpu"])
check("memory 75%", r["memory"].value == "75%", r["memory"])
check("uptime compact", abs(r["uptime"].numeric - (3*168 + 2*24 + 4 + 5/60 + 6/3600)) < 0.01, r["uptime"])
check("firmware row", r["firmware"].value == "7.11.2 (stable)" and r["firmware"].message == "RB5009UG+S+", r["firmware"])
check("interfaces: disabled not counted", r["interfaces"].value == "2/3 up", r["interfaces"])
check("ospf: Init bad", r["ospf"].status == "FAIL" and "10.0.0.3" in r["ospf"].message, r["ospf"])
r = ssh_run("mikrotik", {**MT, "/routing ospf neighbor print terse": "bad command name ospf"})
check("ospf missing -> nothing", "ospf" not in r)

print("== Palo Alto")
def xml(body, status="success"): return f'<response status="{status}">{body}</response>'.encode()
PAN = {
 "<show><system><info/></system></show>": xml("<result><system><hostname>fw</hostname><sw-version>11.1.2</sw-version><model>PA-440</model><uptime>12 days, 3:04:05</uptime></system></result>"),
 "<show><system><resources/></system></show>": xml("<result><![CDATA[top - 10:00\n%Cpu(s):  3.0 us,  1.0 sy,  0.0 ni, 90.0 id,  0.0 wa\nMiB Mem :   8000.0 total,   1000.0 free,   5000.0 used,   2000.0 buff/cache\n]]></result>"),
 "<show><session><info/></session></show>": xml("<result><num-active>85000</num-active><num-max>100000</num-max></result>"),
 "<show><high-availability><state/></high-availability></show>": xml("<result><enabled>yes</enabled><group><local-info><state>active</state></local-info><peer-info><state>passive</state><conn-status>up</conn-status></peer-info><running-sync>synchronized</running-sync></group></result>"),
 "<show><interface>all</interface></show>": xml("<result><hw><entry><name>ethernet1/1</name><state>up</state></entry><entry><name>ethernet1/2</name><state>down</state></entry></hw></result>"),
}
class Resp:
    def __init__(self, content=b"", status=200, js=None, headers=None, links=None):
        self.content, self.status_code, self._js, self.headers, self.links = content, status, js, headers or {}, links or {}
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests; e = requests.HTTPError(f"{self.status_code}"); e.response = self; raise e
    def json(self): return self._js
calls = []
def pan_get(url, params=None, headers=None, **kw):
    calls.append((url, params, headers, kw))
    body = PAN.get(params["cmd"])
    return Resp(body) if body else Resp(xml("<msg>bad command</msg>", "error"))
PA.requests.get = pan_get
def pan_run(**dev):
    d = {"name": "pa", "vendor": "paloalto", "host": "10.0.0.5", "password": "KEY123", **dev}
    return {r.check: r for r in DRIVERS["paloalto"](d, TH, OPTS).run()}
r = pan_run()
check("PAN cpu 10% / memory excludes cache (62.5%)", r["cpu"].value == "10%" and r["memory"].numeric == 62.5, (r["cpu"], r["memory"]))
check("PAN uptime", abs(r["uptime"].numeric - (12*24 + 3 + 4/60)) < 0.01, r["uptime"])
check("PAN version", r["firmware"].value == "11.1.2" and r["firmware"].message == "PA-440")
check("PAN sessions 85% -> WARN", r["sessions"].value == "85%" and r["sessions"].status == "WARN", r["sessions"])
check("PAN HA healthy", r["ha"].status == "OK" and r["ha"].value == "active / peer passive", r["ha"])
check("PAN interfaces", r["interfaces"].value == "1/2 up")
check("API key sent in a header, not the URL", all(c[2]["X-PAN-KEY"] == "KEY123" and "KEY123" not in str(c[1]) and "KEY123" not in c[0] for c in calls))
check("system info fetched once", sum(1 for c in calls if c[1]["cmd"] == "<show><system><info/></system></show>") == 1)
PAN["<show><high-availability><state/></high-availability></show>"] = xml("<result><enabled>no</enabled></result>")
check("HA off, not expected -> OK", pan_run()["ha"].status == "OK")
check("HA off, but expected -> FAIL", pan_run(ha_expected=1)["ha"].status == "FAIL")
PAN["<show><high-availability><state/></high-availability></show>"] = xml("<result><enabled>yes</enabled><group><local-info><state>active</state></local-info><peer-info><state>unknown</state><conn-status>down</conn-status></peer-info><running-sync>not synchronized</running-sync></group></result>")
h = pan_run()["ha"]
check("HA peer down -> FAIL", h.status == "FAIL" and "peer unreachable" in h.message, h)
PAN.pop("<show><session><info/></session></show>")
check("API error becomes an ERROR row", pan_run()["sessions"].status == "ERROR" and "bad command" in pan_run()["sessions"].message)

print("== Meraki")
ORGS = [{"id": "111", "name": "Acme"}, {"id": "222", "name": "Other"}]
STAT = [{"name": "MX-1", "serial": "Q1", "status": "online"}, {"name": "MS-1", "serial": "Q2", "status": "offline"},
        {"name": "MR-1", "serial": "Q3", "status": "alerting"}, {"name": "old", "serial": "Q4", "status": "dormant"}]
UPL = [{"serial": "Q1", "uplinks": [{"interface": "wan1", "status": "active"}, {"interface": "wan2", "status": "failed"}]}]
exp = time.strftime("%b %d, %Y", time.gmtime(time.time() + 20 * 86400)).replace(" 0", " ") + " UTC"
LIC = {"status": "OK", "expirationDate": exp}
mcalls = []
def mer_get(url, params=None, headers=None, **kw):
    mcalls.append((url, params, headers, kw))
    path = url.split("/api/v1")[-1]
    if path == "/organizations": return Resp(js=ORGS)
    if path.endswith("/devices/statuses"): return Resp(js=STAT)
    if path.endswith("/uplink/statuses"): return Resp(js=UPL)
    if path.endswith("/licenses/overview"): return Resp(js=LIC)
    return Resp(status=404)
ME.requests.get = mer_get
def mer_run(**dev):
    d = {"name": "mer", "vendor": "meraki", "host": "api.meraki.com", "password": "MKEY", "site": "Acme", **dev}
    return {r.check: r for r in DRIVERS["meraki"](d, TH, OPTS).run()}
r = mer_run()
check("devices: offline -> FAIL, dormant ignored", r["devices"].status == "FAIL" and r["devices"].value == "1/3 online" and "MS-1" in r["devices"].message and "alerting: MR-1" in r["devices"].message, r["devices"])
check("uplinks: one failed -> WARN, named by device", r["uplinks"].status == "WARN" and "MX-1 wan2" in r["uplinks"].message and r["uplinks"].value == "1/2 up", r["uplinks"])
check("license ok but expiring soon -> WARN", r["licenses"].status == "WARN" and "expires in" in r["licenses"].message, r["licenses"])
check("key goes in the Authorization header over verified TLS", all(c[2]["Authorization"] == "Bearer MKEY" and c[3]["verify"] is True and c[0].startswith("https://api.meraki.com/api/v1") for c in mcalls))
check("organization by id works", "devices" in mer_run(site="222") and "devices" in mer_run(site="111"))
try:
    DRIVERS["meraki"]({"name": "m", "vendor": "meraki", "host": "api.meraki.com", "password": "k", "site": "Nope"}, TH, OPTS).run(); check("unknown org", False)
except ValueError as e: check("unknown org lists what the key can see", "Acme (111)" in str(e), e)
try:
    DRIVERS["meraki"]({"name": "m", "vendor": "meraki", "host": "api.meraki.com", "password": "k", "site": "default"}, TH, OPTS).run(); check("default org with several", False)
except ValueError as e: check("'default' is ambiguous with several orgs", "not found" in str(e))
ORGS[:] = ORGS[:1]
check("'default' works with exactly one org", "devices" in mer_run(site="default"))
LIC["status"] = "Out of compliance"
check("license out of compliance -> WARN", mer_run()["licenses"].status == "WARN")
LIC["expirationDate"] = "Jan 1, 2020 UTC"
check("expired license -> FAIL", mer_run()["licenses"].status == "FAIL")
_old = mer_get
def mer_get2(url, **kw):
    if url.endswith("/licenses/overview") or url.endswith("/uplink/statuses"): return Resp(status=400)
    return _old(url, **kw)
ME.requests.get = mer_get2
r = mer_run()
check("endpoints unsupported by the org are skipped quietly", "licenses" not in r and "uplinks" not in r and "devices" in r)
pages = []
def mer_page(url, params=None, **kw):
    if url.endswith("/organizations"): return Resp(js=ORGS)
    if "statuses" in url and "page2" not in url:
        return Resp(js=[{"name": "a", "status": "online"}], links={"next": {"url": "https://api.meraki.com/api/v1/organizations/111/devices/statuses?page2"}})
    return Resp(js=[{"name": "b", "status": "online"}])
ME.requests.get = mer_page
check("pagination followed", mer_run()["devices"].value == "2/2 online")
n = {"c": 0}
def mer_429(url, params=None, **kw):
    if url.endswith("/organizations"):
        n["c"] += 1
        return Resp(status=429, headers={"Retry-After": "0"}) if n["c"] == 1 else Resp(js=ORGS)
    return Resp(js=[])
ME.requests.get = mer_429
check("one retry on rate limit", "devices" in mer_run() and n["c"] == 2)

print("== through the runner (connection error handling)")
from core.runner import run_one
res = run_one({"name": "j", "vendor": "juniper", "host": "127.0.0.1", "port": 1, "username": "u", "platform": "juniper_junos", "password": "p"}, TH, {**OPTS, "ssh_timeout": 3, "retries": 0})
check("unreachable device -> one connection ERROR", len(res) == 1 and res[0].check == "connection" and res[0].status == "ERROR", res)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
