# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; the devices are stand-ins (no network, no SSH).
# The vendors added in 2026-11: Cisco ISE, SD-WAN Manager and FMC, VMware vCenter and ESXi, Dell PowerSwitch, Sophos Firewall,
# SonicWall, Extreme Networks and Juniper Mist, plus the extra TrueNAS checks. Each driver runs against what its API, command line
# or SNMP agent would answer, as far as the published formats say; the exact replies of a real unit may still differ (see README).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "newv%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingnewv%d" % int(time.time()))
from core import checks, db, vendors
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import drivers
from drivers import DRIVERS, webapi
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5}

print("== the vendors are known everywhere")
NEW = ["ciscoise", "ciscosdwan", "ciscofmc", "vmware", "esxi", "dell", "sophos", "sonicwall", "extreme", "mist"]
check("every new vendor has a driver, a box entry and a check catalogue", all(v in DRIVERS and v in vendors.VENDORS and v in checks.CATALOG for v in NEW))
check("their names are the ones agreed", [vendors.VENDORS[v]["name"] for v in NEW] == ["Cisco ISE", "Cisco SD-WAN Manager", "Cisco FMC", "VMware vCenter", "VMware ESXi (SNMP)",
      "Dell PowerSwitch", "Sophos Firewall (SNMP)", "SonicWall", "Extreme Networks", "Juniper Mist"])
check("the SNMP ones are SNMP, the SSH ones have platforms, Mist takes its organization ID in the site box", vendors.is_snmp("esxi") and vendors.is_snmp("sophos")
      and vendors.platform_keys("dell") == ["dell_os10", "dell_force10", "dell_os6"] and vendors.platform_keys("extreme") == ["extreme_exos", "extreme_vsp"] and vendors.VENDORS["mist"]["site"] == "Organization ID")

# ---------------------------------------------------------------- a stand-in web API
class Resp:
    def __init__(self, status=200, js=None, text="", headers=None):
        self.status_code, self._js, self.text, self.headers = status, js, text if text or js is None else json.dumps(js), dict(headers or {})
        self.content = self.text.encode() if self.text else (b"null" if js is None and status == 200 and text == "" else b"")
        if js is not None:
            self.content = json.dumps(js).encode()
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests; e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
    def json(self):
        return self._js if self._js is not None else (json.loads(self.text) if self.text else None)

ROUTES, CALLS = {}, []
class FakeSession:
    def __init__(self):
        self.headers, self.verify = {}, True
    def request(self, method, url, **kw):
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        path = "/" + path.split("?")[0]
        CALLS.append((method, path, dict(self.headers), kw))
        hit = ROUTES.get((method, path)) or ROUTES.get(("*", path))
        if callable(hit):
            return hit(method, path, self.headers, kw)
        return hit if hit is not None else Resp(404)
    def close(self): pass
webapi.requests.Session = FakeSession

def run(vendor, **dev):
    CALLS.clear()
    d = {"name": vendor + "1", "vendor": vendor, "host": "10.0.0.9", "username": "admin", "password": "pw", "port": 0, **dev}
    return {r.check: r for r in DRIVERS[vendor](d, TH, OPTS).run() if r.device == d["name"]}, [r for r in DRIVERS[vendor](d, TH, OPTS).run() if r.device != d["name"]]

print("== Cisco ISE")
ROUTES.clear()
ROUTES[("GET", "/api/v1/deployment/node")] = Resp(js=[{"hostname": "ise-pan", "nodeStatus": "Connected", "roles": ["PrimaryAdmin"]}, {"hostname": "ise-psn2", "nodeStatus": "Disconnected", "roles": ["PolicyService"]}])
ROUTES[("GET", "/api/v1/patch")] = Resp(js={"iseVersion": "3.2.0.542", "patchVersion": [{"patchNumber": 1}, {"patchNumber": 3}]})
ROUTES[("GET", "/api/v1/license/system/tier-state")] = Resp(js=[{"name": "ESSENTIAL", "status": "ENABLED"}, {"name": "PREMIER", "status": "EVALUATION"}])
ROUTES[("GET", "/api/v1/license/system/smart-state")] = Resp(js={"registrationState": "REGISTERED"})
ROUTES[("GET", "/admin/API/mnt/Session/ActiveCount")] = Resp(text="<activeCount><count>42</count></activeCount>")
r, per = run("ciscoise")
check("ISE: the version comes from the patch call and the nodes are counted", r["reachability"].value == "3.2.0.542" and "2 node" in r["reachability"].message)
check("ISE: a node that is not Connected fails the nodes row and gets its own row", r["nodes"].status == "FAIL" and "ise-psn2" in r["nodes"].message and any(x.device.endswith("/ ise-psn2") and x.status == "FAIL" for x in per))
check("ISE: the patch level, licensing and the MnT session count", r["patches"].value == "patch 3" and r["licensing"].status == "WARN" and "PREMIER: evaluation" in r["licensing"].message and r["sessions"].value == "42")
check("ISE: basic auth goes on every call", all(kw.get("auth") == ("admin", "pw") for m, p, h, kw in CALLS if p.startswith("/api/")))

print("== Cisco SD-WAN Manager")
ROUTES.clear()
ROUTES[("POST", "/j_security_check")] = Resp(text="")
ROUTES[("GET", "/dataservice/client/token")] = Resp(text="XSRF123")
ROUTES[("GET", "/dataservice/client/about")] = Resp(js={"data": {"version": "20.12.3"}})
ROUTES[("GET", "/dataservice/device")] = Resp(js={"data": [{"host-name": "vmanage", "device-type": "vmanage", "reachability": "reachable", "system-ip": "1.1.1.1", "version": "20.12.3"},
                                                           {"host-name": "edge-a", "device-type": "vedge", "reachability": "reachable", "controlConnections": "2", "bfdSessions": "4", "bfdSessionsUp": "3"},
                                                           {"host-name": "edge-b", "device-type": "vedge", "reachability": "unreachable", "controlConnections": "0", "bfdSessions": "0", "bfdSessionsUp": "0"},
                                                           {"host-name": "edge-c", "device-type": "vedge", "reachability": "reachable", "controlConnections": "0", "bfdSessions": "2", "bfdSessionsUp": "2"}]})
ROUTES[("GET", "/dataservice/alarms/count")] = Resp(js={"count": 2})
ROUTES[("GET", "/dataservice/device/system/status")] = Resp(js={"data": [{"cpu_idle": "88.5", "mem_used": "6000", "mem_total": "8000"}]})
r, _per = run("ciscosdwan")
check("SD-WAN: signs in with the form, keeps the XSRF token, reads the version", r["reachability"].value == "20.12.3" and any(h.get("X-XSRF-TOKEN") == "XSRF123" for m, p, h, kw in CALLS if p == "/dataservice/device"))
check("SD-WAN: the unreachable device fails the devices row by name", r["devices"].status == "FAIL" and r["devices"].value == "3/4 reachable" and "edge-b" in r["devices"].message)
check("SD-WAN: a reachable edge with no control connection is a FAIL; the unreachable one is not counted twice", r["control connections"].status == "FAIL" and r["control connections"].message == "no control connection: edge-c")
check("SD-WAN: BFD sessions down warn with the edge named", r["bfd"].status == "WARN" and r["bfd"].value == "5/6 up" and "edge-a (3/4)" in r["bfd"].message)
check("SD-WAN: alarms and the Manager's own CPU and memory", r["alarms"].value == "2" and r["cpu"].value == "12%" and r["memory"].value == "75%" and r["memory"].status == "OK")
ROUTES[("POST", "/j_security_check")] = Resp(text="<html>login</html>")
try:
    DRIVERS["ciscosdwan"]({"name": "m", "vendor": "ciscosdwan", "host": "h", "username": "u", "password": "x"}, TH, OPTS).run(); said = ""
except Exception as e:
    said = str(e)
check("SD-WAN: a login page back means the password was wrong, said once", "rejected the user name or password" in said, said)

print("== Cisco FMC")
ROUTES.clear()
ROUTES[("POST", "/api/fmc_platform/v1/auth/generatetoken")] = Resp(text="", headers={"X-auth-access-token": "T1", "DOMAIN_UUID": "d-1"})
ROUTES[("GET", "/api/fmc_platform/v1/info/serverversion")] = Resp(js={"items": [{"serverVersion": "7.4.1 (build 172)"}]})
ROUTES[("GET", "/api/fmc_config/v1/domain/d-1/devices/devicerecords")] = Resp(js={"items": [{"name": "ftd-1", "healthStatus": "green", "sw_version": "7.4.1", "model": "FTDv"},
                                                                                             {"name": "ftd-2", "healthStatus": "red", "sw_version": "7.2.5", "model": "FTD 1120"}]})
ROUTES[("GET", "/api/fmc_config/v1/domain/d-1/deployment/deployabledevices")] = Resp(js={"items": [{"name": "ftd-1", "canBeDeployed": True}]})
ROUTES[("GET", "/api/fmc_config/v1/domain/d-1/devicehapairs/ftddevicehapairs")] = Resp(js={"items": [{"name": "pair-1", "primaryStatus": {"currentStatus": "Active"}, "secondaryStatus": {"currentStatus": "Standby"}}]})
r, per = run("ciscofmc")
check("FMC: the token and domain from the headers, the version from the platform call", r["reachability"].value == "7.4.1 (build 172)" and any(h.get("X-auth-access-token") == "T1" for m, p, h, kw in CALLS if "devicerecords" in p))
check("FMC: a red device fails the devices row and has its own row with its software", r["devices"].status == "FAIL" and "ftd-2 (red)" in r["devices"].message and any(x.device.endswith("/ ftd-2") and "7.2.5" in x.message for x in per))
check("FMC: a deployment waiting warns, naming the device; a healthy HA pair is OK", r["deployment"].status == "WARN" and "ftd-1" in r["deployment"].message and r["ha"].status == "OK" and r["ha"].value == "1/1 pairs healthy")

print("== VMware vCenter")
ROUTES.clear()
ROUTES[("POST", "/api/session")] = Resp(js="sid-1")
ROUTES[("DELETE", "/api/session")] = Resp(text="")
ROUTES[("GET", "/api/appliance/system/version")] = Resp(js={"version": "8.0.3.00400", "build": "24322831", "product": "VMware vCenter Server"})
ROUTES[("GET", "/api/vcenter/host")] = Resp(js=[{"host": "host-1", "name": "esx1", "connection_state": "CONNECTED", "power_state": "POWERED_ON"}, {"host": "host-2", "name": "esx2", "connection_state": "DISCONNECTED", "power_state": "POWERED_ON"}])
ROUTES[("GET", "/api/vcenter/vm")] = Resp(js=[{"vm": "vm-1", "name": "dc01", "power_state": "POWERED_ON"}, {"vm": "vm-2", "name": "old", "power_state": "POWERED_OFF"}, {"vm": "vm-3", "name": "app", "power_state": "POWERED_ON"}])
ROUTES[("GET", "/api/vcenter/datastore")] = Resp(js=[{"datastore": "ds-1", "name": "ssd1", "capacity": 1000 * 2 ** 30, "free_space": 50 * 2 ** 30}, {"datastore": "ds-2", "name": "nas", "capacity": 2000 * 2 ** 30, "free_space": 1500 * 2 ** 30}])
for part, light in (("system", "green"), ("mem", "yellow"), ("load", "green"), ("storage", "green"), ("database-storage", "green"), ("swap", "green")):
    ROUTES[("GET", f"/api/appliance/health/{part}")] = Resp(js=light)
r, per = run("vmware")
check("vCenter: the session id goes on every call and the version is read", r["reachability"].value == "8.0.3.00400" and any(h.get("vmware-api-session-id") == "sid-1" for m, p, h, kw in CALLS if p == "/api/vcenter/host"))
check("vCenter: a disconnected host fails the hosts row, named", r["hosts"].status == "FAIL" and "esx2 (disconnected" in r["hosts"].message and r["hosts"].value == "1/2 connected")
check("vCenter: VMs powered on are counted", r["vms"].value == "2 of 3 powered on")
check("vCenter: the 95 % datastore is a FAIL by name, the other fine, each with its own row", r["datastores"].status == "FAIL" and "ssd1 (95%)" in r["datastores"].message and any(x.device.endswith("/ nas") and x.status == "OK" for x in per))
check("vCenter: one yellow light is a WARN that names it", r["health"].status == "WARN" and r["health"].message == "mem: yellow")
check("vCenter: the session is closed at the end", any(m == "DELETE" and p == "/api/session" for m, p, h, kw in CALLS))

print("== SonicWall")
ROUTES.clear()
ROUTES[("POST", "/api/sonicos/auth")] = Resp(js={"status": {"success": True}})
ROUTES[("DELETE", "/api/sonicos/auth")] = Resp(text="")
ROUTES[("GET", "/api/sonicos/version")] = Resp(js={"firmware_version": "SonicOS 7.0.1-5111", "model": "TZ470"})
ROUTES[("GET", "/api/sonicos/reporting/status/system")] = Resp(js={"system": {"uptime": "5 Days 3 Hours 2 Minutes", "cpu_usage": "12%", "memory_usage": "40%"}})
ROUTES[("GET", "/api/sonicos/reporting/interfaces/ipv4")] = Resp(js={"interfaces": [{"ipv4": {"name": "X0"}, "link_status": "up"}, {"ipv4": {"name": "X1"}, "link_status": "down"}]})
r, _per = run("sonicwall")
check("SonicWall: firmware and model, then uptime, CPU and memory from the system report", r["reachability"].value == "SonicOS 7.0.1-5111" and abs(r["uptime"].numeric - 123) < 0.1 and r["cpu"].value == "12%" and r["memory"].value == "40%", (r["uptime"].value, r.get("cpu")))
check("SonicWall: an interface that is down is a FAIL by name; HA and licences the firewall does not report are left out", r["interfaces"].status == "FAIL" and r["interfaces"].message == "down: X1" and "ha" not in r and "licenses" not in r)

print("== Juniper Mist")
ROUTES.clear()
ROUTES[("GET", "/api/v1/self")] = Resp(js={"email": "ops@example.com"})
ROUTES[("GET", "/api/v1/orgs/org-1/stats/devices")] = Resp(js=[{"name": "sw-core", "type": "switch", "status": "connected", "version": "23.4R2", "uptime": 90000, "cpu_stat": {"idle": 95}, "memory_stat": {"usage": 40}},
                                                              {"name": "ap-lobby", "type": "ap", "status": "disconnected", "version": "0.14.29117"}])
ROUTES[("GET", "/api/v1/orgs/org-1/alarms/search")] = Resp(js={"results": [{"type": "device_down", "acked": False}, {"type": "device_down", "acked": True}]})
r, per = run("mist", host="api.mist.com", username="", site="org-1")
check("Mist: the token header, the self call, the device count", r["reachability"].value == "2 device(s)" and all(h.get("Authorization") == "Token pw" for m, p, h, kw in CALLS))
check("Mist: the disconnected AP fails the devices row; the switch gets uptime, CPU and memory rows", r["devices"].status == "FAIL" and "ap-lobby" in r["devices"].message
      and any(x.device.endswith("/ sw-core") and x.check == "cpu" and x.value == "5%" for x in per) and any(x.device.endswith("/ sw-core") and x.check == "uptime" for x in per))
check("Mist: only the open alarms count", r["alarms"].value == "1" and "device_down x1" in r["alarms"].message)
try:
    DRIVERS["mist"]({"name": "m", "vendor": "mist", "host": "api.mist.com", "password": "pw", "site": ""}, TH, OPTS).run(); said = ""
except ValueError as e:
    said = str(e)
check("Mist: without the organization ID the run says where to put it", "organization ID" in said, said)

print("== TrueNAS: disks, datasets, services")
import drivers.restapi as RA, requests as _rq
TN = {"/system/info": {"version": "TrueNAS-SCALE-24.04.2", "hostname": "nas", "loadavg": [0.1, 0.2, 0.3], "cores": 4, "uptime_seconds": 400000},
      "/pool": [{"name": "tank", "status": "ONLINE", "healthy": True, "size": 10 * 2 ** 40, "allocated": 2 * 2 ** 40}], "/alert/list": [],
      "/disk": [{"name": "sda"}, {"name": "sdb"}, {"name": "sdc"}],
      "/smart/test/results": [{"disk": "sdb", "tests": [{"status": "SUCCESS"}, {"status": "FAILED"}]}, {"disk": "sda", "tests": [{"status": "SUCCESS"}]}],
      "/pool/dataset": [{"name": "tank", "used": {"parsed": 2 * 2 ** 40}, "available": {"parsed": 8 * 2 ** 40}, "children": [{"name": "tank/backups", "used": {"parsed": 95 * 2 ** 30}, "available": {"parsed": 5 * 2 ** 30}}]}],
      "/service": [{"service": "smb", "state": "RUNNING", "enable": True}, {"service": "nfs", "state": "STOPPED", "enable": True}, {"service": "ftp", "state": "STOPPED", "enable": False}]}
def tn_get(url, params=None, headers=None, auth=None, timeout=None, verify=None, **kw):
    path = url.split("/api/v2.0")[-1]
    return Resp(js=TN[path]) if path in TN else Resp(404)
def tn_post(url, json=None, headers=None, timeout=None, verify=None, **kw):
    return Resp(js={"sda": 31, "sdb": 44, "sdc": 38})
RA.requests.get = tn_get
_rq.post = tn_post
r = {x.check: x for x in DRIVERS["truenas"]({"name": "nas", "vendor": "truenas", "host": "10.0.0.5", "password": "KEY"}, TH, OPTS).run() if x.device == "nas"}
check("TrueNAS disks: a failed SMART test is a FAIL naming the disk", r["disks"].status == "FAIL" and r["disks"].message == "SMART failed: sdb" and r["disks"].value == "3 disk(s)")
check("TrueNAS datasets: the fullest dataset decides and is named", r["datasets"].status == "FAIL" and "tank/backups (95%)" in r["datasets"].message)
check("TrueNAS services: enabled but stopped is a FAIL; a disabled one is not", r["services"].status == "FAIL" and r["services"].message == "enabled but stopped: nfs" and r["services"].value == "1 running")

# ---------------------------------------------------------------- SSH: Dell and Extreme, from what the switches print
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
    try:
        drv.software(c)
    except Exception:
        pass
    for name, fn in drv.checks():
        drv.safe(out, name, lambda fn=fn: fn(c))
    return drv, {x.check: x for x in out}

print("== Dell PowerSwitch (OS10, OS9)")
OS10 = {"show version": "Dell EMC Networking OS10 Enterprise\nOS Version: 10.5.4.2\nBuild Version: 10.5.4.2.123\n",
        "show processes node-id 1 | grep Cpu": "%Cpu(s):  3.5 us,  1.2 sy,  0.0 ni, 94.8 id,  0.5 wa\n",
        "show processes memory node-id 1": "Total: 8084660 kB,  Used: 3160508 kB,  Free: 4924152 kB\n",
        "show system": "Node Id : 1\nUp Time : 12 days 03:04:05\n",
        "show interface status": "Port            Description  Status  Speed   Duplex Mode Vlan\nEth 1/1/1                    up      100G    full   A    1\nEth 1/1/2                    down    0       full   A    1\nEth 1/1/3                    admin-down  0   full   A    1\nMa 1/1/1                     up      1000M   full\n",
        "show environment": "Unit  Fan Tray  Status\n1     1         up\n1     2         up\nPSU   Status\n1     up\n2     fail\n"}
drv, r = ssh_rows("dell", "dell_os10", OS10)
check("OS10: version, CPU from the idle figure, memory from the totals", drv.facts["software"]["version"] == "10.5.4.2" and r["cpu"].value == "5%" and r["memory"].value == "39%", (r.get("cpu"), r.get("memory")))
check("OS10: uptime from show system; the port that is down is a FAIL, admin-down left out, management port counted", r["uptime"].numeric > 24 * 12 and r["interfaces"].status == "FAIL" and r["interfaces"].value == "2/3 up" and "Eth 1/1/2" in r["interfaces"].message, r.get("interfaces"))
check("OS10: a failed PSU is a FAIL", r["environment"].status == "FAIL" and "fail" in r["environment"].message, r.get("environment"))
OS9 = {"show version": "Dell Real Time Operating System Software\nDell Operating System Version: 2.0\nDell Application Software Version: 9.14(2.4)\nDell Networking OS uptime is 1 week(s), 2 day(s), 3 hour(s), 4 minute(s)\n",
       "show processes cpu summary": "CPU utilization   5Sec   1Min   5Min\n                   7%     6%     5%\n",
       "show memory": "Total(b)     Used(b)      Free(b)\n  2147483648   1073741824   1073741824\n",
       "show system": "Stack MAC : x\n",
       "show interfaces status": "Port    Description  Status  Speed   Duplex  Vlan\nTe 0/1               Up      10000 Mbit  Full  1\nTe 0/2               Down    Auto   Auto  1\n",
       "show environment": "Unit  Status  Fan Status\n0     up      up\n"}
drv, r = ssh_rows("dell", "dell_force10", OS9)
check("OS9: CPU from the summary, memory from the Total/Used line, uptime from show version", r["cpu"].value == "7%" and r["memory"].value == "50%" and r["uptime"].numeric > 24 * 9, (r.get("cpu"), r.get("memory"), r.get("uptime")))
check("OS9: ports Up/Down are read", r["interfaces"].value == "1/2 up" and "Te 0/2" in r["interfaces"].message, r.get("interfaces"))

print("== Extreme Networks (EXOS, VOSS)")
EXOS = {"show version": "Switch      : 800516-00-05 1234 Rev 5.0 BootROM: 1.0.4.0    IMG: 31.7.1.4\nImage   : ExtremeXOS version 31.7.1.4 by release-manager\n",
        "show switch": "SysName:          core-sw\nSystem UpTime:    12 days 3 hours 4 minutes 5 seconds\n",
        "show cpu-monitoring": "CPU Utilization Statistics - Monitored every 5 seconds\nProcess      5   10   30   60   90  120  180  240  300  600  Max\n-----\nSystem      4.2  4.0  3.9  3.8  3.8  3.7  3.7  3.7  3.6  3.6  12.1\naaa         0.0  0.0\n",
        "show memory": "System Memory Information\nTotal DRAM (KB): 2097152\nSystem      (KB): 400000\nUser        (KB): 600000\nFree        (KB): 1097152\n",
        "show ports no-refresh": "Port   Display String   VLAN Name   Port  Link  Speed  Duplex\n                                    State State Actual Actual\n1                       Default     E     A     1000   FULL\n2                       Default     E     R\n3                       Default     D     R\n",
        "show fans": "FanTray-1 information:\n State:   Operational\nFan-1 operational at 3000 RPM\nFan-2 operational at 3000 RPM\n",
        "show power": "PowerSupply 1 information:\n State             : Powered On\nPowerSupply 2 information:\n State             : Empty\n"}
drv, r = ssh_rows("extreme", "extreme_exos", EXOS)
check("EXOS: version, CPU from the System row, memory from DRAM and Free", drv.facts["software"]["version"] == "31.7.1.4" and r["cpu"].value == "4%" and r["memory"].value == "48%", (r.get("cpu"), r.get("memory")))
check("EXOS: uptime, the ready-but-not-active port is down, the disabled one left out", r["uptime"].numeric > 24 * 12 and r["interfaces"].value == "1/2 up" and "2" in r["interfaces"].message, r.get("interfaces"))
check("EXOS: fans and power fine (an empty slot is not a fault)", r["environment"].status == "OK", r.get("environment"))
VOSS = {"show sys-info": "SysDescr : VSP-7432CQ (8.10.1.0) BoxType: VSP-7400\nSysUpTime : 3 day(s), 04:05:06\nSysName : fabric-1\n",
        "show khi performance cpu": "CPU Utilization\n  Cpu-Utilization Percent : 9\n",
        "show khi performance memory": "Memory Utilization\n  Used : 1500 MB\n  Free : 2500 MB\n",
        "show interfaces gigabitEthernet": "PORT  LINK  PORT    PHYSICAL  STATUS\nNUM   TRAP  LOCK    ADDRESS   \n1/1   true  false   aa:bb     up\n1/2   true  false   aa:bc     down\n"}
drv, r = ssh_rows("extreme", "extreme_vsp", VOSS)
check("VOSS: version from SysDescr, CPU and memory from the khi commands, uptime from SysUpTime", drv.facts["software"]["version"] == "8.10.1.0" and r["cpu"].value == "9%" and r["memory"].value == "38%" and 76 < r["uptime"].numeric < 77, (r.get("cpu"), r.get("memory"), r.get("uptime")))
check("VOSS: the port that is down is a FAIL", r["interfaces"].status == "FAIL" and "1/2" in r["interfaces"].message, r.get("interfaces"))

# ---------------------------------------------------------------- SNMP: ESXi and Sophos, from their MIBs
class FakeSnmp:
    def __init__(self, scalars, columns): self.scalars, self.columns = scalars, columns
    def try_get(self, *oids): return {o: self.scalars[o] for o in oids if o in self.scalars}
    def get(self, *oids): return self.try_get(*oids)
    def try_column(self, root): return dict(self.columns.get(root, {}))
    def column(self, root): return self.try_column(root)

print("== VMware ESXi by SNMP")
from drivers import esxi as EX, sophos as SO
drv = DRIVERS["esxi"]({"name": "esx", "vendor": "esxi", "host": "h"}, TH, OPTS)
drv.c = FakeSnmp({EX.VMW_PROD_NAME: "VMware ESXi", EX.VMW_PROD_VERSION: "8.0.3", EX.VMW_PROD_BUILD: "24022510"},
                 {EX.VMW_VM_NAME: {"1": "dc01", "2": "old-vm", "3": "app"}, EX.VMW_VM_POWER: {"1": "poweredOn", "2": "poweredOff", "3": "poweredOn"}})
v, vms = drv.version(), drv.vms()
check("ESXi: the product version and build from VMware's MIB, kept as the device's version", v.value == "8.0.3" and "24022510" in v.message and drv.facts["software"]["version"] == "8.0.3")
check("ESXi: the VMs powered on, named", vms.value == "2 of 3 powered on" and vms.message == "dc01, app")
check("ESXi: the check list drops the UPS, printer and NAS checks of the generic driver", [k for k, _ in drv.check_list()] == ["cpu", "memory", "storage", "uptime", "interfaces", "interface errors", "bandwidth", "version", "vms"])

print("== Sophos Firewall by SNMP")
drv = DRIVERS["sophos"]({"name": "xg", "vendor": "sophos", "host": "h"}, TH, OPTS)
drv.c = FakeSnmp({SO.FW_VERSION: "SFOS 21.0.1 MR-1", SO.DEVICE_TYPE: "XGS 2100", SO.DEVICE_NAME: "xg", SO.MEM_PCT: 62, SO.DISK_PCT: 91},
                 {SO.SERVICES: {"3.0": 3, "5.0": 3, "9.0": 0, "10.0": 1, "15.0": 5}, SO.HA: {"1.0": 1, "2.0": "Primary", "3.0": "Auxiliary"},
                  SO.LICENSES: {"1.1.0": "Subscribed", "1.2.0": "2027-01-01", "2.1.0": "Expired", "2.2.0": "2025-01-01"}})
v, m, d, s, h, l = drv.version(), drv.memory(), drv.disk(), drv.services(), drv.ha(), drv.licenses()
check("Sophos: firmware version and model from the SFOS MIB", v.value == "SFOS 21.0.1 MR-1" and v.message == "XGS 2100" and drv.facts["software"]["version"] == "SFOS 21.0.1 MR-1")
check("Sophos: memory from the SFOS percentage, disk graded against the disk limit", m.value == "62%" and d.value == "91%" and d.status == "FAIL")
check("Sophos: a stopped service warns, a dead one fails, untouched ones are not counted", s.status == "FAIL" and "IPS: stopped" in s.message and "IPsec VPN: dead" in s.message and s.value == "2/4 running", s)
check("Sophos: HA enabled with a primary and an auxiliary is fine; an expired module warns", h.status == "OK" and h.value == "primary" and l.status == "WARN" and "module 2: expired" in l.message)

print("== ISE, FMC and SD-WAN under the Cisco vendor")
from core import display
check("the three are Cisco's family: one Cisco entry in the Vendor box, each named as a way to monitor", vendors.family("ciscoise") == "cisco" and "ciscoise" not in vendors.listed()
      and [k for k, _ in vendors.modes("cisco")] == ["cisco", "ciscoise", "ciscofmc", "ciscosdwan"] and display.type_name("ciscofmc") == "Cisco - FMC (REST API)" and display.vendor_name("ciscoise") == "Cisco")
check("import files: cisco + ise is ISE, cisco + cisco_ios stays a switch, unifi + network still the Network API",
      vendors.from_file("cisco", "ise") == ("ciscoise", "") and vendors.from_file("Cisco", "FMC") == ("ciscofmc", "") and vendors.from_file("cisco", "cisco_ios") == ("cisco", "cisco_ios")
      and vendors.from_file("unifi", "network") == ("unifi_network", "") and vendors.from_file("unifi", "login") == ("unifi", ""))
check("Cisco by SSH keeps its platforms; ISE has none", [k for k, _ in vendors.sub_platforms("cisco")] == ["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa"] and vendors.sub_platforms("ciscoise") == [] and vendors.sub_platforms("arista") == [])
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
d = I.DeviceDialog()
d.vendor.setCurrentIndex(d.vendor.findData("cisco"))
check("choosing Cisco offers How to monitor: SSH first, then ISE, FMC and SD-WAN", [d.platform.itemData(i) for i in range(d.platform.count())] == ["cisco", "ciscoise", "ciscofmc", "ciscosdwan"]
      and d.form.labelForField(d.platform).text() == "How to monitor")
check("by SSH the second Platform box lists IOS, IOS XE, NX-OS and ASA, and is saved as the platform", d.form.isRowVisible(d.sub_platform) and d.sub_platform.count() == 4 and d._vendor() == "cisco"
      and (d.sub_platform.setCurrentIndex(2) or d.values()["platform"] == "cisco_nxos") and d.values()["vendor"] == "cisco", d.values().get("platform"))
d.platform.setCurrentIndex(d.platform.findData("ciscoise"))
check("ISE hides the second box, asks for a user name and password, and is saved as the ISE type", not d.form.isRowVisible(d.sub_platform) and d._vendor() == "ciscoise" and d.access.isRowVisible(d.username)
      and d.values()["vendor"] == "ciscoise" and d.values()["platform"] == "" and d.checks_tab.listing.count() == len(checks.CATALOG["ciscoise"]))
d.close()
e = I.DeviceDialog({"id": 1, "name": "nx1", "vendor": "cisco", "platform": "cisco_nxos", "host": "10.0.0.1", "port": 0, "username": "u", "site": "", "verify_ssl": 0, "ha_expected": 0, "enabled": 1, "location": "", "details": "", "folder_id": None})
check("an existing NX-OS switch opens on SSH with NX-OS chosen", e._vendor() == "cisco" and e.sub_platform.currentData() == "cisco_nxos", e.sub_platform.currentData())
e.close()

print("== SSH and SNMP beside the API on ISE, FMC and SD-WAN")
from core import cmdrun, profiles, runner
check("the three have a command line type for SSH, and one account serves the API and SSH", vendors.CLI_TYPES["ciscoise"] == "cisco_ios" and vendors.CLI_TYPES["ciscofmc"] == "cisco_ftd"
      and vendors.CLI_TYPES["ciscosdwan"] == "cisco_viptela" and all(vendors.shared_login(v) for v in ("ciscoise", "ciscofmc", "ciscosdwan")) and not vendors.shared_login("fortinet"))
check("an SSH session can be opened to them, as to a switch, and the Command Runner takes them (a FortiGate keeps its SSH login for the Command Runner only, as before)",
      all(vendors.ssh_reachable(v) for v in ("ciscoise", "ciscofmc", "ciscosdwan", "cisco")) and not vendors.ssh_reachable("fortinet") and not vendors.ssh_reachable("meraki")
      and cmdrun.kind_of({"vendor": "ciscofmc"}) == "cli")
db.save_device(dict(name="ise-pan", vendor="ciscoise", host="10.0.0.40", port=0, platform="", username="admin", site="", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.set_secret(db.secret_name("ise-pan"), "api-pw")
ise = next(d for d in db.list_devices() if d["name"] == "ise-pan")
check("SSH uses the login password until an SSH password of its own is stored", profiles.ssh_secret(ise) == "api-pw" and cmdrun.runnable(ise) == (True, ""))
db.set_secret(db.secret_name("ise-pan", "ssh"), "ssh-pw")
check("...then that one", profiles.ssh_secret(ise) == "ssh-pw")
fw = {"name": "fw", "vendor": "fortinet", "host": "h", "username": "u"}
check("a FortiGate keeps its separate SSH password and never falls back to the API token", profiles.ssh_secret(fw) == "")
g = I.DeviceDialog(); g.vendor.setCurrentIndex(g.vendor.findData("cisco")); g.platform.setCurrentIndex(g.platform.findData("ciscofmc"))
check("the FMC dialog asks for Username and Password, offers an optional SSH password, and has the SNMP tab", g.access.labelForField(g.username).text() == "Username" and g.access.isRowVisible(g.ssh_pw)
      and g.ssh_pw.placeholderText() == "blank = the password above" and g.tabs.isTabVisible(2), (g.access.labelForField(g.username).text(), g.ssh_pw.placeholderText()))
g.close()
check("the catalogue lists the SNMP checks for the managers, switchable like the rest", all(("cpu", "CPU (by SNMP, when set up)") in checks.CATALOG[v] for v in ("ciscoise", "ciscofmc", "ciscosdwan", "vmware", "sonicwall")))
import drivers.snmpdev as SD
from drivers.base import Result as R
SD.SnmpDriver.run = lambda self: [R(self.name, "reachability", "OK", "x")] + [R(self.name, k, "OK", "v") for k, _fn in self.check_list()]   # (what a live agent would answer)
rows = runner.snmp_extras(ise, TH, OPTS, [R("ise-pan", "memory", "OK", "api 50%")])
check("SNMP adds what the API did not give, leaves out its reachability row, and never repeats a check the API already made",
      [r.check for r in rows] == ["cpu", "storage", "uptime", "interfaces", "interface errors"], [r.check for r in rows])
def boom(self): raise OSError("no answer")
SD.SnmpDriver.run = boom
rows = runner.snmp_extras(ise, TH, OPTS, [])
check("an SNMP failure is one ERROR row that names SNMP, not a lost run", len(rows) == 1 and rows[0].check == "snmp" and rows[0].status == "ERROR" and "SNMP" in rows[0].message)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
