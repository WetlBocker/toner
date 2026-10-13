# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The consoles are simulated from the shapes in UniFi's published OpenAPI documents (developer.ui.com).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from urllib.parse import urlparse
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "unifiapi%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingunifiapi%d" % int(time.time()))
from core import checks, db, importer, runner, vendors
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import requests
import drivers.unifiapi as UA
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "http_timeout": 5, "retries": 0, "tls_sweep": False, "custom": [], "disabled": set(), "firmware_severity": "WARN", "counter_mode": "total"}
CALLS = []
ROUTES = {}                                   # path (after /v1) -> JSON, or an int HTTP status, or a function(params) -> JSON

class Resp:
    def __init__(self, status=200, js=None, headers=None):
        self.status_code, self._js, self.headers = status, js, headers or {}
    def json(self): return self._js
    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self; raise e

def fake_get(url, params=None, headers=None, timeout=None, verify=None, **kw):
    CALLS.append({"url": url, "params": params or {}, "headers": headers or {}, "verify": verify})
    path = urlparse(url).path
    path = path[path.index("/v1") + 3:] or "/"
    hit = ROUTES.get(path)
    if callable(hit): hit = hit(params or {})
    if hit is None: return Resp(404, {"message": "not found"})
    if isinstance(hit, int): return Resp(hit, {}, {"Retry-After": "0"})
    return Resp(200, hit)
REAL_GET = requests.get
UA.requests.get = fake_get

def paged(rows):
    """A Network API list that honours offset and limit."""
    def f(p):
        off, lim = int(p.get("offset", 0)), int(p.get("limit", 25))
        part = rows[off:off + lim]
        return {"offset": off, "limit": lim, "count": len(part), "totalCount": len(rows), "data": part}
    return f

def dev(vendor, **kw):
    d = {"name": "udm", "vendor": vendor, "host": "10.0.0.1", "port": 0, "password": "KEY123", "site": "default", "verify_ssl": 0}
    d.update(kw); return d
def run(d, opts=None):
    return DRIVERS[d["vendor"]](d, db.thresholds_for(d), {**OPTS, **(opts or {})}).run()
def by(rows):
    return {(r.device, r.check): r for r in rows}

print("== the new device types")
for v, name in (("unifi_network", "Network"), ("unifi_protect", "Protect"), ("unifi_cloud", "Site Manager")):
    check(f"{v}: it is a device type with a driver, a name and a list of checks", v in vendors.VENDORS and v in DRIVERS and name in vendors.VENDORS[v]["name"] and checks.CATALOG.get(v), v)
    check(f"{v}: it asks for an API key and no user name", vendors.VENDORS[v]["secret"] == "API key" and not vendors.VENDORS[v]["username"])
check("the login-based UniFi is still there, unchanged", "unifi" in DRIVERS and vendors.VENDORS["unifi"]["secret"] == "Password")
check("the new limits exist, and the ones where lower is worse are known", all(k in db.DEFAULT_THRESHOLDS for k in ("tx_retries", "sensor_battery", "wan_uptime", "isp_latency", "isp_loss"))
      and {"sensor_battery", "wan_uptime"} <= db.LOWER_IS_WORSE)
check("an imported file can name them", importer.normalize({"name": "n1", "vendor": "unifi_network", "host": "10.1.1.1"})[0]["vendor"] == "unifi_network")

print("== UniFi Network")
SITES = [{"id": "s1", "internalReference": "default", "name": "Default"}, {"id": "s2", "internalReference": "branch", "name": "Branch"}]
DEVS1 = [{"id": "d1", "name": "AP Lobby", "model": "U6 Pro", "macAddress": "aa", "ipAddress": "10.0.0.5", "state": "ONLINE", "firmwareUpdatable": True, "firmwareVersion": "6.6.55", "features": ["accessPoint"], "interfaces": ["radios"], "supported": True},
         {"id": "d2", "name": "Core Switch", "model": "USW", "macAddress": "bb", "ipAddress": "10.0.0.6", "state": "ONLINE", "firmwareUpdatable": False, "features": ["switching"], "interfaces": ["ports"], "supported": True},
         {"id": "d3", "name": "Old Gateway", "model": "UDM", "macAddress": "cc", "ipAddress": "10.0.0.1", "state": "OFFLINE", "firmwareUpdatable": False, "features": ["gateway"], "interfaces": [], "supported": True},
         {"id": "d4", "name": "AP Annex", "model": "U6", "macAddress": "dd", "ipAddress": "10.0.0.8", "state": "UPDATING", "firmwareUpdatable": False, "features": ["accessPoint"], "interfaces": ["radios"], "supported": True}]
STATS = {"d1": {"uptimeSec": 90 * 86400, "cpuUtilizationPct": 35.0, "memoryUtilizationPct": 85.0, "uplink": {"rxRateBps": 1, "txRateBps": 2},
                "interfaces": {"radios": [{"frequencyGHz": 2.4, "txRetriesPct": 40.0}, {"frequencyGHz": 5, "txRetriesPct": 5.0}]}},
         "d2": {"uptimeSec": 600, "cpuUtilizationPct": 10.0, "memoryUtilizationPct": 30.0, "interfaces": {"radios": []}}}
def net_routes():
    ROUTES.clear()
    ROUTES.update({"/info": {"applicationVersion": "10.1.68"}, "/sites": paged(SITES), "/sites/s1/devices": paged(DEVS1), "/sites/s2/devices": paged([]),
                   "/sites/s1/clients": {"offset": 0, "limit": 1, "count": 1, "totalCount": 42, "data": [{}]}, "/sites/s2/clients": {"totalCount": 3, "data": []},
                   "/pending-devices": paged([{"name": "New AP", "model": "U6", "macAddress": "ee"}])})
    for k, v in STATS.items():
        ROUTES[f"/sites/s1/devices/{k}/statistics/latest"] = v
net_routes()
CALLS.clear()
rows = run(dev("unifi_network"))
R = by(rows)
check("it calls the console's Network integration path with the key in X-API-KEY", CALLS and CALLS[0]["url"] == "https://10.0.0.1/proxy/network/integration/v1/info"
      and all(c["headers"].get("X-API-KEY") == "KEY123" for c in CALLS), CALLS[0])
check("a console with a self-signed certificate is accepted unless 'verify' is ticked", all(c["verify"] is False for c in CALLS))
check("reachability shows the application version", R[("udm", "reachability")].value == "Network 10.1.68")
check("only the chosen site is read (default)", not any("/sites/s2/" in c["url"] for c in CALLS))
check("a device that is online is OK, one that is offline FAILs, one updating WARNs", R[("udm / AP Lobby", "state")].status == "OK" and R[("udm / Old Gateway", "state")].status == "FAIL"
      and R[("udm / AP Annex", "state")].status == "WARN" and R[("udm / Old Gateway", "state")].value == "offline")
check("a device that is not online says what and where", "10.0.0.1" in R[("udm / Old Gateway", "state")].message)
check("uptime reads as days:hours:minutes:seconds and a recent reboot is flagged", R[("udm / AP Lobby", "uptime")].value == "90:00:00:00" and R[("udm / AP Lobby", "uptime")].status == "OK"
      and R[("udm / Core Switch", "uptime")].value == "0:00:10:00" and R[("udm / Core Switch", "uptime")].status == "WARN")
check("CPU and memory use the global limits", R[("udm / AP Lobby", "cpu")].status == "OK" and R[("udm / AP Lobby", "memory")].status == "WARN" and R[("udm / AP Lobby", "memory")].value == "85%")
check("Wi-Fi retries are per radio", R[("udm / AP Lobby", "tx retries (2.4 GHz)")].status == "FAIL" and R[("udm / AP Lobby", "tx retries (5 GHz)")].status == "OK")
check("a firmware update is a warning", R[("udm / AP Lobby", "firmware")].status == "WARN" and "6.6.55" in R[("udm / AP Lobby", "firmware")].value)
check("a device that is offline is not asked for statistics", not any("/d3/" in c["url"] or "/d4/" in c["url"] for c in CALLS))
check("devices waiting to be adopted are a warning", R[("udm", "pending")].status == "WARN" and "New AP" in R[("udm", "pending")].message)
check("the client count is a number", R[("udm", "clients")].value == "42" and R[("udm", "clients")].numeric == 42.0)
check("the results belong to the console in the inventory (sub-devices are 'console / device')", {r.device.split(" / ")[0] for r in rows} == {"udm"})
check("a Settings firmware severity of FAIL or Ignore is honoured", by(run(dev("unifi_network"), {"firmware_severity": "FAIL"}))[("udm / AP Lobby", "firmware")].status == "FAIL"
      and ("udm / AP Lobby", "firmware") not in by(run(dev("unifi_network"), {"firmware_severity": "Ignore"})))

print("== Network: sites, paging, errors, per-device settings")
rows = by(run(dev("unifi_network", site="*")))
check("'*' reads every site and says which site each device is in", ("udm / Default - AP Lobby", "state") in rows and ("udm", "clients (Branch)") in rows, [k for k in rows][:6])
try: run(dev("unifi_network", site="nowhere")); check("an unknown site is explained", False)
except ValueError as e: check("an unknown site is explained", "not found" in str(e) and "Default" in str(e) and "Branch" in str(e))
many = [{"id": f"x{i}", "name": f"AP {i}", "model": "U6", "macAddress": str(i), "ipAddress": "1.1.1.1", "state": "OFFLINE", "firmwareUpdatable": False, "features": [], "interfaces": [], "supported": True} for i in range(430)]
ROUTES["/sites/s1/devices"] = paged(many); CALLS.clear()
rows = run(dev("unifi_network"))
check("a long list is read page by page until it is all there (430 devices, 200 a page)", len([r for r in rows if r.check == "state"]) == 430
      and [c["params"].get("offset") for c in CALLS if c["url"].endswith("/sites/s1/devices")] == [0, 200, 400], [c["params"] for c in CALLS if c["url"].endswith("/sites/s1/devices")])
net_routes()
ROUTES["/info"] = 401
try: run(dev("unifi_network")); check("a wrong key is explained", False)
except ValueError as e: check("a wrong key is explained", "API key was rejected" in str(e) and "unifi.ui.com" in str(e))
net_routes(); hits = []
def limited(p):
    hits.append(1)
    return 429 if len(hits) == 1 else {"applicationVersion": "10.1.68"}
ROUTES["/info"] = limited; UA.time.sleep = lambda s: None
check("the rate limit is waited out once", run(dev("unifi_network"))[0].check == "reachability" and len(hits) == 2)
net_routes(); ROUTES["/sites/s1/devices/d1/statistics/latest"] = 400
check("a kind of device that has no statistics is skipped, not an error", not [r for r in run(dev("unifi_network")) if r.status == "ERROR"])
net_routes(); ROUTES["/sites/s1/devices/d1/statistics/latest"] = 500
errs = [r for r in run(dev("unifi_network")) if r.status == "ERROR"]
check("a real failure is reported against the device, and the others carry on", len(errs) == 1 and errs[0].device == "udm / AP Lobby" and ("udm / Core Switch", "cpu") in by(run(dev("unifi_network"))))
net_routes()
own = dev("unifi_network", checkopts={"thresholds": {"memory": {"warn": 90, "fail": 95}}, "checks": ["devices", "memory"]})
off = {"unifi_network:cpu"}
R = by(run(own, {"disabled": db.disabled_for(own, set())}))
check("a device with its own limits uses them (85% memory is fine under 90)", R[("udm / AP Lobby", "memory")].status == "OK")
check("and with its own list of checks, only those run", {k[1] for k in R} == {"state", "memory"}, {k[1] for k in R})
R = by(run(dev("unifi_network"), {"disabled": {"unifi_network:cpu", "unifi_network:retries"}}))
check("a check switched off in Settings does not run", ("udm / AP Lobby", "cpu") not in R and not any(k[1].startswith("tx retries") for k in R))

print("== UniFi Protect")
NOW_MS = int(time.time() * 1000)
CAMS = [{"id": "c1", "modelKey": "camera", "state": "CONNECTED", "name": "Front door", "mac": "m1"}, {"id": "c2", "modelKey": "camera", "state": "DISCONNECTED", "name": "Garage", "mac": "m2"},
        {"id": "c3", "modelKey": "camera", "state": "CONNECTING", "name": "Yard", "mac": "m3"}]
SENS = [{"id": "s1", "modelKey": "sensor", "state": "CONNECTED", "name": "Basement leak", "mac": "m4", "batteryStatus": {"percentage": 8, "isLow": True},
         "leakDetectedAt": NOW_MS - 3600_000, "tamperingDetectedAt": NOW_MS - 90 * 86400_000},
        {"id": "s2", "modelKey": "sensor", "state": "CONNECTED", "name": "Back door", "mac": "m5", "wirelessConnectionState": {"batteryStatus": {"percentage": 80, "isLow": False}}}]
ROUTES.clear()
ROUTES.update({"/meta/info": {"applicationVersion": "7.3.70"}, "/nvrs": {"id": "n1", "modelKey": "nvr", "name": "UNVR", "type": "UNVR-PRO", "mac": "m0", "armMode": {"status": "disarmed"}},
               "/cameras": CAMS, "/lights": [{"id": "l1", "modelKey": "light", "state": "CONNECTED", "name": "Porch", "mac": "m6"}], "/sensors": SENS})
CALLS.clear()
rows = run(dev("unifi_protect", name="nvr1"))
R = by(rows)
check("it calls the Protect integration path", CALLS[0]["url"] == "https://10.0.0.1/proxy/protect/integration/v1/meta/info" and CALLS[0]["headers"]["X-API-KEY"] == "KEY123")
check("the version and the NVR are reported", R[("nvr1", "reachability")].value == "Protect 7.3.70" and R[("nvr1", "nvr")].status == "OK" and R[("nvr1", "nvr")].value == "UNVR")
check("each camera has its state: connected OK, connecting WARN, disconnected FAIL", R[("nvr1 / Front door", "state")].status == "OK" and R[("nvr1 / Yard", "state")].status == "WARN" and R[("nvr1 / Garage", "state")].status == "FAIL")
check("lights and sensors are listed too", ("nvr1 / Porch", "state") in R and ("nvr1 / Basement leak", "state") in R)
check("a device type this Protect does not have (404) is skipped quietly", not [r for r in rows if r.status == "ERROR"])
check("a low sensor battery is flagged (the percentage and the 'low' flag)", R[("nvr1 / Basement leak", "battery")].status == "FAIL" and R[("nvr1 / Basement leak", "battery")].value == "8%"
      and R[("nvr1 / Back door", "battery")].status == "OK" and R[("nvr1 / Back door", "battery")].value == "80%")
check("a leak in the last day is a warning; tampering months ago is not mentioned", R[("nvr1 / Basement leak", "alarms")].status == "WARN" and "water leak" in R[("nvr1 / Basement leak", "alarms")].message
      and "tampering" not in R[("nvr1 / Basement leak", "alarms")].message and ("nvr1 / Back door", "alarms") not in R)
ROUTES["/nvrs"] = {"id": "n1", "modelKey": "nvr", "name": "UNVR", "armMode": {"status": "breach"}}
check("an alarm breach on the NVR is a failure", by(run(dev("unifi_protect", name="nvr1")))[("nvr1", "nvr")].status == "FAIL")
ROUTES["/nvrs"] = [{"id": "n1", "modelKey": "nvr", "name": "UNVR", "armMode": {"status": "armed"}}]
check("an NVR given as a list is understood too", by(run(dev("unifi_protect", name="nvr1")))[("nvr1", "nvr")].message == "alarm armed")
R = by(run(dev("unifi_protect", name="nvr1"), {"disabled": {"unifi_protect:battery", "unifi_protect:alarms", "unifi_protect:nvr"}}))
check("checks can be switched off", ("nvr1 / Basement leak", "battery") not in R and ("nvr1 / Basement leak", "alarms") not in R and ("nvr1", "nvr") not in R)

print("== UniFi Site Manager (the cloud)")
def host_pages(p):
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10 * 86400))
    fresh = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    return ({"data": [{"id": "h1", "type": "console", "ipAddress": "1.2.3.4", "latestBackupTime": old}], "nextToken": "T2", "httpStatusCode": 200} if not p.get("nextToken")
            else {"data": [{"id": "h2", "type": "console", "latestBackupTime": fresh, "isBlocked": False}], "httpStatusCode": 200})
CLOUD_DEVS = {"data": [
    {"hostId": "h1", "hostName": "HQ UDM", "devices": [{"id": "1", "name": "UDM", "status": "online", "isConsole": True, "updateAvailable": None}, {"id": "2", "name": "Switch", "status": "online", "updateAvailable": "7.1.2"},
                                                         {"id": "3", "name": "AP 1", "status": "offline", "updateAvailable": None}]},
    {"hostId": "h2", "hostName": "Branch UDM", "devices": [{"id": "4", "name": "UDM", "status": "offline", "isConsole": True}]}], "httpStatusCode": 200}
CLOUD_SITES = {"data": [
    {"siteId": "st1", "hostId": "h1", "meta": {"name": "HQ", "timezone": "UTC"}, "statistics": {"counts": {"offlineDevice": 1, "totalDevice": 3, "criticalNotification": 0}, "internetIssues": [], "percentages": {"wanUptime": 97.5}}},
    {"siteId": "st2", "hostId": "h2", "meta": {"name": "Branch"}, "statistics": {"counts": {"offlineDevice": 0, "totalDevice": 5}, "internetIssues": [{"type": "latency"}], "percentages": {"wanUptime": 100}}}], "httpStatusCode": 200}
ISP = {"data": [{"metricType": "5m", "hostId": "h1", "siteId": "st1", "periods": [
        {"metricTime": "2026-10-12T08:00:00Z", "data": {"wan": {"avgLatency": 20, "packetLoss": 0, "ispName": "Fiber Co"}}},
        {"metricTime": "2026-10-12T08:05:00Z", "data": {"wan": {"avgLatency": 300, "packetLoss": 2, "ispName": "Fiber Co", "download_kbps": 1, "upload_kbps": 1}}}]},
       {"metricType": "5m", "hostId": "h2", "siteId": "st2", "periods": [{"metricTime": "2026-10-12T08:00:00Z", "data": {"wan": {"avgLatency": 15, "packetLoss": 0}}}]}], "httpStatusCode": 200}
def cloud_routes():
    ROUTES.clear()
    ROUTES.update({"/hosts": host_pages, "/devices": CLOUD_DEVS, "/sites": CLOUD_SITES, "/isp-metrics/5m": ISP,
                   "/sd-wan-configs": {"data": [{"id": "w1", "name": "Mesh", "type": "sdwan-hbsp"}]},
                   "/sd-wan-configs/w1/status": {"data": {"id": "w1", "generateStatus": "OK", "errors": [], "hubs": [{"id": "hub", "applyStatus": "ok"}],
                                                          "spokes": [{"id": "sp", "applyStatus": "ok", "connections": [{"hubId": "hub", "tunnels": [{"status": "connected"}, {"status": "disconnected"}]}]}]}}})
cloud_routes(); CALLS.clear()
cd = dev("unifi_cloud", name="uni-cloud", host="api.ui.com", site="default", verify_ssl=0)
rows = run(cd); R = by(rows)
check("it calls api.ui.com/v1 with the key, and always verifies the certificate", CALLS[0]["url"] == "https://api.ui.com/v1/hosts" and CALLS[0]["headers"]["X-API-KEY"] == "KEY123" and all(c["verify"] is True for c in CALLS))
check("paging follows the next token", [c["params"].get("nextToken") for c in CALLS if c["url"].endswith("/hosts")] == [None, "T2"] and R[("uni-cloud", "reachability")].value == "2 consoles")
check("a console with an offline device is a warning, listing it", R[("uni-cloud / HQ UDM", "devices")].status == "FAIL" and "AP 1" in R[("uni-cloud / HQ UDM", "devices")].message
      and R[("uni-cloud / HQ UDM", "devices")].value == "2/3 online")
check("a console that is itself offline is a failure", R[("uni-cloud / Branch UDM", "devices")].status == "FAIL")
check("firmware updates are listed per console", R[("uni-cloud / HQ UDM", "firmware")].status == "WARN" and "7.1.2" in R[("uni-cloud / HQ UDM", "firmware")].message)
check("each site's health says what is wrong", R[("uni-cloud / HQ", "site health")].status == "WARN" and "1 device offline" in R[("uni-cloud / HQ", "site health")].value
      and R[("uni-cloud / Branch", "site health")].status == "WARN" and "internet issue" in R[("uni-cloud / Branch", "site health")].value)
check("a console whose last backup is 10 days old fails (limit 7), one backed up an hour ago is fine", R[("uni-cloud / HQ UDM", "console")].status == "FAIL" and "10 days" in R[("uni-cloud / HQ UDM", "console")].value
      and R[("uni-cloud / Branch UDM", "console")].status == "OK" and R[("uni-cloud / Branch UDM", "console")].value == "backed up today", [(k, v.value) for k, v in R.items() if k[1] == "console"])
check("WAN uptime is graded, lower being worse", R[("uni-cloud / HQ", "wan uptime")].status == "WARN" and R[("uni-cloud / Branch", "wan uptime")].status == "OK")
check("the latest ISP figures are used (300 ms is a failure, 2% loss a warning)", R[("uni-cloud / HQ", "isp latency")].status == "FAIL" and R[("uni-cloud / HQ", "isp latency")].value == "300 ms"
      and R[("uni-cloud / HQ", "isp loss")].status == "WARN" and R[("uni-cloud / Branch", "isp latency")].status == "OK" and R[("uni-cloud / HQ", "isp latency")].message == "Fiber Co")
check("SD-WAN: a tunnel that is down is a warning", R[("uni-cloud / SD-WAN Mesh", "sd-wan")].status == "WARN" and "1 tunnel down" in R[("uni-cloud / SD-WAN Mesh", "sd-wan")].value)
R = by(run(dev("unifi_cloud", name="uni-cloud", host="api.ui.com", site="branch")))
check("the Site field filters consoles and sites by name", ("uni-cloud / Branch UDM", "devices") in R and ("uni-cloud / HQ UDM", "devices") not in R and ("uni-cloud / HQ", "site health") not in R and ("uni-cloud / Branch", "isp latency") in R)
ROUTES["/sd-wan-configs"] = None
check("an account without SD-WAN is fine", not [r for r in run(cd) if r.status == "ERROR"])
cloud_routes(); ROUTES["/sites"] = 429
try: run(cd); check("a rate limit that persists is explained", False)
except ValueError as e: check("a rate limit that persists is explained", "rate limit" in str(e))
cloud_routes(); ROUTES["/hosts"] = 401
try: run(cd); check("a wrong key is explained", False)
except ValueError as e: check("a wrong key is explained", "API key was rejected" in str(e))
check("api.ui.com is not given a certificate sweep like a device of yours", not runner.sweepable({"vendor": "unifi_cloud", "platform": ""}) and runner.sweepable({"vendor": "unifi_network", "platform": ""}))

print("== through the runner, and the dialog")
net_routes(); real = runner.DRIVERS["unifi_network"]
res = runner.run_one({"name": "udm", "vendor": "unifi_network", "host": "127.0.0.1", "port": 0, "password": "KEY123", "site": "default", "verify_ssl": 0, "enabled": 1}, TH, {**OPTS})
check("a run through the engine gives results, not an error", res and not [r for r in res if r.status == "ERROR"], [(r.check, r.message) for r in res if r.status == "ERROR"])
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
d = I.DeviceDialog()
names = [d.vendor.itemText(i) for i in range(d.vendor.count())]
check("the Vendor box has one UniFi entry, not four", names.count("UniFi") == 1 and not any("API" in n or "Site Manager" in n for n in names) and d.vendor.findData("unifi_network") < 0, names)
d.vendor.setCurrentIndex(d.vendor.findData("unifi"))
check("choosing UniFi offers how to monitor it, console login first", d.platform.count() == 4 and [d.platform.itemData(i) for i in range(4)] == ["unifi", "unifi_network", "unifi_protect", "unifi_cloud"]
      and d.form.labelForField(d.platform).text() == "How to monitor" and d.form.isRowVisible(d.platform), [d.platform.itemData(i) for i in range(d.platform.count())])
check("the first is the console login: user name and password", d.access.labelForField(d.secret).text() == "Password" and d.access.isRowVisible(d.username) and d._vendor() == "unifi"
      and d.checks_tab.listing.count() == len(checks.CATALOG["unifi"]))
d.platform.setCurrentIndex(d.platform.findData("unifi_cloud"))
check("Site Manager fills in api.ui.com and asks for an API key, not a user name", d.host.text() == "api.ui.com" and d.access.labelForField(d.secret).text() == "API key" and not d.access.isRowVisible(d.username) and d._vendor() == "unifi_cloud")
d.platform.setCurrentIndex(d.platform.findData("unifi_network"))
check("Network clears that address (it needs the console's own), has a Site field and its own checks", d.host.text() == "" and d.access.labelForField(d.site).text() == "Site"
      and d.access.labelForField(d.secret).text() == "API key" and d.checks_tab.listing.count() == len(checks.CATALOG["unifi_network"]))
d.platform.setCurrentIndex(d.platform.findData("unifi_protect"))
check("Protect has no Site field and its own checks", not d.access.isRowVisible(d.site) and d.checks_tab.listing.count() == len(checks.CATALOG["unifi_protect"]))
d.name.setText("nvr"); d.host.setText("10.0.0.9")
v = d.values()
check("what is saved is the kind chosen, with no platform", v["vendor"] == "unifi_protect" and v["platform"] == "", (v["vendor"], v["platform"]))
saved = {**v, "id": db.save_device({**v, "password": ""})}
again = I.DeviceDialog(db.get_device(saved["id"]))
check("editing it shows UniFi and the way it is monitored", again.vendor.currentData() == "unifi" and again.vendor.currentText() == "UniFi" and again.platform.currentData() == "unifi_protect"
      and again._vendor() == "unifi_protect" and again.values()["vendor"] == "unifi_protect")
old_login = I.DeviceDialog({"id": 99, "name": "old", "vendor": "unifi", "host": "1.1.1.1", "port": 0, "platform": "", "site": "default", "enabled": 1})
check("an existing console-login device opens as the console login", old_login.platform.currentData() == "unifi" and old_login.values()["vendor"] == "unifi")
other = I.DeviceDialog(); other.vendor.setCurrentIndex(other.vendor.findData("cisco"))
check("other vendors are as they were (a platform, not 'how to monitor')", other.form.labelForField(other.platform).text() == "Platform" and other.platform.count() == 4
      and other.values()["platform"] == "cisco_ios" and other._vendor() == "cisco")

print("== UniFi is one vendor everywhere")
from core import display
for t in ("unifi", "unifi_network", "unifi_protect", "unifi_cloud"):
    check(f"{t} is shown as UniFi", display.vendor_name(t) == "UniFi" and vendors.family(t) == "unifi")
check("the Settings > Checks headings tell them apart", display.type_name("unifi_network") == "UniFi - Network API (API key)" and display.type_name("unifi") == "UniFi - Console login (user name and password)"
      and display.type_name("cisco") == "Cisco" and len({display.type_name(t) for t in ("unifi", "unifi_network", "unifi_protect", "unifi_cloud")}) == 4)
db.save_device({"name": "n-api", "vendor": "unifi_network", "host": "10.1.1.2", "port": 0, "platform": "", "username": "", "site": "default", "verify_ssl": 0, "ha_expected": 0, "enabled": 1})
db.save_device({"name": "c-api", "vendor": "unifi_cloud", "host": "api.ui.com", "port": 0, "platform": "", "username": "", "site": "default", "verify_ssl": 0, "ha_expected": 0, "enabled": 1})
check("one 'Vendor: UniFi' group holds every UniFi device", [g for g in db.group_labels() if g.startswith("Vendor: ")] == ["Vendor: UniFi"]
      and {d["name"] for d in db.list_devices() if db.in_group(d, "Vendor: UniFi")} == {"nvr", "n-api", "c-api"})
tab = I.InventoryTab()
menu_vendors = {tab._build_filter_menu() or None}
check("the Inventory filter has one UniFi entry", [a.text() for a in tab.filter_menu.actions() if a.menu() and a.text() == "Vendor"] != [] and
      sorted(vendors.family(d["vendor"]) for d in db.list_devices() if vendors.family(d["vendor"]) == "unifi") == ["unifi"] * 3)
tab.set_filter("vendor_sel", "unifi")
names_shown = {tab.payload[k]["name"] for k in tab.payload if k.startswith("device:")}
check("filtering by UniFi shows all three kinds", names_shown == {"nvr", "n-api", "c-api"}, names_shown)
tab.set_filter(None, None)
cols = {tab.payload[k]["name"]: tab._device_values(tab.payload[k]) for k in tab.payload if k.startswith("device:")}
check("the table says UniFi, and the Platform column says how it is monitored", cols["nvr"][1] == "UniFi" and cols["nvr"][2] == "Protect API (API key)" and cols["c-api"][2] == "Site Manager in the cloud (API key)")

print("== import and export")
check("an import file says vendor unifi and the platform", importer.normalize({"name": "a", "vendor": "unifi", "platform": "network", "host": "10.2.2.2"})[0]["vendor"] == "unifi_network"
      and importer.normalize({"name": "a", "vendor": "UniFi", "platform": "Protect", "host": "10.2.2.2"})[0]["vendor"] == "unifi_protect"
      and importer.normalize({"name": "a", "vendor": "unifi", "platform": "cloud", "host": "api.ui.com"})[0]["vendor"] == "unifi_cloud")
check("with no platform it is the console login, as before", importer.normalize({"name": "a", "vendor": "unifi", "host": "10.2.2.2"})[0]["vendor"] == "unifi")
check("the long names still work", importer.normalize({"name": "a", "vendor": "unifi_network", "host": "10.2.2.2"})[0]["vendor"] == "unifi_network")
rows = {r["name"]: r for r in importer.export_rows(db.list_devices())}
check("an export writes vendor unifi with the way it is monitored", rows["n-api"]["vendor"] == "unifi" and rows["n-api"]["platform"] == "network" and rows["c-api"]["platform"] == "cloud")
back, _ = importer.normalize({**rows["n-api"], "name": "n-copy", "host": "10.3.3.3"})
check("and it imports back as the same kind", back["vendor"] == "unifi_network")
import ui.settings as ST
pg = ST.ChecksPage(); pg.load()
heads = [pg.tree.topLevelItem(i).text(0) for i in range(pg.tree.topLevelItemCount())]
check("Settings > Checks has a heading for each kind", sum(h.startswith("UniFi") for h in heads) == 4 and len(set(heads)) == len(heads), heads)

print("== a real HTTPS console (self-signed certificate, real requests)")
import http.server, ssl, threading
from core import openssl
key, cert = openssl.make_self_signed({"CN": "console.test"}, "127.0.0.1", "rsa2048", 10)
cdir = os.path.join(SP, "unifi_tls"); os.makedirs(cdir, exist_ok=True)
open(os.path.join(cdir, "c.pem"), "w").write(cert); open(os.path.join(cdir, "k.pem"), "w").write(key)
SEEN = []
class Console(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        SEEN.append((self.path, self.headers.get("X-API-KEY")))
        if self.headers.get("X-API-KEY") != "REALKEY":
            body, code = b'{"message":"unauthorized"}', 401
        else:
            path = urlparse(self.path).path
            hit = ROUTES.get(path[path.index("/v1") + 3:])
            if callable(hit): hit = hit({})
            body, code = (json.dumps(hit).encode(), 200) if hit is not None and not isinstance(hit, int) else (b"{}", 404)
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Console)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(os.path.join(cdir, "c.pem"), os.path.join(cdir, "k.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
UA.requests.get = REAL_GET
net_routes()
real = DRIVERS["unifi_network"](dev("unifi_network", host="127.0.0.1", port=port, password="REALKEY", verify_ssl=0), TH, OPTS).run()
check("a real console is read over HTTPS with the key, and its self-signed certificate is accepted", real[0].check == "reachability" and real[0].value == "Network 10.1.68"
      and SEEN[0][0].startswith("/proxy/network/integration/v1/info") and SEEN[0][1] == "REALKEY", (real[:1], SEEN[:1]))
check("the whole run works the same (devices, statistics, clients)", ("udm / AP Lobby", "cpu") in by(real) and ("udm", "clients") in by(real))
try: DRIVERS["unifi_network"](dev("unifi_network", host="127.0.0.1", port=port, password="REALKEY", verify_ssl=1), TH, OPTS).run(); check("with 'verify' ticked a self-signed certificate is refused", False)
except requests.exceptions.SSLError: check("with 'verify' ticked a self-signed certificate is refused", True)
try: DRIVERS["unifi_network"](dev("unifi_network", host="127.0.0.1", port=port, password="WRONG", verify_ssl=0), TH, OPTS).run(); check("a wrong key is turned away by the console and explained", False)
except ValueError as e: check("a wrong key is turned away by the console and explained", "rejected" in str(e))
srv.shutdown(); srv.server_close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
