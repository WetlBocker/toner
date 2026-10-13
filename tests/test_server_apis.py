# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Proxmox VE, TrueNAS and OPNsense through their APIs, against simulated servers (and a real local HTTPS one for how the key is sent).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, json, os, sys, time
from urllib.parse import urlparse
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "servapi%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingservapi%d" % int(time.time()))
from core import checks, db, importer, vendors
db.init()
import requests
import drivers.restapi as RA
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5, "counter_mode": "total"}
ROUTES, CALLS = {}, []
class Resp:
    def __init__(self, status=200, js=None): self.status_code, self._js = status, js
    def json(self): return self._js
    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
REAL_GET = requests.get
def fake_get(url, params=None, headers=None, auth=None, **kw):
    CALLS.append({"url": url, "headers": headers or {}, "auth": auth, "verify": kw.get("verify")})
    path = urlparse(url).path
    hit = ROUTES.get(path)
    if hit is None: return Resp(404, {})
    if isinstance(hit, int): return Resp(hit, {})
    return Resp(200, hit)
RA.requests.get = fake_get
def run(vendor, **dev):
    d = {"name": "box", "vendor": vendor, "host": "10.0.0.5", "password": "SECRET", "verify_ssl": 0, **dev}
    return {(r.device, r.check): r for r in DRIVERS[vendor](d, TH, OPTS).run()}

print("== the new device types")
for v, label in (("proxmox", "Proxmox VE"), ("truenas", "TrueNAS"), ("opnsense", "OPNsense")):
    check(f"{v}: it is a vendor with a driver and a list of checks, asking for a key and no user name", vendors.VENDORS[v]["name"] == label and v in DRIVERS and checks.CATALOG.get(v) and not vendors.VENDORS[v]["username"])
check("an import file can name them", all(importer.normalize({"name": "a", "vendor": v, "host": "10.2.2.2"})[0]["vendor"] == v for v in ("proxmox", "truenas", "opnsense")))

print("== Proxmox VE")
now = int(time.time())
PVE = {"/api2/json/version": {"data": {"version": "8.1.3", "release": "8.1"}},
       "/api2/json/cluster/status": {"data": [{"type": "cluster", "name": "lab", "quorate": 1, "nodes": 2}, {"type": "node", "name": "pve1", "online": 1}, {"type": "node", "name": "pve2", "online": 0}]},
       "/api2/json/nodes": {"data": [{"node": "pve1", "status": "online", "cpu": 0.35, "mem": 8 * 2**30, "maxmem": 32 * 2**30, "uptime": 90 * 86400}, {"node": "pve2", "status": "offline"}]},
       "/api2/json/cluster/resources": {"data": [{"type": "storage", "storage": "local-lvm", "node": "pve1", "disk": 95, "maxdisk": 100, "status": "available"}, {"type": "storage", "storage": "nfs", "node": "pve1", "disk": 10, "maxdisk": 100, "status": "unknown"},
                                                 {"type": "qemu", "vmid": 100, "name": "web", "status": "running"}, {"type": "qemu", "vmid": 101, "name": "tpl", "status": "stopped", "template": 1}, {"type": "lxc", "vmid": 200, "status": "stopped"}]},
       "/api2/json/cluster/tasks": {"data": [{"type": "qmstart", "id": "100", "status": "OK", "starttime": now - 500, "endtime": now - 490}, {"type": "qmigrate", "id": "100", "status": "migration aborted", "starttime": now - 400, "endtime": now - 300},
                                              {"type": "vzdump", "status": "OK", "starttime": now - 3600, "endtime": now - 3000}, {"type": "vzdump", "status": "job errors", "starttime": now - 7200, "endtime": now - 6000},
                                              {"type": "aptupdate", "status": "WARNINGS: 1", "starttime": now - 100, "endtime": now - 90}, {"type": "old", "status": "boom", "starttime": now - 9 * 86400, "endtime": now - 9 * 86400}]}}
ROUTES.update(PVE); CALLS.clear()
r = run("proxmox", password="root@pam!toner=abc-123")
check("the token is sent the way Proxmox wants it, on port 8006, over HTTPS", CALLS[0]["url"] == "https://10.0.0.5:8006/api2/json/version" and CALLS[0]["headers"]["Authorization"] == "PVEAPIToken=root@pam!toner=abc-123" and CALLS[0]["verify"] is False, CALLS[0])
check("the version", r[("box", "reachability")].value == "Proxmox VE 8.1.3")
check("a cluster that has quorum but a node offline warns, naming it", r[("box", "cluster")].status == "WARN" and "pve2" in r[("box", "cluster")].message and r[("box", "cluster")].value == "1/2 nodes online")
check("each node is its own row set: state, CPU, memory, uptime", r[("box / pve1", "node")].status == "OK" and r[("box / pve1", "cpu")].value == "35%" and r[("box / pve1", "memory")].value == "25%" and r[("box / pve1", "uptime")].value == "90:00:00:00")
check("a node that is offline fails and has nothing else", r[("box / pve2", "node")].status == "FAIL" and ("box / pve2", "cpu") not in r)
check("storage: the fullest at 95% fails, and one that is not available is named", r[("box", "storage")].status == "FAIL" and "nfs on pve1" in r[("box", "storage")].message)
check("guests: templates are not counted", r[("box", "guests")].value == "1 running, 1 stopped")
check("tasks: only failures, only the last day; vzdump and warnings are not failures here", r[("box", "tasks")].status == "WARN" and r[("box", "tasks")].value == "1 failed" and "qmigrate" in r[("box", "tasks")].message, r[("box", "tasks")])
check("backups: a failed backup job fails", r[("box", "backups")].status == "FAIL" and r[("box", "backups")].value == "1 of 2 failed")
ROUTES["/api2/json/cluster/status"] = {"data": [{"type": "node", "name": "solo", "online": 1}]}; ROUTES["/api2/json/cluster/tasks"] = {"data": []}
r = run("proxmox")
check("a single node (no cluster) has no cluster row, and no backups row when none ran", ("box", "cluster") not in r and ("box", "backups") not in r and r[("box", "tasks")].status == "OK")
ROUTES["/api2/json/cluster/status"] = {"data": [{"type": "cluster", "name": "lab", "quorate": 0, "nodes": 2}]}
check("no quorum fails", run("proxmox")[("box", "cluster")].status == "FAIL")
ROUTES["/api2/json/version"] = 401
try: run("proxmox"); check("a rejected token is explained", False)
except ValueError as e: check("a rejected token is explained", "rejected the key" in str(e) and "Proxmox" in str(e))
ROUTES.update(PVE)

print("== TrueNAS")
TN = {"/api/v2.0/system/info": {"version": "TrueNAS-SCALE-23.10.1", "hostname": "nas1", "uptime_seconds": 90 * 86400, "loadavg": [0.5, 9.0, 8.0], "cores": 4},
      "/api/v2.0/pool": [{"name": "tank", "status": "ONLINE", "healthy": True, "size": 10 * 2**40, "allocated": 9 * 2**40, "scan": {"function": "SCRUB", "state": "FINISHED", "errors": 0}},
                         {"name": "fast", "status": "DEGRADED", "healthy": False, "size": 2**40, "allocated": 2**38, "scan": {"function": "SCRUB", "errors": 3}}],
      "/api/v2.0/alert/list": [{"level": "CRITICAL", "formatted": "Pool fast state is DEGRADED", "dismissed": False}, {"level": "WARNING", "formatted": "Old thing", "dismissed": True}, {"level": "INFO", "formatted": "hello", "dismissed": False}]}
ROUTES.clear(); ROUTES.update(TN); CALLS.clear()
r = run("truenas", password="1-KEY")
check("the key is sent as a Bearer token, on 443", CALLS[0]["url"] == "https://10.0.0.5:443/api/v2.0/system/info" and CALLS[0]["headers"]["Authorization"] == "Bearer 1-KEY")
check("version and host name", r[("box", "reachability")].value == "TrueNAS-SCALE-23.10.1" and r[("box", "reachability")].message == "nas1")
check("a healthy pool that is 90% full warns about space (limit 90 fail: at the limit)", r[("box / tank", "pool")].status == "OK" and r[("box / tank", "pool space")].status in ("WARN", "FAIL") and r[("box / tank", "pool space")].value == "90%", r[("box / tank", "pool space")])
check("a degraded pool is reported, with the errors the scrub found", r[("box / fast", "pool")].status in ("WARN", "FAIL") and r[("box / fast", "pool")].value == "degraded" and r[("box / fast", "pool errors")].status == "FAIL")
check("alerts: dismissed and informational ones are left out; a critical one fails", r[("box", "alerts")].status == "FAIL" and r[("box", "alerts")].value == "1 active" and "DEGRADED" in r[("box", "alerts")].message)
check("load is per core (9.0 on 4 cores) and uptime reads in days", r[("box", "load")].status == "WARN" and r[("box", "uptime")].value == "90:00:00:00")
ROUTES["/api/v2.0/alert/list"] = []; ROUTES["/api/v2.0/pool"] = 404
r = run("truenas")
check("no alerts is fine; a server without pools adds no pool rows", r[("box", "alerts")].status == "OK" and not [k for k in r if k[1].startswith("pool")])
ROUTES["/api/v2.0/system/info"] = 403
try: run("truenas"); check("a key without access is explained", False)
except ValueError as e: check("a key without access is explained", "may not read" in str(e))

print("== OPNsense")
OP = {"/api/core/firmware/status": {"status": "update", "product_version": "24.1.5", "upgrade_packages": [{"name": "a"}, {"name": "b"}], "new_packages": [], "status_msg": "There are 2 updates available"},
      "/api/diagnostics/system/systemResources": {"memory": {"total": "8000", "used": "6400"}},
      "/api/diagnostics/system/systemDisk": {"devices": [{"mountpoint": "/", "used_pct": 40}, {"mountpoint": "/var/log", "used_pct": 92}]},
      "/api/diagnostics/system/systemTime": {"uptime": "10 days, 2:03:04", "datetime": "x"},
      "/api/routes/gateway/status": {"items": [{"name": "WAN_GW", "status_translated": "Online", "delay": "1.2 ms", "loss": "0.0 %"}, {"name": "LTE_GW", "status_translated": "Offline", "delay": "~", "loss": "100.0 %"}]}}
ROUTES.clear(); ROUTES.update(OP); CALLS.clear()
r = run("opnsense", password="mykey:mysecret")
check("key and secret go as HTTP Basic credentials", CALLS[0]["auth"] == ("mykey", "mysecret") and CALLS[0]["url"] == "https://10.0.0.5:443/api/core/firmware/status")
check("the version, and updates waiting", r[("box", "reachability")].value == "OPNsense 24.1.5" and r[("box", "firmware")].status == "WARN" and r[("box", "firmware")].value == "2 update(s)")
check("memory 80% warns (limit 80); the fullest filesystem is named", r[("box", "memory")].value == "80%" and r[("box", "disk")].status == "FAIL" and r[("box", "disk")].message == "/var/log")
check("uptime parsed from 'days, h:m:s'", abs(r[("box", "uptime")].numeric - (10 * 24 + 2 + 3 / 60 + 4 / 3600)) < 0.01)
check("each gateway is its own row: online fine, offline fails", r[("box / WAN_GW", "gateway")].status == "OK" and "1.2 ms" in r[("box / WAN_GW", "gateway")].message and r[("box / LTE_GW", "gateway")].status == "FAIL")
check("an up-to-date firewall says so", (ROUTES.update({"/api/core/firmware/status": {"status": "none", "product_version": "24.1.5"}}), run("opnsense")[("box", "firmware")].value)[1] == "up to date")
ROUTES["/api/core/firmware/status"] = 401
try: run("opnsense"); check("a rejected key is explained", False)
except ValueError as e: check("a rejected key is explained", "OPNsense rejected the key" in str(e))

print("== how the key really travels (a real local HTTPS server)")
import http.server, ssl, threading
from core import openssl
key, cert = openssl.make_self_signed({"CN": "box.test"}, "127.0.0.1", "rsa2048", 10)
cdir = os.path.join(SP, "serv_tls"); os.makedirs(cdir, exist_ok=True)
open(os.path.join(cdir, "c.pem"), "w").write(cert); open(os.path.join(cdir, "k.pem"), "w").write(key)
SEEN = []
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        SEEN.append((self.path, self.headers.get("Authorization")))
        body = json.dumps({"data": {"version": "8.0"}} if "/api2/" in self.path else {"version": "TrueNAS", "hostname": "h", "loadavg": [0, 0, 0], "cores": 1, "uptime_seconds": 999999} if "/api/v2.0/system/info" in self.path
                          else {"status": "none", "product_version": "24"}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(os.path.join(cdir, "c.pem"), os.path.join(cdir, "k.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
RA.requests.get = REAL_GET
DRIVERS["proxmox"]({"name": "p", "vendor": "proxmox", "host": "127.0.0.1", "port": port, "password": "u@pam!t=1", "verify_ssl": 0}, TH, OPTS).data("/version")
DRIVERS["truenas"]({"name": "t", "vendor": "truenas", "host": "127.0.0.1", "port": port, "password": "KEY", "verify_ssl": 0}, TH, OPTS).get("/system/info")
DRIVERS["opnsense"]({"name": "o", "vendor": "opnsense", "host": "127.0.0.1", "port": port, "password": "k:s", "verify_ssl": 0}, TH, OPTS).get("/api/core/firmware/status")
got = dict((p.split("/")[1] if p.startswith("/api2") else p, a) for p, a in SEEN)
check("Proxmox sends the PVEAPIToken header", any(a == "PVEAPIToken=u@pam!t=1" for _, a in SEEN))
check("TrueNAS sends a Bearer token", any(a == "Bearer KEY" for _, a in SEEN))
check("OPNsense sends Basic credentials (key:secret, base64)", any(a == "Basic " + base64.b64encode(b"k:s").decode() for _, a in SEEN), SEEN)
try: DRIVERS["truenas"]({"name": "t", "vendor": "truenas", "host": "127.0.0.1", "port": port, "password": "KEY", "verify_ssl": 1}, TH, OPTS).get("/system/info"); check("with 'verify' ticked a self-signed certificate is refused", False)
except requests.exceptions.SSLError: check("with 'verify' ticked a self-signed certificate is refused", True)
srv.shutdown(); srv.server_close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
