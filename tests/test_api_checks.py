# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The extra checks on Fortinet, Palo Alto and Meraki: readers tested on samples of the APIs' answers, and the drivers against a simulated API.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "apichk%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingapichk%d" % int(time.time()))
from core import checks, db
db.init()
import drivers.fortinet as FG, drivers.paloalto as PA, drivers.meraki as ME
from drivers import DRIVERS, apichecks as A
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

NOW = datetime.now(timezone.utc)
def ep(days): return int((NOW + timedelta(days=days)).timestamp())
TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5}
class Resp:
    def __init__(self, content=b"", status=200, js=None):
        self.content, self.status_code, self._js, self.headers, self.links = content, status, js, {}, {}
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests; e = requests.HTTPError(str(self.status_code)); e.response = self; raise e
    def json(self): return self._js

print("== Fortinet, from the API's answers")
lic = {"forticare": {"status": "registered", "support": {"hardware": {"status": "licensed", "expires": ep(400)}, "enhanced": {"status": "licensed", "expires": ep(20)}}},
       "fortiguard": {"antivirus": {"status": "licensed", "expires": ep(200)}, "ips": {"status": "licensed", "expires": ep(100)}}}
found = A.fortinet_licenses(lic, NOW)
check("every entitlement with an expiry is found, wherever it is nested, and named", sorted((n, round(d)) for n, d, _ in found) == [("antivirus", 200), ("enhanced", 20), ("hardware", 400), ("ips", 100)] or len(found) == 4, found)
check("a reply with nothing in it gives nothing", A.fortinet_licenses({}, NOW) == [] and A.fortinet_licenses(None, NOW) == [])
certs = [{"name": "Fortinet_Factory", "source": "factory", "valid_to": ep(5)}, {"name": "vpn.corp", "source": "user", "valid_to": ep(12)}, {"name": "old", "source": "user", "valid_to": ep(-3)}, {"name": "x", "source": "user"}]
check("certificates: factory ones are ignored, days counted, expired ones negative", [(n, round(d)) for n, d in A.fortinet_cert_days(certs, NOW)] == [("vpn.corp", 12), ("old", -3)])
ha = [{"serial_no": "A", "checksum": [{"name": "global", "checksum": "1"}, {"name": "root", "checksum": "2"}]}, {"serial_no": "B", "checksum": [{"name": "global", "checksum": "1"}, {"name": "root", "checksum": "9"}]}]
check("HA checksums: the parts that differ", A.fortinet_ha_sync(ha) == ["root"] and A.fortinet_ha_sync([ha[0], ha[0]]) == [] and A.fortinet_ha_sync([ha[0]]) is None and A.fortinet_ha_sync("x") is None)
check("log disk percent and managed devices", abs(A.fortinet_log_disk({"used": 80, "total": 100}) - 80) < 1e-9 and A.fortinet_log_disk({}) is None
      and A.fortinet_status_list([{"name": "a", "status": "online"}, {"name": "b", "status": "offline"}, {"serial": "S1", "connection_status": "Disconnected"}]) == (1, ["b", "S1"]))

print("== Fortinet, the driver")
FGDATA = {"system/resource/usage?scope=global": {"cpu": [{"current": 10}], "mem": [{"current": 30}]}, "system/status": {"hostname": "fw", "model_name": "FortiGate", "model_number": "VM64"},
          "system/interface?scope=global": {"port1": {"type": "physical", "link": True, "rx_errors": 0, "tx_errors": 3, "role": "lan"}, "wan1": {"type": "physical", "link": False, "status": "up", "role": "wan"},
                                            "vlan10": {"type": "vlan", "link": True}},
          "system/ha-peer": [], "vpn/ipsec": [], "license/status": lic, "system/available-certificates": certs, "system/ha-checksums": ha,
          "wifi/managed_ap": [{"name": "ap1", "status": "online"}, {"name": "ap2", "status": "offline"}], "switch-controller/managed-switch/status": [{"name": "sw1", "status": "Connected"}],
          "log/current-disk-usage": {"used": 95, "total": 100}}
def fg_get(url, headers=None, **kw):
    path = url.split("/api/v2/monitor/")[-1]
    if path in FGDATA: return Resp(js={"results": FGDATA[path], "serial": "FGVM000000000001", "version": "v8.0.0", "build": 167, "status": "success"})   # (as FortiOS answers)
    return Resp(status=404)
FG.requests.get = fg_get
def fg_run(**dev):
    d = {"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "TOK", **dev}
    return {r.check: r for r in DRIVERS["fortinet"](d, TH, OPTS).run()}
r = fg_run()
check("firmware: the version FortiOS puts beside results, not in them", r["firmware"].value == "v8.0.0", r.get("firmware"))
fg_drv = FG.FortinetDriver({"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "TOK"}, TH, OPTS); fg_drv.run()
check("...and it is kept as the device's version", fg_drv.facts.get("software", {}).get("version") == "v8.0.0", fg_drv.facts)
check("the subscription that ends first decides: 20 days is a failure (limit 30), and it is named", r["licenses"].status == "FAIL" and "enhanced" in r["licenses"].message and r["licenses"].value == "20 days", r["licenses"])
check("a certificate you manage that ends in 12 days warns; the expired one is the one named", r["certificates"].value == "expired" and r["certificates"].status == "FAIL" and r["certificates"].message == "old", r["certificates"])
check("interfaces: the wan port that is down, VLANs left out, errors counted", r["interfaces"].value == "1/2 up" and "wan1" in r["interfaces"].message and "interface errors" in r, {k: v.value for k, v in r.items() if "interface" in k})
check("any interface that is down is a FAIL, and it is named", r["interfaces"].status == "FAIL" and r["interfaces"].message == "down: wan1", r["interfaces"])
r = fg_run(checkopts='{"interfaces": ["port1"]}')
check("limited to port1 (up): OK, and the wan port is not read at all", r["interfaces"].status == "OK" and r["interfaces"].value == "1/1 up" and "wan1" not in r["interfaces"].message, r["interfaces"])
check("its errors are read only for the chosen ones too", r["interface errors"].value == "1" and "port1" in r["interface errors"].message, r["interface errors"])
r = fg_run(checkopts='{"interfaces": ["WAN1"]}')
check("names match whatever their case; the chosen one is down, so FAIL, and there are no errors to read on a port with no link", r["interfaces"].status == "FAIL" and r["interfaces"].message == "down: wan1" and "interface errors" not in r, r["interfaces"])
r = fg_run(checkopts='{"interfaces": ["port1", "port7"]}')
check("a chosen port the firewall does not have is a WARN", r["interfaces"].status == "WARN" and "port7" in r["interfaces"].message, r["interfaces"])
check("the firewall lists its physical ports for the picker (VLANs left out)", FG.FortinetDriver({"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "TOK"}, TH, OPTS).list_interfaces() == [("port1", "up"), ("wan1", "down")])
check("HA sync: out of sync, and which part", r["ha sync"].status == "WARN" and "root" in r["ha sync"].message)
check("FortiAP offline warns, FortiSwitches fine", r["fortiaps"].status == "WARN" and "ap2" in r["fortiaps"].message and r["fortiswitches"].status == "OK")
check("log disk 95% fails", r["log disk"].status == "FAIL" and r["log disk"].value == "95%")
FGDATA.pop("license/status"); FGDATA.pop("wifi/managed_ap"); FGDATA.pop("system/ha-checksums")
r = fg_run()
check("a feature the firewall does not have (404) adds no row and no error", not ({"licenses", "fortiaps", "ha sync"} & set(r)) and not [k for k, v in r.items() if v.status == "ERROR"])

print("== a rejected key is said once, in words")
FGDATA_SAVE = dict(FGDATA)
def fg_denied(url, headers=None, **kw): return Resp(status=401)
FG.requests.get = fg_denied
try: fg_run(); check("Fortinet: a rejected token stops the run with one reason", False)
except ValueError as e: check("Fortinet: a rejected token stops the run with one reason", "rejected the API token" in str(e) and "401" in str(e) and "trusted hosts" in str(e) and "/api/v2" not in str(e), e)
FG.requests.get = lambda url, headers=None, **kw: Resp(status=403)
try: fg_run(); check("Fortinet: a token that may not read says so", False)
except ValueError as e: check("Fortinet: a token that may not read says so", "refused the API token" in str(e) and "403" in str(e), e)
FG.requests.get = fg_get
check("with a good token nothing changes", fg_run()["interfaces"].value == "1/2 up")
rows = []
class Boom(Exception): pass
import requests as _rq
d0 = DRIVERS["fortinet"]({"name": "fw", "vendor": "fortinet", "host": "h", "password": "x"}, TH, OPTS)
def http_err():
    e = _rq.HTTPError("403 Client Error: Forbidden for url: https://h/api/?cmd=%3Cshow%3E"); e.response = Resp(status=500); raise e
d0.safe(rows, "something", http_err)
check("any other HTTP error row says the code, not the long address", rows[0].status == "ERROR" and rows[0].message == "the device's API answered HTTP 500", rows[0].message)
rows.clear(); e403 = _rq.HTTPError("x"); e403.response = Resp(status=403)
d0.safe(rows, "x", lambda: (_ for _ in ()).throw(e403))
check("403 and 404 get a short hint", "may not read" in rows[0].message)

print("== Palo Alto, from the API's answers")
def el(xml): return ET.fromstring(xml)
lic_x = el("<licenses><entry><feature>Threat Prevention</feature><expires>November 30, 2026</expires><expired>no</expired></entry><entry><feature>Support</feature><expires>Never</expires><expired>no</expired></entry><entry><feature>WildFire</feature><expires>June 01, 2026</expires><expired>yes</expired></entry></licenses>")
got = A.pan_licenses(lic_x.findall("entry"), date(2026, 10, 12))
check("licences: days left, 'Never' has none, an expired one is marked", got == [("Threat Prevention", 49, False), ("Support", None, False), ("WildFire", -133, True)], got)
sysx = el("<system><app-version>8700-7777</app-version><app-release-date>2026/09/20 18:20:17 PDT</app-release-date><threat-version>8700-7777</threat-version><threat-release-date>2026/10/09 18:20:17 PDT</threat-release-date><av-release-date>2026/08/01 00:00:00 PDT</av-release-date></system>")
check("content packages: the age of each in days", sorted(A.pan_content_ages(sysx, date(2026, 10, 12))) == [("app", 22), ("av", 72), ("threat", 3)], A.pan_content_ages(sysx, date(2026, 10, 12)))
df = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/root       7.0G  5.1G  1.5G  78% /\n/dev/sda5        15G  9.0G  5.2G  64% /opt/pancfg\ntmpfs           1.9G     0  1.9G   0% /dev/shm\n/dev/sda8        78G   75G  1.5G  98% /opt/panlogs\n"
check("disk: the fullest real partition", A.pan_disk(df) == (98, "/opt/panlogs") and A.pan_disk("nothing") is None)
check("Panorama: connected, not connected, and none configured", A.pan_panorama("Panorama Server 1 : 10.1.1.5\n    Connected     : yes\n") is True and A.pan_panorama("Panorama Server 1 : 10.1.1.5\n    Connected     : no\n") is False and A.pan_panorama("Panorama Server 1 :\n") is None)
jobs = el("<jobs><job><id>10</id><type>Commit</type><result>OK</result><tfin>2026/10/01 10:00:00</tfin></job><job><id>12</id><type>Commit</type><result>FAIL</result><tfin>2026/10/10 10:00:00</tfin></job><job><id>13</id><type>Download</type><result>OK</result></job></jobs>")
check("last commit: the newest commit job, whatever else ran since", A.pan_last_commit(jobs.findall("job")) == ("FAIL", "2026/10/10 10:00:00") and A.pan_last_commit([]) is None)

print("== Palo Alto, the driver")
def xml(body): return f'<response status="success">{body}</response>'.encode()
PAN = {"<show><system><info/></system></show>": xml("<result><system><sw-version>11.1.2</sw-version><model>PA-440</model><uptime>12 days, 3:04:05</uptime><app-release-date>2026/08/01 00:00:00 PDT</app-release-date></system></result>"),
       "<request><license><info/></license></request>": xml(f"<result><licenses><entry><feature>Threat Prevention</feature><expires>{(date.today() + timedelta(days=20)).strftime('%B %d, %Y')}</expires><expired>no</expired></entry></licenses></result>"),
       "<show><system><disk-space/></system></show>": xml("<result><![CDATA[" + df + "]]></result>"),
       "<show><panorama-status/></show>": xml("<result><![CDATA[Panorama Server 1 : 10.1.1.5\n    Connected     : no\n]]></result>"),
       "<show><jobs><all/></jobs></show>": xml("<result><job><id>12</id><type>Commit</type><result>FAIL</result><tfin>2026/10/10 10:00:00</tfin></job></result>")}
def pan_get(url, params=None, headers=None, **kw):
    body = PAN.get(params["cmd"])
    return Resp(body) if body else Resp(xml("<msg>bad command</msg>").replace(b"success", b"error"))
PA.requests.get = pan_get
def pan_run(**dev):
    d = {"name": "pa", "vendor": "paloalto", "host": "10.0.0.5", "password": "KEY", **dev}
    return {r.check: r for r in DRIVERS["paloalto"](d, TH, {**OPTS}).run()}
r = pan_run()
check("licence: ends in under 30 days fails (limit 30), and is named", r["licenses"].status in ("FAIL", "WARN") and "Threat Prevention" in r["licenses"].message and "days" in r["licenses"].value, r["licenses"])
check("content: 72-day-old antivirus/app content fails", r["content"].status == "FAIL" and r["content"].value.endswith("days"), r["content"])
check("disk: the logs partition at 98% fails", r["disk"].status == "FAIL" and r["disk"].value == "98%")
check("Panorama not reachable warns", r["panorama"].status == "WARN" and "Panorama" in r["panorama"].message)
check("the last commit failed", r["last commit"].status == "FAIL" and r["last commit"].value == "fail")
PA.requests.get = lambda url, params=None, headers=None, **kw: Resp(b'<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>', status=403)
try: pan_run(); check("Palo Alto: a rejected key stops the run with one reason", False)
except ValueError as e:
    m = str(e)
    check("Palo Alto: a rejected key stops the run with one reason", m.startswith("Palo Alto rejected the API key (Invalid Credential)") and "/api/?type=op" not in m and "%3C" not in m, m)
PA.requests.get = lambda url, params=None, headers=None, **kw: Resp(b"", status=403)
try: pan_run(); check("Palo Alto: with no message from the firewall the code is named", False)
except ValueError as e: check("Palo Alto: with no message from the firewall the code is named", "(HTTP 403)" in str(e), e)
PA.requests.get = lambda url, params=None, headers=None, **kw: Resp(b"", status=500)
r = pan_run()
check("Palo Alto: any other failure is reported per check, without the address", r["resources"].status == "ERROR" and r["resources"].message == "the device's API answered HTTP 500", r["resources"])
from core.runner import run_one
PA.requests.get = lambda url, params=None, headers=None, **kw: Resp(b'<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>', status=403)
rows = [r for r in run_one({"name": "pa", "vendor": "paloalto", "host": "127.0.0.1", "password": "KEY", "checkopts": "", "location": ""}, TH, {**OPTS, "retries": 3, "retry_delay": 0})
        if r.check != "reachability"]                     # the TCP reachability row comes first, before the login
check("in a run it is one 'connection' row, in words, not retried", len(rows) == 1 and rows[0].check == "connection" and rows[0].message.startswith("Palo Alto rejected the API key (Invalid Credential)") and "AuthRejected" not in rows[0].message, rows)
PA.requests.get = pan_get

print("== Meraki, from the API's answers")
alerts = [{"severity": "critical", "title": "Device offline", "network": {"name": "HQ"}}, {"severity": "warning", "title": "High CPU", "network": {"name": "HQ"}},
          {"severity": "informational", "title": "x"}, {"severity": "critical", "title": "Old", "resolvedAt": "2026-10-01T00:00:00Z"}]
check("alerts: active critical and warning ones, resolved ones ignored", A.meraki_alerts(alerts) == (1, 1, ["HQ Device offline", "HQ High CPU"]), A.meraki_alerts(alerts))
vpn = [{"networkName": "HQ", "merakiVpnPeers": [{"networkName": "Branch", "reachability": "reachable"}, {"networkName": "Depot", "reachability": "unreachable"}], "thirdPartyVpnPeers": [{"name": "AWS", "reachability": "reachable"}]}]
check("VPN: the unreachable peers", A.meraki_vpn(vpn) == (3, ["HQ to Depot"]))
q = [{"serial": "Q1", "uplink": "wan1", "timeSeries": [{"lossPercent": 0, "latencyMs": 10}, {"lossPercent": 6, "latencyMs": 40}]}, {"serial": "Q2", "uplink": "wan1", "timeSeries": [{"lossPercent": 0, "latencyMs": 300}, {"lossPercent": None, "latencyMs": None}]}]
check("uplink quality: the latest sample that has numbers on each uplink, and the worst of them", A.meraki_uplink_quality(q) == (6.0, 300.0, "Q2 wan1"), A.meraki_uplink_quality(q))

print("== Meraki, the driver")
MDATA = {"/organizations": [{"id": "111", "name": "Acme"}], "/organizations/111/devices/statuses": [{"name": "MX-1", "serial": "Q1", "status": "online"}],
         "/organizations/111/assurance/alerts": alerts, "/organizations/111/configurationChanges": [{"adminName": "ann"}, {"adminName": "bob"}, {"adminName": "ann"}],
         "/organizations/111/appliance/vpn/statuses": vpn, "/organizations/111/devices/uplinksLossAndLatency": q}
def mer_get(url, params=None, headers=None, **kw):
    path = url.split("/api/v1")[-1].split("?")[0]
    return Resp(js=MDATA[path]) if path in MDATA else Resp(status=404)
ME.requests.get = mer_get
def mer_run(**dev):
    d = {"name": "mer", "vendor": "meraki", "host": "api.meraki.com", "password": "K", "site": "Acme", **dev}
    return {r.check: r for r in DRIVERS["meraki"](d, TH, {**OPTS}).run()}
r = mer_run()
check("alerts: a critical one fails, with the titles", r["alerts"].status == "FAIL" and r["alerts"].value == "1 critical, 1 warning" and "Device offline" in r["alerts"].message)
check("config changes: counted, with who made them", r["config changes"].value == "3 in 24 h" and "ann" in r["config changes"].message and "bob" in r["config changes"].message and r["config changes"].status == "OK")
check("VPN: an unreachable peer warns", r["vpn"].status == "WARN" and r["vpn"].value == "2/3 reachable" and "HQ to Depot" in r["vpn"].message)
check("uplink quality: 6% loss fails (limit 5), the uplink is named", r["uplink quality"].status == "FAIL" and "Q2 wan1" in r["uplink quality"].message, r["uplink quality"])
MDATA.pop("/organizations/111/assurance/alerts"); MDATA.pop("/organizations/111/appliance/vpn/statuses")
r = mer_run()
check("an organization without those features adds no rows and no errors", not ({"alerts", "vpn"} & set(r)) and not [k for k, v in r.items() if v.status == "ERROR"])

print("== the catalog and limits")
check("the new checks are listed", {"licenses", "certificates", "ha sync", "fortiaps", "log disk"} <= {k for k, _ in checks.CATALOG["fortinet"]} and {"licenses", "content", "disk", "panorama", "last commit"} <= {k for k, _ in checks.CATALOG["paloalto"]}
      and {"alerts", "config changes", "vpn", "uplink quality"} <= {k for k, _ in checks.CATALOG["meraki"]})
check("Palo Alto content age has its limit", "content_age" in db.DEFAULT_THRESHOLDS)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
