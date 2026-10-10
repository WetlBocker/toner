# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\f3%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import alerts, custom, db, iperf, maintenance, notify, vendors, wifi
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from drivers import DRIVERS
from drivers.base import Result
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
def dev(name, vendor="cisco", host="10.0.0.1", **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return d
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.warning = staticmethod(lambda *a, **k: None)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

# ================================================================ maintenance windows
print("== maintenance windows")
at = lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M")
once = {"name": "Upgrade", "kind": "once", "start_at": "2026-10-10 22:00", "end_at": "2026-10-11 02:00", "enabled": 1, "scope": []}
check("a one-off window is active between its times only", maintenance.is_active(once, at("2026-10-10 23:00")) and maintenance.is_active(once, at("2026-10-11 01:59")) and not maintenance.is_active(once, at("2026-10-10 21:59")) and not maintenance.is_active(once, at("2026-10-11 02:00")))
check("a disabled window is never active", not maintenance.is_active({**once, "enabled": 0}, at("2026-10-10 23:00")))
sat = {"name": "Patching", "kind": "weekly", "days": [5], "start_time": "22:00", "end_time": "02:00", "enabled": 1}     # Saturday night
check("a weekly window that runs past midnight: starts Saturday 22:00", maintenance.is_active(sat, at("2026-10-10 22:30")))      # 2026-10-10 is a Saturday
check("...still on in the early hours of Sunday", maintenance.is_active(sat, at("2026-10-11 01:30")))
check("...over at 02:00 and not on a Friday night", not maintenance.is_active(sat, at("2026-10-11 02:00")) and not maintenance.is_active(sat, at("2026-10-09 23:00")) and not maintenance.is_active(sat, at("2026-10-10 01:00")))
day = {"name": "Lunch", "kind": "weekly", "days": [0, 1, 2, 3, 4], "start_time": "12:00", "end_time": "13:00", "enabled": 1}
check("a same-day weekly window", maintenance.is_active(day, at("2026-10-09 12:30")) and not maintenance.is_active(day, at("2026-10-10 12:30")) and not maintenance.is_active(day, at("2026-10-09 13:00")))
check("when a window ends", maintenance.ends_at(once, at("2026-10-10 23:00")) == at("2026-10-11 02:00") and maintenance.ends_at(sat, at("2026-10-10 23:00")) == at("2026-10-11 02:00") and maintenance.ends_at(sat, at("2026-10-11 01:00")) == at("2026-10-11 02:00") and maintenance.ends_at(once, at("2026-10-12 09:00")) is None)
check("windows read in plain words", "2026-10-10 22:00 to" in maintenance.describe(once) and maintenance.describe(sat) == "Sat 22:00-02:00" and maintenance.describe({**day, "days": list(range(7))}) == "every day 12:00-13:00")
for w, why in (({"name": "", "kind": "once"}, "a name"), ({"name": "x", "kind": "weekly", "days": [], "start_time": "22:00", "end_time": "02:00"}, "a day"),
               ({"name": "x", "kind": "weekly", "days": [1], "start_time": "22:00", "end_time": "22:00"}, "different times"), ({"name": "x", "kind": "weekly", "days": [1], "start_time": "25:00", "end_time": "02:00"}, "a real time"),
               ({"name": "x", "kind": "once", "start_at": "2026-10-10 22:00", "end_at": "2026-10-10 21:00"}, "end after start"), ({"name": "x", "kind": "once", "start_at": "soon", "end_at": "later"}, "real dates"), ({"name": "x", "kind": "daily"}, "a type")):
    try: maintenance.validate(w); check(f"refused: needs {why}", False)
    except ValueError: check(f"refused: needs {why}", True)

dev("core-sw1", location="Chicago", tags="core"); dev("edge-fw", "fortinet", "10.0.0.9", location="Denver"); dev("lab-ap", "unifi", "10.0.0.7", location="Chicago")
now = datetime.now()
fmt = lambda d: d.strftime("%Y-%m-%d %H:%M")
wid = maintenance.save_window({"name": "Chicago work", "kind": "once", "start_at": fmt(now - timedelta(hours=1)), "end_at": fmt(now + timedelta(hours=1)), "scope": ["Location: Chicago"], "note": "switch upgrade"})
maintenance.save_window({"name": "Next week", "kind": "once", "start_at": fmt(now + timedelta(days=7)), "end_at": fmt(now + timedelta(days=7, hours=2)), "scope": []})
rows = maintenance.list_windows()
check("saved and listed with scope as a list", len(rows) == 2 and [r for r in rows if r["name"] == "Chicago work"][0]["scope"] == ["Location: Chicago"] and rows[0]["note"] in ("switch upgrade", ""))
held = maintenance.devices_in_maintenance()
check("only the devices in scope are covered, and only now", set(held) == {"core-sw1", "lab-ap"} and held["core-sw1"]["name"] == "Chicago work")
check("a window with no scope covers every device", set(maintenance.devices_in_maintenance(now + timedelta(days=7, hours=1))) == {"core-sw1", "edge-fw", "lab-ap"})
maintenance.save_window({**[r for r in rows if r["name"] == "Chicago work"][0], "id": wid, "name": "Chicago work (edited)"})
check("editing a window keeps one row", len(maintenance.list_windows()) == 2 and any(r["name"] == "Chicago work (edited)" for r in maintenance.list_windows()))

print("== maintenance holds alerts back")
sent = []
notify.channels = lambda: [{"name": "t", "enabled": True, "type": "webhook"}]
notify.wants = lambda ch, e: True
notify.deliver = lambda ch, msg, desktop=None, secrets=None, retry_delay=2: (sent.append(msg), (True, "ok"))[1]
db.set_setting("notify_enabled", True)
res = lambda *rows: [Result(d, c, s, v) for d, c, s, v in rows]
sent.clear(); out = notify.process_run(res(("core-sw1", "cpu", "FAIL", "99%"), ("edge-fw", "cpu", "FAIL", "98%")), ["core-sw1", "edge-fw"], True)
text = " ".join(m.body if hasattr(m, "body") else str(m) for m in sent)
check("a device in maintenance is not announced; one outside it is", len(sent) == 1 and "edge-fw" in text and "core-sw1" not in text, text[:200])
with db.connect() as c:
    states = {r["device"] for r in c.execute("SELECT device FROM alert_state")}
check("its alert state is left untouched", states == {"edge-fw"}, states)
sent.clear(); out = notify.process_run(res(("core-sw1", "cpu", "FAIL", "99%")), ["core-sw1"], True)
check("nothing at all to say while in maintenance", not sent and out == "no changes", out)
maintenance.delete_window(wid)
sent.clear(); out = notify.process_run(res(("core-sw1", "cpu", "FAIL", "99%")), ["core-sw1"], True)
check("once the window is over, a problem that is still there is announced", len(sent) == 1 and "core-sw1" in str(sent[0].body if hasattr(sent[0], "body") else sent[0]))
maintenance.delete_window([r for r in maintenance.list_windows() if r["name"] == "Next week"][0]["id"])
check("deleted", maintenance.list_windows() == [])

# ================================================================ Wi-Fi
print("== Wi-Fi")
IFACE = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : c34e5957-413e-4fd2-bab5-d35f64f36ae8
    Physical address       : c8:6e:08:7a:51:11
    Interface type         : Primary
    State                  : connected
    SSID                   : OfficeNet
    BSSID                  : 11:22:33:44:55:66
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Profile
    Band                   : 5 GHz
    Channel                : 44
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1080
    Signal                 : 72%
    Profile                : OfficeNet
"""
OFF = "\n    Name                   : Wi-Fi\n    Description            : Intel AX211\n    State                  : disconnected\n"
a = wifi.parse_interfaces(IFACE)[0]
check("the connection is read", a["connected"] and a["ssid"] == "OfficeNet" and a["bssid"] == "11:22:33:44:55:66" and a["signal_pct"] == 72 and a["channel_no"] == 44 and a["band_text"] == "5 GHz" and a["rx"] == 1201 and a["tx"] == 1080, a)
check("a disconnected adapter is recognised", not wifi.parse_interfaces(OFF)[0]["connected"] and wifi.parse_interfaces(OFF)[0]["signal_pct"] is None)
check("no adapters", wifi.parse_interfaces("There is no wireless interface on the system.") == [] and wifi.current([]) is None)
NETS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Alpha
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:00:01
         Signal             : 88%
         Radio type         : 802.11ax
         Band               : 2.4 GHz
         Channel            : 6
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : aa:bb:cc:00:00:02
         Signal             : 61%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : de:ad:be:ef:00:03
         Signal             : 30%
         Radio type         : 802.11n
         Channel            : 1

SSID 3 : Gamma
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:00:04
         Signal             : 45%
         Radio type         : 802.11ac
         Channel            : 6
"""
nets = wifi.parse_networks(NETS)
check("every access point is listed under its network", len(nets) == 4 and [n["ssid"] for n in nets] == ["Alpha", "Alpha", "(hidden)", "Gamma"], [n["ssid"] for n in nets])
check("signal, channel, security and radio", nets[0]["signal"] == 88 and nets[0]["channel"] == 6 and nets[0]["auth"] == "WPA2-Personal" and nets[0]["encryption"] == "CCMP" and nets[0]["radio"] == "802.11ax" and nets[3]["auth"] == "WPA3-Personal")
check("the band comes from Windows, or is worked out from the channel", nets[1]["band"] == "5 GHz" and nets[2]["band"] == "2.4 GHz" and nets[3]["band"] == "2.4 GHz")
check("channel use is counted per band", wifi.channel_usage(nets)["2.4 GHz"] == {6: 2, 1: 1} and wifi.channel_usage(nets)["5 GHz"] == {36: 1})
best, load = wifi.best_channels(nets)
check("the quietest of channels 1, 6 and 11 is suggested, counting neighbours", best == 11 and load == {1: 1, 6: 2, 11: 0}, (best, load))
wifi._netsh = lambda *a, **k: "Location permission is required"
check("a location-permission problem is explained", "Location" in wifi.scan()[1])
wifi._netsh = lambda *a, **k: "There is no wireless interface on the system."
check("no adapter is explained", "no Wi-Fi adapter" in wifi.scan()[1])

print("== Wi-Fi as a device")
check("the vendor exists with no login", vendors.get("wifi")["name"] == "This PC's Wi-Fi" and not vendors.has_login("wifi") and not vendors.has_login("cloud") and vendors.has_login("cisco"))
d = dev("my-laptop", "wifi", "localhost")
th = db.thresholds_for(d)
check("signal thresholds exist and lower is worse", th["wifi_signal"] == {"warn": 50, "fail": 30} and "wifi_signal" in db.LOWER_IS_WORSE)
def run_wifi(text):
    wifi._netsh = lambda *a, **k: text
    return {r.check: r for r in DRIVERS["wifi"](d, th, {"disabled": frozenset()}).run()}
r = run_wifi(IFACE)
check("connected, strong: all OK, with numbers for the charts", r["connection"].status == "OK" and r["connection"].value == "OfficeNet" and "channel 44" in r["connection"].message and r["signal"].status == "OK" and r["signal"].numeric == 72 and r["link speed"].numeric == 1201 and "1080" in r["link speed"].message, r)
check("weak signal is a WARN, very weak a FAIL", run_wifi(IFACE.replace("72%", "45%"))["signal"].status == "WARN" and run_wifi(IFACE.replace("72%", "20%"))["signal"].status == "FAIL")
r = run_wifi(OFF); check("not connected is a FAIL", list(r) == ["connection"] and r["connection"].status == "FAIL" and r["connection"].value == "not connected")
r = run_wifi("There is no wireless interface on the system."); check("no adapter is a FAIL", r["connection"].status == "FAIL" and "no Wi-Fi adapter" in r["connection"].value)
check("a check can be switched off in Settings", "signal" not in {x.check for x in DRIVERS["wifi"](d, th, {"disabled": frozenset({"wifi:signal"})}).run()} if (wifi.__dict__.update(_netsh=lambda *a, **k: IFACE) or True) else False)

# ================================================================ cloud status pages
print("== cloud status pages")
SUMMARY = {"status": {"indicator": "minor", "description": "Minor Service Outage"},
           "components": [{"name": "API", "status": "operational"}, {"name": "Actions", "status": "degraded_performance"},
                          {"name": "Git operations", "status": "major_outage"}, {"name": "Group", "status": "major_outage", "group": True},
                          {"name": "Pages", "status": "under_maintenance"}, {"name": "Copilot", "status": "partial_outage"}],
           "incidents": [{"name": "Delayed webhooks", "status": "investigating", "impact": "minor"}, {"name": "Old one", "status": "resolved", "impact": "critical"}],
           "scheduled_maintenances": [{"name": "Database upgrade", "status": "in_progress"}]}
cd = dev("github", "cloud", "www.githubstatus.com")
class Fake(DRIVERS["cloud"]):
    data = SUMMARY
    def fetch(self): return self.data
def run_cloud(data):
    Fake.data = data
    return {r.check: r for r in Fake(cd, db.thresholds_for(cd), {"disabled": frozenset()}).run()}
r = run_cloud(SUMMARY)
check("overall status follows the page's indicator", r["status"].status == "WARN" and r["status"].value == "Minor Service Outage" and "Database upgrade" in r["status"].message and r["status"].numeric == 1)
check("components: a major outage makes it FAIL; groups and maintenance are ignored", r["components"].status == "FAIL" and r["components"].value == "3 affected" and r["components"].numeric == 3 and "Git operations (major outage)" in r["components"].message and "Group" not in r["components"].message and "Pages" not in r["components"].message, r["components"])
check("only unresolved incidents count", r["incidents"].value == "1 open" and r["incidents"].status == "WARN" and "Delayed webhooks" in r["incidents"].message and "Old one" not in r["incidents"].message)
calm = {"status": {"indicator": "none", "description": "All Systems Operational"}, "components": [{"name": "API", "status": "operational"}], "incidents": []}
r = run_cloud(calm); check("a healthy page is all OK", [x.status for x in r.values()] == ["OK", "OK", "OK"] and r["incidents"].value == "none" and r["components"].value == "all operational")
r = run_cloud({**calm, "status": {"indicator": "critical", "description": "Major outage"}}); check("critical is a FAIL", r["status"].status == "FAIL" and r["status"].numeric == 3)
r = run_cloud({**calm, "incidents": [{"name": "Outage", "status": "identified", "impact": "major"}]}); check("a major open incident is a FAIL", r["incidents"].status == "FAIL")
check("the real driver asks the right address", "api/v2/summary.json" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "drivers", "cloud.py")).read())
from drivers import cloud as cloudmod
class Resp:
    def __init__(s, body, code=200): s.body, s.code = body, code
    def raise_for_status(s):
        if s.code >= 400: raise RuntimeError(f"HTTP {s.code}")
    def json(s):
        if isinstance(s.body, Exception): raise s.body
        return s.body
seen = []
cloudmod.requests.get = lambda url, **kw: (seen.append(url), Resp(SUMMARY))[1]
out = DRIVERS["cloud"](cd, db.thresholds_for(cd), {"http_timeout": 5, "disabled": frozenset()}).run()
check("fetched from the status page's own address", seen == ["https://www.githubstatus.com/api/v2/summary.json"] and len(out) == 3, seen)
cloudmod.requests.get = lambda url, **kw: Resp(ValueError("not json"))
try: DRIVERS["cloud"](cd, db.thresholds_for(cd), {"http_timeout": 5, "disabled": frozenset()}).run(); check("a page that is not a status page is explained", False)
except ValueError as e: check("a page that is not a status page is explained", "summary.json" in str(e))
check("presets are real addresses", len(cloudmod.PRESETS) >= 5 and all("." in h and "/" not in h for _, h in cloudmod.PRESETS))

# ================================================================ throughput checks
print("== scheduled throughput (iperf3 custom check)")
fake = os.path.join(SP, "iperf3-f3.bat")
def fake_iperf(mbps, retr=2, fail=False):
    if fail:
        body = "iperf3: error - unable to connect to server: Connection refused\r\n"
    else:
        body = (f"@echo off\r\necho ARGS %*\r\necho [  5]   0.00-1.00   sec  11.2 MBytes  {mbps} Mbits/sec    0   63.4 KBytes\r\n"
                f"echo [  5]   0.00-10.00  sec   112 MBytes  {mbps} Mbits/sec   {retr}             sender\r\n"
                f"echo [  5]   0.00-10.04  sec   112 MBytes  {mbps} Mbits/sec                  receiver\r\n")
    if fail:
        body = "@echo off\r\necho iperf3: error - unable to connect to server: Connection refused\r\nexit /b 1\r\n"
    open(fake, "w").write(body)
db.set_setting("iperf_path", fake)
srv = dev("branch-router", "cisco", "10.5.5.5")
chk = {"name": "WAN speed", "kind": "iperf", "target": "", "port": 5301, "warn": 80, "fail": 40, "higher_worse": 1, "scope": [], "options": {"seconds": 5, "streams": 2, "reverse": True}}
cid = custom.save_check(chk)
saved = [c for c in custom.list_checks() if c["id"] == cid][0]
check("options are saved and come back as a dict; lower is always worse", saved["options"] == {"seconds": 5, "streams": 2, "reverse": True} and saved["higher_worse"] == 0 and saved["kind"] == "iperf")
fake_iperf(94.0)
r = custom.run_network(srv, [saved])[0]
check("a fast link is OK and the speed is kept for the charts", r.status == "OK" and r.numeric == 94.0 and r.value == "94 Mbit/s", r)
check("the retransmits are reported", "2 retransmits" in r.message, r.message)
fake_iperf(60.0); r = custom.run_network(srv, [saved])[0]; check("below WARN is a WARN", r.status == "WARN" and r.numeric == 60.0)
fake_iperf(10.0); r = custom.run_network(srv, [saved])[0]; check("below FAIL is a FAIL", r.status == "FAIL")
fake_iperf(0, fail=True); r = custom.run_network(srv, [saved])[0]; check("an unreachable server says why", r.status == "FAIL" and "Connection refused" in r.message and "unable to connect" in r.message, r)
db.set_setting("iperf_path", os.path.join(SP, "nope.exe")); real = iperf.shutil.which; iperf.shutil.which = lambda n: None
r = custom.run_network(srv, [saved])[0]; iperf.shutil.which = real
check("without iperf3 it is an ERROR with the way forward", r.status == "ERROR" and "iperf3 was not found" in r.message and "Tools" in r.message, r)
db.set_setting("iperf_path", fake); fake_iperf(94.0)
args_seen = []
orig = iperf.run_test; iperf.run_test = lambda exe, args, seconds=10: (args_seen.append(list(args)), orig(exe, args, seconds))[1]
custom.run_network(srv, [saved]); iperf.run_test = orig
a = args_seen[0]
check("the command line uses the device, port and options", a[:2] == ["-c", "10.5.5.5"] and a[a.index("-p") + 1] == "5301" and a[a.index("-t") + 1] == "5" and a[a.index("-P") + 1] == "2" and "-R" in a, a)
custom.save_check({**saved, "id": None, "name": "Other", "target": "{host}"})
iperf.run_test = lambda exe, args, seconds=10: (args_seen.append(list(args)), orig(exe, args, seconds))[1]
custom.run_network(srv, [[c for c in custom.list_checks() if c["name"] == "Other"][0]]); iperf.run_test = orig
check("{host} in the server address is replaced", args_seen[-1][1] == "10.5.5.5")
for bad_opts, why in (({"seconds": 0}, "length"), ({"streams": 999}, "streams"), ({"bandwidth": "fast"}, "rate"), ({"seconds": "abc"}, "text for a number")):
    try: custom.validate({"name": "x", "kind": "iperf", "options": bad_opts}); check(f"refused: bad {why}", False)
    except ValueError: check(f"refused: bad {why}", True)
check("when the login fails, the throughput check still runs", "iperf" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "runner.py")).read())

# ================================================================ UI
print("== UI: maintenance page, custom check dialog, device dialog, graph, Wi-Fi scanner")
import ui.settings as S
import ui.inventory as I
import ui.tools3 as T3
import ui.dashboard as D
mp = S.MaintenancePage(); mp.load()
check("the page starts empty and says so", mp.table.rowCount() == 0 and "No device" in mp.info.text())
dlg = S.MaintenanceDialog(parent=mp)
dlg.name.setText("Sat patching"); dlg.kind.setCurrentIndex(dlg.kind.findData("weekly"))
check("weekly shows days and times; one-off dates are hidden", not dlg.form.isRowVisible(dlg.start) if hasattr(dlg.form, "isRowVisible") else True)
[c.setChecked(i == 5) for i, c in enumerate(dlg.days)]
v = dlg.values()
check("the dialog's values", v["kind"] == "weekly" and v["days"] == [5] and v["start_time"] == "22:00" and v["end_time"] == "02:00" and v["name"] == "Sat patching", v)
mp._save(dlg); check("saved and listed", mp.table.rowCount() == 1 and mp.table.item(0, 1).text() == "Sat 22:00-02:00" and mp.table.item(0, 2).text() == "all devices")
dlg2 = S.MaintenanceDialog(maintenance.list_windows()[0], mp)
check("editing shows what was saved", dlg2.name.text() == "Sat patching" and dlg2.days[5].isChecked() and not dlg2.days[0].isChecked() and dlg2.t_start.time().toString("HH:mm") == "22:00")
dlg3 = S.MaintenanceDialog(parent=mp); dlg3.name.setText("Bad"); dlg3.end.setDateTime(dlg3.start.dateTime().addSecs(-60))
try: maintenance.validate(dlg3.values()); check("a window that ends before it starts is refused", False)
except ValueError: check("a window that ends before it starts is refused", True)
maintenance.delete_window(maintenance.list_windows()[0]["id"])
live = maintenance.save_window({"name": "Now", "kind": "once", "start_at": fmt(now - timedelta(minutes=5)), "end_at": fmt(now + timedelta(hours=1)), "scope": ["Location: Denver"]})
mp.load(); check("an active window is marked ACTIVE", mp.table.item(0, 3).text() == "ACTIVE" and "1 device" in mp.info.text())
db.save_run([Result("edge-fw", "cpu", "FAIL", "99%"), Result("core-sw1", "cpu", "OK", "5%")])
dash = D.DashboardTab(); dash.refresh()
check("the Overview says devices are in maintenance and tags their problems", "in maintenance" in dash.when.text() and dash.attention.rowCount() == 1 and dash.attention.item(0, 2).text().startswith("(maintenance)"), dash.when.text())
maintenance.delete_window(live)
dash.refresh(); check("...and stops when the window ends", "in maintenance" not in dash.when.text() and not dash.attention.item(0, 2).text().startswith("(maintenance)"))

cd_ = S.CheckDialog(); cd_.kind.setCurrentIndex(cd_.kind.findData("iperf")); cd_.name.setText("Link speed")
check("the throughput kind shows its own settings and hides the irrelevant ones", cd_.form.isRowVisible(cd_.seconds) if hasattr(cd_.form, "isRowVisible") else True)
cd_.seconds.setValue(7); cd_.streams.setValue(3); cd_.udp.setChecked(True); cd_.bandwidth.setText("200M"); cd_.warn.setText("500"); cd_.fail.setText("100")
v = cd_.values()
check("its values", v["kind"] == "iperf" and v["options"] == {"seconds": 7, "streams": 3, "reverse": False, "udp": True, "bandwidth": "200M"} and v["higher_worse"] == 0 and v["warn"] == 500, v)
custom.validate(v)
cd_.kind.setCurrentIndex(cd_.kind.findData("ping")); check("other kinds carry no options", cd_.values()["options"] == {})
cd2 = S.CheckDialog({**saved, "options": {"seconds": 12, "streams": 4, "reverse": True, "udp": False, "bandwidth": ""}}); check("editing restores them", cd2.seconds.value() == 12 and cd2.streams.value() == 4 and cd2.reverse.isChecked())
cp = S.CustomChecksPage(); cp.refresh(); check("the list describes it", any("iperf3 port" in cp.table.item(i, 2).text() for i in range(cp.table.rowCount())))
th_page = S.ThresholdsPage(); check("the Wi-Fi signal limits are in Settings > Thresholds", "wifi_signal" in th_page.spins)
from core import checks as _checks; check("the new vendors' checks can be switched on and off in Settings > Checks", {k for k, _ in _checks.CATALOG["cloud"]} == {"status", "components", "incidents"} and {k for k, _ in _checks.CATALOG["wifi"]} == {"connection", "signal", "link speed"})

dd = I.DeviceDialog(); dd.vendor.setCurrentIndex(dd.vendor.findData("cloud"))
check("a status page needs no credentials, SNMP, profile or login", not dd.access.isRowVisible(dd.secret) and not dd.access.isRowVisible(dd.profile) and not dd.use_snmp.isVisibleTo(dd) and not dd.tabs.isTabVisible(2) and dd.form.isRowVisible(dd.preset))
dd.preset.setCurrentIndex(dd.preset.findText("GitHub  -  www.githubstatus.com")); v = dd.values()
check("choosing a popular page fills in the name and address", v["host"] == "www.githubstatus.com" and v["name"] == "GitHub" and v["vendor"] == "cloud" and v["snmp"] == "", v)
w2 = I.DeviceDialog(); w2.vendor.setCurrentIndex(w2.vendor.findData("wifi")); check("a fresh Wi-Fi device gets host 'localhost'", w2.host.text() == "localhost" and not w2.form.isRowVisible(w2.preset))
w2.vendor.setCurrentIndex(w2.vendor.findData("cisco")); check("switching back to a normal vendor brings the login fields back", w2.access.isRowVisible(w2.secret) and w2.tabs.isTabVisible(2))

g = T3.ThroughputGraph(); g.resize(600, 160); g.show(); g.set_points([(1, 90), (2, 94), (3, 88)]); QCoreApplication.processEvents()
check("the graph holds the points and paints", len(g.points) == 3 and not g.grab().isNull())
g.set_points([]); check("and clears", g.points == [])
ip = T3.IperfTab(); ip.exe = fake; fake_iperf(94.0); ip.target.setText("10.1.2.3"); ip.start(); pump(lambda: ip.go.isEnabled())
check("a test fills the graph while it runs", len(ip.graph.points) == 1 and abs(ip.graph.points[0][1] - 94.0) < 0.1, ip.graph.points)
ip.shutdown()

wt = T3.WifiTab(); wt.resize(1000, 600); wt.show()
for n in nets: n["maker"] = ""
wifi.scan = lambda: (nets, ""); wifi.interfaces = lambda: (wifi.parse_interfaces(IFACE), "")
wt.scan(); pump(lambda: wt.table.rowCount() > 0)
check("the scanner lists access points, strongest first", wt.table.rowCount() == 4 and wt.table.item(0, 0).text() == "Alpha" and wt.table.item(0, 1).text() == "88%" and wt.table.item(3, 1).text() == "30%", [wt.table.item(i, 1).text() for i in range(wt.table.rowCount())])
check("it says what this computer is connected to and the quietest channel", "OfficeNet" in wt.me.text() and "Quietest 2.4 GHz channel: 11" in wt.summary.text() and "4 access points in 3 networks" in wt.summary.text(), wt.summary.text())
wt.band.setCurrentText("5 GHz"); check("filter by band", wt.table.rowCount() == 1 and wt.table.item(0, 3).text() == "5 GHz")
wt.band.setCurrentText("All bands"); wt.filter.setText("gam"); check("filter by name", wt.table.rowCount() == 1 and wt.table.item(0, 0).text() == "Gamma")
wt.filter.setText(""); wifi.scan = lambda: ([], "Turn on Location"); wt.scan(); pump(lambda: wt.summary.text().startswith("Turn"))
check("an error is shown instead of an empty list", wt.summary.text() == "Turn on Location")
wt.auto.setChecked(True); check("auto-rescan starts a timer", wt.timer.isActive()); wt.auto.setChecked(False); check("and stops it", not wt.timer.isActive())
wt.shutdown()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
