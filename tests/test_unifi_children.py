# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# UniFi devices under their gateway (Network API) or site (Site Manager), each with its own page. The consoles are simulated
# with fake API answers, as tests/test_unifi_api.py does.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, threading, time
from urllib.parse import urlparse
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "unifikids%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingunifikids%d" % int(time.time()))
from core import db, display
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

OPTS = {**db.runtime_options(), "http_timeout": 5, "retries": 0, "tls_sweep": False, "custom": [], "disabled": set(), "firmware_severity": "WARN", "counter_mode": "total"}
CALLS, ROUTES = [], {}

class Resp:
    def __init__(self, status=200, js=None):
        self.status_code, self._js, self.headers = status, js, {}
    def json(self): return self._js
    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self; raise e

def fake_get(url, params=None, headers=None, timeout=None, verify=None, **kw):
    path = urlparse(url).path
    path = path[path.index("/v1") + 3:] or "/"
    CALLS.append({"path": path, "key": (headers or {}).get("X-API-KEY"), "thread": threading.current_thread()})
    hit = ROUTES.get(path)
    if callable(hit): hit = hit(params or {})
    if hit is None: return Resp(404, {"message": "not found"})
    return Resp(200, hit)
UA.requests.get = fake_get

def paged(rows):
    def f(p):
        off, lim = int(p.get("offset", 0)), int(p.get("limit", 25))
        return {"offset": off, "limit": lim, "count": len(rows[off:off + lim]), "totalCount": len(rows), "data": rows[off:off + lim]}
    return f

def add_dev(**kw):
    d = {"name": "gw", "vendor": "unifi_network", "host": "10.0.0.1", "port": 0, "platform": "", "username": "", "site": "default", "verify_ssl": 0,
         "ha_expected": 0, "enabled": 1}
    d.update(kw)
    return db.get_device(db.save_device(d))

def run_and_save(d):
    rows = DRIVERS[d["vendor"]]({**d, "password": d.get("password") or ""}, db.thresholds_for(d), OPTS).run()
    db.save_run(rows)
    return rows

print("== UniFi Network: a gateway with 3 APs and 2 switches")
GATEWAY = {"id": "d0", "name": "Gateway", "model": "UDM Pro", "macAddress": "aa:00", "ipAddress": "10.0.0.1", "state": "ONLINE", "firmwareUpdatable": False, "features": ["gateway"]}
NET = [{"id": "d1", "name": "AP Lobby", "model": "U6 Pro", "macAddress": "aa:01", "ipAddress": "10.0.0.11", "state": "ONLINE", "firmwareUpdatable": False},
       {"id": "d2", "name": "AP Hall", "model": "U6 Lite", "macAddress": "aa:02", "ipAddress": "10.0.0.12", "state": "ONLINE", "firmwareUpdatable": False},
       {"id": "d3", "name": "AP Yard", "model": "U6 Mesh", "macAddress": "aa:03", "ipAddress": "10.0.0.13", "state": "OFFLINE", "firmwareUpdatable": False},
       {"id": "d4", "name": "Core Switch", "model": "USW Pro 24", "macAddress": "aa:04", "ipAddress": "10.0.0.14", "state": "ONLINE", "firmwareUpdatable": True, "firmwareVersion": "7.0.1"},
       {"id": "d5", "name": "Edge Switch", "model": "USW Lite 8", "macAddress": "aa:05", "ipAddress": "10.0.0.15", "state": "ONLINE", "firmwareUpdatable": False}]
STATS = {"d0": (30.0, 40.0), "d1": (11.0, 21.0), "d2": (12.0, 22.0), "d4": (14.0, 24.0), "d5": (15.0, 25.0)}
def net_routes(devs):
    ROUTES.clear()
    ROUTES.update({"/info": {"applicationVersion": "10.1.68"}, "/sites": paged([{"id": "s1", "internalReference": "default", "name": "Default"}]),
                   "/sites/s1/devices": paged(devs), "/sites/s1/clients": {"totalCount": 7, "data": []}, "/pending-devices": paged([])})
    for k, (cpu, mem) in STATS.items():
        ROUTES[f"/sites/s1/devices/{k}/statistics/latest"] = {"uptimeSec": 9 * 86400, "cpuUtilizationPct": cpu, "memoryUtilizationPct": mem}
net_routes([GATEWAY] + NET)
gw = add_dev(password="NETKEY")
CALLS.clear()
rows = run_and_save(gw)
BEFORE = ["/info", "/sites", "/sites/s1/devices", "/sites/s1/devices/d0/statistics/latest", "/sites/s1/devices/d1/statistics/latest", "/sites/s1/devices/d2/statistics/latest",
          "/sites/s1/devices/d4/statistics/latest", "/sites/s1/devices/d5/statistics/latest", "/sites/s1/clients", "/pending-devices"]
check("one run of the gateway makes the same API calls as before (no new polling)", [c["path"] for c in CALLS] == BEFORE, [c["path"] for c in CALLS])
kids_rows = [r for r in rows if " / " in r.device]
ids = {d["name"]: d["id"] for d in NET}
check("each device's rows carry a stable key (the device id) and its model", kids_rows and all(r.kid and r.kid[0] == ids[r.device.split(" / ")[1]] for r in kids_rows)
      and {r.kid[1] for r in kids_rows} == {d["model"] for d in NET}, [(r.device, r.kid) for r in kids_rows][:3])
from core import unifikids
kids = unifikids.children(gw)
check("the gateway at the entry's address is the entry itself: its rows are the entry's own", any(r.device == "gw" and r.check == "cpu" for r in rows)
      and not any("Gateway" in r.device for r in rows) and not any(r.kid for r in rows if r.device == "gw"))
check("the gateway lists its 5 devices", sorted(k["name"] for k in kids) == sorted(d["name"] for d in NET) and len(kids) == 5, kids)
check("each has its key, model and when it was last seen, none gone", {k["key"] for k in kids} == set(ids.values()) and all(k["last_seen"] and not k["gone"] for k in kids)
      and {k["name"]: k["model"] for k in kids}["Core Switch"] == "USW Pro 24")
check("worst status first (the offline AP, then the switch with a firmware update)", [k["name"] for k in kids][:2] == ["AP Yard", "Core Switch"], [k["name"] for k in kids])
check("rows_for gives that device's latest rows only", {r["check_name"] for r in unifikids.rows_for(gw, "d1")} >= {"cpu", "memory", "state"}
      and all(r["device"] == "gw / AP Lobby" for r in unifikids.rows_for(gw, "d1")))

from PySide6.QtWidgets import QApplication, QMenu, QMessageBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
from ui.device_view import DeviceView
QMessageBox.warning = staticmethod(lambda *a, **k: None)
QMessageBox.information = staticmethod(lambda *a, **k: None)

def find_item(tab, name):
    for it in tab._all_items():
        if tab.kind_of(it)[0] == "device" and tab.payload.get(it.data(0, I.ROLE), {}).get("name") == name:
            return it
tab = I.InventoryTab()
CALLS.clear()
item = find_item(tab, "gw")
check("the gateway's row has an expand arrow", item is not None and item.childIndicatorPolicy() == item.ChildIndicatorPolicy.ShowIndicator)
item.setExpanded(True); app.processEvents()
names = [item.child(i).text(0) for i in range(item.childCount())]
check("expanding it lists the 5 devices", sorted(names) == sorted(d["name"] for d in NET), names)
kid_item = next(item.child(i) for i in range(item.childCount()) if item.child(i).text(0) == "AP Lobby")
check("a device row is a view: it cannot be dragged, edited or deleted from the toolbar", not (kid_item.flags() & Qt.ItemFlag.ItemIsDragEnabled)
      and (tab.table.setCurrentItem(kid_item), kid_item.setSelected(True), not tab.buttons["Edit"].isEnabled() and not tab.buttons["Delete"].isEnabled())[2])
opened = []
tab.open_details.connect(opened.append)
tab.double_clicked(kid_item, 0)
check("double-clicking a device opens its own page", opened and opened[-1].get("kid", {}).get("key") == "d1" and opened[-1]["name"] == "gw / AP Lobby", opened[-1:] and opened[-1].get("name"))

def dials(view):
    return [(g.accessibleName(), g._builder.__defaults__[0]) for g in view._gauges]
child = DeviceView(opened[-1])
check("the device's page shows only its own CPU and memory dials", dials(child) == [("CPU dial", 11.0), ("Memory dial", 21.0)], dials(child))
check("its latest checks are its own", child.checks.rowCount() >= 3 and all(":" not in child.checks.item(i, 0).text() for i in range(child.checks.rowCount())))
check("no Edit, Run checks or Back up on a device's page (it is a view)", all(child.buttons[k].isHidden() for k in ("edit", "checks", "backup")) and not child.tabs.isTabVisible(3))
check("its title is the device's name", child.title.text() == "AP Lobby")
switch = DeviceView(tab._kid_dev(next(item.child(i) for i in range(item.childCount()) if item.child(i).text(0) == "Edge Switch")))
check("another device's page shows its own dials, not the first 3 devices'", dials(switch) == [("CPU dial", 15.0), ("Memory dial", 25.0)], dials(switch))
parent = DeviceView(gw)
check("the gateway's page shows its own CPU and memory dials, and no other device's", dials(parent) == [("CPU dial", 30.0), ("Memory dial", 40.0)], dials(parent))
check("nor their rows in its latest checks", all(":" not in parent.checks.item(i, 0).text() for i in range(parent.checks.rowCount())) and parent.checks.rowCount() >= 2,
      [parent.checks.item(i, 0).text() for i in range(parent.checks.rowCount())])
opened.clear()
tab.table.clearSelection(); tab.table.setCurrentItem(kid_item); kid_item.setSelected(True)
check("the Details button works on a device's row", tab.buttons["Details"].isEnabled())
tab._enter()
check("and Enter opens its page", opened and opened[-1]["name"] == "gw / AP Lobby", [o["name"] for o in opened])
tab.table.clearSelection()
labels = list(child.keys)
check("its History lists its own checks, numbers and text alike", {"CPU", "Memory", "State"} <= set(labels), labels)
child.pick.set_selected(["CPU"]); child.draw()
check("a reading over time is a line chart (chart_kind)", child.over_stack.currentWidget() is child.chart and child.chart.series and child.chart.series[0][0] == "cpu")
child.pick.set_selected(["State"]); child.draw()
check("a status-only check is drawn as how often each status happened", child.over_stack.currentWidget() is child.over_chart)
check("opening the list and the pages made no API calls", CALLS == [], [c["path"] for c in CALLS])

print("== a device the controller no longer reports")
time.sleep(1.1)
net_routes([GATEWAY] + [d for d in NET if d["id"] != "d2"])
run_and_save(gw)
kids = unifikids.children(gw)
hall = next((k for k in kids if k["key"] == "d2"), None)
check("it stays listed, marked gone, after the others", hall is not None and hall["gone"] and kids[-1]["key"] == "d2" and sum(k["gone"] for k in kids) == 1, kids)
tab.refresh()
item = find_item(tab, "gw"); item.setExpanded(True); app.processEvents()
date = display.read_on(hall["last_seen"]).split(" at ")[0]
gone = next((item.child(i) for i in range(item.childCount()) if item.child(i).text(0).startswith("AP Hall")), None)
check("its row says '{name} (not seen since {date})'", gone is not None and gone.text(0) == f"AP Hall (not seen since {date})", gone and gone.text(0))
muted = I.QColor((I.theme.current() or {}).get("muted", "#888888"))
check("and is greyed", gone is not None and gone.foreground(0).color() == muted)
page = DeviceView(tab._kid_dev(gone))
check("its page keeps its history and last readings", db.series("gw / AP Hall", "cpu") and dials(page) == [("CPU dial", 12.0), ("Memory dial", 22.0)], dials(page))
from PySide6.QtCore import QTimer
def menu_actions(open_menu):
    """The actions of the menu `open_menu` opens, read while it is open, then closed (patching QMenu.exec has no effect in PySide6)."""
    got, tries = [], [0]
    def grab():
        m = QApplication.activePopupWidget()
        if isinstance(m, QMenu):
            got.append({a.text(): a for a in m.actions()})
            m.close()
        elif tries[0] < 100:
            tries[0] += 1
            QTimer.singleShot(20, grab)
    QTimer.singleShot(20, grab)
    open_menu()
    return got[-1] if got else {}
tab.table.clearSelection(); gone.setSelected(True)
acts = menu_actions(lambda: tab.show_menu(tab.table.visualItemRect(gone).center()))
check("right-click offers Remove", "Remove" in acts and "Delete..." not in acts and "Edit..." not in acts, list(acts))
present = next(item.child(i) for i in range(item.childCount()) if item.child(i).text(0) == "AP Lobby")
tab.table.clearSelection(); present.setSelected(True)
check("a device still reported cannot be removed (it would come back)", "Remove" not in menu_actions(lambda: tab.show_menu(tab.table.visualItemRect(present).center())))
history_before = len(db.series("gw / AP Hall", "cpu"))
if "Remove" in acts:
    acts["Remove"].trigger()
item = find_item(tab, "gw"); item.setExpanded(True); app.processEvents()
check("Remove forgets it", "d2" not in {k["key"] for k in unifikids.children(gw)} and not any(item.child(i).text(0).startswith("AP Hall") for i in range(item.childCount())))
check("but keeps its history rows", history_before and len(db.series("gw / AP Hall", "cpu")) == history_before)
time.sleep(1.1)
net_routes([GATEWAY] + NET); run_and_save(gw)
check("if it comes back it is listed again", "d2" in {k["key"] for k in unifikids.children(gw) if not k["gone"]})

print("== search finds a console's devices")
tab.search.setText("lobby"); tab.refresh()
item = find_item(tab, "gw")
check("a search on a device's name lists its console, opened on that device", item is not None and item.isExpanded()
      and [item.child(i).text(0) for i in range(item.childCount())] == ["AP Lobby"], item and [item.child(i).text(0) for i in range(item.childCount())])
tab.search.setText(""); tab.refresh()
item = find_item(tab, "gw"); item.setExpanded(True); app.processEvents()
check("cleared, the console lists all its devices again", item.childCount() == 5, item.childCount())

print("== several sites: one that cannot be read marks nothing gone")
from drivers.base import Result
multi = add_dev(name="multi", host="10.0.0.3", site="*", password="NETKEY")
net_routes(NET)
ROUTES["/sites"] = paged([{"id": "s1", "internalReference": "default", "name": "Default"}, {"id": "s2", "internalReference": "lab", "name": "Lab"}])
ROUTES["/sites/s2/devices"] = paged([{"id": "z1", "name": "Lab AP", "model": "U7", "macAddress": "cc:01", "ipAddress": "10.2.0.5", "state": "OFFLINE"}])
ROUTES["/sites/s2/clients"] = {"totalCount": 1, "data": []}
run_and_save(multi)
check("devices of every site are listed", {k["name"] for k in unifikids.children(multi)} >= {"Lab - Lab AP", "Default - AP Lobby"}, unifikids.children(multi))
time.sleep(1.1)
ROUTES["/sites/s2/devices"] = 500
try:
    run_and_save(multi)
except Exception as e:                                     # what the runner stores when a run fails
    db.save_run([Result("multi", "connection", "ERROR", "", str(e))])
check("a site whose devices could not be read leaves them listed, not gone", unifikids.children(multi) and not any(k["gone"] for k in unifikids.children(multi)))
before = len(unifikids.children(multi))
tab.refresh()
tab._save({**db.get_device(multi["id"]), "name": "multi2"}, "", old_name="multi")
multi2 = db.get_device(multi["id"])
check("renaming a console keeps its devices' bookkeeping", multi2["name"] == "multi2" and len(unifikids.children(multi2)) == before and unifikids.children(multi) == [])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
tab.table.clearSelection(); find_item(tab, "multi2").setSelected(True)
tab.delete()
with db.connect() as c:
    left = c.execute("SELECT COUNT(*) FROM unifi_seen WHERE device IN ('multi', 'multi2')").fetchone()[0]
check("deleting a console forgets its devices' bookkeeping", left == 0 and db.get_device(multi["id"]) is None, left)

print("== Site Manager: the Add dialog lists the account's sites")
STALE = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 310 * 86400))
def host_pages(p):
    return {"data": [{"id": "h1", "type": "console", "latestBackupTime": STALE}, {"id": "h2", "type": "console", "latestBackupTime": None}]}
CLOUD_DEVS = {"data": [
    {"hostId": "h1", "hostName": "HQ UDM", "devices": [{"id": "1", "name": "HQ UDM", "model": "UDM Pro", "status": "online", "isConsole": True},
                                                     {"id": "2", "name": "HQ Switch", "model": "USW 24", "status": "online", "updateAvailable": "7.1.2"},
                                                     {"id": "3", "name": "HQ AP", "model": "U6", "status": "offline"}]},
    {"hostId": "h2", "hostName": "Branch UDM", "devices": [{"id": "4", "name": "Branch Gateway", "model": "UDR", "status": "online", "isConsole": True}]}]}
CLOUD_SITES = {"data": [
    {"siteId": "st1", "hostId": "h1", "meta": {"name": "HQ"}, "statistics": {"counts": {"offlineDevice": 1, "totalDevice": 3}, "percentages": {"wanUptime": 99.9}}},
    {"siteId": "st2", "hostId": "h2", "meta": {"name": "Branch"}, "statistics": {"counts": {"offlineDevice": 0, "totalDevice": 1}, "percentages": {"wanUptime": 100}}},
    {"siteId": "st3", "hostId": "h1", "meta": {"name": "HQ Lab"}, "statistics": {"counts": {"offlineDevice": 2, "totalDevice": 2}, "percentages": {"wanUptime": 50}}}]}
ISP = {"data": [{"hostId": "h1", "siteId": sid, "periods": [{"metricTime": "2026-11-07T08:00:00Z", "data": {"wan": {"avgLatency": v, "packetLoss": 0}}}]}
                for sid, v in (("st1", 20), ("st3", 900))]}
def cloud_routes():
    ROUTES.clear()
    ROUTES.update({"/hosts": host_pages, "/devices": CLOUD_DEVS, "/sites": CLOUD_SITES, "/isp-metrics/5m": ISP,
                   "/sd-wan-configs": {"data": [{"id": "w1", "name": "HQ mesh"}, {"id": "w2", "name": "Elsewhere"}]},
                   "/sd-wan-configs/w1/status": {"data": {"generateStatus": "OK", "hubs": [{"id": "a", "hostId": "h1", "siteId": "st1", "applyStatus": "ok"}], "spokes": []}},
                   "/sd-wan-configs/w2/status": {"data": {"generateStatus": "OK", "hubs": [{"id": "b", "hostId": "h9", "siteId": "st9", "applyStatus": "ok"}], "spokes": []}}})
cloud_routes()
d = I.DeviceDialog()
d.vendor.setCurrentIndex(d.vendor.findData("unifi"))
d.platform.setCurrentIndex(d.platform.findData("unifi_cloud"))
d.name.setText("acct")
CALLS.clear()
d.secret.setText("CLOUDKEY"); d.secret.editingFinished.emit()
end = time.time() + 5
while (d.sites.count() == 0 or (d._sites_job and d._sites_job.isRunning())) and time.time() < end:
    app.processEvents(); time.sleep(0.02)
app.processEvents()
check("the dialog has a 'Sites' list for Site Manager", d.access.labelForField(d.sites).text() == "Sites" and d.access.isRowVisible(d.sites))
check("it lists the account's sites with tick boxes", [d.sites.item(i).text() for i in range(d.sites.count())] == ["HQ", "Branch", "HQ Lab"]
      and all(d.sites.item(i).flags() & Qt.ItemFlag.ItemIsUserCheckable for i in range(d.sites.count())), [d.sites.item(i).text() for i in range(d.sites.count())])
check("the sites were fetched off the UI thread, with the key typed", CALLS and all(c["path"] == "/sites" and c["key"] == "CLOUDKEY" and c["thread"] is not threading.main_thread() for c in CALLS),
      [(c["path"], c["thread"].name) for c in CALLS])
other = I.DeviceDialog(); other.vendor.setCurrentIndex(other.vendor.findData("unifi")); other.platform.setCurrentIndex(other.platform.findData("unifi_network"))
check("other kinds have no Sites list", not other.access.isRowVisible(other.sites))
for i in range(d.sites.count()):
    d.sites.item(i).setCheckState(Qt.CheckState.Checked if d.sites.item(i).text() in ("HQ", "Branch") else Qt.CheckState.Unchecked)
d.exec = lambda: True
real_dialog = I.DeviceDialog
I.DeviceDialog = lambda *a, **k: d
tab.add()
I.DeviceDialog = real_dialog
made = {x["name"]: x for x in db.list_devices() if x["vendor"] == "unifi_cloud"}
check("ticking two sites makes two inventory entries", set(made) == {"acct - HQ", "acct - Branch"}, list(made))
check("each scoped to its site", made.get("acct - HQ", {}).get("site") == "st1" and made.get("acct - Branch", {}).get("site") == "st2")
pids = {x.get("profile_id") for x in made.values()}
from core import audit, profiles
check("the shared profile is made once an entry is saved, and audited as Settings does", profiles.by_name("acct") is not None
      and any(e.get("action") == "profile created" and "acct" in str(e.get("detail")) for e in audit.recent(50)), audit.recent(5))
check("both use one API key in the vault: one secret, not two copies", len(pids) == 1 and None not in pids and list(STORE.values()).count("CLOUDKEY") == 1
      and not any(u.endswith("acct - HQ") or u.endswith("acct - Branch") for _s, u in STORE), (pids, [u for _s, u in STORE]))
CALLS.clear()
plain = add_dev(name="acct-all", vendor="unifi_cloud", host="api.ui.com", site="default", password="CLOUDKEY")
run_and_save(plain)
unscoped_calls = [c["path"] for c in CALLS]
CALLS.clear()
hq_rows = run_and_save(made["acct - HQ"])
check("a site entry runs with the shared key, and makes the same API calls as the whole account", [c["path"] for c in CALLS] == unscoped_calls
      and all(c["key"] == "CLOUDKEY" for c in CALLS), ([c["path"] for c in CALLS], unscoped_calls))
br_rows = run_and_save(made["acct - Branch"])
hq = {k["name"] for k in unifikids.children(made["acct - HQ"])}
br = {k["name"] for k in unifikids.children(made["acct - Branch"])}
check("each lists only its own site's devices", hq == {"HQ UDM", "HQ Switch", "HQ AP"} and br == {"Branch Gateway"}, (hq, br))
by_check = {}
for r in hq_rows:
    by_check.setdefault((r.device, r.check), []).append(r)
check("the console's check runs on a site entry: a backup 310 days old FAILs", [r.status for r in by_check.get(("acct - HQ", "console"), [])] == ["FAIL"], list(by_check))
check("site health and ISP are its own site's only (not a sibling site on the same console)", [r.value for r in by_check.get(("acct - HQ", "site health"), [])] == ["1 device offline"]
      and [r.value for r in by_check.get(("acct - HQ", "isp latency"), [])] == ["20 ms"], [(k, [r.value for r in v]) for k, v in by_check.items()])
check("SD-WAN rows only for a configuration its site or console is in", [r.device for r in hq_rows if r.check == "sd-wan"] == ["acct - HQ / SD-WAN HQ mesh"]
      and not [r for r in br_rows if r.check == "sd-wan"], [r.device for r in hq_rows if r.check == "sd-wan"])
check("the console and site rows are the entry's own, not a device's", all(r.device == "acct - HQ" for r in hq_rows if r.check in ("console", "devices", "site health", "wan uptime", "isp latency"))
      and not any(r.device == "acct - HQ" and r.check == "state" for r in hq_rows))
console_rows = unifikids.rows_for(made["acct - HQ"], "1")
check("a console device named like its console: its page shows only its own rows", {r["check_name"] for r in console_rows} == {"state"}
      and all(r["device"] == "acct - HQ / HQ UDM" for r in console_rows), [(r["device"], r["check_name"], r["value"]) for r in console_rows])
check("and the totals (devices online, firmware to update) stay on the entry's page", {("devices", "2/3 online"), ("firmware", "1 to update")} <=
      {(r.check, r.value) for r in hq_rows if r.device == "acct - HQ"})
check("and only its own site's health", not any("Branch" in r.device for r in hq_rows) and not any(r.device.endswith("/ HQ") for r in br_rows))
check("the whole-account entry is as before (no devices under it)", unifikids.children(plain) == [])

print("== 300 devices")
many = [{"id": f"x{i}", "name": f"AP {i:03d}", "model": "U6", "macAddress": f"bb:{i}", "ipAddress": "10.1.0.1", "state": "OFFLINE", "firmwareUpdatable": False}
        for i in range(300)]
net_routes(many)
big = add_dev(name="big", host="10.0.0.2", password="NETKEY")
run_and_save(big)
tab.refresh()
calls = []
real_children = unifikids.children
unifikids.children = lambda *a, **k: (calls.append(1), real_children(*a, **k))[1]
item = find_item(tab, "big")
t0 = time.perf_counter()
item.setExpanded(True); app.processEvents()
took = time.perf_counter() - t0
check("expanding takes under 200 ms", took < 0.2 and item.childCount() == 300, f"{took * 1000:.0f} ms, {item.childCount()} rows")
item.setExpanded(False); item.setExpanded(True); app.processEvents()
check("and the list is built once", len(calls) == 1 and item.childCount() == 300, len(calls))
unifikids.children = real_children

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
