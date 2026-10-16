# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\devchk%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingchk%d" % int(time.time()))
from core import agents, checks, db, importer, runner, winmon
from drivers.base import Driver, Result
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host=kw.pop("host", name), port=0, platform=kw.pop("platform", ""), username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])

print("== a device's own settings, stored")
check("nothing set means nothing stored", db.normalize_checkopts("") == {} and db.normalize_checkopts(None) == {} and db.normalize_checkopts({}) == {} and db.normalize_checkopts("not json") == {})
check("junk is dropped, good parts kept", db.normalize_checkopts({"checks": ["cpu", "cpu", "memory"], "thresholds": {"cpu": {"warn": "60", "fail": 80}, "nope": {"warn": 1, "fail": 2}, "memory": {"warn": 1}}})
      == {"checks": ["cpu", "memory"], "thresholds": {"cpu": {"warn": 60.0, "fail": 80.0}}})
a = dev("plain-sw", host="127.0.0.1")
b = dev("own-sw", host="127.0.0.1", checkopts={"checks": ["cpu"], "thresholds": {"cpu": {"warn": 90, "fail": 95}}})
check("a device saved without settings has none", db.get_device(a["id"])["checkopts"] == "" and db.normalize_checkopts(db.get_device(a["id"])["checkopts"]) == {})
check("one saved with settings gets them back", db.normalize_checkopts(db.get_device(b["id"])["checkopts"]) == {"checks": ["cpu"], "thresholds": {"cpu": {"warn": 90.0, "fail": 95.0}}})
check("the database is at the version that has the column", db.schema_version() == db.SCHEMA_VERSION if hasattr(db, "schema_version") else True)

print("== thresholds: the device's own, else the global ones")
glob = db.get_thresholds()
check("a device with none gets exactly the global limits", db.thresholds_for(a) == glob)
th = db.thresholds_for(b)
check("a device with its own CPU limits gets them, the rest stay global", th["cpu"] == {"warn": 90.0, "fail": 95.0} and th["memory"] == glob["memory"] and th["uptime"] == glob["uptime"], th["cpu"])
check("the global limits are not changed by that", db.get_thresholds()["cpu"] == glob["cpu"] and db.thresholds_for(a)["cpu"] == glob["cpu"])
rules = [{"scope": "Device: own-sw", "check": "cpu", "warn": 10, "fail": 20}, {"scope": "Device: plain-sw", "check": "cpu", "warn": 11, "fail": 22}]
check("its own limits beat a Settings override for the same device", db.thresholds_for(b, overrides=rules)["cpu"] == {"warn": 90.0, "fail": 95.0})
check("and a device without them still gets the Settings override", db.thresholds_for(a, overrides=rules)["cpu"] == {"warn": 11, "fail": 22})
check("a limit for something that is not a threshold is ignored", db.thresholds_for({**a, "checkopts": json.dumps({"thresholds": {"bogus": {"warn": 1, "fail": 2}}})}) == glob)
check("the check for contradicting limits is shared", db.bad_pair("cpu", 90, 80) and not db.bad_pair("cpu", 80, 90) and db.bad_pair("uptime", 1, 5) and not db.bad_pair("uptime", 5, 1))

print("== which checks run: the device's own list, else the global one")
off = {"cisco:memory", "cisco:uptime", "windows:cpu"}
check("a device with no list follows the global list", db.disabled_for(a, off) == off)
check("a device with its own list runs only those (for its own vendor)", db.disabled_for(b, off) == {k for k in (checks.key("cisco", c) for c, _ in checks.CATALOG["cisco"]) if k != "cisco:cpu"} | {"windows:cpu"})
check("it can switch on a check that is off globally", "cisco:memory" not in db.disabled_for({**a, "checkopts": {"checks": ["memory", "cpu"]}}, off) and "cisco:uptime" in db.disabled_for({**a, "checkopts": {"checks": ["memory"]}}, off))
check("an empty own list means nothing runs", {checks.key("cisco", c) for c, _ in checks.CATALOG["cisco"]} <= db.disabled_for({**a, "checkopts": {"checks": []}}, set()))

print("== a real run uses them")
class Probe(Driver):
    def run(self):
        out = []
        for key in ("cpu", "memory", "uptime"):
            if self.enabled(key):
                out.append(self.level_check(key, 75.0) if key != "uptime" else self.result("uptime", "OK", "1"))
        return out
real = runner.DRIVERS["cisco"]; runner.DRIVERS["cisco"] = Probe
base_opts = {**db.runtime_options(), "retries": 0, "tls_sweep": False, "custom": [], "disabled": {"cisco:memory"}}
ra = {r.check: r for r in runner.run_one(a, db.thresholds_for(a), base_opts) if r.check != "reachability"}      # the TCP reachability row is tested in test_reach
rb = {r.check: r for r in runner.run_one(b, db.thresholds_for(b), base_opts) if r.check != "reachability"}
check("the device without its own settings skips what is off globally", set(ra) == {"cpu", "uptime"} and ra["cpu"].status == "WARN", {k: v.status for k, v in ra.items()})
check("the one with its own list runs just that, with its own limits (75% is fine under 90)", set(rb) == {"cpu"} and rb["cpu"].status == "OK", {k: v.status for k, v in rb.items()})
c2 = dev("own-mem", host="127.0.0.1", checkopts={"checks": ["memory"]})
rc = {r.check for r in runner.run_one(c2, db.thresholds_for(c2), base_opts)}
check("a check that is off globally can be turned on for one device", rc == {"memory"}, rc)
runner.DRIVERS["cisco"] = real

print("== export and import keep them")
rows = importer.export_rows([db.get_device(a["id"]), db.get_device(b["id"])])
byname = {r["name"]: r for r in rows}
check("the export has a checkopts column, empty for a device that follows the global settings", "checkopts" in importer.EXPORT_COLUMNS and byname["plain-sw"]["checkopts"] == "")
check("and the JSON for one that has its own", json.loads(byname["own-sw"]["checkopts"])["checks"] == ["cpu"])
norm, _ = importer.normalize({**byname["own-sw"], "name": "copy-sw", "host": "10.9.9.9"})
check("importing it back gives the same settings", db.normalize_checkopts(norm["checkopts"]) == db.normalize_checkopts(b["checkopts"]))
norm2, _ = importer.normalize({**byname["plain-sw"], "name": "copy2", "host": "10.9.9.8"})
check("a row without any gives none", norm2["checkopts"] == "")
try:
    importer.normalize({**byname["own-sw"], "name": "bad", "host": "10.9.9.7", "checkopts": "{nope"}); check("broken JSON is refused", False)
except ValueError as e:
    check("broken JSON is refused", "checkopts" in str(e))

print("== the list of services")
one = json.dumps({"services": {"name": "Spooler", "display": "Print Spooler", "state": "Running", "start": "Auto"}})
many = json.dumps({"services": [{"name": "W32Time", "display": "Windows Time", "state": "Stopped", "start": "Manual"}, {"name": "Dnscache", "display": "DNS Client", "state": "Running", "start": "Auto"}]})
check("a list of one (PowerShell 5.1 turns it into the item) is still a list", [s["name"] for s in winmon.parse_services(one)] == ["Spooler"])
check("services come back sorted by what people read (the display name)", [s["name"] for s in winmon.parse_services(many)] == ["Dnscache", "W32Time"])
for junk in ("", "no json at all", json.dumps({"services": "x"}), json.dumps([1, 2])):
    try: winmon.parse_services(junk); check(f"junk is refused: {junk[:20]!r}", False)
    except (ValueError, TypeError): check(f"junk is refused: {junk[:20]!r}", True)
class FakeClient:
    seen = []
    def __init__(self, host, **kw): FakeClient.kw = kw
    def execute_ps(self, script): FakeClient.seen.append(script); return many, None, False
got = winmon.collect_winrm({"host": "srv1", "vendor": "windows", "platform": "winrm", "username": "u", "winopts": ""}, "pw", factory=FakeClient, script=winmon.LIST_SERVICES, parser=winmon.parse_services)
check("over WinRM the service list script is what runs, not the collector", FakeClient.seen == [winmon.LIST_SERVICES] and [s["name"] for s in got] == ["Dnscache", "W32Time"])
wdev = dev("agent-pc", "windows", platform="agent")
try: winmon.list_services(wdev); check("an agent that has not reported gives a clear reason", False)
except RuntimeError as e: check("an agent that has not reported gives a clear reason", "not reported" in str(e) and "type service names" in str(e))
agents.token_for("agent-pc")
agents.store("agent-pc", {"v": 1, "at": "x", "computer": "AGENT-PC", "os": "Windows", "service_states": {"Spooler": "R", "W32Time": "S"},
                          "auto_stopped": [{"name": "W32Time", "display": "Windows Time"}]}, "10.0.0.5", 3)
svc, note = winmon.list_services(wdev)
check("an agent's last report supplies the names and states", {(s["name"], s["state"]) for s in svc} == {("Spooler", "Running"), ("W32Time", "Stopped")} and "last report" in note, (svc, note))
check("with display names where the report has them", {s["name"]: s["display"] for s in svc}["W32Time"] == "Windows Time")
local = dev("this-pc", "windows", platform="local", host="localhost")
real_svc, note = winmon.list_services(local)
names = {s["name"].lower() for s in real_svc}
check("this computer's real services are listed (real PowerShell)", len(real_svc) > 20 and {"eventlog", "winmgmt"} <= names and all(s["state"] for s in real_svc), len(real_svc))
check("each has a display name, a state and a startup type", all(s["display"] and s["start"] in ("Auto", "Manual", "Disabled", "Boot", "System") for s in real_svc[:30]))

print("== the dialogs")
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
from ui.devicechecks import DeviceChecks
from ui.servicepicker import ServicePicker
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)          # closing a dialog with edits asks first
w = DeviceChecks(); w.set_vendor("cisco"); w.load(None)
check("a new device follows the global settings: nothing chosen, nothing saved", w.values() == {} and not w.own.isChecked() and not w.listing.isEnabled())
check("the list shows today's global state", all(w.listing.item(i).checkState() == Qt.CheckState.Checked for i in range(w.listing.count())) and w.listing.count() == len(checks.CATALOG["cisco"]))
db.set_setting("disabled_checks", ["cisco:memory"]); w.load(None)
mem = next(i for i in range(w.listing.count()) if w.listing.item(i).data(Qt.ItemDataRole.UserRole) == "memory")
check("a check that is off globally shows as off", w.listing.item(mem).checkState() == Qt.CheckState.Unchecked)
w.own.setChecked(True)
check("choosing your own list starts from the global one and enables it", w.listing.isEnabled() and w.values()["checks"] == [k for k, _ in checks.CATALOG["cisco"] if k != "memory"])
w.listing.item(mem).setCheckState(Qt.CheckState.Checked)
for i in range(w.listing.count()):
    if w.listing.item(i).data(Qt.ItemDataRole.UserRole) not in ("cpu", "memory"): w.listing.item(i).setCheckState(Qt.CheckState.Unchecked)
check("ticking and unticking is what is saved", w.values() == {"checks": ["cpu", "memory"]}, w.values())
cpu_row = list(db.DEFAULT_THRESHOLDS).index("cpu")
check("limits start out showing the global values, locked", not w.spins["cpu"][0].isEnabled() and w.spins["cpu"][0].value() == db.get_thresholds()["cpu"]["warn"])
w.limits.item(cpu_row, 0).setCheckState(Qt.CheckState.Checked)
check("ticking a row unlocks it", w.spins["cpu"][0].isEnabled() and w.spins["cpu"][1].isEnabled())
w.spins["cpu"][0].setValue(85); w.spins["cpu"][1].setValue(95)
check("its numbers are what is saved, only for that check", w.values()["thresholds"] == {"cpu": {"warn": 85.0, "fail": 95.0}}, w.values())
w.spins["cpu"][0].setValue(99)
check("contradicting limits are caught", w.problems() and "CPU" in w.problems()[0])
w.reset()
check("'use the global settings' puts everything back", w.values() == {} and not w.own.isChecked() and not w.spins["cpu"][0].isEnabled() and not w.problems())
w.load({"checks": ["cpu"], "thresholds": {"memory": {"warn": 50, "fail": 60}}})
check("an existing device's settings load into the controls", w.own.isChecked() and w.values() == {"checks": ["cpu"], "thresholds": {"memory": {"warn": 50.0, "fail": 60.0}}})
w.set_vendor("windows")
check("changing the vendor rebuilds the list from the new vendor's checks", w.listing.count() == len(checks.CATALOG["windows"]))
w.set_vendor("nonsense")
check("a kind of device with no checks to choose from cannot choose", not w.own.isEnabled() and "no checks" in w.state.text())
db.set_setting("disabled_checks", [])

print("== Edit device")
saved = dev("srv-1", "windows", platform="winrm", host="srv1.corp", winopts={"watch": ["DNS"], "ignore": ["gupdate"], "https": False, "auth": "negotiate"},
            checkopts={"checks": ["cpu", "services"], "thresholds": {"cpu": {"warn": 60, "fail": 80}}})
dlg = I.DeviceDialog(saved)
check("the Checks tab is the last tab", dlg.tabs.tabText(dlg.tabs.count() - 1) == "Checks" and dlg.tabs.widget(dlg.tabs.count() - 1) is dlg.checks_tab)
check("it holds this device's settings, for this device's vendor", dlg.checks_tab.vendor == "windows" and dlg.values()["checkopts"] == {"checks": ["cpu", "services"], "thresholds": {"cpu": {"warn": 60.0, "fail": 80.0}}}, dlg.values()["checkopts"])
for vendor in ("cisco", "windows"):
    d = I.DeviceDialog(); d.vendor.setCurrentIndex(d.vendor.findData(vendor)); d.show(); app.processEvents()
    tb = d.tabs.tabBar(); vis = [i for i in range(tb.count()) if tb.isTabVisible(i)]
    check(f"every tab fits in view in the {vendor} dialog (no scroll arrows hiding some)", not d.tabs.usesScrollButtons() and tb.tabRect(vis[-1]).right() <= tb.width() and d.width() >= tb.sizeHint().width(), (d.width(), tb.width(), tb.tabRect(vis[-1]).right()))
    d.close()
new = I.DeviceDialog()
check("a new device has none", new.values()["checkopts"] == {})
dlg.checks_tab.reset()
check("clearing them saves an empty value, so it follows the global settings again", dlg.values()["checkopts"] == {})
ids = db.save_device({**saved, **{k: v for k, v in dlg.values().items() if k in ("name", "checkopts")}})
check("and the stored device has none", db.normalize_checkopts(db.get_device(saved["id"])["checkopts"]) == {})
dlg.checks_tab.load({"thresholds": {"cpu": {"warn": 90, "fail": 80}}}); dlg.name.setText("srv-1"); dlg.host.setText("srv1.corp")
dlg.accept()
check("saving with contradicting limits is refused and shows the Checks tab", warned and "contradict" in warned[-1] and dlg.tabs.currentWidget() is dlg.checks_tab, warned)
check("the test button runs with the device's own settings (the dialog hands them over as JSON)", isinstance(json.dumps(dlg.values()["checkopts"]), str))

print("== choosing services")
svcs = [{"name": "Spooler", "display": "Print Spooler", "state": "Running", "start": "Auto"},
        {"name": "W32Time", "display": "Windows Time", "state": "Stopped", "start": "Manual"},
        {"name": "Dnscache", "display": "DNS Client", "state": "Running", "start": "Auto"}]
pk = ServicePicker(svcs, ["Spooler", "OldThing"], "Services that must be running", "Tick them.", "From the computer, just now.")
check("what was typed before is ticked, and one that is not on the computer is still there", pk.selected() == ["OldThing", "Spooler"] and pk.table.rowCount() == 4, pk.selected())
pk.search.setText("time")
check("typing filters the list", [pk.table.isRowHidden(i) for i in range(pk.table.rowCount())].count(False) >= 1 and not pk.table.isRowHidden(next(i for i, r in enumerate(pk.rows) if r["name"] == "W32Time")))
check("a ticked service is never hidden by the filter", not pk.table.isRowHidden(next(i for i, r in enumerate(pk.rows) if r["name"] == "Spooler")))
check("an unticked one that does not match is", pk.table.isRowHidden(next(i for i, r in enumerate(pk.rows) if r["name"] == "Dnscache")))
pk.search.setText(""); pk.running.setChecked(True)
check("'Running only' hides stopped ones", pk.table.isRowHidden(next(i for i, r in enumerate(pk.rows) if r["name"] == "W32Time")))
pk.running.setChecked(False)
pk.table.item(next(i for i, r in enumerate(pk.rows) if r["name"] == "W32Time"), 0).setCheckState(Qt.CheckState.Checked)
check("ticking adds to the answer and the count says so", "W32Time" in pk.selected() and pk.count.text().startswith("3 chosen"), pk.count.text())
seen_dev = []
real_list = winmon.list_services
winmon.list_services = lambda d, password=None, timeout=30: (seen_dev.append(d), (svcs, "From the computer, just now."))[1]
ServicePicker.exec = lambda self: (self.table.item(next(i for i, r in enumerate(self.rows) if r["name"] == "Dnscache"), 0).setCheckState(Qt.CheckState.Checked), 1)[1]
dlg2 = I.DeviceDialog(saved)
dlg2.name.setText("srv-1"); dlg2.win_watch.setText("Spooler")
dlg2.win_pick_watch.click()
check("the Choose button asks for this computer's services with the dialog's current settings", seen_dev and seen_dev[0]["name"] == "srv-1" and seen_dev[0]["vendor"] == "windows")
check("and the ticked names land in the field", dlg2.win_watch.text() == "Dnscache, Spooler" or set(winmon._names(dlg2.win_watch.text())) == {"Spooler", "Dnscache"}, dlg2.win_watch.text())
check("saved as the device's required services", set(dlg2.values()["winopts"]["watch"]) == {"Spooler", "Dnscache"})
dlg2.win_pick_ignore.click()
check("the ignore list has its own picker", "Dnscache" in dlg2.win_ignore.text())
def boom(d, password=None, timeout=30): raise RuntimeError("no answer on port 5985")
winmon.list_services = boom; warned.clear(); before = dlg2.win_watch.text()
dlg2.win_pick_watch.click()
check("when the computer cannot be reached the reason is shown and nothing changes", warned and "no answer on port 5985" in warned[-1] and dlg2.win_watch.text() == before, warned)
winmon.list_services = real_list

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
