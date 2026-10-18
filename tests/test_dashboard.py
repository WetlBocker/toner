# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\db%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, backup, profiles
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from drivers.base import Result
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QCoreApplication, Qt
app = QApplication([])
import app as A
A.apply_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host=f"10.0.0.{len(db.list_devices()) + 1}", port=0, platform="cisco_ios" if vendor == "cisco" else "", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]
for n in ("core1", "edge-fw", "ap-ctrl", "quiet", "dead"): dev(n, "fortinet" if n == "edge-fw" else "unifi" if n == "ap-ctrl" else "cisco")
dev("never-run")

print("== data helpers")
db.save_run([Result("core1", "cpu", "OK", "10%", numeric=10.0), Result("edge-fw", "wan links", "OK", "2/2"), Result("quiet", "cpu", "OK", "1%"), Result("dead", "connection", "ERROR", "", "timeout"), Result("ap-ctrl / ap1", "uptime", "OK", "5d"), Result("core1", "config backup", "WARN", "changed")])
time.sleep(1.1)
db.save_run([Result("core1", "cpu", "WARN", "85%", "high", numeric=85.0), Result("core1", "memory", "OK", "40%", numeric=40.0), Result("edge-fw", "wan links", "FAIL", "1/2", "down: wan2"), Result("dead", "connection", "ERROR", "", "timeout"), Result("ap-ctrl / ap1", "temperature", "WARN", "72C"), Result("ap-ctrl / sw", "cpu", "OK", "3%")])
time.sleep(1.1)
db.save_run([Result("quiet", "cpu", "OK", "2%")])              # a run of just one device must not wipe out the others
h = db.device_health()
check("each device is read from the newest run that included it", h["core1"]["status"] == "WARN" and h["quiet"]["at"] > h["core1"]["at"] and h["dead"]["status"] == "ERROR")
check("UniFi sub-devices fold into their controller", set(h) == {"core1", "edge-fw", "ap-ctrl", "quiet", "dead"} and h["ap-ctrl"]["status"] == "WARN" and h["ap-ctrl"]["checks"] == 2, h.get("ap-ctrl"))
check("problems are listed worst first, with messages", h["edge-fw"]["problems"] == [("wan links", "FAIL", "down: wan2")] and h["core1"]["problems"][0][1] == "WARN")
check("'config backup' rows are not health", all(c != "config backup" for v in h.values() for c, _, _ in v["problems"]))
av = db.availability(7)
check("availability counts runs, reachable runs and healthy runs", av["core1"] == {"runs": 2, "reachable": 2, "healthy": 2} and av["edge-fw"] == {"runs": 2, "reachable": 2, "healthy": 1} and av["dead"] == {"runs": 2, "reachable": 0, "healthy": 0} and av["quiet"]["runs"] == 2, av)
check("no devices -> no rows; last run", db.last_run()["id"] == 3)

print("== diagnostics")
db.save_diagnostic("core1", "cpu", "$ show proc\nsome output")
d = db.get_diagnostics("core1", "cpu"); check("raw output is kept per device and check", len(d) == 1 and "some output" in d[0]["body"])
check("sub-device labels find their controller's diagnostics", db.get_diagnostics("core1 / x", "cpu") != [])
for i in range(210): db.save_diagnostic("bulk", "c", f"n{i}")
with db.connect() as c: n = c.execute("SELECT COUNT(*) n FROM diagnostics").fetchone()["n"]
check("only the newest 200 are kept", n == 200)
from drivers import DRIVERS
import drivers.sshbase as SB
class Conn:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, **k): return "garbage\nusername admin secret 9 $9$topsecret\nnothing useful"
drv = DRIVERS["juniper"](dev("jn", "juniper", platform="juniper_junos", password="p"), db.thresholds_for({"name": "x", "vendor": "juniper"}), db.runtime_options())
drv.connect = lambda: Conn(); rows = drv.run()
d = db.get_diagnostics("jn")
check("a parse failure stores the device's raw output, with secrets masked", rows and any(r.status == "ERROR" for r in rows) and d and "show chassis routing-engine" in d[0]["body"] and "garbage" in d[0]["body"] and "topsecret" not in d[0]["body"], d[:1])
import drivers.cisco as DC
class CConn(Conn):
    def send_command(self, cmd, **k): return "no match here"
drv = DRIVERS["cisco"](dev("cs", platform="cisco_ios", password="p"), db.thresholds_for({"name": "x", "vendor": "cisco"}), db.runtime_options()); drv.connect = lambda: CConn()
drv.run()
# Cisco returns [] on no match (no error), so no diagnostic is expected there

print("== dashboard")
import ui.dashboard as D
dash = D.DashboardTab(); dash.resize(1200, 760); dash.show()
c = {k: v.value.text() for k, v in dash.cards.items()}
check("cards count devices and states", c["devices"] == str(len(db.list_devices())) and c["ok"] == "1" and c["warn"] == "2" and c["fail"] == "2", c)
check("the sub line explains the card", "enabled" in dash.cards["devices"].sub.text() and "failing" in dash.cards["fail"].sub.text())
check("the attention list shows only unhealthy devices, worst first", [dash.attention.item(i, 0).text() for i in range(dash.attention.rowCount())] == ["dead", "edge-fw", "ap-ctrl", "core1"], [dash.attention.item(i, 0).text() for i in range(dash.attention.rowCount())])
check("it says what is wrong", "WAN Links: down: wan2" in dash.attention.item(1, 2).text() and "Temperature" in dash.attention.item(2, 2).text(), dash.attention.item(1, 2).text())
check("last run shown", "Last run" in dash.when.text() and dash.hint.isHidden())
check("availability bars: worst first", dash.bars.rows[0][0] == "dead" and dash.bars.rows[0][1] == 0.0 and dash.bars.rows[-1][1] == 100.0, dash.bars.rows)
check("recent runs listed (without a second heading repeating the panel title)", "Recent runs" not in dash.recent.text() and "OK 1" in dash.recent.text())
got = []
dash.open_device.connect(got.append); dash.goto.connect(got.append); dash.show_results.connect(lambda w: got.append("Results:" + w))
dash.attention.selectRow(1); dash._open(); dash.cards["fail"].clicked.emit(); dash.cards["changes"].clicked.emit()
check("double-clicking a problem opens the device; cards navigate (Failing to Results, showing what fails)", got == ["edge-fw", "Results:fail", "Configs"], got)
dash.period.setCurrentIndex(0); check("changing the period refreshes", dash.bars.rows is not None)
dash.grab().save(SP + (r"\dashboard.png").replace("\\", os.sep))
for n in [x["name"] for x in db.list_devices()]: pass
empty_db = SP + (r"\empty%d.db").replace("\\", os.sep) % int(time.time()); os.environ["NETCHECK_DB"] = empty_db; db.init()
d2 = D.DashboardTab()
check("a fresh install is welcoming, not blank", d2.cards["devices"].value.text() == "0" and not d2.hint.isHidden() and "No checks run yet" in d2.when.text())
os.environ["NETCHECK_DB"] = SP + (r"\db_main.db").replace("\\", os.sep); db.init()

print("== command palette")
import ui.palette as P
pal = P.CommandPalette(); calls = []
pal.set_entries([("Go to Results", "Ctrl+2", lambda: calls.append("results")), ("Device: core1", "10.0.0.1", lambda: calls.append("core1")), ("Device: core2", "10.0.0.2", lambda: calls.append("core2")), ("Tool: SNMP", "", lambda: calls.append("snmp"))])
pal.popup(); check("lists everything at first", pal.list.count() == 4)
pal.box.setText("core"); check("filters by words", pal.list.count() == 2)
pal.box.setText("dev 10.0.0.2"); check("every word must match, in label or hint", pal.list.count() == 1 and "core2" in pal.list.item(0).text())
pal.box.setText("zzz"); check("no match, empty list", pal.list.count() == 0)
pal.box.setText("snmp"); pal.run_item(pal.list.item(0)); check("running an item calls it and closes the palette", calls == ["snmp"] and not pal.isVisible())

print("== main window")
for k in list(STORE): STORE.pop(k)
os.environ["NETCHECK_DB"] = SP + (r"\main%d.db").replace("\\", os.sep) % int(time.time()); db.init()
for n in ("core1", "edge-fw"): dev(n, "fortinet" if n == "edge-fw" else "cisco")
db.save_run([Result("core1", "cpu", "WARN", "85%", numeric=85.0), Result("edge-fw", "wan links", "OK", "2/2")])
w = A.Main(); w.show()
w.inventory.edit_device = lambda d: None            # the real one opens a modal dialog
check("sections, with the overview first", [w.tabs.tabText(i) for i in range(w.tabs.count())] == ["Overview", "Results", "Inventory", "Configs", "History", "Reports", "Tools", "Sessions", "Automation", "Settings", "About"])
check("the overview is filled from stored results at startup", w.dashboard.cards["warn"].value.text() == "1")
db.save_run([Result("core1", "cpu", "WARN", "85%", numeric=85.0), Result("core1", "events", "FAIL", "295", "errors"), Result("edge-fw", "wan links", "OK", "2/2")])
w.dashboard.refresh()
check("a device with a warning and a failure counts in both cards", w.dashboard.cards["warn"].value.text() == "1" and w.dashboard.cards["fail"].value.text() == "1"
      and w.dashboard.cards["ok"].value.text() == "1", {k: x.value.text() for k, x in w.dashboard.cards.items()})
db.save_run([Result("core1", "cpu", "WARN", "85%", numeric=85.0), Result("edge-fw", "wan links", "OK", "2/2")])
w.dashboard.refresh()
w.go("Tools"); check("go() switches sections", w.tabs.currentWidget() is w.tools)
w.open_palette(); names = [w.palette.list.item(i).text() for i in range(w.palette.list.count())]
check("the palette offers sections, tools, devices and actions", any("Go to Inventory" in n for n in names) and any("Tool: Command Runner" in n for n in names) and any("Device: core1" in n for n in names) and any("Run checks" in n for n in names), names[:6])
w.palette.hide()
w.open_device_by_name("core1"); v1 = w.views["core1"]; w.open_device_by_name("core1")
check("a device opens one window, reused on the second request", v1.isVisible() and len(w.views) == 1 and w.views["core1"] is v1)

print("== device window")
V = v1
check("header and info", V.title.text() == "core1" and "Cisco" in V.sub.text() and V.info.rowCount() >= 3)
check("latest checks with the worst first", V.checks.rowCount() == 1 and V.checks.item(0, 1).text() == "WARN")
check("buttons reflect what the device supports", V.buttons["ssh"].isEnabled() and V.buttons["backup"].isEnabled() and not V.buttons["snmp"].isEnabled())
Vf = A.DeviceView([x for x in db.list_devices() if x["name"] == "edge-fw"][0]); check("an API firewall has no SSH button but can open its web page", not Vf.buttons["ssh"].isEnabled() and Vf.buttons["web"].isEnabled() and Vf.buttons["backup"].isEnabled())
Vf.close()
check("history lists the numeric checks and draws one", list(V.keys) == ["CPU"] and len(V.chart.series) == 1)
check("no configuration yet says so", "No configuration backed up yet" in V.cfg.toPlainText())
backup.store("core1", "hostname core1\nvlan 10\n"); time.sleep(1.1); backup.store("core1", "hostname core1\nvlan 10\nvlan 20\n")
V.reload(); V.cfg_view.setCurrentIndex(0)
check("configuration tab shows what changed in the newest version", "+vlan 20" in V.cfg.toPlainText() and V.versions.count() == 2)
V.cfg_view.setCurrentIndex(1); check("or the full text", "vlan 20" in V.cfg.toPlainText() and V.cfg.toPlainText().startswith("hostname core1"))
emitted = []
V.ssh_requested.connect(lambda d: emitted.append(("ssh", d["name"]))); V.tool_requested.connect(lambda k, d: emitted.append((k, d["name"]))); V.edit_requested.connect(lambda d: emitted.append(("edit", d["name"])))
w.sessions.open_device = lambda d: None                    # the real one opens a terminal tab and asks for a password
for k in ("ssh", "ping", "edit"): V.buttons[k].click()
check("quick actions emit what the window needs", emitted == [("ssh", "core1"), ("ping", "core1"), ("edit", "core1")], emitted)
import ui.device_view as DV
opened = []; DV.QDesktopServices.openUrl = staticmethod(lambda url: opened.append(url.toString()))
V.buttons["web"].click(); check("web button opens https://host", opened and opened[0].startswith("https://10.0.0."), opened)
ran = {}
DV.run_one = lambda dev, th, opts: [Result("core1", "cpu", "OK", "12%", numeric=12.0), Result("core1", "memory", "OK", "30%", numeric=30.0)]
V.buttons["checks"].click(); check("run checks is busy while running", not V.buttons["checks"].isEnabled())
for _ in range(100):
    QCoreApplication.processEvents(); time.sleep(0.02)
    if V.buttons["checks"].isEnabled(): break
QCoreApplication.processEvents()
check("results are shown and saved as a run; the rest of the app is told", "2 check(s) done" in V.status.text() and V.checks.rowCount() == 2 and db.last_run()["ok"] == 2)
check("the overview refreshed from it", w.dashboard.cards["warn"].value.text() == "0" and w.dashboard.cards["ok"].value.text() == "2", {k: x.value.text() for k, x in w.dashboard.cards.items()})
DV.backup.backup_device = lambda d: Result("core1", "config backup", "OK", "unchanged")
V.buttons["backup"].click()
for _ in range(100):
    QCoreApplication.processEvents(); time.sleep(0.02)
    if V.buttons["checks"].isEnabled(): break
check("backup from the device window", "unchanged" in V.status.text())
V.grab().save(SP + (r"\device_view.png").replace("\\", os.sep))
V.close(); QCoreApplication.processEvents(); check("closing forgets the window so it can be reopened", "core1" not in w.views)

print("== results context menu")
w.results.results = [Result("core1", "cpu", "ERROR", "", "unexpected output")]; w.results.last_ran = ["core1"]; w.results.repopulate()
w.results.table.expandAll()
shown = []; w.results.show_diagnostic = lambda device, diag: shown.append((device, diag["check_name"]))
db.save_diagnostic("core1", "cpu", "$ show proc\nweird output")
diag = db.get_diagnostics("core1", "cpu", 1); check("a diagnostic exists for that check", bool(diag))
w.results.table.topLevelItem(0).child(0)
import ui.results as RS
class FakeMenu:
    actions = []
    def __init__(self, *a): FakeMenu.actions = []
    def addAction(self, text, fn=None): FakeMenu.actions.append((text, fn)); return None
    def addSeparator(self): pass
    def exec(self, *a): pass
import PySide6.QtWidgets as QW
orig = QW.QMenu; QW.QMenu = FakeMenu
tr = w.results.table; item = tr.topLevelItem(0).child(0) or tr.topLevelItem(0)
tr.itemAt = lambda pos: item
w.results.show_menu(tr.rect().center())
QW.QMenu = orig
labels = [t for t, _ in FakeMenu.actions]
check("the menu offers copy, details and the raw output for a failed check", "Copy row" in labels and "Open device details" in labels and "Show raw device output..." in labels, labels)
dict(FakeMenu.actions)["Show raw device output..."](); check("which opens that check's captured output", shown == [("core1", "cpu")], shown)

print("== background mode")
w.notifier.tray_available = True
db.set_setting("run_in_background", False)
check("off by default", not w.background_mode())
db.set_setting("run_in_background", True)
check("on when the setting is on and a tray exists", w.background_mode())
from PySide6.QtGui import QCloseEvent
ev = QCloseEvent(); w.closeEvent(ev)
check("closing the window hides it instead of quitting", not ev.isAccepted() and not w.isVisible())
w.show(); w.tray.showMessage = lambda *a, **k: None
db.set_setting("run_in_background", False); ev = QCloseEvent(); w._quitting = False
w.closeEvent(ev); check("with the setting off, closing really closes", ev.isAccepted())
w2 = A.Main(); w2.notifier.tray_available = True; db.set_setting("run_in_background", True); w2.show()
quit_called = []; A.QApplication.quit = staticmethod(lambda: quit_called.append(1))
w2.quit_for_real(); check("'Quit' from the tray really quits even in background mode", quit_called == [1] and w2._quitting)
logo = A.app_icon(); check("the logo icon is drawn without image files", not logo.isNull() and logo.availableSizes())
check("crash logging writes next to the database", A.data_dir().exists())
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
