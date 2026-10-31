# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The second interface review: one status palette, section headers, Results that opens on the latest results, Overview cards that
# filter, empty states with buttons, acknowledging and snoozing problems, the status strip, and narrowing everything to one client.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ux2%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingux2%d" % int(time.time()))
from core import acks, db, display, notify, reports, scope
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from drivers.base import Result
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== acknowledging and snoozing (the rules)")
P = [("interfaces", "FAIL", "down: Gi0/7"), ("cpu", "WARN", "82%")]
acks.put_aside("sw1", P)
check("acknowledged while the problems stay the same", acks.state("sw1", P) == "acknowledged")
check("or get better (one fixed, one milder)", acks.state("sw1", [("interfaces", "WARN", "")]) == "acknowledged")
check("a new problem ends it", acks.state("sw1", P + [("bgp", "WARN", "")]) is None and acks.state("sw1", P) is None)
acks.put_aside("sw1", P)
check("so does one getting worse", acks.state("sw1", [("interfaces", "FAIL", ""), ("cpu", "FAIL", "")]) is None)
acks.put_aside("sw1", P)
check("and being healthy again clears it", acks.state("sw1", []) is None and "sw1" not in db.get_setting("acks"))
now = datetime.now()
acks.put_aside("fw1", P, hours=4, now=now)
check("snoozed for a while", acks.state("fw1", P, now=now + timedelta(hours=3)) == "snoozed")
check("a snooze ignores a new problem of the same level", acks.state("fw1", P + [("vpn", "WARN", "")], now=now + timedelta(hours=1)) == "snoozed")
check("but not something worse", acks.state("fw1", [("x", "ERROR", "")], now=now + timedelta(hours=1)) is None)
acks.put_aside("fw1", P, hours=4, now=now)
check("and it ends on time", acks.state("fw1", P, now=now + timedelta(hours=5)) is None)
acks.put_aside("fw1", P, hours=4); check("clear brings it back at once", acks.clear("fw1") and acks.state("fw1", P) is None)
check("put-aside state stays on this computer", "acks" in db.NOT_PORTABLE and "client_scope" in db.NOT_PORTABLE)
acks.put_aside("sw1", P)
held = acks.held_by_results([Result("sw1", "interfaces", "FAIL"), Result("sw1", "cpu", "WARN"), Result("sw2", "cpu", "FAIL")])
check("notifications skip an acknowledged device whose problems are unchanged", held == {"sw1"}, held)
check("but not once it has a new problem", acks.held_by_results([Result("sw1", "interfaces", "FAIL"), Result("sw1", "ntp", "WARN")]) == set())
acks.clear("sw1")

print("== notifications leave put-aside devices alone")
sent = []
db.set_setting("notify_enabled", True); db.set_setting("notify_on_manual", True)
real_channels, real_deliver = notify.channels, notify.deliver
notify.channels = lambda: [{"name": "ops", "type": "webhook", "enabled": True, "min": "WARN and worse", "recoveries": True}]
notify.deliver = lambda ch, msg, desktop=None, secrets=None, retry_delay=2: (sent.append(msg.plain()), (True, "ok"))[1]
db.save_device(dict(name="nsw", vendor="cisco", host="10.9.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
acks.put_aside("nsw", [("cpu", "FAIL", "")])
notify.process_run([Result("nsw", "cpu", "FAIL", "99%")], ["nsw"], scheduled=True, retry_delay=0)
check("an acknowledged failure is not announced", not sent, sent)
acks.clear("nsw")
notify.process_run([Result("nsw", "cpu", "FAIL", "99%")], ["nsw"], scheduled=True, retry_delay=0)
check("once it is no longer put aside, it is", sent and "nsw" in sent[-1], sent)
notify.channels, notify.deliver = real_channels, real_deliver
db.set_setting("notify_enabled", False)
db.delete_device(next(x["id"] for x in db.list_devices() if x["name"] == "nsw"))

print("== the status palette")
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
from ui import status as st, theme
for th in ("Light", "Dark"):
    theme.apply(app, th)
    bg = theme.current()["surface"]
    for preset in ("Default", "Color-blind safe"):
        reports.apply_colors(preset)
        worst = min(st.contrast(st.ink(s), bg) for s in ("OK", "WARN", "FAIL", "ERROR"))
        check(f"{th}, {preset}: every status reads as text (contrast 4.5+)", worst >= 4.5, worst)
reports.apply_colors("Default")
check("the ink keeps the pill's hue", abs(st.QColor(st.ink("FAIL")).hslHue() - st.QColor(reports.COLORS["FAIL"]).hslHue()) <= 6)
check("a word that is not a status is grey", st.ink("Not checked") == st.GREY and st.fill("Disabled") is None)
check("levels for tools that colour numbers", st.level(5, 30, 7, lower_is_worse=True) == "FAIL" and st.level(20, 30, 7, lower_is_worse=True) == "WARN" and st.level(90, 65, 40, lower_is_worse=True) == "OK"
      and st.level(85, 80, 90) == "WARN")
A.apply_look(app)

print("== a window with two clients")
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
acme, globex = db.create_folder("Acme Dental"), db.create_folder("Globex Law")
sub = db.create_folder("Branch", parent_id=acme)
def dev(name, vendor, host, fid, **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform=kw.pop("platform", ""), username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location=kw.pop("location", ""), details="", tags="", folder_id=fid)
    db.save_device(d)
dev("acme-sw1", "cisco", "10.0.0.1", acme); dev("acme-fw", "fortinet", "10.0.0.254", sub); dev("acme-dc", "windows", "10.0.0.15", acme, platform="agent")
dev("globex-pa", "paloalto", "10.1.1.1", globex); dev("globex-sw", "cisco", "10.1.0.2", globex)
db.save_run([Result("acme-sw1", "interfaces", "FAIL", "46/48 up", "down: Gi1/0/7"), Result("acme-sw1", "cpu", "OK", "12%"), Result("acme-fw", "cpu", "WARN", "82%", "above 80"),
             Result("acme-dc", "disks", "OK", "40%"), Result("globex-pa", "connection", "ERROR", "", "rejected"), Result("globex-sw", "cpu", "OK", "9%")])
w = A.Main(); w.resize(1400, 860); w.show(); app.processEvents()

print("== Results opens on the latest results")
r = w.results
check("the stored results are there without running anything", r.stored and r.table.topLevelItemCount() == 5 and not r.hint.isVisible(), r.table.topLevelItemCount())
check("worst first, and the summary says where they come from", r.table.topLevelItem(0).text(0) == "globex-pa" and "Latest results for 5 devices" in r.summary.text() and ("ago" in r.summary.text() or "just now" in r.summary.text()), r.summary.text())
check("the counts are filled", r.chips.counts == {"OK": 3, "WARN": 1, "FAIL": 1, "ERROR": 1}, r.chips.counts)
check("the device that needs a look is open", r.table.topLevelItem(0).isExpanded())

print("== the Overview's cards filter Results")
d = w.dashboard
w.go("Overview"); d.cards["fail"].clicked.emit(); app.processEvents()
names = [r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())]
check("Failing opens Results with only what fails", w.tabs.currentWidget() is r and r.status_mode() == 3 and names == ["globex-pa", "acme-sw1"], names)
check("and lists only the failing checks", r.table.topLevelItem(1).childCount() == 1 and r.table.topLevelItem(1).child(0).text(1) == "interfaces")
d.cards["warn"].clicked.emit(); app.processEvents()
check("Warnings: only the warnings", [r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())] == ["acme-fw"])
d.cards["ok"].clicked.emit(); app.processEvents()
check("Healthy: the devices with nothing wrong, every check listed", sorted(r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())) == ["acme-dc", "globex-sw"])
check("each card says what it shows", d.cards["fail"].toolTip().startswith("Show FAIL and ERROR") and "Inventory" in d.cards["devices"].toolTip())
r.show_filter("all")

print("== empty states with a next step")
r.results, r.stored = [], False; r.repopulate()
check("an empty Results offers Run checks", r.hint.isVisibleTo(r) and [b.text() for b in r.hint.buttons] == ["Run checks"])
r.load_stored()
r.show_filter("warn"); r.results = [x for x in r.results if x.status != "WARN"]; r.repopulate()
check("a filter that hides everything says so, and offers to show all", "Nothing matches" in r.hint.head.text() and [b.text() for b in r.hint.buttons] == ["Show all results"])
r.hint.buttons[0].click(); check("which it does", r.status_mode() == 0 and not r.funnel.active())
r.stored = True; r.load_stored()
w.go("Sessions")
check("Sessions offers the usual first steps", [b.text() for b in w.sessions.welcome_buttons.values()] == ["New SSH session", "New Remote Desktop", "New serial console"])
w.sessions._fill_more()
check("Delete has moved into the More menu (the row stays one line)", "Delete" in [a.text() for a in w.sessions.more_menu.actions()] and not w.sessions.delete_btn.isVisibleTo(w.sessions))
check("History's empty run list can run checks", [b.text() for b in w.history.runs_hint.buttons] == ["Run checks"])

print("== section headers")
for attr, title in w.HEADERS:
    h = w.headers[attr]
    check(f"{title} has the same header", h.title.text() == f"Global - {title}" and h.title.property("title") is True and getattr(w, attr).layout().itemAt(0).widget() is h)
w.update_headers()
check("the Inventory's says how the devices are doing", w.headers["inventory"].context.text() == "5 devices  ·  2 failing  ·  1 with warnings", w.headers["inventory"].context.text())
check("Results has one too, with its summary as the context", r.header.title.text() == "Global - Results" and r.header.context is r.summary)

print("== Inventory")
inv = w.inventory; w.go("Inventory"); inv.refresh(); app.processEvents()
vals = {d_["name"]: inv._device_values(d_) for d_ in db.list_devices()}
check("no 'N/A' anywhere", not any("N/A" in v for row in vals.values() for v in row))
check("a Last checked column says when", inv.COLS[inv.CHECKED] == "Last checked" and vals["acme-sw1"][inv.CHECKED] == "just now")
check("the status is drawn as the same pill", type(inv.table.itemDelegateForColumn(inv.STATUS)).__name__ == "StatusDelegate")

print("== Needs attention: doing something about a problem")
w.go("Overview"); d.refresh()
row = d.names.index("acme-sw1"); d.attention.selectRow(row); app.processEvents()
acts = d.row_actions(row)
check("each problem's row carries its own actions, and Connect says how", acts["open"].text() == "Open" and acts["run"].text() == "Run checks" and acts["connect"].text() == "SSH"
      and d.act_ack.text() == "Acknowledge" and d.act_ack.isEnabled(), {k: b and b.text() for k, b in acts.items()})
check("a device with nothing to connect to has no Connect button", any(d.row_actions(i)["connect"] is None for i in range(len(d.names))) or all(d._connect_kind(db.find_device(n)) for n in d.names))
asked = []; real_act = w.on_device_action
w.dashboard.device_action.disconnect(); w.dashboard.device_action.connect(lambda a, n: asked.append((a, n)))
acts["connect"].click(); acts["run"].click(); acts["open"].click()
check("they ask the main window for the device, without needing a selection", asked == [("ssh", "acme-sw1"), ("run", "acme-sw1"), ("open", "acme-sw1")], asked)
w.dashboard.device_action.disconnect(); w.dashboard.device_action.connect(w.on_device_action)
d.attention.selectRow(d.names.index("acme-dc") if "acme-dc" in d.names else 0)
started = []; real_start = r._start; r._start = lambda picked, scheduled: started.append((picked, scheduled))
w.on_device_action("run", "acme-sw1")
check("Run checks runs just that device, in Results", started == [(["Device: acme-sw1"], False)] and w.tabs.currentWidget() is r)
r._start = real_start
check("and the group label for one device matches only it", db.in_group({"name": "acme-sw1"}, "Device: acme-sw1") and not db.in_group({"name": "x"}, "Device: acme-sw1"))
w.go("Overview"); d.refresh(); d.attention.selectRow(d.names.index("acme-sw1")); app.processEvents()
d.act_ack.click(); app.processEvents()
check("Acknowledge takes it off the list", "acme-sw1" not in d.names and acks.state("acme-sw1", [("interfaces", "FAIL")]) == "acknowledged")
check("the list says some are put aside, and can show them", d.show_aside.isVisibleTo(d) and "(1)" in d.show_aside.text())
d.show_aside.setChecked(True); app.processEvents()
row = d.names.index("acme-sw1")
check("shown again, marked and last", row == len(d.names) - 1 and "(acknowledged" in d.attention.item(row, 2).text())
d.attention.selectRow(row); app.processEvents()
check("its button now undoes it", d.act_ack.text() == "Undo")
d.act_ack.click(); app.processEvents()
check("undo brings it back", acks.state("acme-sw1", [("interfaces", "FAIL")]) is None and "(acknowledged" not in " ".join(d.attention.item(i, 2).text() for i in range(d.attention.rowCount())))
d.show_aside.setChecked(False)
d.attention.selectRow(d.names.index("acme-fw")); d._put_aside(24); app.processEvents()
check("Snooze 24 hours puts it aside until then", "acme-fw" not in d.names and acks.state("acme-fw", [("cpu", "WARN")]) == "snoozed")
check("each is written to the audit log", sum(1 for a in db.connect().execute("SELECT * FROM audit WHERE action LIKE 'problem %'").fetchall()) >= 3)
acks.clear("acme-fw"); d.refresh()

print("== the status strip")
s = w.strip
s.refresh()
check("it says when the last run was and how it went", s.run.text().startswith("Last run just now") and "FAIL" in s.run.text() and "ERROR" in s.run.text(), s.run.text())
check("and what is switched off", s.schedule.text() == "Scheduled runs off" and s.backups.text() == "Scheduled backups off" and s.notify.text() == "Notifications off" and s.receiver.text() == "Agents off")
db.set_setting("schedule_enabled", True); db.set_setting("schedule_minutes", 30); w.scheduler.apply(); s.refresh()
check("a scheduled run says when", s.schedule.text().startswith("Next run "), s.schedule.text())
db.set_setting("schedule_enabled", False); w.scheduler.apply()
s.on_progress(2, 5)
check("while checks run it shows the progress", s.run.text() == "Checking devices: 2 of 5 done" and s.progress.isVisibleTo(s) and s.progress.value() == 2)
s.on_progress(5, 5)
check("and goes back to the summary at the end", s.run.text().startswith("Last run") and not s.progress.isVisibleTo(s))
s.schedule.clicked.emit()
check("each part opens where it is set", w.tabs.currentWidget() is w.settings and w.settings.pages[w.settings.stack.currentIndex()].title == "Checks" and w.settings.pages[w.settings.stack.currentIndex()].tabs.tabText(w.settings.pages[w.settings.stack.currentIndex()].tabs.currentIndex()) == "Schedule")

print("== one organization at a time")
from core import orgs as ORGS
check("no organizations yet: no switcher", not w.tabs.org.isVisibleTo(w.tabs.side))
a_org, g_org = ORGS.create("Acme Dental", "ACME"), ORGS.create("Globex Law", "GLOBEX")
devs = {x["name"]: x for x in db.list_devices()}
ORGS.move_devices([devs[n] for n in ("acme-sw1", "acme-fw", "acme-dc")], a_org)
ORGS.move_devices([devs[n] for n in ("globex-pa", "globex-sw")], g_org)
w.refresh_orgs(); app.processEvents()
check("the sidebar offers Global and the organizations", [w.tabs.org.itemText(i) for i in range(w.tabs.org.count())] == ["Global", "Acme Dental", "Globex Law"]
      and w.tabs.org.isVisibleTo(w.tabs.side))
w.tabs.org.setCurrentIndex(1); app.processEvents()
check("picking one is remembered; the window title stays Toner", ORGS.current() == a_org and w.windowTitle() == "Toner")
check("every section's title names it", w.headers["inventory"].title.text() == "Acme Dental - Inventory" and d.title.text() == "Acme Dental - Overview"
      and r.header.title.text() == "Acme Dental - Results", (w.headers["inventory"].title.text(), d.title.text()))
check("the Overview counts only its devices", d.cards["devices"].value.text() == "3" and sorted(d.names) == ["acme-fw", "acme-sw1"], (d.cards["devices"].value.text(), d.names))
check("Results shows only its devices, and says so", sorted(r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())) == ["acme-dc", "acme-fw", "acme-sw1"]
      and "3 devices" in r.summary.text() and r.chips.counts.get("ERROR", 0) == 0, r.summary.text())
inv.refresh()
top = [inv.table.topLevelItem(i).text(0) for i in range(inv.table.topLevelItemCount())]
check("the Inventory shows its own folders", top == ["Acme Dental  (3)"], top)
check("Configs lists only its devices", sorted(w.configs.names) == ["acme-dc", "acme-fw", "acme-sw1"], w.configs.names)
w.history.refresh(); check("History's charts list only its devices", all(n.startswith("acme") for n in w.history.map))
w.reports.load_source(); check("Reports cover only its devices", w.reports.base and all(x.device.startswith("acme") for x in w.reports.base))
w.update_headers(); check("the headers count only its devices", w.headers["inventory"].context.text().startswith("3 devices"))
ran = []; real_worker = A.ResultsTab.__init__.__globals__["Worker"]
class W:
    def __init__(self, devices, *a): ran.append(sorted(x["name"] for x in devices)); self.batch = self; self.finished = self
    def connect(self, *a): pass
    def start(self): pass
    def isRunning(self): return False
A.ResultsTab.__init__.__globals__["Worker"] = W
r._start([], scheduled=False)
check("a run covers only its devices", ran[-1] == ["acme-dc", "acme-fw", "acme-sw1"], ran)
r._active = False
r.run_btn.setEnabled(True)
w.tabs.org.setCurrentIndex(0); app.processEvents()
check("Global shows everything again", ORGS.current() == 0 and d.cards["devices"].value.text() == "5" and w.headers["inventory"].title.text() == "Global - Inventory")
r._start([], scheduled=False)
check("a run in Global covers every organization", ran[-1] == ["acme-dc", "acme-fw", "acme-sw1", "globex-pa", "globex-sw"], ran)
r._active = False
A.ResultsTab.__init__.__globals__["Worker"] = real_worker
r.run_btn.setEnabled(True)
r.reset_view()
orgcol = {r.table.topLevelItem(i).text(0): r.table.topLevelItem(i).text(r.ORG) for i in range(r.table.topLevelItemCount())}
check("Results in Global names each device's organization", orgcol.get("acme-sw1") == "Acme Dental" and orgcol.get("globex-pa") == "Globex Law"
      and not r.table.isColumnHidden(r.ORG), orgcol)
inv.refresh()
top = [inv.table.topLevelItem(i).text(0) for i in range(inv.table.topLevelItemCount())]
check("the Inventory in Global has a branch per organization", top == ["Global  (0)", "Acme Dental  (3)", "Globex Law  (2)"], top)
ORGS.set_archived(a_org, True); w.refresh_orgs(); app.processEvents()
check("an archived organization leaves the switcher", [w.tabs.org.itemText(i) for i in range(w.tabs.org.count())] == ["Global", "Globex Law"])
ORGS.set_archived(a_org, False); w.refresh_orgs()
w.tabs.setCollapsed(True); check("with icons only, the switcher stays", w.tabs.org.isVisibleTo(w.tabs.side))
w.tabs.setCollapsed(False); check("with the names, it is still there", w.tabs.org.isVisibleTo(w.tabs.side))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
