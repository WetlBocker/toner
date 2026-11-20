# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Monitoring profiles: the page, the dialog that makes one, and the line on a device that follows one.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\mpui%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingmp%d" % int(time.time()))
from core import checks, db, display, perms
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
    d = dict(name=name, vendor=vendor, host="127.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])
access = dev("access-sw", tags="access", location="HQ")
core_ = dev("core-rtr", tags="core", location="HQ")
fw = dev("edge-fw", vendor="fortinet", tags="access")
db.set_setting("disabled_checks", ["cisco:memory"])

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QCheckBox, QLabel, QMessageBox, QPushButton
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as ST
import ui.inventory as I
import ui.settings_pages.monitoring as M
warned, asked, answer = [], [], [QMessageBox.StandardButton.Yes]
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), answer[0])[1])
KEY = Qt.ItemDataRole.UserRole
def ticked(w): return [w.listing.item(i).data(KEY) for i in range(w.listing.count()) if w.listing.item(i).checkState() == Qt.CheckState.Checked]
def only(w, keys):
    for i in range(w.listing.count()):
        w.listing.item(i).setCheckState(Qt.CheckState.Checked if w.listing.item(i).data(KEY) in keys else Qt.CheckState.Unchecked)
def texts(w): return [x.text() for x in w.findChildren(QLabel)]
CISCO = [k for k, _ in checks.CATALOG["cisco"]]

print("== making a profile")
d = M.MonitoringProfileDialog(); d.show(); app.processEvents()
check("the window is called New monitoring profile", d.windowTitle() == "New monitoring profile")
check("it asks for a name and a vendor first", d.form.labelForField(d.name).text() == "Name" and d.form.labelForField(d.vendor).text() == "Vendor" and d.form.rowCount() == 2)
kinds = [d.vendor.itemData(i) for i in range(d.vendor.count())]
check("the vendors are the kinds of device Settings > Checks lists, by the same names", kinds == [v for v in checks.CATALOG if v != "all"]
      and [d.vendor.itemText(i) for i in range(d.vendor.count())] == [display.type_name(v) for v in kinds], kinds)
d.vendor.setCurrentIndex(d.vendor.findData("cisco"))
check("then the checks that run, the limits, and where it applies", all(t in texts(d) for t in ("<b>Checks that run</b>", "<b>Limits</b>")) and d.below.labelForField(d.scope).text() == "Applies to", texts(d))
check("the list of checks starts from the global one for that vendor", ticked(d.checks) == [k for k in CISCO if k != "memory"], ticked(d.checks))
check("and can be ticked straight away", all(d.checks.listing.item(i).flags() & Qt.ItemFlag.ItemIsUserCheckable for i in range(d.checks.listing.count())))
check("what belongs to one device is not shown (its own-list box, its interfaces, the reset button)",
      not d.checks.own.isVisibleTo(d) and not d.checks.if_box.isVisibleTo(d) and not any(b.isVisibleTo(d) and "global settings" in b.text() for b in d.checks.findChildren(QPushButton)))
check("the limits table is the one on a device", [d.checks.limits.horizontalHeaderItem(c).text() for c in range(4)] == ["Own limits", "Check", "WARN", "FAIL"])
check("it can apply to every device, a location, a tag or single devices of its vendor", list(d.scope.boxes) == ["All devices", "Location: HQ", "Tag: access", "Tag: core", "Device: access-sw", "Device: core-rtr"], list(d.scope.boxes))
check("nothing is chosen to begin with", d.scope.selected() == [] and d.scope.text() == "Choose groups")
d.scope.set_selected(["Tag: access"])
d.vendor.setCurrentIndex(d.vendor.findData("fortinet"))
check("another vendor shows its own checks and its own devices, and keeps what was chosen", d.checks.listing.count() == len(checks.CATALOG["fortinet"]) and "Device: edge-fw" in d.scope.boxes
      and "Device: access-sw" not in d.scope.boxes and d.scope.selected() == ["Tag: access"])
d.vendor.setCurrentIndex(d.vendor.findData("cisco"))
check("without a name it is not saved", d.problems() == ["Give the profile a name."], d.problems())
d.accept()
check("...the window says so and stays open", warned[-1:] == ["Give the profile a name."] and d.isVisible() and not d.result(), warned)
d.name.setText("  Access switches ")
only(d.checks, ("cpu", "memory"))
cpu_row = list(db.DEFAULT_THRESHOLDS).index("cpu")
d.checks.limits.item(cpu_row, 0).setCheckState(Qt.CheckState.Checked)
d.checks.spins["cpu"][0].setValue(50); d.checks.spins["cpu"][1].setValue(60)
want = {"name": "Access switches", "vendor": "cisco", "checks": ["cpu", "memory"], "thresholds": {"cpu": {"warn": 50.0, "fail": 60.0}}, "scopes": ["Tag: access"]}
check("what is saved is the name, the vendor, the ticked checks, the ticked limits and where it applies", d.values() == want, d.values())
d.checks.spins["cpu"][0].setValue(99)
check("limits that contradict each other are caught", len(d.problems()) == 1 and "CPU" in d.problems()[0], d.problems())
d.checks.spins["cpu"][0].setValue(50)
d.accept()
check("with everything in order it closes", d.result() == 1 and not d.isVisible())
d2 = M.MonitoringProfileDialog(others=["Access switches"]); d2.name.setText("access SWITCHES")
check("a name that is taken is refused, whatever its capitals", d2.problems() == ["A profile named 'access SWITCHES' already exists."], d2.problems())
none = M.MonitoringProfileDialog(); none.name.setText("x"); only(none.checks, ())
check("a profile may run no checks at all", none.values()["checks"] == [] and none.values()["thresholds"] == {} and none.values()["scopes"] == [])

print("== changing one")
e = M.MonitoringProfileDialog(want, others=["Core"]); e.show(); app.processEvents()
check("the window is called Edit monitoring profile", e.windowTitle() == "Edit monitoring profile")
check("it shows what was saved", e.values() == want, e.values())
check("the vendor can no longer be changed", not e.vendor.isEnabled() and e.vendor.currentData() == "cisco")
check("its own name is not a duplicate", e.problems() == [])
e.close()
db.set_setting("disabled_checks", [])
e = M.MonitoringProfileDialog(want)
check("its checks are its own, not the global list of the day", ticked(e.checks) == ["cpu", "memory"])
db.set_setting("disabled_checks", ["cisco:memory"])

print("== the page")
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
page = next(p for p in S.pages if p.title == "Monitoring profiles")
check("Monitoring profiles is listed under Monitoring, after Checks", S.page_titles()[:4] == ["General", "Thresholds", "Checks", "Monitoring profiles"]
      and dict(ST.GROUPS)["Monitoring"] == ["General", "Thresholds", "Checks", "Monitoring profiles", "Scanning", "Maintenance"], S.page_titles()[:6])
check("an admin can open or lock it for a role like any other page", "Monitoring profiles" in perms.SETTINGS_PAGES and perms.DEFAULTS["Tech"]["settings:Monitoring profiles"] is False)
check("it says what a profile is", "A monitoring profile is a set of checks and limits for one vendor. Assign it to a group, a tag or single devices. "
      "Devices without one use Settings > Checks and Settings > Thresholds." in texts(page))
check("the table lists name, vendor, where it applies and its checks", [page.table.horizontalHeaderItem(c).text() for c in range(page.table.columnCount())] == ["Name", "Vendor", "Applies to", "Checks"])
check("with buttons to add, edit, duplicate and remove", [b.text() for b in page.findChildren(QPushButton)] == ["Add...", "Edit...", "Duplicate", "Remove"])
check("there are none to begin with", page.table.rowCount() == 0 and page.items == [])
i = S.pages.index(page)
fill = [lambda dlg: (dlg.vendor.setCurrentIndex(dlg.vendor.findData("cisco")), dlg.name.setText("Access switches"), only(dlg.checks, ("cpu", "memory")), dlg.scope.set_selected(["Tag: access"]),
                     dlg.checks.limits.item(cpu_row, 0).setCheckState(Qt.CheckState.Checked), dlg.checks.spins["cpu"][0].setValue(50), dlg.checks.spins["cpu"][1].setValue(60))]
def fake_exec(self):
    fill[0](self); self.accept(); return self.result()
M.MonitoringProfileDialog.exec = fake_exec
page.add()
row = lambda r: [page.table.item(r, c).text() for c in range(4)]
check("a new profile appears in the table", page.table.rowCount() == 1 and row(0) == ["Access switches", "Cisco", "Tag: access", f"2 of {len(CISCO)}"], row(0) if page.table.rowCount() else "")
check("it is an unsaved change until Save", db.get_setting("monitoring_profiles") == [] and ST.signature(page) != S.baseline[i])
changes = dict(S.pending_changes()).get("Monitoring profiles")
check("the list of changes names it and what it holds", changes == [("Profile: Access switches", "(not set)", "Cisco. Checks: CPU, Memory. Limits: CPU % WARN 50 / FAIL 60. Applies to: Tag: access.")], changes)
page.save()
check("Save stores it", db.get_setting("monitoring_profiles") == [want], db.get_setting("monitoring_profiles"))
check("and the device in that group now follows it", (db.profile_for(access) or {}).get("name") == "Access switches" and db.profile_for(core_) is None and "cisco:memory" not in db.disabled_for(access, {"cisco:memory"}))
warned.clear(); fill[0] = lambda dlg: (dlg.vendor.setCurrentIndex(dlg.vendor.findData("fortinet")), dlg.name.setText("access switches"))
page.add()
check("a second profile cannot take the same name", page.table.rowCount() == 1 and warned == ["A profile named 'access switches' already exists."], warned)
page.table.selectRow(0); page.duplicate()
check("Duplicate makes a copy under a new name, assigned to nothing", page.table.rowCount() == 2 and row(1) == ["Access switches (copy)", "Cisco", "", f"2 of {len(CISCO)}"] and page.items[1]["thresholds"] == want["thresholds"], row(1))
page.table.selectRow(0); page.duplicate()
check("a second copy gets a name of its own", [p["name"] for p in page.items] == ["Access switches", "Access switches (copy)", "Access switches (copy 2)"], [p["name"] for p in page.items])
page.table.selectRow(1); fill[0] = lambda dlg: (dlg.name.setText("Core"), dlg.scope.set_selected(["All devices", "Device: core-rtr"]))
page.edit()
check("Edit changes the chosen one in place", row(1) == ["Core", "Cisco", "All devices, Device: core-rtr", f"2 of {len(CISCO)}"] and page.items[1]["vendor"] == "cisco", row(1))
page.table.selectRow(2); answer[0] = QMessageBox.StandardButton.No; page.remove()
check("Remove asks first, saying what happens to its devices", asked[-1] == "Remove the profile 'Access switches (copy 2)'? Its devices go back to the global checks and thresholds." and page.table.rowCount() == 3, asked[-1:])
answer[0] = QMessageBox.StandardButton.Yes; page.remove()
check("and removes it on Yes", [p["name"] for p in page.items] == ["Access switches", "Core"])
page.table.clearSelection(); page.table.setCurrentCell(-1, -1); n = len(asked); page.remove(); page.edit(); page.duplicate()
check("with nothing chosen the buttons do nothing", len(asked) == n and len(page.items) == 2)
page.load()
check("leaving without Save drops the edits", [p["name"] for p in page.items] == ["Access switches"] and page.table.rowCount() == 1)
db.set_setting("monitoring_profiles", [want, "junk", {"name": "half"}]); page.load()
check("entries that are not profiles are not listed", page.table.rowCount() == 1)
db.set_setting("monitoring_profiles", [want])

print("== on a device")
line = "This device follows the monitoring profile 'Access switches'."
dlg = I.DeviceDialog(access); dlg.show(); app.processEvents(); tab = dlg.checks_tab
check("Edit device > Checks says which profile the device follows", tab.follows.text() == line and tab.follows.isVisibleTo(tab), tab.follows.text())
check("its greyed list shows the profile's checks, not the global ones", ticked(tab) == ["cpu", "memory"] and not tab.own.isChecked(), ticked(tab))
check("and the limits it has not set itself show the profile's", tab.spins["cpu"][0].value() == 50 and tab.spins["cpu"][1].value() == 60 and not tab.spins["cpu"][0].isEnabled())
check("nothing of the profile is saved on the device", dlg.values()["checkopts"] == {})
tab.own.setChecked(True)
check("choosing the device's own list starts from the profile's", tab.values()["checks"] == ["cpu", "memory"])
dlg.vendor.setCurrentIndex(dlg.vendor.findData("fortinet")); app.processEvents()
check("changed to another vendor the line goes: the profile is for one vendor", not tab.follows.isVisibleTo(tab))
dlg.close()
other = I.DeviceDialog(core_); other.show(); app.processEvents()
check("a device no profile applies to has no such line, and shows the global list", not other.checks_tab.follows.isVisibleTo(other.checks_tab) and ticked(other.checks_tab) == [k for k in CISCO if k != "memory"])
other.close()
new = I.DeviceDialog(); new.show(); app.processEvents()
check("nor has a new device", not new.checks_tab.follows.isVisibleTo(new.checks_tab))
new.close()

print("== the notes that point to it")
check("Settings > Checks says a profile gives a group of devices its own list", any(
    "A monitoring profile gives a group of devices its own list: Settings > Monitoring profiles. Devices with neither use this list." in t
    for t in texts(next(p for p in S.pages if p.title == "Checks"))))
check("Settings > Thresholds says where a profile's limits sit", any(
    "A monitoring profile (Settings > Monitoring profiles) can set limits for its devices; they beat these overrides. "
    "A device can also carry its own limits (Inventory > Edit device > Checks); they beat everything." in t
    for t in texts(next(p for p in S.pages if p.title == "Thresholds"))))

print("== the limits table fits its boxes")
from ui.devicechecks import DeviceChecks
def limits_fit(w, label, top=None):
    (top or w).resize(640, 760); w.show(); app.processEvents(); app.processEvents()
    t = w.limits; h = t.horizontalHeader(); bad_rows = []
    for r in range(t.rowCount()):
        for c in (2, 3):
            box = t.cellWidget(r, c); cell = t.visualRect(t.model().index(r, c))
            if t.rowHeight(r) < box.sizeHint().height() or not cell.contains(box.geometry()): bad_rows.append((r, c, t.rowHeight(r), box.sizeHint().height(), box.geometry(), cell))
    check(label + ": every row is as tall as its boxes and each box lies inside its cell", not bad_rows, bad_rows[:2])
    check(label + ": WARN and FAIL are the same width, and the columns fill the viewport",
          h.sectionSize(2) == h.sectionSize(3) and sum(h.sectionSize(i) for i in range(4)) == t.viewport().width(), [h.sectionSize(i) for i in range(4)] + [t.viewport().width()])
    check(label + ": the Check column takes the slack", h.sectionResizeMode(1) == h.ResizeMode.Stretch and h.sectionSize(1) > 0)
pd = M.MonitoringProfileDialog(); pd.show(); app.processEvents()
limits_fit(pd.checks, "profile window", pd)
ed = DeviceChecks(); ed.set_vendor("cisco"); limits_fit(ed, "edit device")
check("the reset button says Use Global Settings", [b.text() for b in ed.findChildren(QPushButton) if "Global" in b.text()] == ["Use Global Settings"])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
