# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\rf%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, reports
db.init()
import keyring
keyring.set_password = lambda *a: None
keyring.get_password = lambda *a: None
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QCheckBox, QMessageBox, QWidgetAction
app = QApplication([])
import app as A
A.apply_look(app)
import ui.reports_tab as RT
from ui.widgets import FilterButton
from drivers.base import Result

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor, loc, tags=""):
    db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location=loc, details="", folder_id=None, tags=tags))

dev("core-sw1", "cisco", "Chicago", "core, wan"); dev("edge-fw", "fortinet", "Chicago", "edge, PCI"); dev("dr-sw", "juniper", "Denver", "core"); dev("lab", "snmp", "", "")
res = [Result("core-sw1", "cpu", "OK", "5%"), Result("core-sw1", "memory", "WARN", "85%"), Result("edge-fw", "wan links", "FAIL", "1/2"),
       Result("dr-sw", "cpu", "OK", "9%"), Result("lab", "cpu", "ERROR", ""), Result("udm / ap1", "cpu", "OK", "1%")]
rt = RT.ReportsTab(lambda: res); rt.resize(1000, 600); rt.show()
names = lambda: sorted({r.device for r in rt.selected_results()})
n = lambda: len(rt.selected_results())

import ui.inventory as I
inv = I.InventoryTab(); inv_mode = inv.filter_btn.popupMode()
print("== the button")
check("it is the Inventory tab's funnel, icon only until something is ticked", isinstance(rt.filter, FilterButton) and not rt.filter.icon().isNull() and rt.filter.text() == "" and rt.filter.toolButtonStyle() == Qt.ToolButtonStyle.ToolButtonIconOnly)
check("it opens its menu on a click, like the Inventory one", rt.filter.popupMode() == inv_mode)

check("both tabs draw the same funnel", rt.filter.icon().pixmap(32, 32).toImage() == inv.filter_btn.icon().pixmap(32, 32).toImage())
check("the old Locations drop-down is gone", not hasattr(rt, "locations"))
check("nothing is filtered at first", n() == 6 and not rt.filter.filtering())
check("the menu offers Status, Location, Vendor and Tag", list(rt.filter.sections) == ["Status", "Location", "Vendor", "Tag"])
s = rt.filter.sections
check("only values that exist are offered, worst status first", [v for _, v in s["Status"]] == ["ERROR", "FAIL", "WARN", "OK"] and [v for _, v in s["Location"]] == ["Chicago", "Denver", "(no location)"], s["Status"])
check("vendors are shown by name, tags in lower case", [t for t, _ in s["Vendor"]] == ["Fortinet", "Juniper", "Cisco", "Generic SNMP"] or sorted(t for t, _ in s["Vendor"]) == sorted(["Cisco", "Fortinet", "Juniper", "Generic SNMP"]), s["Vendor"])
check("tags", [v for _, v in s["Tag"]] == ["core", "edge", "pci", "wan"], s["Tag"])

print("== filtering")
def tick(title, *vals):
    rt.filter.picked[title] = set(vals); rt.filter._update(); rt.filter.changed.emit()
tick("Status", "FAIL"); check("by status", names() == ["edge-fw"] and rt.table.rowCount() == 1)
tick("Status", "FAIL", "WARN"); check("several values in one submenu mean 'any of them'", names() == ["core-sw1", "edge-fw"] and n() == 2)
tick("Location", "Chicago"); check("different submenus must all match", names() == ["core-sw1", "edge-fw"] and n() == 2)
tick("Status"); tick("Location", "Denver", "(no location)"); check("a location choice, including devices with none (a device not in the inventory has no location)", names() == ["dr-sw", "lab", "udm / ap1"], names())
tick("Location"); tick("Vendor", "fortinet", "juniper"); check("by vendor", names() == ["dr-sw", "edge-fw"])
tick("Vendor"); tick("Tag", "core"); check("by tag", names() == ["core-sw1", "dr-sw"])
tick("Tag", "pci", "wan"); check("tag matching ignores case and means any", names() == ["core-sw1", "edge-fw"])
tick("Tag", "core"); tick("Location", "Denver"); check("tag and location together", names() == ["dr-sw"])
tick("Tag"); tick("Location"); tick("Status", "OK"); check("a result for a device that is not in the inventory still filters by status", "udm / ap1" in names() and n() == 3, names())
rt.filter.clear(); check("Clear filter shows everything again", n() == 6 and not rt.filter.filtering() and rt.table.rowCount() == 6)

print("== the button reports what is ticked")
tick("Status", "FAIL", "WARN"); tick("Location", "Chicago")
check("a count appears next to the funnel", rt.filter.text().strip() == "3" and rt.filter.toolButtonStyle() == Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
check("the tooltip says what is ticked", rt.filter.toolTip() == "Filter: Status: FAIL, WARN; Location: Chicago", rt.filter.toolTip())
check("and so does the report's scope line", rt.scope_text() == "Status: FAIL, WARN; Location: Chicago", rt.scope_text())
check("the preview line counts the filtered rows", rt.info.text().startswith("2 results"), rt.info.text())

print("== the menu itself")
rt.filter._build()
subs = [a.text() for a in rt.filter.menu.actions() if a.menu()]
check("submenus, a separator and a Clear filter entry", subs == ["Status", "Location", "Vendor", "Tag"] and rt.filter.menu.actions()[-1].text() == "Clear filter" and rt.filter.menu.actions()[-1].isEnabled())
loc = [a for a in rt.filter.menu.actions() if a.text() == "Location"][0].menu()
boxes = {a.defaultWidget().text(): a.defaultWidget() for a in loc.actions() if isinstance(a, QWidgetAction)}
check("each value is a tick box that shows its current state", set(boxes) == {"Chicago", "Denver", "(no location)"} and boxes["Chicago"].isChecked() and not boxes["Denver"].isChecked())
boxes["Denver"].setChecked(True); check("ticking a box filters straight away", rt.filter.selected("Location") == {"Chicago", "Denver"} and rt.filter.text().strip() == "4")
boxes["Denver"].setChecked(False); boxes["Chicago"].setChecked(False); check("unticking removes it", rt.filter.selected("Location") == set())
rt.filter.menu.actions()[-1].trigger(); check("Clear filter in the menu works", not rt.filter.filtering() and n() == 6)

print("== it survives new data")
tick("Location", "Denver", "Chicago"); tick("Status", "ERROR")
rt.refresh(); check("reloading the report keeps ticks that still apply", rt.filter.selected("Location") == {"Denver", "Chicago"} and rt.filter.selected("Status") == {"ERROR"})
res[:] = [r for r in res if r.device != "lab"]; rt.refresh()
check("a tick for a value that has gone is dropped", rt.filter.selected("Status") == set() and rt.filter.selected("Location") == {"Denver", "Chicago"})
rt.filter.clear()

print("== exports use the filtered rows and say how they were filtered")
got = {}
orig = (RT.QFileDialog.getSaveFileName, reports.to_csv)
RT.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (os.path.join(SP, "x.csv"), ""))
reports.to_csv = lambda rows, path, scope="", when=None: got.update(rows=[r.device for r in rows], scope=scope)
tick("Status", "FAIL"); rt.export_csv()
check("the CSV gets only the filtered rows and the scope text", got["rows"] == ["edge-fw"] and got["scope"] == "Status: FAIL", got)
RT.QFileDialog.getSaveFileName, reports.to_csv = orig
rt.filter.clear()
tick("Location", "Denver")
path = os.path.join(SP, "scoped.html"); reports.save_html(rt.selected_results(), path, scope=rt.scope_text())
check("the report itself shows the scope", "Location: Denver" in open(path, encoding="utf-8").read())

print("== the widget on its own")
fb = FilterButton("Pick"); seen = []
fb.changed.connect(lambda: seen.append(1)); fb.set_sections({"A": [("one", 1), ("two", 2)], "B": []})
check("it starts with the tip and no count", fb.toolTip() == "Pick" and fb.text() == "" and not fb.filtering())
fb._build(); b_menu = [a for a in fb.menu.actions() if a.menu()][1]
check("an empty section is greyed out", not b_menu.isEnabled())
fb._toggle("A", 1, True); fb._toggle("A", 2, True); check("it emits when ticked", len(seen) == 2 and fb.describe() == "A: one, two" and fb.text().strip() == "2")
fb.set_sections({"A": [("two", 2)]}); check("set_sections does not emit and drops stale ticks", len(seen) == 2 and fb.selected("A") == {2})
fb.clear(); check("clear empties and emits", len(seen) == 3 and not fb.filtering())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
