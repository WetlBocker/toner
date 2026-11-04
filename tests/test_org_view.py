# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Global with organizations: Needs attention puts each organization's devices under its heading, worst off first, and
# Organizations takes Network at a glance's place, one row each; Open (or a row) switches Toner to that organization.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "orgview%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingorgview%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from drivers.base import Result
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtTest import QTest
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
A.apply_look(app)
from core import orgs

def dev(name, org=None, vendor="cisco"):
    db.save_device(dict(name=name, vendor=vendor, host="10.0.0.%d" % (len(name) + 1), port=0, platform="cisco_ios", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, org=org))

print("== one organization's view is as before")
dev("core-sw1")
db.save_run([Result("core-sw1", "cpu", "WARN", "86%")])
w = A.Main(); w.resize(1440, 900); w.show(); app.processEvents(); w.go("Overview"); app.processEvents()
d = w.dashboard
check("without organizations: no headings, and Network at a glance as before", not d.heads and d.map_panel.isVisibleTo(d) and not d.org_panel.isVisibleTo(d))

print("== Global with organizations")
acme = orgs.create("Acme Charter", "ACME", "#e91e63")
bolt = orgs.create("Bolt Logistics", "BOLT", "#3f51b5")
calm = orgs.create("Calm Dental", "CALM", "#009688")
for n in ("acme-fw", "acme-sw"): dev(n, acme)
for n in ("bolt-core", "bolt-ap"): dev(n, bolt)
dev("calm-sw", calm)
with db.within(acme):
    db.save_run([Result("acme-fw", "ha", "FAIL", "1/2", "Peer unit is not in sync"), Result("acme-sw", "cpu", "WARN", "88%")])
with db.within(bolt):
    db.save_run([Result("bolt-core", "connection", "ERROR", "", "timeout"), Result("bolt-ap", "cpu", "OK", "5%")])
with db.within(calm):
    db.save_run([Result("calm-sw", "cpu", "OK", "3%")])
w.tabs.set_orgs([(o["id"], o["name"], o["colour"]) for o in orgs.list_orgs(archived=False)], 0)
d.refresh(); app.processEvents()
t = d.attention
order = [(d.heads.get(r), d.names[r]) for r in range(t.rowCount())]
check("each organization's devices sit under its heading, the one with a device down first, then failing, then warned, then Global's own",
      [x for x in order] == [(bolt, None), (None, "bolt-core@@%d" % bolt), (acme, None), (None, "acme-fw@@%d" % acme), (None, "acme-sw@@%d" % acme),
                             (0, None), (None, "core-sw1")], order)
head = t.cellWidget(0, 0)
check("a heading says its name and code, and its counts", head.name.text() == "Bolt Logistics (BOLT)" and head.counts.text() == "1 down", (head.name.text(), head.counts.text()))
check("...and so does its name for a screen reader", head.accessibleName() == "Bolt Logistics (BOLT), 1 down", head.accessibleName())
acme_row = next(r for r, o in d.heads.items() if o == acme)
check("counts leave out what is 0, in the agreed words", t.cellWidget(acme_row, 0).counts.text() == "1 failing, 1 with a warning", t.cellWidget(acme_row, 0).counts.text())
check("the heading spans the first four columns and cannot be selected", t.columnSpan(0, 0) == 4 and not (t.item(0, 1).flags() & Qt.ItemFlag.ItemIsSelectable))
btn = t.cellWidget(0, 4).buttons["switch"]
check("its Open switches Toner to that organization", btn.text() == "Open" and btn.toolTip() == "Switch Toner to Bolt Logistics (BOLT)")
glob = next(r for r, o in d.heads.items() if o == 0)
check("Global's own devices have a heading too, with no Open (Toner is there already)", t.cellWidget(glob, 0).name.text() == "Global" and not t.cellWidget(glob, 4).buttons)
check("the badge's tooltip says how many organizations", w.tabs.item_for(w.results).toolTip().endswith(
      "4 devices need attention: 2 failing, 2 with a warning, across 3 organizations"), w.tabs.item_for(w.results).toolTip())

print("== folding")
h0 = t.height()
head.clicked.emit(); app.processEvents()
check("a click on a heading folds its devices away, and the list gets shorter", t.isRowHidden(1) and not t.isRowHidden(0) and t.height() < h0 and bolt in d.folded)
w.activateWindow(); QTest.qWaitForWindowActive(w, 3000)
t.setFocus(); t.setCurrentCell(0, 1); QTest.keyClick(t, Qt.Key.Key_Return); app.processEvents()
check("Enter on the heading opens it again", not t.isRowHidden(1) and bolt not in d.folded)
d.folded.add(acme); d.refresh(); app.processEvents()
check("a fold lasts through a refresh", all(t.isRowHidden(r) for r in range(t.rowCount()) if d.names[r] and d.names[r].startswith("acme")))
d.folded.clear(); d.refresh(); app.processEvents()
opened = []
d.open_device.connect(opened.append)
r = d.names.index("acme-fw@@%d" % acme)
w.activateWindow(); QTest.qWaitForWindowActive(w, 3000)
t.setFocus(); t.setCurrentCell(r, 1); t.selectRow(r); QTest.keyClick(t, Qt.Key.Key_Return); app.processEvents()
check("Enter on a device still opens it", opened == ["acme-fw@@%d" % acme], opened)
check("a device row keeps its own buttons", d.row_actions(r)["open"].text() == "Open" and d.row_actions(r)["more"] is not None)

print("== Organizations, in the map's place")
check("on Global the panel replaces Network at a glance", d.org_panel.isVisibleTo(d) and not d.map_panel.isVisibleTo(d))
b = d.org_board
rows = [[b.table.item(i, c).text() for c in range(7)] for i in range(b.table.rowCount())]
check("one row each, worst off first, then the quiet ones", [r[0] for r in rows] == ["Bolt Logistics (BOLT)", "Acme Charter (ACME)", "Global", "Calm Dental (CALM)"], rows)
check("its columns", [b.table.horizontalHeaderItem(c).text() for c in range(7)] == ["Organization", "Status", "Down", "Failing", "Warnings", "Devices", "Last run"])
check("status and counts per organization", rows[0][1:6] == ["ERROR", "1", "0", "0", "2"] and rows[1][1:6] == ["FAIL", "0", "1", "1", "2"]
      and rows[3][1:6] == ["OK", "0", "0", "0", "1"] and rows[0][6] == "just now", rows)
from ui import orgboard
fm = b.table.fontMetrics()
check("the number columns are as narrow as their headings, so the names have the room", all(b.table.columnWidth(c) < 100 for c in orgboard.NUMBERS)
      and b.table.columnWidth(0) >= fm.horizontalAdvance("Bolt Logistics (BOLT)"), [b.table.columnWidth(c) for c in range(7)])
check("an organization with a failure stands out (bold); one with only warnings stays quiet, like the healthy ones",
      b.table.item(0, 0).font().bold() and not b.table.item(2, 0).font().bold() and b.table.item(2, 0).text() == "Global"
      and b.table.item(2, 0).foreground().color().name() == b.table.item(3, 0).foreground().color().name(), [b.table.item(i, 0).text() for i in range(4)])
check("the title counts the ones that need attention", d.org_panel.count.text() == "3 of 4 need attention", d.org_panel.count.text())
check("a row says where a click goes", b.table.item(0, 0).toolTip() == "Switch Toner to Bolt Logistics (BOLT)")
b.find.setText("calm"); app.processEvents()
check("the search box narrows the list by name or code", [b.table.isRowHidden(i) for i in range(4)] == [True, True, True, False] and not b.hint.isVisible())
b.find.setText("zzz"); app.processEvents()
check("...and says when nothing matches", all(b.table.isRowHidden(i) for i in range(4)) and b.hint.isVisibleTo(b) and b.hint.head.text() == "No organizations match")
b.find.clear(); app.processEvents()
b.table.horizontalHeader().sectionClicked.emit(5); b.table.sortItems(5, Qt.SortOrder.DescendingOrder); app.processEvents()
check("a heading sorts by number, not by text", b.table.item(0, 5).text() == "2")
d.refresh(); app.processEvents()

print("== switching")
picked = []
d.open_org.connect(picked.append)
t.cellWidget(0, 4).buttons["switch"].click(); app.processEvents()
check("Open switches Toner to the organization (as the switcher does)", picked == [bolt] and db.home() == bolt, (picked, db.home()))
check("in an organization's own view: no headings, the map is back", not d.heads and d.map_panel.isVisibleTo(d) and not d.org_panel.isVisibleTo(d))
w.tabs.org.setCurrentIndex(0); app.processEvents()
check("back on Global", db.home() == 0 and d.org_panel.isVisibleTo(d))
r = next(i for i in range(b.table.rowCount()) if b.table.item(i, 0).text().startswith("Calm"))
w.activateWindow(); QTest.qWaitForWindowActive(w, 3000)
b.table.setFocus(); b.table.setCurrentCell(r, 0); app.processEvents()      # (focus settles before the key)
QTest.keyClick(b.table, Qt.Key.Key_Return); app.processEvents()
check("Enter on a row in Organizations switches too", db.home() == calm, db.home())
w.tabs.org.setCurrentIndex(0); app.processEvents()

print("== a heading's row becomes a device's row")
from PySide6.QtCore import QCoreApplication, QEvent
d.refresh(); app.processEvents()
before = d.heads.copy()
with db.within(bolt):
    db.save_run([Result("bolt-core", "connection", "ERROR", "", "timeout"), Result("bolt-ap", "cpu", "FAIL", "99%")])
d.refresh()
for _ in range(3):                                   # the old headings are really deleted now
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
moved = [r for r in before if r not in d.heads]
check("a row that held a heading now holds a device", moved and all(d.names[r] for r in moved), (before, d.heads))
check("...and the list has let go of the old heading (no widget left in its first column)", all(t.cellWidget(r, 0) is None for r in moved))
t.resize(t.width() - 40, t.height()); t.viewport().repaint(); t.grab(); app.processEvents()
check("the list still lays out and draws", t.rowCount() == len(d.names))

print("== a long list")
from ui import dashboard as D
many = orgs.create("Many Sites", "MANY", "#795548")
for i in range(30): dev(f"many-{i:02d}", many)
with db.within(many):
    db.save_run([Result(f"many-{i:02d}", "cpu", "FAIL", "99%") for i in range(30)])
d.refresh(); app.processEvents()
mine = [n for n in d.names if n and n.startswith("many-")]
more = [r for r, g in d.mores.items() if g == many]
check(f"an organization lists its worst {D.ATTENTION_PER_ORG} devices, then a row for the rest", len(mine) == D.ATTENTION_PER_ORG and len(more) == 1
      and t.item(more[0], 0).text() == "Show 5 more" and t.columnSpan(more[0], 0) == 5, (len(mine), more))
check("the badge still counts every device", "30 failing" in w.tabs.item_for(w.results).toolTip() or w.tabs._counts.get(w.tabs.indexOf(w.results), 0) >= 30)
t.cellClicked.emit(more[0], 0); app.processEvents()
check("a click on it lists them all, and it stays that way", len([n for n in d.names if n and n.startswith("many-")]) == 30 and not any(g == many for g in d.mores.values()))
d.refresh(); app.processEvents()
check("...after a refresh too", len([n for n in d.names if n and n.startswith("many-")]) == 30)

print("== all well")
for oid, names in ((acme, ("acme-fw", "acme-sw")), (bolt, ("bolt-core", "bolt-ap")), (many, [f"many-{i:02d}" for i in range(30)])):
    with db.within(oid):
        db.save_run([Result(n, "cpu", "OK", "5%") for n in names])
db.save_run([Result("core-sw1", "cpu", "OK", "5%")])
d.refresh(); app.processEvents()
check("nothing needs attention: no headings, every organization quiet, the title says so", not d.heads and d.org_panel.count.text() == "all 5 OK", d.org_panel.count.text())

print("== other organizations' scheduled runs")
refreshed = []
real_refresh = d.refresh
d.refresh = lambda *a: (refreshed.append(1), real_refresh())[1]
for _ in range(10):                                      # ten organizations finish their scheduled checks together
    w.on_background_run([], [])
check("Global is not refreshed once per organization as each finishes", refreshed == [])
QTest.qWait(w.GLOBAL_WAIT + 300)
check("...but once, a moment after the first", refreshed == [1], refreshed)
d.refresh = real_refresh

print("== Open in Tools, from a device's menu")
with db.within(acme):
    db.save_run([Result("acme-fw", "ha", "FAIL", "1/2", "Peer unit is not in sync")])
d.refresh(); app.processEvents()
r = d.names.index("acme-fw@@%d" % acme)
t.selectRow(r)
menu = d._menu_for_current()
sub = next((a.menu() for a in menu.actions() if a.text() == "Open in Tools"), None)
check("Needs attention's menu has Open in Tools, with the tools that take a device", sub is not None
      and [a.text() for a in sub.actions()] == ["Live Ping", "Path Monitor (MTR)", "TLS Certificates", "SNMP"], [a.text() for a in menu.actions()])
next(a for a in sub.actions() if a.text() == "TLS Certificates").trigger(); app.processEvents()
check("...and one opens that tool with the device filled in", w.tabs.currentWidget() is w.tools and w.tools.tabs.currentWidget() is w.tools.tls
      and w.tools.tls.host.text() == db.find_device("acme-fw@@%d" % acme)["host"], (w.tools.tabs.currentWidget(), w.tools.tls.host.text()))
w.inventory.tool_requested.emit("mtr", db.find_device("acme-sw@@%d" % acme)); app.processEvents()
check("Inventory's menu opens them the same way", w.tools.tabs.currentWidget() is w.tools.mtr)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
