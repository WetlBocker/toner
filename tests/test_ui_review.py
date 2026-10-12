# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Covers the interface changes from the review of every tab (see the README: "A few things that make the day-to-day quicker").
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "uirev%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roaminguirev%d" % int(time.time()))
from core import checks, db, display, vendors
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton
app = QApplication([])
import app as A
from drivers.base import Result
A.apply_look(app)

def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host=kw.pop("host", "10.0.0.1"), port=0, platform=kw.pop("platform", ""), username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location=kw.pop("location", ""), details="", folder_id=None, tags=kw.pop("tags", ""))
    d.update(kw); return db.get_device(db.save_device(d))

print("== names of checks")
for raw, want in (("tx retries (2.4 GHz)", "TX Retries (2.4 GHz)"), ("isp latency", "ISP Latency"), ("sd-wan", "SD-WAN"), ("nvr", "NVR"), ("channel util (ng)", "Channel Util (NG)"),
                  ("wan links", "WAN Links"), ("port errors", "Port Errors"), ("cpu", "CPU")):
    check(f"{raw!r} reads as {want!r}", display.check_name(raw) == want, display.check_name(raw))

print("== chart axes")
from ui import history as H
check("a chart's grid is at round numbers", [g[1] for g in H.nice_axis(66)[1]] == ["0", "20", "40", "60", "80"] and [g[1] for g in H.nice_axis(1234)[1]] == ["0", "500", "1,000", "1,500"])
check("small values keep sensible decimals", [g[1] for g in H.nice_axis(0.7)[1]] == ["0.0", "0.2", "0.4", "0.6", "0.8"] and H.nice_axis(0)[0] > 0)
check("the top line is at or above the highest value, with no more than 5 gaps", all(H.nice_axis(p)[0] >= p and len(H.nice_axis(p)[1]) <= 6 for p in (0.034, 1, 5, 9, 66, 100, 733, 99999, 7340000)))

print("== column chooser")
from ui.columns import ColumnChooser
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
tree = QTreeWidget(); tree.setColumnCount(4); tree.setHeaderLabels(["A", "B", "C", "D"]); tree.addTopLevelItem(QTreeWidgetItem(["x", "", "", "z"]))
cc = ColumnChooser(tree, tree.header(), "inventory_columns", ["A", "B", "C", "D"], locked=(0,), auto=lambda: {1, 2})
cc.apply()
check("until chosen, empty columns are hidden by themselves", [tree.isColumnHidden(i) for i in range(4)] == [False, True, True, False] and cc.chosen() is None)
cc.toggle(3, False)
check("choosing a column to hide is remembered, and takes over from the automatic one", cc.chosen() == {1, 2, 3} and tree.isColumnHidden(3) and db.get_setting("inventory_columns") == [1, 2, 3])
cc.toggle(1, True)
check("a hidden column can be shown again", not tree.isColumnHidden(1) and cc.chosen() == {2, 3})
cc.toggle(0, False)
check("the first column can never be hidden", not tree.isColumnHidden(0))
cc.reset(); check("'Hide empty columns automatically' goes back", cc.chosen() is None and tree.isColumnHidden(1) and not tree.isColumnHidden(3))

print("== Inventory")
import ui.inventory as I
dev("sw-ok", location="HQ", tags="core"); dev("sw-warn"); dev("sw-off", enabled=0); dev("sw-new", host="10.0.0.7")
db.save_run([Result("sw-ok", "cpu", "OK", "5%"), Result("sw-warn", "cpu", "WARN", "75%", "high"), Result("sw-off", "cpu", "FAIL", "99%")])
tab = I.InventoryTab()
items = {it.text(0): it for it in tab._all_items() if tab.kind_of(it)[0] == "device"}
S = tab.STATUS
check("the Status column says it in words", [items[n].text(S) for n in ("sw-ok", "sw-warn", "sw-off", "sw-new")] == ["OK", "WARN", "Disabled", "Not checked"], [items[n].text(S) for n in items])
check("there is no 'Enabled' column any more", "Enabled" not in tab.COLS and tab.COLS[S] == "Status")
check("a disabled device is dimmed", items["sw-off"].foreground(0).color() == items["sw-off"].foreground(S).color() and items["sw-off"].foreground(0).color() != items["sw-ok"].foreground(0).color())
check("Site, Details and Tags that say nothing are left out; Tags shows once a device has one", tab.table.isColumnHidden(5) and tab.table.isColumnHidden(6) and not tab.table.isColumnHidden(7))
from ui import icons
a = icons.icon_with_dot("device", "#888888", "#2e9e5b", shape="circle").pixmap(20, 20).toImage()
b = icons.icon_with_dot("device", "#888888", "#e0a100", shape="triangle").pixmap(20, 20).toImage()
c = icons.icon_with_dot("device", "#888888", "#d32f2f", shape="square").pixmap(20, 20).toImage()
check("the marks differ in shape, not only colour (each state has its own)", len({tab.SHAPES[k] for k in ("OK", "WARN", "FAIL", "ERROR")}) == 4 and a != b and b != c)
tab.table.setCurrentItem(items["sw-ok"]); items["sw-ok"].setSelected(True)
opened = []
tab.open_details.connect(opened.append)
tab._enter()
check("Enter opens the selected device", opened and opened[0]["name"] == "sw-ok", opened)

print("== Results")
from ui.results import ResultsTab
rt = ResultsTab(); rt.results = [Result("sw-warn", "cpu", "WARN", "75%", "high"), Result("sw-warn", "memory", "FAIL", "95%", "too full"), Result("sw-ok", "cpu", "OK", "5%")]
rt.last_ran = ["sw-warn", "sw-ok"]; rt.repopulate()
tops = {rt.table.topLevelItem(i).text(0): rt.table.topLevelItem(i) for i in range(rt.table.topLevelItemCount())}
check("a collapsed row says what is wrong, worst first, and how many more", tops["sw-warn"].text(4) == "memory: too full   (+1 more)" and tops["sw-ok"].text(4) == "all OK", tops["sw-warn"].text(4))
seen = []; rt.open_device.connect(seen.append); rt.table.setCurrentItem(tops["sw-warn"].child(0)); rt._enter()
check("Enter on any row opens its device", seen == ["sw-warn"], seen)
rt.columns.toggle(3, False)
check("a column can be hidden from the heading", rt.table.isColumnHidden(3)); rt.columns.reset()

print("== Overview")
from ui.dashboard import DashboardTab
db.save_run([Result("sw-ok", "cpu", "OK", "5%"), Result("sw-warn", "cpu", "OK", "5%")])
db.save_run([Result("sw-ok", "cpu", "FAIL", "99%"), Result("sw-warn", "cpu", "WARN", "75%"), Result("sw-warn", "memory", "FAIL", "95%")])
ch = db.changes_since_previous()
check("it works out who got worse between the last two runs", [d for d, _a, _b in ch["worse"]] == ["sw-ok", "sw-warn"] and ch["better"] == [], ch)
db.save_run([Result("sw-ok", "cpu", "OK", "5%"), Result("sw-warn", "cpu", "WARN", "75%"), Result("sw-warn", "memory", "OK", "10%")])
ch = db.changes_since_previous()
check("and who improved", [d for d, _a, _b in ch["better"]] == ["sw-ok", "sw-warn"] and ("sw-warn", "FAIL", "WARN") in ch["better"] and ("sw-ok", "FAIL", "OK") in ch["better"], ch)
dash = DashboardTab(); dash.resize(1200, 700); dash.show(); app.processEvents()
check("the Overview says so in a line above the cards", dash.moved.isVisibleTo(dash) and "improved" in dash.moved.text() and "sw-ok: FAIL to OK" in dash.moved.text(), dash.moved.text())
check("it explains why Warnings and Failing can overlap, only when they do", not dash.overlap.isVisibleTo(dash))
db.save_run([Result("sw-ok", "cpu", "OK", "5%"), Result("sw-warn", "cpu", "WARN", "75%"), Result("sw-warn", "memory", "FAIL", "95%")]); dash.refresh()
check("(now one device has both)", dash.overlap.isVisibleTo(dash) and "1 device has both" in dash.overlap.text(), dash.overlap.text())
now = datetime.now()
check("times are short and relative", dash._ago(now.strftime("%Y-%m-%d %H:%M:%S")) == "just now" and dash._ago((now - timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S")) == "12 min ago"
      and dash._ago((now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S")) == "5 h ago" and dash._ago((now - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")) == "3 days ago" and dash._ago("junk") == "junk")
dash.resize(860, 600); app.processEvents(); app.processEvents()
check("in a narrow window the panels stack, so 'What is wrong' is never squeezed away", dash.cols.direction().name == "TopToBottom", dash.cols.direction())
dash.resize(1300, 700); app.processEvents(); app.processEvents()
check("and sit side by side in a wide one", dash.cols.direction().name == "LeftToRight")

print("== Configs, History, Tools")
from ui.configs import ConfigsTab
cf = ConfigsTab(); cf.resize(1100, 600); cf.show(); app.processEvents()
check("the device list never scrolls sideways", cf.devs.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
check("the right-hand panes say what to do while empty", cf.vers_hint.isVisibleTo(cf) and cf.text.placeholderText() != "")
from ui.history import HistoryTab
hs = HistoryTab(); hs.resize(1100, 600); hs.show(); app.processEvents()
check("History selects the latest run itself, so the lower table is not blank", hs.runs.currentRow() == 0 and hs.detail.rowCount() > 0 and not hs.detail_hint.isVisibleTo(hs))
with db.connect() as c: c.execute("DELETE FROM runs")
hs.refresh()
check("and says so when there are no runs", hs.runs_hint.isVisibleTo(hs) and hs.detail_hint.isVisibleTo(hs))
from ui.tools import ToolsTab
tt = ToolsTab()
check("Tools has room for its longest name, and a tooltip for each", tt.tabs.list.width() >= 220 and tt.tabs.list.item(1).toolTip() != "")
check("the Command Runner's empty table says what to do", tt.runner.table_hint.isVisibleTo(tt.runner))

print("== checkboxes in lists")
from ui import theme
sheet = app.styleSheet()
check("a tick box in a list, tree or table is drawn in the theme's own style (it was nearly invisible in the dark theme)", "QListView::indicator" in sheet and "QTreeView::indicator:checked" in sheet)

print("== Sessions")
from ui.sessions import SessionsTab
ss = SessionsTab()
ss._fill_more()
labels = [a.text() for a in ss.more_menu.actions()]
check("the rarely used buttons live in a More menu", labels == ["New folder", "Duplicate", "Expand all", "Collapse all", "Session logs"], labels)
check("and the row itself is short", ss.more_btn.text() == "More" and all(not b.isVisibleTo(ss) for b in (ss.folder_btn, ss.copy_btn, ss.expand_btn, ss.collapse_btn, ss.logs_btn)))
check("Duplicate follows the selection like its button (off with nothing chosen)", not [a for a in ss.more_menu.actions() if a.text() == "Duplicate"][0].isEnabled())

print("== Settings pages")
import ui.settings as ST
pg = ST.NotificationsPage(); pg.load()
check("the Type column is plain text; the mark is by the name", pg.table.horizontalHeaderItem(2).text() == "Type")
check("the delivery log says what it will hold", pg.log_hint.isVisibleTo(pg))
th = ST.ThresholdsPage(); th.load()
check("the limits are grouped", set(db.DEFAULT_THRESHOLDS) <= {k for _t, ks in db.THRESHOLD_GROUPS for k in ks} and len(db.THRESHOLD_GROUPS) == 3)
w, f = th.spins["cpu"]
check("each limit has a Reset button, enabled only when it differs from the default", not th.resets["cpu"].isEnabled())
w.setValue(55)
check("(now it does)", th.resets["cpu"].isEnabled()); th.reset_one("cpu")
check("Reset puts the default back", (w.value(), f.value()) == (db.DEFAULT_THRESHOLDS["cpu"]["warn"], db.DEFAULT_THRESHOLDS["cpu"]["fail"]) and not th.resets["cpu"].isEnabled())
ag = ST.AgentsPage(); ag.load()
check("the Agents page opens with one line on whether it is working", "receiver is off" in ag.banner.text().lower())
check("the details are tucked away until asked for", not ag.advanced.content.isVisibleTo(ag) and not ag.intro.isVisibleTo(ag))
ag.advanced.open()
check("(and open when you ask)", ag.advanced.toggle.isChecked() and not ag.advanced.content.isHidden())
check("the firewall command can be copied", ag.copy_fw.text() == "Copy")
QApplication.clipboard().clear(); ag.copy_fw.click()
check("(it lands on the clipboard)", "New-NetFirewallRule" in QApplication.clipboard().text())

print("== Device window and dialog")
from ui.device_view import DeviceView
d1 = dev("own-sw", checkopts={"checks": ["cpu"], "thresholds": {"cpu": {"warn": 50, "fail": 70}}})
text = DeviceView._own_settings(d1)
check("the device window says whether it has its own checks and limits", "runs only: CPU" in text and "own limits" in text and "50/70" in text, text)
check("or that it follows the global ones", DeviceView._own_settings(dev("plain-sw")) == "Global checks and limits")
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.No)[1])
dlg = I.DeviceDialog(); dlg.show()
dlg.reject()
check("cancelling an untouched dialog just closes it", not asked and not dlg.isVisible())
dlg = I.DeviceDialog(); dlg.show(); dlg.name.setText("something typed"); dlg.reject()
check("cancelling after typing asks first, and 'No' keeps the dialog open", asked and "Close without saving" in asked[0] and dlg.isVisible(), asked)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
dlg.reject()
check("'Yes' closes it", not dlg.isVisible())

print("== the command palette")
w = A.Main(); w.show()
w.open_palette()
def found(text):
    w.palette.box.setText(text)
    return [w.palette.list.item(i).text() for i in range(w.palette.list.count())]
check("it also finds Settings pages by name", any(n.startswith("Settings: Agents") for n in found("agents")))
check("and limits", any(n.startswith("Threshold: CPU") for n in found("threshold cpu")))
check("and the checks of the kinds of device in use", any(n.startswith("Check: CPU") for n in found("check cpu")), found("check cpu"))
w.palette.hide()

print("== nothing stretches across a wide window")
from PySide6.QtWidgets import QComboBox, QDoubleSpinBox, QSpinBox, QToolButton
def stretched(root, wide_button=380, wide_combo=650):
    out = []
    for b in root.findChildren(QPushButton) + root.findChildren(QToolButton):
        if b.isVisibleTo(root) and b.width() > wide_button and not hasattr(b, "set_labels"): out.append(("button", b.text(), b.width()))
    for b in root.findChildren(QSpinBox) + root.findChildren(QDoubleSpinBox):
        if b.isVisibleTo(root) and b.width() > wide_button: out.append(("spin", b.value(), b.width()))
    for b in root.findChildren(QComboBox):
        if b.isVisibleTo(root) and b.width() > wide_combo: out.append(("combo", b.currentText()[:20], b.width()))
    return out
big = ST.SettingsTab(); big.resize(2000, 900); big.show()
bad_pages = {}
for i, p in enumerate(big.pages):
    big.stack.setCurrentIndex(i); app.processEvents(); app.processEvents()
    found = stretched(p)
    if found: bad_pages[p.title] = found
check("on a 2000 px window no Settings page has a stretched button, number box or drop-down", not bad_pages, bad_pages)
ap = [p for p in big.pages if p.title == "Appearance"][0]
xs = [b.x() for b in ap.swatch.values()]
check("the four status colours sit together, not spread across the page", max(xs) - min(xs) < 400, xs)
ag = [p for p in big.pages if p.title == "Agents"][0]
check("Download agent package is as wide as its words, with the 'reports every' box right after it", ag.download.width() < 300 and ag.minutes.x() - ag.download.x() < 450, (ag.download.width(), ag.minutes.x() - ag.download.x()))
from ui.tools import ToolsTab
tt2 = ToolsTab(); tt2.resize(2000, 900); tt2.show()
bad_tools = {}
for i in range(tt2.tabs.count()):
    tt2.tabs.setCurrentIndex(i); app.processEvents(); app.processEvents()
    found = stretched(tt2.tabs.currentWidget())
    if found: bad_tools[tt2.tabs.tabText(i)] = found
check("and the same for every tool (Wake-on-LAN's button and iperf's mode box were both far too wide)", not bad_tools, bad_tools)
sec = [p for p in big.pages if p.title == "Security"][0]
check("an empty table in Security says what it will hold, and the hint goes when it has rows", sec.keys_hint.isVisibleTo(sec) and sec.creds.rowCount() > 0 and not sec.creds_hint.isVisibleTo(sec))
cu = [p for p in big.pages if p.title == "Custom checks"][0]
check("and so does the list of custom checks", cu.hint.isVisibleTo(cu))

print("== the search (Ctrl+K) closes when you click elsewhere")
from PySide6.QtCore import QPoint
from PySide6.QtTest import QTest
w.resize(1100, 700); app.processEvents()
w.open_palette(); app.processEvents()
check("it opens as a popup", w.palette.isVisible() and bool(w.palette.windowFlags() & Qt.WindowType.Popup))
QTest.mouseClick(w.palette.box, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(20, 10)); app.processEvents()
check("a click inside it keeps it open", w.palette.isVisible())
QTest.mouseClick(w.tabs.side, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(20, 640)); app.processEvents()
check("a click back in the Toner window closes it", not w.palette.isVisible())
w.open_palette(); app.processEvents(); QTest.keyClick(w.palette.box, Qt.Key.Key_Escape); app.processEvents()
check("Esc still closes it", not w.palette.isVisible())
w.open_palette(); app.processEvents(); w.palette.box.setText("overview"); QTest.keyClick(w.palette.box, Qt.Key.Key_Return); app.processEvents()
check("and choosing something still works and closes it", not w.palette.isVisible() and w.tabs.tabText(w.tabs.currentIndex()) == "Overview")
w.open_palette(); app.processEvents(); w.palette.hide(); app.processEvents()
QTest.mouseClick(w.tabs.side, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(20, 640)); app.processEvents()
check("once closed it does not watch clicks any more (nothing is left behind)", not w.palette.isVisible())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
