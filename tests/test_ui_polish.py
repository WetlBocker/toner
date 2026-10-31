# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pol%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import agents, db, notify
from drivers.base import Result
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QHeaderView, QMessageBox, QPushButton
app = QApplication([])
import app as A
A.apply_look(app)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def settle(w=None):
    for _ in range(3): app.processEvents()

print("== 1. Tools > Command Runner fits a normal window")
from ui import tools as T
tools = T.ToolsTab()
from ui import tools2
r = tools2.CommandRunnerTab()                           # on its own, so it can be given any width (inside Tools it sits in a scroll area)
for width in (860, 1000, 1280):
    r.resize(width, 720); r.show(); settle()
    inside = all(r.rect().contains(b.mapTo(r, b.rect().bottomRight())) and b.mapTo(r, b.rect().topLeft()).x() >= 0 for b in (r.go, r.stop, r.copy_btn, r.save_btn, r.snip_save, r.snip_del))
    check(f"at {width} px wide every button is inside the page", inside, [(b.text(), b.mapTo(r, b.rect().bottomRight()).x()) for b in (r.go, r.stop, r.copy_btn, r.save_btn)])
check("its smallest width is modest (it wraps instead of forcing a scrollbar)", r.minimumSizeHint().width() <= 760, r.minimumSizeHint().width())
r.resize(860, 720); settle()
ys = {round(b.mapTo(r, b.rect().topLeft()).y() / 10) for b in (r.snip_save, r.snip_del, r.go, r.stop)}
check("narrow, the row of controls wraps onto more lines, and none is on top of another", len(ys) >= 2 and not any(a is not b and a.geometry().intersects(b.geometry()) and a.parent() is b.parent() for a in (r.snip_save, r.snip_del, r.go, r.stop) for b in (r.snip_save, r.snip_del, r.go, r.stop)), ys)

print("== 2. lists with headings: room above each heading")
from ui.nav import PageStack, ITEM_HEIGHT, HEADING_HEIGHT
ps = tools.tabs
heads = [i for i in range(ps.list.count()) if not (ps.list.item(i).flags() & Qt.ItemFlag.ItemIsSelectable)]
items = [i for i in range(ps.list.count()) if i not in heads]
check("every page row has a proper height, headings are taller (the gap is above them)", all(ps.list.item(i).sizeHint().height() == ITEM_HEIGHT for i in items)
      and all(ps.list.item(h).sizeHint().height() == HEADING_HEIGHT for h in heads[1:]) and ps.list.item(heads[0]).sizeHint().height() < HEADING_HEIGHT)
check("a heading's text sits at the bottom of its row, next to its own pages", all(ps.list.item(h).textAlignment() & Qt.AlignmentFlag.AlignBottom for h in heads))
tools.show(); tools.resize(1280, 760); settle()
gaps = []
for h in heads[1:]:
    above, head, below = ps.list.visualItemRect(ps.list.item(h - 1)), ps.list.visualItemRect(ps.list.item(h)), ps.list.visualItemRect(ps.list.item(h + 1))
    gaps.append((head.height(), below.top() - head.bottom()))
check("on screen a heading row is taller than a page row", all(hgt > ITEM_HEIGHT for hgt, _ in gaps), gaps)

print("== 3. Settings: groups, spacing, search")
from ui.settings import SettingsTab, GROUPS
st = SettingsTab(); st.resize(1100, 700); st.show(); settle()
titles = st.page_titles()
check("every page is in the list exactly once", sorted(titles) == sorted(p.title for p in st.pages) and len(titles) == len(set(titles)))
check("they are grouped under headings in this order", [st.nav.item(r).text() for r in range(st.nav.count()) if st._index_of(r) is None] == [h.upper() for h, _ in GROUPS])
check("the groups hold the pages you would look for", dict(GROUPS)["Alerts and reports"] == ["Notifications", "Reports", "Config backups"] and "Agents" in dict(GROUPS)["Connections"] and "Thresholds" in dict(GROUPS)["Monitoring"])
check("headings cannot be selected", all(not (st.nav.item(r).flags() & Qt.ItemFlag.ItemIsSelectable) for r in range(st.nav.count()) if st._index_of(r) is None))
check("rows have the same generous height as elsewhere, headings more", all(st.nav.item(r).sizeHint().height() == ITEM_HEIGHT for r in range(st.nav.count()) if st._index_of(r) is not None)
      and max(st.nav.item(r).sizeHint().height() for r in range(st.nav.count())) == HEADING_HEIGHT)
st.select_page("Notifications")
check("choosing a page shows it", st.current_title() == "Notifications" and st.stack.currentIndex() == [p.title for p in st.pages].index("Notifications"))
st.nav.setCurrentRow(0)
check("clicking a heading does nothing", st.current_title() == "Notifications")
check("pages can be looked up by name, and an unknown name is refused", st.select_page("Agents") and st.current_title() == "Agents" and not st.select_page("No such page"))
check("the search box is there", st.search.placeholderText() == "Search settings  (Ctrl+F)" and st.search.isClearButtonEnabled())
n = st.filter_pages("proxy")
visible = [st.nav.item(r).text() for r in range(st.nav.count()) if not st.nav.isRowHidden(r) and st._index_of(r) is not None]
check("searching keeps the pages that mention it, and moves to the first one", "Proxy" in visible and len(visible) < len(titles) and st.current_title() in visible, visible)
heads_shown = [st.nav.item(r).text() for r in range(st.nav.count()) if not st.nav.isRowHidden(r) and st._index_of(r) is None]
check("a heading with no page left is hidden too", len(heads_shown) < len(GROUPS) and "CONNECTIONS" in heads_shown, heads_shown)
check("the search looks inside pages, not only at their names", "Notifications" in [st.nav.item(r).text() for r in range(st.nav.count()) if (st.filter_pages("snooze") or True) and not st.nav.isRowHidden(r) and st._index_of(r) is not None])
check("every word has to match", st.filter_pages("snooze zzzzqq") == 0)
check("nothing matching shows an empty list rather than everything", all(st.nav.isRowHidden(r) for r in range(st.nav.count())))
st.search.setText("")
check("clearing the search brings everything back", st.filter_pages("") == len(titles) and not any(st.nav.isRowHidden(r) for r in range(st.nav.count())))
st.search.setText("agent package")
check("typing in the box filters (Agents has the package button)", st.current_title() == "Agents", st.current_title()); st.search.clear()
st.pages[1].spins["cpu"][0].setValue(95); st.pages[1].spins["cpu"][1].setValue(10)
warned = []; QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
st.search.setText("proxy"); st.save()
check("a save that finds a problem clears the search and shows the page with it", st.current_title() == "Thresholds" and not st.search.text() and warned)
st.reload()

print("== 4. Thresholds: labelled boxes, no trailing zeros")
from ui.settings_pages.general import ThresholdsPage
th = ThresholdsPage(); th.load(); th.resize(900, 900); th.show(); settle()
w_cpu, f_cpu = th.spins["cpu"]
check("each box says what it is (WARN at / FAIL at), so it needs no separate heading to line up under", w_cpu.prefix() == "WARN at " and f_cpu.prefix() == "FAIL at "
      and w_cpu.text() == "WARN at 70" and f_cpu.text() == "FAIL at 90", (w_cpu.text(), f_cpu.text()))
check("whole numbers show without .0", w_cpu.cleanText() == "70" and f_cpu.cleanText() == "90" and th.spins["disk"][0].cleanText() == "80", (w_cpu.cleanText(), f_cpu.cleanText()))
check("a limit with a fraction keeps it", (w_cpu.setValue(70.5), w_cpu.cleanText())[1] == "70.5" and (w_cpu.setValue(0.25), w_cpu.cleanText())[1] == "0.25" and (w_cpu.setValue(70), w_cpu.cleanText())[1] == "70")
check("the value is still a number, and saving stores it", (w_cpu.setValue(72), th.save(), db.get_thresholds()["cpu"]["warn"])[2] == 72)
check("typing a value works", (w_cpu.lineEdit().setText("WARN at 65"), w_cpu.interpretText(), w_cpu.value())[2] == 65)
check("the error-count limits (whole numbers by nature) show none either", th.spins["port_errors"][0].cleanText() == "100" and th.spins["port_errors"][1].cleanText() == "10000")
th.add_row(scope=None, check="cpu")
check("override rows use the same trimmed boxes", th.table.cellWidget(0, 2).cleanText() in ("70", "72"), th.table.cellWidget(0, 2).cleanText())
print("== 5. Overview")
from ui.dashboard import DashboardTab
for n, h in (("sw-a", "10.0.0.1"), ("sw-b", "10.0.0.2"), ("win-1", "10.0.0.3")):
    db.save_device(dict(name=n, vendor="cisco" if n.startswith("sw") else "windows", host=h, port=0, platform="cisco_ios" if n.startswith("sw") else "winrm", username="", site="d",
                        verify_ssl=0, ha_expected=0, enabled=1))
db.save_run([Result("sw-a", "bgp", "FAIL", "", "peer down"), Result("sw-b", "cpu", "WARN", "85%", ""), Result("win-1", "cpu", "OK", "5%", "")])
dash = DashboardTab(); dash.resize(1100, 720); dash.show(); settle()
hh = dash.attention.horizontalHeader()
check("the 'what is wrong' column is the one that stretches", hh.sectionResizeMode(2) == QHeaderView.ResizeMode.Stretch and hh.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents)
total = sum(hh.sectionSize(i) for i in range(5))
check("so the table fills its panel (no empty strip on the right)", abs(total - dash.attention.viewport().width()) <= 2, (total, dash.attention.viewport().width()))
check("cells show the full text on hover", dash.attention.item(0, 2).toolTip() == dash.attention.item(0, 2).text() and dash.attention.item(0, 2).text())
check("with only runs to show there is no second 'Recent runs' heading under 'Recent activity'", "Recent runs" not in dash.recent.text() and "OK" in dash.recent.text(), dash.recent.text())
db.save_device(dict(name="sw-a2", vendor="cisco", host="10.0.0.9", port=0, platform="cisco_ios", username="", site="d", verify_ssl=0, ha_expected=0, enabled=1))
from core import backup
with db.connect() as c:
    c.execute("INSERT INTO config_backups(device, taken_at, sha, size, lines, body, added, removed) VALUES('sw-a2','2020-01-01 00:00:00','a',1,1,x'00',0,0)")
    c.execute("INSERT INTO config_backups(device, taken_at, sha, size, lines, body, added, removed) VALUES('sw-a2',?,'b',1,1,x'00',2,1)", (time.strftime("%Y-%m-%d %H:%M:%S"),))
dash.refresh()
check("with changes as well, the two parts are labelled apart", "Configuration changes (24 h)" in dash.recent.text() and "<b>Runs</b>" in dash.recent.text(), dash.recent.text())
check("one Windows computer reads '1 computer', not '1 computer(s)' (and says how it is monitored)", "<b>1</b> computer " in dash.fleet_label.text() + " " and "computer(s)" not in dash.fleet_label.text() and "by WinRM" in dash.fleet_label.text(), dash.fleet_label.text())
db.save_device(dict(name="win-2", vendor="windows", host="10.0.0.4", port=0, platform="agent", username="", site="d", verify_ssl=0, ha_expected=0, enabled=1)); dash.refresh()
check("several are plural, by kind", "<b>2</b> computers" in dash.fleet_label.text() and "1 by agent" in dash.fleet_label.text() and "1 by WinRM" in dash.fleet_label.text(), dash.fleet_label.text())

print("== 6. Notifications tables")
from ui.settings_pages.notifications import NotificationsPage
for t in ("discord", "slack"):
    notify.save_channels(notify.channels() + [notify.new_channel(t)])
np_ = NotificationsPage(); np_.resize(800, 800); np_.show(); np_.load(); settle()
check("no meaningless row numbers on either table", not np_.table.verticalHeader().isVisible() and not np_.log.verticalHeader().isVisible())
hh = np_.table.horizontalHeader()
check("the Sends column stretches and the others fit their contents", hh.sectionResizeMode(3) == QHeaderView.ResizeMode.Stretch and hh.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents)
check("so nothing is cut off at the right edge", abs(sum(hh.sectionSize(i) for i in range(4)) - np_.table.viewport().width()) <= 2)
check("full text is available on hover", np_.table.item(0, 3).toolTip() == np_.table.item(0, 3).text() and "recoveries" in np_.table.item(0, 3).text())
np_.resize(560, 800); settle()
check("narrower, the Sends text is shortened with an ellipsis, not clipped under another column", np_.table.textElideMode() == Qt.TextElideMode.ElideRight)

print("== 7. the fleet table in Inventory")
from ui.agentfleet import AgentFleet
def agent(name, age_min, comp=None, ver=2, reboot=False):
    db.save_device(dict(name=name, vendor="windows", host=name, port=0, platform="agent", username="", site="d", verify_ssl=0, ha_expected=0, enabled=1))
    agents.token_for(name)
    agents.store(name, {"v": 1, "at": "x", "computer": comp or name, "domain": "corp", "joined": True, "os": "Microsoft Windows 11 Pro", "reboot": ["x"] if reboot else []}, "10.1.1.1", ver)
    if age_min is not None:
        with db.connect() as c: c.execute("UPDATE agent_reports SET received_at=? WHERE device=?", ((__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - __import__("datetime").timedelta(minutes=age_min)).isoformat(), name))
for n, a in (("pc-fresh", 2), ("pc-old", 180), ("pc-ancient", 60 * 24 * 120), ("pc-nine", 9)):
    agent(n, a)
agent("pc-never", None)
with db.connect() as c: c.execute("UPDATE agent_reports SET received_at='' , report='' WHERE device='pc-never'")
fl = AgentFleet(); fl.resize(870, 400); fl.show(); settle()
tb = fl.table
check("clicking a heading sorts", tb.isSortingEnabled() and tb.horizontalHeader().isSortIndicatorShown())
check("the Computer column is hidden when it only repeats the device name", tb.isColumnHidden(1))
agent("pc-named", 5, comp="Reception-PC"); fl.refresh()
check("and shown as soon as a computer reports a different name", not tb.isColumnHidden(1))
db.delete_device([d for d in db.list_devices() if d["name"] == "pc-named"][0]["id"]); db.delete_device_secrets("pc-named"); agents.forget("pc-named"); fl.refresh()
check("then hidden again", tb.isColumnHidden(1))
check("at a normal width the table needs no sideways scrolling", not tb.horizontalScrollBar().isVisible() and tb.horizontalScrollBar().maximum() == 0, tb.horizontalScrollBar().maximum())
col = {tb.horizontalHeaderItem(i).text(): i for i in range(tb.columnCount())}
tb.sortByColumn(col["Age"], Qt.SortOrder.AscendingOrder)
order = [tb.item(i, 0).text() for i in range(tb.rowCount())]
check("sorting by Age is by time, not by text ('9 min' before '2.0 h' before '120 days', 'never' last)", order == ["pc-fresh", "pc-nine", "pc-old", "pc-ancient", "pc-never"][:0] + ["pc-fresh", "pc-nine", "pc-old", "pc-ancient", "pc-never"] or order[:4] == ["pc-fresh", "pc-nine", "pc-old", "pc-ancient"] and order[-1] == "pc-never", order)
tb.sortByColumn(col["Age"], Qt.SortOrder.DescendingOrder)
check("and the other way round", [tb.item(i, 0).text() for i in range(tb.rowCount())][0] == "pc-never")
tb.sortByColumn(col["Device"], Qt.SortOrder.AscendingOrder)
check("by name too", [tb.item(i, 0).text() for i in range(tb.rowCount())] == sorted(n.lower() for n in ["pc-fresh", "pc-old", "pc-ancient", "pc-nine", "pc-never"]))
check("ages over two days are in days", [tb.item(i, col["Age"]).text() for i in range(tb.rowCount()) if tb.item(i, 0).text() == "pc-ancient"] == ["120 days"])
tb.sortByColumn(col["Age"], Qt.SortOrder.DescendingOrder); fl.refresh()
check("a refresh keeps the chosen sort", tb.horizontalHeader().sortIndicatorSection() == col["Age"] and [tb.item(i, 0).text() for i in range(tb.rowCount())][0] == "pc-never")
row = [i for i in range(tb.rowCount()) if tb.item(i, 0).text() == "pc-old"][0]
tb.selectRow(row)
check("the selected row is the right computer however the table is sorted", fl._selected() == ["pc-old"])
opened = []; fl.open_device.connect(opened.append); tb.cellDoubleClicked.emit(row, 0)
check("double-click opens that computer", opened == ["pc-old"])
fl._revoke()
check("Revoke acts on that computer, not the one that was in that position before sorting", ("netcheck", "pc-old:agent") not in STORE and ("netcheck", "pc-fresh:agent") in STORE)
check("the selection survives the refresh", fl._selected() == ["pc-old"])
fl._remove()
check("Remove deletes the right one", not any(d["name"] == "pc-old" for d in db.list_devices()) and any(d["name"] == "pc-fresh" for d in db.list_devices()))
check("the heading counts and uses the right plural", "4 computers" in fl.info.text(), fl.info.text())
for n in ("pc-fresh", "pc-nine", "pc-ancient", "pc-never"):
    if n != "pc-fresh":
        db.delete_device([d for d in db.list_devices() if d["name"] == n][0]["id"]); db.delete_device_secrets(n); agents.forget(n)
fl.refresh()
check("one computer is '1 computer'", "1 computer reporting" in fl.info.text(), fl.info.text())

print("== rows of captioned boxes (OpenSSL > Create)")
import ui.opensslui as OSL
g = OSL.GenerateTab(); g.resize(1800, 400); g.show(); app.processEvents(); app.processEvents()
pair = g.country.parentWidget()
check("a box capped in width (Country) stays beside its caption instead of taking a share of the spare width", g.country.width() == 60 and pair.width() < 140, (g.country.width(), pair.width()))
check("the boxes that can grow still share the room", g.org.width() > 200 and g.state.width() > 200 and g.email.width() > 200 and abs(g.org.width() - g.city.width()) < 8, (g.org.width(), g.city.width()))
g.resize(700, 400); app.processEvents(); app.processEvents()
check("and in a narrow window it wraps without overlapping", pair.geometry().width() >= g.country.width() and g.org.width() >= 100, (pair.width(), g.org.width()))
g.close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
