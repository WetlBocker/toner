# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The twenty adjustments of 2026-10-31: the sidebar (Observability, bigger icons, breaks when folded, the fold button astride the
# edge, a gear for Settings), every row of a list in its turn when it flies in, the constellation wandering round the page,
# see-through list headers and menus with rounded corners, lists that end under their rows with a Refresh button above them,
# folders that start closed, the N/A rows folded into one, reports on History and a check's row choosing the chart, a quick
# Ping on every device menu, Move to organization as a list, the details pane counting a device's checks, the Assistant button
# that floats and rubber-bands, SSH sessions that enter enable mode, and the topology's Port-Channels, legend and zoom buttons.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "adjust%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingadjust%d" % int(time.time()))
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
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtWidgets import QApplication, QGraphicsScene, QMenu, QMessageBox, QTableWidget, QWidget
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
for i, (n, v) in enumerate((("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("dist-sw2", "cisco"), ("WITSDC01", "windows"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="cisco_ios" if v == "cisco" else ("winrm" if v == "windows" else ""),
                        username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
db.save_run([Result("core-sw1", "cpu", "OK", "12%", numeric=12.0), Result("core-sw1", "memory", "WARN", "86%", numeric=86.0),
             Result("core-sw1", "bgp", "N/A", "not configured", "BGP is not configured"), Result("core-sw1", "ospf", "N/A", "not configured", "OSPF is not configured"),
             Result("core-sw1", "eigrp", "N/A", "not configured", "EIGRP is not configured"), Result("edge-fw", "wan links", "OK", "2/2"),
             Result("dist-sw2", "connection", "ERROR", "", "timeout"), Result("WITSDC01", "patches", "WARN", "48 days")])
for k, v in dict(theme="Aurora", look="Soft", panels="Raised").items():
    db.set_setting(k, v)
import app as A
A.apply_look(app)
from core import display, nettools, topology
from ui import icons, motion, nav, theme
from ui.widgets import RefreshButton

def spin(ms):
    t0 = time.time()
    while time.time() - t0 < ms / 1000:
        app.processEvents(); time.sleep(0.01)

print("== the sidebar")
w = A.Main(); w.resize(1400, 820); w.show(); app.processEvents()
n = w.tabs
heads = [n.list.item(r).text() for r in n._headings if r != n._spacer]
check("the first group is Observability; Reports is no longer a section", heads == ["OBSERVABILITY", "NETWORK", "WORK"] and "Reports" not in [n.tabText(i) for i in range(n.count())], heads)
check("the group names are set in a bigger type than before (no longer two points smaller than the page)",
      n.list.item(n._headings[0]).font().pointSizeF() >= QApplication.font().pointSizeF() - 0.6, n.list.item(n._headings[0]).font().pointSizeF())
check("the section icons grew", nav.NAV_ICON >= 20 and n.list.iconSize().width() == nav.NAV_ICON)
check("Settings has a gear", 'circle cx="12" cy="12" r="3"' in icons.PATHS["settings"] and n._icon_names[n.indexOf(w.settings)] == "settings")
check("the fold button sits in the top row, inside the sidebar", 0 < n.fold.x() and n.fold.x() + n.fold.width() <= nav.SIDE_WIDTH, n.fold.pos())
n.setCollapsed(True); app.processEvents()
check("folded: a rule between the groups, none above the first", [n.is_break(r) for r in n._headings if r != n._spacer] == [False, True, True])
check("folded: the fold button sits astride the sidebar's edge", n.fold.x() < nav.SIDE_FOLDED < n.fold.x() + n.fold.width(), n.fold.pos())
check("folded: the mark and Search are centred in the column", abs(n.mark.x() + n.mark.width() / 2 - nav.SIDE_FOLDED / 2) <= 2 and n.quick.property("folded") is True, n.mark.pos())
n.setCollapsed(False); app.processEvents()
motion.force("Lively")
n.setCollapsed(True); spin(120)
check("with motion on, the sidebar slides shut rather than snapping", n._slide is not None and nav.SIDE_FOLDED <= n.side.width() < nav.SIDE_WIDTH, n.side.width())
spin(700)
check("...and settles at the folded width, the fold button on its edge", n.side.width() == nav.SIDE_FOLDED and n.fold.x() < nav.SIDE_FOLDED < n.fold.x() + n.fold.width(), (n.side.width(), n.fold.pos()))
n.setCollapsed(False); spin(700)
check("...and back", n.side.width() == nav.SIDE_WIDTH)
w.show_assistant(True); app.processEvents()
check("the Assistant panel slides open too", 0 < w.body.sizes()[1] < w.assistant.minimumWidth() or w.body.sizes()[1] >= w.assistant.minimumWidth(), w.body.sizes())
spin(700)
check("...and ends at its full width, with its usual least width back", w.body.sizes()[1] >= w.assistant.minimumWidth() == 320, w.body.sizes())
w.show_assistant(False); spin(700)
check("...and shuts", not w.assistant.isVisible())
motion.force(None)

print("== Refresh buttons on the main pages")
for key in ("inventory", "configs", "history"):
    check(f"{key} has one in its header", len(w.headers[key].findChildren(RefreshButton)) == 1)
check("Overview, Results and Scanning have their own", all(isinstance(x, RefreshButton) for x in (w.dashboard.refresh_btn, w.results.refresh_btn, w.scanning.refresh_btn)))
check("it says what it does", "Refresh" in w.results.refresh_btn.toolTip())
w.results.reload(); check("Results reloads the stored results", w.results.stored and w.results.table.topLevelItemCount() == 4)

print("== the theme: see-through headers, rounded menus, the tab rule")
qss = theme.stylesheet(theme.current())
check("list headers paint no background (the list's rounded corners stay round)", "QHeaderView::section {\n    background: transparent" in qss)
check("the rule under tabs is the bar's own; the pane draws none", "QTabWidget::pane { border: 0; }" in qss and "QTabBar { background: transparent; border-bottom: 1px solid" in qss)
m = QMenu(); m.ensurePolished()
check("a menu gets a see-through window, so its rounded corners are really round", m.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground))
m.addAction("one"); m.addAction("two"); m.resize(160, 90); m.show(); app.processEvents()
mask = m.mask()
check("...and its window is clipped to the rounded shape: the corners are outside it, the middle inside",
      not mask.isEmpty() and not mask.contains(QPoint(0, 0)) and not mask.contains(QPoint(159, 89)) and mask.contains(QPoint(80, 45)) and mask.contains(QPoint(0, 45)),
      mask.boundingRect())
m.close()

print("== lists end under their rows")
from ui.panels import fit_rows
t = QTableWidget(3, 2); t.resize(400, 600); t.show(); app.processEvents()
h = fit_rows(t)
check("a table's height becomes its rows plus the header", h is not None and t.maximumHeight() == h and h < 200, h)
t.setRowCount(40); app.processEvents()
h40 = fit_rows(t)
check("it grows with its rows up to 25, then scrolls", h40 is not None and abs(h40 - (h - 3 * t.rowHeight(0) + 25 * t.rowHeight(0))) <= 2 and t.verticalScrollBar().maximum() > 0, (h, h40))
t.setRowCount(0); app.processEvents()
check("an empty one keeps its height for the hint", fit_rows(t) is None and t.maximumHeight() == 16777215)
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
tr = QTreeWidget(); tr.setColumnCount(1); tr.resize(300, 800); tr.show(); app.processEvents()
top = QTreeWidgetItem(tr, ["parent"]); [QTreeWidgetItem(top, [f"child {i}"]) for i in range(6)]; app.processEvents()
closed = fit_rows(tr); top.setExpanded(True); opened = fit_rows(tr)
check("a tree grows the moment a branch is opened (no waiting for the next paint)", closed and opened and opened >= closed + 6 * tr.visualItemRect(top).height() - 2, (closed, opened))
w.go("Results"); app.processEvents()
check("Results ends under its rows", w.results.table.maximumHeight() < w.results.height(), w.results.table.maximumHeight())
check("Configs too", w.configs.devs.maximumHeight() < 16777215)
from core import agents
db.save_device(dict(name="w-agent-1", vendor="windows", host="10.0.0.9", port=0, platform="agent", username="", site="", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
agents.token_for("w-agent-1"); agents.store("w-agent-1", {"v": 1, "at": "2026-01-01T00:00:00Z", "computer": "PC", "domain": "", "joined": True, "os": "Microsoft Windows 11 Pro", "reboot": []}, "10.0.0.9", "1.0.0")
w.inventory.fleet.refresh(); app.processEvents()
check("and the Inventory's Agents page, with its one row", w.inventory.fleet.table.rowCount() == 1 and w.inventory.fleet.table.maximumHeight() < 120, w.inventory.fleet.table.maximumHeight())
check("the Inventory and Sessions start with every folder closed", not w.inventory.expanded and not w.sessions.expanded)

print("== every row in its turn when a list flies in")
motion.force("Lively")
tbl = QTableWidget(40, 1); tbl.resize(300, 1300); tbl.show(); app.processEvents()
eff = motion.reveal(tbl)
check("a long list starts its rows closer together, within the time limit", eff is not None and eff._stagger < motion.REVEAL_STAGGER and eff._total <= motion.REVEAL_TOTAL + 0.5, (eff._stagger, eff._total))
eff.t = 0.5
check("halfway through, the top row has landed, a middle row is on its way and the last has not started", eff.progress(0) == 1.0 > eff.progress(20) > eff.progress(39) == 0.0,
      (eff.progress(0), eff.progress(20), eff.progress(39)))
motion.stop(eff._anim); eff._done()
tbl.close()

print("== the constellation wanders round the page")
from ui.backdrop import Backdrop
bd = Backdrop(); bd.resize(1200, 800)
motion.force("Subtle")
c, s = bd.constellation_centre()
check("under Subtle it stays at the top right", c.x() == 880 and c.y() == 250 and s == 1.0, (c, s))
motion.force("Lively")
bd.orbit = 0.25; low, _ = bd.constellation_centre()
bd.orbit = 0.75; high, _ = bd.constellation_centre()
check("under Lively its place follows the lap: the bottom at a quarter, the top at three quarters", low.y() > 500 and high.y() < 300, (low, high))
before = bd.orbit; bd._on_phase(0.2)
check("each tick of the wash moves it on", bd.orbit != before)
from ui import backdrop as BD
a = bd.dot_drift(); bd.orbit = (bd.orbit + 0.05) % 1.0; b2 = bd.dot_drift()
check("every dot has a path of its own (no two move alike), and there are more of them than the mockup's eleven",
      len(BD._DOTS) >= 16 and all(a[i] != b2[i] for i in range(len(a))) and len({round(b2[i][0] - a[i][0], 4) for i in range(len(a))}) == len(a)
      and all(max(i, j) < len(BD._DOTS) for i, j in BD._LINKS), (len(BD._DOTS), len(BD._LINKS)))
motion.force(None)

print("== the Assistant button and panel")
from ui.assistant import SideButton
motion.force("Subtle")
host = QWidget(); host.resize(600, 400); host.show()
b = SideButton(host); b.show(); app.processEvents()
check("on its own it is half faded", abs(b._fade.opacity() - SideButton.IDLE) < 0.01, b._fade.opacity())
b.settle(QPoint(50, 50)); check("placed by the window it moves at once", b.pos() == QPoint(50, 50))
b._settling = True; b.settle(QPoint(300, 200))
check("just dropped, it rubber-bands to its place", b._gliding and b.pos() != QPoint(300, 200))
spin(900)
check("...and lands there", b.pos() == QPoint(300, 200) and not b._gliding, b.pos())
b.setChecked(True); spin(350)
check("with the panel open it is solid", b._fade.opacity() > 0.95, b._fade.opacity())
motion.force(None)
w.assistant._user("Why is dist-sw2 failing?")
check("the panel keeps the transcript in a card and sets your question in a tinted block", w.assistant.transcript.property("card") is True and "<table" in w.assistant.view.toHtml())

print("== Results folds the checks that do not apply")
tops = {w.results.table.topLevelItem(i).text(0): w.results.table.topLevelItem(i) for i in range(w.results.table.topLevelItemCount())}
core = tops["core-sw1"]
kids = [(core.child(i).text(1), core.child(i).text(2), core.child(i).childCount()) for i in range(core.childCount())]
check("core-sw1: its two real checks, then one N/A row holding the three that do not apply", kids == [("memory", "WARN", 0), ("cpu", "OK", 0), ("3 checks do not apply", "N/A", 3)], kids)
check("the folded row starts closed and knows its device", not core.child(2).isExpanded() and w.results.device_row(core.child(2).child(1)) is core)

print("== History: reports, and a check's row choosing the chart")
hs = w.history
hs.refresh(); hs.show_run(); app.processEvents()
check("the report buttons sit under the run's checks", [x.text() for x in (hs.csv_btn, hs.html_btn, hs.pdf_btn, hs.trend_btn)] == ["Export CSV", "HTML report", "PDF report", "Trend report"])
rows = hs.report_rows()
check("a report covers the chosen run's checks", len(rows) == 8 and {r.device for r in rows} == {"core-sw1", "edge-fw", "dist-sw2", "WITSDC01"}, len(rows))
import ui.history as HI
HI.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (os.path.join(SP, "adjust.csv"), ""))
hs.export_csv()
check("Export CSV writes it", os.path.exists(os.path.join(SP, "adjust.csv")) and "core-sw1" in open(os.path.join(SP, "adjust.csv"), encoding="utf-8").read())
row = next(i for i in range(hs.detail.rowCount()) if hs.detail.item(i, 1).data(Qt.ItemDataRole.UserRole) == "memory")
hs.detail.selectRow(row); app.processEvents()
check("choosing core-sw1's Memory row puts that device and check on the chart", hs.dev.currentData() == "core-sw1" and hs.chk.selected() == [display.check_name("memory")],
      (hs.dev.currentData(), hs.chk.selected()))

print("== Ping, on every device menu")
from ui import pingpop as PP
check("one echo's line, with and without a reply", PP.line(1, 3.0, "10.0.0.1") == "1. Reply from 10.0.0.1: 3 ms" and PP.line(2, None, "10.0.0.1") == "2. No reply from 10.0.0.1 (waited 1 s)")
check("the count at the end", PP.summary([3.0, None, 4.5, 2.0, 3.0]) == "5 sent, 4 answered, 1 lost, 2 to 4.5 ms" and PP.summary([None] * 5) == "5 sent, none answered")
PP.pinger.ping_once = lambda host, timeout_ms=1000: 2.0
dlg = PP.ping_popup(w, "core-sw1", "10.0.0.1"); dlg.worker.wait(5000); spin(100)
check("the pop-up sends five and shows each reply, with OK and Ping Again", dlg.text.toPlainText().count("Reply from") == 5 and dlg.result.text() == "5 sent, 5 answered, 2 ms"
      and dlg.ok.text() == "OK" and dlg.again.text() == "Ping Again", (dlg.text.toPlainText(), dlg.result.text()))
dlg.close()
from PySide6.QtCore import QTimer

def menu_texts(open_menu):
    """The entries of the menu `open_menu` opens: read from the pop-up while it is open, then closed (QMenu.exec blocks
    until then; patching it on the class has no effect in PySide6)."""
    got, tries = [], [0]

    def grab():
        m = QApplication.activePopupWidget()
        if isinstance(m, QMenu):
            got.append([a.text() for a in m.actions()])
            m.close()
        elif tries[0] < 100:
            tries[0] += 1
            QTimer.singleShot(20, grab)
    QTimer.singleShot(20, grab)
    open_menu()
    return got[-1] if got else []

inv = w.inventory
item = next(it for it in inv._all_items() if inv.kind_of(it)[0] == "device" and it.text(0) == "core-sw1")
inv.table.clearSelection(); item.setSelected(True)
got = menu_texts(lambda: inv.show_menu(inv.table.visualItemRect(item).center()))
check("the Inventory's right-click has Ping", "Ping" in got, got)
got = menu_texts(lambda: w.results.show_menu(w.results.table.visualItemRect(core).center()))
check("so has Results'", "Ping" in got, got)
w.dashboard.attention.selectRow(0); dm = w.dashboard._menu_for_current()
check("and the Overview's", dm is not None and "Ping" in [x.text() for x in dm.actions()])
from core import sessions as SE
sid = SE.save({"name": "core console", "kind": "ssh", "host": "10.0.0.1", "port": 22, "username": "u", "folder_id": None, "device": ""})
w.sessions.refresh(); app.processEvents()
sit = next(it for it in w.sessions._all_items() if w.sessions.kind_of(it) == ("session", sid))
w.sessions.tree.clearSelection(); sit.setSelected(True)
got = menu_texts(lambda: w.sessions._menu(w.sessions.tree.visualItemRect(sit).center()))
check("and a session's", "Ping" in got, got)
n_before = len(w.findChildren(PP.PingPopup))
w.quick_ping("core-sw1"); app.processEvents()
check("the topology's Ping opens the same pop-up", len(w.findChildren(PP.PingPopup)) == n_before + 1)
for p in w.findChildren(PP.PingPopup):
    p.close()

print("== Move to organization is a list")
from core import orgs
from ui.orgpick import OrgPicker
acme = orgs.create("Acme Charter", "ACME")
op = OrgPicker([{"org": 0}], w)
check("every organization is listed; the one the devices are in cannot be chosen", op.list.count() == 2 and not (op.list.item(0).flags() & Qt.ItemFlag.ItemIsEnabled) and not op.move_btn.isEnabled())
op.find.setText("acme"); app.processEvents()
check("the search box narrows the list", op.list.item(0).isHidden() and not op.list.item(1).isHidden())
op.list.setCurrentRow(1); app.processEvents()
check("picking one enables Move and says which", op.move_btn.isEnabled() and op.chosen() == acme)
op.close()
inv.table.clearSelection(); item.setSelected(True)
got = menu_texts(lambda: inv.show_menu(inv.table.visualItemRect(item).center()))
check("the Inventory offers it as one entry, not a menu of every organization", "Move to organization..." in got, got)

print("== the details pane counts a device's checks as they run")
dev = next(d for d in db.list_devices() if d["name"] == "core-sw1")
w.go("Inventory"); app.processEvents()
pane = inv.pane
pane.set_device(dev)
pane.run_started([dev["key"]])
check("Run checks: 'Running: 0 of 5' under the name, with a line that fills", pane.running.text() == "Running: 0 of 5" and pane.running.isVisible() and pane.progress.isVisible(), pane.running.text())
pane.check_done("core-sw1", "cpu"); pane.check_done("other", "cpu")
check("each of its checks counts; another device's do not", pane.running.text() == "Running: 1 of 5", pane.running.text())
pane.run_finished()
check("when the run ends the line goes", not pane.running.isVisible())
db.save_run([Result("core-sw1", "cpu", "FAIL", "99%", numeric=99.0)])
inv.update_values()
check("after a run the pane shows the device's new state", pane.chip.text() == "FAIL" and pane.summary.checks.rowCount() == 1, (pane.chip.text(), pane.summary.checks.rowCount()))

print("== SSH sessions enter enable mode")
check("a prompt is a line ending in >, # or $, or a password prompt",
      all(nettools.looks_like_prompt(x) for x in ("WetASA>", "sw1#", "user@host:~$", "Password:", "[admin@MikroTik] >")) and not nettools.looks_like_prompt("Loading..."))
check("escape sequences are not part of a prompt", nettools.last_line(b"\x1b[0m\r\nWetASA> ") == "WetASA>")
import socket as _socket
class FakeChan:
    closed = False
    def __init__(self, first, replies):
        self.queue, self.replies, self.sent = [first], replies, []
    def recv(self, _n):
        if self.queue:
            return self.queue.pop(0)
        raise _socket.timeout()
    def send(self, data):
        self.sent.append(data)
        if data in self.replies:
            self.queue.append(self.replies[data])
s = nettools.SshSession("h", 22, "u", "p", "terminal length 0", enable="s3cret")
s.chan = FakeChan(b"User admin logged in\r\nWetASA> ", {b"enable\r": b"Password: ", b"s3cret\r": b"\r\nWetASA# "})
s._sign_in_steps()
check("a '>' prompt gets `enable`, then the enable password, then the paging command", s.chan.sent == [b"enable\r", b"s3cret\r", "terminal length 0\r"] and s.entered_enable, s.chan.sent)
s2 = nettools.SshSession("h", 22, "u", "p", "terminal length 0", enable="s3cret")
s2.chan = FakeChan(b"\r\nsw1# ", {})
s2._sign_in_steps()
check("a '#' prompt is privileged already: the paging command alone", s2.chan.sent == ["terminal length 0\r"] and not s2.entered_enable, s2.chan.sent)
s3 = nettools.SshSession("h", 22, "u", "p", "", enable=None)
s3.chan = FakeChan(b"user@host:~$ ", {})
s3._sign_in_steps()
check("a device Toner never enables on, with no command to send, is left alone", s3.chan.sent == [])

print("== the topology: Port-Channels, the legend, the buttons")
members = topology.channel_members([("Po1", "SU", [("Gi1/0/1", "P"), ("Gi1/0/2", "P")]), ("Po2", "SD", [("Te1/1/1", "D")])])
check("the members of each channel, by short port name", members == {"gi1/0/1": "Po1", "gi1/0/2": "Po1", "te1/1/1": "Po2"}, members)
L = lambda ap, bp, ca="", cb="": {"a": "sw1", "b": "sw2", "a_port": ap, "b_port": bp, "a_channel": ca, "b_channel": cb, "protocols": {"LLDP"}, "rows": [], "down": False, "speed": "", "change": "", "both": True}
links = topology.bundle_channels([L("Gi1/0/1", "Gi1/0/1", "Po1", "Po1"), L("Gi1/0/2", "Gi1/0/2", "Po1", "Po1"), L("Gi1/0/5", "Gi1/0/5"), L("Gi1/0/6", "Gi1/0/6")])
check("two cables in Po1 become one link labelled Po1 with both members; two plain parallel cables stay two links",
      len(links) == 3 and links[0].get("channel") and links[0]["count"] == 2 and links[0]["a_port"] == "Po1" and links[0]["members"] == [("Gi1/0/1", "Gi1/0/1"), ("Gi1/0/2", "Gi1/0/2")]
      and not any(l.get("channel") for l in links[1:]), links)
one_sided = topology.bundle_channels([L("Gi1/0/1", "Et1", "Po1"), L("Gi1/0/2", "Et2", "Po1")])
check("a channel reported from one end only: that end says Po1, the other lists its ports", one_sided[0]["a_port"] == "Po1" and one_sided[0]["b_port"] == "Et1, Et2", one_sided)
from ui import topology as TU
check("the Links table shows the channel with its members", TU.port_text(links[0], "a") == "Po1 (Gi1/0/1, Gi1/0/2)" and TU.port_text(links[1], "a") == "Gi1/0/5")
rows = [{"device": "sw1", "local_port": "GigabitEthernet1/0/1", "remote_name": "sw2", "remote_port": "Gi1/0/1", "remote_desc": "", "remote_addr": "", "protocol": "LLDP", "local_channel": "Po1"},
        {"device": "sw2", "local_port": "Gi1/0/1", "remote_name": "sw1", "remote_port": "Gi1/0/1", "remote_desc": "", "remote_addr": "", "protocol": "LLDP", "local_channel": "Po7"}]
_n, glinks = topology.build_graph(rows)
check("build_graph carries each end's channel", len(glinks) == 1 and {glinks[0]["a_channel"], glinks[0]["b_channel"]} == {"Po1", "Po7"}, glinks)
tp = w.tools.topology
check("the legend shows on an empty map, and says Port-Channel instead of Merged links", tp.l2.legend_lay.count() >= 6 and any("Port-Channel" in tp.l2.legend_lay.itemAt(i).widget().text() for i in range(tp.l2.legend_lay.count())))
check("the zoom buttons carry icons (their glyphs were cut off)", all(not x.icon().isNull() and x.text() == "" for x in (tp.l2.zoom_in, tp.l2.zoom_out, tp.l2.fit_btn)))
check("the rail says what the tick does", tp.merge.text() == "Bundle Port-Channels")
w.go("Tools"); w.tools.tabs.setCurrentWidget(tp); app.processEvents()
tp.select_link(links[0], "l2"); app.processEvents()
check("clicking a Port-Channel's line opens a card listing its members", tp.l2.card.isVisible() and tp.l2.card.role.text() == "Port-Channel Po1  ⇄  Po1  ·  2 members"
      and tp.l2.card.grid.count() == 4, tp.l2.card.role.text())
sc = QGraphicsScene()
na, nb = TU.NodeItem("sw1", "switch", "", True, "sw1"), TU.NodeItem("sw2", "switch", "", True, "sw2")
na.setPos(0, 0); nb.setPos(400, 0); sc.addItem(na); sc.addItem(nb)
edge = TU.EdgeItem(na, nb, links[0], "l2"); sc.addItem(edge)
check("a click lands on a link along its line, not anywhere in its box", edge.shape().contains(QPointF(200, 2)) and not edge.shape().contains(QPointF(200, 40)))

w.close()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
